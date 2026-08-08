package h2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	xhttp2 "golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	defaultWindowSize         = 65535
	defaultFrameSize          = 16384
	maxWindowSize             = 1<<31 - 1
	maxInformationalResponses = 8
	// HPACK accounts 32 bytes per field; the contract accounts four.
	maxHPACKListSize = maxHeaderBytes + (32-4)*maxHeaderFields
)

// StreamResetError reports a server-originated RST_STREAM.
type StreamResetError struct {
	Code xhttp2.ErrCode
}

func (e *StreamResetError) Error() string {
	return fmt.Sprintf("h2: stream reset: %s", e.Code)
}

// GoAwayError reports a draining session and the server's acceptance bound.
type GoAwayError struct {
	LastStreamID uint32
	Code         xhttp2.ErrCode
}

func (e *GoAwayError) Error() string {
	return fmt.Sprintf("h2: goaway: last stream %d: %s", e.LastStreamID, e.Code)
}

type stream struct {
	id              uint32
	sendWindow      int64
	done            chan struct{}
	response        Response
	err             error
	finished        bool
	headersReceived bool
	expectedLength  *int64
	observeHeaders  func(int, []Header)
	informational   int
}

type writeCall struct {
	ctx     context.Context
	write   func(*xhttp2.Framer) error
	started chan struct{}
	done    chan error
}

// Session owns one HTTP/2 connection and multiplexes one stream per attempt.
type Session struct {
	conn   net.Conn
	framer *xhttp2.Framer

	writeCh chan writeCall
	done    chan struct{}
	once    sync.Once

	mu                  sync.Mutex
	closeErr            error
	streams             map[uint32]*stream
	nextStreamID        uint32
	connectionWindow    int64
	initialStreamWindow int64
	maxFrameSize        int
	maxConcurrent       uint32
	flowChanged         chan struct{}
	admissionChanged    chan struct{}
	goAway              *GoAwayError
}

// NewSession performs the client preface and initial SETTINGS handshake.
func NewSession(ctx context.Context, conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, errors.New("h2: nil connection")
	}
	s := &Session{
		conn: conn, framer: xhttp2.NewFramer(conn, conn),
		writeCh: make(chan writeCall, 64), done: make(chan struct{}),
		streams: make(map[uint32]*stream), nextStreamID: 1,
		connectionWindow: defaultWindowSize, initialStreamWindow: defaultWindowSize,
		maxFrameSize: defaultFrameSize, maxConcurrent: math.MaxUint32,
		flowChanged: make(chan struct{}), admissionChanged: make(chan struct{}),
	}

	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer func() {
		stop()
		_ = conn.SetDeadline(time.Time{})
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("h2: set handshake deadline: %w", err)
		}
	}
	if _, err := io.WriteString(conn, xhttp2.ClientPreface); err != nil {
		return nil, fmt.Errorf("h2: write client preface: %w", err)
	}
	if err := s.framer.WriteSettings(
		xhttp2.Setting{ID: xhttp2.SettingHeaderTableSize, Val: 0},
		xhttp2.Setting{ID: xhttp2.SettingEnablePush, Val: 0},
		xhttp2.Setting{ID: xhttp2.SettingMaxHeaderListSize, Val: maxHPACKListSize},
	); err != nil {
		return nil, fmt.Errorf("h2: write client settings: %w", err)
	}
	frame, err := s.framer.ReadFrame()
	if err != nil {
		return nil, fmt.Errorf("h2: read server settings: %w", err)
	}
	settings, ok := frame.(*xhttp2.SettingsFrame)
	if !ok || settings.IsAck() {
		return nil, errors.New("h2: server preface did not begin with settings")
	}
	if err := s.applySettings(settings); err != nil {
		return nil, err
	}
	if err := s.framer.WriteSettingsAck(); err != nil {
		return nil, fmt.Errorf("h2: acknowledge server settings: %w", err)
	}

	decoder := hpack.NewDecoder(0, func(hpack.HeaderField) {})
	decoder.SetAllowedMaxDynamicTableSize(0)
	s.framer.ReadMetaHeaders = decoder
	s.framer.MaxHeaderListSize = maxHPACKListSize
	s.framer.SetMaxReadFrameSize(defaultFrameSize)
	go s.writeLoop()
	go s.readLoop()
	return s, nil
}

// Do writes one request stream and waits for its bounded response.
func (s *Session) Do(ctx context.Context, request *Request) (Response, error) {
	block, err := encodeRequestHeaders(request)
	if err != nil {
		return Response{}, err
	}
	st, err := s.acquireStream(ctx)
	if err != nil {
		return Response{}, err
	}
	st.observeHeaders = request.HeadersReceived
	fail := func(err error) (Response, error) {
		s.cancelStream(st, err)
		return Response{}, err
	}

	if err := s.write(ctx, func(framer *xhttp2.Framer) error {
		return writeHeaderBlock(framer, st.id, block, len(request.Body) == 0, s.outboundFrameSize())
	}); err != nil {
		return fail(err)
	}
	for offset := 0; offset < len(request.Body); {
		size, err := s.reserveSend(ctx, st, len(request.Body)-offset)
		if err != nil {
			if st.finished {
				return st.response, st.err
			}
			if ctx.Err() != nil {
				if resetErr := s.resetCanceledStream(st, ctx.Err()); resetErr != nil {
					return Response{}, errors.Join(ctx.Err(), resetErr)
				}
				return Response{}, ctx.Err()
			}
			return fail(err)
		}
		chunk := request.Body[offset : offset+size]
		end := offset+size == len(request.Body)
		first := offset == 0
		if err := s.write(ctx, func(framer *xhttp2.Framer) error {
			if first && request.MarkCommitted != nil {
				request.MarkCommitted()
			}
			return framer.WriteData(st.id, end, chunk)
		}); err != nil {
			return fail(err)
		}
		offset += size
	}

	for {
		select {
		case <-st.done:
			return st.response, st.err
		case <-ctx.Done():
			if err := s.resetCanceledStream(st, ctx.Err()); err != nil {
				return Response{}, errors.Join(ctx.Err(), err)
			}
			return Response{}, ctx.Err()
		case <-s.done:
			return Response{}, s.sessionError()
		}
	}
}

// LastGoAway returns the most recent server drain boundary.
func (s *Session) LastGoAway() (lastStreamID uint32, code xhttp2.ErrCode, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.goAway == nil {
		return 0, 0, false
	}
	return s.goAway.LastStreamID, s.goAway.Code, true
}

// Reusable reports whether the pool may assign a new stream.
func (s *Session) Reusable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr == nil && s.goAway == nil && s.nextStreamID <= math.MaxInt32
}

// Close terminates the session and all pending streams.
func (s *Session) Close() error {
	s.shutdown(ErrSessionClosed)
	return nil
}

func (s *Session) acquireStream(ctx context.Context) (*stream, error) {
	for {
		s.mu.Lock()
		if s.closeErr != nil {
			err := s.closeErr
			s.mu.Unlock()
			return nil, err
		}
		if s.goAway != nil {
			err := *s.goAway
			s.mu.Unlock()
			return nil, &err
		}
		if s.nextStreamID > math.MaxInt32 {
			s.mu.Unlock()
			return nil, ErrSessionClosed
		}
		if uint64(len(s.streams)) < uint64(s.maxConcurrent) {
			st := &stream{id: s.nextStreamID, sendWindow: s.initialStreamWindow, done: make(chan struct{})}
			s.nextStreamID += 2
			s.streams[st.id] = st
			s.mu.Unlock()
			return st, nil
		}
		changed := s.admissionChanged
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, s.sessionError()
		}
	}
}

func (s *Session) reserveSend(ctx context.Context, st *stream, remaining int) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		s.mu.Lock()
		if st.finished {
			err := st.err
			if err == nil {
				err = io.EOF
			}
			s.mu.Unlock()
			return 0, err
		}
		available := min(int64(remaining), int64(s.maxFrameSize), s.connectionWindow, st.sendWindow)
		if available > 0 {
			s.connectionWindow -= available
			st.sendWindow -= available
			s.mu.Unlock()
			return int(available), nil
		}
		changed := s.flowChanged
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-s.done:
			return 0, s.sessionError()
		}
	}
}

func (s *Session) outboundFrameSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxFrameSize
}

func (s *Session) write(ctx context.Context, write func(*xhttp2.Framer) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	call := writeCall{ctx: ctx, write: write, started: make(chan struct{}), done: make(chan error, 1)}
	select {
	case s.writeCh <- call:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.sessionError()
	}
	select {
	case err := <-call.done:
		return err
	case <-ctx.Done():
		select {
		case <-call.started:
			select {
			case err := <-call.done:
				return err
			case <-s.done:
				return ctx.Err()
			}
		default:
			return ctx.Err()
		}
	case <-s.done:
		return s.sessionError()
	}
}

// resetCanceledStream notifies the peer before releasing the stream locally, so
// a concurrent teardown cannot skip the RST_STREAM. The stream is finished
// either way, including when the reset cannot be written.
func (s *Session) resetCanceledStream(st *stream, err error) error {
	writeErr := s.write(context.Background(), func(framer *xhttp2.Framer) error {
		return framer.WriteRSTStream(st.id, xhttp2.ErrCodeCancel)
	})
	s.cancelStream(st, err)
	return writeErr
}

func (s *Session) queue(write func(*xhttp2.Framer) error) {
	select {
	case s.writeCh <- writeCall{ctx: context.Background(), write: write, started: make(chan struct{}), done: make(chan error, 1)}:
	case <-s.done:
	}
}

func (s *Session) writeLoop() {
	for {
		select {
		case call := <-s.writeCh:
			close(call.started)
			if err := call.ctx.Err(); err != nil {
				call.done <- err
				continue
			}
			// Interrupt a blocked write with a write deadline rather than by
			// closing the connection: a cancellation that lands just after the
			// frame reached the peer must leave the session usable so the
			// stream reset can still be written.
			var (
				unblockMu sync.Mutex
				settled   bool
			)
			stopCancellation := context.AfterFunc(call.ctx, func() {
				unblockMu.Lock()
				defer unblockMu.Unlock()
				if !settled {
					_ = s.conn.SetWriteDeadline(time.Now())
				}
			})
			err := call.write(s.framer)
			stopCancellation()
			unblockMu.Lock()
			settled = true
			_ = s.conn.SetWriteDeadline(time.Time{})
			unblockMu.Unlock()
			if err != nil && call.ctx.Err() != nil {
				err = call.ctx.Err()
			}
			call.done <- err
			if err != nil {
				s.shutdown(fmt.Errorf("h2: write frame: %w", err))
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *Session) readLoop() {
	for {
		frame, err := s.framer.ReadFrame()
		if err != nil {
			var streamErr xhttp2.StreamError
			if errors.As(err, &streamErr) {
				s.finishStream(streamErr.StreamID, &Response{}, ErrResponseProtocol)
				s.queue(func(framer *xhttp2.Framer) error {
					return framer.WriteRSTStream(streamErr.StreamID, streamErr.Code)
				})
				continue
			}
			s.shutdown(fmt.Errorf("h2: read frame: %w", err))
			return
		}
		switch frame := frame.(type) {
		case *xhttp2.MetaHeadersFrame:
			s.handleHeaders(frame)
		case *xhttp2.DataFrame:
			s.handleData(frame)
		case *xhttp2.RSTStreamFrame:
			s.finishStream(frame.StreamID, &Response{}, &StreamResetError{Code: frame.ErrCode})
		case *xhttp2.GoAwayFrame:
			s.handleGoAway(frame)
		case *xhttp2.WindowUpdateFrame:
			if err := s.handleWindowUpdate(frame); err != nil {
				s.shutdown(err)
				return
			}
		case *xhttp2.SettingsFrame:
			if !frame.IsAck() {
				if err := s.applySettings(frame); err != nil {
					s.shutdown(err)
					return
				}
				s.queue(func(framer *xhttp2.Framer) error { return framer.WriteSettingsAck() })
			}
		case *xhttp2.PingFrame:
			if !frame.IsAck() {
				data := frame.Data
				s.queue(func(framer *xhttp2.Framer) error { return framer.WritePing(true, data) })
			}
		case *xhttp2.PushPromiseFrame:
			s.shutdown(ErrResponseProtocol)
			return
		}
	}
}

func (s *Session) handleHeaders(frame *xhttp2.MetaHeadersFrame) {
	response, expected, err := decodeResponseHeaders(frame)
	if err != nil {
		s.finishStream(frame.StreamID, &Response{}, err)
		s.queue(func(framer *xhttp2.Framer) error {
			return framer.WriteRSTStream(frame.StreamID, xhttp2.ErrCodeProtocol)
		})
		return
	}
	s.mu.Lock()
	st := s.streams[frame.StreamID]
	if st == nil || st.finished {
		s.mu.Unlock()
		return
	}
	if response.Status >= 100 && response.Status < 200 {
		st.informational++
		invalid := response.Status == 101 || frame.StreamEnded() || st.headersReceived || st.informational > maxInformationalResponses
		s.mu.Unlock()
		if invalid {
			s.finishStream(frame.StreamID, &Response{}, ErrResponseProtocol)
		}
		return
	}
	if st.headersReceived {
		s.mu.Unlock()
		s.finishStream(frame.StreamID, &Response{}, ErrResponseProtocol)
		return
	}
	st.headersReceived = true
	st.response = response
	st.expectedLength = expected
	observeHeaders := st.observeHeaders
	headers := append([]Header(nil), response.Headers...)
	end := frame.StreamEnded()
	if end && expected != nil && *expected != 0 {
		s.mu.Unlock()
		if observeHeaders != nil {
			observeHeaders(response.Status, headers)
		}
		s.finishStream(frame.StreamID, &Response{}, ErrResponseProtocol)
		return
	}
	s.mu.Unlock()
	if observeHeaders != nil {
		observeHeaders(response.Status, headers)
	}
	if end {
		response, err = finalizeResponse(&response)
		s.finishStream(frame.StreamID, &response, err)
	}
}

func (s *Session) handleData(frame *xhttp2.DataFrame) {
	streamID, data := frame.StreamID, frame.Data()
	if len(data) > 0 {
		dataLength := len(data)
		if uint64(dataLength) > math.MaxUint32 {
			s.finishStream(streamID, &Response{}, ErrResponseTooLarge)
			return
		}
		size := uint32(dataLength)
		s.queue(func(framer *xhttp2.Framer) error {
			if err := framer.WriteWindowUpdate(0, size); err != nil {
				return err
			}
			return framer.WriteWindowUpdate(streamID, size)
		})
	}
	s.mu.Lock()
	st := s.streams[streamID]
	if st == nil || st.finished {
		s.mu.Unlock()
		return
	}
	if !st.headersReceived {
		s.mu.Unlock()
		s.finishStream(streamID, &Response{}, ErrResponseProtocol)
		return
	}
	if len(st.response.Body)+len(data) > maxBodyBytes {
		s.mu.Unlock()
		s.finishStream(streamID, &Response{}, ErrResponseTooLarge)
		return
	}
	st.response.Body = append(st.response.Body, data...)
	if st.expectedLength != nil && int64(len(st.response.Body)) > *st.expectedLength {
		s.mu.Unlock()
		s.finishStream(streamID, &Response{}, ErrResponseProtocol)
		return
	}
	if frame.StreamEnded() {
		if st.expectedLength != nil && int64(len(st.response.Body)) != *st.expectedLength {
			s.mu.Unlock()
			s.finishStream(streamID, &Response{}, ErrResponseProtocol)
			return
		}
		response := st.response
		s.mu.Unlock()
		response, err := finalizeResponse(&response)
		s.finishStream(streamID, &response, err)
		return
	}
	s.mu.Unlock()
}

func (s *Session) handleWindowUpdate(frame *xhttp2.WindowUpdateFrame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if frame.StreamID == 0 {
		if s.connectionWindow+int64(frame.Increment) > maxWindowSize {
			return ErrResponseProtocol
		}
		s.connectionWindow += int64(frame.Increment)
	} else if st := s.streams[frame.StreamID]; st != nil && !st.finished {
		if st.sendWindow+int64(frame.Increment) > maxWindowSize {
			return ErrResponseProtocol
		}
		st.sendWindow += int64(frame.Increment)
	}
	s.signalFlowLocked()
	return nil
}

func (s *Session) applySettings(frame *xhttp2.SettingsFrame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return frame.ForeachSetting(func(setting xhttp2.Setting) error {
		if err := setting.Valid(); err != nil {
			return fmt.Errorf("h2: invalid setting: %w", err)
		}
		switch setting.ID {
		case xhttp2.SettingInitialWindowSize:
			delta := int64(setting.Val) - s.initialStreamWindow
			s.initialStreamWindow = int64(setting.Val)
			for _, st := range s.streams {
				st.sendWindow += delta
			}
			s.signalFlowLocked()
		case xhttp2.SettingMaxFrameSize:
			s.maxFrameSize = int(setting.Val)
		case xhttp2.SettingMaxConcurrentStreams:
			s.maxConcurrent = setting.Val
			s.signalAdmissionLocked()
		}
		return nil
	})
}

func (s *Session) handleGoAway(frame *xhttp2.GoAwayFrame) {
	s.mu.Lock()
	if s.goAway == nil || frame.LastStreamID < s.goAway.LastStreamID {
		s.goAway = &GoAwayError{LastStreamID: frame.LastStreamID, Code: frame.ErrCode}
	}
	for id, st := range s.streams {
		if id > s.goAway.LastStreamID {
			err := *s.goAway
			s.finishLocked(st, &Response{}, &err)
		}
	}
	s.signalAdmissionLocked()
	s.mu.Unlock()
}

func (s *Session) cancelStream(st *stream, err error) {
	s.mu.Lock()
	if !st.finished {
		s.finishLocked(st, &Response{}, err)
	}
	s.mu.Unlock()
}

func (s *Session) finishStream(id uint32, response *Response, err error) {
	s.mu.Lock()
	if st := s.streams[id]; st != nil && !st.finished {
		s.finishLocked(st, response, err)
	}
	s.mu.Unlock()
}

func (s *Session) finishLocked(st *stream, response *Response, err error) {
	st.response, st.err, st.finished = *response, err, true
	delete(s.streams, st.id)
	close(st.done)
	s.signalAdmissionLocked()
	s.signalFlowLocked()
}

func (s *Session) signalFlowLocked() {
	close(s.flowChanged)
	s.flowChanged = make(chan struct{})
}

func (s *Session) signalAdmissionLocked() {
	close(s.admissionChanged)
	s.admissionChanged = make(chan struct{})
}

func (s *Session) shutdown(err error) {
	s.once.Do(func() {
		s.mu.Lock()
		s.closeErr = err
		for _, st := range s.streams {
			s.finishLocked(st, &Response{}, err)
		}
		close(s.done)
		s.mu.Unlock()
		_ = s.conn.Close()
	})
}

func (s *Session) sessionError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeErr != nil {
		return s.closeErr
	}
	return ErrSessionClosed
}
