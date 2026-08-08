// Package h1 implements Repost's bounded, byte-exact HTTP/1.1 wire format.
package h1

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/repost-sh/repost-go/internal/wirelimits"
)

// Exported wire limits mirror the shared transport limits.
const (
	MaxRequestBodyBytes       = wirelimits.BodyBytes
	MaxCompressedBodyBytes    = wirelimits.BodyBytes
	MaxDecompressedBodyBytes  = wirelimits.BodyBytes
	MaxErrorBodyBytes         = wirelimits.ErrorBodyBytes
	MaxExpansionRatio         = wirelimits.ExpansionRatio
	MaxHeaderFields           = wirelimits.HeaderFields
	MaxHeaderBytes            = wirelimits.HeaderBytes
	MaxHeaderNameBytes        = wirelimits.HeaderNameBytes
	MaxHeaderValueBytes       = wirelimits.HeaderValueBytes
	maxTargetBytes            = 2048
	maxInformationalResponses = 8
)

// Response and request framing errors.
var (
	ErrInvalidRequest = errors.New("h1: invalid request")
	ErrProtocol       = errors.New("h1: invalid response protocol")
	ErrHeaderLimit    = errors.New("h1: response header limit exceeded")
	ErrBodyTooLarge   = errors.New("h1: response body limit exceeded")
	ErrExpansionRatio = errors.New("h1: response expansion ratio exceeded")
	ErrIncompleteBody = errors.New("h1: incomplete response body")
)

// Request contains the only fields permitted by the outbound framing contract.
type Request struct {
	Target         string
	Authority      string
	Authorization  string
	UserAgent      string
	IdempotencyKey string
	Traceparent    string
	Tracestate     string
	Body           []byte
}

// Header preserves response field order and duplicates.
type Header struct {
	Name  string
	Value string
}

// Response is one fully framed, bounded response.
type Response struct {
	Status            int
	Headers           []Header
	Body              []byte
	CompressedBytes   int64
	DecompressedBytes int64
	Truncated         bool
}

// WriteRequest writes the exact outbound request and marks commitment after
// the first body byte reaches w.
func WriteRequest(w io.Writer, req *Request, markCommitted func()) error {
	if !validRequest(req) {
		return ErrInvalidRequest
	}
	var header strings.Builder
	_, _ = fmt.Fprintf(&header, "POST %s HTTP/1.1\r\n", req.Target)
	_, _ = fmt.Fprintf(&header, "host: %s\r\n", req.Authority)
	_, _ = fmt.Fprintf(&header, "content-length: %d\r\n", len(req.Body))
	_, _ = fmt.Fprintf(&header, "authorization: %s\r\n", req.Authorization)
	header.WriteString("content-type: application/json\r\n")
	header.WriteString("accept-encoding: gzip\r\n")
	_, _ = fmt.Fprintf(&header, "user-agent: %s\r\n", req.UserAgent)
	_, _ = fmt.Fprintf(&header, "idempotency-key: %s\r\n", req.IdempotencyKey)
	if req.Traceparent != "" {
		_, _ = fmt.Fprintf(&header, "traceparent: %s\r\n", req.Traceparent)
		if req.Tracestate != "" {
			_, _ = fmt.Fprintf(&header, "tracestate: %s\r\n", req.Tracestate)
		}
	}
	header.WriteString("\r\n")
	if err := writeAll(w, []byte(header.String()), nil); err != nil {
		return err
	}
	return writeAll(w, req.Body, markCommitted)
}

func validRequest(req *Request) bool {
	return req != nil && req.Target != "" && len(req.Target) <= maxTargetBytes && req.Target[0] == '/' &&
		req.Authority != "" && len(req.Body) <= MaxRequestBodyBytes &&
		validWireValue(req.Target) && validWireValue(req.Authority) &&
		validWireValue(req.Authorization) && req.Authorization != "" &&
		validWireValue(req.UserAgent) && req.UserAgent != "" &&
		validWireValue(req.IdempotencyKey) && req.IdempotencyKey != "" &&
		validWireValue(req.Traceparent) && validWireValue(req.Tracestate) &&
		(req.Tracestate == "" || req.Traceparent != "")
}

func validWireValue(value string) bool {
	return !strings.ContainsAny(value, "\r\n\x00")
}

func writeAll(w io.Writer, data []byte, firstByte func()) error {
	marked := false
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		if n > 0 && !marked && firstByte != nil {
			firstByte()
			marked = true
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// ReadResponse parses one response without trusting declared lengths for
// allocation. It accepts content-length and chunked receive framing only.
func ReadResponse(r *bufio.Reader) (Response, error) {
	return readFinalResponse(r, nil)
}

// ReadResponseWithHeaders invokes onHeaders after the final response headers
// are parsed and before any response body bytes are read.
func ReadResponseWithHeaders(r *bufio.Reader, onHeaders func(Response)) (Response, error) {
	return readFinalResponse(r, onHeaders)
}

func readFinalResponse(r *bufio.Reader, onHeaders func(Response)) (Response, error) {
	var response Response
	var contentLength int64
	var hasLength, chunked bool
	var encoding string
	var err error
	for informational := 0; ; {
		response = Response{}
		statusLine, err := readLine(r, MaxHeaderValueBytes)
		if err != nil {
			return response, err
		}
		response.Status, err = parseStatus(statusLine)
		if err != nil {
			return response, err
		}

		headerBytes := 0
		for {
			line, readErr := readLine(r, MaxHeaderBytes+2)
			if readErr != nil {
				return response, readErr
			}
			if len(line) == 0 {
				break
			}
			if len(response.Headers) == MaxHeaderFields {
				return response, ErrHeaderLimit
			}
			header, parseErr := parseHeader(line)
			if parseErr != nil {
				return response, parseErr
			}
			response.Headers = append(response.Headers, header)
			headerBytes += len(header.Name) + 2 + len(header.Value) + 2
			if headerBytes > MaxHeaderBytes {
				return response, ErrHeaderLimit
			}
		}

		contentLength, hasLength, err = singleContentLength(response.Headers)
		if err != nil {
			return response, err
		}
		chunked, err = transferChunked(response.Headers)
		if err != nil || hasLength && chunked {
			return response, ErrProtocol
		}
		encoding, err = contentEncoding(response.Headers)
		if err != nil {
			return response, err
		}
		if response.Status < 100 || response.Status >= 200 {
			break
		}
		informational++
		if response.Status == 101 || informational > maxInformationalResponses || chunked || hasLength && contentLength != 0 {
			return response, ErrProtocol
		}
	}
	if onHeaders != nil {
		onHeaders(response)
	}
	if hasLength && contentLength > MaxCompressedBodyBytes {
		response.CompressedBytes = contentLength
		return response, ErrBodyTooLarge
	}

	var compressed []byte
	switch {
	case hasLength:
		compressed, err = readContentLength(r, contentLength)
	case chunked:
		compressed, err = readChunked(r)
	case response.Status >= 100 && response.Status < 200 || response.Status == 204 || response.Status == 304:
		compressed = []byte{}
	default:
		return response, ErrProtocol
	}
	response.CompressedBytes = int64(len(compressed))
	if err != nil {
		if encoding == "identity" {
			response.DecompressedBytes = response.CompressedBytes
		}
		if errors.Is(err, ErrBodyTooLarge) {
			return response, err
		}
		if errors.Is(err, ErrProtocol) || errors.Is(err, ErrHeaderLimit) {
			return response, err
		}
		response.Truncated = true
		return response, ErrIncompleteBody
	}
	if compressed == nil {
		compressed = []byte{}
	}

	decoded := compressed
	if encoding == "gzip" {
		decoded, err = decodeGzip(compressed)
		if err != nil {
			response.DecompressedBytes = int64(len(decoded))
			response.Truncated = errors.Is(err, ErrBodyTooLarge) || errors.Is(err, ErrExpansionRatio)
			return response, err
		}
	}
	response.DecompressedBytes = int64(len(decoded))
	if response.Status < 200 || response.Status >= 300 {
		response.Body = []byte{}
		response.Truncated = len(decoded) > MaxErrorBodyBytes
		return response, nil
	}
	response.Body = append([]byte{}, decoded...)
	return response, nil
}

func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		fragment, err := r.ReadSlice('\n')
		if len(line)+len(fragment) > limit+2 {
			return nil, ErrHeaderLimit
		}
		line = append(line, fragment...)
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, ErrProtocol
	}
	return line[:len(line)-2], nil
}

func parseStatus(line []byte) (int, error) {
	if len(line) < 12 || string(line[:9]) != "HTTP/1.1 " || line[9] < '1' || line[9] > '5' ||
		line[10] < '0' || line[10] > '9' || line[11] < '0' || line[11] > '9' ||
		len(line) > 12 && line[12] != ' ' {
		return 0, ErrProtocol
	}
	status := int(line[9]-'0')*100 + int(line[10]-'0')*10 + int(line[11]-'0')
	return status, nil
}

func parseHeader(line []byte) (Header, error) {
	if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
		return Header{}, ErrProtocol
	}
	colon := bytes.IndexByte(line, ':')
	if colon < 1 {
		return Header{}, ErrProtocol
	}
	name := line[:colon]
	if len(name) > MaxHeaderNameBytes {
		return Header{}, ErrHeaderLimit
	}
	for _, c := range name {
		if !tokenByte(c) {
			return Header{}, ErrProtocol
		}
	}
	value := bytes.Trim(line[colon+1:], " \t")
	if len(value) > MaxHeaderValueBytes {
		return Header{}, ErrHeaderLimit
	}
	if !utf8.Valid(value) {
		return Header{}, ErrProtocol
	}
	for _, c := range value {
		if c == 0x7f || c < 0x20 && c != '\t' {
			return Header{}, ErrProtocol
		}
	}
	return Header{Name: string(name), Value: string(value)}, nil
}

func tokenByte(c byte) bool {
	if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}

func singleContentLength(headers []Header) (contentLength int64, present bool, err error) {
	value := ""
	found := false
	for _, header := range headers {
		if !strings.EqualFold(header.Name, "content-length") {
			continue
		}
		if found || header.Value == "" {
			return 0, false, ErrProtocol
		}
		found, value = true, header.Value
	}
	if !found {
		return 0, false, nil
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, false, ErrProtocol
		}
	}
	n, err := strconv.ParseUint(value, 10, 63)
	if err != nil {
		return 0, false, ErrProtocol
	}
	if n > uint64(MaxCompressedBodyBytes) {
		return int64(MaxCompressedBodyBytes) + 1, true, nil
	}
	return int64(n), true, nil
}

func transferChunked(headers []Header) (bool, error) {
	found := false
	for _, header := range headers {
		if !strings.EqualFold(header.Name, "transfer-encoding") {
			continue
		}
		if found || !strings.EqualFold(header.Value, "chunked") {
			return false, ErrProtocol
		}
		found = true
	}
	return found, nil
}

func contentEncoding(headers []Header) (string, error) {
	encoding := "identity"
	found := false
	for _, header := range headers {
		if !strings.EqualFold(header.Name, "content-encoding") {
			continue
		}
		if found {
			return "", ErrProtocol
		}
		found, encoding = true, strings.ToLower(header.Value)
	}
	if encoding != "identity" && encoding != "gzip" {
		return "", ErrProtocol
	}
	return encoding, nil
}

func readContentLength(r io.Reader, length int64) ([]byte, error) {
	body := make([]byte, length)
	n, err := io.ReadFull(r, body)
	return body[:n], err
}

func readChunked(r *bufio.Reader) ([]byte, error) {
	var body bytes.Buffer
	for {
		line, err := readLine(r, 256)
		if err != nil {
			return body.Bytes(), err
		}
		if semi := bytes.IndexByte(line, ';'); semi >= 0 {
			line = line[:semi]
		}
		if len(line) == 0 {
			return body.Bytes(), ErrProtocol
		}
		size, err := strconv.ParseUint(string(line), 16, 63)
		if err != nil {
			return body.Bytes(), ErrProtocol
		}
		if size == 0 {
			trailer, err := readLine(r, MaxHeaderBytes)
			if err != nil {
				return body.Bytes(), err
			}
			if len(trailer) != 0 {
				return body.Bytes(), ErrProtocol
			}
			return body.Bytes(), nil
		}
		remaining := MaxCompressedBodyBytes + 1 - body.Len()
		if remaining <= 0 {
			return body.Bytes(), ErrBodyTooLarge
		}
		if size >= uint64(remaining) {
			if _, err := io.CopyN(&body, r, int64(remaining)); err != nil {
				return body.Bytes(), err
			}
			return body.Bytes(), ErrBodyTooLarge
		}
		if _, err := io.CopyN(&body, r, int64(size)); err != nil {
			return body.Bytes(), err
		}
		ending := [2]byte{}
		if _, err := io.ReadFull(r, ending[:]); err != nil {
			return body.Bytes(), err
		}
		if ending != [2]byte{'\r', '\n'} {
			return body.Bytes(), ErrProtocol
		}
	}
}

func decodeGzip(compressed []byte) ([]byte, error) {
	source := bytes.NewReader(compressed)
	reader, err := gzip.NewReader(source)
	if err != nil {
		return nil, ErrProtocol
	}
	reader.Multistream(false)
	defer func() { _ = reader.Close() }()
	var decoded bytes.Buffer
	buffer := make([]byte, 32<<10)
	expansionLimit := len(compressed) * MaxExpansionRatio
	for {
		readBuffer := buffer
		remaining := expansionLimit + 1 - decoded.Len()
		if remaining < len(readBuffer) {
			readBuffer = readBuffer[:remaining]
		}
		n, readErr := reader.Read(readBuffer)
		if n > 0 {
			_, _ = decoded.Write(buffer[:n])
			if decoded.Len() > expansionLimit {
				return decoded.Bytes(), ErrExpansionRatio
			}
			if decoded.Len() > MaxDecompressedBodyBytes {
				return decoded.Bytes(), ErrBodyTooLarge
			}
		}
		if errors.Is(readErr, io.EOF) {
			if source.Len() != 0 {
				return decoded.Bytes(), ErrProtocol
			}
			return decoded.Bytes(), nil
		}
		if readErr != nil {
			return decoded.Bytes(), ErrProtocol
		}
	}
}
