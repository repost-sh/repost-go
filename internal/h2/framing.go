// Package h2 implements the SDK's bounded HTTP/2 wire lane without net/http.
package h2

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/repost-sh/repost-go/internal/wirelimits"
	xhttp2 "golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	maxBodyBytes    = wirelimits.BodyBytes
	errorBodyBytes  = wirelimits.ErrorBodyBytes
	maxExpansion    = wirelimits.ExpansionRatio
	maxHeaderFields = wirelimits.HeaderFields
	maxHeaderBytes  = wirelimits.HeaderBytes
	maxHeaderName   = wirelimits.HeaderNameBytes
	maxHeaderValue  = wirelimits.HeaderValueBytes
)

// Response framing and session errors.
var (
	ErrResponseProtocol = errors.New("h2: response protocol is invalid")
	ErrResponseTooLarge = errors.New("h2: response exceeds the size limit")
	ErrSessionClosed    = errors.New("h2: session is closed")
)

// Header preserves response field order and duplicates.
type Header struct {
	Name  string
	Value string
}

// Request is one exact POST stream. Header names and fixed values are owned by
// this package so callers cannot accidentally drift from the wire contract.
type Request struct {
	Scheme          string
	Authority       string
	Path            string
	Authorization   string
	UserAgent       string
	IdempotencyKey  string
	TraceParent     string
	TraceState      string
	Body            []byte
	MarkCommitted   func()
	HeadersReceived func(int, []Header)
}

// Response is the bounded encoded response body and its ordered fields.
type Response struct {
	Status            int
	Headers           []Header
	Body              []byte
	CompressedBytes   int64
	DecompressedBytes int64
	Truncated         bool
}

func encodeRequestHeaders(request *Request) ([]byte, error) {
	if request.Scheme != "https" && request.Scheme != "http" {
		return nil, errors.New("h2: scheme must be http or https")
	}
	if request.Authority == "" || invalidValue(request.Authority) {
		return nil, errors.New("h2: invalid authority")
	}
	if !strings.HasPrefix(request.Path, "/") || strings.Contains(request.Path, "#") || invalidValue(request.Path) {
		return nil, errors.New("h2: invalid origin-form path")
	}
	if request.Authorization == "" || request.UserAgent == "" || request.IdempotencyKey == "" {
		return nil, errors.New("h2: required field is empty")
	}
	for _, value := range []string{request.Authorization, request.UserAgent, request.IdempotencyKey, request.TraceParent, request.TraceState} {
		if invalidValue(value) {
			return nil, errors.New("h2: invalid field value")
		}
	}
	if request.TraceState != "" && request.TraceParent == "" {
		return nil, errors.New("h2: tracestate requires traceparent")
	}
	if len(request.Body) > maxBodyBytes {
		return nil, errors.New("h2: request exceeds the size limit")
	}

	fields := []hpack.HeaderField{
		{Name: ":method", Value: "POST", Sensitive: true},
		{Name: ":scheme", Value: request.Scheme, Sensitive: true},
		{Name: ":authority", Value: request.Authority, Sensitive: true},
		{Name: ":path", Value: request.Path, Sensitive: true},
		{Name: "content-length", Value: strconv.Itoa(len(request.Body)), Sensitive: true},
		{Name: "authorization", Value: request.Authorization, Sensitive: true},
		{Name: "content-type", Value: "application/json", Sensitive: true},
		{Name: "accept-encoding", Value: "gzip", Sensitive: true},
		{Name: "user-agent", Value: request.UserAgent, Sensitive: true},
		{Name: "idempotency-key", Value: request.IdempotencyKey, Sensitive: true},
	}
	if request.TraceParent != "" {
		fields = append(fields, hpack.HeaderField{Name: "traceparent", Value: request.TraceParent, Sensitive: true})
	}
	if request.TraceState != "" {
		fields = append(fields, hpack.HeaderField{Name: "tracestate", Value: request.TraceState, Sensitive: true})
	}

	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	encoder.SetMaxDynamicTableSizeLimit(0)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			return nil, fmt.Errorf("h2: encode request headers: %w", err)
		}
	}
	return block.Bytes(), nil
}

func invalidValue(value string) bool {
	return strings.ContainsAny(value, "\x00\r\n")
}

func writeHeaderBlock(framer *xhttp2.Framer, streamID uint32, block []byte, endStream bool, maxFrameSize int) error {
	first := min(len(block), maxFrameSize)
	if err := framer.WriteHeaders(xhttp2.HeadersFrameParam{
		StreamID: streamID, BlockFragment: block[:first], EndHeaders: first == len(block), EndStream: endStream,
	}); err != nil {
		return err
	}
	for offset := first; offset < len(block); {
		next := min(offset+maxFrameSize, len(block))
		if err := framer.WriteContinuation(streamID, next == len(block), block[offset:next]); err != nil {
			return err
		}
		offset = next
	}
	return nil
}

func decodeResponseHeaders(frame *xhttp2.MetaHeadersFrame) (Response, *int64, error) {
	if frame.Truncated {
		return Response{}, nil, ErrResponseTooLarge
	}
	pseudos := frame.PseudoFields()
	if len(pseudos) != 1 || pseudos[0].Name != ":status" || len(pseudos[0].Value) != 3 {
		return Response{}, nil, ErrResponseProtocol
	}
	status, err := strconv.Atoi(pseudos[0].Value)
	if err != nil || status < 100 || status > 599 {
		return Response{}, nil, ErrResponseProtocol
	}
	regular := frame.RegularFields()
	if len(regular) > maxHeaderFields {
		return Response{}, nil, ErrResponseTooLarge
	}
	response := Response{Status: status, Headers: make([]Header, 0, len(regular))}
	logicalBytes := 0
	var expected *int64
	for _, field := range regular {
		if field.Name == "" || len(field.Name) > maxHeaderName || len(field.Value) > maxHeaderValue || !utf8.ValidString(field.Value) || invalidResponseValue(field.Value) {
			return Response{}, nil, ErrResponseProtocol
		}
		logicalBytes += len(field.Name) + 2 + len(field.Value) + 2
		if logicalBytes > maxHeaderBytes {
			return Response{}, nil, ErrResponseTooLarge
		}
		if field.Name == "content-length" {
			if expected != nil || !canonicalDecimal(field.Value) {
				return Response{}, nil, ErrResponseProtocol
			}
			length, err := strconv.ParseInt(field.Value, 10, 64)
			if err != nil {
				return Response{}, nil, ErrResponseProtocol
			}
			if length > maxBodyBytes {
				return Response{}, nil, ErrResponseTooLarge
			}
			expected = &length
		}
		response.Headers = append(response.Headers, Header{Name: field.Name, Value: field.Value})
	}
	return response, expected, nil
}

func invalidResponseValue(value string) bool {
	for _, r := range value {
		if r == 0x7f || (r < 0x20 && r != '\t') {
			return true
		}
	}
	return false
}

func canonicalDecimal(value string) bool {
	if value == "0" {
		return true
	}
	if value == "" || value[0] == '0' {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func finalizeResponse(response *Response) (Response, error) {
	encoded := response.Body
	response.CompressedBytes = int64(len(encoded))
	encoding := "identity"
	encodingSeen := false
	for _, field := range response.Headers {
		if field.Name != "content-encoding" {
			continue
		}
		if encodingSeen || !ascii(field.Value) {
			return Response{}, ErrResponseProtocol
		}
		encodingSeen = true
		encoding = strings.ToLower(strings.TrimSpace(field.Value))
		if encoding == "" {
			encoding = "identity"
		}
	}
	limit := maxBodyBytes
	if response.Status < 200 || response.Status >= 300 {
		limit = errorBodyBytes
	}

	var decoded []byte
	switch encoding {
	case "identity":
		decoded = encoded
	case "gzip":
		source := bytes.NewReader(encoded)
		reader, err := gzip.NewReader(source)
		if err != nil {
			return Response{}, ErrResponseProtocol
		}
		reader.Multistream(false)
		decoded, err = io.ReadAll(io.LimitReader(reader, int64(limit)+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil {
			return Response{}, ErrResponseProtocol
		}
		if len(decoded) <= limit && source.Len() != 0 {
			return Response{}, ErrResponseProtocol
		}
	default:
		return Response{}, ErrResponseProtocol
	}
	response.DecompressedBytes = int64(len(decoded))
	if len(decoded) > len(encoded)*maxExpansion {
		return Response{}, ErrResponseTooLarge
	}
	if len(decoded) > limit {
		if response.Status >= 200 && response.Status < 300 {
			return Response{}, ErrResponseTooLarge
		}
		response.Truncated = true
		decoded = decoded[:limit]
	}
	response.Body = decoded
	return *response, nil
}

func ascii(value string) bool {
	for _, char := range value {
		if char > 0x7f {
			return false
		}
	}
	return true
}
