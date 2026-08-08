package repost

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/repost-sh/repost-go/internal/wirelimits"
)

type attemptResponseCloser struct {
	once sync.Once
	fn   func() error
	err  error
}

func (c *attemptResponseCloser) close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		if c.fn != nil {
			c.err = c.fn()
		}
	})
	return c.err
}

// NewAttemptResponse constructs a bounded custom-transport response for
// request. It snapshots caller-owned data and transfers close ownership to
// Runtime.
func NewAttemptResponse(request *AttemptRequest, status int, headers []HeaderField, wireBody []byte, closeFn func() error) (*AttemptResponse, error) {
	response, err := normalizeAttemptResponse(status, headers, wireBody, maxPayloadBytes, closeFn)
	if err != nil {
		return response, err
	}
	response.HeadersReceivedAt, response.HeadersReceivedAtSet, response.HeaderClockFailed = snapshotResponseWallTime(request, status, response.Headers)
	return response, nil
}

func normalizeAttemptResponse(status int, headers []HeaderField, wireBody []byte, compressedLimit int, closeFn func() error) (*AttemptResponse, error) {
	closer := &attemptResponseCloser{fn: closeFn}
	if status < 100 || status > 599 || headers == nil || wireBody == nil {
		_ = closer.close()
		return nil, errors.New("invalid attempt response")
	}
	response := &AttemptResponse{
		Status: status, Headers: append([]HeaderField{}, headers...), Body: []byte{}, normalized: true, closer: closer,
	}
	if fields, headerBytes, valid := validateResponseHeaders(response.Headers); !valid {
		response.markResponseHeaderViolation(fields, headerBytes)
		return response, nil
	}
	encoding, valid := responseContentEncoding(response.Headers)
	if !valid {
		response.protocolViolation = true
		return response, nil
	}
	response.CompressedBytes = int64(len(wireBody))
	if len(wireBody) > compressedLimit {
		if encoding == "identity" {
			response.DecompressedBytes = response.CompressedBytes
			response.limitViolation = true
		} else {
			response.protocolViolation = true
		}
		response.retryForbidden = status < 200 || status >= 300
		return response, nil
	}
	decoded, failure := decodeAttemptResponseBody(encoding, wireBody)
	response.DecompressedBytes = int64(len(decoded))
	if failure != nil {
		response.protocolViolation = true
		response.retryForbidden = status < 200 || status >= 300
		return response, nil
	}
	if len(decoded) > maxPayloadBytes || len(wireBody) > 0 && len(decoded) > len(wireBody)*wirelimits.ExpansionRatio {
		response.protocolViolation = true
		response.retryForbidden = status < 200 || status >= 300
		return response, nil
	}
	if status < 200 || status >= 300 {
		response.Truncated = len(decoded) > wirelimits.ErrorBodyBytes
		return response, nil
	}
	response.Body = decoded
	return response, nil
}

func snapshotAttemptResponse(response *AttemptResponse) *AttemptResponse {
	if response == nil {
		return nil
	}
	snapshot := *response
	if response.Headers != nil {
		snapshot.Headers = append([]HeaderField{}, response.Headers...)
	}
	if response.Body != nil {
		snapshot.Body = append([]byte{}, response.Body...)
	}
	if snapshot.Headers != nil {
		if fields, headerBytes, valid := validateResponseHeaders(snapshot.Headers); !valid {
			snapshot.markResponseHeaderViolation(fields, headerBytes)
		}
	}
	if !snapshot.normalized && !snapshot.protocolViolation && !snapshot.limitViolation && responseExceedsLimits(&snapshot) {
		encoding, _ := responseContentEncoding(snapshot.Headers)
		if encoding == "gzip" {
			snapshot.protocolViolation = true
		} else {
			snapshot.limitViolation = true
		}
	}
	return &snapshot
}

func responseExceedsLimits(response *AttemptResponse) bool {
	if len(response.Body) > maxPayloadBytes || response.CompressedBytes > maxPayloadBytes || response.DecompressedBytes > maxPayloadBytes {
		return true
	}
	if response.CompressedBytes == 0 {
		return response.DecompressedBytes > 0
	}
	return response.DecompressedBytes/response.CompressedBytes > wirelimits.ExpansionRatio ||
		response.DecompressedBytes/response.CompressedBytes == wirelimits.ExpansionRatio && response.DecompressedBytes%response.CompressedBytes > 0
}

func (r *AttemptResponse) markResponseHeaderViolation(fields int, headerBytes int64) {
	if responseHeadersExceedLimit(r.Headers, fields, headerBytes) {
		r.limitViolation = true
		r.retryForbidden = true
		r.headerLimitViolation = true
	} else {
		r.protocolViolation = true
	}
	r.Body = []byte{}
}

func (r *AttemptResponse) close() error {
	if r == nil {
		return nil
	}
	return r.closer.close()
}

func validateResponseHeaders(headers []HeaderField) (fields int, size int64, valid bool) {
	fields, size = headerCounts(headers)
	if responseHeadersExceedLimit(headers, fields, size) {
		return fields, size, false
	}
	for _, header := range headers {
		if !validResponseHeaderName(header.Name) || !validResponseHeaderValue(header.Value) {
			return fields, size, false
		}
	}
	return fields, size, true
}

func responseHeadersExceedLimit(headers []HeaderField, fields int, size int64) bool {
	if fields > wirelimits.HeaderFields || size > wirelimits.HeaderBytes {
		return true
	}
	for _, header := range headers {
		if len(header.Name) > wirelimits.HeaderNameBytes || len(header.Value) > wirelimits.HeaderValueBytes {
			return true
		}
	}
	return false
}

func validResponseHeaderName(name string) bool {
	if name == "" || len(name) > wirelimits.HeaderNameBytes {
		return false
	}
	for i := range name {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

func validResponseHeaderValue(value string) bool {
	if len(value) > wirelimits.HeaderValueBytes || !utf8.ValidString(value) {
		return false
	}
	for _, current := range value {
		if current != '\t' && (current < 0x20 || current == 0x7f) {
			return false
		}
	}
	return true
}

func responseContentEncoding(headers []HeaderField) (string, bool) {
	values := headerValues(headers, "content-encoding")
	if len(values) == 0 {
		return "identity", true
	}
	if len(values) != 1 {
		return "", false
	}
	value := strings.ToLower(values[0])
	return value, value == "identity" || value == "gzip"
}

func decodeAttemptResponseBody(encoding string, wireBody []byte) ([]byte, error) {
	if encoding == "identity" {
		return append([]byte{}, wireBody...), nil
	}
	source := bytes.NewReader(wireBody)
	reader, err := gzip.NewReader(source)
	if err != nil {
		return nil, err
	}
	reader.Multistream(false)
	decoded, readErr := io.ReadAll(io.LimitReader(reader, maxPayloadBytes+2))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || source.Len() != 0 {
		return nil, errors.New("invalid gzip response")
	}
	return decoded, nil
}
