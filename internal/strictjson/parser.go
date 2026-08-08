// Package strictjson parses one bounded, scalar-valid JSON document without
// accepting duplicate object keys.
package strictjson

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"
)

// Parser limits applied to every response document.
const (
	MaxDocumentBytes         = 1_048_576
	MaxNestingDepth          = 32
	MaxTokens                = 10_000
	MaxFieldNameUTF8Bytes    = 64
	MaxScalarStringUTF8Bytes = 8_192
	MaxScalarStringChars     = 8_192
	MaxNumberChars           = 128
	MaxMembersPerObject      = 16
)

// Failure is the stable reason a document was rejected.
type Failure uint8

// Parser failure kinds.
const (
	FailureNone Failure = iota
	FailureProtocol
	FailureLimit
)

// Error contains no input or parser details.
type Error struct {
	Kind Failure
}

// Error returns a stable, input-independent message.
func (e *Error) Error() string {
	if e != nil && e.Kind == FailureLimit {
		return "JSON limit exceeded"
	}
	return "invalid JSON"
}

// Parse validates and decodes exactly one JSON value. Numbers are returned as
// json.Number so decoding never rounds them.
func Parse(data []byte) (any, *Error) {
	if len(data) > MaxDocumentBytes {
		return nil, limitError()
	}
	if len(data) >= 3 && bytes.Equal(data[:3], []byte{0xef, 0xbb, 0xbf}) || !utf8.Valid(data) {
		return nil, protocolError()
	}
	scanner := scanner{data: data}
	if err := scanner.parse(); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, protocolError()
	}
	return value, nil
}

type scanner struct {
	data   []byte
	index  int
	tokens int
}

func (s *scanner) parse() *Error {
	s.whitespace()
	if err := s.value(0); err != nil {
		return err
	}
	s.whitespace()
	if s.index != len(s.data) {
		return protocolError()
	}
	return nil
}

func (s *scanner) value(depth int) *Error {
	s.whitespace()
	if s.index >= len(s.data) {
		return protocolError()
	}
	switch s.data[s.index] {
	case '{':
		return s.object(depth + 1)
	case '[':
		return s.array(depth + 1)
	case '"':
		if err := s.token(); err != nil {
			return err
		}
		_, err := s.string(false)
		return err
	case 't':
		return s.literal("true")
	case 'f':
		return s.literal("false")
	case 'n':
		return s.literal("null")
	default:
		return s.number()
	}
}

func (s *scanner) object(depth int) *Error {
	if depth > MaxNestingDepth {
		return limitError()
	}
	if err := s.token(); err != nil {
		return err
	}
	s.index++
	s.whitespace()
	if s.consume('}') {
		return s.token()
	}
	keys := make(map[string]struct{}, MaxMembersPerObject)
	for members := 1; ; members++ {
		s.whitespace()
		if s.index >= len(s.data) || s.data[s.index] != '"' {
			return protocolError()
		}
		if err := s.token(); err != nil {
			return err
		}
		key, err := s.string(true)
		if err != nil {
			return err
		}
		if _, duplicate := keys[key]; duplicate {
			return protocolError()
		}
		keys[key] = struct{}{}
		if members > MaxMembersPerObject {
			return limitError()
		}
		s.whitespace()
		if !s.consume(':') {
			return protocolError()
		}
		if err := s.value(depth); err != nil {
			return err
		}
		s.whitespace()
		if s.consume('}') {
			return s.token()
		}
		if !s.consume(',') {
			return protocolError()
		}
	}
}

func (s *scanner) array(depth int) *Error {
	if depth > MaxNestingDepth {
		return limitError()
	}
	if err := s.token(); err != nil {
		return err
	}
	s.index++
	s.whitespace()
	if s.consume(']') {
		return s.token()
	}
	for {
		if err := s.value(depth); err != nil {
			return err
		}
		s.whitespace()
		if s.consume(']') {
			return s.token()
		}
		if !s.consume(',') {
			return protocolError()
		}
	}
}

func (s *scanner) string(fieldName bool) (string, *Error) {
	start := s.index
	s.index++
	for s.index < len(s.data) {
		switch s.data[s.index] {
		case '"':
			s.index++
			var value string
			if err := json.Unmarshal(s.data[start:s.index], &value); err != nil {
				return "", protocolError()
			}
			if fieldName {
				if len(value) > MaxFieldNameUTF8Bytes {
					return "", limitError()
				}
			} else if len(value) > MaxScalarStringUTF8Bytes || utf8.RuneCountInString(value) > MaxScalarStringChars {
				return "", limitError()
			}
			return value, nil
		case '\\':
			if err := s.escape(); err != nil {
				return "", err
			}
		default:
			if s.data[s.index] < 0x20 {
				return "", protocolError()
			}
			s.index++
		}
	}
	return "", protocolError()
}

func (s *scanner) escape() *Error {
	if s.index+1 >= len(s.data) {
		return protocolError()
	}
	switch s.data[s.index+1] {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		s.index += 2
		return nil
	case 'u':
		value, ok := s.hexUnit(s.index + 2)
		if !ok {
			return protocolError()
		}
		s.index += 6
		if value >= 0xd800 && value <= 0xdbff {
			if s.index+6 > len(s.data) || s.data[s.index] != '\\' || s.data[s.index+1] != 'u' {
				return protocolError()
			}
			low, ok := s.hexUnit(s.index + 2)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return protocolError()
			}
			s.index += 6
		} else if value >= 0xdc00 && value <= 0xdfff {
			return protocolError()
		}
		return nil
	default:
		return protocolError()
	}
}

func (s *scanner) hexUnit(offset int) (uint16, bool) {
	if offset+4 > len(s.data) {
		return 0, false
	}
	var value uint16
	for _, digit := range s.data[offset : offset+4] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value += uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value += uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value += uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func (s *scanner) literal(value string) *Error {
	if len(s.data)-s.index < len(value) || string(s.data[s.index:s.index+len(value)]) != value {
		return protocolError()
	}
	if err := s.token(); err != nil {
		return err
	}
	s.index += len(value)
	return nil
}

func (s *scanner) number() *Error {
	start := s.index
	if s.consume('-') && s.index >= len(s.data) {
		return protocolError()
	}
	if s.consume('0') {
		if s.index < len(s.data) && isDigit(s.data[s.index]) {
			return protocolError()
		}
	} else {
		if s.index >= len(s.data) || s.data[s.index] < '1' || s.data[s.index] > '9' {
			return protocolError()
		}
		for s.index < len(s.data) && isDigit(s.data[s.index]) {
			s.index++
		}
	}
	if s.consume('.') {
		if s.index >= len(s.data) || !isDigit(s.data[s.index]) {
			return protocolError()
		}
		for s.index < len(s.data) && isDigit(s.data[s.index]) {
			s.index++
		}
	}
	if s.index < len(s.data) && (s.data[s.index] == 'e' || s.data[s.index] == 'E') {
		s.index++
		if s.index < len(s.data) && (s.data[s.index] == '+' || s.data[s.index] == '-') {
			s.index++
		}
		if s.index >= len(s.data) || !isDigit(s.data[s.index]) {
			return protocolError()
		}
		for s.index < len(s.data) && isDigit(s.data[s.index]) {
			s.index++
		}
	}
	if s.index-start > MaxNumberChars {
		return limitError()
	}
	return s.token()
}

func (s *scanner) whitespace() {
	for s.index < len(s.data) {
		switch s.data[s.index] {
		case ' ', '\t', '\n', '\r':
			s.index++
		default:
			return
		}
	}
}

func (s *scanner) token() *Error {
	s.tokens++
	if s.tokens > MaxTokens {
		return limitError()
	}
	return nil
}

func (s *scanner) consume(value byte) bool {
	if s.index >= len(s.data) || s.data[s.index] != value {
		return false
	}
	s.index++
	return true
}

func isDigit(value byte) bool { return value >= '0' && value <= '9' }

func protocolError() *Error { return &Error{Kind: FailureProtocol} }
func limitError() *Error    { return &Error{Kind: FailureLimit} }
