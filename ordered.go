package repost

import (
	"bytes"
	"encoding/json"
	"errors"
)

var errJSONLimit = errors.New("JSON size limit exceeded")

// OrderedObject is an insertion-ordered string-keyed JSON object. The wire
// contract pins key order (descriptor declaration order), which Go maps
// cannot represent — every serialized payload is an *OrderedObject. Nested
// values may themselves be *OrderedObject, []any, primitives, or
// json.RawMessage.
type OrderedObject struct {
	keys   []string
	values map[string]any
}

// NewOrderedObject returns an empty ordered object.
func NewOrderedObject() *OrderedObject {
	return &OrderedObject{values: make(map[string]any)}
}

// Set stores value under key, appending the key on first insertion and
// keeping its original position on overwrite.
func (o *OrderedObject) Set(key string, value any) {
	if _, exists := o.values[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

// MarshalJSON renders the object as compact JSON in insertion order, UTF-8
// without unnecessary escaping (no HTML escaping of <, >, &).
func (o *OrderedObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		encodedKey, err := encodeJSONValue(key)
		if err != nil {
			return nil, err
		}
		buf.Write(encodedKey)
		buf.WriteByte(':')
		encodedValue, err := encodeJSONValue(o.values[key])
		if err != nil {
			return nil, err
		}
		buf.Write(encodedValue)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func (o *OrderedObject) marshalJSONLimit(limit int) ([]byte, error) {
	encoder := limitedJSONEncoder{limit: limit}
	if err := encoder.value(o); err != nil && !errors.Is(err, errJSONLimit) {
		return nil, err
	}
	return encoder.buffer.Bytes(), nil
}

type limitedJSONEncoder struct {
	buffer bytes.Buffer
	limit  int
}

func (e *limitedJSONEncoder) write(data []byte) error {
	remaining := e.limit + 1 - e.buffer.Len()
	if remaining <= 0 {
		return errJSONLimit
	}
	if len(data) > remaining {
		data = data[:remaining]
	}
	_, _ = e.buffer.Write(data)
	if e.buffer.Len() > e.limit {
		return errJSONLimit
	}
	return nil
}

func (e *limitedJSONEncoder) byte(value byte) error { return e.write([]byte{value}) }

func (e *limitedJSONEncoder) value(value any) error {
	switch current := value.(type) {
	case *OrderedObject:
		if err := e.byte('{'); err != nil {
			return err
		}
		for index, key := range current.keys {
			if index > 0 {
				if err := e.byte(','); err != nil {
					return err
				}
			}
			if err := e.value(key); err != nil {
				return err
			}
			if err := e.byte(':'); err != nil {
				return err
			}
			if err := e.value(current.values[key]); err != nil {
				return err
			}
		}
		return e.byte('}')
	case []any:
		if err := e.byte('['); err != nil {
			return err
		}
		for index, item := range current {
			if index > 0 {
				if err := e.byte(','); err != nil {
					return err
				}
			}
			if err := e.value(item); err != nil {
				return err
			}
		}
		return e.byte(']')
	case string:
		if len(current)+2 > e.limit+1-e.buffer.Len() {
			return e.fillLimit()
		}
	}
	encoded, err := encodeJSONValue(value)
	if err != nil {
		return err
	}
	return e.write(encoded)
}

func (e *limitedJSONEncoder) fillLimit() error {
	remaining := e.limit + 1 - e.buffer.Len()
	if remaining > 0 {
		_, _ = e.buffer.Write(make([]byte, remaining))
	}
	return errJSONLimit
}

// encodeJSONValue marshals value compactly without HTML escaping —
// encoding/json escapes <, >, and & by default; json.Encoder with
// SetEscapeHTML(false) does not (non-ASCII like ü is never escaped either
// way). The encoder's trailing newline is trimmed.
func encodeJSONValue(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
