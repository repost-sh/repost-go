package repost

// Optional is the tri-state input container used by generated models whenever
// a schema field may be omitted. Its zero value is absent. Present preserves a
// value (including that value's zero value); Null represents explicit JSON
// null and is accepted only when the field descriptor is nullable.
type Optional[T any] struct {
	state optionalState
	value T
}

type optionalState uint8

const (
	optionalAbsent optionalState = iota
	optionalPresent
	optionalNull
)

// Absent returns an omitted Optional value. It is equivalent to the zero value.
func Absent[T any]() Optional[T] { return Optional[T]{} }

// Present returns an Optional containing value.
func Present[T any](value T) Optional[T] {
	return Optional[T]{state: optionalPresent, value: value}
}

// Null returns an explicitly-null Optional value.
func Null[T any]() Optional[T] { return Optional[T]{state: optionalNull} }

// IsAbsent reports whether the field was omitted.
func (o Optional[T]) IsAbsent() bool { return o.state == optionalAbsent }

// IsPresent reports whether the field contains a value.
func (o Optional[T]) IsPresent() bool { return o.state == optionalPresent }

// IsNull reports whether the field is explicitly null.
func (o Optional[T]) IsNull() bool { return o.state == optionalNull }

// Value returns the present value and true, or the type's zero value and false.
func (o Optional[T]) Value() (T, bool) { return o.value, o.state == optionalPresent }

// repostOptional is intentionally private: descriptor-driven serialization,
// not encoding/json or omitempty, owns the wire decision.
func (o Optional[T]) repostOptional() (any, optionalState) { return o.value, o.state }

type optionalCarrier interface {
	repostOptional() (any, optionalState)
}
