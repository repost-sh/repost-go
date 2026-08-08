package reposttest

import (
	"errors"
	"sync"
	"time"

	repost "github.com/repost-sh/repost-go"
)

const timestampLayout = "2006-01-02T15:04:05.000Z"

// FixedGenerators returns generators that repeat the supplied values.
func FixedGenerators(now time.Time, uuid, cuid string) repost.Generators {
	formatted := now.UTC().Format(timestampLayout)
	return repost.Generators{Now: func() string { return formatted }, UUID: func() string { return uuid }, CUID: func() string { return cuid }}
}

// SequenceGenerators returns three independent, concurrency-safe sequences.
func SequenceGenerators(times []time.Time, uuids, cuids []string) repost.Generators {
	formatted := make([]string, len(times))
	for index, value := range times {
		formatted[index] = value.UTC().Format(timestampLayout)
	}
	return repost.Generators{Now: stringSequence(formatted, "timestamp"), UUID: stringSequence(uuids, "UUID"), CUID: stringSequence(cuids, "CUID")}
}

// FailingGenerators returns generators that panic with err. Runtime converts
// generator panics into its bounded generator-failure surface.
func FailingGenerators(err error) repost.Generators {
	if err == nil {
		err = errors.New("reposttest: generator failure")
	}
	fail := func() string { panic(err) }
	return repost.Generators{Now: fail, UUID: fail, CUID: fail}
}

func stringSequence(values []string, name string) func() string {
	copied := append([]string(nil), values...)
	var mu sync.Mutex
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		if len(copied) == 0 {
			panic("reposttest: " + name + " sequence exhausted")
		}
		value := copied[0]
		copied = copied[1:]
		return value
	}
}

// FixedIdempotencyKeys returns a generator that repeats key.
func FixedIdempotencyKeys(key string) func() (string, error) {
	return func() (string, error) { return key, nil }
}

// SequenceIdempotencyKeys returns a concurrency-safe FIFO generator.
func SequenceIdempotencyKeys(keys ...string) func() (string, error) {
	remaining := append([]string(nil), keys...)
	var mu sync.Mutex
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(remaining) == 0 {
			return "", errors.New("reposttest: idempotency key sequence exhausted")
		}
		value := remaining[0]
		remaining = remaining[1:]
		return value, nil
	}
}

// FailingIdempotencyKeys returns a generator that always returns err.
func FailingIdempotencyKeys(err error) func() (string, error) {
	if err == nil {
		err = errors.New("reposttest: idempotency key failure")
	}
	return func() (string, error) { return "", err }
}

type entropy struct {
	mu     sync.Mutex
	values []int64
	zero   bool
}

// ZeroEntropy always chooses the minimum retry delay.
func ZeroEntropy() repost.RetryEntropy { return &entropy{zero: true} }

// SequenceEntropy consumes values in order and panics on invalid values or exhaustion.
func SequenceEntropy(values ...int64) repost.RetryEntropy {
	return &entropy{values: append([]int64(nil), values...)}
}

func (e *entropy) NextInt64(exclusiveBound int64) int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if exclusiveBound <= 0 {
		panic("reposttest: entropy bound must be positive")
	}
	if e.zero {
		return 0
	}
	if len(e.values) == 0 {
		panic("reposttest: entropy sequence exhausted")
	}
	value := e.values[0]
	e.values = e.values[1:]
	if value < 0 || value >= exclusiveBound {
		panic("reposttest: entropy value outside bound")
	}
	return value
}
