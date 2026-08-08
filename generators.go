package repost

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/repost-sh/repost-go/internal/cuid2"
)

// Generators are the injectable clock and id sources used by the envelope
// timestamp and @default(now()/uuid()/cuid()) injection. Zero-value fields
// fall back to the real implementations — override them for deterministic
// tests (the conformance suite's seam).
type Generators struct {
	// Now returns an ISO-8601 UTC timestamp with millisecond precision:
	// 2006-01-02T15:04:05.000Z.
	Now func() string
	// UUID returns a UUIDv4 string for @default(uuid()).
	UUID func() string
	// CUID returns a cuid2 string for @default(cuid()).
	CUID func() string
}

// timestampLayout is the timestamp canon every runtime pins (JS toISOString
// shape): YYYY-MM-DDTHH:MM:SS.mmmZ — millisecond precision, Z suffix in UTC.
const timestampLayout = "2006-01-02T15:04:05.000Z07:00"

// withDefaults fills nil generators with the real implementations.
func (g Generators) withDefaults() Generators {
	if g.Now == nil {
		g.Now = defaultNow
	}
	if g.UUID == nil {
		g.UUID = defaultUUID
	}
	if g.CUID == nil {
		g.CUID = cuid2.New
	}
	return g
}

// defaultNow formats the current UTC time as [timestampLayout].
func defaultNow() string {
	return time.Now().UTC().Format(timestampLayout)
}

// defaultUUID returns a crypto/rand-based UUIDv4.
func defaultUUID() string {
	var b [16]byte
	// crypto/rand.Read never fails on supported platforms (it aborts the
	// program on entropy failure), so the error is unreachable.
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	var out [36]byte
	hex.Encode(out[:8], b[:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:], b[10:])
	return string(out[:])
}
