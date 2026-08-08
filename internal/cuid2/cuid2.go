// Package cuid2 generates cuid2-shaped identifiers: 24 characters, a
// lowercase letter first, the rest base36 (lowercase letters and digits),
// from crypto/rand entropy. It matches the documented cuid2 shape, not the
// reference algorithm's session counters and fingerprints — vendored so the
// runtime carries zero third-party dependencies.
package cuid2

import "crypto/rand"

const (
	// Length is the number of characters in a generated id.
	Length = 24

	letters = "abcdefghijklmnopqrstuvwxyz"
	base36  = "0123456789abcdefghijklmnopqrstuvwxyz"
)

// New returns a cuid2-shaped id: Length characters, first a lowercase
// letter, the rest base36.
func New() string {
	id := make([]byte, Length)
	id[0] = letters[randomIndex(len(letters))]
	for i := 1; i < Length; i++ {
		id[i] = base36[randomIndex(len(base36))]
	}
	return string(id)
}

// randomIndex returns an unbiased random index in [0, n) via rejection
// sampling over single crypto/rand bytes. n must be in (0, 256).
func randomIndex(n int) int {
	// The largest multiple of n that fits in a byte; values at or above it
	// are rejected to avoid modulo bias.
	limit := 256 - 256%n
	var b [1]byte
	for {
		// crypto/rand.Read never fails on supported platforms (it aborts the
		// program on entropy failure), so the error is unreachable.
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		if int(b[0]) < limit {
			return int(b[0]) % n
		}
	}
}
