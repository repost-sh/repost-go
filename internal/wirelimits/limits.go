// Package wirelimits owns the response limits shared by custom, HTTP/1.1,
// and HTTP/2 transports.
package wirelimits

// Shared response wire limits.
const (
	BodyBytes        = 1 << 20
	ErrorBodyBytes   = 64 << 10
	ExpansionRatio   = 100
	HeaderFields     = 100
	HeaderBytes      = 64 << 10
	HeaderNameBytes  = 256
	HeaderValueBytes = 8 << 10
)
