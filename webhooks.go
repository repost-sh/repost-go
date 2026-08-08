package repost

import (
	"context"
	"encoding/json"
	"time"
)

// RetryEntropy supplies uniform retry jitter in [0, exclusiveBound).
type RetryEntropy interface {
	NextInt64(exclusiveBound int64) int64
}

// Scheduler waits without preventing context cancellation.
type Scheduler interface {
	Sleep(context.Context, time.Duration) error
}

// ClientOptions configures a generated client's sends. Runtime construction
// snapshots the values and relevant environment variables, so later mutation
// does not alter that runtime.
type ClientOptions struct {
	// APIKey is the environment's publish API key (created with the
	// environment in the dashboard). At runtime construction, empty means
	// REPOST_SEND_API_KEY — the variable `repost schema init` scaffolds into
	// .env — then legacy REPOST_TOKEN.
	APIKey string
	// APIURL is the API base URL. At runtime construction, empty means the
	// snapshotted REPOST_API_URL, then https://api.repost.sh.
	APIURL string
	// Transport overrides how sends reach Repost. Nil means the HTTP
	// transport against the publish API; pass [StubTransport] for no-network
	// tests.
	Transport Transport
	// Generators are the injectable clock and id sources, used by the
	// envelope timestamp and @default(now()/uuid()/cuid()) injection.
	// Zero-value fields default to the real ones.
	Generators Generators

	// APIKeyProvider supplies a credential once per operation. It is mutually
	// exclusive with a fixed APIKey; callback errors fail before sending.
	APIKeyProvider func(context.Context) (string, error)
	// HTTPTransportOptions configures the built-in transport and is mutually
	// exclusive with Transport. Construction copies the value; references it
	// contains remain borrowed for the runtime's lifetime.
	HTTPTransportOptions *HTTPTransportOptions
	// ConnectTimeout is the connection budget. Nil defaults to 10s; values
	// must be positive whole milliseconds at most 9,223,372,036,854ms.
	ConnectTimeout *time.Duration
	// AttemptTimeout is each HTTP attempt's budget. Nil defaults to 30s;
	// values have the same duration range as ConnectTimeout.
	AttemptTimeout *time.Duration
	// OperationTimeout is the total operation budget. Nil defaults to 120s;
	// values have the same duration range as ConnectTimeout.
	OperationTimeout *time.Duration
	// MaxAttempts includes the first attempt. Nil defaults to 4; valid values
	// are 1 through 10.
	MaxAttempts *int
	// RetryBaseDelay is the initial retry delay. Nil defaults to 250ms; values
	// have the duration range above and cannot exceed RetryMaxDelay.
	RetryBaseDelay *time.Duration
	// RetryMaxDelay caps retry delay. Nil defaults to 60s; values have the
	// duration range above.
	RetryMaxDelay *time.Duration
	// MaxInFlightOperations limits concurrent operations. Nil defaults to 256;
	// valid values are 1 through 65,536.
	MaxInFlightOperations *int
	// MaxBufferedBytes limits buffered operation data. Nil defaults to
	// 67,108,864; valid values are 4,194,304 through 1,073,741,824.
	MaxBufferedBytes *int64
	// IdempotencyKeyGenerator runs once when an operation has no caller key.
	// Nil uses a crypto-random cuid2; callback errors fail before sending.
	IdempotencyKeyGenerator func() (string, error)
	// RetryEntropy supplies retry jitter and is borrowed for the runtime's
	// lifetime. Nil uses crypto/rand with uniform positive bounds.
	RetryEntropy RetryEntropy
	// MonotonicClock returns elapsed nanoseconds from an arbitrary monotonic
	// origin. Nil uses time.Since; a supplied function is borrowed.
	MonotonicClock func() int64
	// WallClock supplies current wall time when needed. Nil uses time.Now; a
	// supplied function is borrowed for the runtime's lifetime.
	WallClock func() time.Time
	// Scheduler performs context-cancellable retry waits and is borrowed for
	// the runtime's lifetime. Nil uses timers; Sleep errors stop the operation.
	Scheduler Scheduler
	// Observer receives bounded, serialized lifecycle events off the send path.
	Observer Observer
	// Telemetry receives the live operation and attempt lifecycle inline.
	Telemetry Telemetry
	// UserAgentSuffix appends product identification. Nil omits it; values
	// must be 1–256 printable ASCII bytes without leading or trailing spaces.
	UserAgentSuffix *string

	apiKeySet bool
}

// SetAPIKey records value as an explicitly configured fixed credential,
// including the empty string, which construction rejects as invalid.
func (o *ClientOptions) SetAPIKey(value string) {
	o.APIKey = value
	o.apiKeySet = true
}

// SendInput is the per-send input a generated send method forwards.
type SendInput struct {
	// CustomerID is the receiving tenant.
	CustomerID string
	// Data is the payload to serialize: a generated model struct (or
	// pointer) with `repost` tags, or a map[string]any keyed by field name.
	Data any
	// IdempotencyKey is the caller-owned idempotency key (e.g. "order-42"):
	// the server dedups it for 24h. Empty means the transport mints one per
	// send, deduplicating internal retries only.
	IdempotencyKey string
}

// StubTransport is the no-network one-attempt transport for tests.
type StubTransport struct{}

// Send implements [Transport] without touching the network.
func (StubTransport) Send(_ context.Context, req *AttemptRequest) AttemptOutcome {
	var sent struct {
		Type       string `json:"type"`
		CustomerID string `json:"customerId"`
		Timestamp  string `json:"timestamp"`
	}
	if json.Unmarshal(req.Body, &sent) != nil {
		return AttemptOutcome{Failure: &AttemptFailure{Code: ErrorCodeIO}}
	}
	body, _ := json.Marshal(SendResult{ID: "msg_stub", Type: sent.Type, CustomerID: sent.CustomerID, Timestamp: sent.Timestamp})
	return AttemptOutcome{Response: &AttemptResponse{
		Status: statusAccepted, Headers: []HeaderField{{Name: "content-type", Value: "application/json"}}, Body: body,
		CompressedBytes: int64(len(body)), DecompressedBytes: int64(len(body)),
	}}
}
