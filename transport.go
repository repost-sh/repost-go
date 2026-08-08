package repost

import (
	"context"
	"sync/atomic"
	"time"
)

const (
	defaultAPIURL = "https://api.repost.sh"
	// maxPayloadBytes is the publish API's request and response body cap.
	maxPayloadBytes         = 1 << 20
	retryAfterCap           = 60 * time.Second
	httpDateLayout          = "Mon, 02 Jan 2006 15:04:05 GMT"
	statusAccepted          = 202
	statusConflict          = 409
	statusProxyAuthRequired = 407
	statusTooManyRequests   = 429
)

// SendResult is the result of a webhook send, as returned by Repost's
// publish API.
type SendResult struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	CustomerID string `json:"customerId"`
	Timestamp  string `json:"timestamp"`
}

// HeaderField preserves wire order and duplicates for strict response checks.
type HeaderField struct {
	Name  string
	Value string
}

// CommitTracker records when an attempt may have written request bytes.
type CommitTracker struct{ committed atomic.Bool }

// MarkCommitted records a possibly-sent attempt.
func (c *CommitTracker) MarkCommitted() {
	if c != nil {
		c.committed.Store(true)
	}
}

func (c *CommitTracker) isCommitted() bool { return c != nil && c.committed.Load() }

// AttemptRequest is the immutable request for one transport attempt.
type AttemptRequest struct {
	OperationID              string
	APIURL                   string
	Headers                  []HeaderField
	Body                     []byte
	AttemptNumber            int
	ConnectTimeout           time.Duration
	AttemptTimeout           time.Duration
	CommitTracker            *CommitTracker
	SnapshotResponseWallTime func() (time.Time, bool)
}

// AttemptResponse is a bounded one-attempt HTTP response.
type AttemptResponse struct {
	Status               int
	Headers              []HeaderField
	Body                 []byte
	CompressedBytes      int64
	DecompressedBytes    int64
	Truncated            bool
	HeadersReceivedAt    time.Time
	HeadersReceivedAtSet bool
	HeaderClockFailed    bool
	protocolViolation    bool
	limitViolation       bool
	incomplete           bool
	retryForbidden       bool
	headerLimitViolation bool
	attemptFailureCode   ErrorCode
	attemptFailureReason FailureReason
	normalized           bool
	closer               *attemptResponseCloser
}

// AttemptFailure is a classified one-attempt transport failure.
type AttemptFailure struct {
	Code          ErrorCode
	FailureReason FailureReason
	Committed     bool
	causeCategory CauseCategory
}

// AttemptOutcome contains exactly one response or failure.
type AttemptOutcome struct {
	Response *AttemptResponse
	Failure  *AttemptFailure
}

// Transport performs exactly one attempt. Retry policy belongs to Runtime.
type Transport interface {
	Send(context.Context, *AttemptRequest) AttemptOutcome
}

// NewHTTPTransport returns the built-in raw one-attempt transport.
func NewHTTPTransport(options HTTPTransportOptions) Transport {
	transport, err := newRawTransport(options)
	if err != nil {
		return invalidHTTPTransport{err: err}
	}
	return transport
}

type invalidHTTPTransport struct{ err *Error }

func (t invalidHTTPTransport) constructionError() *Error { return t.err }

func (invalidHTTPTransport) Send(context.Context, *AttemptRequest) AttemptOutcome {
	return rawFailure(ErrorCodeIO, FailureReasonUnknown, false)
}
