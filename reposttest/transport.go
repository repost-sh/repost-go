package reposttest

import (
	"context"
	"strings"
	"sync"
	"time"

	repost "github.com/repost-sh/repost-go"
)

// RecordedRequest is a credential-free copy of one transport attempt.
type RecordedRequest struct {
	URL             string
	Headers         [][2]string
	Body            []byte
	AttemptNumber   int
	IdempotencyKey  string
	ConnectTimeout  time.Duration
	AttemptTimeout  time.Duration
	CaptureSequence int
}

type script func(context.Context) repost.AttemptOutcome

// ScriptedTransport is a FIFO one-attempt transport for no-network tests.
type ScriptedTransport struct {
	mu       sync.Mutex
	scripts  []script
	requests []RecordedRequest
	sequence int
}

// NewScriptedTransport returns an empty transport.
func NewScriptedTransport() *ScriptedTransport { return &ScriptedTransport{} }

// EnqueueResponse appends one acquired response.
func (t *ScriptedTransport) EnqueueResponse(status int, body string, headers ...[2]string) *ScriptedTransport {
	response := responseOutcome(status, body, headers)
	return t.enqueue(func(context.Context) repost.AttemptOutcome { return response })
}

// EnqueueFailure appends one structured transport failure.
func (t *ScriptedTransport) EnqueueFailure(code repost.ErrorCode, reason repost.FailureReason, committed bool) *ScriptedTransport {
	outcome := repost.AttemptOutcome{Failure: &repost.AttemptFailure{Code: code, FailureReason: reason, Committed: committed}}
	return t.enqueue(func(context.Context) repost.AttemptOutcome { return outcome })
}

// EnqueuePending appends a response controlled by the caller.
func (t *ScriptedTransport) EnqueuePending() *ControlledResponse {
	controlled := &ControlledResponse{result: make(chan repost.AttemptOutcome, 1)}
	t.enqueue(controlled.wait)
	return controlled
}

func (t *ScriptedTransport) enqueue(next script) *ScriptedTransport {
	t.mu.Lock()
	t.scripts = append(t.scripts, next)
	t.mu.Unlock()
	return t
}

// Send records and consumes one scripted attempt. An exhausted script returns
// an invalid empty outcome so Runtime reports a non-retryable custom defect.
func (t *ScriptedTransport) Send(ctx context.Context, request *repost.AttemptRequest) repost.AttemptOutcome {
	t.mu.Lock()
	t.sequence++
	t.requests = append(t.requests, captureRequest(request, t.sequence))
	if len(t.scripts) == 0 {
		t.mu.Unlock()
		return repost.AttemptOutcome{}
	}
	next := t.scripts[0]
	t.scripts = t.scripts[1:]
	t.mu.Unlock()
	return next(ctx)
}

// Requests returns a deep snapshot in capture order.
func (t *ScriptedTransport) Requests() []RecordedRequest {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]RecordedRequest, len(t.requests))
	for index, request := range t.requests {
		result[index] = request
		result[index].Headers = append([][2]string(nil), request.Headers...)
		result[index].Body = append([]byte(nil), request.Body...)
	}
	return result
}

func captureRequest(request *repost.AttemptRequest, sequence int) RecordedRequest {
	result := RecordedRequest{
		URL: request.APIURL, Body: append([]byte(nil), request.Body...), AttemptNumber: request.AttemptNumber,
		ConnectTimeout: request.ConnectTimeout, AttemptTimeout: request.AttemptTimeout, CaptureSequence: sequence,
	}
	for _, header := range request.Headers {
		if strings.EqualFold(header.Name, "authorization") {
			continue
		}
		result.Headers = append(result.Headers, [2]string{header.Name, header.Value})
		if strings.EqualFold(header.Name, "idempotency-key") {
			result.IdempotencyKey = header.Value
		}
	}
	return result
}

func responseOutcome(status int, body string, headers [][2]string) repost.AttemptOutcome {
	fields := make([]repost.HeaderField, len(headers))
	for index, header := range headers {
		fields[index] = repost.HeaderField{Name: header[0], Value: header[1]}
	}
	bodyBytes := []byte(body)
	return repost.AttemptOutcome{Response: &repost.AttemptResponse{
		Status: status, Headers: fields, Body: bodyBytes,
		CompressedBytes: int64(len(bodyBytes)), DecompressedBytes: int64(len(bodyBytes)),
	}}
}

// ControlledResponse settles one pending script. The first settlement wins.
type ControlledResponse struct {
	mu     sync.Mutex
	done   bool
	result chan repost.AttemptOutcome
}

// Complete settles the script with a response.
func (c *ControlledResponse) Complete(status int, body string, headers ...[2]string) bool {
	return c.settle(responseOutcome(status, body, headers))
}

// Fail settles the script with a structured failure.
func (c *ControlledResponse) Fail(code repost.ErrorCode, reason repost.FailureReason, committed bool) bool {
	return c.settle(repost.AttemptOutcome{Failure: &repost.AttemptFailure{Code: code, FailureReason: reason, Committed: committed}})
}

// Cancel settles the script as an uncommitted cancellation.
func (c *ControlledResponse) Cancel() bool {
	return c.Fail(repost.ErrorCodeCancelled, repost.FailureReasonUnknown, false)
}

// IsDone reports whether the controller has settled.
func (c *ControlledResponse) IsDone() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.done
}

func (c *ControlledResponse) settle(outcome repost.AttemptOutcome) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return false
	}
	c.done = true
	c.result <- outcome
	return true
}

func (c *ControlledResponse) wait(ctx context.Context) repost.AttemptOutcome {
	select {
	case outcome := <-c.result:
		return outcome
	case <-ctx.Done():
		c.Cancel()
		return <-c.result
	}
}
