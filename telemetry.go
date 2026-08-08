package repost

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Telemetry integrates live operation and attempt span lifecycles.
type Telemetry interface {
	CaptureContext(ctx context.Context) context.Context
	StartOperation(captured context.Context, start TelemetryOperationStart) TelemetryOperation
}

// TelemetryOperation is the live telemetry handle for one operation.
type TelemetryOperation interface {
	Context() context.Context
	StartAttempt(start TelemetryAttemptStart) TelemetryAttempt
	End(end TelemetryOperationEnd)
}

// TelemetryAttempt is the live telemetry handle for one attempt.
type TelemetryAttempt interface {
	PropagationHeaders() [][2]string
	End(end TelemetryAttemptEnd)
}

// TelemetryOperationStart describes an operation start.
type TelemetryOperationStart struct {
	StartedAt int64
}

// TelemetryOperationEnd describes an operation completion.
type TelemetryOperationEnd struct {
	Outcome   ObserverOutcome
	ErrorCode ErrorCode
	Duration  time.Duration
}

// TelemetryAttemptStart describes an attempt start.
type TelemetryAttemptStart struct {
	StartedAt     int64
	AttemptNumber int
}

// TelemetryAttemptEnd describes an attempt completion.
type TelemetryAttemptEnd struct {
	HTTPStatusClass HTTPStatusClass
	Outcome         ObserverOutcome
	ErrorCode       ErrorCode
	Duration        time.Duration
}

type operationObservability struct {
	runtime          *Runtime
	operationID      string
	startedAt        int64
	lastTimestamp    int64
	attemptStartedAt int64
	attemptNumber    int
	summaries        []AttemptSummary
	telemetry        TelemetryOperation
	attemptTelemetry TelemetryAttempt
	transportValues  context.Context
	finished         bool
}

func (r *Runtime) captureTelemetry(ctx context.Context) (captured context.Context) {
	if r.config.telemetry == nil {
		return nil
	}
	defer func() {
		if recover() != nil || captured == nil {
			r.state.addTelemetryFailure()
			captured = nil
		}
	}()
	return r.config.telemetry.CaptureContext(ctx)
}

func (r *Runtime) startObservability(permit *operationPermit, operationID string) *operationObservability {
	o := &operationObservability{
		runtime:       r,
		operationID:   operationID,
		startedAt:     permit.startedNanos,
		lastTimestamp: permit.startedNanos,
		summaries:     make([]AttemptSummary, 0, r.config.maxAttempts),
	}
	o.emit(&ObserverEvent{Kind: ObserverEventKindOperationStart})
	if r.config.telemetry == nil || permit.telemetryContext == nil {
		return o
	}
	func() {
		defer func() {
			if recover() != nil || o.telemetry == nil {
				r.state.addTelemetryFailure()
				o.telemetry = nil
			}
		}()
		o.telemetry = r.config.telemetry.StartOperation(permit.telemetryContext, TelemetryOperationStart{StartedAt: permit.startedNanos})
	}()
	if o.telemetry != nil {
		func() {
			defer func() {
				if recover() != nil || o.transportValues == nil {
					r.state.addTelemetryFailure()
					o.transportValues = nil
				}
			}()
			o.transportValues = o.telemetry.Context()
		}()
	}
	return o
}

func (o *operationObservability) context(base context.Context) context.Context {
	if o == nil || o.transportValues == nil {
		return base
	}
	return telemetryValueContext{Context: base, values: o.transportValues}
}

type telemetryValueContext struct {
	context.Context
	values context.Context
}

func (c telemetryValueContext) Value(key any) any { return c.values.Value(key) }

func (o *operationObservability) startAttempt(attempt int) []HeaderField {
	if o == nil || o.finished {
		return nil
	}
	o.attemptNumber = attempt
	o.attemptStartedAt = o.sample()
	o.emit(&ObserverEvent{Kind: ObserverEventKindAttemptStart, AttemptNumber: attempt})
	if o.telemetry == nil {
		return nil
	}
	func() {
		defer func() {
			if recover() != nil || o.attemptTelemetry == nil {
				o.runtime.state.addTelemetryFailure()
				o.attemptTelemetry = nil
			}
		}()
		o.attemptTelemetry = o.telemetry.StartAttempt(TelemetryAttemptStart{StartedAt: o.attemptStartedAt, AttemptNumber: attempt})
	}()
	if o.attemptTelemetry == nil {
		return nil
	}
	var pairs [][2]string
	func() {
		defer func() {
			if recover() != nil {
				o.runtime.state.addTelemetryFailure()
				pairs = nil
			}
		}()
		pairs = o.attemptTelemetry.PropagationHeaders()
	}()
	return authorizedPropagationHeaders(pairs)
}

func authorizedPropagationHeaders(pairs [][2]string) []HeaderField {
	var traceparent, tracestate *HeaderField
	for _, pair := range pairs {
		switch {
		case strings.EqualFold(pair[0], "traceparent") && traceparent == nil:
			field := HeaderField{Name: pair[0], Value: pair[1]}
			traceparent = &field
		case strings.EqualFold(pair[0], "tracestate") && tracestate == nil:
			field := HeaderField{Name: pair[0], Value: pair[1]}
			tracestate = &field
		}
	}
	if traceparent == nil {
		return nil
	}
	result := []HeaderField{*traceparent}
	if tracestate != nil {
		result = append(result, *tracestate)
	}
	return result
}

func (o *operationObservability) endAttempt(err *Error, retryable bool) {
	if o == nil || o.attemptNumber == 0 {
		return
	}
	endedAt := o.sample()
	duration := nonnegativeDuration(endedAt - o.attemptStartedAt)
	outcome := o.outcome(err)
	if retryable {
		outcome = ObserverOutcomeRetryableFailure
	}
	var status HTTPStatusClass
	var code ErrorCode
	var delivery DeliveryState
	if err != nil {
		status, code, delivery = httpStatusClass(err.HTTPStatus), err.Code, err.DeliveryState
	} else {
		status, delivery = HTTPStatusClassSuccess, DeliveryStateAccepted
	}
	summary := AttemptSummary{AttemptNumber: o.attemptNumber, Outcome: outcome, ErrorCode: code, DeliveryState: delivery, HTTPStatusClass: status, Duration: duration}
	if len(o.summaries) < 10 {
		o.summaries = append(o.summaries, summary)
	}
	o.emit(&ObserverEvent{
		Kind: ObserverEventKindAttemptEnd, AttemptNumber: o.attemptNumber, Duration: duration,
		Outcome: outcome, ErrorCode: code, DeliveryState: delivery, HTTPStatusClass: status,
	})
	if o.attemptTelemetry != nil {
		func() {
			defer func() {
				if recover() != nil {
					o.runtime.state.addTelemetryFailure()
				}
			}()
			o.attemptTelemetry.End(TelemetryAttemptEnd{HTTPStatusClass: status, Outcome: outcome, ErrorCode: code, Duration: duration})
		}()
	}
	o.attemptTelemetry = nil
	o.attemptNumber = 0
}

func (o *operationObservability) retry(delay time.Duration, err *Error) {
	if o == nil || o.finished || err == nil {
		return
	}
	o.emit(&ObserverEvent{
		Kind: ObserverEventKindRetryDelay, AttemptNumber: err.AttemptCount,
		Outcome: ObserverOutcomeRetryableFailure, ErrorCode: err.Code,
		DeliveryState: err.DeliveryState, HTTPStatusClass: httpStatusClass(err.HTTPStatus), RetryDelay: delay,
	})
}

func (o *operationObservability) finish(err error) {
	if o == nil || o.finished {
		return
	}
	o.finished = true
	var repostErr *Error
	_ = errors.As(err, &repostErr)
	o.endAttempt(repostErr, false)
	outcome, code, delivery, status := o.outcome(repostErr), ErrorCode(""), DeliveryStateAccepted, HTTPStatusClassSuccess
	if repostErr != nil {
		code, delivery, status = repostErr.Code, repostErr.DeliveryState, httpStatusClass(repostErr.HTTPStatus)
	}
	if outcome == ObserverOutcomeCancelled {
		o.emit(&ObserverEvent{Kind: ObserverEventKindOperationCancel, Outcome: outcome, ErrorCode: code, DeliveryState: delivery, HTTPStatusClass: status})
	}
	endedAt := o.sample()
	duration := nonnegativeDuration(endedAt - o.startedAt)
	if o.telemetry != nil {
		func() {
			defer func() {
				if recover() != nil {
					o.runtime.state.addTelemetryFailure()
				}
			}()
			o.telemetry.End(TelemetryOperationEnd{Outcome: outcome, ErrorCode: code, Duration: duration})
		}()
	}
	o.emitAt(&ObserverEvent{
		Kind: ObserverEventKindOperationEnd, Duration: duration, Outcome: outcome, ErrorCode: code,
		DeliveryState: delivery, HTTPStatusClass: status, OperationStartedAt: o.startedAt,
		OperationEndedAt: endedAt, AttemptSummaries: o.summaries,
	}, endedAt)
}

func (o *operationObservability) emit(event *ObserverEvent) {
	if o == nil || o.runtime.observer == nil {
		return
	}
	o.emitAt(event, o.sample())
}

func (o *operationObservability) emitAt(event *ObserverEvent, timestamp int64) {
	if o == nil || o.runtime.observer == nil {
		return
	}
	event.SchemaVersion = 1
	event.OperationID = o.operationID
	event.Timestamp = timestamp
	o.runtime.observer.emit(event)
}

func (o *operationObservability) sample() int64 {
	if o == nil {
		return 0
	}
	now, ok := callMonotonicClock(o.runtime.config.monotonicClock)
	if ok && now > o.lastTimestamp {
		o.lastTimestamp = now
	}
	return o.lastTimestamp
}

func outcomeForError(err *Error) ObserverOutcome {
	if err == nil {
		return ObserverOutcomeAccepted
	}
	switch err.Code {
	case ErrorCodeCancelled:
		return ObserverOutcomeCancelled
	case ErrorCodeClosed:
		return ObserverOutcomeClosed
	}
	if err.DeliveryState == DeliveryStateRejected {
		return ObserverOutcomeRejected
	}
	return ObserverOutcomeFailed
}

func (o *operationObservability) outcome(err *Error) ObserverOutcome {
	if err != nil && err.Code == ErrorCodeCancelled && o.runtime.context.Err() != nil {
		return ObserverOutcomeClosed
	}
	return outcomeForError(err)
}

func httpStatusClass(status int) HTTPStatusClass {
	switch {
	case status >= 200 && status < 300:
		return HTTPStatusClassSuccess
	case status >= 300 && status < 400:
		return HTTPStatusClassRedirection
	case status >= 400 && status < 500:
		return HTTPStatusClassClientError
	case status >= 500 && status < 600:
		return HTTPStatusClassServerError
	default:
		return ""
	}
}

func nonnegativeDuration(nanos int64) time.Duration {
	if nanos < 0 {
		return 0
	}
	return time.Duration(nanos)
}
