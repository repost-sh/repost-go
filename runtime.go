package repost

import (
	"context"
	"errors"
	"time"
)

// Runtime is a construction-time snapshot of client configuration.
type Runtime struct {
	config        *runtimeConfig
	transport     Transport
	ownsTransport bool
	context       context.Context
	cancel        context.CancelFunc
	state         runtimeState
	observer      *observerDispatcher
}

// NewRuntime validates and snapshots options for subsequent sends.
func NewRuntime(options *ClientOptions) (*Runtime, error) {
	if options == nil {
		options = &ClientOptions{}
	}
	config, err := snapshotConfig(options)
	if err != nil {
		return nil, err
	}
	transport := config.transport
	ownsTransport := transport == nil
	if invalid, ok := transport.(interface{ constructionError() *Error }); ok {
		return nil, invalid.constructionError()
	}
	if ownsTransport {
		var transportErr *Error
		transport, transportErr = newRawTransportFromSnapshot(config.httpTransportOptions)
		if transportErr != nil {
			return nil, transportErr
		}
	}
	runtimeContext, cancel := context.WithCancel(context.Background())
	runtime := &Runtime{
		config:        config,
		transport:     transport,
		ownsTransport: ownsTransport,
		context:       runtimeContext,
		cancel:        cancel,
		state:         newRuntimeState(config),
	}
	runtime.observer = newObserverDispatcher(config.observer, &runtime.state)
	return runtime, nil
}

// Send serializes and sends one generated webhook through this runtime's
// construction snapshot.
func (r *Runtime) Send(ctx context.Context, schema SchemaDescriptor, group, member string, input SendInput) (*SendResult, error) {
	deadlineContext, deadlineCancel := operationDeadlineContext(ctx, r.config.operationTimeout)
	defer deadlineCancel()
	permit, admissionErr := r.state.admit(ctx, deadlineContext)
	if admissionErr != nil {
		return nil, admissionErr
	}
	defer permit.release()
	permit.telemetryContext = r.captureTelemetry(ctx)
	operationContext, cancel := context.WithCancel(deadlineContext)
	stopRuntimeCancellation := context.AfterFunc(r.context, cancel)
	stopCallerCancellation := context.AfterFunc(ctx, func() {
		if errors.Is(ctx.Err(), context.Canceled) {
			cancel()
		}
	})
	if r.context.Err() != nil {
		cancel()
	}
	defer stopRuntimeCancellation()
	defer stopCallerCancellation()
	defer cancel()
	return r.sendAdmitted(operationContext, permit, schema, group, member, input)
}

func operationDeadlineContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	remaining := timeout
	if deadline, ok := parent.Deadline(); ok {
		remaining = min(remaining, max(time.Until(deadline), 0))
	}
	return context.WithTimeout(context.WithoutCancel(parent), remaining)
}

// Diagnostics returns one coherent runtime state snapshot.
func (r *Runtime) Diagnostics() RuntimeDiagnostics {
	return r.state.snapshot()
}

// Close rejects new sends, cancels admitted sends, and waits for their
// reservations to be released.
func (r *Runtime) Close() error {
	self := r.observer.isCurrentCallback()
	if !r.state.beginClose() {
		if self {
			return nil
		}
		r.state.waitUntilClosed()
		// A callback-owned shutdown may publish Closed before that callback
		// returns. External callers still wait for dispatcher quiescence.
		r.observer.close()
		return nil
	}
	r.cancel()
	r.state.waitForOperations()
	r.observer.close()
	if r.ownsTransport {
		if transport, ok := r.transport.(interface{ closeIdleConnections() }); ok {
			transport.closeIdleConnections()
		}
	}
	r.state.finishClose()
	return nil
}

// FlushObservers waits until every queued observer event has been delivered
// and the current callback has returned. It is intended for deterministic
// tests.
func (r *Runtime) FlushObservers() {
	if r.observer.isCurrentCallback() {
		return
	}
	r.observer.flush()
}

func cancelledError(deliveryState DeliveryState) *Error {
	return &Error{Code: ErrorCodeCancelled, DeliveryState: deliveryState}
}

func operationError(code ErrorCode) *Error {
	return &Error{Code: code, DeliveryState: DeliveryStateNotSent}
}
