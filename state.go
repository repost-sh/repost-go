package repost

import (
	"context"
	"math"
	"sync"
	"time"
)

const (
	requestWorkspaceBytes            = int64(1_048_576)
	responseWorkspaceBytes           = int64(1_048_576)
	parserScratchBytes               = int64(262_144)
	initialOperationReservationBytes = requestWorkspaceBytes + responseWorkspaceBytes + parserScratchBytes
	maximumDiagnosticCounter         = int64(9_007_199_254_740_991)
)

// RuntimeDiagnostics is one coherent snapshot of runtime admission and
// lifecycle state.
type RuntimeDiagnostics struct {
	InFlightOperations            int
	BufferedBytes                 int64
	ConcurrencyOverloadRejections int64
	ByteOverloadRejections        int64
	ResponseHeaderLimitFailures   int64
	ResponseCloseFailures         int64
	DroppedObserverEvents         int64
	ObserverFailures              int64
	TelemetryFailures             int64
	Closed                        bool
}

type runtimeState struct {
	mu sync.Mutex
	wg sync.WaitGroup

	maxInFlightOperations int
	maxBufferedBytes      int64
	operationTimeout      time.Duration
	monotonicClock        func() int64
	diagnostics           RuntimeDiagnostics
	closing               bool
	closeDone             chan struct{}
}

func (s *runtimeState) recordResponseHeaderLimitFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	saturatingAdd(&s.diagnostics.ResponseHeaderLimitFailures, 1)
}

func (s *runtimeState) recordResponseCloseFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	saturatingAdd(&s.diagnostics.ResponseCloseFailures, 1)
}

type operationPermit struct {
	ownershipMu       sync.Mutex
	activeCalls       int
	releaseRequested  bool
	state             *runtimeState
	heldBytes         int64
	startedNanos      int64
	exclusiveDeadline int64
	released          bool
	deadlineContext   context.Context
	callerContext     context.Context
	telemetryContext  context.Context
}

func newRuntimeState(config *runtimeConfig) runtimeState {
	return runtimeState{
		maxInFlightOperations: config.maxInFlightOperations,
		maxBufferedBytes:      config.maxBufferedBytes,
		operationTimeout:      config.operationTimeout,
		monotonicClock:        config.monotonicClock,
		closeDone:             make(chan struct{}),
	}
}

func (s *runtimeState) admit(ctx, deadlineContext context.Context) (*operationPermit, *Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.diagnostics.Closed {
		return nil, &Error{Code: ErrorCodeClosed, DeliveryState: DeliveryStateNotSent}
	}
	if s.diagnostics.InFlightOperations >= s.maxInFlightOperations {
		saturatingAdd(&s.diagnostics.ConcurrencyOverloadRejections, 1)
		return nil, &Error{Code: ErrorCodeOverloaded, DeliveryState: DeliveryStateNotSent}
	}
	if s.diagnostics.BufferedBytes > s.maxBufferedBytes-initialOperationReservationBytes {
		saturatingAdd(&s.diagnostics.ByteOverloadRejections, 1)
		return nil, &Error{Code: ErrorCodeOverloaded, DeliveryState: DeliveryStateNotSent}
	}

	if deadlineContext.Err() != nil {
		return nil, &Error{Code: ErrorCodeOperationDeadline, DeliveryState: DeliveryStateNotSent}
	}
	started, ok := callMonotonicClock(s.monotonicClock)
	if !ok {
		return nil, hookConfigurationError(DeliveryStateNotSent, "", "", 0,
			ClientOptionKeyMonotonicClock, CauseCategoryUnknown)
	}
	deadline := addNanosSaturated(started, s.operationTimeout.Nanoseconds())
	if parentDeadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(parentDeadline)
		if remaining < 0 {
			remaining = 0
		}
		if parent := addNanosSaturated(started, remaining.Nanoseconds()); parent < deadline {
			deadline = parent
		}
	}
	s.diagnostics.InFlightOperations++
	s.diagnostics.BufferedBytes += initialOperationReservationBytes
	s.wg.Add(1)
	return &operationPermit{
		state:             s,
		heldBytes:         initialOperationReservationBytes,
		startedNanos:      started,
		exclusiveDeadline: deadline,
		deadlineContext:   deadlineContext,
		callerContext:     ctx,
	}, nil
}

func (p *operationPermit) release() {
	p.ownershipMu.Lock()
	p.releaseRequested = true
	finalize := p.activeCalls == 0 && !p.released
	if finalize {
		p.released = true
	}
	p.ownershipMu.Unlock()
	if finalize {
		p.finishRelease()
	}
}

func (p *operationPermit) beginCall() {
	p.ownershipMu.Lock()
	p.activeCalls++
	p.ownershipMu.Unlock()
}

func (p *operationPermit) endCall() {
	p.ownershipMu.Lock()
	p.activeCalls--
	finalize := p.activeCalls == 0 && p.releaseRequested && !p.released
	if finalize {
		p.released = true
	}
	p.ownershipMu.Unlock()
	if finalize {
		p.finishRelease()
	}
}

func (p *operationPermit) finishRelease() {
	p.state.mu.Lock()
	p.state.diagnostics.InFlightOperations--
	p.state.diagnostics.BufferedBytes -= p.heldBytes
	p.state.mu.Unlock()
	p.state.wg.Done()
}

func (p *operationPermit) shrinkRequest(serializedBytes int64) {
	if serializedBytes < 0 || serializedBytes >= requestWorkspaceBytes {
		return
	}
	p.state.mu.Lock()
	releasedBytes := requestWorkspaceBytes - serializedBytes
	p.heldBytes -= releasedBytes
	p.state.diagnostics.BufferedBytes -= releasedBytes
	p.state.mu.Unlock()
}

func (s *runtimeState) snapshot() RuntimeDiagnostics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.diagnostics
}

func (s *runtimeState) addDroppedObserverEvents(delta int64) {
	s.mu.Lock()
	saturatingAdd(&s.diagnostics.DroppedObserverEvents, delta)
	s.mu.Unlock()
}

func (s *runtimeState) addObserverFailure() {
	s.mu.Lock()
	saturatingAdd(&s.diagnostics.ObserverFailures, 1)
	s.mu.Unlock()
}

func (s *runtimeState) addTelemetryFailure() {
	s.mu.Lock()
	saturatingAdd(&s.diagnostics.TelemetryFailures, 1)
	s.mu.Unlock()
}

func (s *runtimeState) beginClose() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.diagnostics.Closed {
		return false
	}
	s.closing = true
	return true
}

func (s *runtimeState) waitForOperations() {
	s.wg.Wait()
}

func (s *runtimeState) waitUntilClosed() {
	<-s.closeDone
}

func (s *runtimeState) finishClose() {
	s.mu.Lock()
	if s.diagnostics.Closed {
		s.mu.Unlock()
		return
	}
	s.diagnostics.Closed = true
	close(s.closeDone)
	s.mu.Unlock()
}

func saturatingAdd(counter *int64, delta int64) {
	if delta <= 0 || *counter >= maximumDiagnosticCounter {
		return
	}
	if delta > maximumDiagnosticCounter-*counter {
		*counter = maximumDiagnosticCounter
		return
	}
	*counter += delta
}

func addNanosSaturated(value, delta int64) int64 {
	if delta > 0 && value > math.MaxInt64-delta {
		return math.MaxInt64
	}
	if delta < 0 && value < math.MinInt64-delta {
		return math.MinInt64
	}
	return value + delta
}
