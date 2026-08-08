package repost

import (
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const observerQueueCapacity = 1024

// Observer receives immutable, credential-free runtime events.
type Observer func(event ObserverEvent)

// ObserverEventKind identifies a runtime lifecycle event.
type ObserverEventKind string

// Observer event kinds emitted by Runtime.
const (
	ObserverEventKindOperationStart  ObserverEventKind = "operation.start"
	ObserverEventKindAttemptStart    ObserverEventKind = "attempt.start"
	ObserverEventKindAttemptEnd      ObserverEventKind = "attempt.end"
	ObserverEventKindRetryDelay      ObserverEventKind = "retry.delay"
	ObserverEventKindOperationCancel ObserverEventKind = "operation.cancel"
	ObserverEventKindOperationEnd    ObserverEventKind = "operation.end"
)

// ObserverOutcome is a low-cardinality operation or attempt result.
type ObserverOutcome string

// Observer outcomes emitted for attempts and operations.
const (
	ObserverOutcomeAccepted         ObserverOutcome = "ACCEPTED"
	ObserverOutcomeRetryableFailure ObserverOutcome = "RETRYABLE_FAILURE"
	ObserverOutcomeRejected         ObserverOutcome = "REJECTED"
	ObserverOutcomeFailed           ObserverOutcome = "FAILED"
	ObserverOutcomeCancelled        ObserverOutcome = "CANCELLED"
	ObserverOutcomeClosed           ObserverOutcome = "CLOSED"
)

// HTTPStatusClass is a bounded HTTP response classification.
type HTTPStatusClass string

// HTTP status classes exposed to observers and telemetry.
const (
	HTTPStatusClassNone        HTTPStatusClass = ""
	HTTPStatusClassSuccess     HTTPStatusClass = "SUCCESS"
	HTTPStatusClassRedirection HTTPStatusClass = "REDIRECTION"
	HTTPStatusClassClientError HTTPStatusClass = "CLIENT_ERROR"
	HTTPStatusClassServerError HTTPStatusClass = "SERVER_ERROR"
)

// AttemptSummary is a credential-free summary of one completed attempt.
type AttemptSummary struct {
	AttemptNumber   int
	Outcome         ObserverOutcome
	ErrorCode       ErrorCode
	DeliveryState   DeliveryState
	HTTPStatusClass HTTPStatusClass
	Duration        time.Duration
}

// ObserverEvent is one versioned, credential-free runtime event.
type ObserverEvent struct {
	SchemaVersion      int
	Kind               ObserverEventKind
	OperationID        string
	Timestamp          int64
	AttemptNumber      int
	Duration           time.Duration
	Outcome            ObserverOutcome
	ErrorCode          ErrorCode
	DeliveryState      DeliveryState
	HTTPStatusClass    HTTPStatusClass
	RetryDelay         time.Duration
	OperationStartedAt int64
	OperationEndedAt   int64
	AttemptSummaries   []AttemptSummary
}

type observerDispatcher struct {
	observer Observer
	state    *runtimeState
	events   chan *ObserverEvent
	stop     chan struct{}
	done     chan struct{}
	runGID   atomic.Uint64

	mu      sync.Mutex
	pending int
	active  bool
	closing bool
	cond    *sync.Cond
}

func newObserverDispatcher(observer Observer, state *runtimeState) *observerDispatcher {
	if observer == nil {
		return nil
	}
	d := &observerDispatcher{
		observer: observer,
		state:    state,
		events:   make(chan *ObserverEvent, observerQueueCapacity),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	d.cond = sync.NewCond(&d.mu)
	go d.run()
	return d
}

func (d *observerDispatcher) emit(event *ObserverEvent) {
	if d == nil || event == nil {
		return
	}
	snapshot := *event
	snapshot.AttemptSummaries = append([]AttemptSummary(nil), event.AttemptSummaries...)
	d.mu.Lock()
	if d.closing {
		d.mu.Unlock()
		d.state.addDroppedObserverEvents(1)
		return
	}
	select {
	case d.events <- &snapshot:
		d.pending++
		d.mu.Unlock()
	default:
		d.mu.Unlock()
		d.state.addDroppedObserverEvents(1)
	}
}

func (d *observerDispatcher) run() {
	d.runGID.Store(currentGoroutineID())
	defer close(d.done)
	for {
		select {
		case <-d.stop:
			d.dropPending()
			return
		default:
		}
		select {
		case event := <-d.events:
			if d.claimDelivery() {
				d.deliver(event)
			} else {
				d.state.addDroppedObserverEvents(1)
				d.complete(1)
			}
		case <-d.stop:
			d.dropPending()
			return
		}
	}
}

func (d *observerDispatcher) claimDelivery() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing {
		return false
	}
	d.active = true
	return true
}

func (d *observerDispatcher) deliver(event *ObserverEvent) {
	func() {
		defer func() {
			if recover() != nil {
				d.state.addObserverFailure()
			}
		}()
		d.observer(*event)
	}()
	d.mu.Lock()
	d.active = false
	d.pending--
	d.cond.Broadcast()
	d.mu.Unlock()
}

func (d *observerDispatcher) dropPending() {
	dropped := 0
	for {
		select {
		case <-d.events:
			dropped++
		default:
			if dropped > 0 {
				d.state.addDroppedObserverEvents(int64(dropped))
				d.complete(dropped)
			}
			return
		}
	}
}

func (d *observerDispatcher) complete(count int) {
	d.mu.Lock()
	d.pending -= count
	if d.pending == 0 {
		d.cond.Broadcast()
	}
	d.mu.Unlock()
}

func (d *observerDispatcher) flush() {
	if d == nil {
		return
	}
	d.mu.Lock()
	for d.pending != 0 {
		d.cond.Wait()
	}
	d.mu.Unlock()
}

func (d *observerDispatcher) close() {
	if d == nil {
		return
	}
	self := d.isCurrentCallback()
	d.mu.Lock()
	if d.closing {
		d.mu.Unlock()
		if self {
			return
		}
		<-d.done
		return
	}
	d.closing = true
	if self {
		close(d.stop)
		d.mu.Unlock()
		return
	}
	for d.active {
		d.cond.Wait()
	}
	close(d.stop)
	d.mu.Unlock()
	<-d.done
}

func (d *observerDispatcher) isCurrentCallback() bool {
	return d != nil && sameNonzeroGoroutine(currentGoroutineID(), d.runGID.Load())
}

func sameNonzeroGoroutine(current, dispatcher uint64) bool {
	return current != 0 && dispatcher != 0 && current == dispatcher
}

// Go exposes no callback-context token to Close. The dispatcher needs its
// goroutine identity only to avoid waiting for its own callback.
func currentGoroutineID() uint64 {
	var stack [64]byte
	fields := strings.Fields(string(stack[:runtime.Stack(stack[:], false)]))
	if len(fields) < 2 {
		return 0
	}
	id, _ := strconv.ParseUint(fields[1], 10, 64)
	return id
}
