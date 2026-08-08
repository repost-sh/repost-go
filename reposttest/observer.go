package reposttest

import (
	"context"
	"errors"
	"sync"

	repost "github.com/repost-sh/repost-go"
)

// RecordingObserver records immutable observer events in callback order.
type RecordingObserver struct {
	mu      sync.Mutex
	events  []repost.ObserverEvent
	unread  []repost.ObserverEvent
	active  int
	changed chan struct{}
}

// NewRecordingObserver returns an empty recorder.
func NewRecordingObserver() *RecordingObserver {
	return &RecordingObserver{changed: make(chan struct{})}
}

// Observer returns the callback to put in repost.ClientOptions.
func (r *RecordingObserver) Observer() repost.Observer {
	return func(event repost.ObserverEvent) {
		event.AttemptSummaries = append([]repost.AttemptSummary(nil), event.AttemptSummaries...)
		r.mu.Lock()
		r.events = append(r.events, event)
		r.unread = append(r.unread, event)
		switch event.Kind {
		case repost.ObserverEventKindOperationStart:
			r.active++
		case repost.ObserverEventKindOperationEnd:
			if r.active > 0 {
				r.active--
			}
		}
		r.signalLocked()
		r.mu.Unlock()
	}
}

// Events returns a deep event snapshot.
func (r *RecordingObserver) Events() []repost.ObserverEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneEvents(r.events)
}

// AwaitNext waits for and consumes the next unread event.
func (r *RecordingObserver) AwaitNext(ctx context.Context) (repost.ObserverEvent, error) {
	for {
		r.mu.Lock()
		if len(r.unread) > 0 {
			event := cloneEvents(r.unread[:1])[0]
			r.unread = r.unread[1:]
			r.mu.Unlock()
			return event, nil
		}
		changed := r.changed
		r.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return repost.ObserverEvent{}, ctx.Err()
		}
	}
}

// AwaitQuiescence waits until at least one complete operation has been observed
// and no observed operation remains active. Call Runtime.FlushObservers first
// when every event enqueued before the call must be included.
func (r *RecordingObserver) AwaitQuiescence(ctx context.Context) error {
	for {
		r.mu.Lock()
		complete := len(r.events) > 0 && r.active == 0 && r.events[len(r.events)-1].Kind == repost.ObserverEventKindOperationEnd
		if complete {
			r.mu.Unlock()
			return nil
		}
		changed := r.changed
		r.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (r *RecordingObserver) signalLocked() {
	if r.changed == nil {
		panic(errors.New("reposttest: observer is not initialized"))
	}
	close(r.changed)
	r.changed = make(chan struct{})
}

func cloneEvents(events []repost.ObserverEvent) []repost.ObserverEvent {
	result := append([]repost.ObserverEvent(nil), events...)
	for index := range result {
		result[index].AttemptSummaries = append([]repost.AttemptSummary(nil), result[index].AttemptSummaries...)
	}
	return result
}
