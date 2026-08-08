package reposttest

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// ManualClock drives monotonic and wall time from one elapsed counter.
type ManualClock struct {
	mu         sync.Mutex
	base       time.Time
	elapsed    time.Duration
	schedulers map[*ManualScheduler]struct{}
}

// NewManualClock returns a clock at start with zero monotonic time.
func NewManualClock(start time.Time) *ManualClock {
	return &ManualClock{base: start, schedulers: make(map[*ManualScheduler]struct{})}
}

// Now returns elapsed monotonic nanoseconds.
func (c *ManualClock) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int64(c.elapsed)
}

// WallNow returns start plus elapsed time.
func (c *ManualClock) WallNow() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.base.Add(c.elapsed)
}

// Advance moves both clock surfaces and releases every newly due sleep.
func (c *ManualClock) Advance(duration time.Duration) {
	if duration < 0 {
		panic("reposttest: clock cannot move backwards")
	}
	c.mu.Lock()
	c.elapsed += duration
	now := int64(c.elapsed)
	schedulers := make([]*ManualScheduler, 0, len(c.schedulers))
	for scheduler := range c.schedulers {
		schedulers = append(schedulers, scheduler)
	}
	c.mu.Unlock()
	for _, scheduler := range schedulers {
		scheduler.release(now)
	}
}

type sleepWaiter struct {
	id  int64
	due int64
	ch  chan struct{}
}

// ManualScheduler blocks sleeps until its paired clock advances past them.
type ManualScheduler struct {
	mu      sync.Mutex
	clock   *ManualClock
	nextID  int64
	waiters []sleepWaiter
	sleeps  []time.Duration
	changed chan struct{}
}

// NewManualScheduler pairs a scheduler with clock.
func NewManualScheduler(clock *ManualClock) *ManualScheduler {
	if clock == nil {
		panic("reposttest: manual clock is nil")
	}
	scheduler := &ManualScheduler{clock: clock, changed: make(chan struct{})}
	clock.mu.Lock()
	clock.schedulers[scheduler] = struct{}{}
	clock.mu.Unlock()
	return scheduler
}

// Sleep waits until the clock reaches the requested delay or ctx ends.
func (s *ManualScheduler) Sleep(ctx context.Context, duration time.Duration) error {
	if duration < 0 {
		return errors.New("reposttest: negative sleep")
	}
	s.mu.Lock()
	now := s.clock.Now()
	if duration == 0 {
		s.sleeps = append(s.sleeps, duration)
		s.signalLocked()
		s.mu.Unlock()
		return nil
	}
	s.nextID++
	waiter := sleepWaiter{id: s.nextID, due: now + int64(duration), ch: make(chan struct{})}
	s.waiters = append(s.waiters, waiter)
	s.sleeps = append(s.sleeps, duration)
	s.signalLocked()
	s.mu.Unlock()

	select {
	case <-waiter.ch:
		return nil
	case <-ctx.Done():
		s.remove(waiter.id)
		return ctx.Err()
	}
}

// Sleeps returns requested delays in registration order.
func (s *ManualScheduler) Sleeps() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.sleeps...)
}

// AwaitSleepCount waits without polling until count sleeps have registered.
func (s *ManualScheduler) AwaitSleepCount(ctx context.Context, count int) error {
	if count < 0 {
		return errors.New("reposttest: negative sleep count")
	}
	for {
		s.mu.Lock()
		if len(s.sleeps) >= count {
			s.mu.Unlock()
			return nil
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *ManualScheduler) release(now int64) {
	s.mu.Lock()
	sort.SliceStable(s.waiters, func(left, right int) bool {
		if s.waiters[left].due == s.waiters[right].due {
			return s.waiters[left].id < s.waiters[right].id
		}
		return s.waiters[left].due < s.waiters[right].due
	})
	count := 0
	for count < len(s.waiters) && s.waiters[count].due <= now {
		close(s.waiters[count].ch)
		count++
	}
	s.waiters = append([]sleepWaiter(nil), s.waiters[count:]...)
	s.mu.Unlock()
}

func (s *ManualScheduler) remove(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := range s.waiters {
		if s.waiters[index].id == id {
			s.waiters = append(s.waiters[:index], s.waiters[index+1:]...)
			return
		}
	}
}

func (s *ManualScheduler) signalLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}
