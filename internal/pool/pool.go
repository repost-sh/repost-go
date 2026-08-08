// Package pool owns per-origin raw transport resources.
package pool

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// ErrClosed is returned after Pool.Close.
var ErrClosed = errors.New("transport pool is closed")

// Resource is one raw connection or multiplexed protocol session.
type Resource interface{ io.Closer }

// Mode determines whether a resource can serve concurrent leases.
type Mode uint8

// Resource sharing modes.
const (
	Exclusive Mode = iota
	Shared
)

// DialFunc creates one resource for an origin.
type DialFunc func(context.Context) (Resource, Mode, error)

// Options configures per-origin caps and expiry.
type Options struct {
	MaxConnections int
	Lifetime       time.Duration
	IdleTimeout    time.Duration
	Clock          func() time.Time
}

// Pool is safe for concurrent acquisition and release.
type Pool struct {
	mu      sync.Mutex
	options Options
	entries map[string][]*entry
	pending map[string]int
	notify  chan struct{}
	closed  bool
}

type entry struct {
	resource     Resource
	mode         Mode
	createdAt    time.Time
	lastIdleAt   time.Time
	active       int
	acquisitions uint64
	retiring     bool
}

// Lease holds one exclusive connection or one share of a multiplexed session.
type Lease struct {
	pool     *Pool
	key      string
	entry    *entry
	reused   bool
	released sync.Once
}

// New constructs an empty pool.
func New(options Options) *Pool {
	if options.Clock == nil {
		options.Clock = time.Now
	}
	return &Pool{
		options: options,
		entries: make(map[string][]*entry),
		pending: make(map[string]int),
		notify:  make(chan struct{}),
	}
}

// Acquire reuses an eligible resource or dials under the per-origin cap.
func (p *Pool) Acquire(ctx context.Context, key string, dial DialFunc) (*Lease, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		p.expireLocked(key, p.options.Clock())
		if p.closed {
			p.mu.Unlock()
			return nil, ErrClosed
		}
		if candidate := p.availableLocked(key); candidate != nil {
			candidate.active++
			candidate.acquisitions++
			lease := &Lease{pool: p, key: key, entry: candidate, reused: candidate.acquisitions > 1}
			p.mu.Unlock()
			return lease, nil
		}
		if len(p.entries[key])+p.pending[key] < p.options.MaxConnections {
			p.pending[key]++
			p.mu.Unlock()
			resource, mode, err := dial(ctx)
			p.mu.Lock()
			p.pending[key]--
			if p.pending[key] == 0 {
				delete(p.pending, key)
			}
			p.signalLocked()
			if err != nil {
				p.mu.Unlock()
				return nil, err
			}
			if p.closed {
				p.mu.Unlock()
				_ = resource.Close()
				return nil, ErrClosed
			}
			now := p.options.Clock()
			created := &entry{resource: resource, mode: mode, createdAt: now, lastIdleAt: now, active: 1, acquisitions: 1}
			p.entries[key] = append(p.entries[key], created)
			p.mu.Unlock()
			return &Lease{pool: p, key: key, entry: created}, nil
		}
		notify := p.notify
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-notify:
		}
	}
}

func (p *Pool) availableLocked(key string) *entry {
	for _, candidate := range p.entries[key] {
		if reusable, ok := candidate.resource.(interface{ Reusable() bool }); ok && !reusable.Reusable() {
			candidate.retiring = true
		}
		if !candidate.retiring && (candidate.mode == Shared || candidate.active == 0) {
			return candidate
		}
	}
	return nil
}

func (p *Pool) expireLocked(key string, now time.Time) {
	entries := p.entries[key]
	kept := entries[:0]
	for _, candidate := range entries {
		if now.Sub(candidate.createdAt) >= p.options.Lifetime ||
			candidate.active == 0 && now.Sub(candidate.lastIdleAt) >= p.options.IdleTimeout {
			candidate.retiring = true
		}
		if candidate.retiring && candidate.active == 0 {
			_ = candidate.resource.Close()
			continue
		}
		kept = append(kept, candidate)
	}
	if len(kept) == 0 {
		delete(p.entries, key)
	} else {
		p.entries[key] = kept
	}
}

// Resource returns the leased connection or session.
func (l *Lease) Resource() Resource { return l.entry.resource }

// Reused reports whether this resource had a prior lease.
func (l *Lease) Reused() bool { return l.reused }

// Release returns a reusable resource to the pool. A non-reusable shared
// resource closes after its last active lease settles.
func (l *Lease) Release(reusable bool) {
	l.released.Do(func() {
		p := l.pool
		p.mu.Lock()
		candidate := l.entry
		candidate.active--
		if !reusable || p.closed {
			candidate.retiring = true
		}
		if candidate.active == 0 {
			candidate.lastIdleAt = p.options.Clock()
			if candidate.retiring {
				p.removeLocked(l.key, candidate)
				_ = candidate.resource.Close()
			}
		}
		p.signalLocked()
		p.mu.Unlock()
	})
}

func (p *Pool) removeLocked(key string, target *entry) {
	entries := p.entries[key]
	for index, candidate := range entries {
		if candidate == target {
			entries = append(entries[:index], entries[index+1:]...)
			break
		}
	}
	if len(entries) == 0 {
		delete(p.entries, key)
	} else {
		p.entries[key] = entries
	}
}

// Close rejects acquisition, closes idle resources immediately, and marks
// active resources for close on release.
func (p *Pool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	for key, entries := range p.entries {
		kept := entries[:0]
		for _, candidate := range entries {
			candidate.retiring = true
			if candidate.active == 0 {
				_ = candidate.resource.Close()
				continue
			}
			kept = append(kept, candidate)
		}
		if len(kept) == 0 {
			delete(p.entries, key)
		} else {
			p.entries[key] = kept
		}
	}
	close(p.notify)
	p.mu.Unlock()
}

func (p *Pool) signalLocked() {
	if p.closed {
		return
	}
	close(p.notify)
	p.notify = make(chan struct{})
}
