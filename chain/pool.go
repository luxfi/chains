// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"context"
	"errors"
	"sync"

	"github.com/luxfi/ids"
	vmcore "github.com/luxfi/vm"
)

// Pool is what a chain has waiting for a block: the queue, in the order it
// arrived, and the set of effects those entries claim.
//
// The claim set is DERIVED from the queue — rebuilt from what is left whenever
// the queue shrinks — so a claim cannot outlive the entry that made it. A set
// maintained alongside the queue instead of from it drifts the moment one
// removal path forgets to touch it, and what it then refuses is work nothing
// is going to do.
//
// LOCK ORDER: a chain takes its Store's lock first and a Pool's second, never
// the other way round. Accept holds the store lock and drops from the pool
// inside it, so the reverse order deadlocks.
type Pool[T any] struct {
	mu    sync.Mutex
	claim func(T) ids.ID
	max   int
	queue []T
	held  map[ids.ID]struct{}
	work  vmcore.Latch
}

var (
	// ErrFull reports a pool at its bound. Admission is open to anyone who can
	// pay, so without a bound the queue is whatever an adversary makes it.
	ErrFull = errors.New("chain: pool is full")

	// ErrHeld reports a second entry claiming what a queued entry already
	// claims. Both would pass every check alone and together spend a block on
	// work only one of them can do.
	ErrHeld = errors.New("chain: claimed by a queued entry")
)

// NewPool returns a pool bounded at max entries, where claim says what an
// entry takes — which is also how it is found again.
func NewPool[T any](max int, claim func(T) ids.ID) *Pool[T] {
	return &Pool[T]{
		claim: claim,
		max:   max,
		held:  make(map[ids.ID]struct{}),
	}
}

// Add queues an entry and tells consensus there is something to build. A chain
// builds nothing until it is told.
func (p *Pool[T]) Add(entry T) error {
	p.mu.Lock()
	if len(p.queue) >= p.max {
		p.mu.Unlock()
		return ErrFull
	}
	c := p.claim(entry)
	if _, dup := p.held[c]; dup {
		p.mu.Unlock()
		return ErrHeld
	}
	p.held[c] = struct{}{}
	p.queue = append(p.queue, entry)
	p.mu.Unlock()

	p.work.Signal()
	return nil
}

// Take returns up to n entries in arrival order, oldest first, and leaves them
// queued. A block SELECTS from the pool rather than draining it, so an engine
// that discards a proposal — which it may do without ever rejecting it —
// cannot take the queue with it. n of zero or less takes everything.
func (p *Pool[T]) Take(n int) []T {
	p.mu.Lock()
	defer p.mu.Unlock()

	if n <= 0 || n > len(p.queue) {
		n = len(p.queue)
	}
	return append([]T(nil), p.queue[:n]...)
}

// Drop removes accepted entries and rebuilds the claim set from what remains.
func (p *Pool[T]) Drop(entries []T) {
	if len(entries) == 0 {
		return
	}
	gone := make(map[ids.ID]struct{}, len(entries))
	for _, e := range entries {
		gone[p.claim(e)] = struct{}{}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	kept := p.queue[:0]
	for _, e := range p.queue {
		if _, ok := gone[p.claim(e)]; !ok {
			kept = append(kept, e)
		}
	}
	p.queue = kept
	p.held = make(map[ids.ID]struct{}, len(kept))
	for _, e := range kept {
		p.held[p.claim(e)] = struct{}{}
	}
}

// Holds reports whether a queued entry already claims c.
func (p *Pool[T]) Holds(c ids.ID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.held[c]
	return ok
}

// Len is how many entries are waiting.
func (p *Pool[T]) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.queue)
}

// Wait blocks until there is something to build a block from, or the caller
// gives up. Waiting on the context alone would mean a chain never leaves
// genesis however much it is offered.
func (p *Pool[T]) Wait(ctx context.Context) (vmcore.Message, error) {
	return p.work.WaitForEvent(ctx)
}
