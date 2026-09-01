// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package chain holds what every chain in this module is made of: a block's
// place in the sequence, the store that advances the chain one block at a
// time, the queue of entries waiting for a block, and the fee floor that
// admits them.
//
// A chain package declares what it IS — its transactions, its records, its
// authorization rules. It does not restate how a block becomes fact. That is
// here, once, because every chain does it identically and the one way to get
// it wrong is to write it again.
package chain

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
)

// Block is a unit of state change a Store can accept: an identity, a place in
// the sequence, an encoding, and the two halves of applying it.
//
// Splitting Write from Publish is what makes a half-applied block unwritable.
// Write can fail and is discarded whole; Publish cannot fail and runs only
// once the writes are durable. A chain that writes and publishes in one pass
// has no such boundary, and its first failed write leaves the chain believing
// something that is not on disk.
//
// This is deliberately NOT the engine's block interface. A linear chain's
// blocks satisfy that as well; a DAG's vertices have several parents and no
// timestamp and do not. Both change state the same way, and this is that way.
type Block interface {
	ID() ids.ID
	Bytes() []byte

	// Parent and Height are the block's place in the sequence, and it takes
	// both. Height alone is not a place: a block whose parent is an old
	// accepted block satisfies height == parent+1 perfectly well, and a chain
	// that admits it rewinds. Accept compares Parent against the tip, so a
	// block that reports one it does not extend is a block that reports the
	// wrong parent to consensus as well.
	Parent() ids.ID
	Height() uint64

	// Write stages every durable change the block makes, through the view it
	// is given and nothing else. Writing anywhere else escapes the rollback.
	Write(database.Database) error

	// Publish makes the block's effects visible in memory. It runs after the
	// commit, under the store's lock. It cannot fail: anything that can fail
	// belongs in Write.
	Publish()
}

// Store is a chain's durable state, the blocks in flight above it, and the tip
// it has reached.
//
// ONE lock covers all three, and whatever caches the chain keeps beside them —
// take it with Lock or RLock. A second mutex over any part of this gives one
// map two owners, which in Go is a fatal throw rather than a bug you get to
// debug.
type Store[B Block] struct {
	sync.RWMutex

	base database.Database   // committed state
	view *versiondb.Database // what a block writes through until it commits

	reload func() error

	flight    map[ids.ID]B
	last      B // the accepted tip, kept so a proposal never re-reads it
	tip       ids.ID
	height    uint64
	preferred ids.ID
}

// Key namespaces. Blocks, the height index and the tip pointer are the store's
// own; a chain's records live under prefixes of its choosing and cannot
// collide with these.
var (
	tipKey       = []byte("chain/tip")
	blockPrefix  = []byte("chain/block/")
	heightPrefix = []byte("chain/height/")
)

// ErrNoBlock reports that no block is known by that id or at that height.
var ErrNoBlock = errors.New("chain: no such block")

// ErrNotOnTip refuses a block that does not extend the chain. It is the one
// name for that refusal: a chain that spells it itself gives the same fact two
// names, and a caller then has two things to match on.
var ErrNotOnTip = errors.New("chain: block does not extend the accepted tip")

// ErrNotOpen reports a store that has not opened. It knows no tip, so it
// cannot say what a block would extend or what a seed would start, and
// answering either from an empty tip writes the zero id over the chain's own.
var ErrNotOpen = errors.New("chain: store has not opened")

// New opens a store over db.
//
// reload rebuilds whatever the chain caches in memory from committed state. It
// is called after a failed apply, so the caches say what the database says
// rather than what the abandoned block said. A chain that mutates nothing in
// memory before the commit has nothing to rebuild and passes nil.
func New[B Block](db database.Database, reload func() error) *Store[B] {
	return &Store[B]{
		base:   db,
		view:   versiondb.New(db),
		reload: reload,
		flight: make(map[ids.ID]B),
	}
}

// View is what a block writes through, and what every read sees: committed
// state plus whatever the block in progress has staged.
func (s *Store[B]) View() database.Database { return s.view }

// Base is committed state, for the writes a chain makes outside any block. A
// write here is durable at once and belongs to no block, so no rollback takes
// it back — which is right for a record no block claims and wrong for one a
// block does.
func (s *Store[B]) Base() database.Database { return s.base }

// Accept applies b and commits it.
//
// A block extends the tip or it is not accepted, and that is decided HERE,
// under the lock that commits. Verify reached the same verdict earlier against
// the tip AT THAT TIME; the tip moves between the two, so a caller that asks
// before calling this asks in a window the store then reopens — it releases
// the read, the tip moves, and the commit lands anyway. The height index and
// the tip pointer would then name a block on an abandoned branch, and every
// peer bootstrapping from that index is served an orphan as canonical. The
// lock is not reentrant, so the check cannot come from the caller and be held
// across the commit; it comes from here or it is not held at all.
//
// Every write b makes goes through the view and lands in ONE commit, together
// with the block itself, its height entry and the tip pointer. So the chain
// has the whole block or none of it. Any failure rolls the view back, rebuilds
// the caches from committed state, and leaves the tip where it was: nothing
// the block claimed survives, and the chain does not believe it happened.
//
// The block's own effects become visible last, after the commit, so there is
// no window in which the chain has advanced past state that is not on disk.
func (s *Store[B]) Accept(b B) error {
	s.Lock()
	defer s.Unlock()

	id := b.ID()
	if s.tip == ids.Empty {
		// A store that has not opened has no sequence to extend, and a block
		// naming no parent would otherwise match that emptiness and commit
		// itself as the beginning.
		return fmt.Errorf("%w, so %s extends nothing", ErrNotOpen, id)
	}
	if parent := b.Parent(); parent != s.tip {
		return fmt.Errorf("%w: %s extends %s, and the tip is %s",
			ErrNotOnTip, id, parent, s.tip)
	}

	raw := b.Bytes()
	if len(raw) == 0 {
		return s.undo(fmt.Errorf("chain: block %s has no encoding", id))
	}
	if err := b.Write(s.view); err != nil {
		return s.undo(err)
	}
	if err := s.view.Put(blockKey(id), raw); err != nil {
		return s.undo(err)
	}
	if err := s.view.Put(heightKey(b.Height()), id[:]); err != nil {
		return s.undo(err)
	}
	if err := s.view.Put(tipKey, id[:]); err != nil {
		return s.undo(err)
	}
	if err := s.view.Commit(); err != nil {
		return s.undo(fmt.Errorf("chain: commit block %s: %w", id, err))
	}

	s.tip, s.height, s.last = id, b.Height(), b
	delete(s.flight, id)
	s.prune()
	b.Publish()
	return nil
}

// undo discards everything the block staged and puts the caches back to what
// committed state says. The caller gets the block's own error; a reload that
// also fails is joined to it, because a chain that cannot re-read its own
// state has a second problem and reporting only the first hides it.
func (s *Store[B]) undo(cause error) error {
	s.view.Abort()
	if s.reload != nil {
		if err := s.reload(); err != nil {
			return errors.Join(cause, err)
		}
	}
	return cause
}

// Seed applies the one mutation a chain makes outside consensus: what its
// genesis allocates, written through the view and committed at once, before
// any block exists. Everything after this happens in a block.
//
// It commits for the same reason Accept does. Left staged, a genesis
// allocation would ride on whichever block committed first and vanish with a
// chain that never accepted one.
//
// The tip goes in that same commit, because seeding is the act that makes a
// chain no longer fresh. Open calls a chain fresh when no tip is recorded, and
// a seed that recorded none left the two disagreeing: a chain that had
// allocated its genesis and not yet accepted a block reported itself fresh on
// every boot and allocated again. On the second start that is a duplicate the
// chain's own state refuses — "already exists" — and the node cannot restart
// until it produces a block it cannot produce. One commit holds both, so a
// chain has allocated and recorded it, or has done neither.
func (s *Store[B]) Seed(write func(database.Database) error) error {
	s.Lock()
	defer s.Unlock()

	if s.tip == ids.Empty {
		return fmt.Errorf("%w, so there is no genesis to seed", ErrNotOpen)
	}
	if err := write(s.view); err != nil {
		return s.undo(err)
	}
	if err := s.view.Put(tipKey, s.tip[:]); err != nil {
		return s.undo(err)
	}
	if err := s.view.Commit(); err != nil {
		return s.undo(fmt.Errorf("chain: commit genesis: %w", err))
	}
	return nil
}

// Prefer records the block the engine wants the next one built on. It is the
// tip until the engine says otherwise, and a preference the store no longer
// holds — pruned, or never tracked — falls back to the tip rather than naming
// a parent nothing can resolve.
func (s *Store[B]) Prefer(id ids.ID) {
	s.Lock()
	defer s.Unlock()
	s.preferred = id
}

// Propose hands the caller the block to build on and tracks whatever it
// builds, in one step. Reading the parent and registering the child as two
// steps leaves a window in which a block is accepted between them, and the
// proposal is then built on a parent that has moved.
//
// A build with nothing to propose says so with an error, and nothing is
// tracked.
func (s *Store[B]) Propose(build func(parent B) (B, error)) (B, error) {
	s.Lock()
	defer s.Unlock()

	parent := s.last
	if b, ok := s.flight[s.preferred]; ok {
		parent = b
	}

	b, err := build(parent)
	if err != nil {
		var nothing B
		return nothing, err
	}
	s.track(b)
	return b, nil
}

// Track makes a block findable by id while it is in flight, so a child can
// resolve it as a parent — whether this node built the block or parsed it from
// a peer. Tracking only what a node builds leaves a follower able to verify
// the first block of a run and unable to verify the second.
func (s *Store[B]) Track(b B) {
	s.Lock()
	defer s.Unlock()
	s.track(b)
}

func (s *Store[B]) track(b B) {
	if b.Height() <= s.height {
		return
	}
	s.prune()
	s.flight[b.ID()] = b
}

// prune drops every block in flight at or below the accepted height. Nothing
// else will: the engine may abandon a block without ever accepting or
// rejecting it, so a set that only grew would leak. Anything at or below the
// tip is already decided or orphaned, which bounds this to the blocks actually
// in flight above it. Caller holds the lock.
func (s *Store[B]) prune() {
	for id, b := range s.flight {
		if b.Height() <= s.height {
			delete(s.flight, id)
		}
	}
}

// Drop forgets a block in flight. A rejected block is one the chain will not
// build on, and it never wrote anything, so there is nothing else to undo.
func (s *Store[B]) Drop(id ids.ID) {
	s.Lock()
	defer s.Unlock()
	delete(s.flight, id)
}

// Tip is the accepted block's id and height.
func (s *Store[B]) Tip() (ids.ID, uint64) {
	s.RLock()
	defer s.RUnlock()
	return s.tip, s.height
}

// Accepted reports whether id is the accepted tip or a block committed beneath
// it. A block in flight is neither.
func (s *Store[B]) Accepted(id ids.ID) bool {
	s.RLock()
	defer s.RUnlock()
	if id == s.tip {
		return true
	}
	ok, _ := s.view.Has(blockKey(id))
	return ok
}

// Block returns a block by id: one in flight, or one read back from committed
// state and decoded by parse.
func (s *Store[B]) Block(id ids.ID, parse func([]byte) (B, error)) (B, error) {
	s.RLock()
	defer s.RUnlock()

	if b, ok := s.flight[id]; ok {
		return b, nil
	}
	if id == s.tip {
		return s.last, nil
	}
	raw, err := s.view.Get(blockKey(id))
	if err != nil {
		var nothing B
		return nothing, fmt.Errorf("%w: %s", ErrNoBlock, id)
	}
	return parse(raw)
}

// IDAtHeight names the block accepted at height, from the index written in the
// same commit as the block itself — so the index can never name a block the
// chain did not accept.
func (s *Store[B]) IDAtHeight(height uint64) (ids.ID, error) {
	s.RLock()
	defer s.RUnlock()

	raw, err := s.view.Get(heightKey(height))
	if err != nil {
		return ids.Empty, fmt.Errorf("%w: height %d", ErrNoBlock, height)
	}
	return ids.ToID(raw)
}

// Open sets the chain's starting point: the tip recorded in committed state,
// or genesis if nothing is recorded. It reports which, so a chain that seeds
// state on its first run can tell its first run from every later one.
func (s *Store[B]) Open(genesis B, parse func([]byte) (B, error)) (B, bool, error) {
	s.Lock()
	defer s.Unlock()

	var nothing B

	// Only a tip that is ABSENT means a fresh chain. Reading any other failure
	// that way — a closed database, an unreadable volume, a short read — starts
	// a live chain over at genesis and lets it build height 1 on top of state
	// it cannot see, durably. A chain that cannot read its own tip does not
	// know where it is, and the honest answer is to refuse to open.
	raw, err := s.view.Get(tipKey)
	switch {
	case errors.Is(err, database.ErrNotFound):
		s.tip, s.height, s.last = genesis.ID(), genesis.Height(), genesis
		return genesis, true, nil
	case err != nil:
		return nothing, false, fmt.Errorf("chain: read tip: %w", err)
	case len(raw) != ids.IDLen:
		return nothing, false, fmt.Errorf("chain: tip is %d bytes, want %d", len(raw), ids.IDLen)
	}

	id, err := ids.ToID(raw)
	if err != nil {
		return nothing, false, err
	}
	if id == genesis.ID() {
		s.tip, s.height, s.last = id, genesis.Height(), genesis
		return genesis, false, nil
	}

	block, err := s.view.Get(blockKey(id))
	if err != nil {
		return nothing, false, fmt.Errorf("%w: tip %s", ErrNoBlock, id)
	}
	b, err := parse(block)
	if err != nil {
		return nothing, false, err
	}
	s.tip, s.height, s.last = id, b.Height(), b
	return b, false, nil
}

// Close releases the store. The view is closed rather than committed: anything
// still staged belongs to a block that was never accepted.
func (s *Store[B]) Close() error {
	s.Lock()
	defer s.Unlock()
	return s.view.Close()
}

func blockKey(id ids.ID) []byte {
	return append(append([]byte(nil), blockPrefix...), id[:]...)
}

func heightKey(h uint64) []byte {
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], h)
	return append(append([]byte(nil), heightPrefix...), u[:]...)
}
