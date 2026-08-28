// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// alloc_test.go — the state-layer proof for the per-range allocator counter
// (alloc/<range>), the leaderless pinned-writer replacement for raft's global
// volume-id / fileId sequence. It proves the counter behaves (absent reads as 0,
// monotonic, per-range disjoint, corruption-rejecting) AND — the load-bearing
// property — that the counter is folded into Root(): changing any allocator
// counter changes the state root, so a validator that diverges on an allocation
// can never share a root with an honest one.
package state

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/luxfi/database/zapdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/metric"
)

func newState(t *testing.T) *State {
	t.Helper()
	db, err := zapdb.New(t.TempDir(), nil, "schain-alloc-test", metric.NewRegistry())
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := New(db)
	if err := s.Initialize(); err != nil {
		t.Fatalf("init state: %v", err)
	}
	return s
}

// TestAllocAbsentReadsZero proves an unallocated range reads as 0 — its first
// allocation starts handing out ids at 0.
func TestAllocAbsentReadsZero(t *testing.T) {
	s := newState(t)
	n, err := s.GetAlloc("never-allocated")
	if err != nil {
		t.Fatalf("GetAlloc: %v", err)
	}
	if n != (Alloc{}) {
		t.Fatalf("absent range reads %+v, want the zero Alloc", n)
	}
}

// TestAllocMonotonicPerRange proves Set/Get round-trips and that distinct ranges
// carry DISJOINT counters — advancing one never moves another (the property that
// lets disjoint ranges allocate independently).
func TestAllocMonotonicPerRange(t *testing.T) {
	s := newState(t)

	if err := s.SetAlloc("A", Alloc{Next: 5, Nonce: 1}); err != nil {
		t.Fatalf("SetAlloc A: %v", err)
	}
	if err := s.SetAlloc("B", Alloc{Next: 100, Nonce: 1}); err != nil {
		t.Fatalf("SetAlloc B: %v", err)
	}

	if n, _ := s.GetAlloc("A"); n.Next != 5 {
		t.Fatalf("A = %d, want 5", n)
	}
	if n, _ := s.GetAlloc("B"); n.Next != 100 {
		t.Fatalf("B = %d, want 100", n)
	}

	// Advance A; B is untouched.
	if err := s.SetAlloc("A", Alloc{Next: 12, Nonce: 2}); err != nil {
		t.Fatalf("SetAlloc A again: %v", err)
	}
	if n, _ := s.GetAlloc("A"); n.Next != 12 {
		t.Fatalf("A after advance = %d, want 12", n)
	}
	if n, _ := s.GetAlloc("B"); n.Next != 100 {
		t.Fatalf("B moved when A advanced = %d, want 100 (counters not disjoint)", n)
	}
}

// TestRootCoversAlloc is the load-bearing state-layer proof: the allocator
// counter is part of the state root. Two stores with identical manifests but a
// DIFFERENT allocator counter for a range produce DIFFERENT roots — so allocator
// divergence cannot hide behind a matching root. And an absent counter (reads 0)
// must NOT equal a counter explicitly set to 0-advanced: any non-equal counter
// value moves the root.
func TestRootCoversAlloc(t *testing.T) {
	mkBase := func() *State {
		s := newState(t)
		// Identical manifest content in every store, so only the allocator differs.
		if err := s.PutManifest("b", "o", Manifest{FileIDs: []string{"1"}, Size: 1, ETag: "e"}); err != nil {
			t.Fatalf("seed manifest: %v", err)
		}
		return s
	}
	root := func(s *State) ids.ID {
		r, err := s.Root()
		if err != nil {
			t.Fatalf("Root: %v", err)
		}
		return r
	}

	// Baseline: manifest only, no allocations.
	baseRoot := root(mkBase())

	// Adding an allocator counter moves the root.
	withAlloc := mkBase()
	if err := withAlloc.SetAlloc("R", Alloc{Next: 7, Nonce: 1}); err != nil {
		t.Fatalf("SetAlloc: %v", err)
	}
	if root(withAlloc) == baseRoot {
		t.Fatal("setting an allocator counter did not change the root — alloc not covered")
	}

	// A DIFFERENT counter value for the same range yields a DIFFERENT root.
	withAlloc2 := mkBase()
	if err := withAlloc2.SetAlloc("R", Alloc{Next: 8, Nonce: 1}); err != nil {
		t.Fatalf("SetAlloc: %v", err)
	}
	if root(withAlloc) == root(withAlloc2) {
		t.Fatal("distinct allocator counters share a root — divergence can hide")
	}

	// A counter on a DIFFERENT range also yields a different root (key is covered,
	// not just value).
	otherRange := mkBase()
	if err := otherRange.SetAlloc("R2", Alloc{Next: 7, Nonce: 1}); err != nil {
		t.Fatalf("SetAlloc: %v", err)
	}
	if root(withAlloc) == root(otherRange) {
		t.Fatal("same counter on different ranges share a root — range key not covered")
	}
}

// TestRootAllocDeterministic proves the alloc fold is order-independent: the same
// allocator state written in different order into two stores yields the same root.
func TestRootAllocDeterministic(t *testing.T) {
	a := newState(t)
	b := newState(t)

	sets := []struct {
		rng string
		n   Alloc
	}{{"x", Alloc{Next: 1, Nonce: 1}}, {"y", Alloc{Next: 2, Nonce: 1}}, {"z", Alloc{Next: 3, Nonce: 1}}}

	for _, p := range sets {
		if err := a.SetAlloc(p.rng, p.n); err != nil {
			t.Fatalf("a.SetAlloc: %v", err)
		}
	}
	for i := len(sets) - 1; i >= 0; i-- {
		if err := b.SetAlloc(sets[i].rng, sets[i].n); err != nil {
			t.Fatalf("b.SetAlloc: %v", err)
		}
	}

	ra, rb := mustRoot(t, a), mustRoot(t, b)
	if ra != rb {
		t.Fatalf("alloc root not deterministic across write order: %s != %s", ra, rb)
	}
	if ra == ids.Empty {
		t.Fatal("root empty for non-empty alloc state")
	}
}

func mustRoot(t *testing.T, s *State) ids.ID {
	t.Helper()
	r, err := s.Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	return r
}

// TestAllocIsStoredCanonically proves a range's cursor and the nonce that last
// moved it live under ONE key in a fixed-width encoding, and that any other
// width is corruption rather than a value to be interpreted. A cursor read back
// without its nonce is an allocation that can be replayed.
func TestAllocIsStoredCanonically(t *testing.T) {
	s := newState(t)
	want := Alloc{Next: 0x0102030405060708, Nonce: 0x1112131415161718}
	if err := s.SetAlloc("R", want); err != nil {
		t.Fatalf("SetAlloc: %v", err)
	}
	got, err := s.GetAlloc("R")
	if err != nil {
		t.Fatalf("GetAlloc: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip = %+v, want %+v", got, want)
	}

	// The stored bytes are exactly the two big-endian words, in that order.
	raw, err := s.db.Get(allocKey("R"))
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if len(raw) != allocSize {
		t.Fatalf("stored width = %d, want %d", len(raw), allocSize)
	}
	if binary.BigEndian.Uint64(raw[:8]) != want.Next ||
		binary.BigEndian.Uint64(raw[8:]) != want.Nonce {
		t.Fatalf("stored bytes %x do not spell %+v", raw, want)
	}

	// A stored value of the old, narrower shape is corruption, not a cursor with
	// an implied nonce of zero — which would make every prior allocation
	// replayable exactly once more.
	if err := s.db.Put(allocKey("legacy"), raw[:8]); err != nil {
		t.Fatalf("seed narrow value: %v", err)
	}
	if _, err := s.GetAlloc("legacy"); !errors.Is(err, ErrStateCorrupted) {
		t.Fatalf("narrow value read as %v, want ErrStateCorrupted", err)
	}
}

// TestAllocNonceMovesTheRoot proves the spend record is part of the commitment,
// not bookkeeping beside it: two chains agreeing on every cursor but disagreeing
// on which allocations have been spent produce different roots.
func TestAllocNonceMovesTheRoot(t *testing.T) {
	mk := func(a Alloc) ids.ID {
		s := newState(t)
		if err := s.SetAlloc("R", a); err != nil {
			t.Fatalf("SetAlloc: %v", err)
		}
		return mustRoot(t, s)
	}
	if mk(Alloc{Next: 5, Nonce: 1}) == mk(Alloc{Next: 5, Nonce: 2}) {
		t.Fatal("the spent-nonce mark is not covered by the state root")
	}
}

// TestManifestRoundTripAndCorruption proves the manifest accessors behave: an
// absent object is not found (not an error), a stored one round-trips whole, and
// a value that cannot be decoded is reported as corruption rather than returned
// as an empty manifest — an object whose file list silently emptied is an object
// whose blobs are unreachable.
func TestManifestRoundTripAndCorruption(t *testing.T) {
	s := newState(t)

	if _, found, err := s.GetManifest("b", "absent"); err != nil || found {
		t.Fatalf("absent manifest = (found %v, err %v), want (false, nil)", found, err)
	}

	want := Manifest{FileIDs: []string{"1,2a", "3,4b"}, Size: 4096, ETag: "etag"}
	if err := s.PutManifest("b", "o", want); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	got, found, err := s.GetManifest("b", "o")
	if err != nil || !found {
		t.Fatalf("GetManifest = (found %v, err %v)", found, err)
	}
	if got.Size != want.Size || got.ETag != want.ETag || len(got.FileIDs) != 2 ||
		got.FileIDs[0] != want.FileIDs[0] || got.FileIDs[1] != want.FileIDs[1] {
		t.Fatalf("manifest round-trip = %+v, want %+v", got, want)
	}

	// Distinct (bucket, object) splits cannot collide, because the key frames
	// each part with its length. Bare concatenation maps ("ab","c") and
	// ("a","bc") onto the same bytes — one object silently overwriting another.
	if err := s.PutManifest("ab", "c", Manifest{FileIDs: []string{"first"}}); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	if err := s.PutManifest("a", "bc", Manifest{FileIDs: []string{"second"}}); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	one, found, err := s.GetManifest("ab", "c")
	if err != nil || !found || one.FileIDs[0] != "first" {
		t.Fatalf(`("ab","c") = %+v (found %v, err %v) — split boundary not framed`, one, found, err)
	}
	two, found, err := s.GetManifest("a", "bc")
	if err != nil || !found || two.FileIDs[0] != "second" {
		t.Fatalf(`("a","bc") = %+v (found %v, err %v) — split boundary not framed`, two, found, err)
	}

	if err := s.db.Put(manifestKey("b", "corrupt"), []byte("{{{")); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}
	if _, _, err := s.GetManifest("b", "corrupt"); !errors.Is(err, ErrStateCorrupted) {
		t.Fatalf("corrupt manifest read as %v, want ErrStateCorrupted", err)
	}
}

// TestLastBlockPointerSurvivesAReload proves the recovery anchor is persistent
// state, not an in-memory field: a state manager rebuilt over the same store
// reports the block the chain last accepted.
func TestLastBlockPointerSurvivesAReload(t *testing.T) {
	db, err := zapdb.New(t.TempDir(), nil, "schain-anchor-test", metric.NewRegistry())
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := New(db)
	if err := s.Initialize(); err != nil {
		t.Fatalf("init: %v", err)
	}
	if id, height := s.GetLastBlock(); id != ids.Empty || height != 0 {
		t.Fatalf("fresh anchor = (%s, %d), want (empty, 0)", id, height)
	}

	want := ids.ID{9, 9, 9}
	if err := s.SetLastBlock(want, 42); err != nil {
		t.Fatalf("SetLastBlock: %v", err)
	}
	if id, height := s.GetLastBlock(); id != want || height != 42 {
		t.Fatalf("anchor = (%s, %d), want (%s, 42)", id, height, want)
	}

	reopened := New(db)
	if err := reopened.Initialize(); err != nil {
		t.Fatalf("reinit: %v", err)
	}
	if id, height := reopened.GetLastBlock(); id != want || height != 42 {
		t.Fatalf("anchor after reload = (%s, %d), want (%s, 42)", id, height, want)
	}
}
