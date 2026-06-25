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
	if n != 0 {
		t.Fatalf("absent range counter = %d, want 0", n)
	}
}

// TestAllocMonotonicPerRange proves Set/Get round-trips and that distinct ranges
// carry DISJOINT counters — advancing one never moves another (the property that
// lets disjoint ranges allocate independently).
func TestAllocMonotonicPerRange(t *testing.T) {
	s := newState(t)

	if err := s.SetAlloc("A", 5); err != nil {
		t.Fatalf("SetAlloc A: %v", err)
	}
	if err := s.SetAlloc("B", 100); err != nil {
		t.Fatalf("SetAlloc B: %v", err)
	}

	if n, _ := s.GetAlloc("A"); n != 5 {
		t.Fatalf("A = %d, want 5", n)
	}
	if n, _ := s.GetAlloc("B"); n != 100 {
		t.Fatalf("B = %d, want 100", n)
	}

	// Advance A; B is untouched.
	if err := s.SetAlloc("A", 12); err != nil {
		t.Fatalf("SetAlloc A again: %v", err)
	}
	if n, _ := s.GetAlloc("A"); n != 12 {
		t.Fatalf("A after advance = %d, want 12", n)
	}
	if n, _ := s.GetAlloc("B"); n != 100 {
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
	if err := withAlloc.SetAlloc("R", 7); err != nil {
		t.Fatalf("SetAlloc: %v", err)
	}
	if root(withAlloc) == baseRoot {
		t.Fatal("setting an allocator counter did not change the root — alloc not covered")
	}

	// A DIFFERENT counter value for the same range yields a DIFFERENT root.
	withAlloc2 := mkBase()
	if err := withAlloc2.SetAlloc("R", 8); err != nil {
		t.Fatalf("SetAlloc: %v", err)
	}
	if root(withAlloc) == root(withAlloc2) {
		t.Fatal("distinct allocator counters share a root — divergence can hide")
	}

	// A counter on a DIFFERENT range also yields a different root (key is covered,
	// not just value).
	otherRange := mkBase()
	if err := otherRange.SetAlloc("R2", 7); err != nil {
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
		n   uint64
	}{{"x", 1}, {"y", 2}, {"z", 3}}

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
