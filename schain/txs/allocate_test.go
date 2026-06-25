// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// allocate_test.go — the AllocateTx wire-codec proof. AllocateTx is the
// leaderless pinned-writer replacement for raft's volume-id / fileId sequence;
// these tests prove its codec is faithful (round-trips to an identical mutation
// with a stable, deterministic id) and its isolated Verify rejects the two
// degenerate forms (empty range, zero count) — exactly the discipline
// PutManifestTx holds, so the parser handles both tx types one way.
package txs

import (
	"errors"
	"testing"
)

// TestAllocateRoundTrip proves an AllocateTx parses back to an identical mutation
// with the same deterministic id — the same wire faithfulness PutManifest has.
func TestAllocateRoundTrip(t *testing.T) {
	orig := NewAllocateTx("bucket-A/band-3", 64)

	parser := &TxParser{}
	parsed, err := parser.Parse(orig.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Type() != TxAllocate {
		t.Fatalf("parsed type = %v, want TxAllocate", parsed.Type())
	}
	if parsed.ID() != orig.ID() {
		t.Fatalf("round-trip id mismatch: %s != %s", parsed.ID(), orig.ID())
	}
	at, ok := parsed.(*AllocateTx)
	if !ok {
		t.Fatalf("parsed type = %T, want *AllocateTx", parsed)
	}
	if at.Range != "bucket-A/band-3" || at.Count != 64 {
		t.Fatalf("parsed fields wrong: %+v", at)
	}
}

// TestAllocateDeterministicID proves the id is a pure function of (range, count):
// two independently-constructed AllocateTxs with the same fields share an id, and
// any field change moves it. This is what lets the id be the tx's content address.
func TestAllocateDeterministicID(t *testing.T) {
	a := NewAllocateTx("r", 10)
	b := NewAllocateTx("r", 10)
	if a.ID() != b.ID() {
		t.Fatalf("identical AllocateTx have different ids: %s != %s", a.ID(), b.ID())
	}
	if NewAllocateTx("r", 11).ID() == a.ID() {
		t.Fatal("changing count did not change the id")
	}
	if NewAllocateTx("r2", 10).ID() == a.ID() {
		t.Fatal("changing range did not change the id")
	}
}

// TestAllocateVerify proves the isolated (state-free) Verify rejects the two
// degenerate allocations and accepts a well-formed one. The OWNER gate is NOT
// here — it is block-level (the VM's applyAllocate), because a single tx cannot
// see the block's validator set.
func TestAllocateVerify(t *testing.T) {
	if err := NewAllocateTx("r", 1).Verify(); err != nil {
		t.Fatalf("well-formed allocate rejected: %v", err)
	}
	if err := (&AllocateTx{Range: "", Count: 1}).Verify(); !errors.Is(err, ErrEmptyRange) {
		t.Fatalf("empty range: err = %v, want ErrEmptyRange", err)
	}
	if err := (&AllocateTx{Range: "r", Count: 0}).Verify(); !errors.Is(err, ErrZeroCount) {
		t.Fatalf("zero count: err = %v, want ErrZeroCount", err)
	}
}
