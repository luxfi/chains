// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build redteam

// redteam_vertex_clock_test.go — RED TEAM proof for the DAG-vertex wall-clock
// determinism finding: DexVertex.Verify must process with the proposer-CARRIED
// block time (serialized in the vertex bytes, committed by the vertex id), NOT
// the local wall clock (mockable.Clock.Time() == time.Now() when unfaked). The
// block time flows through deriveBlockHash into relay-receipt keys AND
// computeStateRoot, so a per-validator wall clock would fork the StateRoot for
// the SAME vertex => consensus split.
//
// The linear Block path (block.go) was always safe (it carries b.timestamp);
// these tests pin the DAG path to the same invariant and FAIL against the old
// code (which injected v.vm.inner.clock.Time() in Verify).
//
// The assertions touch only ProcessBlock (stable signature) and result.StateRoot,
// so they don't break as the settlement-root internals evolve.

package dexvm

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/ids"
)

// buildVertexAt drives the real BuildVertex with the proxy clock pinned to `at`,
// so the proposer-chosen timestamp is deterministic for the test. Returns the
// serialized vertex bytes (what consensus gossips to every validator).
func buildVertexAt(t *testing.T, cvm *ChainVM, at time.Time, txBytes [][]byte) []byte {
	t.Helper()
	cvm.inner.clock.Set(at)
	cvm.pendingTxs = append(cvm.pendingTxs, txBytes...)
	v, err := cvm.BuildVertex(context.Background())
	if err != nil {
		t.Fatalf("BuildVertex: %v", err)
	}
	return v.Bytes()
}

// referenceRoot computes the StateRoot a fresh proxy produces for (height, time,
// txs) via the stable ProcessBlock path — the deterministic ground truth a
// correct Verify must reproduce from the CARRIED time.
func referenceRoot(t *testing.T, height uint64, blockTime time.Time, txBytes [][]byte) ids.ID {
	t.Helper()
	ref, _, _, _, _ := newCountingHarness(t, nil)
	res, err := ref.inner.ProcessBlock(context.Background(), height, blockTime, txBytes)
	if err != nil {
		t.Fatalf("reference ProcessBlock: %v", err)
	}
	return res.StateRoot
}

// TestRED_DAGVertex_WallClockSplitsStateRoot is the HEADLINE proof. One proposer
// builds a vertex (fixing the block time in its bytes). TWO validators receive
// the IDENTICAL bytes and each Verify at a DIFFERENT local wall-clock instant
// (their clocks are deliberately skewed). The processed StateRoot — which keys
// relay receipts and feeds computeStateRoot — MUST be identical on both, or the
// network splits on a block that every honest node agreed on.
//
// Old code (Verify used clock.Time()): roots differ -> FAIL.
// Fixed code (Verify uses the carried v.timestamp): roots identical -> PASS.
func TestRED_DAGVertex_WallClockSplitsStateRoot(t *testing.T) {
	ctx := context.Background()

	// Proposer builds the vertex at a fixed proposal time. Use a relay (clob_submit)
	// tx so both validators can Verify the same bytes without per-validator UTXO
	// setup; the relay plan is deterministic and keyed by (blockHash, txIndex).
	proposer, _, _, _, _ := newCountingHarness(t, nil)
	maker := ids.GenerateTestShortID()
	pid := ids.GenerateTestID()
	relayTx := newRelayTxBytes(t, maker, ids.GenerateTestID(), clobSubmitPayload(pid, 100))
	proposalTime := time.Unix(1_700_000_000, 0)
	vtxBytes := buildVertexAt(t, proposer, proposalTime, [][]byte{relayTx})

	// Validator A verifies with its wall clock at T (skewed +5.123s).
	valA, _, _, _, _ := newCountingHarness(t, nil)
	valA.inner.clock.Set(time.Unix(1_700_000_005, 123_000_000))
	va, err := valA.ParseVertex(ctx, vtxBytes)
	if err != nil {
		t.Fatalf("validator A ParseVertex: %v", err)
	}
	if err := va.Verify(ctx); err != nil {
		t.Fatalf("validator A Verify: %v", err)
	}
	rootA := va.(*DexVertex).result.StateRoot

	// Validator B verifies the SAME bytes with a DIFFERENT wall clock (+9.987s).
	valB, _, _, _, _ := newCountingHarness(t, nil)
	valB.inner.clock.Set(time.Unix(1_700_000_009, 987_000_000))
	vb, err := valB.ParseVertex(ctx, vtxBytes)
	if err != nil {
		t.Fatalf("validator B ParseVertex: %v", err)
	}
	if err := vb.Verify(ctx); err != nil {
		t.Fatalf("validator B Verify: %v", err)
	}
	rootB := vb.(*DexVertex).result.StateRoot

	t.Logf("proposalTime=%d  rootA=%x  rootB=%x", proposalTime.UnixNano(), rootA[:8], rootB[:8])

	if rootA != rootB {
		t.Fatalf("CONSENSUS SPLIT: two validators processed the SAME vertex bytes "+
			"and derived DIFFERENT StateRoots (A=%x B=%x) because Verify injected "+
			"each validator's local wall clock instead of the carried block time. "+
			"The block time keys relay receipts + computeStateRoot.", rootA[:8], rootB[:8])
	}

	// And the agreed root must equal what the CARRIED proposal time deterministically
	// implies (height 1 since genesis is height 0) — independent of any wall clock.
	if want := referenceRoot(t, 1, proposalTime, [][]byte{relayTx}); rootA != want {
		t.Fatalf("StateRoot %x does not match the carried-time derivation %x", rootA[:8], want[:8])
	}
}

// TestRED_DAGVertex_VerifyIgnoresWallClock pins the invariant directly: with the
// VM clock set FAR from the vertex's carried time, Verify still derives the
// StateRoot from the carried time. If Verify consulted the clock, the derived
// root would track clockTime and this assertion would fail.
func TestRED_DAGVertex_VerifyIgnoresWallClock(t *testing.T) {
	ctx := context.Background()

	proposer, _, _, _, _ := newCountingHarness(t, nil)
	maker := ids.GenerateTestShortID()
	pid := ids.GenerateTestID()
	relayTx := newRelayTxBytes(t, maker, ids.GenerateTestID(), clobSubmitPayload(pid, 7))
	carried := time.Unix(1_650_000_000, 0)
	vtxBytes := buildVertexAt(t, proposer, carried, [][]byte{relayTx})

	v, err := proposer.ParseVertex(ctx, vtxBytes)
	if err != nil {
		t.Fatalf("ParseVertex: %v", err)
	}
	if got := v.(*DexVertex).Timestamp(); !got.Equal(carried) {
		t.Fatalf("parsed timestamp %v != carried %v", got, carried)
	}

	// Move the VM wall clock FAR from the carried time, then Verify.
	clockTime := time.Unix(1_999_999_999, 0)
	proposer.inner.clock.Set(clockTime)
	if err := v.Verify(ctx); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	gotRoot := v.(*DexVertex).result.StateRoot

	carriedRoot := referenceRoot(t, v.Height(), carried, [][]byte{relayTx})
	clockRoot := referenceRoot(t, v.Height(), clockTime, [][]byte{relayTx})

	if carriedRoot == clockRoot {
		t.Fatalf("test precondition broken: carried- and clock-derived roots collide (%x)", carriedRoot[:8])
	}
	if gotRoot == clockRoot {
		t.Fatalf("Verify used the WALL CLOCK: StateRoot %x matches clock-derived %x, "+
			"not carried-time-derived %x", gotRoot[:8], clockRoot[:8], carriedRoot[:8])
	}
	if gotRoot != carriedRoot {
		t.Fatalf("StateRoot %x is neither clock- nor carried-derived (carried=%x): "+
			"unexpected derivation", gotRoot[:8], carriedRoot[:8])
	}
}

// TestRED_DAGVertex_TimestampRoundTripAndIDBinding proves the carried time
// survives serialize->parse byte-for-byte and that the vertex ID COMMITS to it
// (a tampered timestamp yields a different id, so a peer cannot silently swap
// the block time while keeping the same vertex id).
func TestRED_DAGVertex_TimestampRoundTripAndIDBinding(t *testing.T) {
	ctx := context.Background()
	cvm, _, _, _, _ := newCountingHarness(t, nil)

	maker := ids.GenerateTestShortID()
	pid := ids.GenerateTestID()
	relayTx := newRelayTxBytes(t, maker, ids.GenerateTestID(), clobSubmitPayload(pid, 1))
	carried := time.Unix(1_600_000_000, 42)
	vtxBytes := buildVertexAt(t, cvm, carried, [][]byte{relayTx})

	parsed, err := cvm.ParseVertex(ctx, vtxBytes)
	if err != nil {
		t.Fatalf("ParseVertex: %v", err)
	}
	pv := parsed.(*DexVertex)
	if !pv.Timestamp().Equal(carried) {
		t.Fatalf("round-trip timestamp %v != %v", pv.Timestamp(), carried)
	}

	// ID binding: a vertex identical in every field EXCEPT the timestamp must
	// have a different id (otherwise the time is not committed and is malleable).
	tampered := &DexVertex{
		height:    pv.height,
		epoch:     pv.epoch,
		timestamp: carried.Add(time.Second),
		parents:   pv.parents,
		rawTxs:    pv.rawTxs,
	}
	if tampered.computeID() == pv.id {
		t.Fatalf("vertex id does NOT commit to the timestamp: a different block "+
			"time produced the same id %x — the time is malleable", pv.id[:8])
	}
}

// TestRED_DAGVertex_SubSecondCadenceAndMonotonicClamp proves the D-Chain block
// cadence is genuinely SUB-SECOND and that the proposer's monotonicity guard
// (BuildVertex/BuildBlock: newTimestamp clamped non-decreasing vs GetLastBlockTime)
// operates at NANOSECOND resolution — dexvm has NO whole-second truncation like the
// C-Chain EVM's integer-seconds targetBlockRate floor. Regression lock: if anyone
// ever floors/rounds the proposer time to whole seconds, (a) and (d) FAIL.
//
// Three proposals from ONE proxy (state carries, so the clamp sees the real prior
// block time):
//  1. clock = T            (T has a non-zero .5s sub-second component)
//  2. clock = T + 1ms      (advances sub-second, SAME wall second as T)
//  3. clock = T - 1ms      (BACKWARD — must be clamped, never go back)
//
// Locks four properties the order-book's fairness/determinism depends on:
//
//	(a) NO whole-second truncation: ts2-ts1 == exactly 1ms and ts1 keeps its .5s.
//	(b) sub-second monotonic advance: ts2 strictly after ts1.
//	(c) monotonicity clamp at ns resolution: backward clock yields ts3 == ts2
//	    (non-decreasing), never earlier than the last block.
//	(d) ordering integrity: distinct sub-second times at the SAME height derive
//	    DISTINCT block hashes (deriveBlockHash keys relay-receipt idempotency),
//	    so two sub-second blocks never alias.
func TestRED_DAGVertex_SubSecondCadenceAndMonotonicClamp(t *testing.T) {
	ctx := context.Background()
	cvm, _, _, _, _ := newCountingHarness(t, nil)

	// A wall-clock instant with a deliberately non-zero sub-second (.5s) part, so a
	// whole-second truncation would be observable as a lost fractional second.
	base := time.Unix(1_700_000_000, 500_000_000)
	tsAt := func(at time.Time) time.Time {
		maker := ids.GenerateTestShortID()
		relayTx := newRelayTxBytes(t, maker, ids.GenerateTestID(), clobSubmitPayload(ids.GenerateTestID(), 1))
		vtx := buildVertexAt(t, cvm, at, [][]byte{relayTx})
		v, err := cvm.ParseVertex(ctx, vtx)
		if err != nil {
			t.Fatalf("ParseVertex: %v", err)
		}
		return v.(*DexVertex).Timestamp()
	}

	ts1 := tsAt(base)                        // clock = T
	ts2 := tsAt(base.Add(time.Millisecond))  // clock = T + 1ms
	ts3 := tsAt(base.Add(-time.Millisecond)) // clock = T - 1ms (backward)

	// (a) NO whole-second truncation: the 1ms advance survives byte-exactly, and the
	// sub-second component of the first block is preserved (would be 0 if truncated).
	if d := ts2.Sub(ts1); d != time.Millisecond {
		t.Fatalf("sub-second cadence lost: ts2-ts1 = %v, want exactly 1ms "+
			"(a whole-second floor would collapse this to 0)", d)
	}
	if ns := ts1.Nanosecond(); ns != 500_000_000 {
		t.Fatalf("sub-second component truncated: ts1.Nanosecond()=%d, want 500000000", ns)
	}

	// (b) sub-second monotonic advance.
	if !ts2.After(ts1) {
		t.Fatalf("block time did not advance sub-second: ts1=%v ts2=%v", ts1, ts2)
	}

	// (c) monotonicity clamp at ns resolution: the backward clock is pinned to the
	// last block time, never earlier. Non-decreasing block time is the DEX fairness
	// invariant under clock skew / re-proposal.
	if ts3.Before(ts2) {
		t.Fatalf("MONOTONICITY VIOLATION: backward clock produced ts3=%v < ts2=%v", ts3, ts2)
	}
	if !ts3.Equal(ts2) {
		t.Fatalf("clamp expected ts3==ts2 (%v), got %v", ts2, ts3)
	}

	// (d) ordering integrity: two DISTINCT sub-second times at the SAME height derive
	// DISTINCT block hashes (deriveBlockHash binds the block + keys relay-receipt
	// idempotency), so sub-second blocks never alias.
	if deriveBlockHash(1, ts1) == deriveBlockHash(1, ts2) {
		t.Fatalf("sub-second block-hash collision: two 1ms-apart blocks share a hash — " +
			"relay idempotency keys would alias")
	}
}

// TestRED_LinearBlock_SubSecondCadenceAndMonotonicClamp pins the SAME sub-second +
// non-decreasing guard on the linear chain.ChainVM.BuildBlock proposer path
// (chainvm.go), which carries the identical clamp as the DAG BuildVertex path. Two
// proposals: forward by 1ms, then a backward clock. ts advances by exactly 1ms
// (no whole-second floor) and the backward clock is clamped to the prior block time.
func TestRED_LinearBlock_SubSecondCadenceAndMonotonicClamp(t *testing.T) {
	ctx := context.Background()
	cvm, _, _, _, _ := newCountingHarness(t, nil)

	buildAt := func(at time.Time) time.Time {
		cvm.inner.clock.Set(at)
		relayTx := newRelayTxBytes(t, ids.GenerateTestShortID(), ids.GenerateTestID(), clobSubmitPayload(ids.GenerateTestID(), 1))
		cvm.pendingTxs = append(cvm.pendingTxs, relayTx)
		blk, err := cvm.BuildBlock(ctx)
		if err != nil {
			t.Fatalf("BuildBlock: %v", err)
		}
		return blk.(*Block).Timestamp()
	}

	base := time.Unix(1_700_000_000, 250_000_000) // .25s sub-second component
	b1 := buildAt(base)
	b2 := buildAt(base.Add(time.Millisecond))  // +1ms, same wall second
	b3 := buildAt(base.Add(-time.Millisecond)) // backward clock

	if d := b2.Sub(b1); d != time.Millisecond {
		t.Fatalf("linear path lost sub-second cadence: b2-b1 = %v, want 1ms", d)
	}
	if ns := b1.Nanosecond(); ns != 250_000_000 {
		t.Fatalf("linear path truncated sub-second component: b1.Nanosecond()=%d, want 250000000", ns)
	}
	if b3.Before(b2) {
		t.Fatalf("linear MONOTONICITY VIOLATION: backward clock produced b3=%v < b2=%v", b3, b2)
	}
	if !b3.Equal(b2) {
		t.Fatalf("linear clamp expected b3==b2 (%v), got %v", b2, b3)
	}
}
