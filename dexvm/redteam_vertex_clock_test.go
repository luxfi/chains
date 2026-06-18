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
