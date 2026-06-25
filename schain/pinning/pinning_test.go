// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pinning

import (
	"fmt"
	"math"
	"testing"

	"github.com/luxfi/ids"
)

// node builds a deterministic NodeID from a small int so tests are readable.
func node(i byte) ids.NodeID {
	var n ids.NodeID
	n[0] = i
	return n
}

func members(weights ...uint64) []Member {
	ms := make([]Member, len(weights))
	for i, w := range weights {
		ms[i] = Member{NodeID: node(byte(i + 1)), Weight: w}
	}
	return ms
}

// TestEmptySet: no members → no owner. The VM must treat this as "cannot pin"
// (fail closed), never as "I am the owner".
func TestEmptySet(t *testing.T) {
	if _, ok := Owner([]byte("bucket/0"), nil); ok {
		t.Fatal("empty set must yield no owner")
	}
	if IsOwner([]byte("k"), node(1), nil) {
		t.Fatal("empty set: nobody is owner")
	}
}

// TestDeterministic: the SAME (key, set) yields the SAME owner across repeated
// and reordered evaluations. This is the property that lets ownership be
// resolved inside deterministic block Verify on every node.
func TestDeterministic(t *testing.T) {
	ms := members(10, 10, 10, 10, 10)
	key := []byte("bucket-A/object-Q")
	want, ok := Owner(key, ms)
	if !ok {
		t.Fatal("expected an owner")
	}
	for i := 0; i < 100; i++ {
		got, _ := Owner(key, ms)
		if got != want {
			t.Fatalf("non-deterministic owner: %s != %s", got, want)
		}
	}
	// Reorder the slice; the winner must not change (Owner is order-independent).
	rev := make([]Member, len(ms))
	for i := range ms {
		rev[len(ms)-1-i] = ms[i]
	}
	if got, _ := Owner(key, rev); got != want {
		t.Fatalf("owner changed under reordering: %s != %s", got, want)
	}
}

// TestSingleWriterPerRange: every key resolves to exactly one owner. There is no
// (key, set) input for which two distinct nodes both believe they own it — the
// safety core: two writes to the SAME object are impossible because only one
// node is ever the owner.
func TestSingleWriterPerRange(t *testing.T) {
	ms := members(7, 3, 11, 5, 9, 2, 8)
	for i := 0; i < 5000; i++ {
		key := []byte(fmt.Sprintf("bkt-%d/obj-%d", i%13, i))
		owner, ok := Owner(key, ms)
		if !ok {
			t.Fatalf("key %q: no owner", key)
		}
		ownerCount := 0
		for _, m := range ms {
			if IsOwner(key, m.NodeID, ms) {
				ownerCount++
			}
		}
		if ownerCount != 1 {
			t.Fatalf("key %q: %d owners, want exactly 1 (owner=%s)", key, ownerCount, owner)
		}
	}
}

// TestParallelDifferentRanges: two DIFFERENT keys frequently resolve to two
// DIFFERENT owners — the win over raft. Under raft both writes serialize through
// one leader; under HRW pinning distinct ranges have distinct writers that
// proceed in parallel. We assert that across many key pairs a healthy fraction
// land on different owners (it must not collapse to one global writer).
func TestParallelDifferentRanges(t *testing.T) {
	ms := members(10, 10, 10, 10, 10)
	distinct := 0
	const trials = 2000
	for i := 0; i < trials; i++ {
		a, _ := Owner([]byte(fmt.Sprintf("range-a-%d", i)), ms)
		b, _ := Owner([]byte(fmt.Sprintf("range-b-%d", i)), ms)
		if a != b {
			distinct++
		}
	}
	// With 5 equal validators, P(two random keys differ) = 4/5 = 0.8. Allow slack.
	if distinct < trials*7/10 {
		t.Fatalf("only %d/%d key pairs had distinct owners — writes are not parallelizing across ranges", distinct, trials)
	}
}

// TestWeightedDistribution: ownership share tracks stake weight. A validator
// with 2x the weight should own ~2x the ranges. This is the economic alignment
// raft's single leader never had.
func TestWeightedDistribution(t *testing.T) {
	// weights 1,2,3,4 → total 10. Expected shares 0.1,0.2,0.3,0.4.
	ms := members(1, 2, 3, 4)
	counts := map[ids.NodeID]int{}
	const trials = 200000
	for i := 0; i < trials; i++ {
		owner, _ := Owner([]byte(fmt.Sprintf("o/%d", i)), ms)
		counts[owner]++
	}
	totalWeight := uint64(0)
	for _, m := range ms {
		totalWeight += m.Weight
	}
	for _, m := range ms {
		expected := float64(m.Weight) / float64(totalWeight)
		actual := float64(counts[m.NodeID]) / float64(trials)
		if math.Abs(actual-expected) > 0.02 {
			t.Fatalf("node %s: share %.4f, expected %.4f (weight %d/%d)",
				m.NodeID, actual, expected, m.Weight, totalWeight)
		}
	}
}

// TestZeroWeightNeverOwns: a zero-weight member (e.g. a validator being removed,
// reported with 0 stake) can never be pinned as a writer.
func TestZeroWeightNeverOwns(t *testing.T) {
	ms := []Member{
		{NodeID: node(1), Weight: 0},
		{NodeID: node(2), Weight: 5},
		{NodeID: node(3), Weight: 5},
	}
	for i := 0; i < 2000; i++ {
		owner, ok := Owner([]byte(fmt.Sprintf("k/%d", i)), ms)
		if !ok {
			t.Fatalf("k/%d: expected an owner among non-zero members", i)
		}
		if owner == node(1) {
			t.Fatalf("zero-weight node owned k/%d", i)
		}
	}
}

// TestMinimalDisruption: removing ONE validator moves only the ranges that node
// owned; every other range keeps its owner. This bounds epoch-boundary re-pin
// churn — the property that makes validator-set change cheap rather than a full
// reshuffle. Adding back is symmetric.
func TestMinimalDisruption(t *testing.T) {
	full := members(10, 10, 10, 10, 10)        // nodes 1..5
	removed := full[len(full)-1].NodeID          // drop node 5
	reduced := full[:len(full)-1]

	const trials = 20000
	moved, ownedByRemoved := 0, 0
	for i := 0; i < trials; i++ {
		key := []byte(fmt.Sprintf("obj/%d", i))
		before, _ := Owner(key, full)
		after, _ := Owner(key, reduced)
		if before == removed {
			ownedByRemoved++
			continue // expected to move; it has to.
		}
		if before != after {
			moved++ // a range NOT owned by the removed node should not move.
		}
	}
	if moved != 0 {
		t.Fatalf("%d ranges not owned by the removed node changed owner — HRW should keep them put", moved)
	}
	if ownedByRemoved == 0 {
		t.Fatal("removed node owned zero ranges in the sample — test set too small to be meaningful")
	}
	t.Logf("removed node owned %d/%d ranges (all correctly re-pinned); 0 others moved", ownedByRemoved, trials)
}

// TestEpochFingerprintAgreement: the same validator set at the same height
// fingerprints identically regardless of input order; a different set or height
// fingerprints differently. This is the divergence detector a proposer stamps
// into its Allocate tx so peers reject a block pinned against the wrong epoch.
func TestEpochFingerprintAgreement(t *testing.T) {
	ms := members(3, 7, 2, 9)
	rev := make([]Member, len(ms))
	for i := range ms {
		rev[len(ms)-1-i] = ms[i]
	}
	if EpochFingerprint(100, ms) != EpochFingerprint(100, rev) {
		t.Fatal("fingerprint must be order-independent")
	}
	if EpochFingerprint(100, ms) == EpochFingerprint(101, ms) {
		t.Fatal("different height must fingerprint differently")
	}
	diff := append([]Member{}, ms...)
	diff[0].Weight++
	if EpochFingerprint(100, ms) == EpochFingerprint(100, diff) {
		t.Fatal("different weight must fingerprint differently")
	}
}

// TestSingleMember: a one-validator set always owns every range (the degenerate
// case — equivalent to a single-master deployment, but with no raft).
func TestSingleMember(t *testing.T) {
	ms := members(1)
	for i := 0; i < 100; i++ {
		owner, ok := Owner([]byte(fmt.Sprintf("k/%d", i)), ms)
		if !ok || owner != node(1) {
			t.Fatalf("single member must own everything; got ok=%v owner=%s", ok, owner)
		}
	}
}
