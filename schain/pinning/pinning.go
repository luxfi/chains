// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pinning is the deterministic single-writer assignment for the S-Chain
// storage VM. It maps each storage key-range to exactly ONE owning validator
// using weighted rendezvous (Highest-Random-Weight, HRW) hashing over the
// P-Chain validator set pinned to a block's epoch height.
//
// This replaces raft leader election. Raft serializes EVERY mutation through one
// elected leader; HRW pinning gives a DIFFERENT single writer PER RANGE with NO
// election round-trip — two writes to different ranges proceed in parallel, two
// writes to the same range resolve to the same owner on every node. The function
// is PURE: the same (range, validator-set-at-epoch) inputs produce the identical
// owner on every validator, so it is safe to evaluate inside deterministic block
// Verify without any coordination.
//
// HARD INVARIANT: the validator set MUST be the set at a fixed P-Chain epoch
// height (block.pChainHeight), never the live set. Every node verifying a block
// resolves the owner against the same frozen set, so ownership is a deterministic
// function of the block — not of wall-clock validator churn. Re-pinning happens
// only at epoch boundaries, when pChainHeight advances.
package pinning

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sort"

	"github.com/luxfi/ids"
)

// Member is one validator eligible to own a range: its identity and its stake
// weight. It is the projection of validators.GetValidatorOutput this package
// needs — id + weight only, no keys — so the pure pinning logic carries no
// dependency on the validators package and is trivially testable. The caller
// (the VM, holding *runtime.Runtime.ValidatorState) builds []Member from
// GetValidatorSet(ctx, block.pChainHeight, netID).
type Member struct {
	NodeID ids.NodeID
	Weight uint64
}

// Owner returns the NodeID that owns key, and true, or EmptyNodeID and false
// when the set is empty. Ownership is weighted rendezvous: each member m draws a
// score from H(key || m.NodeID) scaled by m.Weight; the highest score wins.
//
// Determinism: the score is a pure function of (key, NodeID); ties break on the
// lexicographically smaller NodeID. No map iteration order, no time, no float
// accumulation across members affects the winner. Every node computes the same
// owner for the same (key, members) — the property that lets the owner be
// resolved inside block Verify with zero coordination.
//
// Weighting: a member with twice the stake is ~twice as likely to own any given
// range, so write load tracks stake — the same economic alignment raft never
// had (raft's single leader carried 100% regardless of stake).
//
// Minimal disruption: when one member is added or removed, only the ranges whose
// winner WAS or NOW IS that member move; every other range keeps its owner. This
// is the defining HRW property and is what bounds re-pinning churn at an epoch
// boundary to O(ranges × Δvalidators / N) rather than a full reshuffle.
func Owner(key []byte, members []Member) (ids.NodeID, bool) {
	if len(members) == 0 {
		return ids.EmptyNodeID, false
	}
	var (
		best      ids.NodeID
		bestScore uint64
		haveBest  bool
	)
	for i := range members {
		m := members[i]
		if m.Weight == 0 {
			// A zero-weight member cannot own a range: it carries no stake to
			// back the write. Skipping keeps the weighting monotone (score 0
			// would still beat nothing, which we forbid).
			continue
		}
		s := score(key, m.NodeID, m.Weight)
		switch {
		case !haveBest, s > bestScore:
			best, bestScore, haveBest = m.NodeID, s, true
		case s == bestScore && nodeIDLess(m.NodeID, best):
			// Deterministic tie-break: smaller NodeID wins. Ties are
			// astronomically rare (256-bit hash) but MUST resolve identically
			// on every node, so we never leave it to iteration order.
			best = m.NodeID
		}
	}
	return best, haveBest
}

// IsOwner reports whether self owns key under members. This is the exact check a
// node runs to decide "am I the pinned writer for this range?" — emit the
// Allocate/Put tx iff true; otherwise verify-and-vote only.
func IsOwner(key []byte, self ids.NodeID, members []Member) bool {
	owner, ok := Owner(key, members)
	return ok && owner == self
}

// score is the weighted rendezvous score for (key, nodeID) at weight w.
//
// The base draw u is the first 8 bytes of SHA-256(key || nodeID), interpreted as
// a uniform uint64. We map it to the unit interval and apply the standard
// weighted-rendezvous transform score = -w / ln(u), which is the exponential
// trick that makes P(member m wins) = w_m / Σw exactly. The transform is
// monotone in w (more stake → higher expected score) and in u, and depends only
// on the two inputs, so it is fully deterministic.
//
// We return the score as a uint64 by ordering on the IEEE-754 bit pattern of a
// strictly-positive float64, which preserves numeric order — so comparison stays
// in integer space (no float == across the hot path) while the ranking is the
// true weighted-rendezvous ranking.
func score(key []byte, nodeID ids.NodeID, w uint64) uint64 {
	h := sha256.New()
	h.Write(key)
	h.Write(nodeID.Bytes())
	sum := h.Sum(nil)
	draw := binary.BigEndian.Uint64(sum[:8])

	// Map draw to (0,1]. (draw+1)/2^64 keeps u strictly positive so ln(u) is
	// defined and finite; u can equal 1 (the max), giving the smallest -1/ln(u)
	// magnitude, which is fine — it is still a valid, monotone score.
	u := (float64(draw) + 1) / (math.MaxUint64 + 1.0)
	s := -float64(w) / math.Log(u) // ln(u) < 0 for u in (0,1], so s > 0.
	return orderedFloatBits(s)
}

// orderedFloatBits maps a strictly-positive float64 to a uint64 whose unsigned
// ordering matches the float's numeric ordering. For positive floats the raw
// IEEE-754 bits are already monotone, so we return them directly. A non-positive
// or non-finite score (which score() never produces for w>0) sorts to zero.
func orderedFloatBits(f float64) uint64 {
	if f <= 0 || math.IsInf(f, 1) || math.IsNaN(f) {
		return 0
	}
	return math.Float64bits(f)
}

// nodeIDLess is the deterministic tie-break order: byte-lexicographic on the
// fixed-width NodeID.
func nodeIDLess(a, b ids.NodeID) bool {
	ab, bb := a.Bytes(), b.Bytes()
	for i := range ab {
		if ab[i] != bb[i] {
			return ab[i] < bb[i]
		}
	}
	return false
}

// SortMembers returns members in a canonical (NodeID-ascending) order. The
// caller does not need this for correctness — Owner is order-independent — but a
// canonical order makes the set hashable for an epoch-fingerprint and makes test
// output stable.
func SortMembers(members []Member) []Member {
	out := make([]Member, len(members))
	copy(out, members)
	sort.Slice(out, func(i, j int) bool {
		return nodeIDLess(out[i].NodeID, out[j].NodeID)
	})
	return out
}

// EpochFingerprint is a deterministic digest of the (sorted) member set. Two
// nodes that resolved ownership against the same validator set produce the same
// fingerprint; a node can stamp it into its Allocate tx so peers VERIFY the
// owner was computed against the agreed epoch set — the divergence detector for
// the manifest state root (M1). A mismatch means the proposer pinned against a
// different validator set and the block must be rejected.
func EpochFingerprint(pChainHeight uint64, members []Member) ids.ID {
	sorted := SortMembers(members)
	h := sha256.New()
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], pChainHeight)
	h.Write(u8[:])
	for _, m := range sorted {
		h.Write(m.NodeID.Bytes())
		binary.BigEndian.PutUint64(u8[:], m.Weight)
		h.Write(u8[:])
	}
	return ids.ID(sha256.Sum256(h.Sum(nil)))
}
