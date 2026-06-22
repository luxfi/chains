// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// quorum.go is the tally: group the revealed output_hashes and find the
// plurality. The quorum RULE (is the plurality >= threshold) and the payout /
// slash consequences live in settlement.go; this file is only the counting,
// kept separate so the agreement function is a pure, total, deterministic
// primitive.

import "github.com/luxfi/geth/common"

// plurality returns the most-common hash and its count. Deterministic tie-break:
// among hashes tied for the max count the big-endian-smallest hash wins, so
// every validator computes the identical result. (A tie cannot reach a strict-
// majority threshold anyway, but the tie-break keeps the function total.)
func plurality(hashes []common.Hash) (common.Hash, uint32) {
	counts := make(map[common.Hash]uint32, len(hashes))
	for _, h := range hashes {
		counts[h]++
	}
	var best common.Hash
	var bestN uint32
	for h, c := range counts {
		if c > bestN || (c == bestN && bytesLess(h, best)) {
			best, bestN = h, c
		}
	}
	return best, bestN
}

// tally reads the per-task revealer array and returns the revealers (in reveal
// order) with their revealed output_hashes. Bounded by N.
func tally(st QuorumState, taskID common.Hash) (revealers []common.Address, hashes []common.Hash) {
	rc := revealCount(st, taskID)
	revealers = make([]common.Address, rc)
	hashes = make([]common.Hash, rc)
	for i := uint32(0); i < rc; i++ {
		op := common.BytesToAddress(st.GetState(slotHashIdx(nsRevealList, taskID, i)).Bytes())
		revealers[i] = op
		hashes[i] = st.GetState(slotHashAddr(nsReveal, taskID, op))
	}
	return revealers, hashes
}
