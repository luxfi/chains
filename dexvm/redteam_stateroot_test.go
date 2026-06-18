// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build redteam

// redteam_stateroot_test.go — RED TEAM proof that the block StateRoot is a
// FAITHFUL commitment to the proxy's mutated state, not merely a re-encoding of
// the block hash.
//
// THE FINDING: computeStateRoot used to hash ONLY blockHash[:] and the height.
// It committed NOTHING about the consumed-UTXO set, collateral escrow, relay
// receipts, or the accumulated cross-chain (import/export) requests. So two
// validators whose state GENUINELY diverged — one applied an import + settled an
// export, a peer whose relay failed (vm.go: "individual tx failures don't fail
// the block; log and continue") committed no cross-chain op — emitted the SAME
// StateRoot whenever their block hash matched. Real divergence was invisible to
// the root-based safety check.
//
// These tests process the SAME block (same height + time => same blockHash) on
// harnesses that end in DIFFERENT states, and assert the roots DIFFER while the
// block hash is IDENTICAL. They FAIL against the old blockHash-only root (roots
// collide) and PASS against the faithful root. The final test pins the converse:
// identical state still yields identical roots (determinism).

package dexvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"

	"github.com/luxfi/chains/dexvm/txs"
)

// seedFixedUTXO exports `amount` of `asset` from C-Chain to the proxy under a
// CALLER-CHOSEN utxoID, so two harnesses can be seeded with the byte-identical
// source UTXO (the shared seedExportedUTXO helper randomizes the id, which would
// itself fork the consumed-set state). Mirrors that helper otherwise.
func seedFixedUTXO(t *testing.T, cChainSM atomic.SharedMemory, proxyChain ids.ID, owner ids.ShortID, asset, utxoID ids.ID, amount uint64) {
	t.Helper()
	val := encodeExportedOutput(txs.AtomicOutput{Owner: owner, Asset: asset, Amount: amount})
	if err := cChainSM.Apply(map[ids.ID]*atomic.Requests{
		proxyChain: {PutRequests: []*atomic.Element{{
			Key:    utxoID[:],
			Value:  val,
			Traits: [][]byte{owner[:]},
		}}},
	}); err != nil {
		t.Fatalf("seed fixed UTXO: %v", err)
	}
}

// legacyBlockHashOnlyRoot reproduces the OLD computeStateRoot (blockHash || height)
// — the root that committed no actual state. The tests use it to show that the
// divergent states being distinguished COLLIDE under the old scheme, so the new
// root is precisely what makes the divergence visible.
func legacyBlockHashOnlyRoot(blockHash ids.ID, height uint64) ids.ID {
	h := sha256.New()
	h.Write(blockHash[:])
	var heightBuf [8]byte
	binary.BigEndian.PutUint64(heightBuf[:], height)
	h.Write(heightBuf[:])
	return ids.ID(h.Sum(nil))
}

// TestRED_StateRoot_DivergentRelayOutcomeForksRoot is the HEADLINE proof that the
// faithful StateRoot commits the SETTLEMENT — now exercised against the post-#9
// residual divergence vector: divergent CARRIED FILLS.
//
// Under the carried-fills model the relay happens once at the proposer's build and
// NO node relays at accept, so the old "one validator's accept-relay fails" fork is
// structurally impossible (proven by TestRED_PerValidatorRelay_SplitsConsensus).
// The divergence that COULD still matter is two nodes settling DIFFERENT carried
// fills for the same block coordinate — e.g. an equivocating proposer that gossips
// two blocks with the same (height, time, txs) but different fills, or a tampered
// block. The faithful root MUST distinguish them: a node that settles 1000 base of
// proceeds (consuming the escrow into a base export) and a node that settles a
// 600-base partial (base export + 400 refund) produce DIFFERENT consumed/escrow/
// export state, hence different roots. The legacy blockHash-only root collides on
// both (same height+time => same blockHash), so it could not.
func TestRED_StateRoot_DivergentRelayOutcomeForksRoot(t *testing.T) {
	ctx := context.Background()

	const height = uint64(1)
	blockTime := time.Unix(1_700_000_000, 0)
	wantBlockHash := deriveBlockHash(height, blockTime)

	// FIXED ids so both nodes process a BYTE-IDENTICAL block (same blockHash) — the
	// ONLY difference is the CARRIED FILLS each node settles.
	var taker ids.ShortID
	copy(taker[:], "fixed-taker-addr-1234")
	asset := ids.ID{0xa5}
	srcUTXOID := ids.ID{0x5a}

	// relayTxIndex is the clob_submit relay's position in the block (import is 0).
	const relayTxIndex = uint32(1)

	// runBlock processes the identical import+relay block and settles the SUPPLIED
	// carried fills (modeling a node that received block bytes carrying those fills).
	runBlock := func(carried []Fill) *BlockResult {
		h := newConservationHarness(t, nil)
		h.exportTaker = taker
		seedFixedUTXO(t, h.cChainSM, h.proxyChain, taker, asset, srcUTXOID, 1000)
		importTx := newImportTxBytes(t, taker, h.cChain, srcUTXOID, asset, 1000)
		relayTx := newRelayTxBytes(t, taker, srcUTXOID, clobSubmitPayload(asset, 1000))

		res, err := h.vm.ProcessBlock(ctx, height, blockTime, [][]byte{importTx, relayTx})
		if err != nil {
			t.Fatalf("ProcessBlock: %v", err)
		}
		// Settle from the CARRIED fills (no node relays at accept; the fills came
		// from the block bytes). This is exactly what Block.Verify threads in.
		res.carriedFills = []carriedFill{{txIndex: relayTxIndex, fills: carried}}
		if err := h.vm.acceptBlock(ctx, res); err != nil {
			t.Fatalf("acceptBlock: %v", err)
		}
		return res
	}

	// Node A settles a full 1000-base fill; node B settles a 600-base partial (the
	// remaining 400 quote refunds). Same block bytes, DIFFERENT carried fills.
	resA := runBlock([]Fill{{Price: 1, Size: 1000, Side: 0}})
	resB := runBlock([]Fill{{Price: 1, Size: 600, Side: 0}})

	// Block hashes are identical, so the OLD blockHash-only root — a pure function
	// of (blockHash, height) — necessarily collided on these divergent settlements.
	if resA.blockHash != wantBlockHash || resB.blockHash != wantBlockHash {
		t.Fatalf("block hash drift: A=%x B=%x want=%x", resA.blockHash[:8], resB.blockHash[:8], wantBlockHash[:8])
	}
	legacyRoot := legacyBlockHashOnlyRoot(wantBlockHash, height)
	t.Logf("legacy blockHash-only root (identical for both settlements): %x", legacyRoot[:8])

	// THE FIX: the faithful roots MUST differ — the root commits the settlement
	// (escrow consumed + the export legs), so divergent carried fills are visible.
	if resA.StateRoot == resB.StateRoot {
		t.Fatalf("SETTLEMENT DIVERGENCE INVISIBLE TO ROOT: node A settled a full 1000-base "+
			"fill and node B a 600-base partial (different export legs + escrow), yet both "+
			"emitted the SAME StateRoot %x (block hash %x matched). The root does not commit "+
			"the settlement.", resA.StateRoot[:8], wantBlockHash[:8])
	}
	t.Logf("faithful roots fork on divergent carried fills: A=%x B=%x", resA.StateRoot[:8], resB.StateRoot[:8])
}

// TestRED_StateRoot_ConsumedUTXOSetForksRoot isolates ONE state component the old
// root ignored: the consumed-UTXO set. Two validators process the SAME (height,
// time) empty block — identical blockHash, identical (empty) atomic requests —
// but one inherited an extra consumed UTXO from a prior block. The faithful root
// must reflect that divergent state; the legacy root cannot (it never reads the
// consumed set).
func TestRED_StateRoot_ConsumedUTXOSetForksRoot(t *testing.T) {
	ctx := context.Background()
	const height = uint64(2)
	blockTime := time.Unix(1_700_000_500, 0)

	rootWith := func(extraConsumed ids.ID) ids.ID {
		h := newConservationHarness(t, nil)
		if extraConsumed != ids.Empty {
			if err := h.vm.state.MarkConsumed(extraConsumed); err != nil {
				t.Fatalf("seed consumed: %v", err)
			}
		}
		res, err := h.vm.ProcessBlock(ctx, height, blockTime, nil)
		if err != nil {
			t.Fatalf("ProcessBlock: %v", err)
		}
		return res.StateRoot
	}

	rootPlain := rootWith(ids.Empty)
	rootExtra := rootWith(ids.ID{0x42})

	if rootPlain == rootExtra {
		t.Fatalf("CONSUMED-SET DIVERGENCE INVISIBLE: a validator carrying an extra "+
			"consumed UTXO produced the SAME StateRoot %x as one without it, for the same "+
			"block. The root ignores the consumed-UTXO set.", rootPlain[:8])
	}
	legacyRoot := legacyBlockHashOnlyRoot(deriveBlockHash(height, blockTime), height)
	t.Logf("legacy root (identical for both): %x", legacyRoot[:8])
	t.Logf("consumed-set divergence forks faithful root: plain=%x extra=%x", rootPlain[:8], rootExtra[:8])
}

// TestRED_StateRoot_IdenticalStateMatchesRoot is the CONVERSE: identical inputs
// MUST yield identical roots (determinism). A faithful root that forked on
// matching state would be useless for consensus. The block is built from FIXED
// ids so nothing random forks the state, processed on two fresh validators.
func TestRED_StateRoot_IdenticalStateMatchesRoot(t *testing.T) {
	ctx := context.Background()
	const height = uint64(1)
	blockTime := time.Unix(1_700_000_000, 0)

	run := func() ids.ID {
		h := newConservationHarness(t, nil)
		var taker ids.ShortID
		copy(taker[:], "fixed-taker-addr-1234")
		asset := ids.ID{0xcd}
		fixedUTXO := ids.ID{0xab}
		// FIXED source chain too: executeImport keys the atomic RemoveRequests by
		// SourceChain and the faithful root commits them, so the harness's random
		// cChain would (correctly) fork the root. A determinism check must hold every
		// input fixed.
		srcChain := ids.ID{0xef}
		importTx := newImportTxBytes(t, taker, srcChain, fixedUTXO, asset, 1000)
		res, err := h.vm.ProcessBlock(ctx, height, blockTime, [][]byte{importTx})
		if err != nil {
			t.Fatalf("ProcessBlock: %v", err)
		}
		return res.StateRoot
	}

	if r1, r2 := run(), run(); r1 != r2 {
		t.Fatalf("DETERMINISM BROKEN: identical block on two validators produced "+
			"DIFFERENT roots %x vs %x — a faithful root must be a pure function of "+
			"(inputs, state).", r1[:8], r2[:8])
	} else {
		t.Logf("identical state => identical root: %x", r1[:8])
	}
}
