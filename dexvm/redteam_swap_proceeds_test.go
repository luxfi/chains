// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build redteam

// redteam_swap_proceeds_test.go — the HIGH-1 happy-path proof: a swap's PROCEEDS
// leg is exported under the REAL output-asset id, so the C-side ImportSettlement can
// actually credit the taker and the swap COMPLETES.
//
// THE BUG (now closed): settleFromFills exported the proceeds leg under
// assetFromRef(collateralRef, leg) = SHA256(ref||leg) — a synthetic routing handle.
// The C-side ImportSettlement requires recAsset == claim.Asset == assetID(currency_out)
// (the injective 32-byte id that ALSO keys seamReserve[assetOut]). A SHA256 handle can
// never equal an injective assetID, so the proceeds credit ALWAYS failed with
// ErrNativeSettleAsset — the taker NEVER received their swap output. Normal swaps did
// not complete (the swarm's swapsWork=NO).
//
// THE FIX: settleFromFills exports the proceeds leg under the REAL output-asset id
// carried with the settling relay (RelayOrderTx.AssetOut). These tests drive the full
// cross-asset match -> D export and assert the proceeds object decodes under EXACTLY the
// real output asset (the value the C-side equality-binds), at both the unit level
// (direct settleFromFills) and end-to-end (proposer build -> accept -> settle).

package dexvm

import (
	"context"
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/luxfi/ids"

	"github.com/luxfi/chains/dexvm/txs"
)

// decodeExportLeg reads one exported D->C object (rail|owner|asset|amount) the way the
// C-side decodeAtomicObject does, so the assertions reason in the C-side's own terms.
func decodeExportLeg(v []byte) (owner ids.ShortID, asset ids.ID, amount uint64, ok bool) {
	if len(v) != exportedOutputSize {
		return ids.ShortEmpty, ids.Empty, 0, false
	}
	copy(owner[:], v[1:21])
	copy(asset[:], v[21:53])
	amount = binary.BigEndian.Uint64(v[53:61])
	return owner, asset, amount, true
}

// legsTo returns every exported leg credited to `owner`, keyed by asset id. This is
// the exact shape the C-side ImportSettlement consumes: for the taker to be credited,
// there must be a leg whose ASSET equals the real output asset.
func legsTo(ar *atomicRequests, owner ids.ShortID) map[ids.ID]uint64 {
	out := make(map[ids.ID]uint64)
	for _, reqs := range ar.reqs {
		for _, e := range reqs.PutRequests {
			o, a, amt, ok := decodeExportLeg(e.Value)
			if ok && o == owner {
				out[a] += amt
			}
		}
	}
	return out
}

// TestRED_SwapProceeds_ExportedUnderRealOutputAsset is the UNIT-level HIGH-1 proof. A
// taker BUYs (locks quote, receives base): settleFromFills MUST export the base
// proceeds under the REAL base asset id (the relay's declared AssetOut), NOT a
// SHA256(ref||leg) handle. The C-side ImportSettlement equality-binds recAsset ==
// assetID(currency_out); only an export under the real id can ever satisfy it.
func TestRED_SwapProceeds_ExportedUnderRealOutputAsset(t *testing.T) {
	// Taker BUY: 100 base @ price 2 => receives 100 base, spends 200 quote.
	fills := []Fill{{Price: 2, Size: 100, Side: 0}}
	cvm, _, _, _, _ := newCountingHarness(t, fills)

	taker := ids.GenerateTestShortID()
	collateralRef := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID() // the LOCKED (input) asset
	baseAsset := ids.GenerateTestID()  // the REAL output asset the taker receives
	const lockedQuote uint64 = 500

	if err := cvm.inner.state.PutEscrow(collateralRef, taker, quoteAsset, lockedQuote); err != nil {
		t.Fatalf("PutEscrow: %v", err)
	}

	// Settle with the REAL output asset declared (baseAsset) — the HIGH-1 fix path.
	ar := newAtomicRequests()
	if err := cvm.inner.settleFromFills(taker, collateralRef, fills, baseAsset, 0, false, ids.GenerateTestID(), 0, ar); err != nil {
		t.Fatalf("settleFromFills: %v", err)
	}

	legs := legsTo(ar, taker)

	// THE PROCEEDS LEG MUST BE UNDER THE REAL OUTPUT ASSET. Pre-fix this was a
	// SHA256(ref||leg) handle the C-side could never match.
	proceeds, ok := legs[baseAsset]
	if !ok {
		t.Fatalf("HIGH-1 NOT FIXED: no proceeds leg exported under the real output asset %s. "+
			"Exported legs: %v. The C-side ImportSettlement binds recAsset==assetID(currency_out); "+
			"a proceeds leg under any other id (e.g. a SHA256(ref||leg) handle) is permanently unclaimable.",
			baseAsset, legs)
	}
	if proceeds != 100 {
		t.Fatalf("proceeds amount = %d, want 100 base (sum(size)=100)", proceeds)
	}

	// The refund leg is the unspent locked quote (500 locked - 200 spent = 300), under
	// the REAL quote asset. Conservation: 100 base proceeds + 300 quote refund.
	if refund := legs[quoteAsset]; refund != 300 {
		t.Fatalf("refund leg = %d quote, want 300 (locked 500 - spent 200)", refund)
	}

	// Belt-and-braces: assert NO leg is exported under the OLD synthetic handle, so a
	// regression that re-introduces assetFromRef would be caught here.
	staleHandle := ids.ID(idHash(append(append([]byte{}, collateralRef[:]...), 0)))
	if _, bad := legs[staleHandle]; bad {
		t.Fatalf("REGRESSION: proceeds exported under the stale SHA256(ref||leg) handle %s — "+
			"the C-side can never claim it.", staleHandle)
	}
}

// TestRED_SwapProceeds_EndToEnd_TakerCreditedRealOutput is the END-TO-END HIGH-1
// happy-path proof on the real import -> relay -> build -> accept -> settle path. A
// taker imports quote collateral, submits a SETTLING relay that declares the real base
// output asset, and after accept the taker is credited the correct base amount UNDER
// THE REAL BASE ASSET — the exact object the C-side ImportSettlement consumes to credit
// the swap output. This is the proof that swaps actually complete.
func TestRED_SwapProceeds_EndToEnd_TakerCreditedRealOutput(t *testing.T) {
	// Taker BUY: book fills 150 base @ price 2 => 150 base received, 300 quote spent.
	fills := []Fill{{Price: 2, Size: 150, Side: 0}}
	cvm, matcher, cChainSM, proxyChain, _ := newCountingHarness(t, fills)
	ctx := context.Background()

	taker := ids.GenerateTestShortID()
	quoteAsset := ids.GenerateTestID() // locked input
	baseAsset := ids.GenerateTestID()  // real output
	const lockedQuote uint64 = 1000

	// The C-Chain exported `lockedQuote` of the quote asset to the proxy for the taker
	// (the import binds the escrow owner = taker from the recorded UTXO).
	srcUTXOID := seedExportedUTXO(t, cChainSM, proxyChain, taker, quoteAsset, lockedQuote)
	importTx := newImportTxBytes(t, taker, cvm.inner.cChainID(), srcUTXOID, quoteAsset, lockedQuote)

	// The taker submits a SETTLING relay declaring the REAL output asset (baseAsset) —
	// what the keeper builds once it has resolved the market's output side.
	relayTx := newSettlingRelayTxBytes(t, taker, srcUTXOID, baseAsset, clobSubmitPayload(quoteAsset, lockedQuote), 0, false)

	// Proposer builds (relays once, carries fills) + accepts (settle from carried).
	cvm.inner.clock.Set(time.Unix(1, 0))
	cvm.pendingTxs = [][]byte{importTx, relayTx}
	built, err := cvm.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock: %v", err)
	}
	if err := cvm.SetPreference(ctx, built.ID()); err != nil {
		t.Fatalf("SetPreference: %v", err)
	}
	if err := built.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := built.Accept(ctx); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Read what the proxy exported to the taker on the C-Chain, by asset. This is the
	// set of objects the C-side ImportSettlement will consume.
	legs := exportedLegsByAsset(t, cChainSM, proxyChain, taker)

	t.Logf("AFTER CROSS-ASSET SWAP SETTLE: base proceeds=%d (under %s)  quote refund=%d (under %s)",
		legs[baseAsset], baseAsset, legs[quoteAsset], quoteAsset)

	// THE SWAP COMPLETES: the taker has a proceeds object UNDER THE REAL BASE ASSET for
	// the correct amount (150 base). The C-side ImportSettlement (recAsset==assetID(
	// currency_out)) can now credit it — pre-fix this object was under a SHA256 handle
	// and the credit ALWAYS reverted with ErrNativeSettleAsset.
	if legs[baseAsset] != 150 {
		t.Fatalf("HIGH-1 (swapsWork=NO) NOT FIXED: taker base proceeds under the real output asset = %d, want 150. "+
			"All exported legs: %v. Without a proceeds leg under assetID(currency_out), the taker's swap output is "+
			"permanently unclaimable on C.", legs[baseAsset], legs)
	}
	// Conservation: 150 base proceeds + (1000 - 300) = 700 quote refund.
	if legs[quoteAsset] != 700 {
		t.Fatalf("refund under the real quote asset = %d, want 700 (locked 1000 - spent 300)", legs[quoteAsset])
	}
	// Exactly one relay submit (the proposer relays once for the whole network).
	if submits, _, _ := matcher.counts(); submits != 1 {
		t.Fatalf("expected exactly one proposer relay submit, got %d", submits)
	}
	// The escrow was consumed exactly once (settled).
	if _, _, _, found, _ := cvm.inner.state.GetEscrow(srcUTXOID); found {
		t.Fatalf("a completed swap settle must consume the escrow exactly once (still present)")
	}
}

// exportedLegsByAsset reads the proxy's exports to `owner` on the C-Chain and buckets
// the amounts by asset id (the C-side's view of the objects it will import).
func exportedLegsByAsset(t *testing.T, cChainSM atomicShared, proxyChain ids.ID, owner ids.ShortID) map[ids.ID]uint64 {
	t.Helper()
	vals, _, _, err := cChainSM.Indexed(proxyChain, [][]byte{owner[:]}, nil, nil, 100)
	if err != nil {
		t.Fatalf("indexed: %v", err)
	}
	out := make(map[ids.ID]uint64)
	for _, v := range vals {
		if _, a, amt, ok := decodeExportLeg(v); ok {
			out[a] += amt
		}
	}
	return out
}

// atomicShared is the minimal shared-memory read surface this test needs (Indexed),
// satisfied by the real atomic.SharedMemory the harness wires.
type atomicShared interface {
	Indexed(peerChainID ids.ID, traits [][]byte, startTrait, startKey []byte, limit int) ([][]byte, []byte, []byte, error)
}

var _ = txs.RailSwap

// floatBits packs a float64 price into the uint64 wire form the relay carries (the
// same math.Float64bits the precompile's priceLimitToCLOB produces).
func floatBits(p float64) uint64 { return math.Float64bits(p) }

// TestRED_SwapSlippageLimit_RejectsWorseThanLimit is the MEDIUM (bounded sandwich/MEV)
// proof. A taker BUY carries a worst-acceptable price limit (an UPPER bound: never pay
// more than `limit` quote per base). A fill at a WORSE price (above the limit) is
// REFUSED before any value moves — the escrow stays intact and reclaimable — while a
// fill at/within the limit settles normally. Without this, a sandwich that pushes the
// price beyond the taker's floor would fill them at the adversarial price.
func TestRED_SwapSlippageLimit_RejectsWorseThanLimit(t *testing.T) {
	taker := ids.GenerateTestShortID()
	quoteAsset := ids.GenerateTestID()
	baseAsset := ids.GenerateTestID()
	const lockedQuote uint64 = 1000
	const limit = 2.0 // BUY ceiling: never pay more than 2 quote per base.

	// (a) WORSE fill: price 3 > limit 2 (a sandwich pushed the price up). Refused.
	worse := []Fill{{Price: 3, Size: 100, Side: 0}}
	cvm, _, _, _, _ := newCountingHarness(t, worse)
	ref := ids.GenerateTestID()
	if err := cvm.inner.state.PutEscrow(ref, taker, quoteAsset, lockedQuote); err != nil {
		t.Fatalf("PutEscrow: %v", err)
	}
	ar := newAtomicRequests()
	err := cvm.inner.settleFromFills(taker, ref, worse, baseAsset, floatBits(limit), true, ids.GenerateTestID(), 0, ar)
	if err == nil {
		t.Fatalf("MEV GUARD MISSING: a fill at price 3 (above the taker's limit 2) was settled — a "+
			"sandwich could fill the taker beyond their slippage floor.")
	}
	if !ar.empty() {
		t.Fatalf("a refused (out-of-limit) settle must export nothing")
	}
	// The escrow is intact and reclaimable (the refused settle did not consume it).
	if _, _, _, found, _ := cvm.inner.state.GetEscrow(ref); !found {
		t.Fatalf("a refused out-of-limit settle must leave the escrow intact for reclaim")
	}
	t.Logf("MEV GUARD: fill@3 rejected against BUY limit 2 (escrow intact): %v", err)

	// (b) AT-LIMIT fill: price 2 == limit 2. Settles normally (100 base proceeds).
	atLimit := []Fill{{Price: 2, Size: 100, Side: 0}}
	cvm2, _, _, _, _ := newCountingHarness(t, atLimit)
	ref2 := ids.GenerateTestID()
	if err := cvm2.inner.state.PutEscrow(ref2, taker, quoteAsset, lockedQuote); err != nil {
		t.Fatalf("PutEscrow: %v", err)
	}
	ar2 := newAtomicRequests()
	if err := cvm2.inner.settleFromFills(taker, ref2, atLimit, baseAsset, floatBits(limit), true, ids.GenerateTestID(), 0, ar2); err != nil {
		t.Fatalf("an at-limit fill (price == limit) must settle, got: %v", err)
	}
	if legsTo(ar2, taker)[baseAsset] != 100 {
		t.Fatalf("at-limit fill must credit 100 base proceeds, got %v", legsTo(ar2, taker))
	}
	t.Logf("MEV GUARD: fill@2 accepted at BUY limit 2 (100 base credited)")

	// (c) SELL floor: a SELL carries a LOWER bound (never receive less than `limit` quote
	// per base). A fill BELOW the floor is refused.
	sellFloor := []Fill{{Price: 4, Size: 100, Side: 1}}
	cvm3, _, _, _, _ := newCountingHarness(t, sellFloor)
	ref3 := ids.GenerateTestID()
	if err := cvm3.inner.state.PutEscrow(ref3, taker, baseAsset /*locked base for a sell*/, lockedQuote); err != nil {
		t.Fatalf("PutEscrow: %v", err)
	}
	ar3 := newAtomicRequests()
	if err := cvm3.inner.settleFromFills(taker, ref3, sellFloor, quoteAsset, floatBits(5.0), false, ids.GenerateTestID(), 0, ar3); err == nil {
		t.Fatalf("SELL floor MISSING: a fill at price 4 (below the floor 5) was settled.")
	}
	t.Logf("MEV GUARD: SELL fill@4 rejected against floor 5")
}
