// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// conservation_partial_test.go — the value-conservation proof under PARTIAL and
// FAILED settlement, the cases the happy-path 100%-fill test cannot reach.
//
// THE CONSERVATION LAW the atomic proxy must obey, stated as an equation over a
// single round (import -> relay -> settle -> export), measured in the asset the
// taker LOCKED on import:
//
//	value_in  = collateral locked by the Import (debited from C-Chain)
//	value_out = proceeds exported back + unfilled collateral refunded back
//	REQUIRED:  value_in == value_out          (conserved: nothing minted, nothing destroyed)
//	WEAKER:    value_out <= value_in          (no-mint only; a LEAK still passes this)
//
// The happy-path test (TestEndToEndAtomicValueConservation) fills 100% at
// price 1, so value_in == value_out trivially and the weaker no-mint bound is
// indistinguishable from true conservation. These tests separate the two: on a
// partial or zero fill the locked collateral exceeds the realized proceeds, so a
// proxy that does not REFUND the unfilled remainder destroys value while still
// satisfying the no-mint bound. The taker's exported credit is measured directly
// from C-Chain shared memory after accept (server-side truth), never asserted.
//
// These run under `GOWORK=off CGO_ENABLED=0 go test ./...` — pure Go, in-memory
// two-chain atomic.SharedMemory, fake d-chain matcher via the zapDialer seam.

package dexvm

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"

	"github.com/luxfi/chains/dexvm/txs"
)

// settledRound drives one full import -> relay(clob_submit) -> accept round on a
// fresh harness whose fake matcher returns exactly `fills`, with the taker
// locking `collateral` units of `lockedAsset` on the import leg. It returns the
// TOTAL value the C-Chain can claim back afterwards (proceeds + any refund),
// summed across every exported element owned by the taker. This is the measured
// `value_out` of the conservation equation.
func settledRound(t *testing.T, fills []Fill, collateral uint64, takerSide uint8) (valueIn, valueOut uint64) {
	t.Helper()
	// The matcher must echo the taker side on every fill (the proxy reads the
	// settlement direction from fills[0].Side), so stamp it.
	stamped := make([]Fill, len(fills))
	for i, f := range fills {
		f.Side = takerSide
		stamped[i] = f
	}
	h := newConservationHarness(t, stamped)
	ctx := context.Background()

	taker := ids.GenerateTestShortID()
	h.exportTaker = taker
	lockedAsset := ids.GenerateTestID()

	// C-Chain exports `collateral` units into shared memory for the proxy to import.
	srcUTXOID := deriveUTXOID(ids.GenerateTestID(), 0)
	exportedVal := encodeExportedOutput(txs.AtomicOutput{Owner: taker, Asset: lockedAsset, Amount: collateral})
	if err := h.cChainSM.Apply(map[ids.ID]*atomic.Requests{
		h.proxyChain: {PutRequests: []*atomic.Element{{
			Key:    srcUTXOID[:],
			Value:  exportedVal,
			Traits: [][]byte{taker[:]},
		}}},
	}); err != nil {
		t.Fatalf("seed C-Chain export: %v", err)
	}

	// import (locks `collateral`) -> relay clob_submit (matcher returns `fills`).
	importTx := newImportTxBytes(t, taker, h.cChain, srcUTXOID, lockedAsset, collateral)
	// size in the submit frame is the taker's requested size; the matcher ignores
	// it and returns the canned fills, so any positive value is fine here.
	relayTx := newRelayTxBytes(t, taker, srcUTXOID, clobSubmitPayload(lockedAsset, collateral))

	// Propose (relay ONCE at build, carry the fills) + accept (settle from carried
	// bytes). RED #9: the relay moved from accept to build; the conservation
	// arithmetic at settle is unchanged.
	_ = ctx
	proposeAndAccept(t, h.vm, 1, time.Unix(1, 0), [][]byte{importTx, relayTx})

	return collateral, exportedTotal(t, h)
}

// fillNotional returns the SPENT quantity a fill stream consumes from the asset
// the taker LOCKED: a BUY locks quote and the realized quote spent is
// sum(price*size); a SELL locks base and the realized base sold is sum(size).
// This is the amount that legitimately leaves as the *other* asset's proceeds —
// the rest of the locked collateral is the unfilled remainder conservation
// requires be refunded.
//
// It mirrors settleFromFills exactly: the spent quantity is aggregated over the
// fills as an exact float and rounded UP (ceiling) ONCE — the conservation-safe
// direction for a charge, so the refund (locked - spent) is never inflated. (The
// prior per-fill uint64 truncation was the escrow-extraction bug.)
func fillNotional(fills []Fill, takerSide uint8) uint64 {
	var n float64
	for _, f := range fills {
		if takerSide == 0 { // BUY locked quote; quote consumed = price*size
			n += f.Price * f.Size
		} else { // SELL locked base; base consumed = size
			n += f.Size
		}
	}
	return ceilToUnit(n)
}

// ceilToUnit rounds a non-negative float aggregate UP to integer asset units,
// snapping a mathematically-integral aggregate (e.g. 1.5*3+2.5*3 == 12, but may
// evaluate to 12 ± 1e-13) to that integer first. It mirrors atomic.go's
// quantToCharge so the tests reason in the SAME arithmetic the proxy uses.
func ceilToUnit(f float64) uint64 {
	r := math.Round(f)
	if math.Abs(f-r) <= 1e-9*math.Max(1, math.Abs(f)) {
		return uint64(r)
	}
	return uint64(math.Ceil(f))
}

// TestConservationPartialFillBuy is the decisive partial-settlement proof. The
// taker locks 1000 quote and submits a marketable BUY, but the book only fills
// 400 quote worth (200 base @ price 2). Conservation REQUIRES the C-Chain get
// back 1000 total — 200 base of proceeds PLUS 600 quote refunded. The proxy
// credits only the 200-base proceeds leg, so 600 quote of locked collateral is
// destroyed. The test states the law and prints the measured imbalance.
func TestConservationPartialFillBuy(t *testing.T) {
	const lockedQuote uint64 = 1000
	// One fill: 200 base @ price 2 => 400 quote spent, 600 quote should refund.
	fills := []Fill{{Price: 2, Size: 200}}
	const takerSide uint8 = 0 // BUY

	valueIn, valueOut := settledRound(t, fills, lockedQuote, takerSide)

	spentQuote := fillNotional(fills, takerSide) // 400
	wantRefund := valueIn - spentQuote           // 600

	// Proceeds the taker received, denominated in the proceeds asset (base). The
	// taker's exported credit is split across two assets (base proceeds + quote
	// refund) but exportedTotal sums raw amounts; we reason in conservation units.
	t.Logf("CONSERVATION LEDGER (BUY, partial): value_in(locked quote)=%d  spent_quote=%d  required_refund=%d  measured_value_out(total exported to taker)=%d",
		valueIn, spentQuote, wantRefund, valueOut)

	// No-mint bound MUST always hold (the proxy never fabricates value).
	if valueOut > valueIn {
		t.Fatalf("NO-MINT VIOLATED: value_out=%d > value_in=%d", valueOut, valueIn)
	}

	// Full conservation: every locked unit comes back either as proceeds or refund.
	// value_out is base-proceeds(200) + quote-refund(600) = 800 if the refund leg
	// exists; 200 (proceeds only) if it does not. We assert the conservation law:
	// value_out must equal proceeds(=200 base) + refund(=600 quote) = 800.
	const wantProceedsBase uint64 = 200
	wantOut := wantProceedsBase + wantRefund // 800
	if valueOut != wantOut {
		t.Fatalf("CONSERVATION VIOLATED on partial fill: measured value_out=%d, want proceeds(%d base)+refund(%d quote)=%d. "+
			"The %d-unit gap is locked collateral neither filled nor refunded — value DESTROYED in the proxy.",
			valueOut, wantProceedsBase, wantRefund, wantOut, wantOut-valueOut)
	}
}

// TestConservationZeroFill is the strongest case: a marketable order that
// crosses NOTHING. The taker locked 1000 quote; the matcher returns zero fills.
// Conservation REQUIRES the full 1000 be refunded to C-Chain. A proxy with no
// refund leg exports nothing, destroying the entire locked collateral.
func TestConservationZeroFill(t *testing.T) {
	const lockedQuote uint64 = 1000
	valueIn, valueOut := settledRound(t, nil, lockedQuote, 0)

	t.Logf("CONSERVATION LEDGER (zero fill): value_in(locked quote)=%d  required_refund=%d  measured_value_out=%d",
		valueIn, valueIn, valueOut)

	if valueOut > valueIn {
		t.Fatalf("NO-MINT VIOLATED: value_out=%d > value_in=%d", valueOut, valueIn)
	}
	if valueOut != valueIn {
		t.Fatalf("CONSERVATION VIOLATED on zero fill: measured value_out=%d, want full refund=%d. "+
			"%d units of locked collateral were DESTROYED (no fills, no refund export).",
			valueOut, valueIn, valueIn-valueOut)
	}
}

// TestConservationPartialFillSell mirrors the partial-fill proof for a SELL: the
// taker locks 1000 BASE and submits a marketable sell, but only 300 base fills
// (300 base @ price 5 => 1500 quote proceeds). Conservation REQUIRES 700 base
// refunded plus 1500 quote proceeds. Measured in conservation units, value_out
// must be proceeds(1500 quote) + refund(700 base) = 2200.
func TestConservationPartialFillSell(t *testing.T) {
	const lockedBase uint64 = 1000
	fills := []Fill{{Price: 5, Size: 300}} // 300 base sold, 1500 quote received
	const takerSide uint8 = 1              // SELL

	valueIn, valueOut := settledRound(t, fills, lockedBase, takerSide)

	soldBase := fillNotional(fills, takerSide) // 300
	wantRefund := valueIn - soldBase           // 700
	const wantProceedsQuote uint64 = 1500
	wantOut := wantProceedsQuote + wantRefund // 2200

	t.Logf("CONSERVATION LEDGER (SELL, partial): value_in(locked base)=%d  sold_base=%d  required_refund=%d  proceeds_quote=%d  measured_value_out=%d  want=%d",
		valueIn, soldBase, wantRefund, wantProceedsQuote, valueOut, wantOut)

	if valueOut != wantOut {
		t.Fatalf("CONSERVATION VIOLATED on partial sell: value_out=%d, want proceeds(%d quote)+refund(%d base)=%d (gap=%d destroyed)",
			valueOut, wantProceedsQuote, wantRefund, wantOut, wantOut-valueOut)
	}
}

// TestSettleConsumesEscrowOnce proves the refund leg cannot double-pay: once a
// settle has refunded the unfilled remainder, the escrow is consumed, so a
// second settle against the same collateral ref refunds NOTHING (it would
// otherwise mint a duplicate refund). This is the return-leg analogue of the
// import double-spend guard.
func TestSettleConsumesEscrowOnce(t *testing.T) {
	h := newConservationHarness(t, nil)
	taker := ids.GenerateTestShortID()
	lockedAsset := ids.GenerateTestID()
	ref := deriveUTXOID(ids.GenerateTestID(), 0)

	// Record an escrow of 1000 directly (the import leg's effect). The escrow owner
	// is the taker — the authenticated owner who alone may settle it (CRITICAL bind).
	if err := h.vm.state.PutEscrow(ref, taker, lockedAsset, 1000); err != nil {
		t.Fatalf("PutEscrow: %v", err)
	}

	// First settle with zero fills => full 1000 refund + escrow consumed.
	ar := newAtomicRequests()
	if err := h.vm.settleFromFills(taker, ref, nil, ids.GenerateTestID(), 0, ar); err != nil {
		t.Fatalf("first settle: %v", err)
	}
	if _, _, _, found, _ := h.vm.state.GetEscrow(ref); found {
		t.Fatal("escrow still present after settle — not consumed")
	}

	// Second settle against the now-consumed ref must refund nothing (no escrow).
	ar2 := newAtomicRequests()
	if err := h.vm.settleFromFills(taker, ref, nil, ids.GenerateTestID(), 1, ar2); err != nil {
		t.Fatalf("second settle: %v", err)
	}
	if !ar2.empty() {
		t.Fatal("second settle produced an export — escrow was double-refunded (value minted)")
	}
}

// TestFailedRelayCommitsNothing proves CONSERVATION on a FAILED build relay (RED
// #9). The relay is performed once by the PROPOSER at build (obtainFills); if it
// errors, the proposer carries an explicit ZERO-FILL entry for that order. Every
// validator then settles that as a full refund of the locked collateral — the
// taker's value returns to C-Chain in full, the escrow is consumed exactly once,
// and nothing is minted or destroyed. (This is the same conservation-safe path as
// a legitimate zero-fill submit; see TestConservationZeroFill.)
//
// This is STRICTLY stronger than the old relay-at-accept behavior (escrow left in
// limbo for a later retry): the value is returned immediately rather than stranded
// in escrow, and there is no per-validator divergence because the zero-fill is
// carried in the block bytes, settled identically by every node.
func TestFailedRelayCommitsNothing(t *testing.T) {
	h := newConservationHarness(t, nil)
	taker := ids.GenerateTestShortID()
	h.exportTaker = taker
	lockedAsset := ids.GenerateTestID()

	// Make the matcher fail the build relay (transport failure on the relay leg).
	h.matcher.failNext = true

	// Seed + import 1000 collateral, then relay (which will fail at the matcher).
	srcUTXOID := deriveUTXOID(ids.GenerateTestID(), 0)
	exportedVal := encodeExportedOutput(txs.AtomicOutput{Owner: taker, Asset: lockedAsset, Amount: 1000})
	if err := h.cChainSM.Apply(map[ids.ID]*atomic.Requests{
		h.proxyChain: {PutRequests: []*atomic.Element{{Key: srcUTXOID[:], Value: exportedVal, Traits: [][]byte{taker[:]}}}},
	}); err != nil {
		t.Fatalf("seed export: %v", err)
	}
	importTx := newImportTxBytes(t, taker, h.cChain, srcUTXOID, lockedAsset, 1000)
	relayTx := newRelayTxBytes(t, taker, srcUTXOID, clobSubmitPayload(lockedAsset, 1000))

	// Propose (build relay fails -> zero fills carried) + accept (settle -> full
	// refund of the 1000 locked collateral).
	proposeAndAccept(t, h.vm, 1, time.Unix(1, 0), [][]byte{importTx, relayTx})

	// CONSERVATION: the full locked collateral is refunded to C-Chain (no fills =>
	// no proceeds, refund == locked). Value is preserved exactly — nothing minted,
	// nothing destroyed.
	if got := exportedTotal(t, h); got != 1000 {
		t.Fatalf("failed build relay refunded %d to C-Chain, want 1000 (full refund of locked collateral)", got)
	}
	// The escrow is consumed exactly once by the refunding settle (it cannot be
	// refunded again).
	_, _, _, found, _ := h.vm.state.GetEscrow(srcUTXOID)
	if found {
		t.Fatalf("escrow after refund must be consumed exactly once, but it is still present")
	}
}

// TestConservationRoundingBoundary probes the float64->uint64 seam in the
// spent/refund split. settleFromFills aggregates the quote notional over the
// fills as an exact float and rounds the SPENT side UP (ceiling) ONCE — the
// conservation-safe direction so the refund (locked - spent) is never inflated.
// Two fractional fills (price 1.5 * size 3 = 4.5; price 2.5 * size 3 = 7.5) sum
// to an aggregate quote notional of exactly 12.0, so spent = ceil(12.0) = 12
// (NOT the old per-fill floor sum 4+7=11, which understated spend and over-
// refunded by 1). Proceeds base rounds DOWN: floor(sum(size)) = floor(6.0) = 6.
// The taker locked 1000 quote; refund = 1000-12 = 988, and value_out =
// base-proceeds(6) + quote-refund(988) = 994.
func TestConservationRoundingBoundary(t *testing.T) {
	const lockedQuote uint64 = 1000
	fills := []Fill{{Price: 1.5, Size: 3}, {Price: 2.5, Size: 3}} // BUY
	const takerSide uint8 = 0

	valueIn, valueOut := settledRound(t, fills, lockedQuote, takerSide)

	// SPENT quote = aggregate notional, rounded UP (the exact arithmetic
	// settleFromFills uses via quantToCharge). Mirrors fillNotional.
	spent := fillNotional(fills, takerSide)
	// PROCEEDS base = aggregate size, rounded DOWN (quantToCredit).
	var baseAgg float64
	for _, f := range fills {
		baseAgg += f.Size
	}
	proceedsBase := uint64(math.Floor(baseAgg))

	wantRefund := lockedQuote - spent
	wantOut := proceedsBase + wantRefund

	t.Logf("CONSERVATION LEDGER (rounding): value_in=%d  spent(ceil)=%d  proceeds_base(floor)=%d  refund=%d  measured_value_out=%d  want=%d",
		valueIn, spent, proceedsBase, wantRefund, valueOut, wantOut)

	if spent != 12 || proceedsBase != 6 {
		t.Fatalf("arithmetic anchor drifted: spent=%d (want 12) proceeds_base=%d (want 6)", spent, proceedsBase)
	}
	if valueOut != wantOut {
		t.Fatalf("CONSERVATION VIOLATED at rounding boundary: value_out=%d, want %d. "+
			"refund and proceeds legs disagree on the rounded notional — sub-unit value leaked.", valueOut, wantOut)
	}
	if valueOut > valueIn {
		t.Fatalf("NO-MINT VIOLATED: value_out=%d > value_in=%d", valueOut, valueIn)
	}
}
