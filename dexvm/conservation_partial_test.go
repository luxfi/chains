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

	result, err := h.vm.ProcessBlock(ctx, 1, time.Unix(1, 0), [][]byte{importTx, relayTx})
	if err != nil {
		t.Fatalf("ProcessBlock: %v", err)
	}
	if err := h.vm.acceptBlock(result); err != nil {
		t.Fatalf("acceptBlock: %v", err)
	}

	return collateral, exportedTotal(t, h)
}

// fillNotional returns the value a fill stream realizes in the asset the taker
// LOCKED: a BUY locks quote and the realized quote spent is sum(price*size); a
// SELL locks base and the realized base sold is sum(size). This is the amount
// that legitimately leaves as the *other* asset's proceeds — the rest of the
// locked collateral is the unfilled remainder that conservation requires be
// refunded.
func fillNotional(fills []Fill, takerSide uint8) uint64 {
	var n uint64
	for _, f := range fills {
		if takerSide == 0 { // BUY locked quote; quote consumed = price*size
			n += uint64(f.Price * f.Size)
		} else { // SELL locked base; base consumed = size
			n += uint64(f.Size)
		}
	}
	return n
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
