// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build redteam

// byzantine_settlement_test.go proves the SETTLEMENT layer's byzantine guarantees
// that the fill-attestation tests do NOT cover: the CONSERVATION BOUND is
// independent of TRUST. Attestation (redteam_fill_attestation_test.go) proves a
// carried fill came from the venue key; this file proves that even a fill the venue
// GENUINELY SIGNED cannot make the proxy mint or misvalue.
//
// THREAT MODEL. Here the venue itself is byzantine and CO-LOCATED with the proposer
// (it holds the signing seed), so every fabricated fill it emits carries a VALID
// Ed25519 attestation — the attestation gate passes. The only thing standing
// between a lying venue and minted value is settleFromFills' conservation math:
//
//	spent > locked            => "would mint" => settle refused, escrow intact
//	mixed-side fill stream     => over-credit  => refused
//	(and: the settle is a PURE function of the fill SET, order-independent)
//
// These are the RED C4 / mixed-side / RED #9 guards, exercised through the real
// ChainVM Build->Verify->Accept lifecycle with a genuinely-signing byzantine venue.

package dexvm

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/crypto/ed25519"
	"github.com/luxfi/ids"
)

// byzantineVenueKeys returns a deterministic Ed25519 seed + derived public key for
// a byzantine venue that is co-located with the proposer (so it signs whatever
// fills it fabricates, and the attestation always VERIFIES).
func byzantineVenueKeys(t *testing.T) (seed []byte, pub ed25519.PublicKey) {
	t.Helper()
	seed = make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	priv, err := ed25519.NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("derive venue key: %v", err)
	}
	return seed, priv.Public().(ed25519.PublicKey)
}

// settleByzantineFills drives one import(locks `lockedQuote` quote) + settling BUY
// relay through the ChainVM with the byzantine venue's `fills`, and returns the
// export legs the C-Chain can claim. Enforcement is ON with the venue key, so the
// (byzantine) fills are VALIDLY ATTESTED — only the conservation math can stop them.
func settleByzantineFills(t *testing.T, fills []Fill, lockedQuote uint64) (taker ids.ShortID, baseAsset, quoteAsset ids.ID, legs map[ids.ID]uint64) {
	t.Helper()
	ctx := context.Background()
	seed, pub := byzantineVenueKeys(t)

	cvm, _, cChainSM, proxyChain, _ := newCountingHarness(t, fills)
	cvm.inner.Config.FillAttestationSeed = seed  // co-located byzantine venue signs
	cvm.inner.Config.FillAttestationPubKey = pub // enforcement ON, key matches => VALID attestation

	taker = ids.GenerateTestShortID()
	quoteAsset = ids.GenerateTestID()
	baseAsset = ids.GenerateTestID()

	srcUTXOID := seedExportedUTXO(t, cChainSM, proxyChain, taker, quoteAsset, lockedQuote)
	importTx := newImportTxBytes(t, taker, cvm.inner.cChainID(), srcUTXOID, quoteAsset, lockedQuote)
	relayTx := newSettlingRelayTxBytes(t, taker, srcUTXOID, baseAsset, clobSubmitPayload(quoteAsset, lockedQuote), 0, false)

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
		t.Fatalf("Verify: %v", err)
	}
	if err := built.Accept(ctx); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	return taker, baseAsset, quoteAsset, exportedLegsByAsset(t, cChainSM, proxyChain, taker)
}

// TestByzantineVenue_OverNotionalAttestedFillCannotMint is the keystone: a byzantine
// venue signs a fill whose notional EXCEEDS the taker's locked collateral (a BUY of
// 600 base @ price 2 = 1200 quote spent against only 1000 locked). The attestation
// is VALID (the venue holds the seed), so the trust gate passes — yet settleFromFills
// refuses "spent > locked" and NO value moves: no proceeds, no over-refund, escrow
// intact. Conservation is enforced INDEPENDENTLY of who signed the fill.
func TestByzantineVenue_OverNotionalAttestedFillCannotMint(t *testing.T) {
	const lockedQuote uint64 = 1000
	// BUY: receives base = 600, spends quote = 600*2 = 1200 > 1000 locked (mint attempt).
	fills := []Fill{{Price: 2, Size: 600, Side: 0}}

	_, baseAsset, quoteAsset, legs := settleByzantineFills(t, fills, lockedQuote)

	if legs[baseAsset] != 0 {
		t.Fatalf("MINT: %d base proceeds exported for a fill spending 1200 quote against 1000 locked — "+
			"a validly-attested over-notional fill minted value", legs[baseAsset])
	}
	// No over-refund either: the conservation refusal leaves the escrow intact rather
	// than exporting a partial/refund derived from the impossible fill.
	var exported uint64
	for _, v := range legs {
		exported += v
	}
	if exported > lockedQuote {
		t.Fatalf("MINT: exported %d > locked %d (proxy minted against its own escrow)", exported, lockedQuote)
	}
	if legs[quoteAsset] != 0 {
		t.Fatalf("over-notional fill produced a %d quote refund; the settle must refuse entirely (escrow intact), not partially settle", legs[quoteAsset])
	}
	t.Logf("CONSERVATION BOUND HELD: a VALIDLY-ATTESTED over-notional fill (1200 spent vs 1000 locked) minted 0 — escrow intact")
}

// TestByzantineVenue_WithinCollateralAttestedFillSettles is the positive control:
// the SAME byzantine venue signs a fill WITHIN the locked collateral (400 base @ 2 =
// 800 spent <= 1000 locked). This one settles — proceeds 400 base + refund 200 quote
// — proving the discriminator is the CONSERVATION BOUND (spent<=locked), not the
// attestation (both fills are validly signed). value_in == value_out exactly.
func TestByzantineVenue_WithinCollateralAttestedFillSettles(t *testing.T) {
	const lockedQuote uint64 = 1000
	// BUY: receives base = 400, spends quote = 400*2 = 800 <= 1000 locked.
	fills := []Fill{{Price: 2, Size: 400, Side: 0}}

	_, baseAsset, quoteAsset, legs := settleByzantineFills(t, fills, lockedQuote)

	if legs[baseAsset] != 400 {
		t.Fatalf("within-collateral attested fill must settle: base proceeds=%d, want 400", legs[baseAsset])
	}
	if legs[quoteAsset] != 200 {
		t.Fatalf("refund leg wrong: quote refund=%d, want 200 (locked 1000 - spent 800)", legs[quoteAsset])
	}
	// value_out (proceeds valued at price + refund) conserves the 1000 locked: the
	// 400 base proceeds cost 800 quote, + 200 quote refund == 1000 quote-equivalent.
	if legs[quoteAsset]+ /*spent*/ 800 != lockedQuote {
		t.Fatalf("CONSERVATION: refund %d + spent 800 != locked %d", legs[quoteAsset], lockedQuote)
	}
	t.Logf("CONTROL: a within-collateral attested fill settled (400 base proceeds + 200 quote refund) — bound is spent<=locked, not trust")
}

// TestByzantineVenue_MixedSideAttestedFillRefused proves the single-side guard under
// a genuinely-signing byzantine venue: a fill stream mixing BUY and SELL (which no
// honest single marketable submit can produce) is refused at settle, so the venue
// cannot over-credit by returning both-side volume. The attestation is valid; the
// settle refuses on the mixed-side invariant, leaving the escrow intact (no mint).
func TestByzantineVenue_MixedSideAttestedFillRefused(t *testing.T) {
	const lockedQuote uint64 = 1000
	// A lying venue returns [BUY 100, SELL 300]: the mixed-side over-credit attempt.
	fills := []Fill{{Price: 2, Size: 100, Side: 0}, {Price: 2, Size: 300, Side: 1}}

	_, baseAsset, quoteAsset, legs := settleByzantineFills(t, fills, lockedQuote)

	var exported uint64
	for _, v := range legs {
		exported += v
	}
	if legs[baseAsset] != 0 {
		t.Fatalf("MIXED-SIDE OVER-CREDIT: %d base proceeds exported for a mixed BUY/SELL stream — the single-side guard failed", legs[baseAsset])
	}
	if exported > lockedQuote {
		t.Fatalf("MINT via mixed-side: exported %d > locked %d", exported, lockedQuote)
	}
	if legs[quoteAsset] != 0 {
		t.Fatalf("mixed-side fill produced a %d quote refund; settle must refuse entirely (escrow intact)", legs[quoteAsset])
	}
	t.Logf("MIXED-SIDE GUARD HELD: a validly-attested [BUY,SELL] stream minted 0 — escrow intact")
}

// TestByzantineSettlement_DeterministicRegardlessOfFillOrder proves settle is a PURE
// FUNCTION of the fill SET, not its order (threat #5, RED #9). The byzantine venue
// returns the SAME two fills in two different orderings to two independent ChainVMs;
// both settle to byte-identical export legs. A settlement that depended on fill order
// would let a byzantine proposer bias the outcome by reordering; it does not.
func TestByzantineSettlement_DeterministicRegardlessOfFillOrder(t *testing.T) {
	const lockedQuote uint64 = 1000
	// Two same-side (BUY) fills; total spent = 3*100 + 2*150 = 600 <= 1000 locked.
	fillsAB := []Fill{{Price: 3, Size: 100, Side: 0}, {Price: 2, Size: 150, Side: 0}}
	fillsBA := []Fill{{Price: 2, Size: 150, Side: 0}, {Price: 3, Size: 100, Side: 0}}

	_, baseA, quoteA, legsAB := settleByzantineFills(t, fillsAB, lockedQuote)
	_, baseB, quoteB, legsBA := settleByzantineFills(t, fillsBA, lockedQuote)

	// Proceeds (base) = 100 + 150 = 250; spent quote = 300 + 300 = 600; refund = 400.
	if legsAB[baseA] != 250 || legsBA[baseB] != 250 {
		t.Fatalf("proceeds differ by fill order: AB=%d BA=%d, want 250 each", legsAB[baseA], legsBA[baseB])
	}
	if legsAB[quoteA] != legsBA[quoteB] {
		t.Fatalf("REORDER-DEPENDENT SETTLEMENT: refund AB=%d != BA=%d — settle is not a pure function of the fill set",
			legsAB[quoteA], legsBA[quoteB])
	}
	if legsAB[quoteA] != 400 {
		t.Fatalf("refund=%d, want 400 (locked 1000 - spent 600)", legsAB[quoteA])
	}
	t.Logf("ORDER-INDEPENDENT: both fill orderings settled to 250 base proceeds + 400 quote refund")
}
