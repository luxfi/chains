// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build redteam

// redteam_fill_attestation_test.go — the MEDIUM single-proposer fabricated-fills proof.
// A malicious/MITM proposer can carry FABRICATED fills (carried_fills.go). The fix: the
// venue (d-chain matcher) ATTESTS the fills with an Ed25519 signature over the canonical
// (blockHash, entries) message, and every validator verifies it before settling. These
// tests prove:
//
//   (1) enforcement OFF (no venue pubkey): carried fills settle as before (interim model);
//   (2) enforcement ON + VALID attestation: the attested fills settle normally;
//   (3) enforcement ON + NO/INVALID attestation: the (possibly fabricated) fills are
//       DISTRUSTED — every submit is refunded in full, no fabricated proceeds move.

package dexvm

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/crypto/ed25519"
	"github.com/luxfi/ids"
)

// TestRED_FillAttestation_VerifyRejectsForgedFills is the unit-level proof of the
// verify gate over the canonical message: a correct venue signature verifies; a missing
// one, a wrong-key one, and a tampered-entries one are all rejected when a pubkey is
// configured; and with NO pubkey enforcement is off (any/no sig passes).
func TestRED_FillAttestation_VerifyRejectsForgedFills(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	blockHash := ids.GenerateTestID()
	entries := []carriedFill{{txIndex: 0, fills: []Fill{{Price: 2, Size: 100, Side: 0}}}}

	sig := signFillAttestation(priv, blockHash, entries)
	if len(sig) == 0 {
		t.Fatalf("signFillAttestation produced no signature")
	}

	// Valid signature, enforcement on => accepted.
	if err := verifyFillAttestation(pub, sig, blockHash, entries); err != nil {
		t.Fatalf("a valid venue attestation must verify, got: %v", err)
	}

	// Missing signature, enforcement on => required.
	if err := verifyFillAttestation(pub, nil, blockHash, entries); err != ErrFillAttestationRequired {
		t.Fatalf("a missing attestation under enforcement must be ErrFillAttestationRequired, got: %v", err)
	}

	// Wrong key => invalid (an attacker cannot forge the venue's signature).
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := verifyFillAttestation(otherPub, sig, blockHash, entries); err != ErrFillAttestationInvalid {
		t.Fatalf("a signature under a different key must be ErrFillAttestationInvalid, got: %v", err)
	}

	// TAMPERED ENTRIES (the fabrication): the proposer keeps the venue's signature but
	// swaps in fabricated fills. The message changes => the signature no longer verifies.
	forged := []carriedFill{{txIndex: 0, fills: []Fill{{Price: 2, Size: 1_000_000, Side: 0}}}}
	if err := verifyFillAttestation(pub, sig, blockHash, forged); err != ErrFillAttestationInvalid {
		t.Fatalf("a fabricated fill set under the genuine signature must be ErrFillAttestationInvalid, got: %v", err)
	}

	// DIFFERENT BLOCK (replay): the same fills+sig under a different block hash fail —
	// the message binds the block hash, so a venue signature is not replayable.
	if err := verifyFillAttestation(pub, sig, ids.GenerateTestID(), entries); err != ErrFillAttestationInvalid {
		t.Fatalf("a venue signature replayed onto another block must be ErrFillAttestationInvalid, got: %v", err)
	}

	// No pubkey configured => enforcement off => nil regardless of sig.
	if err := verifyFillAttestation(nil, nil, blockHash, entries); err != nil {
		t.Fatalf("with no venue pubkey, enforcement is off and verify must return nil, got: %v", err)
	}

	// Misconfigured (wrong-width) pubkey must FAIL CLOSED, never silently disable.
	if err := verifyFillAttestation([]byte{1, 2, 3}, sig, blockHash, entries); err != ErrFillAttestationInvalid {
		t.Fatalf("a malformed pubkey must fail closed (ErrFillAttestationInvalid), got: %v", err)
	}
}

// TestRED_FillAttestation_EndToEnd_ValidAttestationSettles is the positive control: a
// proposer co-located with the venue (holds the seed) signs the carried fills, and with
// the matching pubkey configured the attested cross-asset fills settle normally — the
// taker receives the real output proceeds.
func TestRED_FillAttestation_EndToEnd_ValidAttestationSettles(t *testing.T) {
	// One key pair shared by the (co-located) proposer-signer and the validators: the
	// proposer signs with `seed`, the validators verify with the derived pubkey.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv, err := ed25519.NewKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("derive key from seed: %v", err)
	}
	pubFromSeed := priv.Public().(ed25519.PublicKey)

	fills := []Fill{{Price: 2, Size: 150, Side: 0}}
	cvm, matcher, cChainSM, proxyChain, _ := newCountingHarness(t, fills)
	// Enforcement ON with the matching key pair (proposer signs with seed; validators
	// verify with the derived pubkey).
	cvm.inner.Config.FillAttestationSeed = seed
	cvm.inner.Config.FillAttestationPubKey = pubFromSeed
	ctx := context.Background()

	taker := ids.GenerateTestShortID()
	quoteAsset := ids.GenerateTestID()
	baseAsset := ids.GenerateTestID()
	const lockedQuote uint64 = 1000

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
		t.Fatalf("verify: %v", err)
	}
	if err := built.Accept(ctx); err != nil {
		t.Fatalf("accept: %v", err)
	}

	legs := exportedLegsByAsset(t, cChainSM, proxyChain, taker)
	if legs[baseAsset] != 150 {
		t.Fatalf("attested fills must settle: taker base proceeds=%d, want 150 (legs=%v)", legs[baseAsset], legs)
	}
	if submits, _, _ := matcher.counts(); submits != 1 {
		t.Fatalf("expected exactly one proposer relay submit, got %d", submits)
	}
	t.Logf("ATTESTATION OK: venue-signed cross-asset fill settled (150 base proceeds + %d quote refund)", legs[quoteAsset])
}

// TestRED_FillAttestation_FabricatedFillsRefunded is the decisive fabricated-fills
// proof. Enforcement is ON (a venue pubkey is configured) but the proposer holds NO
// signing seed, so the block it builds carries NO attestation — modeling a proposer
// that fabricates fills it cannot get the venue to sign. Every settle is then a FULL
// REFUND: the taker's locked collateral returns to C and NO fabricated proceeds move.
func TestRED_FillAttestation_FabricatedFillsRefunded(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// A proposer carries a FABRICATED fill (200 base) but cannot attest it (no seed).
	fills := []Fill{{Price: 2, Size: 200, Side: 0}}
	cvm, _, cChainSM, proxyChain, _ := newCountingHarness(t, fills)
	cvm.inner.Config.FillAttestationPubKey = pub // enforcement ON
	// NO FillAttestationSeed => the proposer's block carries an empty signature.
	ctx := context.Background()

	taker := ids.GenerateTestShortID()
	quoteAsset := ids.GenerateTestID()
	baseAsset := ids.GenerateTestID()
	const lockedQuote uint64 = 1000

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
		t.Fatalf("verify: %v", err)
	}
	if err := built.Accept(ctx); err != nil {
		t.Fatalf("accept: %v", err)
	}

	legs := exportedLegsByAsset(t, cChainSM, proxyChain, taker)
	t.Logf("AFTER UNATTESTED (fabricated) BLOCK: base proceeds=%d quote refund=%d", legs[baseAsset], legs[quoteAsset])

	// NO fabricated proceeds moved: the base proceeds leg is absent (the unattested fills
	// were distrusted), and the taker is made whole by a FULL quote refund.
	if legs[baseAsset] != 0 {
		t.Fatalf("FABRICATED FILL SETTLED: %d base proceeds moved despite a missing venue attestation — a "+
			"lying proposer minted proceeds for fills the venue never confirmed.", legs[baseAsset])
	}
	if legs[quoteAsset] != lockedQuote {
		t.Fatalf("fail-secure refund broken: quote refund=%d, want the full locked %d (an unattested block must "+
			"refund the taker, not strand or partially settle).", legs[quoteAsset], lockedQuote)
	}
}

// TestRED_FillAttestation_OffByDefaultSettlesInterim pins that with NO venue pubkey
// (the single-trusted-operator / dev default) enforcement is off and carried fills
// settle exactly as the interim model — so the new gate is strictly opt-in and does not
// regress existing deployments.
func TestRED_FillAttestation_OffByDefaultSettlesInterim(t *testing.T) {
	fills := []Fill{{Price: 2, Size: 100, Side: 0}}
	cvm, _, cChainSM, proxyChain, _ := newCountingHarness(t, fills)
	// Default config: no FillAttestationPubKey => enforcement off.
	ctx := context.Background()

	taker := ids.GenerateTestShortID()
	quoteAsset := ids.GenerateTestID()
	baseAsset := ids.GenerateTestID()
	const lockedQuote uint64 = 1000

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
		t.Fatalf("verify: %v", err)
	}
	if err := built.Accept(ctx); err != nil {
		t.Fatalf("accept: %v", err)
	}

	legs := exportedLegsByAsset(t, cChainSM, proxyChain, taker)
	if legs[baseAsset] != 100 {
		t.Fatalf("with enforcement off, carried fills must settle as before: base proceeds=%d, want 100", legs[baseAsset])
	}
}
