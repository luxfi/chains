// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"errors"

	"github.com/luxfi/crypto/ed25519"
	"github.com/luxfi/ids"
	"github.com/zeebo/blake3"
)

// fill_attestation.go closes the MEDIUM single-proposer carried-fills trust gap: the
// d-chain MATCHER (the venue) ATTESTS the fills it returned with an Ed25519 signature
// over a canonical message; every validator verifies that signature before settling
// from the carried fills. Without it, a malicious or MITM proposer can carry FABRICATED
// fills (carried_fills.go documents this as the interim, conservation-bounded trust
// surface — a lying proposer is bounded to ONE taker's own escrow, never supply
// inflation, but it CAN mis-settle that taker). With it, the proceeds a validator
// settles are ATTESTED by the venue, not merely proposer-asserted.
//
// THE RESERVED SLOT. The carried-fills wire (carried_fills.go encode/decodeCarriedFills)
// already reserves a self-delimiting `sig` field. This module fills it: the signature
// rides there with NO further wire-format change (the reserved-but-unimplemented slot
// noted at vm.go BuildBlockResult). The trustless evolution path (P3Q -> starkfri ZK
// proof of the matching) can later replace the Ed25519 verify here behind the SAME slot.
//
// SCHEME. Ed25519 (luxfi/crypto) over blake3(domain || blockHash || canonical-entries).
// The message is a DETERMINISTIC function of the block hash + the carried entries, so
// every validator recomputes the identical message and a single venue signature covers
// the whole block's fills. The message binds the BLOCK HASH so a venue signature for one
// block's fills cannot be replayed onto another block (a different block hash => a
// different message => the signature fails).
//
// ENFORCEMENT GATE (config.RequireFillAttestation, derived: ON iff a venue pubkey is
// configured). For an UNTRUSTED validator set the operator configures the venue's
// attestation pubkey; enforcement is then ON and a block whose carried fills lack a
// valid attestation is settled as a FULL REFUND (zero-fill) — fail-secure: an
// unattested/forged fill never moves proceeds. For a single-trusted-operator dev
// network no pubkey is configured; enforcement is OFF and the carried fills settle as
// before (the documented interim model). Default-on the moment a pubkey exists.

// fillAttestationDomain scopes the attestation message so a venue signature over a
// carried-fills block can never be confused with any other Ed25519 message the venue
// key might sign.
const fillAttestationDomain = "lux.dex.dexvm.fills.attestation.v1"

var (
	// ErrFillAttestationRequired is returned when enforcement is on (a venue pubkey is
	// configured) but the block carried NO attestation signature.
	ErrFillAttestationRequired = errors.New("dexvm: fill attestation required but the block carried no signature")
	// ErrFillAttestationInvalid is returned when the carried signature does not verify
	// against the configured venue pubkey over the canonical (blockHash, entries) message.
	ErrFillAttestationInvalid = errors.New("dexvm: carried fill attestation signature is invalid")
)

// fillAttestationMessage builds the canonical, deterministic message a venue signs to
// attest the fills it returned for a block: blake3(domain || blockHash || entries),
// where the entries are serialized in their canonical block-order form (the SAME
// length-prefixed encoding the block carries, MINUS the reserved sig — a signature can
// obviously not cover itself). Every validator recomputes this identically, so one
// venue signature covers the whole block's carried fills.
func fillAttestationMessage(blockHash ids.ID, entries []carriedFill) []byte {
	// encodeCarriedFills(entries, nil) is the canonical entries serialization with an
	// empty sig tail — a deterministic function of (txIndex, fills) in block order.
	body := encodeCarriedFills(entries, nil)
	h := blake3.New()
	_, _ = h.Write([]byte(fillAttestationDomain))
	_, _ = h.Write(blockHash[:])
	_, _ = h.Write(body)
	var sum [32]byte
	h.Digest().Read(sum[:])
	return sum[:]
}

// signFillAttestation produces the venue's Ed25519 attestation over the canonical
// (blockHash, entries) message. The proposer uses this ONLY when it holds the venue
// signing key (a co-located single-operator venue); otherwise the venue returns the
// signature alongside its fills and the proposer carries it verbatim. A nil/empty key
// yields a nil signature (no attestation produced).
func signFillAttestation(signer ed25519.PrivateKey, blockHash ids.ID, entries []carriedFill) []byte {
	if len(signer) != ed25519.PrivateKeySize {
		return nil
	}
	return ed25519.Sign(signer, fillAttestationMessage(blockHash, entries))
}

// verifyFillAttestation checks the carried signature against the configured venue
// pubkey over the canonical (blockHash, entries) message, applying the enforcement
// gate:
//
//   - pubKey empty (no venue key configured: single-trusted-operator / dev): enforcement
//     is OFF; returns nil regardless of sig (the documented interim trust model).
//   - pubKey set (untrusted validator set): enforcement is ON; a missing signature is
//     ErrFillAttestationRequired and an invalid one is ErrFillAttestationInvalid. Only a
//     signature that verifies against the venue pubkey permits the carried fills to
//     settle — so a fabricated fill with no/invalid attestation is refused.
func verifyFillAttestation(pubKey []byte, sig []byte, blockHash ids.ID, entries []carriedFill) error {
	if len(pubKey) == 0 {
		return nil // enforcement off (no venue attestation key configured)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		// A misconfigured (wrong-width) pubkey must FAIL CLOSED — never silently treat a
		// garbage key as "no enforcement", which would re-open the proposer-trust gap.
		return ErrFillAttestationInvalid
	}
	if len(sig) == 0 {
		return ErrFillAttestationRequired
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrFillAttestationInvalid
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKey), fillAttestationMessage(blockHash, entries), sig) {
		return ErrFillAttestationInvalid
	}
	return nil
}
