// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// attest_security.go — the security-crossing attestation domain on the M-Chain.
//
// The same seam as attest_bridge.go, for paper that is a security rather than a
// fungible asset: M threshold-signs a domain-bound crossing message, B verifies
// it before the position lands, and B decides what the message means. M owns the
// signature; it holds no opinion about registers.
//
// The message itself is bridgeattest.SecurityCrossing, aliased rather than
// copied. attest_bridge.go keeps its own copy of BridgeTransfer and the two
// definitions have to be kept in step by hand, which is a way for the digest to
// drift on one side of a boundary whose whole value is that it cannot.

import (
	"context"
	"fmt"
	"time"

	"github.com/luxfi/chains/internal/bridgeattest"
)

// DomainSecurityCrossing registers the security domain with the attestation
// domain registry, alongside DomainBridgeTransfer.
const DomainSecurityCrossing AttestationDomain = "bridge/security"

func init() {
	domainSeparators[DomainSecurityCrossing] = []byte(bridgeattest.SecurityDomainTag)
}

// SecurityCrossing is the domain-bound message B commits to when a security
// leaves one register. Aliased from the shared package so M and B cannot
// disagree about the preimage.
type SecurityCrossing = bridgeattest.SecurityCrossing

// SecurityAttestation is M's threshold signature over a crossing, with the
// context B needs to verify it without a round-trip.
type SecurityAttestation = bridgeattest.SecurityAttestation

// AttestSecurityCrossing threshold-signs one crossing and returns the
// attestation that authorises exactly that arrival.
//
// Identical in shape to AttestBridgeTransfer, and deliberately so: the caller is
// authorised the same way, the ceremony is the same leaderless derivation, and
// the group key travels with the result so B verifies without asking M
// anything. What differs is only the message, and therefore the digest.
func (vm *VM) AttestSecurityCrossing(
	ctx context.Context,
	by Caller,
	keyID string,
	sc SecurityCrossing,
) (*SecurityAttestation, error) {
	digest := sc.Digest()

	op, err := vm.RequestSignature(ctx, by, keyID, digest[:])
	if err != nil {
		return nil, fmt.Errorf("mpcvm: security attestation for %s: %w", keyID, err)
	}
	// Failing to read the group key is fatal rather than something to paper
	// over with a nil: an attestation nobody can verify is worse than an error.
	pub, err := vm.PublicKey(keyID)
	if err != nil {
		return nil, err
	}

	// party.ID is M's name for a signer; the shared attestation carries strings
	// so a verifier on the far side of the boundary — B, a relayer, Solidity —
	// needs nothing of M's type graph to read who signed.
	signers := make([]string, len(op.Signers))
	for i, id := range op.Signers {
		signers[i] = string(id)
	}

	return &SecurityAttestation{
		Crossing:    sc,
		Digest:      digest,
		Signature:   op.Artifact,
		GroupPubKey: pub,
		Signers:     signers,
		KeyID:       keyID,
		CeremonyID:  op.CeremonyID,
		CreatedAt:   time.Now().Unix(),
	}, nil
}

// VerifySecurityAttestation is B's gate: true iff sig is a valid threshold
// signature by the group key over THIS crossing's domain-bound digest. No
// interaction with M — a threshold ECDSA signature verifies like a single-key
// one.
func VerifySecurityAttestation(groupPubKey []byte, sc SecurityCrossing, sig []byte) bool {
	return bridgeattest.VerifySecurityAttestation(groupPubKey, sc, sig)
}
