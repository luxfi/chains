// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// attest_nft.go — the NFT-ownership attestation domain on the M-Chain.
//
// This is the seam between an external NFT collection and a node's right to
// activate an entitlement-gated chain. Someone who can read the collection
// asserts a fact — address O holds token T, and binds it to node N — and M
// threshold-signs it. The node verifies that signature and nothing else: it
// never reads Ethereum, never holds the token, and never talks to M.
//
// The token is not moved, wrapped or mirrored. The attestation is a statement
// ABOUT the token, so the collection stays the single source of truth and an
// entitlement stays revocable (stop re-attesting) and transferable (attest the
// new owner) without any on-chain migration.
//
// Mirrors attest_bridge.go: additive domain registration, then one entry point
// that computes the domain-bound payload and runs the ceremony. It differs in
// reusing the QuantumAttestation payload (ComputeAttestationPayload) rather than
// defining a parallel digest, so DetectEquivocation and VerifyAttestation apply
// to ownership attestations for free.
//
// Who is allowed to assert the fact is deliberately NOT decided here — it is
// M-Chain's existing per-key permission table (requestingChain + keyID), the same
// authority that governs bridge releases. Swapping the asserter therefore never
// touches this file, and never touches the node.

import (
	"context"
	"fmt"

	"github.com/luxfi/chains/ownership"
)

// DomainNFTOwnership registers the ownership domain with the attestation domain
// registry. The name and the separator both come from chains/ownership, which is
// also what every verifier hashes — one constant, so M and its verifiers cannot
// drift into signing and checking different bytes.
const DomainNFTOwnership AttestationDomain = ownership.Domain

func init() {
	// Additive registration; does not touch existing domains.
	domainSeparators[DomainNFTOwnership] = []byte(ownership.DomainTag)
}

// AttestNFTOwnership threshold-signs an ownership claim and returns it in the
// portable, self-describing form a verifier consumes — the claim, the quorum that
// signed, and the group key, so verification needs no callback to M.
//
// The claim's Block is used as the attestation epoch. That makes the temporal
// binding exactly the block the ownership read was taken at, which gives
// equivocation a precise meaning: two different facts about one node at one block
// are contradictory and slashable (DetectEquivocation), while re-attesting the
// same node at a LATER block is the legitimate way ownership changes hands.
func (vm *VM) AttestNFTOwnership(
	ctx context.Context,
	by Caller,
	keyID string,
	claim ownership.Claim,
) (*ownership.Attestation, error) {
	qa, err := vm.attest(ctx, by, keyID, DomainNFTOwnership, claim.Subject(), claim.Root(), claim.Block)
	if err != nil {
		return nil, fmt.Errorf("mpcvm: attest ownership of token %d for node %x: %w", claim.Token, claim.Node, err)
	}
	// The group key travels with the attestation so a verifier needs no
	// round-trip. Failing to read it is fatal rather than papered over with a nil
	// key: an attestation nobody can verify is worse than an error.
	pub, err := vm.PublicKey(keyID)
	if err != nil {
		return nil, err
	}
	return &ownership.Attestation{
		Claim:     claim,
		Epoch:     claim.Block,
		Signers:   len(qa.Signers),
		Quorum:    qa.Policy.K,
		Signature: qa.Signature,
		GroupKey:  pub,
	}, nil
}
