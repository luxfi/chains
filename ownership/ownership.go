// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ownership is the ONE canonical definition of the NFT-ownership
// entitlement seam: M-Chain (mpcvm) threshold-signs the fact that an address
// holds a specific token of a specific collection and has bound that token to a
// specific node; a node's chain manager verifies that signature before it
// activates an entitlement-gated chain.
//
// The collection lives on an external EVM chain (the Lux Genesis collection is an
// ERC-721 on Ethereum mainnet). Nothing here moves, wraps or mirrors the token —
// the claim is a statement ABOUT the token, signed by a quorum, so the token
// stays the single source of truth and the attestation stays revocable and
// re-issuable. The reader of an attestation never touches Ethereum.
//
// Why this package exists rather than the encoding living in mpcvm: a node must
// verify an attestation WITHOUT importing the M-Chain VM, because M is a
// plugin-only VM that luxd must never link in-process. So the digest is a value
// seam, not a place — a pure function of the claim's field values, in one small
// package that both the M-Chain VM and the node import. Never duplicated, never
// able to drift.
//
// The package is deliberately dependency-free (stdlib + luxfi/crypto/secp256k1),
// so importing it costs a node nothing.
//
// The domain tag, field order, digest layout and signature encoding are FROZEN.
// The KAT vectors in ownership_test.go pin the bytes, so drift on either surface
// trips a test.
package ownership

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/secp256k1"
)

// Domain is the attestation domain this package defines. mpcvm registers it in
// its domain-separator registry under exactly this name.
const Domain = "nft/ownership"

// DomainTag is the domain-separation byte string hashed into every payload, so
// an ownership attestation can never be replayed as any other message M signs
// (oracle reads/writes, session-complete, epoch beacons, bridge transfers). It
// follows the registry's own convention, LUX:QuantumAttest:<domain>:v1, and is
// written raw (no length prefix) as the first bytes of the preimage.
//
// mpcvm MUST register this exact byte string for Domain; the shared constant is
// what makes that impossible to get wrong.
const DomainTag = "LUX:QuantumAttest:nft/ownership:v1"

var (
	// ErrNoQuorum means fewer parties signed than the key's policy requires, so
	// the signature cannot represent the committee's decision.
	ErrNoQuorum = errors.New("ownership: signer count below quorum")
	// ErrNoKey means no group key was supplied, so nothing can be verified.
	ErrNoKey = errors.New("ownership: no group key")
	// ErrBadSignature means the threshold signature does not verify against the
	// group key over this claim's domain-bound payload.
	ErrBadSignature = errors.New("ownership: signature does not verify")
	// ErrWrongNode means the attestation is authentic but authorizes a DIFFERENT
	// node. This is the reason a node may not borrow a peer's entitlement.
	ErrWrongNode = errors.New("ownership: attestation is bound to a different node")
)

// Claim is the fact a quorum signs. Field layout is FROZEN so the digest is
// canonical across the M-Chain VM, every node, and any future non-Go verifier.
//
// One attestation over one Claim authorizes exactly one node — on the strength
// of exactly one token, of one collection, on one chain, as read at one block —
// and nothing else.
type Claim struct {
	// Chain is the EVM chain id the collection lives on (1 = Ethereum mainnet).
	Chain uint64 `json:"chain"`
	// Collection is the ERC-721 contract address.
	Collection [20]byte `json:"collection"`
	// Token is the tokenId. For the Lux Genesis collection the token IS the
	// validator slot.
	Token uint64 `json:"token"`
	// Owner is ownerOf(Token) as read at Block.
	Owner [20]byte `json:"owner"`
	// Node is the luxd node this entitlement binds to — the raw 20 bytes of its
	// NodeID. The node proves nothing at verification time: it simply IS this
	// identity, because a NodeID is a hash of the staking certificate it must
	// hold to be that node at all.
	Node [20]byte `json:"node"`
	// Block is the block height the ownership read was taken at, so a claim is
	// pinned to a point in the collection's history rather than "now".
	Block uint64 `json:"block"`
}

// Root is the canonical commitment to a claim — the CommitmentRoot an M-Chain
// QuantumAttestation carries.
//
//	sha256(
//	  "LUX:QuantumAttest:nft/ownership:v1"  // ASCII tag, raw
//	  || uint64_BE(Chain)                   // 8
//	  || Collection[20]                     // 20
//	  || uint64_BE(Token)                   // 8
//	  || Owner[20]                          // 20
//	  || Node[20]                           // 20
//	  || uint64_BE(Block)                   // 8
//	)
func (c Claim) Root() [32]byte {
	h := sha256.New()
	h.Write([]byte(DomainTag))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], c.Chain)
	h.Write(b[:])
	h.Write(c.Collection[:])
	binary.BigEndian.PutUint64(b[:], c.Token)
	h.Write(b[:])
	h.Write(c.Owner[:])
	h.Write(c.Node[:])
	binary.BigEndian.PutUint64(b[:], c.Block)
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Subject is the attestation's SubjectID: WHO is entitled, as opposed to Root's
// WHAT was verified. It is the node's 20 NodeID bytes, left-aligned in 32.
//
// Keying the subject on the node is what makes equivocation meaningful: two
// attestations in this domain with the same subject and epoch but different
// roots are two conflicting ownership facts about one node, which is exactly the
// condition mpcvm's DetectEquivocation slashes.
func (c Claim) Subject() [32]byte {
	var out [32]byte
	copy(out[:], c.Node[:])
	return out
}

// Payload is the preimage a quorum signs. It MUST stay byte-identical to
// mpcvm.ComputeAttestationPayload for this domain — that function hashes the
// domain separator, then the subject, then the commitment root, then the epoch
// big-endian, and so does this.
func Payload(subject, root [32]byte, epoch uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte(DomainTag))
	h.Write(subject[:])
	h.Write(root[:])
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], epoch)
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Attestation is a quorum's signature over a Claim plus everything a verifier
// needs, so verification is zero-interaction: no callback to M-Chain, no
// Ethereum read, no network at all.
type Attestation struct {
	Claim Claim `json:"claim"`
	// Epoch binds the attestation in time; it is part of the signed payload.
	Epoch uint64 `json:"epoch"`
	// Signers is how many parties participated in the ceremony.
	Signers int `json:"signers"`
	// Quorum is the signing policy's K — the number of parties required. It
	// travels with the attestation because a bare signature cannot say what
	// threshold produced it.
	Quorum int `json:"quorum"`
	// Signature is secp256k1 r(32)||s(32)||v(1), the encoding every M-Chain
	// ceremony artifact uses. r||s (64) is also accepted.
	Signature []byte `json:"signature"`
	// GroupKey is the compressed secp256k1 group public key. A verifier must
	// obtain this from consensus state, never from the party being authorized —
	// see the caller-side note on Authorizes.
	GroupKey []byte `json:"groupKey"`
}

// Authorizes reports whether this attestation authorizes [node]. It answers
// authenticity AND binding in ONE call, and there is deliberately no exported
// way to ask only one of them: a caller that could check the signature and
// forget the binding would let any node activate on a peer's entitlement.
//
// Authenticity here means "a quorum of the holders of GroupKey signed this
// claim". It does NOT mean GroupKey is the right key — the caller must read
// GroupKey from consensus state the operator cannot edit. An attestation
// verified against an operator-supplied key proves nothing, because the operator
// can sign anything.
func (a *Attestation) Authorizes(node [20]byte) error {
	if a == nil {
		return ErrBadSignature
	}
	if a.Claim.Node != node {
		return fmt.Errorf("%w: attested %x, asked about %x", ErrWrongNode, a.Claim.Node, node)
	}
	if a.Quorum <= 0 || a.Signers < a.Quorum {
		return fmt.Errorf("%w: %d signers for a %d-party quorum", ErrNoQuorum, a.Signers, a.Quorum)
	}
	if len(a.GroupKey) == 0 {
		return ErrNoKey
	}
	sig := a.Signature
	if len(sig) == 65 {
		sig = sig[:64] // drop the recovery id; VerifySignature wants r||s
	}
	if len(sig) != 64 {
		return fmt.Errorf("%w: signature is %d bytes", ErrBadSignature, len(a.Signature))
	}
	payload := Payload(a.Claim.Subject(), a.Claim.Root(), a.Epoch)
	if !secp256k1.VerifySignature(a.GroupKey, payload[:], sig) {
		return ErrBadSignature
	}
	return nil
}
