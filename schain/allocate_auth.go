// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// allocate_auth.go — the cryptographic half of the leaderless pinned-writer gate.
//
// pinning.Owner answers "WHICH validator owns this range" deterministically. This
// file answers the verifiable question the original gate could not: "did the ACTUAL
// owner authorize this allocate?" — without trusting any unverifiable proposer
// identity. An AllocateTx carries an ML-DSA signature by the owner's staking key;
// the owner's NodeID is a SHAKE256-384 commitment to that key (ids.DeriveMLDSA), so
// the carried public key is bound to the claimed NodeID and the signature is bound
// to the key. A non-owner cannot forge it: they cannot sign as the owner (no key),
// and claiming the owner's NodeID with their own key fails the NodeID re-derivation.
//
// The signature uses the SAME ML-DSA scheme the validator NodeID derives from
// (FIPS 204 ML-DSA-65/87), so the staking identity and the allocate authorization
// are one key, one trust root. Verification is pure and local: it needs only the
// tx, the epoch-frozen member set (already required by pinning), and the chain id
// the NodeIDs were derived under — no network, no live validator lookup.
package schain

import (
	"errors"
	"fmt"

	mldsa65 "github.com/luxfi/crypto/pq/mldsa/mldsa65"
	mldsa87 "github.com/luxfi/crypto/pq/mldsa/mldsa87"
	"github.com/luxfi/ids"

	"github.com/luxfi/chains/schain/txs"
)

// allocateSigContext is the FIPS 204 §5.2 domain-separating context string bound
// into every allocate signature. It isolates a validator's ML-DSA staking key from
// any other protocol that key might sign for — a signature made here can never be
// replayed as a signature in another context, and vice versa.
var allocateSigContext = []byte("lux/schain/allocate-sig/v1")

var (
	// errUnsignedAllocate — a block carried an AllocateTx with no pinned-writer
	// authorization. Fail closed: an unsigned allocate is unauthorized.
	errUnsignedAllocate = errors.New("allocate: missing pinned-writer signature")

	// errUnknownSignerScheme — the SignerScheme byte names no ML-DSA scheme this
	// build verifies (only the post-quantum ML-DSA family is accepted).
	errUnknownSignerScheme = errors.New("allocate: signer scheme is not ML-DSA")

	// errSignerKeyMismatch — the carried public key does not re-derive to the
	// claimed Signer NodeID. The NodeID is a commitment to the key, so this means
	// the key was swapped: someone claimed an owner's NodeID with a foreign key.
	errSignerKeyMismatch = errors.New("allocate: signer public key does not bind to signer NodeID")

	// errBadAllocateSig — the ML-DSA signature did not verify over the canonical
	// signing bytes under the signer's key (forged or tampered).
	errBadAllocateSig = errors.New("allocate: pinned-writer signature is invalid")

	// errEpochMismatch — the signed Epoch does not equal the block's epoch, so the
	// ownership the signer attested to was resolved against a different set.
	errEpochMismatch = errors.New("allocate: signed epoch does not match block epoch")

	// errEpochFingerprintMismatch — the signed validator-set fingerprint does not
	// match the fingerprint recomputed from the verifier's local epoch snapshot.
	// This is the DESIGN §6.4 local-determinism guard: the proposer pinned against
	// a set the verifier does not hold, so the block is rejected (fail closed)
	// rather than the verifier reaching over the network to reconcile.
	errEpochFingerprintMismatch = errors.New("allocate: epoch validator-set fingerprint mismatch")
)

// isAllocateGateError reports whether err is a pinned-writer safety-gate violation.
// Every such error FAILS THE WHOLE BLOCK (it is not a soft per-tx failure): letting
// one through would silently admit an allocate the owner did not authorize — the
// exact double-write the pinned writer forbids.
func isAllocateGateError(err error) bool {
	switch {
	case errors.Is(err, errNonOwnerAllocate),
		errors.Is(err, errNoValidatorSet),
		errors.Is(err, errUnsignedAllocate),
		errors.Is(err, errUnknownSignerScheme),
		errors.Is(err, errSignerKeyMismatch),
		errors.Is(err, errBadAllocateSig),
		errors.Is(err, errEpochMismatch),
		errors.Is(err, errEpochFingerprintMismatch):
		return true
	default:
		return false
	}
}

// AllocateSigner stamps an unsigned AllocateTx with the proposer's ML-DSA
// pinned-writer authorization. It binds one validator's staking key to the
// allocate gate: its NodeID is the SHAKE256-384 commitment to its public key under
// identityChainID, and it signs with the matching secret key. The VM installs one
// on the owning node; BuildBlock uses it to sign the allocates that node owns.
type AllocateSigner struct {
	scheme          ids.NodeIDScheme
	identityChainID ids.ID
	nodeID          ids.NodeID
	pub             []byte
	sign            func(msg, ctx []byte) ([]byte, error)
}

// NewMLDSA65Signer builds an AllocateSigner over an ML-DSA-65 staking key. chainID
// is the chain the validator NodeIDs are derived under (the same id Verify uses to
// re-derive and check the NodeID binding).
func NewMLDSA65Signer(chainID ids.ID, pub *mldsa65.PublicKey, sk *mldsa65.PrivateKey) (*AllocateSigner, error) {
	pubB := pub.Bytes()
	nodeID, _, err := ids.NodeIDSchemeMLDSA65.DeriveMLDSA(chainID, pubB)
	if err != nil {
		return nil, fmt.Errorf("allocate signer: derive node id: %w", err)
	}
	return &AllocateSigner{
		scheme:          ids.NodeIDSchemeMLDSA65,
		identityChainID: chainID,
		nodeID:          nodeID,
		pub:             pubB,
		// Deterministic signatures (randomized=false): reproducible and equally
		// EUF-CMA-secure under FIPS 204.
		sign: func(msg, ctx []byte) ([]byte, error) { return mldsa65.Sign(sk, msg, ctx, false) },
	}, nil
}

// NewMLDSA87Signer builds an AllocateSigner over an ML-DSA-87 staking key (the
// high-value validator scheme). Identical contract to NewMLDSA65Signer.
func NewMLDSA87Signer(chainID ids.ID, pub *mldsa87.PublicKey, sk *mldsa87.PrivateKey) (*AllocateSigner, error) {
	pubB := pub.Bytes()
	nodeID, _, err := ids.NodeIDSchemeMLDSA87.DeriveMLDSA(chainID, pubB)
	if err != nil {
		return nil, fmt.Errorf("allocate signer: derive node id: %w", err)
	}
	return &AllocateSigner{
		scheme:          ids.NodeIDSchemeMLDSA87,
		identityChainID: chainID,
		nodeID:          nodeID,
		pub:             pubB,
		sign:            func(msg, ctx []byte) ([]byte, error) { return mldsa87.Sign(sk, msg, ctx, false) },
	}, nil
}

// NodeID is this signer's validator NodeID (the candidate range owner).
func (s *AllocateSigner) NodeID() ids.NodeID { return s.nodeID }

// signAllocate stamps Epoch/Nonce/Fingerprint onto an unsigned AllocateTx and
// signs the resulting canonical bytes, returning the authoritative signed tx.
func (s *AllocateSigner) signAllocate(tx *txs.AllocateTx, epoch, nonce uint64, fingerprint ids.ID) (*txs.AllocateTx, error) {
	msg := txs.AllocateSigningBytes(tx.Range, tx.Count, epoch, nonce, fingerprint)
	sig, err := s.sign(msg, allocateSigContext)
	if err != nil {
		return nil, fmt.Errorf("allocate signer: sign: %w", err)
	}
	return tx.WithAuthorization(epoch, nonce, fingerprint, s.nodeID, uint8(s.scheme), s.pub, sig), nil
}

// verifyAllocateSig checks the pinned-writer authorization on an AllocateTx:
//
//  1. the carried public key re-derives (under identityChainID) to the claimed
//     Signer NodeID — binding the key to the identity; and
//  2. the ML-DSA signature verifies over the canonical signing bytes under that
//     key — binding the authorization to the key holder.
//
// It does NOT decide ownership (whether Signer is the HRW owner) — that is the
// caller's pinning.Owner check. Together they make a non-owner's forged allocate
// unverifiable: a non-owner cannot sign as the owner (step 2 fails), and cannot
// claim the owner's NodeID with a foreign key (step 1 fails).
func verifyAllocateSig(tx *txs.AllocateTx, identityChainID ids.ID) error {
	if !tx.IsSigned() || len(tx.SignerPubKey) == 0 {
		return errUnsignedAllocate
	}
	scheme := ids.NodeIDScheme(tx.SignerScheme)
	if !scheme.IsPostQuantum() {
		return errUnknownSignerScheme
	}

	// (1) Bind the public key to the claimed NodeID. The NodeID is a SHAKE256-384
	// commitment to (domain, chainID, scheme, pubkey); re-deriving and comparing it
	// proves the carried key is the genuine key for that NodeID. A forger who claims
	// the owner's NodeID with their own key is rejected here.
	derivedID, _, err := scheme.DeriveMLDSA(identityChainID, tx.SignerPubKey)
	if err != nil {
		return fmt.Errorf("%w: %v", errSignerKeyMismatch, err)
	}
	if derivedID != tx.Signer {
		return errSignerKeyMismatch
	}

	// (2) Verify the signature over the canonical signing bytes under the bound key.
	ok, err := mldsaVerify(scheme, tx.SignerPubKey, tx.SigningBytes(), allocateSigContext, tx.Sig)
	if err != nil {
		return fmt.Errorf("%w: %v", errBadAllocateSig, err)
	}
	if !ok {
		return errBadAllocateSig
	}
	return nil
}

// mldsaVerify dispatches signature verification to the scheme named by the byte.
// Only the post-quantum ML-DSA family is accepted.
func mldsaVerify(scheme ids.NodeIDScheme, pubBytes, msg, ctx, sig []byte) (bool, error) {
	switch scheme {
	case ids.NodeIDSchemeMLDSA65:
		pk := new(mldsa65.PublicKey)
		if err := pk.UnmarshalBinary(pubBytes); err != nil {
			return false, err
		}
		return mldsa65.Verify(pk, msg, ctx, sig), nil
	case ids.NodeIDSchemeMLDSA87:
		pk := new(mldsa87.PublicKey)
		if err := pk.UnmarshalBinary(pubBytes); err != nil {
			return false, err
		}
		return mldsa87.Verify(pk, msg, ctx, sig), nil
	default:
		return false, errUnknownSignerScheme
	}
}
