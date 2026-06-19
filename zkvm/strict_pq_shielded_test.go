// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"errors"
	"strings"
	"testing"

	"github.com/luxfi/log"
	"github.com/luxfi/precompile/starkfri"
)

// This file proves the strict-PQ hard-disable of the classical
// (bn254 pairing-based) shielded-tx proof path (Red H1).
//
// On a strict-PQ chain the ProofVerifier that gates Zcash-style shielded
// transactions MUST:
//   - REFUSE groth16 / plonk / bulletproofs tx proofs (a CRQC that breaks
//     bn254 cannot forge a shield/unshield proof to mint/steal value);
//   - accept ONLY the post-quantum STARK/FRI system, delegated to
//     precompile/starkfri and failing closed until the prover binds;
//   - ERROR when a real (non-dummy) bn254 verifying key is loaded.
//
// A non-strict chain is unchanged: groth16/plonk reach the classical path.

func strictPQVerifier(t *testing.T) *ProofVerifier {
	t.Helper()
	pv, err := NewProofVerifier(ZConfig{
		ProofSystem:    "stark",
		ProofCacheSize: 100,
		StrictPQ:       true,
	}, log.NoLog{})
	if err != nil {
		t.Fatalf("NewProofVerifier(strictPQ): %v", err)
	}
	return pv
}

// shieldedTx builds a minimal shielded transaction with the given proof
// type and proof bytes.
func shieldedTx(proofType string, proofData []byte) *Transaction {
	nullifier := make([]byte, 32)
	commitment := make([]byte, 32)
	tx := &Transaction{
		Type:       TransactionTypeTransfer,
		Version:    1,
		Nullifiers: [][]byte{nullifier},
		Outputs:    []*ShieldedOutput{{Commitment: commitment}},
		Proof: &ZKProof{
			ProofType:    proofType,
			ProofData:    proofData,
			PublicInputs: [][]byte{nullifier, commitment},
		},
	}
	tx.ID = tx.ComputeID()
	return tx
}

// TestStrictPQ_RefusesClassicalShieldedProofs is the core H1 test: a
// strict-PQ chain refuses every classical proof system on the shielded
// path, returning the strict-PQ refusal error.
func TestStrictPQ_RefusesClassicalShieldedProofs(t *testing.T) {
	pv := strictPQVerifier(t)

	for _, pt := range []string{"groth16", "plonk", "bulletproofs"} {
		t.Run(pt, func(t *testing.T) {
			// 256 bytes is enough to reach any classical body had the gate
			// not fired; the gate must fire FIRST.
			tx := shieldedTx(pt, make([]byte, 544))
			err := pv.VerifyTransactionProof(tx)
			if !errors.Is(err, errStrictPQClassicalForbidden) {
				t.Fatalf("strict-PQ must refuse %s with errStrictPQClassicalForbidden, got: %v", pt, err)
			}
		})
	}
}

// TestStrictPQ_RealBN254VKLoadErrors proves that constructing a
// ProofVerifier on a strict-PQ chain with REAL (non-dummy) bn254
// verifying keys is an error — the explicit fail-closed gate, not the
// implicit dummy-key detector.
//
// This drives the PRODUCTION path: NewProofVerifier -> loadVerifyingKeys
// with a real (non-zero) key supplied via ZConfig.VerifyingKeys. The
// guard must fire inside the real loadVerifyingKeys, so a future refactor
// that drops it from the real function is caught here (the previous
// version asserted a test-local mirror and would NOT have caught that).
func TestStrictPQ_RealBN254VKLoadErrors(t *testing.T) {
	realVK := make([]byte, 1024)
	realVK[0] = 0x01 // non-zero ⇒ a real (non-dummy) bn254 verifying key

	_, err := NewProofVerifier(ZConfig{
		ProofSystem:    "stark",
		ProofCacheSize: 100,
		StrictPQ:       true,
		VerifyingKeys: map[string][]byte{
			string(TransactionTypeTransfer): realVK,
		},
	}, log.NoLog{})
	if !errors.Is(err, errStrictPQRealVKForbidden) {
		t.Fatalf("strict-PQ chain must error on real bn254 VK loaded by the production loadVerifyingKeys, got: %v", err)
	}
}

// TestStrictPQ_DummyVKConstructs confirms the converse: a strict-PQ
// verifier with NO supplied keys (all-zero dummy) constructs cleanly —
// the guard fires only on a REAL key, not on the dummy default. (Proof
// verification is then disabled / fail-closed via dummyKeys.)
func TestStrictPQ_DummyVKConstructs(t *testing.T) {
	pv := strictPQVerifier(t)
	if !pv.dummyKeys {
		t.Fatal("strict-PQ verifier with no supplied keys must start with dummy keys")
	}
}

// TestNonStrict_RealVKConstructs confirms a NON-strict chain accepts a
// real bn254 VK (the guard is strict-PQ only): the classical path stays
// available off the strict-PQ profile.
func TestNonStrict_RealVKConstructs(t *testing.T) {
	realVK := make([]byte, 1024)
	realVK[0] = 0x01
	pv, err := NewProofVerifier(ZConfig{
		ProofSystem:    "groth16",
		ProofCacheSize: 100,
		StrictPQ:       false,
		VerifyingKeys: map[string][]byte{
			string(TransactionTypeTransfer): realVK,
		},
	}, log.NoLog{})
	if err != nil {
		t.Fatalf("non-strict chain must accept a real bn254 VK, got: %v", err)
	}
	if pv.dummyKeys {
		t.Fatal("non-strict verifier with a supplied real key must NOT be dummy")
	}
}

// TestStrictPQ_STARKIsOnlyAcceptedSystem proves that under strict-PQ the
// STARK/FRI path is the only one that reaches the verifier, and that it
// fails closed when unbound and accepts only when the FRI verifier binds.
func TestStrictPQ_STARKIsOnlyAcceptedSystem(t *testing.T) {
	pv := strictPQVerifier(t)

	proof := append([]byte(starkfri.MagicHeader), []byte("strict-pq-fri-payload")...)
	tx := shieldedTx("stark", proof)

	// Unbound: fail closed.
	starkfri.RegisterVerifier(nil)
	if err := pv.VerifyTransactionProof(tx); err == nil {
		t.Fatal("unbound STARK shielded verifier must fail closed, got nil")
	} else if !errors.Is(err, starkfri.ErrVerifierNotRegistered) {
		t.Fatalf("unbound STARK must wrap ErrVerifierNotRegistered, got: %v", err)
	}

	// Bound + accept: the shielded path verifies, and the public inputs
	// are the tx's nullifiers ‖ output commitments.
	defer starkfri.RegisterVerifier(nil)
	var sawPub []byte
	starkfri.RegisterVerifier(func(_ byte, _, pub []byte) (bool, error) {
		sawPub = append([]byte(nil), pub...)
		return true, nil
	})
	if err := pv.VerifyTransactionProof(tx); err != nil {
		t.Fatalf("bound STARK accept path returned error: %v", err)
	}
	// 1 nullifier (32) + 1 commitment (32) = 64 bytes of bound public input.
	if len(sawPub) != 64 {
		t.Fatalf("STARK public inputs must bind nullifiers+commitments (64 bytes), got %d", len(sawPub))
	}

	// Bound + reject: a non-verifying proof is rejected.
	starkfri.RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return false, nil })
	if err := pv.VerifyTransactionProof(tx); err == nil {
		t.Fatal("bound STARK reject path must return error")
	}
}

// TestStrictPQ_GPUBatchPathRefusesClassical proves the strict-PQ gate is
// ALSO enforced on the GPU batch verification path (which deserializes
// and verifies Groth16 INLINE, bypassing VerifyTransactionProof). A
// strict-PQ chain must refuse a classical proof regardless of path.
func TestStrictPQ_GPUBatchPathRefusesClassical(t *testing.T) {
	pv := strictPQVerifier(t)

	// Two groth16 txs to exercise the batch collector.
	txs := []*Transaction{
		shieldedTx("groth16", make([]byte, 256)),
		shieldedTx("groth16", make([]byte, 256)),
	}
	results := batchVerifyProofsGPU(pv, txs)
	for i, err := range results {
		if !errors.Is(err, errStrictPQClassicalForbidden) {
			t.Fatalf("batch tx %d: strict-PQ must refuse groth16, got: %v", i, err)
		}
	}
}

// TestNonStrict_ClassicalPathUnchanged confirms a NON-strict chain is
// unaffected: a groth16 proof reaches the classical verification body
// (and is rejected only on its own merits / dummy keys, NOT by a
// strict-PQ refusal).
func TestNonStrict_ClassicalPathUnchanged(t *testing.T) {
	pv, err := NewProofVerifier(ZConfig{
		ProofSystem:    "groth16",
		ProofCacheSize: 100,
		StrictPQ:       false,
	}, log.NoLog{})
	if err != nil {
		t.Fatalf("NewProofVerifier: %v", err)
	}
	pv.dummyKeys = false // reach the classical switch body

	tx := shieldedTx("groth16", make([]byte, 256)) // zero bytes => invalid curve points
	err = pv.VerifyTransactionProof(tx)
	if errors.Is(err, errStrictPQClassicalForbidden) {
		t.Fatal("non-strict chain must NOT apply the strict-PQ refusal to groth16")
	}
	// It should fail on the proof's own merits (invalid points), not the gate.
	if err == nil {
		t.Fatal("zero-byte groth16 proof should be rejected on its merits")
	}
	if strings.Contains(err.Error(), "strict-PQ") {
		t.Fatalf("non-strict groth16 rejection must not mention strict-PQ, got: %v", err)
	}
}
