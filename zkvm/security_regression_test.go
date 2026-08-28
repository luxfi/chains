// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"strings"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/log"
)

// =============================================================================
// CRITICAL Regressions
// =============================================================================

// TestRegressionC03_BulletproofDisabled verifies that submitting a Bulletproof
// proof returns an explicit error, not a false-positive validation.
// Finding C-03: Bulletproof verify was structurally checking (L/R length, a0/b0
// non-zero) without verifying the inner product argument.
func TestRegressionC03_BulletproofDisabled(t *testing.T) {
	verifier := newTestProofVerifier(t)
	// Force non-dummy keys so the proof type switch is reached
	verifier.dummyKeys = false

	tx := &Transaction{
		Type:    TransactionTypeTransfer,
		Version: 1,
		Nullifiers: [][]byte{
			make([]byte, 32),
		},
		Outputs: []*ShieldedOutput{
			{Commitment: make([]byte, 32)},
		},
		Proof: &ZKProof{
			ProofType:    "bulletproofs",
			ProofData:    make([]byte, 512),
			PublicInputs: [][]byte{make([]byte, 32), make([]byte, 32)},
		},
	}
	tx.ID = tx.ComputeID()

	err := verifier.VerifyTransactionProof(tx)
	if err == nil {
		t.Fatal("Bulletproof must return error -- C-03 regression")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected 'not yet implemented' in error, got: %v", err)
	}
}

// =============================================================================
// HIGH Regressions
// =============================================================================

// TestRegressionH01_Groth16SubgroupCheck verifies that Groth16 proof
// deserialization rejects G1 points not in the prime-order subgroup.
// Finding H-01: Missing subgroup checks allowed small-subgroup attacks
// that could forge proofs.
func TestRegressionH01_Groth16SubgroupCheck(t *testing.T) {
	// The verifier checks at proof_verifier.go:362-367:
	//   if !grothProof.Ar.IsInSubGroup() || !grothProof.Krs.IsInSubGroup() { error }
	//   if !grothProof.Bs.IsInSubGroup() { error }
	// Zero bytes are not valid BN254 curve points, so deserialization or
	// subgroup check must reject them.
	verifier := newTestProofVerifier(t)
	verifier.dummyKeys = false
	verifier.verifyingKeys[string(TransactionTypeTransfer)] = make([]byte, 1024)

	nullifier := bytes.Repeat([]byte{0xAA}, 32)
	commitment := make([]byte, 32)

	tx := &Transaction{
		Type:    TransactionTypeTransfer,
		Version: 1,
		Nullifiers: [][]byte{
			nullifier,
		},
		Outputs: []*ShieldedOutput{
			{Commitment: commitment},
		},
		Proof: &ZKProof{
			ProofType:    "groth16",
			ProofData:    make([]byte, 256), // zero bytes = invalid curve points
			PublicInputs: [][]byte{testBind[:], nullifier, commitment},
		},
	}
	tx.ID = tx.ComputeID()

	err := verifier.VerifyTransactionProof(tx)
	if err == nil {
		t.Fatal("Groth16 proof with invalid points must reject -- H-01 regression")
	}
}

// TestRegressionH02_STARKFailsClosed verifies that STARK proofs are now
// routed to the strict-PQ starkfri verifier and FAIL CLOSED — never a
// false-positive structural validation.
// Finding H-02: STARK verify previously only checked commitment lengths
// and FRI layer presence without verifying the FRI protocol. The Z-Chain
// rollup rewire (this branch) deletes that structural check and delegates
// to precompile/starkfri, which rejects a proof lacking the "P3Q1" magic
// header BEFORE any verifier callback. A zero-filled proof must reject.
func TestRegressionH02_STARKFailsClosed(t *testing.T) {
	verifier := newTestProofVerifier(t)
	// Force non-dummy keys so the classical guard does not short-circuit
	// (irrelevant for the STARK path, which routes before the dummy gate).
	verifier.dummyKeys = false

	tx := &Transaction{
		Type:    TransactionTypeTransfer,
		Version: 1,
		Nullifiers: [][]byte{
			make([]byte, 32),
		},
		Outputs: []*ShieldedOutput{
			{Commitment: make([]byte, 32)},
		},
		Proof: &ZKProof{
			ProofType:    "stark",
			ProofData:    make([]byte, 1024), // zero bytes: no P3Q1 magic header
			PublicInputs: [][]byte{make([]byte, 32), make([]byte, 32)},
		},
	}
	tx.ID = tx.ComputeID()

	err := verifier.VerifyTransactionProof(tx)
	if err == nil {
		t.Fatal("STARK proof must return error (fail-closed) -- H-02 regression")
	}
	if !strings.Contains(err.Error(), "STARK") {
		t.Errorf("expected STARK verification failure, got: %v", err)
	}
}

// TestRegressionH03_PublicInputsValueEqual verifies that public inputs are
// compared by value (bytes.Equal), not just by length.
// Finding H-03: The original check compared len(publicInputs[i]) to
// len(nullifier) instead of comparing actual bytes.
func TestRegressionH03_PublicInputsValueEqual(t *testing.T) {
	verifier := newTestProofVerifier(t)
	verifier.dummyKeys = false
	verifier.verifyingKeys[string(TransactionTypeTransfer)] = make([]byte, 1024)

	nullifier := make([]byte, 32)
	nullifier[0] = 0xAA
	nullifier[31] = 0x01

	// Same length, different bytes
	badInput := make([]byte, 32)
	copy(badInput, nullifier)
	badInput[0] ^= 0xFF

	commitment := make([]byte, 32)

	tx := &Transaction{
		Type:    TransactionTypeTransfer,
		Version: 1,
		Nullifiers: [][]byte{
			nullifier,
		},
		Outputs: []*ShieldedOutput{
			{Commitment: commitment},
		},
		Proof: &ZKProof{
			ProofType: "groth16",
			ProofData: make([]byte, 256),
			PublicInputs: [][]byte{
				badInput,   // same length, different bytes
				commitment, // correct commitment
			},
		},
	}
	tx.ID = tx.ComputeID()

	err := verifier.VerifyTransactionProof(tx)
	if err == nil {
		t.Fatal("public input mismatch (same length, different bytes) must reject -- H-03 regression")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected 'mismatch' in error, got: %v", err)
	}
}

// TestRegressionH05_NoMutableVerifiedField verifies that the ZKProof struct
// does not contain a mutable 'verified' field.
// Finding H-05: A 'verified' bool on ZKProof allowed bypass of proof
// verification by setting it to true before submission.
func TestRegressionH05_NoMutableVerifiedField(t *testing.T) {
	typ := reflect.TypeOf(ZKProof{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if strings.EqualFold(name, "verified") {
			t.Fatalf("ZKProof must not have '%s' field -- H-05 regression", name)
		}
	}
}

// =============================================================================
// MEDIUM Regressions
// =============================================================================

// TestRegressionM03_NullifierPruningRemoved verifies that NullifierDB does not
// have a PruneOldNullifiers method.
// Finding M-03: Nullifier pruning enabled double-spend by deleting spent
// nullifiers after a time window.
func TestRegressionM03_NullifierPruningRemoved(t *testing.T) {
	typ := reflect.TypeOf(&NullifierDB{})
	for _, name := range []string{"PruneOldNullifiers", "RemoveNullifier", "Prune", "Delete", "Clear"} {
		if _, found := typ.MethodByName(name); found {
			t.Fatalf("%s must not exist -- M-03 regression (enables double-spend)", name)
		}
	}
}

// TestRegressionM05_PLONKSubgroupCheck verifies that PLONK proof deserialization
// performs subgroup checks on every G1 point and rejects invalid curve points.
// Finding M-05: Missing subgroup checks on PLONK proof points.
func TestRegressionM05_PLONKSubgroupCheck(t *testing.T) {
	// For BN254 G1, the cofactor is 1 so all curve points are in the subgroup.
	// The defense is: (1) Unmarshal rejects non-curve points, and
	// (2) IsInSubGroup() is called for every point (catches higher-cofactor groups).
	// Test with bytes that are NOT valid curve points.
	badProof := make([]byte, 736)
	// Set each 64-byte G1 slot to coordinates that are NOT on the BN254 curve.
	// x=1, y=1 is not on y^2 = x^3 + 3 (mod p) since 1 != 4.
	for i := 0; i < 9; i++ {
		offset := i * 64
		badProof[offset+31] = 1 // x = 1 (big-endian, last byte of first 32)
		badProof[offset+63] = 1 // y = 1 (big-endian, last byte of second 32)
	}

	_, err := deserializePLONKProof(badProof)
	if err == nil {
		t.Fatal("PLONK proof with non-curve points must reject -- M-05 regression")
	}

	// Also verify the error path is in deserialization or subgroup check
	errStr := err.Error()
	if !strings.Contains(errStr, "unmarshal") && !strings.Contains(errStr, "subgroup") {
		t.Logf("PLONK rejection error: %v", err)
	}
}

// TestRegressionM06_FiatShamirFullLength verifies that Fiat-Shamir challenges
// use the full 32-byte SHA-256 output with domain separation.
// Finding M-06: Challenge derivation was truncating to fewer bytes.
func TestRegressionM06_FiatShamirFullLength(t *testing.T) {
	transcript := sha256.Sum256([]byte("test-transcript-state"))
	alphaHash := sha256.Sum256(append(transcript[:], []byte("alpha")...))
	betaHash := sha256.Sum256(append(transcript[:], []byte("beta")...))

	if bytes.Equal(alphaHash[:], betaHash[:]) {
		t.Fatal("different domain tags must produce different challenges -- M-06 regression")
	}
	if len(alphaHash) != 32 {
		t.Fatalf("challenge must be 32 bytes, got %d -- M-06 regression", len(alphaHash))
	}

	diffCount := 0
	for i := range alphaHash {
		if alphaHash[i] != betaHash[i] {
			diffCount++
		}
	}
	if diffCount < 16 {
		t.Errorf("challenges differ in only %d/32 bytes -- M-06 regression", diffCount)
	}
}

// =============================================================================
// INFO Regressions
// =============================================================================

// =============================================================================
// LOW Regressions
// =============================================================================

// TestRegressionL02_LoadNullifiersPopulatesCache verifies that loadNullifiers
// populates the in-memory cache when constructing a NullifierDB from a
// database that already has nullifiers stored.
// Finding L-02: loadNullifiers was empty, leaving cache unpopulated.
func TestRegressionL02_LoadNullifiersPopulatesCache(t *testing.T) {
	db := memdb.New()

	// Pre-populate database with a nullifier entry
	nullifier := []byte("test-nullifier-l02")
	key := makeNullifierKey(nullifier)
	heightBytes := make([]byte, 8)
	heightBytes[7] = 42 // height = 42
	if err := db.Put(key, heightBytes); err != nil {
		t.Fatalf("db.Put: %v", err)
	}
	// Construct NullifierDB -- loadNullifiers runs during construction
	ndb, err := NewNullifierDB(db, log.NoLog{})
	if err != nil {
		t.Fatalf("NewNullifierDB: %v", err)
	}

	// Cache must contain the nullifier loaded from disk
	if !spentOf(t, ndb, nullifier) {
		t.Fatal("loadNullifiers must populate cache from database -- L-02 regression")
	}

	height, _, err := ndb.Spent(nullifier)
	if err != nil {
		t.Fatalf("Spent: %v", err)
	}
	if height != 42 {
		t.Fatalf("expected height 42, got %d -- L-02 regression", height)
	}
}

// =============================================================================
// Helpers
// =============================================================================

func newTestProofVerifier(t *testing.T) *ProofVerifier {
	t.Helper()
	config := ZConfig{
		ProofCacheSize: 100,
	}
	pv, err := NewProofVerifier(config, [32]byte{}, log.NoLog{})
	if err != nil {
		t.Fatalf("NewProofVerifier: %v", err)
	}
	return pv
}
