// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/luxfi/accel"
	"github.com/luxfi/log"
	"github.com/luxfi/precompile/starkfri"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	lru "github.com/hashicorp/golang-lru"
)

// errStrictPQClassicalForbidden is returned by the shielded-tx verifier
// when a strict-PQ chain is asked to verify a classical (bn254
// pairing-based) proof system. On a strict-PQ chain only the STARK/FRI
// system is accepted; groth16/plonk/bulletproofs are hard-disabled.
var errStrictPQClassicalForbidden = errors.New(
	"zkvm: classical proof system forbidden on strict-PQ chain — only STARK/FRI accepted")

// errStrictPQRealVKForbidden is returned at construction when a strict-PQ
// chain attempts to load a real (non-dummy) bn254 verifying key. Real
// classical VKs on a strict-PQ chain would re-enable the forgeable
// pairing path; refuse explicitly rather than rely on dummy-key detection.
var errStrictPQRealVKForbidden = errors.New(
	"zkvm: real bn254 verifying key forbidden on strict-PQ chain — shielded value uses STARK/FRI (P3Q) only")

// ProofVerifier verifies zero-knowledge proofs.
// When verifying keys are all zeros (dummy), proof verification is disabled
// and VerifyProof returns an error. This is fail-closed by design.
type ProofVerifier struct {
	config ZConfig
	log    log.Logger

	// Proof verification cache
	proofCache *lru.Cache

	// Verifying keys
	verifyingKeys map[string][]byte // circuit type -> verifying key
	dummyKeys     bool              // true if all verifying keys are zero-filled

	// Statistics
	verifyCount uint64
	cacheHits   uint64
	cacheMisses uint64

	mu sync.RWMutex
}

// NewProofVerifier creates a new proof verifier
func NewProofVerifier(config ZConfig, log log.Logger) (*ProofVerifier, error) {
	// Create LRU cache for proof verification results
	cache, err := lru.New(int(config.ProofCacheSize))
	if err != nil {
		return nil, err
	}

	pv := &ProofVerifier{
		config:        config,
		log:           log,
		proofCache:    cache,
		verifyingKeys: make(map[string][]byte),
	}

	// Load verifying keys
	if err := pv.loadVerifyingKeys(); err != nil {
		return nil, err
	}

	return pv, nil
}

// VerifyTransactionProof verifies a transaction's zero-knowledge proof.
// Returns an error if verifying keys are dummy (all zeros).
func (pv *ProofVerifier) VerifyTransactionProof(tx *Transaction) error {
	if tx.Proof == nil {
		return errors.New("transaction missing proof")
	}

	// Strict-PQ gate (Red H1). On a strict-PQ chain the classical
	// (bn254 pairing-based) systems are hard-disabled BEFORE any other
	// check — a CRQC that breaks bn254 must not be able to forge a
	// shield/unshield proof. Only STARK/FRI is accepted there.
	if err := pv.refuseClassicalUnderStrictPQ(tx.Proof.ProofType); err != nil {
		return err
	}

	// STARK/FRI path: delegate to the strict-PQ verifier (precompile/
	// starkfri). This is the ONLY accepted system on a strict-PQ chain
	// and is the quantum-safe shielded-proof path everywhere. It fails
	// closed (errVerifierUnavailable-equivalent) when no FRI binding is
	// registered — see verifySTARKProof.
	if tx.Proof.ProofType == "stark" {
		return pv.verifySTARKProof(tx)
	}

	// Classical path (non-strict chains only — the gate above already
	// rejected these under strict-PQ). Requires real (non-dummy) VKs.
	if pv.dummyKeys {
		return errors.New("zkvm: proof verification disabled — no real verifying keys loaded")
	}

	// Check cache first — include tx ID to bind proof to specific transaction
	proofHash := pv.hashProof(tx)

	pv.mu.Lock()
	pv.verifyCount++

	if cached, ok := pv.proofCache.Get(string(proofHash)); ok {
		pv.cacheHits++
		pv.mu.Unlock()

		if cached.(bool) {
			return nil
		}
		return errors.New("proof verification failed (cached)")
	}
	pv.cacheMisses++
	pv.mu.Unlock()

	// Verify proof based on type
	var err error
	switch tx.Proof.ProofType {
	case "groth16":
		err = pv.verifyGroth16Proof(tx)
	case "plonk":
		err = pv.verifyPLONKProof(tx)
	case "bulletproofs":
		err = errors.New("zkvm: Bulletproof verification not yet implemented, use groth16 or plonk")
	default:
		err = errors.New("unsupported proof type")
	}

	// Cache result
	pv.proofCache.Add(string(proofHash), err == nil)

	return err
}

// refuseClassicalUnderStrictPQ is the single strict-PQ enforcement point
// for the shielded-tx verifier. On a strict-PQ chain it refuses every
// classical (quantum-breakable) proof system, leaving only "stark"
// (STARK/FRI). On a non-strict chain it is a no-op. Both VerifyTransactionProof
// and the GPU batch path call this so neither can verify a classical proof
// on a strict-PQ chain.
func (pv *ProofVerifier) refuseClassicalUnderStrictPQ(proofType string) error {
	if !pv.config.StrictPQ {
		return nil
	}
	switch proofType {
	case "stark":
		return nil
	default:
		// groth16, plonk, bulletproofs, anything else: forbidden.
		return errStrictPQClassicalForbidden
	}
}

// verifySTARKProof verifies a strict-PQ STARK/FRI shielded proof by
// delegating to precompile/starkfri (cSHAKE256 Merkle over Goldilocks,
// FRI low-degree test — no pairings, no bn254, no trusted setup). It
// fails closed when no FRI verifier binding is registered (CGO_ENABLED=0
// or the starkfri_p3q tag absent): a structurally well-formed proof is
// NEVER accepted without the real verifier, so there is no forgery oracle.
//
// The proof bytes are tx.Proof.ProofData (which must begin with the
// starkfri MagicHeader); the public inputs are the canonical
// concatenation of the tx's nullifiers and output commitments, binding
// the proof to this transaction's shielded value flow.
//
// PROVER STATUS (tracked, not faked). The FULL post-quantum shielded
// path also needs the prover side: a `p3q_prove` C ABI (Rust prover
// behind the starkfri_p3q cgo tag) and a shielded/ML-DSA AIR that
// arithmetises the Zcash-style spend/output circuit (note commitments,
// nullifier derivation, value balance, range proofs) over the Goldilocks
// field. Until that AIR + prover land, this verifier accepts no shielded
// proof on a strict-PQ chain (fail-closed), and shielded value transfer
// is effectively disabled there — which is the correct posture: no
// classical fallback, no forgeable path.
func (pv *ProofVerifier) verifySTARKProof(tx *Transaction) error {
	// Bind the proof to this tx's shielded value via the public inputs:
	// nullifiers (spends) ‖ output commitments (outputs).
	pub := make([]byte, 0, 64)
	for _, n := range tx.Nullifiers {
		pub = append(pub, n...)
	}
	for _, c := range tx.GetOutputCommitments() {
		pub = append(pub, c...)
	}

	ok, err := starkfri.Verify(tx.Proof.ProofData, pub)
	if err != nil {
		if errors.Is(err, starkfri.ErrVerifierNotRegistered) {
			// Binding pending: fail closed, distinguishable for operators.
			return fmt.Errorf("zkvm: strict-PQ STARK shielded verifier unbound (build with -tags starkfri_p3q): %w", err)
		}
		// Malformed / non-verifying proof.
		return fmt.Errorf("zkvm: STARK shielded proof verification failed: %w", err)
	}
	if !ok {
		return errors.New("zkvm: STARK shielded proof rejected")
	}
	return nil
}

// VerifyBlockProof verifies an aggregated block proof.
// When GPU is available and multiple proofs exist, uses batch MSM acceleration.
func (pv *ProofVerifier) VerifyBlockProof(block *Block) error {
	if block.BlockProof == nil {
		return nil // Block proof is optional
	}

	// Batch verify when multiple transactions and GPU available
	if len(block.Txs) > 1 && accel.Available() {
		results := batchVerifyProofsGPU(pv, block.Txs)
		for i, err := range results {
			if err != nil {
				return fmt.Errorf("tx %d proof verification failed: %w", i, err)
			}
		}
		return nil
	}

	// Sequential fallback
	for _, tx := range block.Txs {
		if err := pv.VerifyTransactionProof(tx); err != nil {
			return err
		}
	}

	return nil
}

// verifyGroth16Proof verifies a Groth16 proof using gnark
func (pv *ProofVerifier) verifyGroth16Proof(tx *Transaction) error {
	// Get verifying key for circuit type
	vkBytes, exists := pv.verifyingKeys[string(tx.Type)]
	if !exists {
		return fmt.Errorf("zkvm: no verifying key for circuit %q", tx.Type)
	}

	// Verify public inputs match transaction data
	if err := pv.verifyPublicInputs(tx); err != nil {
		return err
	}

	// Validate proof data length (Groth16: 2 G1 points + 1 G2 point)
	// BN254: G1 = 64 bytes (compressed), G2 = 128 bytes (compressed)
	// Total: 2*64 + 128 = 256 bytes minimum
	if len(tx.Proof.ProofData) < 256 {
		return errors.New("invalid proof data length for Groth16")
	}

	// Perform actual Groth16 verification using gnark-crypto
	if err := pv.verifyGroth16WithGnark(tx.Proof, vkBytes); err != nil {
		return fmt.Errorf("groth16 verification failed: %w", err)
	}

	pv.log.Debug("Groth16 proof verified",
		log.String("txID", tx.ID.String()),
		log.Int("vkLen", len(vkBytes)),
	)

	return nil
}

// verifyPLONKProof verifies a PLONK proof using gnark-crypto BN254 pairings
func (pv *ProofVerifier) verifyPLONKProof(tx *Transaction) error {
	// Get verifying key for circuit type
	vkBytes, exists := pv.verifyingKeys[string(tx.Type)]
	if !exists {
		return fmt.Errorf("zkvm: no verifying key for circuit %q", tx.Type)
	}

	// Verify public inputs
	if err := pv.verifyPublicInputs(tx); err != nil {
		return err
	}

	// PLONK proof structure: 7 G1 commitments + 3 scalars = 7*64 + 3*32 = 544 bytes
	if len(tx.Proof.ProofData) < 544 {
		return errors.New("invalid PLONK proof data length: expected 544+ bytes")
	}

	// Perform actual PLONK verification
	if err := pv.verifyPLONKWithGnark(tx.Proof, vkBytes); err != nil {
		return fmt.Errorf("PLONK verification failed: %w", err)
	}

	pv.log.Debug("PLONK proof verified",
		log.String("txID", tx.ID.String()),
		log.Int("vkLen", len(vkBytes)),
	)

	return nil
}

// verifyPublicInputs verifies that public inputs match transaction data
func (pv *ProofVerifier) verifyPublicInputs(tx *Transaction) error {
	if len(tx.Proof.PublicInputs) == 0 {
		return errors.New("no public inputs provided")
	}

	// Verify nullifiers are included in public inputs (exact byte comparison)
	for i, nullifier := range tx.Nullifiers {
		if i >= len(tx.Proof.PublicInputs) {
			return errors.New("missing public input for nullifier")
		}

		if !bytes.Equal(tx.Proof.PublicInputs[i], nullifier) {
			return errors.New("public input mismatch for nullifier")
		}
	}

	// Verify output commitments are included (exact byte comparison)
	outputCommitments := tx.GetOutputCommitments()
	offset := len(tx.Nullifiers)

	for i, commitment := range outputCommitments {
		idx := offset + i
		if idx >= len(tx.Proof.PublicInputs) {
			return errors.New("missing public input for output commitment")
		}

		if !bytes.Equal(tx.Proof.PublicInputs[idx], commitment) {
			return errors.New("public input mismatch for output commitment")
		}
	}

	return nil
}

// loadVerifyingKeys takes the verifying key for each circuit the config keys,
// and installs nothing for the others.
//
// It used to install an all-zero key for an unkeyed circuit and then decide, for
// the whole verifier at once, whether the keys were "dummy" — true only while
// EVERY key was zero. So keying one circuit turned that protection off for the
// rest, and their all-zero keys were then used as if real. That is the worst
// direction for a rule to fail in: the more of a chain an operator configures,
// the less of it is guarded. A key that is absent cannot be mistaken for one
// that is present, so the placeholder is gone and the circuit is refused by
// name at the lookup that already checks for it.
func (pv *ProofVerifier) loadVerifyingKeys() error {
	for _, ct := range []TransactionType{
		TransactionTypeTransfer,
		TransactionTypeShield,
		TransactionTypeUnshield,
	} {
		// Copied, so the verifier owns its bytes.
		if vk, ok := pv.config.VerifyingKeys[string(ct)]; ok && len(vk) > 0 {
			pv.verifyingKeys[string(ct)] = append([]byte(nil), vk...)
		}
	}

	// A verifier holding no key at all judges nothing, which is what the
	// classical path checks before it starts.
	pv.dummyKeys = len(pv.verifyingKeys) == 0

	// Strict-PQ hard gate (Red H1). Loading a REAL (non-dummy) bn254
	// verifying key on a strict-PQ chain is forbidden: such keys would
	// re-enable the forgeable classical pairing path for shielded value.
	// Refuse explicitly at construction rather than relying on the
	// implicit dummy-key detector — the shielded path on a strict-PQ
	// chain is STARK/FRI only.
	if pv.config.StrictPQ && !pv.dummyKeys {
		return errStrictPQRealVKForbidden
	}

	pv.log.Info("Loaded verifying keys",
		log.Int("count", len(pv.verifyingKeys)),
		log.String("proofSystem", pv.config.ProofSystem),
		log.Bool("strictPQ", pv.config.StrictPQ),
	)

	return nil
}

// VerifyingKeysLoaded returns true if real (non-dummy) verifying keys are loaded.
func (pv *ProofVerifier) VerifyingKeysLoaded() bool {
	return !pv.dummyKeys
}

// hashProof computes a hash of a proof for caching.
// Includes the transaction ID to bind the proof to a specific transaction,
// preventing a valid proof from being replayed for a different tx.
func (pv *ProofVerifier) hashProof(tx *Transaction) []byte {
	h := sha256.New()
	h.Write(tx.ID[:])
	h.Write([]byte(tx.Proof.ProofType))
	h.Write(tx.Proof.ProofData)

	for _, input := range tx.Proof.PublicInputs {
		h.Write(input)
	}

	return h.Sum(nil)
}

// GetCacheSize returns the current size of the proof cache
func (pv *ProofVerifier) GetCacheSize() int {
	return pv.proofCache.Len()
}

// GetStats returns verifier statistics
func (pv *ProofVerifier) GetStats() (verifyCount, cacheHits, cacheMisses uint64) {
	pv.mu.RLock()
	defer pv.mu.RUnlock()

	return pv.verifyCount, pv.cacheHits, pv.cacheMisses
}

// ClearCache clears the proof verification cache
func (pv *ProofVerifier) ClearCache() {
	pv.proofCache.Purge()

	pv.mu.Lock()
	pv.cacheHits = 0
	pv.cacheMisses = 0
	pv.mu.Unlock()

	pv.log.Info("Cleared proof verification cache")
}

// Groth16Proof represents a Groth16 proof structure
type Groth16Proof struct {
	Ar  bn254.G1Affine // Proof component A
	Bs  bn254.G2Affine // Proof component B
	Krs bn254.G1Affine // Proof component C
}

// Groth16VerifyingKey represents a Groth16 verifying key
type Groth16VerifyingKey struct {
	Alpha bn254.G1Affine   // Alpha in G1
	Beta  bn254.G2Affine   // Beta in G2
	Gamma bn254.G2Affine   // Gamma in G2
	Delta bn254.G2Affine   // Delta in G2
	K     []bn254.G1Affine // K[i] for public inputs
}

// verifyGroth16WithGnark performs actual Groth16 verification using pairing operations
func (pv *ProofVerifier) verifyGroth16WithGnark(proof *ZKProof, vkBytes []byte) error {
	// Deserialize verifying key
	vk, err := deserializeVerifyingKey(vkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize verifying key: %w", err)
	}

	// Validate verifying key with subgroup checks (CRITICAL for trusted setup validation)
	if err := validateVerifyingKey(vk); err != nil {
		return fmt.Errorf("verifying key validation failed: %w", err)
	}

	// Deserialize proof
	grothProof, err := deserializeGroth16Proof(proof.ProofData)
	if err != nil {
		return fmt.Errorf("failed to deserialize proof: %w", err)
	}

	// Deserialize public witness (public inputs)
	witness := make([]fr.Element, 0, len(proof.PublicInputs))
	for _, inputBytes := range proof.PublicInputs {
		var elem fr.Element
		elem.SetBytes(inputBytes)
		witness = append(witness, elem)
	}

	// Perform pairing-based verification
	if err := verifyGroth16Pairing(grothProof, vk, witness); err != nil {
		return fmt.Errorf("pairing verification failed: %w", err)
	}

	return nil
}

// verifyGroth16Pairing performs the Groth16 pairing check
// Verifies: e(A, B) = e(alpha, beta) * e(sum(pubInput_i * K_i), gamma) * e(C, delta)
//
// K carries one point per public input plus the constant term K[0], so a key
// of n points speaks about n-1 public inputs. The witness length arrives with
// the transaction and a peer chooses it, so it is bounded against the key
// before any K point is read.
func verifyGroth16Pairing(proof *Groth16Proof, vk *Groth16VerifyingKey, witness []fr.Element) error {
	if len(witness)+1 > len(vk.K) {
		return fmt.Errorf("public inputs: %d supplied, verifying key holds %d K points",
			len(witness), len(vk.K))
	}

	// Public input linear combination: K[0] + sum(witness_i * K[i+1]).
	// Every node has to reach the same point from the same key and witness,
	// so the sum stays on the CPU rather than being handed to an accelerator
	// whose answer is never compared against it.
	var publicInputLC bn254.G1Affine
	publicInputLC.Set(&vk.K[0])
	var scalar big.Int
	for i := range witness {
		var term bn254.G1Affine
		term.ScalarMultiplication(&vk.K[i+1], witness[i].BigInt(&scalar))
		publicInputLC.Add(&publicInputLC, &term)
	}

	// Pairing check: e(A, B) == e(alpha, beta) * e(publicInputLC, gamma) * e(C, delta)
	leftSide, err := bn254.Pair([]bn254.G1Affine{proof.Ar}, []bn254.G2Affine{proof.Bs})
	if err != nil {
		return fmt.Errorf("pairing A*B failed: %w", err)
	}

	alphaBeta, err := bn254.Pair([]bn254.G1Affine{vk.Alpha}, []bn254.G2Affine{vk.Beta})
	if err != nil {
		return fmt.Errorf("pairing alpha*beta failed: %w", err)
	}

	pubGamma, err := bn254.Pair([]bn254.G1Affine{publicInputLC}, []bn254.G2Affine{vk.Gamma})
	if err != nil {
		return fmt.Errorf("pairing pubInput*gamma failed: %w", err)
	}

	cDelta, err := bn254.Pair([]bn254.G1Affine{proof.Krs}, []bn254.G2Affine{vk.Delta})
	if err != nil {
		return fmt.Errorf("pairing C*delta failed: %w", err)
	}

	var rightSide bn254.GT
	rightSide.Set(&alphaBeta)
	rightSide.Mul(&rightSide, &pubGamma)
	rightSide.Mul(&rightSide, &cDelta)

	if !leftSide.Equal(&rightSide) {
		return errors.New("pairing check failed: proof is invalid")
	}

	return nil
}

// A point this verifier reads has to be in the prime-order subgroup and must
// not be the point at infinity. gnark encodes infinity as all-zero bytes and
// reports it as in-subgroup, and a pairing drops any term whose argument is
// infinity — so an element at infinity silently removes itself from the
// equation and leaves a weaker check than the one written down. checkG1 and
// checkG2 are the one place that decides what a usable point is; every
// decoder below routes through them.
var (
	errOffSubgroup = errors.New("point not in the prime-order subgroup")
	errAtInfinity  = errors.New("point at infinity")
)

func checkG1(p *bn254.G1Affine) error {
	if !p.IsInSubGroup() {
		return errOffSubgroup
	}
	if p.IsInfinity() {
		return errAtInfinity
	}
	return nil
}

func checkG2(p *bn254.G2Affine) error {
	if !p.IsInSubGroup() {
		return errOffSubgroup
	}
	if p.IsInfinity() {
		return errAtInfinity
	}
	return nil
}

// validateVerifyingKey checks every point of a Groth16 verifying key.
// A trusted setup never produces infinity for alpha, beta, gamma, delta or K,
// so a key that carries one is not a setup output and its pairing equation
// would collapse to something weaker.
func validateVerifyingKey(vk *Groth16VerifyingKey) error {
	if err := checkG1(&vk.Alpha); err != nil {
		return fmt.Errorf("Alpha: %w", err)
	}
	if err := checkG2(&vk.Beta); err != nil {
		return fmt.Errorf("Beta: %w", err)
	}
	if err := checkG2(&vk.Gamma); err != nil {
		return fmt.Errorf("Gamma: %w", err)
	}
	if err := checkG2(&vk.Delta); err != nil {
		return fmt.Errorf("Delta: %w", err)
	}
	for i := range vk.K {
		if err := checkG1(&vk.K[i]); err != nil {
			return fmt.Errorf("K[%d]: %w", i, err)
		}
	}

	return nil
}

// deserializeGroth16Proof deserializes a Groth16 proof from bytes.
// A proof it returns has already passed the point checks, so callers never
// repeat them.
func deserializeGroth16Proof(data []byte) (*Groth16Proof, error) {
	// Expected format: Ar (64 bytes) | Bs (128 bytes) | Krs (64 bytes) = 256 bytes
	if len(data) < 256 {
		return nil, errors.New("proof data too short")
	}

	proof := &Groth16Proof{}
	offset := 0

	// Deserialize Ar (G1 point, 64 bytes compressed)
	if err := proof.Ar.Unmarshal(data[offset : offset+64]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Ar: %w", err)
	}
	if err := checkG1(&proof.Ar); err != nil {
		return nil, fmt.Errorf("Ar: %w", err)
	}
	offset += 64

	// Deserialize Bs (G2 point, 128 bytes compressed)
	if err := proof.Bs.Unmarshal(data[offset : offset+128]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Bs: %w", err)
	}
	if err := checkG2(&proof.Bs); err != nil {
		return nil, fmt.Errorf("Bs: %w", err)
	}
	offset += 128

	// Deserialize Krs (G1 point, 64 bytes compressed)
	if err := proof.Krs.Unmarshal(data[offset : offset+64]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Krs: %w", err)
	}
	if err := checkG1(&proof.Krs); err != nil {
		return nil, fmt.Errorf("Krs: %w", err)
	}

	return proof, nil
}

// deserializeVerifyingKey deserializes a Groth16 verifying key from bytes
func deserializeVerifyingKey(data []byte) (*Groth16VerifyingKey, error) {
	// Format: Alpha (64) | Beta (128) | Gamma (128) | Delta (128) | numK (4) | K[...] (64*numK)
	minSize := 64 + 128 + 128 + 128 + 4
	if len(data) < minSize {
		return nil, errors.New("verifying key data too short")
	}

	vk := &Groth16VerifyingKey{}
	offset := 0

	// Alpha (G1)
	if err := vk.Alpha.Unmarshal(data[offset : offset+64]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Alpha: %w", err)
	}
	offset += 64

	// Beta (G2)
	if err := vk.Beta.Unmarshal(data[offset : offset+128]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Beta: %w", err)
	}
	offset += 128

	// Gamma (G2)
	if err := vk.Gamma.Unmarshal(data[offset : offset+128]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Gamma: %w", err)
	}
	offset += 128

	// Delta (G2)
	if err := vk.Delta.Unmarshal(data[offset : offset+128]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Delta: %w", err)
	}
	offset += 128

	// Number of K points
	numK := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data) < offset+int(numK)*64 {
		return nil, errors.New("insufficient data for K points")
	}

	// K points (G1)
	vk.K = make([]bn254.G1Affine, numK)
	for i := uint32(0); i < numK; i++ {
		if err := vk.K[i].Unmarshal(data[offset : offset+64]); err != nil {
			return nil, fmt.Errorf("failed to unmarshal K[%d]: %w", i, err)
		}
		offset += 64
	}

	return vk, nil
}

// ============================================================================
// PLONK Verification Implementation
// ============================================================================

// PLONKProof represents a PLONK proof structure
type PLONKProof struct {
	// Commitments (7 G1 points)
	LCommit bn254.G1Affine // Wire L commitment
	RCommit bn254.G1Affine // Wire R commitment
	OCommit bn254.G1Affine // Wire O commitment
	ZCommit bn254.G1Affine // Permutation polynomial commitment
	TLow    bn254.G1Affine // Quotient polynomial low
	TMid    bn254.G1Affine // Quotient polynomial mid
	THigh   bn254.G1Affine // Quotient polynomial high

	// Opening proof components
	WzOpening  bn254.G1Affine // Opening at z
	WzwOpening bn254.G1Affine // Opening at z*omega

	// Evaluation proofs (scalars)
	AEval     fr.Element // a(z) evaluation
	BEval     fr.Element // b(z) evaluation
	CEval     fr.Element // c(z) evaluation
	SigmaEval fr.Element // sigma permutation evaluation
	ZEval     fr.Element // z(z*omega) evaluation
}

// PLONKVerifyingKey represents a PLONK verifying key
type PLONKVerifyingKey struct {
	// SRS elements
	G1      bn254.G1Affine // Generator in G1
	G2      bn254.G2Affine // Generator in G2
	G2Alpha bn254.G2Affine // [alpha]_2

	// Selector commitments
	QLCommit bn254.G1Affine // Left selector
	QRCommit bn254.G1Affine // Right selector
	QMCommit bn254.G1Affine // Multiplication selector
	QOCommit bn254.G1Affine // Output selector
	QCCommit bn254.G1Affine // Constant selector

	// Permutation commitments
	S1Commit bn254.G1Affine // Sigma_1 permutation
	S2Commit bn254.G1Affine // Sigma_2 permutation
	S3Commit bn254.G1Affine // Sigma_3 permutation

	// Domain parameters
	N      uint64     // Circuit size (power of 2)
	K1, K2 fr.Element // Coset generators
	Omega  fr.Element // Root of unity
}

// verifyPLONKWithGnark performs actual PLONK verification
func (pv *ProofVerifier) verifyPLONKWithGnark(proof *ZKProof, vkBytes []byte) error {
	// Deserialize verifying key
	vk, err := deserializePLONKVerifyingKey(vkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize PLONK verifying key: %w", err)
	}

	// Deserialize proof
	plonkProof, err := deserializePLONKProof(proof.ProofData)
	if err != nil {
		return fmt.Errorf("failed to deserialize PLONK proof: %w", err)
	}

	// Deserialize public inputs
	publicInputs := make([]fr.Element, 0, len(proof.PublicInputs))
	for _, inputBytes := range proof.PublicInputs {
		var elem fr.Element
		elem.SetBytes(inputBytes)
		publicInputs = append(publicInputs, elem)
	}

	// Perform PLONK verification
	if err := verifyPLONKPairing(plonkProof, vk, publicInputs); err != nil {
		return fmt.Errorf("PLONK pairing verification failed: %w", err)
	}

	return nil
}

// errPLONKIncomplete says why a PLONK proof is never accepted here.
//
// What stood in this place checked e(Wz + u·Wzw, [α]₂) = e(z·Wz + u·zω·Wzw, [1]₂)
// and nothing else. It computed the public-input polynomial at the challenge
// point and threw the value away, and it never read the selector, permutation,
// quotient or evaluation commitments — so it related the two opening proofs to
// each other and said nothing about the statement being proved. A proof bound to
// no statement is a proof of anything.
//
// The precompile at 0x81 reached the same conclusion about its own copy and
// fails closed for it. This is the same rule at the second door: refusing costs
// nothing that works today, because an honest prover's proof does not satisfy
// that equation either.
var errPLONKIncomplete = errors.New(
	"plonk: the verification equation is not implemented — failing closed rather than " +
		"binding a proof to nothing; use the STARK/FRI verifier on strict-PQ chains")

// verifyPLONKPairing refuses every proof. The decoding above it still runs, so a
// caller can tell a malformed proof from one this will not judge, and there is
// no path through here that returns nil.
func verifyPLONKPairing(_ *PLONKProof, _ *PLONKVerifyingKey, _ []fr.Element) error {
	return errPLONKIncomplete
}

// plonkProofSize is 9 G1 commitments and the 5 evaluations that go with them.
const plonkProofSize = 9*64 + 5*32

// deserializePLONKProof reads a PLONK proof, which is exactly plonkProofSize
// bytes. It used to take anything from 544 bytes up and leave whichever
// evaluations were missing at zero, so a truncated proof decoded as a
// well-formed one carrying values nobody sent. Trailing bytes are refused for
// the same reason they are refused elsewhere: bytes the format does not
// describe are bytes two different proofs can differ in.
func deserializePLONKProof(data []byte) (*PLONKProof, error) {
	if len(data) != plonkProofSize {
		return nil, fmt.Errorf("PLONK proof is %d bytes, want %d", len(data), plonkProofSize)
	}

	proof := &PLONKProof{}
	offset := 0

	// Unmarshal 9 G1 points
	points := []*bn254.G1Affine{
		&proof.LCommit, &proof.RCommit, &proof.OCommit,
		&proof.ZCommit, &proof.TLow, &proof.TMid, &proof.THigh,
		&proof.WzOpening, &proof.WzwOpening,
	}

	for i, pt := range points {
		if err := pt.Unmarshal(data[offset : offset+64]); err != nil {
			return nil, fmt.Errorf("failed to unmarshal G1 point %d: %w", i, err)
		}
		if err := checkG1(pt); err != nil {
			return nil, fmt.Errorf("PLONK proof G1 point %d: %w", i, err)
		}
		offset += 64
	}

	for _, sc := range []*fr.Element{
		&proof.AEval, &proof.BEval, &proof.CEval, &proof.SigmaEval, &proof.ZEval,
	} {
		sc.SetBytes(data[offset : offset+32])
		offset += 32
	}

	return proof, nil
}

// deserializePLONKVerifyingKey deserializes a PLONK verifying key from bytes
func deserializePLONKVerifyingKey(data []byte) (*PLONKVerifyingKey, error) {
	if len(data) < 1024 {
		return nil, errors.New("PLONK verifying key data too short")
	}

	vk := &PLONKVerifyingKey{}
	offset := 0

	// G1 (64 bytes)
	if err := vk.G1.Unmarshal(data[offset : offset+64]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal G1: %w", err)
	}
	if err := checkG1(&vk.G1); err != nil {
		return nil, fmt.Errorf("PLONK VK G1 generator: %w", err)
	}
	offset += 64

	// G2 (128 bytes)
	if err := vk.G2.Unmarshal(data[offset : offset+128]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal G2: %w", err)
	}
	if err := checkG2(&vk.G2); err != nil {
		return nil, fmt.Errorf("PLONK VK G2 generator: %w", err)
	}
	offset += 128

	// G2Alpha (128 bytes)
	if err := vk.G2Alpha.Unmarshal(data[offset : offset+128]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal G2Alpha: %w", err)
	}
	if err := checkG2(&vk.G2Alpha); err != nil {
		return nil, fmt.Errorf("PLONK VK G2Alpha: %w", err)
	}
	offset += 128

	// Selector commitments (5 G1 points)
	selectorPoints := []*bn254.G1Affine{
		&vk.QLCommit, &vk.QRCommit, &vk.QMCommit, &vk.QOCommit, &vk.QCCommit,
	}
	for i, pt := range selectorPoints {
		if offset+64 > len(data) {
			return nil, fmt.Errorf("insufficient data for selector %d", i)
		}
		if err := pt.Unmarshal(data[offset : offset+64]); err != nil {
			return nil, fmt.Errorf("failed to unmarshal selector %d: %w", i, err)
		}
		if err := checkG1(pt); err != nil {
			return nil, fmt.Errorf("PLONK VK selector %d: %w", i, err)
		}
		offset += 64
	}

	// Permutation commitments (3 G1 points)
	permPoints := []*bn254.G1Affine{&vk.S1Commit, &vk.S2Commit, &vk.S3Commit}
	for i, pt := range permPoints {
		if offset+64 > len(data) {
			return nil, fmt.Errorf("insufficient data for permutation %d", i)
		}
		if err := pt.Unmarshal(data[offset : offset+64]); err != nil {
			return nil, fmt.Errorf("failed to unmarshal permutation %d: %w", i, err)
		}
		if err := checkG1(pt); err != nil {
			return nil, fmt.Errorf("PLONK VK permutation %d: %w", i, err)
		}
		offset += 64
	}

	// Domain parameters
	if offset+8 <= len(data) {
		vk.N = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	// K1, K2 (32 bytes each)
	if offset+32 <= len(data) {
		vk.K1.SetBytes(data[offset : offset+32])
		offset += 32
	}
	if offset+32 <= len(data) {
		vk.K2.SetBytes(data[offset : offset+32])
		offset += 32
	}

	// Omega (32 bytes)
	if offset+32 <= len(data) {
		vk.Omega.SetBytes(data[offset : offset+32])
	}

	return vk, nil
}

// STARK verification is disabled. The previous implementation only performed
// structural checks (commitment lengths, FRI layer presence) without actually
// verifying the FRI protocol or constraint composition. Accepting structurally-
// valid but mathematically-invalid proofs is worse than rejecting all proofs.
// Use groth16 or plonk proof types.

// Bulletproof verification is disabled. The previous implementation only checked
// that L/R vectors were present and a0/b0 were non-zero, without verifying the
// inner product argument. This is structurally checking, not mathematical
// verification. Use groth16 or plonk proof types.
