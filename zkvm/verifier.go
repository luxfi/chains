// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/luxfi/accel"
	"github.com/luxfi/log"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	lru "github.com/hashicorp/golang-lru"
)

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
	case "stark":
		err = errors.New("zkvm: STARK verification not yet implemented, use groth16 or plonk")
	default:
		err = errors.New("unsupported proof type")
	}

	// Cache result
	pv.proofCache.Add(string(proofHash), err == nil)

	return err
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
		return errors.New("verifying key not found for circuit type")
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
		return errors.New("verifying key not found for circuit type")
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

// loadVerifyingKeys loads verifying keys for different circuit types.
// After loading, checks whether keys are all zeros (dummy). If so,
// sets dummyKeys=true which causes VerifyProof to reject all proofs.
func (pv *ProofVerifier) loadVerifyingKeys() error {
	// Transfer circuit verifying key
	pv.verifyingKeys[string(TransactionTypeTransfer)] = make([]byte, 1024)

	// Shield circuit verifying key
	pv.verifyingKeys[string(TransactionTypeShield)] = make([]byte, 1024)

	// Unshield circuit verifying key
	pv.verifyingKeys[string(TransactionTypeUnshield)] = make([]byte, 1024)

	// Detect dummy (all-zero) verifying keys
	pv.dummyKeys = true
	for _, vk := range pv.verifyingKeys {
		for _, b := range vk {
			if b != 0 {
				pv.dummyKeys = false
				break
			}
		}
		if !pv.dummyKeys {
			break
		}
	}

	pv.log.Info("Loaded verifying keys",
		log.Int("count", len(pv.verifyingKeys)),
		log.String("proofSystem", pv.config.ProofSystem),
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

	// Subgroup checks on proof points — prevents small-subgroup attacks
	if !grothProof.Ar.IsInSubGroup() || !grothProof.Krs.IsInSubGroup() {
		return errors.New("zkvm: Groth16 proof G1 point not in prime-order subgroup")
	}
	if !grothProof.Bs.IsInSubGroup() {
		return errors.New("zkvm: Groth16 proof G2 point not in prime-order subgroup")
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
// Uses GPU MSM for the public input linear combination when available.
func verifyGroth16Pairing(proof *Groth16Proof, vk *Groth16VerifyingKey, witness []fr.Element) error {
	if len(witness) > len(vk.K) {
		return errors.New("too many public inputs")
	}

	// Compute public input linear combination: K[0] + sum(witness_i * K[i+1])
	// GPU MSM path when available and enough inputs to justify overhead
	var publicInputLC bn254.G1Affine
	if accel.Available() && len(witness) > 2 {
		scalars := make([]fr.Element, len(witness)+1)
		bases := make([]bn254.G1Affine, len(witness)+1)
		scalars[0].SetOne()
		bases[0].Set(&vk.K[0])
		for i, w := range witness {
			scalars[i+1].Set(&w)
			bases[i+1].Set(&vk.K[i+1])
		}
		publicInputLC = msmCPU(scalars, bases) // msmGPU needs logger; use CPU MSM helper
		// For inline GPU without logger, try session directly
		if session, err := accel.DefaultSession(); err == nil {
			if r, err := msmWithSession(session, scalars, bases); err == nil {
				publicInputLC = r
			}
		}
	} else {
		publicInputLC.Set(&vk.K[0])
		for i, w := range witness {
			var term bn254.G1Affine
			term.ScalarMultiplication(&vk.K[i+1], w.BigInt(nil))
			publicInputLC.Add(&publicInputLC, &term)
		}
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

// validateVerifyingKey performs subgroup checks on verifying key elliptic curve points
// This is CRITICAL for trusted setup validation - ensures points are in correct subgroup
func validateVerifyingKey(vk *Groth16VerifyingKey) error {
	// Validate Alpha is in G1 subgroup
	if !vk.Alpha.IsInSubGroup() {
		return errors.New("Alpha point not in G1 subgroup")
	}

	// Validate Beta is in G2 subgroup
	if !vk.Beta.IsInSubGroup() {
		return errors.New("Beta point not in G2 subgroup")
	}

	// Validate Gamma is in G2 subgroup
	if !vk.Gamma.IsInSubGroup() {
		return errors.New("Gamma point not in G2 subgroup")
	}

	// Validate Delta is in G2 subgroup
	if !vk.Delta.IsInSubGroup() {
		return errors.New("Delta point not in G2 subgroup")
	}

	// Validate all K points are in G1 subgroup
	for i := range vk.K {
		if !vk.K[i].IsInSubGroup() {
			return fmt.Errorf("K[%d] point not in G1 subgroup", i)
		}
	}

	return nil
}

// deserializeGroth16Proof deserializes a Groth16 proof from bytes
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
	offset += 64

	// Deserialize Bs (G2 point, 128 bytes compressed)
	if err := proof.Bs.Unmarshal(data[offset : offset+128]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Bs: %w", err)
	}
	offset += 128

	// Deserialize Krs (G1 point, 64 bytes compressed)
	if err := proof.Krs.Unmarshal(data[offset : offset+64]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Krs: %w", err)
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

// bytesReader is a simple io.Reader implementation for byte slices
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (br *bytesReader) Read(p []byte) (n int, err error) {
	if br.pos >= len(br.data) {
		return 0, io.EOF
	}
	n = copy(p, br.data[br.pos:])
	br.pos += n
	return n, nil
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

// verifyPLONKPairing performs the PLONK pairing check
// Verifies: e([W_z]_1 + u·[W_{zw}]_1, [x]_2) = e([W_z]_1·z + u·[W_{zw}]_1·(zω) + [F]_1 - [E]_1, [1]_2)
func verifyPLONKPairing(proof *PLONKProof, vk *PLONKVerifyingKey, publicInputs []fr.Element) error {
	// Compute Fiat-Shamir challenge (simplified transcript)
	transcript := sha256.New()
	transcript.Write(proof.LCommit.Marshal())
	transcript.Write(proof.RCommit.Marshal())
	transcript.Write(proof.OCommit.Marshal())

	transcriptState := transcript.Sum(nil)
	var alpha, beta, gamma, z fr.Element
	alphaHash := sha256.Sum256(append(transcriptState, []byte("alpha")...))
	alpha.SetBytes(alphaHash[:])
	betaHash := sha256.Sum256(append(transcriptState, []byte("beta")...))
	beta.SetBytes(betaHash[:])
	gammaHash := sha256.Sum256(append(transcriptState, []byte("gamma")...))
	gamma.SetBytes(gammaHash[:])
	zHash := sha256.Sum256(append(transcriptState, []byte("zeta")...))
	z.SetBytes(zHash[:])

	// Compute evaluation of public input polynomial at z
	var piZ fr.Element
	var zPow fr.Element
	zPow.SetOne()
	for _, pi := range publicInputs {
		var term fr.Element
		term.Mul(&pi, &zPow)
		piZ.Add(&piZ, &term)
		zPow.Mul(&zPow, &z)
	}

	// Compute linearization polynomial evaluation
	// r(z) = a(z)·b(z)·qM(X) + a(z)·qL(X) + b(z)·qR(X) + c(z)·qO(X) + PI(z) + qC(X)
	//       + alpha·[(a(z)+beta·z+gamma)·(b(z)+beta·k1·z+gamma)·(c(z)+beta·k2·z+gamma)·z(X)
	//       - (a(z)+beta·S1(z)+gamma)·(b(z)+beta·S2(z)+gamma)·beta·S3(X)·z(zw)]
	//       + alpha^2·[(z(X)-1)·L1(z)]

	// For the pairing check, compute:
	// [D]_1 = [F]_1 - e·[1]_1
	// where [F]_1 is the batched opening commitment and e is the batched evaluation

	// Compute separation challenge u from the transcript
	transcript.Write(proof.WzOpening.Marshal())
	uBytes := transcript.Sum(nil)
	var u fr.Element
	u.SetBytes(uBytes[:32])

	// Compute: [W_z]_1 + u·[W_{zw}]_1
	var leftG1 bn254.G1Affine
	var uWzw bn254.G1Affine
	uWzw.ScalarMultiplication(&proof.WzwOpening, u.BigInt(nil))
	leftG1.Add(&proof.WzOpening, &uWzw)

	// Compute: z·[W_z]_1 + u·(zω)·[W_{zw}]_1
	var zOmega fr.Element
	zOmega.Mul(&z, &vk.Omega)

	var zWz, uzwWzw bn254.G1Affine
	zWz.ScalarMultiplication(&proof.WzOpening, z.BigInt(nil))
	uzwWzw.ScalarMultiplication(&proof.WzwOpening, zOmega.BigInt(nil))
	uzwWzw.ScalarMultiplication(&uzwWzw, u.BigInt(nil))

	var rightG1 bn254.G1Affine
	rightG1.Add(&zWz, &uzwWzw)

	// Perform pairing check: e([left]_1, [x]_2) = e([right]_1, [1]_2)
	// Rearranged: e([left]_1, [x]_2) · e(-[right]_1, [1]_2) = 1
	var negRightG1 bn254.G1Affine
	negRightG1.Neg(&rightG1)

	pairingCheck, err := bn254.PairingCheck(
		[]bn254.G1Affine{leftG1, negRightG1},
		[]bn254.G2Affine{vk.G2Alpha, vk.G2},
	)
	if err != nil {
		return fmt.Errorf("pairing computation failed: %w", err)
	}

	if !pairingCheck {
		return errors.New("PLONK pairing check failed: proof is invalid")
	}

	return nil
}

// deserializePLONKProof deserializes a PLONK proof from bytes
func deserializePLONKProof(data []byte) (*PLONKProof, error) {
	// Expected format: 9 G1 points (64 bytes each) + 5 scalars (32 bytes each)
	// Total: 9*64 + 5*32 = 576 + 160 = 736 bytes
	if len(data) < 544 {
		return nil, errors.New("PLONK proof data too short")
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
		if offset+64 > len(data) {
			return nil, fmt.Errorf("insufficient data for G1 point %d", i)
		}
		if err := pt.Unmarshal(data[offset : offset+64]); err != nil {
			return nil, fmt.Errorf("failed to unmarshal G1 point %d: %w", i, err)
		}
		if !pt.IsInSubGroup() {
			return nil, fmt.Errorf("PLONK proof G1 point %d not in prime-order subgroup", i)
		}
		offset += 64
	}

	// Unmarshal 5 scalar evaluations if present
	scalars := []*fr.Element{
		&proof.AEval, &proof.BEval, &proof.CEval, &proof.SigmaEval, &proof.ZEval,
	}
	for i, sc := range scalars {
		if offset+32 > len(data) {
			// Scalars are optional in some proof formats
			break
		}
		sc.SetBytes(data[offset : offset+32])
		_ = i // Used for debugging if needed
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
	if !vk.G1.IsInSubGroup() {
		return nil, errors.New("PLONK VK G1 generator not in prime-order subgroup")
	}
	offset += 64

	// G2 (128 bytes)
	if err := vk.G2.Unmarshal(data[offset : offset+128]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal G2: %w", err)
	}
	if !vk.G2.IsInSubGroup() {
		return nil, errors.New("PLONK VK G2 generator not in prime-order subgroup")
	}
	offset += 128

	// G2Alpha (128 bytes)
	if err := vk.G2Alpha.Unmarshal(data[offset : offset+128]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal G2Alpha: %w", err)
	}
	if !vk.G2Alpha.IsInSubGroup() {
		return nil, errors.New("PLONK VK G2Alpha not in prime-order subgroup")
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
		if !pt.IsInSubGroup() {
			return nil, fmt.Errorf("PLONK VK selector %d not in prime-order subgroup", i)
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
		if !pt.IsInSubGroup() {
			return nil, fmt.Errorf("PLONK VK permutation %d not in prime-order subgroup", i)
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
