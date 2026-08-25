// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/luxfi/accel"
	"github.com/luxfi/log"
)

// msmGPU computes multi-scalar multiplication using GPU acceleration.
// scalars: field elements, bases: G1 affine points.
// Returns the resulting G1 point = sum(scalar_i * base_i).
// Falls back to CPU if GPU is unavailable.
func msmGPU(scalars []fr.Element, bases []bn254.G1Affine, logger log.Logger) (bn254.G1Affine, error) {
	var result bn254.G1Affine
	n := len(scalars)
	if n == 0 {
		return result, errors.New("empty MSM inputs")
	}
	if n != len(bases) {
		return result, errors.New("MSM: scalars/bases length mismatch")
	}

	// GPU path
	if accel.Available() {
		session, err := accel.DefaultSession()
		if err == nil {
			r, gpuErr := msmWithSession(session, scalars, bases)
			if gpuErr == nil {
				return r, nil
			}
			logger.Debug("GPU MSM failed, falling back to CPU", log.Reflect("error", gpuErr))
		}
	}

	// CPU fallback: sequential scalar multiplication
	return msmCPU(scalars, bases), nil
}

// msmWithSession runs MSM on GPU via accel session.
func msmWithSession(session *accel.Session, scalars []fr.Element, bases []bn254.G1Affine) (bn254.G1Affine, error) {
	var result bn254.G1Affine
	n := len(scalars)

	// Serialize scalars: each fr.Element is 32 bytes
	const scalarSize = 32
	scalarBytes := make([]byte, n*scalarSize)
	for i, s := range scalars {
		b := s.Bytes() // [32]byte big-endian
		copy(scalarBytes[i*scalarSize:], b[:])
	}

	// Serialize bases: each G1Affine is 64 bytes (two 32-byte coordinates)
	const pointSize = 64
	baseBytes := make([]byte, n*pointSize)
	for i, p := range bases {
		b := p.Marshal()
		copy(baseBytes[i*pointSize:], b[:pointSize])
	}

	// Create tensors
	scalarTensor, err := accel.NewTensorWithData[byte](session, []int{n, scalarSize}, scalarBytes)
	if err != nil {
		return result, err
	}
	defer scalarTensor.Close()

	baseTensor, err := accel.NewTensorWithData[byte](session, []int{n, pointSize}, baseBytes)
	if err != nil {
		return result, err
	}
	defer baseTensor.Close()

	resultTensor, err := accel.NewTensor[byte](session, []int{pointSize})
	if err != nil {
		return result, err
	}
	defer resultTensor.Close()

	// Execute MSM
	zk := session.ZK()
	if err := zk.MSM(scalarTensor.Untyped(), baseTensor.Untyped(), resultTensor.Untyped()); err != nil {
		return result, err
	}

	if err := session.Sync(); err != nil {
		return result, err
	}

	// Read result
	resultBytes, err := resultTensor.ToSlice()
	if err != nil {
		return result, err
	}
	if err := result.Unmarshal(resultBytes); err != nil {
		return result, fmt.Errorf("unmarshal MSM result: %w", err)
	}

	return result, nil
}

// msmCPU computes MSM sequentially on CPU.
func msmCPU(scalars []fr.Element, bases []bn254.G1Affine) bn254.G1Affine {
	var result bn254.G1Affine
	var scalar big.Int
	for i := range scalars {
		var term bn254.G1Affine
		term.ScalarMultiplication(&bases[i], scalars[i].BigInt(&scalar))
		result.Add(&result, &term)
	}
	return result
}

// batchVerifyProofsGPU verifies multiple ZK proofs in a block using GPU batch MSM.
// Returns per-proof results. Falls back to sequential CPU verification.
func batchVerifyProofsGPU(pv *ProofVerifier, txs []*Transaction) []error {
	results := make([]error, len(txs))

	// Collect Groth16 proofs that can be batched
	type batchEntry struct {
		index int
		proof *Groth16Proof
		vk    *Groth16VerifyingKey
		wit   []fr.Element
	}
	var batch []batchEntry

	for i, tx := range txs {
		if tx.Proof == nil {
			results[i] = errors.New("transaction missing proof")
			continue
		}

		// Strict-PQ gate (Red H1). The GPU batch path deserializes and
		// verifies Groth16 INLINE below, bypassing VerifyTransactionProof,
		// so the strict-PQ refusal MUST be applied here too — otherwise a
		// strict-PQ chain could verify a classical proof via the batch path.
		if err := pv.refuseClassicalUnderStrictPQ(tx.Proof.ProofType); err != nil {
			results[i] = err
			continue
		}

		// Only batch Groth16 — other types (incl. "stark") verified
		// individually through VerifyTransactionProof, which routes STARK
		// to the strict-PQ starkfri verifier.
		if tx.Proof.ProofType != "groth16" {
			results[i] = pv.VerifyTransactionProof(tx)
			continue
		}

		vkBytes, exists := pv.verifyingKeys[string(tx.Type)]
		if !exists {
			results[i] = errors.New("verifying key not found for circuit type")
			continue
		}

		if err := pv.verifyPublicInputs(tx); err != nil {
			results[i] = err
			continue
		}

		if len(tx.Proof.ProofData) < 256 {
			results[i] = errors.New("invalid proof data length for Groth16")
			continue
		}

		grothProof, err := deserializeGroth16Proof(tx.Proof.ProofData)
		if err != nil {
			results[i] = fmt.Errorf("deserialize proof: %w", err)
			continue
		}

		vk, err := deserializeVerifyingKey(vkBytes)
		if err != nil {
			results[i] = fmt.Errorf("deserialize vk: %w", err)
			continue
		}

		if err := validateVerifyingKey(vk); err != nil {
			results[i] = err
			continue
		}

		witness := make([]fr.Element, 0, len(tx.Proof.PublicInputs))
		for _, inputBytes := range tx.Proof.PublicInputs {
			var elem fr.Element
			elem.SetBytes(inputBytes)
			witness = append(witness, elem)
		}

		batch = append(batch, batchEntry{index: i, proof: grothProof, vk: vk, wit: witness})
	}

	// One pairing check serves both doors: a block of one transaction and a
	// block of many must reach the same verdict on the same proof.
	for _, e := range batch {
		results[e.index] = verifyGroth16Pairing(e.proof, e.vk, e.wit)
	}
	return results
}

// poseidonHashGPU computes Poseidon hash of inputs using GPU acceleration.
// Falls back to SHA-256 if GPU is unavailable.
func poseidonHashGPU(inputs [][]byte) ([]byte, error) {
	if !accel.Available() || len(inputs) == 0 {
		return nil, errors.New("GPU unavailable")
	}

	session, err := accel.DefaultSession()
	if err != nil {
		return nil, err
	}

	// Each input is a field element (uint64). Pad or truncate to 8 bytes.
	const fieldSize = 8
	n := len(inputs)
	flat := make([]byte, n*fieldSize)
	for i, inp := range inputs {
		if len(inp) >= fieldSize {
			copy(flat[i*fieldSize:], inp[:fieldSize])
		} else {
			copy(flat[i*fieldSize:], inp)
		}
	}

	inputTensor, err := accel.NewTensorWithData[byte](session, []int{1, n * fieldSize}, flat)
	if err != nil {
		return nil, err
	}
	defer inputTensor.Close()

	outputTensor, err := accel.NewTensor[byte](session, []int{1, fieldSize})
	if err != nil {
		return nil, err
	}
	defer outputTensor.Close()

	crypto := session.Crypto()
	if err := crypto.Poseidon(inputTensor.Untyped(), outputTensor.Untyped()); err != nil {
		return nil, err
	}

	if err := session.Sync(); err != nil {
		return nil, err
	}

	return outputTensor.ToSlice()
}
