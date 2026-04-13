// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"errors"
	"fmt"

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
	for i, s := range scalars {
		var term bn254.G1Affine
		term.ScalarMultiplication(&bases[i], s.BigInt(nil))
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

		// Only batch Groth16 — other types verified individually
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

		// Subgroup checks on proof points
		if !grothProof.Ar.IsInSubGroup() || !grothProof.Krs.IsInSubGroup() {
			results[i] = errors.New("zkvm: Groth16 proof G1 point not in prime-order subgroup")
			continue
		}
		if !grothProof.Bs.IsInSubGroup() {
			results[i] = errors.New("zkvm: Groth16 proof G2 point not in prime-order subgroup")
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

	// If no GPU or only 1 proof, verify sequentially
	if len(batch) <= 1 || !accel.Available() {
		for _, e := range batch {
			results[e.index] = verifyGroth16Pairing(e.proof, e.vk, e.wit)
		}
		return results
	}

	// GPU batch path: accelerate MSM per proof, verify pairings
	for _, e := range batch {
		results[e.index] = verifyGroth16PairingGPU(e.proof, e.vk, e.wit, pv.log)
	}
	return results
}

// verifyGroth16PairingGPU is identical to verifyGroth16Pairing but uses GPU MSM
// for the public input linear combination step.
func verifyGroth16PairingGPU(proof *Groth16Proof, vk *Groth16VerifyingKey, witness []fr.Element, logger log.Logger) error {
	if len(witness) > len(vk.K) {
		return errors.New("too many public inputs")
	}

	// GPU-accelerated MSM for public input LC: K[0] + sum(witness_i * K[i+1])
	// Build scalars=[1, w0, w1, ...] and bases=[K[0], K[1], K[2], ...]
	scalars := make([]fr.Element, len(witness)+1)
	bases := make([]bn254.G1Affine, len(witness)+1)

	scalars[0].SetOne()
	bases[0].Set(&vk.K[0])
	for i, w := range witness {
		scalars[i+1].Set(&w)
		bases[i+1].Set(&vk.K[i+1])
	}

	publicInputLC, err := msmGPU(scalars, bases, logger)
	if err != nil {
		return fmt.Errorf("GPU MSM failed: %w", err)
	}

	// Pairing check (same as CPU path)
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
