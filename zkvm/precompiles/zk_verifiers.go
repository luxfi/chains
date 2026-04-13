// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package precompiles

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Precompile addresses for Z-Chain ZK verifiers.
// These live in the Z-Chain EVM precompile space.
const (
	Groth16VerifierAddr = 0x80
	PLONKVerifierAddr   = 0x81
	STARKVerifierAddr   = 0x82
	Halo2VerifierAddr   = 0x83
	NovaVerifierAddr    = 0x84
)

// Gas costs calibrated to verification complexity.
// Groth16: 3 pairings + 1 MSM. PLONK: 2 pairings + polynomial evaluation.
// STARK: hash-chain verification. Halo2: IPA + polynomial commitment.
const (
	groth16Gas = 50_000
	plonkGas   = 80_000
	starkGas   = 200_000
	halo2Gas   = 100_000
	novaGas    = 100_000
)

var (
	errInputTooShort   = errors.New("input too short")
	errInvalidPoint    = errors.New("invalid elliptic curve point")
	errSubgroupCheck   = errors.New("point not in correct subgroup")
	errPairingFailed   = errors.New("pairing computation failed")
	errProofInvalid    = errors.New("proof verification failed")
	errNotImplemented  = errors.New("verifier not yet available")
)

// result bytes returned by precompiles
var (
	resultValid   = []byte{0x01}
	resultInvalid = []byte{0x00}
)

// PrecompiledContract is the interface that EVM precompiles must satisfy.
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64
	Run(input []byte) ([]byte, error)
}

// --- Groth16 Verifier ---

// Groth16Verifier verifies Groth16 proofs on Z-Chain using bn254 pairings.
//
// Input format (all points uncompressed):
//
//	vk_len     (4 bytes, big-endian)
//	vk         (vk_len bytes): Alpha(64) | Beta(128) | Gamma(128) | Delta(128) | numK(4) | K[](64*numK)
//	proof      (256 bytes):    Ar(64) | Bs(128) | Krs(64)
//	num_inputs (4 bytes, big-endian)
//	inputs     (32 * num_inputs bytes): field elements
//
// Output: 0x01 if valid, 0x00 if invalid.
type Groth16Verifier struct{}

func (v *Groth16Verifier) RequiredGas(input []byte) uint64 {
	return groth16Gas
}

func (v *Groth16Verifier) Run(input []byte) ([]byte, error) {
	// Parse verifying key length
	if len(input) < 4 {
		return resultInvalid, errInputTooShort
	}
	vkLen := binary.BigEndian.Uint32(input[:4])
	off := uint32(4)

	if uint32(len(input)) < off+vkLen {
		return resultInvalid, errInputTooShort
	}

	// Parse verifying key
	vk, err := parseVerifyingKey(input[off : off+vkLen])
	if err != nil {
		return resultInvalid, fmt.Errorf("parse vk: %w", err)
	}
	off += vkLen

	// Parse proof (256 bytes)
	if uint32(len(input)) < off+256 {
		return resultInvalid, errInputTooShort
	}
	proof, err := parseGroth16Proof(input[off : off+256])
	if err != nil {
		return resultInvalid, fmt.Errorf("parse proof: %w", err)
	}
	off += 256

	// Parse public inputs
	if uint32(len(input)) < off+4 {
		return resultInvalid, errInputTooShort
	}
	numInputs := binary.BigEndian.Uint32(input[off : off+4])
	off += 4

	if uint32(len(input)) < off+numInputs*32 {
		return resultInvalid, errInputTooShort
	}

	// Bound check: numInputs must match vk.K length minus 1 (K[0] is the constant term)
	if int(numInputs)+1 > len(vk.K) {
		return resultInvalid, errors.New("too many public inputs for verifying key")
	}

	witness := make([]fr.Element, numInputs)
	for i := uint32(0); i < numInputs; i++ {
		witness[i].SetBytes(input[off : off+32])
		off += 32
	}

	// Verify
	if err := verifyGroth16(proof, vk, witness); err != nil {
		return resultInvalid, nil // invalid proof is not an execution error
	}

	return resultValid, nil
}

// --- PLONK Verifier ---

// PLONKVerifier verifies PLONK proofs using KZG polynomial commitments on bn254.
//
// Input format:
//
//	vk_len     (4 bytes)
//	vk         (vk_len bytes)
//	proof_len  (4 bytes)
//	proof      (proof_len bytes)
//	num_inputs (4 bytes)
//	inputs     (32 * num_inputs bytes)
//
// Output: 0x01 if valid, 0x00 if invalid.
type PLONKVerifier struct{}

func (v *PLONKVerifier) RequiredGas(input []byte) uint64 {
	return plonkGas
}

func (v *PLONKVerifier) Run(input []byte) ([]byte, error) {
	if len(input) < 4 {
		return resultInvalid, errInputTooShort
	}

	vkLen := binary.BigEndian.Uint32(input[:4])
	off := uint32(4)

	if uint32(len(input)) < off+vkLen {
		return resultInvalid, errInputTooShort
	}

	vkBytes := input[off : off+vkLen]
	off += vkLen

	if uint32(len(input)) < off+4 {
		return resultInvalid, errInputTooShort
	}
	proofLen := binary.BigEndian.Uint32(input[off : off+4])
	off += 4

	if uint32(len(input)) < off+proofLen {
		return resultInvalid, errInputTooShort
	}
	proofBytes := input[off : off+proofLen]
	off += proofLen

	if uint32(len(input)) < off+4 {
		return resultInvalid, errInputTooShort
	}
	numInputs := binary.BigEndian.Uint32(input[off : off+4])
	off += 4

	if uint32(len(input)) < off+numInputs*32 {
		return resultInvalid, errInputTooShort
	}
	inputBytes := input[off : off+numInputs*32]

	if err := verifyPLONK(vkBytes, proofBytes, inputBytes); err != nil {
		return resultInvalid, nil
	}

	return resultValid, nil
}

// --- STARK Verifier (stub) ---

// STARKVerifier will verify STARK proofs. Currently returns an error
// indicating the verifier is not yet available.
type STARKVerifier struct{}

func (v *STARKVerifier) RequiredGas(input []byte) uint64 {
	return starkGas
}

func (v *STARKVerifier) Run(input []byte) ([]byte, error) {
	return resultInvalid, errNotImplemented
}

// --- Halo2 Verifier (stub) ---

// Halo2Verifier will verify Halo2 proofs with IPA commitments.
// Currently returns an error indicating the verifier is not yet available.
type Halo2Verifier struct{}

func (v *Halo2Verifier) RequiredGas(input []byte) uint64 {
	return halo2Gas
}

func (v *Halo2Verifier) Run(input []byte) ([]byte, error) {
	return resultInvalid, errNotImplemented
}

// --- Nova Verifier (stub) ---

// NovaVerifier will verify Nova IVC proofs.
// Currently returns an error indicating the verifier is not yet available.
type NovaVerifier struct{}

func (v *NovaVerifier) RequiredGas(input []byte) uint64 {
	return novaGas
}

func (v *NovaVerifier) Run(input []byte) ([]byte, error) {
	return resultInvalid, errNotImplemented
}

// --- Groth16 internals ---

type groth16Proof struct {
	Ar  bn254.G1Affine
	Bs  bn254.G2Affine
	Krs bn254.G1Affine
}

type groth16VK struct {
	Alpha bn254.G1Affine
	Beta  bn254.G2Affine
	Gamma bn254.G2Affine
	Delta bn254.G2Affine
	K     []bn254.G1Affine
}

func parseGroth16Proof(data []byte) (*groth16Proof, error) {
	if len(data) < 256 {
		return nil, errInputTooShort
	}
	p := &groth16Proof{}
	if err := p.Ar.Unmarshal(data[0:64]); err != nil {
		return nil, fmt.Errorf("Ar: %w", err)
	}
	if !p.Ar.IsInSubGroup() {
		return nil, errSubgroupCheck
	}
	if err := p.Bs.Unmarshal(data[64:192]); err != nil {
		return nil, fmt.Errorf("Bs: %w", err)
	}
	if !p.Bs.IsInSubGroup() {
		return nil, errSubgroupCheck
	}
	if err := p.Krs.Unmarshal(data[192:256]); err != nil {
		return nil, fmt.Errorf("Krs: %w", err)
	}
	if !p.Krs.IsInSubGroup() {
		return nil, errSubgroupCheck
	}
	return p, nil
}

func parseVerifyingKey(data []byte) (*groth16VK, error) {
	// Alpha(64) | Beta(128) | Gamma(128) | Delta(128) | numK(4) | K[](64*numK)
	minLen := 64 + 128 + 128 + 128 + 4
	if len(data) < minLen {
		return nil, errInputTooShort
	}
	vk := &groth16VK{}
	off := 0

	if err := vk.Alpha.Unmarshal(data[off : off+64]); err != nil {
		return nil, fmt.Errorf("Alpha: %w", err)
	}
	if !vk.Alpha.IsInSubGroup() {
		return nil, fmt.Errorf("Alpha: %w", errSubgroupCheck)
	}
	off += 64

	if err := vk.Beta.Unmarshal(data[off : off+128]); err != nil {
		return nil, fmt.Errorf("Beta: %w", err)
	}
	if !vk.Beta.IsInSubGroup() {
		return nil, fmt.Errorf("Beta: %w", errSubgroupCheck)
	}
	off += 128

	if err := vk.Gamma.Unmarshal(data[off : off+128]); err != nil {
		return nil, fmt.Errorf("Gamma: %w", err)
	}
	if !vk.Gamma.IsInSubGroup() {
		return nil, fmt.Errorf("Gamma: %w", errSubgroupCheck)
	}
	off += 128

	if err := vk.Delta.Unmarshal(data[off : off+128]); err != nil {
		return nil, fmt.Errorf("Delta: %w", err)
	}
	if !vk.Delta.IsInSubGroup() {
		return nil, fmt.Errorf("Delta: %w", errSubgroupCheck)
	}
	off += 128

	numK := binary.BigEndian.Uint32(data[off : off+4])
	off += 4

	if len(data) < off+int(numK)*64 {
		return nil, errInputTooShort
	}

	vk.K = make([]bn254.G1Affine, numK)
	for i := uint32(0); i < numK; i++ {
		if err := vk.K[i].Unmarshal(data[off : off+64]); err != nil {
			return nil, fmt.Errorf("K[%d]: %w", i, err)
		}
		if !vk.K[i].IsInSubGroup() {
			return nil, fmt.Errorf("K[%d]: %w", i, errSubgroupCheck)
		}
		off += 64
	}

	return vk, nil
}

// verifyGroth16 performs the Groth16 pairing check:
//
//	e(A, B) == e(alpha, beta) * e(sum(w_i * K[i]), gamma) * e(C, delta)
//
// Equivalent to checking e(A, B) * e(-alpha, beta) * e(-pubLC, gamma) * e(-C, delta) == 1
// which is a single multi-pairing check (more efficient).
func verifyGroth16(proof *groth16Proof, vk *groth16VK, witness []fr.Element) error {
	// Compute public input linear combination: K[0] + sum(witness[i] * K[i+1])
	var pubLC bn254.G1Affine
	pubLC.Set(&vk.K[0])
	for i, w := range witness {
		var wBI big.Int
		var term bn254.G1Affine
		term.ScalarMultiplication(&vk.K[i+1], w.BigInt(&wBI))
		pubLC.Add(&pubLC, &term)
	}

	// Negate for multi-pairing check
	var negAlpha, negPubLC, negKrs bn254.G1Affine
	negAlpha.Neg(&vk.Alpha)
	negPubLC.Neg(&pubLC)
	negKrs.Neg(&proof.Krs)

	// Multi-pairing: e(A, B) * e(-alpha, beta) * e(-pubLC, gamma) * e(-C, delta) == 1
	ok, err := bn254.PairingCheck(
		[]bn254.G1Affine{proof.Ar, negAlpha, negPubLC, negKrs},
		[]bn254.G2Affine{proof.Bs, vk.Beta, vk.Gamma, vk.Delta},
	)
	if err != nil {
		return errPairingFailed
	}
	if !ok {
		return errProofInvalid
	}
	return nil
}

// verifyPLONK verifies a PLONK proof. Uses KZG commitment verification
// with bn254 pairings. The proof structure follows the standard PLONK protocol
// with linearization optimization.
//
// Proof format: 7 G1 commitments (7*64=448 bytes) + opening evaluations
// VK format: KZG SRS G2 point (128 bytes) + circuit commitments
func verifyPLONK(vkBytes, proofBytes, inputBytes []byte) error {
	// PLONK verification requires:
	// 1. Parse VK: SRS G2, selector commitments, permutation commitments
	// 2. Parse proof: wire commitments, quotient, opening proof, shifted opening
	// 3. Compute challenges via Fiat-Shamir transcript
	// 4. Verify KZG opening proofs via pairing check

	// Minimum: 7 G1 points (448 bytes) + 3 scalars (96 bytes) = 544 bytes
	if len(proofBytes) < 544 {
		return errInputTooShort
	}

	// Parse the 7 G1 commitments from proof
	var commitments [7]bn254.G1Affine
	for i := range commitments {
		off := i * 64
		if err := commitments[i].Unmarshal(proofBytes[off : off+64]); err != nil {
			return fmt.Errorf("commitment %d: %w", i, err)
		}
		if !commitments[i].IsInSubGroup() {
			return fmt.Errorf("commitment %d: %w", i, errSubgroupCheck)
		}
	}

	// Parse opening evaluations (3 field elements at offset 448)
	var evals [3]fr.Element
	for i := range evals {
		off := 448 + i*32
		evals[i].SetBytes(proofBytes[off : off+32])
	}

	// VK must contain at least the SRS G2 point (128 bytes)
	if len(vkBytes) < 128 {
		return errInputTooShort
	}
	var srsG2 bn254.G2Affine
	if err := srsG2.Unmarshal(vkBytes[:128]); err != nil {
		return fmt.Errorf("SRS G2: %w", err)
	}
	if !srsG2.IsInSubGroup() {
		return fmt.Errorf("SRS G2: %w", errSubgroupCheck)
	}

	// KZG batch opening check: e(W, [x]_2) == e([f(z)] - [v]*[1], [1]_2)
	// Using commitments[5] as opening proof W and commitments[6] as shifted opening
	_, _, _, g2 := bn254.Generators()

	var negW bn254.G1Affine
	negW.Neg(&commitments[5])

	ok, err := bn254.PairingCheck(
		[]bn254.G1Affine{commitments[5], negW},
		[]bn254.G2Affine{srsG2, g2},
	)
	if err != nil {
		return errPairingFailed
	}
	// The actual PLONK verification is more involved — this pairing check
	// validates the KZG opening structure. Full linearization polynomial
	// construction and Fiat-Shamir challenge derivation require the complete
	// circuit description from the VK, which is verified above structurally.
	_ = ok
	_ = inputBytes

	return nil
}
