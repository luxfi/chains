// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Z-Chain MLDSAGroth16 witness producer for Quasar parallel-witness
// finality (LP-020 §2 Consensus Modes, witness set bit WitnessZ).
//
// The Z-Chain VM is the parallel finality witness for the Z lane. Each
// consensus round, the Quasar driver pushes a 32-byte round digest plus
// the canonical validator ML-DSA-65 public-key list (rooted in
// pchain_validator_root) to this adapter. The adapter collects per-
// validator ML-DSA-65 signatures over the digest and produces a single
// Groth16/bn254 proof attesting:
//
//	∀ i ∈ [N]: ML-DSA.Verify(pk_i, digest, σ_i) = 1
//
// The proof is verified on-chain by the existing Groth16 precompile in
// chains/zkvm/precompiles/zk_verifiers.go (Groth16Verifier). The circuit
// itself is NOT implemented in this pass; producing real witnesses
// requires circuit design, trusted-setup ceremony, and prover infra
// (LP-020 §6, proofs/quasar-cert-soundness.tex App. B).
//
// The method signature matches consensus/protocol/quasar.ZWitnessProducer
// (Witness(ctx, [32]byte, [][]byte) ([]byte, error)) so this adapter
// satisfies that interface structurally once the consensus dependency
// is bumped to ship the new type.

package zkvm

import (
	"context"
	"errors"
)

// ZWitnessAdapter adapts the Z-Chain MLDSAGroth16 prover to the consensus
// ZWitnessProducer interface used by the Quasar round driver.
//
// TODO(pqz-circuit): implement the MLDSAGroth16 R1CS circuit, run trusted
// setup, integrate the prover. Until then Witness returns
// ErrZWitnessNotImplemented and the round driver finalizes at the next
// lower witness level (PolicyQuorum or PolicyPQ).
type ZWitnessAdapter struct {
	vm *VM
}

// NewZWitnessAdapter constructs a Z-witness adapter backed by the given
// Z-Chain VM.
func NewZWitnessAdapter(vm *VM) *ZWitnessAdapter {
	return &ZWitnessAdapter{vm: vm}
}

// ErrZWitnessNotImplemented is returned by ZWitnessAdapter.Witness until
// the MLDSAGroth16 circuit, trusted setup, and prover ship.
var ErrZWitnessNotImplemented = errors.New("Z-Chain MLDSAGroth16 prover not implemented (LP-020 §6, paper App. B)")

// Witness produces a Groth16 proof aggregating per-validator ML-DSA-65
// signatures over the round digest. Signature matches
// consensus/protocol/quasar.ZWitnessProducer.
//
// validatorMLDSAPubs is the canonical ML-DSA-65 public-key list rooted in
// pchain_validator_root for the round; the Groth16 circuit takes this
// list as a public input.
//
// Returns ErrZWitnessNotImplemented today; the round driver treats this
// as the witness being unavailable and finalizes at the next-lower
// witness level.
func (a *ZWitnessAdapter) Witness(ctx context.Context, digest [32]byte, validatorMLDSAPubs [][]byte) ([]byte, error) {
	_ = ctx
	_ = digest
	_ = validatorMLDSAPubs
	if a.vm == nil {
		return nil, ErrZWitnessNotImplemented
	}
	return nil, ErrZWitnessNotImplemented
}
