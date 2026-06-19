// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Z-Chain MLDSAStark witness producer for Quasar parallel-witness
// finality (LP-020 §2 Consensus Modes, witness set bit WitnessZ).
//
// The Z-Chain VM is the parallel finality witness for the Z lane. Each
// consensus round, the Quasar driver pushes a 32-byte round digest plus
// the canonical validator ML-DSA-65 public-key list (rooted in
// pchain_validator_root) to this adapter. The adapter collects per-
// validator ML-DSA-65 signatures over the digest and produces a single
// post-quantum STARK / FRI proof attesting:
//
//	∀ i ∈ [N]: ML-DSA.Verify(pk_i, digest, σ_i) = 1
//
// The proof is a strict-PQ STARK (a Plonky3 fork: cSHAKE256 Merkle
// commitments over the Goldilocks 64-bit prime field, FRI low-degree
// test — NO KZG, NO pairings, NO trusted setup). It is verified on-chain
// by the STARK verifier (chains/zkvm/precompiles/zk_verifiers.go
// STARKVerifier, which delegates to precompile/starkfri), NOT by the
// pairing-based Groth16 precompile. This keeps the Z-lane witness
// quantum-safe: a quantum adversary that breaks bn254 cannot forge the
// aggregation proof, whose soundness rests only on cSHAKE256 collision
// resistance and the Reed–Solomon proximity gap.
//
// PROVER STATUS — NOT YET WIRED (the honest remaining step).
// ----------------------------------------------------------
// Producing real witnesses requires:
//
//	(1) the MLDSA-rollup AIR/circuit: an arithmetization of
//	    "∀ i: ML-DSA.Verify(pk_i, digest, σ_i) = 1" over the Goldilocks
//	    field. This circuit does NOT exist in ~/work/lux/p3q today
//	    (the p3q-zchain crate has DKG / committee / rotation logic but
//	    no validator-signature-aggregation AIR), and
//	(2) a prover C ABI: the p3q workspace exposes a Rust-level prover
//	    (p3q-stark::Prover trait, p3q-fri), but its C ABI (p3q-c-abi)
//	    exports ONLY `p3q_verify` — there is NO `p3q_prove` entry point
//	    for the Go consensus layer to invoke over cgo.
//
// Until both land, Witness returns ErrZWitnessNotImplemented and the
// round driver finalizes at the next-lower witness level (PolicyQuorum
// or PolicyPQ). The VERIFIER side and the proof-type plumbing are
// already STARK/FRI (see STARKVerifier); only the prover binding is
// outstanding. We intentionally do NOT fake a prover: emitting bytes
// that "look like" a proof but carry no soundness would be a forgery
// oracle on the finality path. See LP-020 §6 and
// proofs/quasar-cert-soundness.tex App. B for the AIR constraint-count
// and prover-cost analysis.
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

// ZWitnessAdapter adapts the Z-Chain MLDSAStark prover to the consensus
// ZWitnessProducer interface used by the Quasar round driver.
//
// TODO(pqz-circuit): implement the MLDSAStark rollup AIR (Goldilocks)
// and add a `p3q_prove` C ABI to ~/work/lux/p3q, then integrate the
// prover here. Until then Witness returns ErrZWitnessNotImplemented and
// the round driver finalizes at the next lower witness level
// (PolicyQuorum or PolicyPQ). The verifier side is already STARK/FRI.
type ZWitnessAdapter struct {
	vm *VM
}

// NewZWitnessAdapter constructs a Z-witness adapter backed by the given
// Z-Chain VM.
func NewZWitnessAdapter(vm *VM) *ZWitnessAdapter {
	return &ZWitnessAdapter{vm: vm}
}

// ErrZWitnessNotImplemented is returned by ZWitnessAdapter.Witness until
// the MLDSAStark rollup AIR and the p3q prover C ABI ship. The verifier
// side (STARKVerifier → precompile/starkfri) is already wired; this is
// the prover-binding gap only.
var ErrZWitnessNotImplemented = errors.New("Z-Chain MLDSAStark prover not implemented: needs the MLDSA-rollup AIR + a p3q_prove C ABI (LP-020 §6, paper App. B)")

// Witness produces a post-quantum STARK / FRI proof aggregating per-
// validator ML-DSA-65 signatures over the round digest. Signature
// matches consensus/protocol/quasar.ZWitnessProducer.
//
// validatorMLDSAPubs is the canonical ML-DSA-65 public-key list rooted in
// pchain_validator_root for the round; the STARK circuit takes this list
// as a public input.
//
// Returns ErrZWitnessNotImplemented today (prover binding outstanding —
// see the package comment); the round driver treats this as the witness
// being unavailable and finalizes at the next-lower witness level. We do
// NOT return fabricated proof bytes: an unsound "proof" on the finality
// path would be a forgery oracle.
func (a *ZWitnessAdapter) Witness(ctx context.Context, digest [32]byte, validatorMLDSAPubs [][]byte) ([]byte, error) {
	_ = ctx
	_ = digest
	_ = validatorMLDSAPubs
	if a.vm == nil {
		return nil, ErrZWitnessNotImplemented
	}
	return nil, ErrZWitnessNotImplemented
}
