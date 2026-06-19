// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package precompiles

import "fmt"

// PrecompileRegistry allows registering precompiled contracts at fixed addresses.
type PrecompileRegistry interface {
	Register(addr byte, contract PrecompiledContract)
}

// RegisterZKPrecompiles registers the Z-Chain ZK verifier precompiles.
//
// strictPQ gates the classical (quantum-breakable) verifiers. The
// PrecompiledContract.Run([]byte) interface carries no AccessibleState,
// so a strict-PQ chain cannot refuse at call time the way the
// AccessibleState-aware precompile/zk path does (RefuseUnderStrictPQ).
// Instead the decision is made HERE, at genesis registration: on a
// strict-PQ chain the classical Groth16 (0x80) and PLONK (0x81)
// verifiers are simply NOT REGISTERED, so any call to those addresses
// hits "no precompile at address" — fail-closed by absence. The
// post-quantum STARK/FRI verifier (0x82) is the only accepted proof
// system. Halo2 (0x83) and Nova (0x84) are stubs that already
// fail-closed (errNotImplemented) on every chain.
//
// On a non-strict chain every verifier is registered: Groth16/PLONK are
// kept as an OPTIONAL building block for cross-chain verification of
// classical proofs, never deleted.
func RegisterZKPrecompiles(registry PrecompileRegistry, strictPQ bool) {
	// Post-quantum + always-fail-closed stubs: registered on every chain.
	registry.Register(STARKVerifierAddr, &STARKVerifier{})
	registry.Register(Halo2VerifierAddr, &Halo2Verifier{})
	registry.Register(NovaVerifierAddr, &NovaVerifier{})

	if strictPQ {
		// Classical pairing-based verifiers are forbidden on strict-PQ
		// chains: omit them so 0x80/0x81 resolve to "no precompile".
		return
	}

	// Non-strict chain: classical verifiers available as an optional
	// (quantum-breakable) building block.
	registry.Register(Groth16VerifierAddr, &Groth16Verifier{})
	registry.Register(PLONKVerifierAddr, &PLONKVerifier{})
}

// MapRegistry is a simple map-based precompile registry for testing.
type MapRegistry struct {
	contracts map[byte]PrecompiledContract
}

func NewMapRegistry() *MapRegistry {
	return &MapRegistry{contracts: make(map[byte]PrecompiledContract)}
}

func (r *MapRegistry) Register(addr byte, contract PrecompiledContract) {
	r.contracts[addr] = contract
}

func (r *MapRegistry) Get(addr byte) (PrecompiledContract, error) {
	c, ok := r.contracts[addr]
	if !ok {
		return nil, fmt.Errorf("no precompile at address 0x%02x", addr)
	}
	return c, nil
}
