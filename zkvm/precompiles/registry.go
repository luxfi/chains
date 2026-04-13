// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package precompiles

import "fmt"

// PrecompileRegistry allows registering precompiled contracts at fixed addresses.
type PrecompileRegistry interface {
	Register(addr byte, contract PrecompiledContract)
}

// RegisterZKPrecompiles registers all Z-Chain ZK verifier precompiles.
func RegisterZKPrecompiles(registry PrecompileRegistry) {
	registry.Register(Groth16VerifierAddr, &Groth16Verifier{})
	registry.Register(PLONKVerifierAddr, &PLONKVerifier{})
	registry.Register(STARKVerifierAddr, &STARKVerifier{})
	registry.Register(Halo2VerifierAddr, &Halo2Verifier{})
	registry.Register(NovaVerifierAddr, &NovaVerifier{})
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
