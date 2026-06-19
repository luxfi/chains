// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"testing"

	"github.com/luxfi/chains/zkvm/precompiles"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// strict_pq_wiring_test.go proves Red's wiring task 1 deliverable (a):
// on a real Z-Chain (initialized via the production Factory -> VM ->
// Initialize path, NOT a hand-built ZConfig), the strict-PQ posture is
// active by default and BOTH switches it drives are set from the single
// config.StrictPQ field:
//
//	(1) the shielded-proof verifier is strict-PQ (refuses classical), and
//	(2) RegisterZKPrecompiles ran with strictPQ=true, so the classical
//	    Groth16 (0x80) / PLONK (0x81) verifiers are NOT registered
//	    (fail-closed by absence) and only STARK/FRI (0x82) exists.
//
// The Z-Chain is DEFINITIVELY strict-PQ: a genesis with no explicit
// ZConfig must yield a strict-PQ chain — the default is not permissive.

// newDefaultZKVM initializes a Z-Chain VM through the production Factory
// with genesis bytes that carry NO ZConfig, exercising the default-config
// path in Initialize.
func newDefaultZKVM(t *testing.T) *VM {
	t.Helper()
	logger := log.NewNoOpLogger()
	rt := &runtime.Runtime{
		ChainID:   ids.GenerateTestID(),
		NetworkID: 96369,
		Log:       logger,
	}

	// Build through the real Factory the node wires at vms.go (&zkvm.Factory{}).
	f := &Factory{}
	vmAny, err := f.New(logger)
	if err != nil {
		t.Fatalf("Factory.New: %v", err)
	}
	v, ok := vmAny.(*VM)
	if !ok {
		t.Fatalf("Factory.New returned %T, want *VM", vmAny)
	}

	if err := v.Initialize(context.Background(), vmcore.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  []byte(`{"timestamp":0}`), // no ZConfig ⇒ default-config path
	}); err != nil {
		t.Fatalf("init zkvm: %v", err)
	}
	return v
}

// TestZChain_DefaultIsStrictPQ proves the Z-Chain default profile is
// strict-PQ (deliverable a, the "factory/genesis sets StrictPQ" half).
func TestZChain_DefaultIsStrictPQ(t *testing.T) {
	v := newDefaultZKVM(t)
	if !v.StrictPQ() {
		t.Fatal("Z-Chain default config must be strict-PQ (StrictPQ==true)")
	}
	if v.config.ProofSystem != "stark" {
		t.Fatalf("Z-Chain default ProofSystem = %q, want \"stark\" (only system accepted under strict-PQ)", v.config.ProofSystem)
	}
}

// TestZChain_RegistersPrecompilesStrictPQ proves the SAME StrictPQ bit
// drove RegisterZKPrecompiles(strictPQ=true): the classical Groth16/PLONK
// verifiers are absent (fail-closed) while STARK/FRI and the always-
// fail-closed stubs are present (deliverable a, the "registers strictPQ=
// true" half).
func TestZChain_RegistersPrecompilesStrictPQ(t *testing.T) {
	v := newDefaultZKVM(t)
	reg := v.ZKPrecompiles()
	if reg == nil {
		t.Fatal("Z-Chain must register ZK precompiles at Initialize")
	}

	// Classical (quantum-breakable) verifiers MUST be absent on a strict-PQ
	// Z-Chain: a call to 0x80/0x81 hits "no precompile at address".
	for _, addr := range []byte{precompiles.Groth16VerifierAddr, precompiles.PLONKVerifierAddr} {
		if _, err := reg.Get(addr); err == nil {
			t.Fatalf("classical verifier 0x%02x must NOT be registered on a strict-PQ Z-Chain", addr)
		}
	}

	// The post-quantum STARK/FRI verifier + the always-fail-closed stubs
	// MUST be present on every chain.
	for _, addr := range []byte{precompiles.STARKVerifierAddr, precompiles.Halo2VerifierAddr, precompiles.NovaVerifierAddr} {
		if _, err := reg.Get(addr); err != nil {
			t.Fatalf("verifier 0x%02x must be registered on every chain, got: %v", addr, err)
		}
	}
}

// TestZChain_StrictPQ_ShieldedRefusesGroth16 is deliverable (c) at the VM
// level (also the empirical Red case): a groth16 shielded proof on the
// default (strict-PQ) Z-Chain is REFUSED with the strict-PQ error, before
// reaching any bn254 verification. The proof verifier is the one the VM
// actually constructed from its config — not a hand-built one.
func TestZChain_StrictPQ_ShieldedRefusesGroth16(t *testing.T) {
	v := newDefaultZKVM(t)
	tx := shieldedTx("groth16", make([]byte, 544))
	err := v.proofVerifier.VerifyTransactionProof(tx)
	if err == nil || err != errStrictPQClassicalForbidden {
		t.Fatalf("default Z-Chain must refuse a groth16 shielded proof with errStrictPQClassicalForbidden, got: %v", err)
	}
}

// TestZChain_ExplicitNonStrictGenesisOptsOut confirms a permissive
// deployment is still possible but MUST be explicit: a genesis ZConfig
// with StrictPQ=false yields a non-strict chain. This proves the wiring
// reads the profile bit (not a hardcode) — flipping the bit flips both
// switches in lockstep.
func TestZChain_ExplicitNonStrictGenesisOptsOut(t *testing.T) {
	// Build a ZConfig with StrictPQ=false and feed it as init.Config.
	cfg := ZConfig{
		EnableConfidentialTransfers: true,
		ProofSystem:                 "groth16",
		CircuitType:                 "transfer",
		StrictPQ:                    false,
		MaxUTXOsPerBlock:            100,
		ProofCacheSize:              1000,
	}
	cfgBytes, err := Codec.Marshal(0, &cfg)
	if err != nil {
		t.Fatalf("marshal ZConfig: %v", err)
	}

	logger := log.NewNoOpLogger()
	rt := &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: logger}
	v := &VM{}
	if err := v.Initialize(context.Background(), vmcore.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Config:   cfgBytes,
		Genesis:  []byte(`{"timestamp":0}`),
	}); err != nil {
		t.Fatalf("init zkvm (non-strict): %v", err)
	}

	if v.StrictPQ() {
		t.Fatal("explicit StrictPQ=false genesis must yield a non-strict chain")
	}
	// Both switches track the bit: classical verifiers ARE registered now.
	if _, err := v.ZKPrecompiles().Get(precompiles.Groth16VerifierAddr); err != nil {
		t.Fatalf("non-strict chain must register the classical Groth16 verifier, got: %v", err)
	}
}
