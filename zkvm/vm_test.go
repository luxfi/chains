// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/vm"
	"github.com/luxfi/runtime"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

func TestVMInitialize(t *testing.T) {
	require := require.New(t)

	// Create test context
	ctx := context.Background()
	chainRuntime := &runtime.Runtime{
		ChainID: ids.GenerateTestID(),
		Log:     log.NoLog{},
	}

	// Create test database
	db := memdb.New()

	// Create genesis
	genesis := &Genesis{
		Timestamp: 1607144400,
		InitialTxs: []*Transaction{
			{
				Type: TransactionTypeMint,
				Outputs: []*ShieldedOutput{
					{
						Commitment:      make([]byte, 32),
						EncryptedNote:   make([]byte, 256),
						EphemeralPubKey: make([]byte, 32),
						OutputProof:     make([]byte, 128),
					},
				},
				Proof: &ZKProof{
					ProofType:    "groth16",
					ProofData:    make([]byte, 256),
					PublicInputs: [][]byte{make([]byte, 32)},
				},
			},
		},
	}

	genesisBytes, err := Codec.Marshal(codecVersion, genesis)
	require.NoError(err)

	// Create config
	config := ZConfig{
		EnableConfidentialTransfers: true,
		EnablePrivateAddresses:      true,
		ProofSystem:                 "groth16",
		CircuitType:                 "transfer",
		EnableFHE:                   false,
		MaxUTXOsPerBlock:            100,
		ProofCacheSize:              1000,
	}

	configBytes, err := Codec.Marshal(codecVersion, config)
	require.NoError(err)

	// Create VM
	vmImpl := &VM{}

	// Initialize VM
	toEngine := make(chan vm.Message, 1)
	require.NoError(vmImpl.Initialize(ctx, vm.Init{
		Runtime:  chainRuntime,
		DB:       db,
		Genesis:  genesisBytes,
		Config:   configBytes,
		ToEngine: toEngine,
	}))

	// Verify initialization
	require.NotNil(vmImpl.utxoDB)
	require.NotNil(vmImpl.nullifierDB)
	require.NotNil(vmImpl.stateTree)
	require.NotNil(vmImpl.proofVerifier)
	require.NotNil(vmImpl.addressManager)
	require.NotNil(vmImpl.mempool)

	// Test health check
	health, err := vmImpl.HealthCheck(ctx)
	require.NoError(err)
	require.NotNil(health)

	// Shutdown
	require.NoError(vmImpl.Shutdown(ctx))
}

func TestShieldedTransaction(t *testing.T) {
	require := require.New(t)

	// Setup VM
	vmImpl := setupTestVM(t)
	defer vmImpl.Shutdown(context.Background())

	// Create a shielded transaction
	tx := &Transaction{
		Type:    TransactionTypeTransfer,
		Version: 1,
		Nullifiers: [][]byte{
			make([]byte, 32), // dummy nullifier
		},
		Outputs: []*ShieldedOutput{
			{
				Commitment:      make([]byte, 32),
				EncryptedNote:   make([]byte, 256),
				EphemeralPubKey: make([]byte, 32),
				OutputProof:     make([]byte, 128),
			},
		},
		Proof: &ZKProof{
			ProofType: "groth16",
			ProofData: make([]byte, 256),
			PublicInputs: [][]byte{
				make([]byte, 32), // nullifier
				make([]byte, 32), // output commitment
			},
		},
		Fee:    1000,
		Expiry: 0,
	}

	// Compute transaction ID
	tx.ID = tx.ComputeID()

	// Validate transaction
	require.NoError(tx.ValidateBasic())

	// Add to mempool
	require.NoError(vmImpl.mempool.AddTransaction(tx))

	// Verify in mempool
	require.True(vmImpl.mempool.HasTransaction(tx.ID))
	require.Equal(1, vmImpl.mempool.Size())
}

func TestPrivateAddress(t *testing.T) {
	require := require.New(t)

	// Setup VM with privacy enabled
	vmImpl := setupTestVMWithPrivacy(t)
	defer vmImpl.Shutdown(context.Background())

	// Generate a private address
	addr, err := vmImpl.addressManager.GenerateAddress()
	require.NoError(err)
	require.NotNil(addr)

	// Verify address components
	require.Len(addr.Address, 32)
	require.Len(addr.ViewingKey, 32)
	require.Len(addr.SpendingKey, 32)
	require.Len(addr.Diversifier, 11)
	require.Len(addr.IncomingViewKey, 32)

	// Test address retrieval
	retrieved, err := vmImpl.addressManager.GetAddress(addr.Address)
	require.NoError(err)
	require.Equal(addr.Address, retrieved.Address)
}

// Helper functions

func setupTestVM(t *testing.T) *VM {
	ctx := context.Background()
	chainRuntime := &runtime.Runtime{
		ChainID: ids.GenerateTestID(),
		Log:     log.NoLog{},
	}

	db := memdb.New()

	genesis := &Genesis{
		Timestamp:  1607144400,
		InitialTxs: []*Transaction{},
	}
	genesisBytes, _ := Codec.Marshal(codecVersion, genesis)

	config := ZConfig{
		ProofSystem:      "groth16",
		MaxUTXOsPerBlock: 100,
		ProofCacheSize:   1000,
	}
	configBytes, _ := Codec.Marshal(codecVersion, config)

	vmImpl := &VM{}
	toEngine := make(chan vm.Message, 1)

	require.NoError(t, vmImpl.Initialize(ctx, vm.Init{
		Runtime:  chainRuntime,
		DB:       db,
		Genesis:  genesisBytes,
		Config:   configBytes,
		ToEngine: toEngine,
	}))

	return vmImpl
}

func setupTestVMWithPrivacy(t *testing.T) *VM {
	ctx := context.Background()
	chainRuntime := &runtime.Runtime{
		ChainID: ids.GenerateTestID(),
		Log:     log.NoLog{},
	}

	db := memdb.New()

	genesis := &Genesis{
		Timestamp:  1607144400,
		InitialTxs: []*Transaction{},
	}
	genesisBytes, _ := Codec.Marshal(codecVersion, genesis)

	config := ZConfig{
		EnablePrivateAddresses: true,
		ProofSystem:            "groth16",
		MaxUTXOsPerBlock:       100,
		ProofCacheSize:         1000,
	}
	configBytes, _ := Codec.Marshal(codecVersion, config)

	vmImpl := &VM{}
	toEngine := make(chan vm.Message, 1)

	require.NoError(t, vmImpl.Initialize(ctx, vm.Init{
		Runtime:  chainRuntime,
		DB:       db,
		Genesis:  genesisBytes,
		Config:   configBytes,
		ToEngine: toEngine,
	}))

	return vmImpl
}
