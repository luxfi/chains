// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/vm"
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

	genesisBytes, err := json.Marshal(genesis)
	require.NoError(err)

	// Create config
	config := ZConfig{
		MaxTxPerBlock:  100,
		ProofCacheSize: 1000,
	}

	configBytes, err := json.Marshal(config)
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
	require.NotNil(vmImpl.root)
	require.NotNil(vmImpl.proofVerifier)
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
				testBind[:],      // chain binding
				make([]byte, 32), // nullifier
				make([]byte, 32), // output commitment
			},
		},
		Fee:    1000,
		Expiry: 1 << 20,
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
	genesisBytes, _ := json.Marshal(genesis)

	config := ZConfig{
		MaxTxPerBlock:  100,
		ProofCacheSize: 1000,
	}
	configBytes, _ := json.Marshal(config)

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
