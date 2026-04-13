// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package netrunner provides integration tests for DEX VM with the network runner.
// These tests verify that DEX VM can be deployed and operated as a chain VM.
package netrunner

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/vm"
	"github.com/luxfi/runtime"
	"github.com/luxfi/constants"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/chains/dexvm"
	"github.com/luxfi/chains/dexvm/config"
	"github.com/luxfi/warp"
)

// TestDexVMID verifies that the DEX VM ID is correctly registered.
func TestDexVMID(t *testing.T) {
	require := require.New(t)

	// Verify DexVMID is set
	require.NotEqual(ids.Empty, constants.DexVMID, "DexVMID should not be empty")

	// Verify the VM name matches
	name := constants.VMName(constants.DexVMID)
	require.Equal("dexvm", name, "DexVMID should resolve to 'dexvm'")

	// Verify the ID bytes
	expectedID := ids.ID{'d', 'e', 'x', 'v', 'm'}
	require.Equal(expectedID, constants.DexVMID, "DexVMID bytes should match")
}

// TestDexVMFactory tests that the DEX VM factory creates valid VMs.
func TestDexVMFactory(t *testing.T) {
	require := require.New(t)

	factory := &dexvm.Factory{}
	vmImpl, err := factory.New(nil)
	require.NoError(err, "Factory.New should not fail")
	require.NotNil(vmImpl, "Factory.New should return a VM")
	require.IsType(&dexvm.ChainVM{}, vmImpl, "Factory.New should return a *dexvm.ChainVM")
}

// DEXGenesisConfig represents the genesis configuration for DEX VM.
type DEXGenesisConfig struct {
	BlockInterval     string            `json:"blockInterval"`
	MaxOrdersPerBlock int               `json:"maxOrdersPerBlock"`
	TradingPairs      []TradingPairSpec `json:"tradingPairs"`
	Fees              FeeConfig         `json:"fees"`
	Perpetuals        PerpetualsConfig  `json:"perpetuals"`
}

// TradingPairSpec defines a trading pair configuration.
type TradingPairSpec struct {
	Base         string `json:"base"`
	Quote        string `json:"quote"`
	MinOrderSize string `json:"minOrderSize"`
	TickSize     string `json:"tickSize"`
}

// FeeConfig defines fee settings.
type FeeConfig struct {
	MakerFee       string `json:"makerFee"`
	TakerFee       string `json:"takerFee"`
	LiquidationFee string `json:"liquidationFee"`
}

// PerpetualsConfig defines perpetuals settings.
type PerpetualsConfig struct {
	Enabled                bool   `json:"enabled"`
	MaxLeverage            int    `json:"maxLeverage"`
	FundingInterval        string `json:"fundingInterval"`
	MaintenanceMarginRatio string `json:"maintenanceMarginRatio"`
}

// TestDexVMGenesisFormat tests that DEX VM accepts valid genesis configurations.
func TestDexVMGenesisFormat(t *testing.T) {
	require := require.New(t)

	// Create a genesis configuration
	genesisConfig := DEXGenesisConfig{
		BlockInterval:     "1ms",
		MaxOrdersPerBlock: 10000,
		TradingPairs: []TradingPairSpec{
			{Base: "LUX", Quote: "USDT", MinOrderSize: "0.001", TickSize: "0.01"},
			{Base: "ETH", Quote: "USDT", MinOrderSize: "0.0001", TickSize: "0.01"},
			{Base: "BTC", Quote: "USDT", MinOrderSize: "0.00001", TickSize: "0.01"},
		},
		Fees: FeeConfig{
			MakerFee:       "0.001",
			TakerFee:       "0.002",
			LiquidationFee: "0.005",
		},
		Perpetuals: PerpetualsConfig{
			Enabled:                true,
			MaxLeverage:            100,
			FundingInterval:        "8h",
			MaintenanceMarginRatio: "0.01",
		},
	}

	// Serialize to JSON
	genesisBytes, err := json.Marshal(genesisConfig)
	require.NoError(err, "Genesis config should serialize to JSON")
	require.NotEmpty(genesisBytes, "Genesis bytes should not be empty")

	// Create VM and initialize with genesis
	logger := log.NewNoOpLogger()
	cfg := config.DefaultConfig()
	cfg.BlockInterval = time.Millisecond

	vmImpl := dexvm.NewVMForTest(cfg, logger)

	chainID := ids.GenerateTestID()
	db := memdb.New()
	toEngine := make(chan vm.Message, 100)
	appSender := warp.FakeSender{}

	rt := &runtime.Runtime{
		ChainID: chainID,
		Log:     logger,
	}

	err = vmImpl.Initialize(
		context.Background(),
		vm.Init{
			Runtime:  rt,
			DB:       db,
			ToEngine: toEngine,
			Sender:   appSender,
			Log:      logger,
			Genesis:  genesisBytes,
			Upgrade:  nil,
			Config:   nil,
			Fx:       nil,
		},
	)
	require.NoError(err, "VM should initialize with genesis config")

	// Clean up
	err = vmImpl.Shutdown(context.Background())
	require.NoError(err, "VM should shut down cleanly")
}

// TestDexVMNetworkSimulation simulates a multi-node DEX network.
func TestDexVMNetworkSimulation(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create 5 nodes like netrunner would
	nodeCount := 5
	vms := make([]*dexvm.VM, nodeCount)
	cleanups := make([]func(), nodeCount)

	logger := log.NewNoOpLogger()
	cfg := config.DefaultConfig()
	cfg.BlockInterval = time.Millisecond

	// Initialize all nodes with the same genesis
	genesisBytes := []byte(`{"blockInterval":"1ms","maxOrdersPerBlock":10000}`)

	for i := 0; i < nodeCount; i++ {
		vmImpl := dexvm.NewVMForTest(cfg, logger)
		chainID := ids.GenerateTestID()
		db := memdb.New()
		toEngine := make(chan vm.Message, 100)
		appSender := warp.FakeSender{}

		rt := &runtime.Runtime{
			ChainID: chainID,
			Log:     logger,
		}

		err := vmImpl.Initialize(
			ctx,
			vm.Init{
				Runtime:  rt,
				DB:       db,
				ToEngine: toEngine,
				Sender:   appSender,
				Log:      logger,
				Genesis:  genesisBytes,
				Upgrade:  nil,
				Config:   nil,
				Fx:       nil,
			},
		)
		require.NoError(err, "Node %d should initialize", i)

		err = vmImpl.SetState(ctx, uint32(vm.Ready))
		require.NoError(err, "Node %d should enter normal operation", i)

		vms[i] = vmImpl
		cleanups[i] = func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = vmImpl.Shutdown(ctx)
		}
	}

	// Ensure cleanup
	defer func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()

	// Create a test trading pair on all nodes
	symbol := "LUX/USDT"
	for i, vmImpl := range vms {
		ob := vmImpl.GetOrCreateOrderbook(symbol)
		require.NotNil(ob, "Node %d should create orderbook", i)
	}

	// Process blocks on all nodes (simulating consensus)
	blockHeight := uint64(0)
	for round := 0; round < 10; round++ {
		blockHeight++
		blockTime := time.Now()

		var stateRoots []ids.ID
		for i, vmImpl := range vms {
			result, err := vmImpl.ProcessBlock(ctx, blockHeight, blockTime, nil)
			require.NoError(err, "Node %d should process block %d", i, blockHeight)
			stateRoots = append(stateRoots, result.StateRoot)
		}

		// Verify all nodes have the same state root (consensus check)
		for i := 1; i < len(stateRoots); i++ {
			require.Equal(stateRoots[0], stateRoots[i],
				"Node %d state root should match node 0 at block %d", i, blockHeight)
		}
	}

	// Verify final state
	for i, vmImpl := range vms {
		currentHeight := vmImpl.GetBlockHeight()
		require.Equal(blockHeight, currentHeight, "Node %d block height should match", i)
	}
}

// TestDexVMChainDeploymentScenario tests the full chain deployment scenario.
func TestDexVMChainDeploymentScenario(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// This test simulates what netrunner does when deploying DEX VM as a chain:
	// 1. Creates a chain
	// 2. Deploys DEX VM blockchain on the chain
	// 3. All validators run the DEX VM
	// 4. Blocks are processed deterministically

	// Step 1: Simulate chain creation (done by P-Chain)
	chainID := ids.GenerateTestID()
	t.Logf("Simulated chain ID: %s", chainID)

	// Step 2: Simulate blockchain creation with DEX VM
	blockchainID := ids.GenerateTestID()
	t.Logf("Simulated blockchain ID: %s", blockchainID)

	// Step 3: Initialize DEX VM on 5 validators
	validators := make([]*dexvm.VM, 5)
	logger := log.NewNoOpLogger()
	cfg := config.DefaultConfig()
	cfg.BlockInterval = time.Millisecond

	genesisConfig := DEXGenesisConfig{
		BlockInterval:     "1ms",
		MaxOrdersPerBlock: 10000,
		TradingPairs: []TradingPairSpec{
			{Base: "LUX", Quote: "USDT", MinOrderSize: "0.001", TickSize: "0.01"},
		},
		Fees: FeeConfig{
			MakerFee: "0.001",
			TakerFee: "0.002",
		},
	}
	genesisBytes, _ := json.Marshal(genesisConfig)

	for i := 0; i < 5; i++ {
		vmImpl := dexvm.NewVMForTest(cfg, logger)
		db := memdb.New()
		toEngine := make(chan vm.Message, 100)

		rt := &runtime.Runtime{
			ChainID: blockchainID, // All validators use same chain ID
			Log:     logger,
		}

		err := vmImpl.Initialize(
			ctx,
			vm.Init{
				Runtime:  rt,
				DB:       db,
				ToEngine: toEngine,
				Sender:   warp.FakeSender{},
				Log:      logger,
				Genesis:  genesisBytes,
				Upgrade:  nil,
				Config:   nil,
				Fx:       nil,
			},
		)
		require.NoError(err)

		err = vmImpl.SetState(ctx, uint32(vm.Ready))
		require.NoError(err)

		validators[i] = vmImpl
	}

	defer func() {
		for _, vmImpl := range validators {
			_ = vmImpl.Shutdown(ctx)
		}
	}()

	// Step 4: Process blocks (simulating consensus engine)
	t.Log("Processing 100 blocks across 5 validators...")
	startTime := time.Now()

	for height := uint64(1); height <= 100; height++ {
		blockTime := time.Now()

		var results []*dexvm.BlockResult
		for _, vmImpl := range validators {
			result, err := vmImpl.ProcessBlock(ctx, height, blockTime, nil)
			require.NoError(err)
			results = append(results, result)
		}

		// Verify consensus: all validators should have same state
		for i := 1; i < len(results); i++ {
			require.Equal(results[0].StateRoot, results[i].StateRoot,
				"Validator %d state mismatch at height %d", i, height)
			require.Equal(results[0].BlockHeight, results[i].BlockHeight)
		}
	}

	elapsed := time.Since(startTime)
	blocksPerSec := 100.0 / elapsed.Seconds() * 5 // 5 validators
	t.Logf("Processed 100 blocks on 5 validators in %v (%.0f validator-blocks/sec)", elapsed, blocksPerSec)

	// Verify throughput is acceptable
	require.Greater(blocksPerSec, 100.0, "Should process at least 100 validator-blocks/sec")
}

// BenchmarkDexVMBlockProcessing benchmarks block processing for netrunner scenarios.
func BenchmarkDexVMBlockProcessing(b *testing.B) {
	ctx := context.Background()

	// Setup: Create 5 validators like netrunner would
	validators := make([]*dexvm.VM, 5)
	logger := log.NewNoOpLogger()
	cfg := config.DefaultConfig()
	cfg.BlockInterval = time.Millisecond

	for i := 0; i < 5; i++ {
		vmImpl := dexvm.NewVMForTest(cfg, logger)
		chainID := ids.GenerateTestID()
		db := memdb.New()
		toEngine := make(chan vm.Message, 100)

		rt := &runtime.Runtime{
			ChainID: chainID,
			Log:     logger,
		}

		_ = vmImpl.Initialize(ctx, vm.Init{
			Runtime:  rt,
			DB:       db,
			ToEngine: toEngine,
			Sender:   warp.FakeSender{},
			Log:      logger,
			Genesis:  nil,
			Upgrade:  nil,
			Config:   nil,
			Fx:       nil,
		})
		_ = vmImpl.SetState(ctx, uint32(vm.Ready))

		validators[i] = vmImpl
	}

	defer func() {
		for _, vmImpl := range validators {
			_ = vmImpl.Shutdown(ctx)
		}
	}()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		height := uint64(i + 1)
		blockTime := time.Now()

		for _, vmImpl := range validators {
			_, _ = vmImpl.ProcessBlock(ctx, height, blockTime, nil)
		}
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N*5), "validator-blocks")
}
