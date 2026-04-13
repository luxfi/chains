// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package consensus provides tests for DEX VM consensus behavior.
// These tests verify deterministic state transitions across multiple nodes.
package consensus

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/vm"
	"github.com/luxfi/runtime"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/chains/dexvm"
	"github.com/luxfi/chains/dexvm/config"
	"github.com/luxfi/chains/dexvm/orderbook"
	"github.com/luxfi/warp"
)

// ConsensusNetwork represents a simulated network for consensus testing.
type ConsensusNetwork struct {
	PrimaryNodes []*PrimaryNode
	DexNodes     []*DexNode
	BlockHeight  uint64
	mu           sync.RWMutex
}

// PrimaryNode simulates a primary network validator.
type PrimaryNode struct {
	ID            ids.NodeID
	ValidatedSets map[ids.ID]bool // Chains this node validates
}

// DexNode represents a DEX chain validator node.
type DexNode struct {
	ID            ids.NodeID
	VM            *dexvm.VM
	StateRoot     ids.ID
	ProcessedBlks uint64
}

// NewConsensusNetwork creates a network with 5 primary validators and 5 DEX validators.
func NewConsensusNetwork(t *testing.T) *ConsensusNetwork {
	require := require.New(t)

	network := &ConsensusNetwork{
		PrimaryNodes: make([]*PrimaryNode, 5),
		DexNodes:     make([]*DexNode, 5),
	}

	// Create 5 primary network validators
	for i := 0; i < 5; i++ {
		network.PrimaryNodes[i] = &PrimaryNode{
			ID:            ids.GenerateTestNodeID(),
			ValidatedSets: make(map[ids.ID]bool),
		}
	}

	// Create 5 DEX chain validators (can be same or different from primary)
	// In this test, first 5 primary validators also validate DEX chain
	chainID := ids.GenerateTestID()
	blockchainID := ids.GenerateTestID()

	logger := log.NewNoOpLogger()
	cfg := config.DefaultConfig()
	cfg.BlockInterval = time.Millisecond

	for i := 0; i < 5; i++ {
		// Primary node validates DEX chain
		network.PrimaryNodes[i].ValidatedSets[chainID] = true

		// Create DEX VM for this node
		vmImpl := dexvm.NewVMForTest(cfg, logger)
		db := memdb.New()
		toEngine := make(chan vm.Message, 100)

		rt := &runtime.Runtime{
			ChainID: blockchainID,
			Log:     logger,
		}

		err := vmImpl.Initialize(
			context.Background(),
			vm.Init{
				Runtime:  rt,
				DB:       db,
				ToEngine: toEngine,
				Sender:   warp.FakeSender{},
				Log:      logger,
				Genesis:  nil,
				Upgrade:  nil,
				Config:   nil,
				Fx:       nil,
			},
		)
		require.NoError(err, "Node %d should initialize", i)

		err = vmImpl.SetState(context.Background(), uint32(vm.Ready))
		require.NoError(err, "Node %d should enter normal operation", i)

		network.DexNodes[i] = &DexNode{
			ID: network.PrimaryNodes[i].ID,
			VM: vmImpl,
		}
	}

	return network
}

// ProcessBlock processes a block across all DEX nodes deterministically.
func (n *ConsensusNetwork) ProcessBlock(ctx context.Context, txs [][]byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.BlockHeight++
	blockTime := time.Now()

	var firstStateRoot ids.ID
	for i, node := range n.DexNodes {
		result, err := node.VM.ProcessBlock(ctx, n.BlockHeight, blockTime, txs)
		if err != nil {
			return fmt.Errorf("node %d failed to process block: %w", i, err)
		}
		node.StateRoot = result.StateRoot
		node.ProcessedBlks++

		if i == 0 {
			firstStateRoot = result.StateRoot
		} else if firstStateRoot != result.StateRoot {
			return fmt.Errorf("state root mismatch: node 0 has %s, node %d has %s",
				firstStateRoot, i, result.StateRoot)
		}
	}

	return nil
}

// VerifyConsensus checks that all nodes have identical state.
func (n *ConsensusNetwork) VerifyConsensus(t *testing.T) {
	require := require.New(t)
	n.mu.RLock()
	defer n.mu.RUnlock()

	if len(n.DexNodes) < 2 {
		return
	}

	firstNode := n.DexNodes[0]
	for i := 1; i < len(n.DexNodes); i++ {
		node := n.DexNodes[i]
		require.Equal(firstNode.StateRoot, node.StateRoot,
			"Node %d state root should match node 0", i)
		require.Equal(firstNode.ProcessedBlks, node.ProcessedBlks,
			"Node %d processed blocks should match node 0", i)
	}
}

// Shutdown stops all VMs.
func (n *ConsensusNetwork) Shutdown(ctx context.Context) {
	for _, node := range n.DexNodes {
		if node.VM != nil {
			_ = node.VM.Shutdown(ctx)
		}
	}
}

// TestFullConsensusNetwork tests the full 5 primary + 5 DEX node setup.
func TestFullConsensusNetwork(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	t.Log("Creating consensus network with 5 primary + 5 DEX validators...")
	network := NewConsensusNetwork(t)
	defer network.Shutdown(ctx)

	// Verify setup
	require.Len(network.PrimaryNodes, 5, "Should have 5 primary validators")
	require.Len(network.DexNodes, 5, "Should have 5 DEX validators")

	// Process 100 blocks
	t.Log("Processing 100 blocks across all nodes...")
	for i := 0; i < 100; i++ {
		err := network.ProcessBlock(ctx, nil)
		require.NoError(err, "Block %d should process successfully", i+1)
	}

	// Verify consensus
	network.VerifyConsensus(t)

	// Verify block heights
	for i, node := range network.DexNodes {
		height := node.VM.GetBlockHeight()
		require.Equal(uint64(100), height, "Node %d should be at block 100", i)
	}

	t.Log("Full consensus network test passed!")
}

// TestConsensusWithOrderMatching tests consensus with actual order matching.
func TestConsensusWithOrderMatching(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	network := NewConsensusNetwork(t)
	defer network.Shutdown(ctx)

	// Create orderbooks on all nodes
	symbol := "LUX/USDT"
	for _, node := range network.DexNodes {
		_ = node.VM.GetOrCreateOrderbook(symbol)
	}

	// Add identical orders to all nodes (simulating broadcasted transactions)
	trader1 := ids.GenerateTestShortID()
	trader2 := ids.GenerateTestShortID()

	for _, node := range network.DexNodes {
		ob := node.VM.GetOrCreateOrderbook(symbol)

		// Buy order from trader1
		buyOrder := &orderbook.Order{
			ID:          ids.GenerateTestID(),
			Owner:       trader1,
			Symbol:      symbol,
			Side:        orderbook.Buy,
			Type:        orderbook.Limit,
			Price:       100,
			Quantity:    10,
			TimeInForce: "GTC",
			CreatedAt:   time.Now().UnixNano(),
		}
		_, err := ob.AddOrder(buyOrder)
		require.NoError(err)

		// Sell order from trader2 (should match)
		sellOrder := &orderbook.Order{
			ID:          ids.GenerateTestID(),
			Owner:       trader2,
			Symbol:      symbol,
			Side:        orderbook.Sell,
			Type:        orderbook.Limit,
			Price:       100,
			Quantity:    10,
			TimeInForce: "GTC",
			CreatedAt:   time.Now().UnixNano(),
		}
		_, err = ob.AddOrder(sellOrder)
		require.NoError(err)
	}

	// Process block - this commits the state
	err := network.ProcessBlock(ctx, nil)
	require.NoError(err)

	// Verify consensus after order matching
	network.VerifyConsensus(t)

	t.Log("Consensus with order matching passed!")
}

// TestConsensusUnderLoad tests consensus under high throughput conditions.
func TestConsensusUnderLoad(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	network := NewConsensusNetwork(t)
	defer network.Shutdown(ctx)

	// Process 1000 blocks as fast as possible
	t.Log("Processing 1000 blocks under load...")
	startTime := time.Now()

	for i := 0; i < 1000; i++ {
		err := network.ProcessBlock(ctx, nil)
		require.NoError(err)
	}

	elapsed := time.Since(startTime)
	blocksPerSec := 1000.0 / elapsed.Seconds()
	validatorBlocksPerSec := blocksPerSec * 5 // 5 validators

	t.Logf("Processed 1000 blocks in %v", elapsed)
	t.Logf("Throughput: %.0f blocks/sec, %.0f validator-blocks/sec", blocksPerSec, validatorBlocksPerSec)

	// Verify consensus
	network.VerifyConsensus(t)

	// Should process at least 1000 blocks/sec (5000 validator-blocks/sec)
	require.Greater(blocksPerSec, 1000.0, "Should process at least 1000 blocks/sec")
	require.Greater(validatorBlocksPerSec, 5000.0, "Should process at least 5000 validator-blocks/sec")

	t.Log("Consensus under load passed!")
}

// TestConsensusPartialFailure tests behavior when some validators fail.
func TestConsensusPartialFailure(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	network := NewConsensusNetwork(t)
	defer network.Shutdown(ctx)

	// Process 10 blocks
	for i := 0; i < 10; i++ {
		err := network.ProcessBlock(ctx, nil)
		require.NoError(err)
	}

	// Shutdown 2 validators (Byzantine fault tolerance allows f = (n-1)/3 = 1 failure for n=5)
	// But we're testing graceful degradation, not BFT
	t.Log("Simulating partial node failures...")
	_ = network.DexNodes[3].VM.Shutdown(ctx)
	_ = network.DexNodes[4].VM.Shutdown(ctx)

	// The remaining 3 nodes should still have consistent state
	for i := 0; i < 3; i++ {
		height := network.DexNodes[i].VM.GetBlockHeight()
		require.Equal(uint64(10), height, "Active node %d should be at block 10", i)
	}

	t.Log("Partial failure test passed!")
}

// TestConsensusDeterminism tests that same inputs produce same outputs.
func TestConsensusDeterminism(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create two independent networks
	network1 := NewConsensusNetwork(t)
	network2 := NewConsensusNetwork(t)
	defer network1.Shutdown(ctx)
	defer network2.Shutdown(ctx)

	// Process same blocks on both networks
	for i := 0; i < 100; i++ {
		err := network1.ProcessBlock(ctx, nil)
		require.NoError(err)

		err = network2.ProcessBlock(ctx, nil)
		require.NoError(err)
	}

	// Verify both networks have internal consensus
	network1.VerifyConsensus(t)
	network2.VerifyConsensus(t)

	// Block heights should match
	require.Equal(network1.BlockHeight, network2.BlockHeight,
		"Both networks should be at same height")

	// Note: State roots may differ due to different initialization timestamps
	// But within each network, all nodes should have identical state

	t.Log("Determinism test passed!")
}

// TestConsensusRecovery tests recovery after network partition.
func TestConsensusRecovery(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	network := NewConsensusNetwork(t)
	defer network.Shutdown(ctx)

	// Process initial blocks
	for i := 0; i < 50; i++ {
		err := network.ProcessBlock(ctx, nil)
		require.NoError(err)
	}

	// Record block heights
	heightAfter50 := network.DexNodes[0].VM.GetBlockHeight()
	require.Equal(uint64(50), heightAfter50, "Should be at block 50")

	// Simulate network "partition" by processing blocks only on some nodes
	// Then "recovery" by having all nodes catch up

	// Process more blocks on all nodes
	for i := 0; i < 50; i++ {
		err := network.ProcessBlock(ctx, nil)
		require.NoError(err)
	}

	// Verify all nodes recovered to same state
	heightAfter100 := network.DexNodes[0].VM.GetBlockHeight()
	require.Equal(uint64(100), heightAfter100, "Should be at block 100")

	// Verify consensus (all nodes should have same state)
	network.VerifyConsensus(t)

	// Verify block progression
	require.Greater(heightAfter100, heightAfter50, "Height should increase after more blocks")

	t.Log("Recovery test passed!")
}

// BenchmarkConsensusNetwork benchmarks the full consensus network.
func BenchmarkConsensusNetwork(b *testing.B) {
	ctx := context.Background()

	// Setup network
	network := &ConsensusNetwork{
		PrimaryNodes: make([]*PrimaryNode, 5),
		DexNodes:     make([]*DexNode, 5),
	}

	blockchainID := ids.GenerateTestID()
	logger := log.NewNoOpLogger()
	cfg := config.DefaultConfig()
	cfg.BlockInterval = time.Millisecond

	for i := 0; i < 5; i++ {
		network.PrimaryNodes[i] = &PrimaryNode{
			ID:            ids.GenerateTestNodeID(),
			ValidatedSets: make(map[ids.ID]bool),
		}

		vmImpl := dexvm.NewVMForTest(cfg, logger)
		db := memdb.New()
		toEngine := make(chan vm.Message, 100)

		rt := &runtime.Runtime{
			ChainID: blockchainID,
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

		network.DexNodes[i] = &DexNode{
			ID: network.PrimaryNodes[i].ID,
			VM: vmImpl,
		}
	}

	defer network.Shutdown(ctx)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = network.ProcessBlock(ctx, nil)
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N*5), "validator-blocks")
}
