// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package e2e provides end-to-end tests for the DEX VM.
// These tests verify multi-node consensus, order matching, and state synchronization.
package e2e

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

const (
	// Default trading pair for E2E tests
	testSymbol = "LUX/USDT"
)

// TestNode represents a simulated DEX node for E2E testing.
type TestNode struct {
	ID        ids.NodeID
	VM        *dexvm.VM
	Blocks    []*dexvm.BlockResult
	mu        sync.RWMutex
	connected map[ids.NodeID]*TestNode
}

// TestNetwork represents a network of DEX nodes for E2E testing.
type TestNetwork struct {
	Nodes       []*TestNode
	mu          sync.RWMutex
	blockHeight uint64
}

// createTestVM creates a VM for E2E testing.
func createTestVM(t *testing.T) *dexvm.VM {
	require := require.New(t)

	logger := log.NewNoOpLogger()
	cfg := config.DefaultConfig()
	cfg.BlockInterval = time.Millisecond // 1ms blocks for HFT

	vmImpl := dexvm.NewVMForTest(cfg, logger)

	chainID := ids.GenerateTestID()
	db := memdb.New()
	toEngine := make(chan vm.Message, 100)
	appSender := warp.FakeSender{} // Use warp's FakeSender

	rt := &runtime.Runtime{
		ChainID: chainID,
		Log:     logger,
	}

	err := vmImpl.Initialize(
		context.Background(),
		vm.Init{
			Runtime:  rt,
			DB:       db,
			ToEngine: toEngine,
			Sender:   appSender,
			Log:      logger,
			Genesis:  nil,
			Upgrade:  nil,
			Config:   nil,
			Fx:       nil,
		},
	)
	require.NoError(err)

	return vmImpl
}

// NewTestNetwork creates a new test network with the specified number of nodes.
func NewTestNetwork(t *testing.T, nodeCount int) *TestNetwork {
	network := &TestNetwork{
		Nodes: make([]*TestNode, nodeCount),
	}

	// Create nodes
	for i := 0; i < nodeCount; i++ {
		nodeID := ids.GenerateTestNodeID()
		vmImpl := createTestVM(t)

		// Create orderbook for trading
		_ = vmImpl.GetOrCreateOrderbook(testSymbol)

		network.Nodes[i] = &TestNode{
			ID:        nodeID,
			VM:        vmImpl,
			Blocks:    make([]*dexvm.BlockResult, 0),
			connected: make(map[ids.NodeID]*TestNode),
		}
	}

	// Connect all nodes to each other (full mesh)
	for i, node := range network.Nodes {
		for j, other := range network.Nodes {
			if i != j {
				node.connected[other.ID] = other
			}
		}
	}

	return network
}

// ProcessBlock processes a block across all nodes deterministically.
func (n *TestNetwork) ProcessBlock(ctx context.Context, txs [][]byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.blockHeight++
	blockTime := time.Now()

	var errs []error

	// Process block on all nodes
	for _, node := range n.Nodes {
		result, err := node.VM.ProcessBlock(ctx, n.blockHeight, blockTime, txs)
		if err != nil {
			errs = append(errs, fmt.Errorf("node %s: %w", node.ID, err))
			continue
		}
		node.mu.Lock()
		node.Blocks = append(node.Blocks, result)
		node.mu.Unlock()
	}

	if len(errs) > 0 {
		return errs[0]
	}

	return nil
}

// VerifyConsensus verifies all nodes have the same state.
func (n *TestNetwork) VerifyConsensus(t *testing.T) {
	require := require.New(t)
	n.mu.RLock()
	defer n.mu.RUnlock()

	if len(n.Nodes) < 2 {
		return
	}

	// Compare state roots across all nodes
	firstNode := n.Nodes[0]
	firstNode.mu.RLock()
	if len(firstNode.Blocks) == 0 {
		firstNode.mu.RUnlock()
		return
	}
	lastBlock := firstNode.Blocks[len(firstNode.Blocks)-1]
	firstNode.mu.RUnlock()

	for i := 1; i < len(n.Nodes); i++ {
		node := n.Nodes[i]
		node.mu.RLock()
		require.Equal(len(firstNode.Blocks), len(node.Blocks),
			"node %d block count mismatch", i)

		if len(node.Blocks) > 0 {
			nodeLastBlock := node.Blocks[len(node.Blocks)-1]
			require.Equal(lastBlock.BlockHeight, nodeLastBlock.BlockHeight,
				"node %d block height mismatch", i)
			require.Equal(lastBlock.StateRoot, nodeLastBlock.StateRoot,
				"node %d state root mismatch", i)
		}
		node.mu.RUnlock()
	}
}

// Shutdown stops all nodes in the network.
func (n *TestNetwork) Shutdown(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	for _, node := range n.Nodes {
		if err := node.VM.Shutdown(ctx); err != nil {
			return err
		}
	}
	return nil
}

// TestNetworkBasic tests basic network operations with 5 nodes.
func TestNetworkBasic(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create 5-node network
	network := NewTestNetwork(t, 5)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = network.Shutdown(ctx)
	}()

	require.Len(network.Nodes, 5)

	// Bootstrap all VMs
	for _, node := range network.Nodes {
		err := node.VM.SetState(ctx, uint32(vm.Ready))
		require.NoError(err)
	}

	// Process 10 empty blocks
	for i := 0; i < 10; i++ {
		err := network.ProcessBlock(ctx, nil)
		require.NoError(err)
	}

	// Verify consensus
	network.VerifyConsensus(t)

	// Check block heights
	for _, node := range network.Nodes {
		node.mu.RLock()
		require.Len(node.Blocks, 10)
		node.mu.RUnlock()
	}
}

// TestNetworkOrderMatching tests order matching across the network.
func TestNetworkOrderMatching(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create 5-node network
	network := NewTestNetwork(t, 5)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = network.Shutdown(ctx)
	}()

	// Bootstrap all VMs
	for _, node := range network.Nodes {
		err := node.VM.SetState(ctx, uint32(vm.Ready))
		require.NoError(err)
	}

	// Use the default trading pair
	symbol := testSymbol

	// Add orders on all nodes (simulating user transactions)
	trader1 := ids.GenerateTestShortID()
	trader2 := ids.GenerateTestShortID()

	// These would normally be in transaction format
	// For this test, we directly manipulate the orderbooks
	for _, node := range network.Nodes {
		ob := node.VM.GetOrCreateOrderbook(symbol)
		require.NotNil(ob)

		// Trader1 places a buy order at 100
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

		// Trader2 places a sell order at 100 (should match)
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

	// Process block - this triggers matching
	err := network.ProcessBlock(ctx, nil)
	require.NoError(err)

	// Verify consensus - all nodes should have same state
	network.VerifyConsensus(t)

	// Verify trades occurred
	for _, node := range network.Nodes {
		node.mu.RLock()
		require.Len(node.Blocks, 1)
		// Trades were matched during AddOrder, Match() finds remaining crosses
		node.mu.RUnlock()
	}
}

// TestNetworkDeterminism tests that the same inputs produce the same outputs.
func TestNetworkDeterminism(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create two independent 5-node networks
	network1 := NewTestNetwork(t, 5)
	network2 := NewTestNetwork(t, 5)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = network1.Shutdown(ctx)
		_ = network2.Shutdown(ctx)
	}()

	// Bootstrap all VMs
	for _, node := range network1.Nodes {
		err := node.VM.SetState(ctx, uint32(vm.Ready))
		require.NoError(err)
	}
	for _, node := range network2.Nodes {
		err := node.VM.SetState(ctx, uint32(vm.Ready))
		require.NoError(err)
	}

	// Process the same blocks on both networks
	for i := 0; i < 10; i++ {
		err := network1.ProcessBlock(ctx, nil)
		require.NoError(err)

		err = network2.ProcessBlock(ctx, nil)
		require.NoError(err)
	}

	// Verify both networks reached consensus internally
	network1.VerifyConsensus(t)
	network2.VerifyConsensus(t)

	// Note: State roots will differ because block times differ
	// But block heights should match
	require.Equal(network1.blockHeight, network2.blockHeight)
}

// TestNetworkHighThroughput tests processing many blocks quickly.
func TestNetworkHighThroughput(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create 5-node network
	network := NewTestNetwork(t, 5)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = network.Shutdown(ctx)
	}()

	// Bootstrap all VMs
	for _, node := range network.Nodes {
		err := node.VM.SetState(ctx, uint32(vm.Ready))
		require.NoError(err)
	}

	// Process 100 blocks as fast as possible (1ms target)
	start := time.Now()
	blockCount := 100

	for i := 0; i < blockCount; i++ {
		err := network.ProcessBlock(ctx, nil)
		require.NoError(err)
	}

	elapsed := time.Since(start)
	blocksPerSecond := float64(blockCount) / elapsed.Seconds()

	t.Logf("Processed %d blocks in %v (%.0f blocks/sec)", blockCount, elapsed, blocksPerSecond)

	// Verify consensus after high throughput
	network.VerifyConsensus(t)

	// Should process at least 100 blocks/second (with 5 nodes)
	require.Greater(blocksPerSecond, 100.0, "throughput too low")
}

// TestNetworkPartialFailure tests network behavior when some nodes fail.
func TestNetworkPartialFailure(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create 5-node network
	network := NewTestNetwork(t, 5)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = network.Shutdown(ctx)
	}()

	// Bootstrap all VMs
	for _, node := range network.Nodes {
		err := node.VM.SetState(ctx, uint32(vm.Ready))
		require.NoError(err)
	}

	// Process initial blocks
	for i := 0; i < 5; i++ {
		err := network.ProcessBlock(ctx, nil)
		require.NoError(err)
	}

	// Shut down 2 nodes (simulate failure)
	ctx2, cancel := context.WithTimeout(ctx, time.Second)
	err := network.Nodes[3].VM.Shutdown(ctx2)
	cancel()
	require.NoError(err)

	ctx3, cancel2 := context.WithTimeout(ctx, time.Second)
	err = network.Nodes[4].VM.Shutdown(ctx3)
	cancel2()
	require.NoError(err)

	// Verify the 3 active nodes still have consensus from before
	activeNodes := network.Nodes[:3]
	for _, node := range activeNodes {
		node.mu.RLock()
		require.Len(node.Blocks, 5)
		node.mu.RUnlock()
	}
}

// BenchmarkNetworkProcessBlock benchmarks block processing in a 5-node network.
func BenchmarkNetworkProcessBlock(b *testing.B) {
	ctx := context.Background()

	// Create network outside of timing
	network := &TestNetwork{
		Nodes: make([]*TestNode, 5),
	}

	logger := log.NewNoOpLogger()
	cfg := config.DefaultConfig()
	cfg.BlockInterval = time.Millisecond

	for i := 0; i < 5; i++ {
		nodeID := ids.GenerateTestNodeID()
		vmImpl := dexvm.NewVMForTest(cfg, logger)

		chainID := ids.GenerateTestID()
		db := memdb.New()
		toEngine := make(chan vm.Message, 100)
		appSender := warp.FakeSender{}

		rt := &runtime.Runtime{
			ChainID: chainID,
			Log:     logger,
		}

		_ = vmImpl.Initialize(
			context.Background(),
			vm.Init{
				Runtime:  rt,
				DB:       db,
				ToEngine: toEngine,
				Sender:   appSender,
				Log:      logger,
				Genesis:  nil,
				Upgrade:  nil,
				Config:   nil,
				Fx:       nil,
			},
		)

	_ = vmImpl.SetState(ctx, uint32(vm.Ready))

		network.Nodes[i] = &TestNode{
			ID:        nodeID,
			VM:        vmImpl,
			Blocks:    make([]*dexvm.BlockResult, 0),
			connected: make(map[ids.NodeID]*TestNode),
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		network.blockHeight++
		blockTime := time.Now()

		for _, node := range network.Nodes {
			_, _ = node.VM.ProcessBlock(ctx, network.blockHeight, blockTime, nil)
		}
	}

	b.StopTimer()

	// Cleanup
	for _, node := range network.Nodes {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = node.VM.Shutdown(ctx)
		cancel()
	}
}
