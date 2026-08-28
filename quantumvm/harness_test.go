// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	luxvm "github.com/luxfi/vm"
	"github.com/stretchr/testify/require"
)

// chainTime is the fixed wall clock every test VM starts at. Fixed rather than
// real so a block's timestamp is something the test states, not something the
// machine happens to have.
var chainTime = time.Unix(1_700_000_000, 0).UTC()

// testNetwork and testChain are the SAME on every VM a test boots, because that
// is the production shape: one chain, many nodes. Giving each test VM its own
// chain id varied the wrong field — every per-node value derived from the chain
// then differed by accident, and a bug that gave all nodes ONE identity could
// not be seen, because the test's chain ids were all different anyway.
const testNetwork uint32 = 96369

var (
	testChain      = ids.ID{'q', 'c', 'h', 'a', 'i', 'n'}
	otherChain     = ids.ID{'o', 't', 'h', 'e', 'r'}
	otherNetworkID = testNetwork + 1
)

// bootVM starts a VM the way the node does — through Initialize, over a real
// store — and returns it with the base store, so a test can reopen the same
// bytes and see what actually survived.
func bootVM(t *testing.T, cfg config.Config) (*VM, database.Database) {
	t.Helper()
	db := memdb.New()
	return bootVMOn(t, cfg, db), db
}

func bootVMOn(t *testing.T, cfg config.Config, db database.Database) *VM {
	t.Helper()
	return bootVMAs(t, cfg, db, testNetwork, testChain)
}

// bootVMAs starts a VM on a named network and chain. Every node gets its own
// NodeID and they share the chain, which is the only combination production
// ever has.
func bootVMAs(t *testing.T, cfg config.Config, db database.Database, networkID uint32, chainID ids.ID) *VM {
	t.Helper()
	vm := &VM{Config: cfg}
	err := vm.Initialize(context.Background(), luxvm.Init{
		DB:  db,
		Log: log.NewNoOpLogger(),
		Runtime: &runtime.Runtime{
			NetworkID: networkID,
			ChainID:   chainID,
			NodeID:    ids.GenerateTestNodeID(),
		},
		Genesis: []byte("q-chain genesis"),
	})
	require.NoError(t, err)
	vm.clock.Set(chainTime)
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	return vm
}

// quietVM has quantum stamping off, which makes a transaction's admission a
// matter of the pool alone. Tests about block structure use it so a signature
// expiring mid-test cannot turn a structural failure into a crypto one.
func quietConfig() config.Config {
	cfg := config.DefaultConfig()
	cfg.QuantumStampEnabled = false
	cfg.CoronaEnabled = false
	return cfg
}

// tipOf is the last accepted block id, which a test may always read.
func tipOf(t *testing.T, vm *VM) ids.ID {
	t.Helper()
	id, err := vm.tip()
	require.NoError(t, err)
	return id
}

// heightOf is the tip height, which a test may always read.
func heightOf(t *testing.T, vm *VM) uint64 {
	t.Helper()
	h, err := vm.tipHeight()
	require.NoError(t, err)
	return h
}

// signedTx is a transaction carrying a genuine ML-DSA signature over its own
// wire, produced by the VM's own signer — the shape ProcessBatch expects.
func signedTx(t *testing.T, vm *VM, nonce uint64, data string) *BaseTransaction {
	t.Helper()
	tx := &BaseTransaction{timestamp: chainTime, nonce: nonce, data: []byte(data)}
	key, err := vm.quantumSigner.GenerateCoronaKey()
	require.NoError(t, err)
	sig, err := vm.quantumSigner.Sign(tx.Bytes(), key)
	require.NoError(t, err)
	tx.quantumSignature = sig
	return tx
}

// stampedTx carries a signature that is present but meaningless. Enough to get
// past the pool's admission check, never enough to pass verification.
func stampedTx(nonce uint64, data string) *BaseTransaction {
	return &BaseTransaction{
		timestamp:        chainTime,
		nonce:            nonce,
		data:             []byte(data),
		quantumSignature: &quantum.QuantumSignature{Signature: []byte{1}, QuantumStamp: []byte{1}},
	}
}

// blockOn assembles a block on a parent without going through the builder, so a
// test can state a field the builder would never produce.
func blockOn(vm *VM, parent *Block, txs ...Transaction) *Block {
	blk := &Block{
		timestamp:    parent.timestamp,
		height:       parent.height + 1,
		parentID:     parent.id,
		chainID:      vm.blockchainID,
		networkID:    vm.NetworkID,
		transactions: txs,
		vm:           vm,
	}
	blk.id = blk.computeID()
	return blk
}

// buildWith pools one transaction and builds the next block from it.
func buildWith(t *testing.T, vm *VM, tx Transaction) *Block {
	t.Helper()
	require.NoError(t, vm.txPool.AddTransaction(tx))
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	return blk.(*Block)
}

// nonce hands out a distinct transaction nonce per call, so two blocks built in
// one test never carry the same transaction — the pool refuses a duplicate, and
// a test that hit that would be measuring the pool rather than what it meant to.
var nonce atomic.Uint64

// buildOn produces the next block on the tip with one transaction in it.
func buildOn(t *testing.T, vm *VM) *Block {
	t.Helper()
	return buildWith(t, vm, stampedTx(nonce.Add(1), "op"))
}

// advance builds, verifies and accepts n blocks, returning the last.
func advance(t *testing.T, vm *VM, n int) *Block {
	t.Helper()
	var last *Block
	for i := 0; i < n; i++ {
		last = buildOn(t, vm)
		require.NoError(t, last.Verify(context.Background()))
		require.NoError(t, last.Accept(context.Background()))
	}
	return last
}

// advanceSigned is advance for a VM with quantum stamping ON, where a
// transaction has to carry a signature that actually checks out.
func advanceSigned(t *testing.T, vm *VM, n int) *Block {
	t.Helper()
	var last *Block
	for i := 0; i < n; i++ {
		last = buildWith(t, vm, signedTx(t, vm, nonce.Add(1), "op"))
		require.NoError(t, last.Verify(context.Background()))
		require.NoError(t, last.Accept(context.Background()))
	}
	return last
}
