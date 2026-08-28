// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
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
	vm := &VM{Config: cfg}
	err := vm.Initialize(context.Background(), luxvm.Init{
		DB:  db,
		Log: log.NewNoOpLogger(),
		Runtime: &runtime.Runtime{
			NetworkID: 96369,
			ChainID:   ids.GenerateTestID(),
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

// buildOn produces the next block on the tip with one transaction in it.
func buildOn(t *testing.T, vm *VM) *Block {
	t.Helper()
	require.NoError(t, vm.txPool.AddTransaction(stampedTx(uint64(vm.getHeight()+1), "op")))
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	return blk.(*Block)
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
