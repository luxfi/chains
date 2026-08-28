// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/internal/bridgeattest"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// The harness builds a VM the way the node does — through Initialize — and
// transfers the way a source chain does — id equal to the digest of the
// contents. A rig that hands each node a different chain id, or names a
// request something other than its transfer, cannot see the defects those two
// rules exist to stop.

const (
	srcChain uint32 = 96368  // Lux testnet C
	dstChain uint32 = 200201 // Zoo
)

// testChainID is ONE value, shared by every VM a test builds, because a
// running network is one chain. A rig that generated a fresh chain id per node
// would make every cross-node block mismatch look like correct behaviour.
var testChainID = ids.ID{'b', '-', 'c', 'h', 'a', 'i', 'n', '-', 't', 'e', 's', 't'}

func testConfig() BridgeConfig {
	return BridgeConfig{
		MinConfirmations:     12,
		MaxBridgeAmount:      1_000_000,
		DailyBridgeLimit:     10_000_000,
		RequireValidatorBond: minValidatorBond,
		MaxSigners:           100,
		ExternalChains: []ExternalChainConfig{
			{Name: "lux-testnet-c", ChainID: uint64(srcChain), Gateway: "0x0000000000000000000000000000000000000001"},
			{Name: "zoo-testnet", ChainID: uint64(dstChain), Gateway: "0x0000000000000000000000000000000000000002"},
		},
	}
}

// refusingDB is a real database whose flush to disk can be made to fail. That
// is how a block fails in the field: the writes are complete and staged, and
// making them durable is what does not happen.
type refusingDB struct {
	database.Database
	refuse bool
}

func (d *refusingDB) NewBatch() database.Batch {
	return &refusingBatch{Batch: d.Database.NewBatch(), db: d}
}

type refusingBatch struct {
	database.Batch
	db *refusingDB
}

var errRefused = errors.New("flush refused")

func (b *refusingBatch) Write() error {
	if b.db.refuse {
		return errRefused
	}
	return b.Batch.Write()
}

// initFor is what the node hands Initialize.
func initFor(db database.Database, cfg BridgeConfig) vmcore.Init {
	raw, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	return vmcore.Init{
		Runtime: &runtime.Runtime{
			Log:       log.NewNoOpLogger(),
			NetworkID: 96369,
			ChainID:   testChainID,
			NodeID:    ids.GenerateTestNodeID(),
		},
		DB:      db,
		Genesis: []byte(`{"timestamp":1000000}`),
		Config:  raw,
	}
}

// bootOn brings a VM up over db exactly as the node does, with cfg as its
// configuration.
func bootOn(t *testing.T, db database.Database, cfg BridgeConfig) *VM {
	t.Helper()
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), initFor(db, cfg)))
	return vm
}

// boot is a VM on a fresh database with the standard configuration.
func boot(t *testing.T) *VM {
	t.Helper()
	return bootOn(t, memdb.New(), testConfig())
}

// bootRefusing is a VM whose database can be told to refuse a flush.
func bootRefusing(t *testing.T) (*VM, *refusingDB) {
	t.Helper()
	db := &refusingDB{Database: memdb.New()}
	return bootOn(t, db, testConfig()), db
}

// transferFor is one locked transfer. The request's id is the digest of its
// contents, which is what a source chain's gateway emits and what the chain
// requires.
func transferFor(nonce, amount uint64) bridgeattest.BridgeTransfer {
	bt := bridgeattest.BridgeTransfer{
		SrcChainID: srcChain,
		DstChainID: dstChain,
		Amount:     amount,
		Nonce:      nonce,
	}
	bt.Asset[31] = 1
	bt.Recipient[19] = 9
	return bt
}

// requestFor is the request a watcher builds from that transfer.
func requestFor(nonce, amount uint64) *BridgeRequest {
	bt := transferFor(nonce, amount)
	req := &BridgeRequest{
		ID:         ids.ID(bt.Digest()),
		SrcChainID: bt.SrcChainID,
		DstChainID: bt.DstChainID,
		Nonce:      bt.Nonce,
		Asset:      ids.ID(bt.Asset),
		Amount:     bt.Amount,
		Recipient:  append([]byte(nil), bt.Recipient[:]...),
	}
	req.SourceTxID[0] = byte(nonce)
	return req
}

// pend puts transfers in the set waiting for a block, as the watcher would.
func pend(vm *VM, reqs ...*BridgeRequest) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	for _, req := range reqs {
		vm.pendingBridges[req.ID] = req
	}
}

// buildAndAccept runs one block through the whole path a block takes: built,
// verified, accepted. Calling the store directly instead would skip the very
// checks Verify and Accept exist to make.
func buildAndAccept(t *testing.T, vm *VM) *Block {
	t.Helper()
	blk := build(t, vm)
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))
	return blk
}

func build(t *testing.T, vm *VM) *Block {
	t.Helper()
	built, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	return built.(*Block)
}

// watcherOn is a watcher wired to one source chain, without the goroutine.
func watcherOn(vm *VM, src ChainClient) *watcher {
	vm.mu.Lock()
	vm.evmByChainID[srcChain] = src
	vm.mu.Unlock()
	return &watcher{vm: vm, cursor: make(map[uint32]uint64), quit: make(chan struct{})}
}
