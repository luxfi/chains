// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

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

// vmWithTransfer builds a bridge VM holding one ready transfer, over a
// database whose flush can be refused, with a release worker whose queue is
// only a channel so the test can see what was handed to it.
func vmWithTransfer(t *testing.T) (*VM, *refusingDB, *BridgeRequest) {
	t.Helper()

	db := &refusingDB{Database: memdb.New()}
	vm := &VM{
		log:            log.NewNoOpLogger(),
		config:         BridgeConfig{MinConfirmations: 1, MaxBridgeAmount: 1 << 40, DailyBridgeLimit: 1 << 40},
		pendingBridges: make(map[ids.ID]*BridgeRequest, 1),
		bridgeRegistry: &BridgeRegistry{
			CompletedBridges: make(map[ids.ID]*CompletedBridge),
			DailyVolume:      make(map[string]uint64),
		},
	}
	vm.chain = chain.New[*Block](db, nil)
	vm.releaser = &releaser{vm: vm, queue: make(chan *BridgeRequest, 8), quit: make(chan struct{})}

	genesis := &Block{BridgeRequests: []*BridgeRequest{}, vm: vm}
	genesis.ID_ = genesis.computeID()
	vm.genesisBlock = genesis
	_, _, err := vm.chain.Open(genesis, vm.parseBlock)
	require.NoError(t, err)

	req := &BridgeRequest{
		ID:            ids.GenerateTestID(),
		SourceChain:   "C",
		DestChain:     "eth",
		Amount:        7,
		Recipient:     make([]byte, 20),
		Confirmations: 12,
		Status:        "pending",
		CreatedAt:     time.Unix(0, 0),
	}
	vm.pendingBridges[req.ID] = req
	return vm, db, req
}

// TestABlockThatCannotCommitReleasesNothing is the defect this chain had.
// Accept credited the daily volume, completed the request, advanced
// lastAcceptedID and handed the transfer to the release worker — which
// broadcasts on an external chain — and only then wrote the block. A write
// that failed left all of it done, including a release in flight for a
// transfer no block records. lastAcceptedID was never written at all, so the
// tip reset to genesis on restart and the daily limit reset with it.
func TestABlockThatCannotCommitReleasesNothing(t *testing.T) {
	vm, db, req := vmWithTransfer(t)

	built, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := built.(*Block)

	tipBefore, heightBefore := vm.chain.Tip()

	db.refuse = true
	require.ErrorIs(t, blk.Accept(context.Background()), errRefused)

	// The irreversible part: nothing was handed to the release worker.
	require.Empty(t, vm.releaser.queue,
		"an external release must not start for a block that did not commit")

	// Nor did any of the reversible part happen.
	vm.bridgeRegistry.mu.RLock()
	completed := len(vm.bridgeRegistry.CompletedBridges)
	volume := vm.bridgeRegistry.DailyVolume["eth"]
	vm.bridgeRegistry.mu.RUnlock()
	require.Zero(t, completed, "no transfer is completed by a block that did not commit")
	require.Zero(t, volume, "and none of its amount counts against the daily limit")

	vm.mu.RLock()
	_, stillPending := vm.pendingBridges[req.ID]
	vm.mu.RUnlock()
	require.True(t, stillPending, "the transfer is still in flight, so it is not lost")

	tip, height := vm.chain.Tip()
	require.Equal(t, tipBefore, tip)
	require.Equal(t, heightBefore, height)

	// The block is not committed. It is still in flight, which is right — the
	// engine may put it to a vote again — but nothing about it is on disk.
	require.False(t, vm.chain.Accepted(blk.ID()))
	found, err := vm.GetBlock(context.Background(), blk.ID())
	require.NoError(t, err, "a block in flight is still findable as a parent")
	require.Equal(t, blk.ID(), found.ID())

	// And it can be applied again once the database will take it.
	db.refuse = false
	require.NoError(t, blk.Accept(context.Background()))
	require.True(t, vm.chain.Accepted(blk.ID()))
	require.Len(t, vm.releaser.queue, 1)
}

// TestAnAcceptedBlockIsDurableAndReleased is the other half, and pins the tip
// as durable: it was never written before, so a restart reset the chain to
// genesis and reset the daily bridge limit with it.
func TestAnAcceptedBlockIsDurableAndReleased(t *testing.T) {
	vm, db, req := vmWithTransfer(t)

	built, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := built.(*Block)

	require.NoError(t, blk.Accept(context.Background()))

	require.Len(t, vm.releaser.queue, 1)
	require.Equal(t, req.ID, (<-vm.releaser.queue).ID)

	vm.bridgeRegistry.mu.RLock()
	volume := vm.bridgeRegistry.DailyVolume["eth"]
	vm.bridgeRegistry.mu.RUnlock()
	require.Equal(t, uint64(7), volume)

	tip, height := vm.chain.Tip()
	require.Equal(t, blk.ID(), tip)
	require.Equal(t, uint64(1), height)

	// A second store over the same database is a restart: the tip is where the
	// chain left it, not back at genesis.
	restarted := chain.New[*Block](db, nil)
	at, fresh, err := restarted.Open(vm.genesisBlock, vm.parseBlock)
	require.NoError(t, err)
	require.False(t, fresh)
	require.Equal(t, blk.ID(), at.ID())
}

// TestTheHeightIndexNamesOnlyAcceptedBlocks pins the index to the commit that
// wrote it.
func TestTheHeightIndexNamesOnlyAcceptedBlocks(t *testing.T) {
	vm, db, _ := vmWithTransfer(t)

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)

	db.refuse = true
	require.ErrorIs(t, blk.Accept(context.Background()), errRefused)
	_, err = vm.GetBlockIDAtHeight(context.Background(), 1)
	require.Error(t, err, "a block that did not commit has no height entry")

	db.refuse = false
	require.NoError(t, blk.Accept(context.Background()))
	at, err := vm.GetBlockIDAtHeight(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, blk.ID(), at)
}
