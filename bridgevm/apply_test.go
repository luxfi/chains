// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
)

// TestABlockThatCannotCommitReleasesNothing is the defect this chain had.
// Accept credited the daily volume, completed the request, advanced
// lastAcceptedID and handed the transfer to the release worker — which
// broadcasts on an external chain — and only then wrote the block. A write
// that failed left all of it done, including a release in flight for a
// transfer no block records. lastAcceptedID was never written at all, so the
// tip reset to genesis on restart and the daily limit reset with it.
func TestABlockThatCannotCommitReleasesNothing(t *testing.T) {
	vm, db := bootRefusing(t)
	vm.releaser = &releaser{vm: vm, queue: make(chan *BridgeRequest, 8), quit: make(chan struct{})}
	req := requestFor(1, 7)
	pend(vm, req)

	blk := build(t, vm)
	require.NoError(t, blk.Verify(context.Background()))

	tipBefore, heightBefore := vm.chain.Tip()

	db.refuse = true
	require.ErrorIs(t, blk.Accept(context.Background()), errRefused)

	// The irreversible part: nothing was handed to the release worker.
	require.Empty(t, vm.releaser.queue,
		"an external release must not start for a block that did not commit")

	// Nor did any of the durable part happen.
	require.Zero(t, moved(t, vm, blk.BlockTimestamp, dstChain),
		"none of the amount counts against the daily cap")
	settled, err := newSpend(vm.chain.Base()).isSettled(req.ID)
	require.NoError(t, err)
	require.False(t, settled, "no transfer is settled by a block that did not commit")

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
	vm, db := bootRefusing(t)
	vm.releaser = &releaser{vm: vm, queue: make(chan *BridgeRequest, 8), quit: make(chan struct{})}
	req := requestFor(1, 7)
	pend(vm, req)

	blk := buildAndAccept(t, vm)

	require.Len(t, vm.releaser.queue, 1)
	require.Equal(t, req.ID, (<-vm.releaser.queue).ID)
	require.Equal(t, uint64(7), moved(t, vm, blk.BlockTimestamp, dstChain))

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
	vm, db := bootRefusing(t)
	pend(vm, requestFor(1, 7))

	blk := build(t, vm)
	require.NoError(t, blk.Verify(context.Background()))

	db.refuse = true
	require.ErrorIs(t, blk.Accept(context.Background()), errRefused)
	_, err := vm.GetBlockIDAtHeight(context.Background(), 1)
	require.Error(t, err, "a block that did not commit has no height entry")

	db.refuse = false
	require.NoError(t, blk.Accept(context.Background()))
	at, err := vm.GetBlockIDAtHeight(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, blk.ID(), at)
}

// TestTheDailyCapSurvivesARestart is the defect this file exists for.
//
// The counter the cap is measured against lived in a map on the heap. A
// restart built a fresh one, so the whole day's allowance came back: an
// operator restart — or a crash, or a rolling deploy — was a free reset of
// the number that bounds what this bridge can move.
func TestTheDailyCapSurvivesARestart(t *testing.T) {
	db := memdb.New()
	cfg := testConfig()
	cfg.MaxBridgeAmount = 600
	cfg.DailyBridgeLimit = 1000

	vm := bootOn(t, db, cfg)
	pend(vm, requestFor(1, 600))
	first := buildAndAccept(t, vm)
	require.Equal(t, uint64(600), moved(t, vm, first.BlockTimestamp, dstChain))

	// Restart: a second VM over the same database, exactly as the node does.
	restarted := bootOn(t, db, cfg)
	require.Equal(t, uint64(600), moved(t, restarted, first.BlockTimestamp, dstChain),
		"the day's spend is read back from disk, not started over")

	// 600 already moved against a cap of 1000, so a second 600 does not fit.
	pend(restarted, requestFor(2, 600))
	_, err := restarted.BuildBlock(context.Background())
	require.Error(t, err, "the restarted chain must still refuse what the cap no longer allows")

	// And what does fit, fits.
	pend(restarted, requestFor(3, 400))
	blk := build(t, restarted)
	require.Len(t, blk.BridgeRequests, 1)
	require.Equal(t, uint64(400), blk.BridgeRequests[0].Amount)
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))
	require.Equal(t, uint64(1000), moved(t, restarted, blk.BlockTimestamp, dstChain))
}

// TestTheCapIsCountedPerDestination keeps one busy route from closing another.
func TestTheCapIsCountedPerDestination(t *testing.T) {
	cfg := testConfig()
	cfg.MaxBridgeAmount = 100
	cfg.DailyBridgeLimit = 100
	vm := bootOn(t, memdb.New(), cfg)

	toZoo := requestFor(1, 100)
	other := transferFor(2, 100)
	other.DstChainID = 777
	toElsewhere := &BridgeRequest{
		ID: ids.ID(other.Digest()), SrcChainID: other.SrcChainID, DstChainID: other.DstChainID,
		Nonce: other.Nonce, Asset: ids.ID(other.Asset), Amount: other.Amount,
		Recipient: append([]byte(nil), other.Recipient[:]...),
	}
	pend(vm, toZoo, toElsewhere)

	blk := buildAndAccept(t, vm)
	require.Len(t, blk.BridgeRequests, 2, "two destinations each have their own cap")
	require.Equal(t, uint64(100), moved(t, vm, blk.BlockTimestamp, dstChain))
	require.Equal(t, uint64(100), moved(t, vm, blk.BlockTimestamp, 777))
}

// TestTheWindowReopensOnTheNextDay proves the cap is daily rather than
// permanent. The counter it replaced only ever grew, so once total volume
// passed the limit every later block failed verification and the bridge
// stopped for good.
//
// Both blocks are stamped by hand, in the past, because what decides the
// window is the BLOCK's time — the whole point of measuring it there rather
// than off each node's clock.
func TestTheWindowReopensOnTheNextDay(t *testing.T) {
	cfg := testConfig()
	cfg.MaxBridgeAmount = 100
	cfg.DailyBridgeLimit = 100
	vm := bootOn(t, memdb.New(), cfg)

	genesisTime := vm.genesisBlock.BlockTimestamp
	first := blockOn(t, vm, vm.genesisBlock, genesisTime, requestFor(1, 100))
	require.NoError(t, first.Verify(context.Background()))
	require.NoError(t, first.Accept(context.Background()))

	// A third 100 on the same day does not fit.
	same := blockOn(t, vm, first, genesisTime, requestFor(2, 100))
	require.ErrorContains(t, same.Verify(context.Background()), "daily cap")

	// The next day starts the window over.
	next := blockOn(t, vm, first, genesisTime+dayLength, requestFor(2, 100))
	require.NoError(t, next.Verify(context.Background()))
	require.NoError(t, next.Accept(context.Background()))

	require.Equal(t, uint64(100), moved(t, vm, genesisTime, dstChain))
	require.Equal(t, uint64(100), moved(t, vm, genesisTime+dayLength, dstChain))
}

// blockOn assembles a block on a chosen parent at a chosen time, which is how
// a peer's block arrives: this node did not pick either.
func blockOn(t *testing.T, vm *VM, parent *Block, at int64, reqs ...*BridgeRequest) *Block {
	t.Helper()
	blk := &Block{
		ParentID_:      parent.ID(),
		BlockHeight:    parent.Height() + 1,
		BlockTimestamp: at,
		BridgeRequests: reqs,
		vm:             vm,
	}
	blk.ID_ = blk.computeID()
	return blk
}
