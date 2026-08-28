// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/threshold/pkg/party"
	vmcore "github.com/luxfi/vm"
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

func newApplyVM(t *testing.T) (*VM, *refusingDB) {
	t.Helper()
	db := &refusingDB{Database: memdb.New()}
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), NetworkID: 3, ChainID: ids.GenerateTestID()},
		DB:       db,
		Log:      log.NewNoOpLogger(),
		ToEngine: make(chan vmcore.Message, 1),
	}))
	return vm, db
}

// signOp is a completed sign ceremony. Write records ceremonies without
// re-verifying them — Verify has already done that — so a fabricated one is
// enough to exercise what Write does with the records it is given.
func signOp(id string) *Operation {
	return &Operation{
		Type:       OpTypeSign,
		CeremonyID: id,
		KeyID:      "key-" + id,
		Digest:     make([]byte, 32),
		Artifact:   make([]byte, 65),
		Signers:    []party.ID{"a", "b"},
	}
}

// blockOver builds a block carrying ops on the current tip, with the root they
// actually reach.
func blockOver(t *testing.T, vm *VM, ops ...*Operation) *Block {
	t.Helper()
	parentID, height := vm.chain.Tip()

	root := vm.state.Root()
	for _, op := range ops {
		root = advance(root, op.digest())
	}
	blk := &Block{
		ParentID_:      parentID,
		BlockHeight:    height + 1,
		BlockTimestamp: 1,
		StateRoot:      root,
		Operations:     ops,
		vm:             vm,
	}
	blk.ID_ = blk.computeID()
	return blk
}

// TestARootMismatchLeavesNoCeremonyBehind is the defect this chain had, and
// the reason it was worse than a lost block.
//
// Accept folded the operations into the registry and the ceremony log with one
// Put each, and only THEN compared the root it reached with the one the block
// claims. Refusing there left every record it had already written on disk —
// exactly the disagreeing state the check exists to refuse. And because PutKey
// and PutCeremony refuse a record they already hold, the block could never be
// applied again: the chain was wedged at that height.
func TestARootMismatchLeavesNoCeremonyBehind(t *testing.T) {
	vm, _ := newApplyVM(t)
	defer vm.Shutdown(context.Background())

	first, second := signOp("one"), signOp("two")
	blk := blockOver(t, vm, first, second)

	good := blk.StateRoot
	rootBefore := vm.state.Root()
	blk.StateRoot = [32]byte{0xde, 0xad}

	require.ErrorIs(t, blk.Accept(context.Background()), ErrRootMismatch)

	// The first ceremony is the one the old code always landed: its Put ran
	// before the check that refused the block.
	_, err := vm.state.GetCeremony(first.CeremonyID)
	require.Error(t, err, "a ceremony must not survive a block the chain refused")
	_, err = vm.state.GetCeremony(second.CeremonyID)
	require.Error(t, err)
	require.Equal(t, rootBefore, vm.state.Root(), "and the root must not have moved")

	tip, height := vm.chain.Tip()
	require.Equal(t, blk.ParentID_, tip)
	require.Equal(t, blk.BlockHeight-1, height)

	// The block is applicable again once its root is right. Under the old code
	// PutCeremony would have refused both ceremonies as already recorded, and
	// no block could ever carry them.
	blk.StateRoot = good
	blk.ID_ = blk.computeID()
	require.NoError(t, blk.Accept(context.Background()))

	rec, err := vm.state.GetCeremony(first.CeremonyID)
	require.NoError(t, err)
	require.Equal(t, first.CeremonyID, rec.ID)
	require.Equal(t, good, vm.state.Root())
}

// TestABlockThatCannotCommitRecordsNothing is the same property against a
// database that will not flush.
func TestABlockThatCannotCommitRecordsNothing(t *testing.T) {
	vm, db := newApplyVM(t)
	defer vm.Shutdown(context.Background())

	op := signOp("solo")
	vm.stage(op)
	require.Equal(t, 1, vm.staged.Len())

	blk := blockOver(t, vm, op)
	rootBefore := vm.state.Root()
	tipBefore, heightBefore := vm.chain.Tip()

	db.refuse = true
	require.ErrorIs(t, blk.Accept(context.Background()), errRefused)

	_, err := vm.state.GetCeremony(op.CeremonyID)
	require.Error(t, err)
	require.Equal(t, rootBefore, vm.state.Root())
	require.Equal(t, 1, vm.staged.Len(), "the ceremony is still staged, so it is not lost")

	tip, height := vm.chain.Tip()
	require.Equal(t, tipBefore, tip)
	require.Equal(t, heightBefore, height)

	// And it applies once the database will take it.
	db.refuse = false
	require.NoError(t, blk.Accept(context.Background()))
	_, err = vm.state.GetCeremony(op.CeremonyID)
	require.NoError(t, err)
	require.Zero(t, vm.staged.Len(), "and the ceremony leaves the queue only then")

	tip, height = vm.chain.Tip()
	require.Equal(t, blk.ID(), tip)
	require.Equal(t, heightBefore+1, height)
}

// TestTheHeightIndexNamesOnlyAcceptedBlocks pins the index to the commit that
// wrote it. It used to be two Puts with an early return between them, so a
// fault could leave a block recorded with no height entry, or a height entry
// naming a tip that was never recorded.
func TestTheHeightIndexNamesOnlyAcceptedBlocks(t *testing.T) {
	vm, db := newApplyVM(t)
	defer vm.Shutdown(context.Background())

	doomed := blockOver(t, vm, signOp("doomed"))
	db.refuse = true
	require.ErrorIs(t, doomed.Accept(context.Background()), errRefused)

	_, err := vm.GetBlockIDAtHeight(context.Background(), doomed.BlockHeight)
	require.Error(t, err, "a block that did not commit has no height entry")

	db.refuse = false
	good := blockOver(t, vm, signOp("good"))
	require.NoError(t, good.Accept(context.Background()))

	at, err := vm.GetBlockIDAtHeight(context.Background(), good.BlockHeight)
	require.NoError(t, err)
	require.Equal(t, good.ID(), at)
}

// TestAStagedCeremonyIsQueuedOnce holds the idempotence staging always had:
// a ceremony that completes twice — a re-proposal after a rejected block —
// stages once.
func TestAStagedCeremonyIsQueuedOnce(t *testing.T) {
	vm, _ := newApplyVM(t)
	defer vm.Shutdown(context.Background())

	op := signOp("repeat")
	vm.stage(op)
	vm.stage(op)
	vm.stage(signOp("other"))
	require.Equal(t, 2, vm.staged.Len())
}
