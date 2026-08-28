// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

// TestAcceptedBlockSurvivesRestart is the property the chain could not run
// without, and the one nothing asserted.
//
// Accept wrote through the version layer and never committed, so every accepted
// block lived in one process's memory. A node that had accepted a thousand
// blocks came back from a restart naming genesis — while its peers held it to
// the tip it had already told them about.
func TestAcceptedBlockSurvivesRestart(t *testing.T) {
	vm, db := bootVM(t, quietConfig())
	tip := advance(t, vm, 3)
	require.Equal(t, uint64(3), vm.getHeight())

	restarted := bootVMOn(t, quietConfig(), db)

	got, err := restarted.LastAccepted(context.Background())
	require.NoError(t, err)
	require.Equal(t, tip.id, got, "the tip did not survive the restart: the accepted blocks were never committed")
	require.Equal(t, uint64(3), restarted.getHeight())

	stored, err := restarted.GetBlock(context.Background(), tip.id)
	require.NoError(t, err, "the tip pointer names a block the store does not hold")
	require.Equal(t, tip.id, stored.ID())
}

// refusing is a store whose batches will not write, which is what a full disk
// looks like from up here: staging succeeds, the commit does not.
type refusing struct{ database.Database }

var errDiskFull = errors.New("store refused the write")

func (d refusing) NewBatch() database.Batch { return refusingBatch{d.Database.NewBatch()} }

type refusingBatch struct{ database.Batch }

func (b refusingBatch) Write() error { return errDiskFull }

// refuseWrites points the VM's version layer at a store that cannot commit.
// Everything already committed stays readable underneath.
func refuseWrites(vm *VM) {
	vm.db = refusing{vm.db}
	vm.state = versiondb.New(vm.db)
}

// TestAcceptLeavesNothingBehindWhenAWriteFails: a block is stored, indexed by
// height and made the tip. Those are one fact about the chain, so a failure
// part-way through must leave none of them.
//
// Written as three Puts that each returned early, a failure on the second left
// the block stored under a tip pointer that still named its parent and a height
// index that named nothing — and the version layer carried the half-write into
// whatever committed next.
func TestAcceptLeavesNothingBehindWhenAWriteFails(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	before := vm.getLastAcceptedID()
	beforeHeight := vm.getHeight()

	blk := buildOn(t, vm)
	require.NoError(t, blk.Verify(context.Background()))

	refuseWrites(vm)

	require.ErrorIs(t, blk.Accept(context.Background()), errDiskFull)

	require.Equal(t, before, vm.getLastAcceptedID(), "the tip moved to a block whose writes failed")
	require.Equal(t, beforeHeight, vm.getHeight(), "the height moved to a block whose writes failed")
	_, err := vm.GetBlock(context.Background(), blk.id)
	require.Error(t, err, "a partially written block is readable")
	_, err = vm.GetBlockIDAtHeight(context.Background(), blk.height)
	require.Error(t, err, "a partially written block is indexed")
}

// TestAcceptKeepsTheMempoolWhenTheWriteFails: the transactions of a block that
// did not persist must still be there to go into the next one.
func TestAcceptKeepsTheMempoolWhenTheWriteFails(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	blk := buildOn(t, vm)
	require.Equal(t, 1, vm.txPool.PendingCount())

	refuseWrites(vm)

	require.Error(t, blk.Accept(context.Background()))
	require.Equal(t, 1, vm.txPool.PendingCount(),
		"the block never persisted but its transactions were dropped from the pool")
}

// TestAcceptEvictsWhatItCommitted is the other half: once the block IS durable,
// its transactions are settled and must not be built into another block.
func TestAcceptEvictsWhatItCommitted(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	blk := buildOn(t, vm)
	require.Equal(t, 1, vm.txPool.PendingCount())
	require.NoError(t, blk.Accept(context.Background()))
	require.Zero(t, vm.txPool.PendingCount(), "an accepted block's transactions stayed pending")
}

// TestVerifyRefusesAnOrphan. Checking only that the parent exists ABOVE height
// one meant a height-one block could name any parent at all, including one no
// node has ever seen: it verified, it was accepted, and the chain it extended
// was not this one.
func TestVerifyRefusesAnOrphan(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())

	orphan := &Block{
		timestamp: chainTime,
		height:    1,
		parentID:  ids.GenerateTestID(), // a block this node has never held
		vm:        vm,
	}
	orphan.id = orphan.computeID()

	require.ErrorIs(t, orphan.Verify(context.Background()), errInvalidParentID)
}

// TestVerifyRefusesAHeightThatSkipsItsParent. Height is the parent's, advanced
// by one. Without that a proposer names genesis as the parent of a height-500
// block and the 499 heights in between simply do not exist.
func TestVerifyRefusesAHeightThatSkipsItsParent(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	genesis := vm.getLastAcceptedID()

	for _, height := range []uint64{2, 7, 500} {
		blk := &Block{timestamp: chainTime, height: height, parentID: genesis, vm: vm}
		blk.id = blk.computeID()
		require.ErrorIs(t, blk.Verify(context.Background()), errInvalidBlockHeight,
			"height %d was accepted as the child of height 0", height)
	}
}

// TestVerifyRefusesGenesisAsAProposal: height zero is written by the VM at
// start, identically on every node. A proposed one would be a second genesis.
func TestVerifyRefusesGenesisAsAProposal(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	blk := &Block{timestamp: chainTime, height: 0, parentID: ids.Empty, vm: vm}
	blk.id = blk.computeID()
	require.ErrorIs(t, blk.Verify(context.Background()), errInvalidBlockHeight)
}

// TestVerifyRefusesTimeRunningBackwards. Chain time is what a quantum stamp's
// validity window is measured against, so a proposer that rewinds it revives
// stamps the chain has already aged out.
func TestVerifyRefusesTimeRunningBackwards(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	parent := advance(t, vm, 1)

	blk := &Block{
		timestamp: parent.timestamp.Add(-time.Second),
		height:    parent.height + 1,
		parentID:  parent.id,
		vm:        vm,
	}
	blk.id = blk.computeID()
	require.ErrorIs(t, blk.Verify(context.Background()), errTimeBeforeParent)

	// The parent's own timestamp is fine — time may stand still, only not reverse.
	same := &Block{timestamp: parent.timestamp, height: parent.height + 1, parentID: parent.id, vm: vm}
	same.id = same.computeID()
	require.NoError(t, same.Verify(context.Background()))
}

// TestVerifyRefusesTimeJumpingAhead. Uncapped, one proposer stamping a block
// far in the future expires every quantum stamp in flight at once — every
// pending transaction becomes unverifiable in a single block.
func TestVerifyRefusesTimeJumpingAhead(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	parent := advance(t, vm, 1)

	blk := &Block{
		timestamp: vm.clock.Time().Add(MaxFutureSkew + time.Second),
		height:    parent.height + 1,
		parentID:  parent.id,
		vm:        vm,
	}
	blk.id = blk.computeID()
	require.ErrorIs(t, blk.Verify(context.Background()), errTimeTooFarAhead)

	// Just inside the allowance is a clock that is merely fast, not a rewrite
	// of chain time, and it verifies.
	ok := &Block{
		timestamp: vm.clock.Time().Add(MaxFutureSkew - time.Second),
		height:    parent.height + 1,
		parentID:  parent.id,
		vm:        vm,
	}
	ok.id = ok.computeID()
	require.NoError(t, ok.Verify(context.Background()))
}

// TestVerifyRefusesABlockWhoseStampsDoNotCheck: with Corona on, the signatures
// over the transactions are checked, and a block carrying one that does not
// verify is refused whole.
func TestVerifyRefusesABlockWhoseStampsDoNotCheck(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	parent := advance(t, vm, 1)
	vm.Config.CoronaEnabled = true

	good := signedTx(t, vm, 1, "honest")
	blk := &Block{
		timestamp:    parent.timestamp,
		height:       parent.height + 1,
		parentID:     parent.id,
		transactions: []Transaction{good},
		vm:           vm,
	}
	blk.id = blk.computeID()
	require.NoError(t, blk.Verify(context.Background()), "a correctly signed transaction must verify")

	// One flipped bit in the signature is the whole difference.
	good.quantumSignature.Signature[0] ^= 0xFF
	blk.bytes = nil
	require.ErrorIs(t, blk.Verify(context.Background()), errBlockVerificationFailed)
}

// TestVerifyDoesNotDeadlockAgainstABuilder.
//
// Verify held the VM's read lock and then called the exported GetBlock, which
// takes it again. Go queues a waiting writer ahead of any later reader, so a
// build arriving between the two acquisitions blocked the second one — and the
// builder waited on the reader that was waiting on the builder. Nothing times
// out; the chain stops.
//
// The test runs the two against each other. Fixed, it finishes in milliseconds;
// with the recursive acquisition back, it does not finish at all.
func TestVerifyDoesNotDeadlockAgainstABuilder(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	parent := advance(t, vm, 1)

	blk := &Block{timestamp: parent.timestamp, height: parent.height + 1, parentID: parent.id, vm: vm}
	blk.id = blk.computeID()

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(2)
			go func() { defer wg.Done(); _ = blk.Verify(context.Background()) }()
			go func(i int) {
				defer wg.Done()
				_ = vm.txPool.AddTransaction(stampedTx(uint64(i), "x"))
				_, _ = vm.BuildBlock(context.Background())
			}(i)
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Verify and BuildBlock deadlocked: the chain stops here and no timeout releases it")
	}
}

// TestRejectLeavesTheMempoolAlone. BuildBlock copies from the queue rather than
// draining it, so a rejected block's transactions were never taken out. Putting
// them "back" only produced an error per transaction per rejected block.
func TestRejectLeavesTheMempoolAlone(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	blk := buildOn(t, vm)
	require.Equal(t, 1, vm.txPool.PendingCount())

	require.NoError(t, blk.Reject(context.Background()))
	require.Equal(t, 1, vm.txPool.PendingCount(),
		"a rejected block's transactions must still be available to the next one")

	// And they are: the next block carries them.
	next, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.Len(t, next.(*Block).transactions, 1)
}

// TestStatusReportsStorage: 0 while proposed, 1 once committed.
func TestStatusReportsStorage(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	blk := buildOn(t, vm)
	require.Equal(t, uint8(0), blk.Status())
	require.NoError(t, blk.Accept(context.Background()))
	require.Equal(t, uint8(1), blk.Status())
}

// TestBlockAccessors pins the values the consensus engine reads off a block.
func TestBlockAccessors(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	blk := advance(t, vm, 1)

	require.Equal(t, blk.id, blk.ID())
	require.Equal(t, blk.parentID, blk.Parent())
	require.Equal(t, blk.parentID, blk.ParentID())
	require.Equal(t, uint64(1), blk.Height())
	require.Equal(t, blk.timestamp, blk.Timestamp())
	require.Equal(t, blk.timestamp.Unix(), blk.TimestampUnix())
	require.Equal(t, blk.id.String(), blk.String())
}
