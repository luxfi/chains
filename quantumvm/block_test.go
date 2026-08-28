// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
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
	require.Equal(t, uint64(3), heightOf(t, vm))

	restarted := bootVMOn(t, quietConfig(), db)

	got, err := restarted.LastAccepted(context.Background())
	require.NoError(t, err)
	require.Equal(t, tip.id, got, "the tip did not survive the restart: the accepted blocks were never committed")
	require.Equal(t, uint64(3), heightOf(t, restarted))

	stored, err := restarted.GetBlock(context.Background(), tip.id)
	require.NoError(t, err, "the tip pointer names a block the store does not hold")
	require.Equal(t, tip.id, stored.ID())
}

// refusing is a store whose batches will not write, which is what a full disk
// looks like from up here: staging succeeds, the commit does not. The refusal
// is switchable, because the interesting question is what the store holds AFTER
// it comes back.
type refusing struct {
	database.Database
	refuse *bool
}

var errDiskFull = errors.New("store refused the write")

func (d refusing) NewBatch() database.Batch { return refusingBatch{d.Database.NewBatch(), d.refuse} }

type refusingBatch struct {
	database.Batch
	refuse *bool
}

func (b refusingBatch) Write() error {
	if *b.refuse {
		return errDiskFull
	}
	return b.Batch.Write()
}

// refuseWrites points the VM's version layer at a store that cannot commit.
// Everything already committed stays readable underneath.
func refuseWrites(vm *VM) {
	always := true
	vm.db = refusing{vm.db, &always}
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
	before := tipOf(t, vm)
	beforeHeight := heightOf(t, vm)

	blk := buildOn(t, vm)
	require.NoError(t, blk.Verify(context.Background()))

	refuseWrites(vm)

	require.ErrorIs(t, blk.Accept(context.Background()), errDiskFull)

	require.Equal(t, before, tipOf(t, vm), "the tip moved to a block whose writes failed")
	require.Equal(t, beforeHeight, heightOf(t, vm), "the height moved to a block whose writes failed")
	_, err := vm.GetBlock(context.Background(), blk.id)
	require.Error(t, err, "a partially written block is readable")
	_, err = vm.GetBlockIDAtHeight(context.Background(), blk.height)
	require.Error(t, err, "a partially written block is indexed")
}

// TestAFailedCommitStagesNothingForTheNextOne.
//
// Staged writes that are not discarded are not discarded LATER either — they
// are flushed, wholesale, by the next commit that succeeds. So a block whose
// Accept returned an error to the engine still reached the store, riding into
// it on an unrelated block minutes afterwards.
func TestAFailedCommitStagesNothingForTheNextOne(t *testing.T) {
	refuse := false
	vm := bootVMOn(t, quietConfig(), refusing{memdb.New(), &refuse})
	tip := advance(t, vm, 1)

	refuse = true
	orphan := buildOn(t, vm)
	require.ErrorIs(t, orphan.Accept(context.Background()), errDiskFull)

	// The store comes back, and an unrelated block commits.
	refuse = false
	vm.clock.Set(chainTime.Add(time.Hour))
	next := buildOn(t, vm)
	require.NotEqual(t, orphan.id, next.id, "precondition: two distinct blocks")
	require.NoError(t, next.Accept(context.Background()))

	held, err := vm.state.Has(orphan.id[:])
	require.NoError(t, err)
	require.False(t, held, "the refused block was flushed into the store by the next successful commit")

	require.Equal(t, next.id, tipOf(t, vm))
	at, err := vm.GetBlockIDAtHeight(context.Background(), tip.height+1)
	require.NoError(t, err)
	require.Equal(t, next.id, at, "the height index names a block that never committed")
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

// TestAcceptTakesOnlyTheBlockThatFollOwsTheTip.
//
// Accept wrote the tip pointer unconditionally, and Verify only ever compared a
// block against its PARENT — never against the chain's head. So any block that
// verified could be accepted, at any height, at any time:
//
//   - a height-1 block accepted onto a height-5 chain rewound it to height 1,
//     while heights 2 through 5 stayed indexed to the branch just abandoned —
//     and GetBlockIDAtHeight served those to bootstrapping peers as canonical;
//   - a block already accepted, accepted again, did the same;
//   - two siblings both verified and both committed, the second silently
//     replacing the first.
func TestAcceptTakesOnlyTheBlockThatFollowsTheTip(t *testing.T) {
	ctx := context.Background()
	vm, _ := bootVM(t, quietConfig())

	chain := make([]*Block, 0, 5)
	for i := 0; i < 5; i++ {
		chain = append(chain, advance(t, vm, 1))
	}
	tip := chain[len(chain)-1]
	require.Equal(t, uint64(5), heightOf(t, vm))

	// An old block, re-offered.
	require.ErrorIs(t, chain[0].Accept(ctx), errNotTheTip,
		"a height-1 block rewound a height-5 chain")
	require.Equal(t, tip.id, tipOf(t, vm))
	require.Equal(t, uint64(5), heightOf(t, vm))
	for i, blk := range chain {
		at, err := vm.GetBlockIDAtHeight(ctx, uint64(i+1))
		require.NoError(t, err)
		require.Equal(t, blk.id, at, "height %d was re-indexed to an abandoned branch", i+1)
	}

	// The tip itself, re-offered.
	require.ErrorIs(t, tip.Accept(ctx), errNotTheTip, "an accepted block was accepted a second time")

	// Two siblings. Both verify — that is what makes consensus a choice — and
	// exactly one may be accepted.
	first := buildOn(t, vm)
	require.NoError(t, first.Verify(ctx))
	vm.clock.Set(chainTime.Add(time.Minute))
	second := buildOn(t, vm)
	require.NoError(t, second.Verify(ctx))
	require.NotEqual(t, first.id, second.id, "precondition: two distinct siblings")
	require.Equal(t, first.parentID, second.parentID, "precondition: they are siblings")

	require.NoError(t, first.Accept(ctx))
	require.ErrorIs(t, second.Accept(ctx), errNotTheTip, "a sibling silently replaced the accepted block")
	require.Equal(t, first.id, tipOf(t, vm))
}

// countingTx records how many times it was applied, and can refuse.
type countingTx struct {
	*BaseTransaction
	runs *int32
	fail error
}

func (tx countingTx) Execute() error {
	atomic.AddInt32(tx.runs, 1)
	return tx.fail
}

// TestTransactionsRunWhenTheBlockIsAccepted, and only then.
//
// They ran at BUILD time. A block the network never accepted had already
// applied its effects; a rebuild applied them twice; and a node that RECEIVED
// the block rather than building it applied them never — which is every node
// but one, for every block.
func TestTransactionsRunWhenTheBlockIsAccepted(t *testing.T) {
	ctx := context.Background()
	vm, _ := bootVM(t, quietConfig())
	var runs int32
	tx := countingTx{BaseTransaction: stampedTx(1, "apply me"), runs: &runs}

	blk := buildWith(t, vm, tx)
	require.Zero(t, atomic.LoadInt32(&runs), "building a block applied its transactions")

	// Building again over the same pool contents must not apply them again.
	rebuilt, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.Zero(t, atomic.LoadInt32(&runs), "a rebuild applied the same transaction a second time")

	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))
	require.Equal(t, int32(1), atomic.LoadInt32(&runs), "an accepted block applied nothing")

	// The sibling can no longer be accepted, so nothing runs twice.
	require.Error(t, rebuilt.(*Block).Accept(ctx))
	require.Equal(t, int32(1), atomic.LoadInt32(&runs))
}

// TestRejectAppliesNothing: a block that loses never ran, so there is nothing
// for Reject to undo — which is why Reject undoing nothing is correct rather
// than a gap.
func TestRejectAppliesNothing(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	var runs int32

	blk := buildWith(t, vm, countingTx{BaseTransaction: stampedTx(1, "never"), runs: &runs})
	require.NoError(t, blk.Reject(context.Background()))
	require.Zero(t, atomic.LoadInt32(&runs), "a rejected block had already applied its transactions")
}

// TestAcceptCommitsNothingWhenATransactionCannotBeApplied. A node that cannot
// apply an agreed block stops rather than committing a chain its state no
// longer matches.
func TestAcceptCommitsNothingWhenATransactionCannotBeApplied(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	before := tipOf(t, vm)
	var runs int32

	blk := buildWith(t, vm, countingTx{
		BaseTransaction: stampedTx(1, "cannot apply"),
		runs:            &runs,
		fail:            errors.New("state says no"),
	})
	require.ErrorIs(t, blk.Accept(context.Background()), errExecute)
	require.Equal(t, before, tipOf(t, vm), "the tip advanced past a block that could not be applied")
}

// TestVerifyRefusesAnOrphan. Checking only that the parent exists ABOVE height
// one meant a height-one block could name any parent at all, including one no
// node has ever seen: it verified, it was accepted, and the chain it extended
// was not this one.
func TestVerifyRefusesAnOrphan(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())

	orphan := &Block{
		timestamp:    chainTime,
		height:       1,
		parentID:     ids.GenerateTestID(), // a block this node has never held
		chainID:      vm.blockchainID,
		networkID:    vm.NetworkID,
		transactions: []Transaction{stampedTx(1, "op")},
		vm:           vm,
	}
	orphan.id = orphan.computeID()

	require.ErrorIs(t, orphan.Verify(context.Background()), errInvalidParentID)
}

// TestVerifyRefusesAHeightThatSkipsItsParent. Height is the parent's, advanced
// by one. Without that a proposer names genesis as the parent of a height-500
// block and the 499 heights in between simply do not exist.
func TestVerifyRefusesAHeightThatSkipsItsParent(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	genesis, err := vm.blockAt(tipOf(t, vm))
	require.NoError(t, err)

	for _, height := range []uint64{2, 7, 500} {
		blk := blockOn(vm, genesis, stampedTx(height, "op"))
		blk.height = height
		blk.bytes = nil
		blk.id = blk.computeID()
		require.ErrorIs(t, blk.Verify(context.Background()), errInvalidBlockHeight,
			"height %d was accepted as the child of height 0", height)
	}
}

// TestVerifyRefusesGenesisAsAProposal: height zero is written by the VM at
// start, identically on every node. A proposed one would be a second genesis.
func TestVerifyRefusesGenesisAsAProposal(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	blk := &Block{
		timestamp: chainTime, height: 0, parentID: ids.Empty,
		chainID: vm.blockchainID, networkID: vm.NetworkID, vm: vm,
	}
	blk.id = blk.computeID()
	require.ErrorIs(t, blk.Verify(context.Background()), errInvalidBlockHeight)
}

// TestVerifyRefusesAnEmptyBlock. A proposal carries work, and refusing an empty
// one is also what stops the transaction-signature check being satisfied by
// removing its subject: a block with no transactions verifies no signatures, so
// it must not verify at all.
func TestVerifyRefusesAnEmptyBlock(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	genesis, err := vm.blockAt(tipOf(t, vm))
	require.NoError(t, err)

	require.ErrorIs(t, blockOn(vm, genesis).Verify(context.Background()), errEmptyBlock)
}

// TestVerifyRefusesTimeRunningBackwards. Chain time is what orders the chain, and
// a proposer that rewinds it decides what the block after it may be stamped.
func TestVerifyRefusesTimeRunningBackwards(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	parent := advance(t, vm, 1)

	blk := blockOn(vm, parent, stampedTx(2, "op"))
	blk.timestamp = parent.timestamp.Add(-time.Second)
	blk.bytes = nil
	blk.id = blk.computeID()
	require.ErrorIs(t, blk.Verify(context.Background()), errTimeBeforeParent)

	// The parent's own timestamp is fine — time may stand still, only not reverse.
	same := blockOn(vm, parent, stampedTx(3, "op"))
	require.NoError(t, same.Verify(context.Background()))
}

// TestVerifyRefusesTimeJumpingAhead. Uncapped, one proposer stamping a block
// far in the future decides chain time for everyone behind it.
func TestVerifyRefusesTimeJumpingAhead(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	parent := advance(t, vm, 1)

	blk := blockOn(vm, parent, stampedTx(2, "op"))
	blk.timestamp = vm.clock.Time().Add(MaxFutureSkew + time.Second)
	blk.bytes = nil
	blk.id = blk.computeID()
	require.ErrorIs(t, blk.Verify(context.Background()), errTimeTooFarAhead)

	// Just inside the allowance is a clock that is merely fast, not a rewrite
	// of chain time, and it verifies.
	ok := blockOn(vm, parent, stampedTx(3, "op"))
	ok.timestamp = vm.clock.Time().Add(MaxFutureSkew)
	ok.bytes = nil
	ok.id = ok.computeID()
	require.NoError(t, ok.Verify(context.Background()))
}

// TestVerifyRefusesABlockWhoseStampsDoNotCheck: the signatures over the
// transactions are checked, and a block carrying one that does not verify is
// refused whole.
func TestVerifyRefusesABlockWhoseStampsDoNotCheck(t *testing.T) {
	vm, _ := bootVM(t, config.DefaultConfig()) // stamps ON
	parent := advanceSigned(t, vm, 1)

	good := signedTx(t, vm, 1, "honest")
	blk := blockOn(vm, parent, good)
	require.NoError(t, blk.Verify(context.Background()), "a correctly signed transaction must verify")

	// One flipped bit in the signature is the whole difference.
	good.quantumSignature.Signature[0] ^= 0xFF
	blk.bytes = nil
	require.ErrorIs(t, blk.Verify(context.Background()), errBlockVerificationFailed)
}

// TestVerifyChecksTheSignaturesOfABlockItDidNotBuild.
//
// This is the one that mattered. The parser did not reconstruct the transaction
// set, so a received block held ZERO transactions, and the signature check was
// gated on there being some — so it ran only on blocks this node built itself
// and never once on the receive path. Identical bytes got opposite verdicts, and
// a block whose transactions were arbitrary bytes verified and committed.
func TestVerifyChecksTheSignaturesOfABlockItDidNotBuild(t *testing.T) {
	ctx := context.Background()
	vm, _ := bootVM(t, config.DefaultConfig()) // stamps ON
	parent := advanceSigned(t, vm, 1)

	built := blockOn(vm, parent, signedTx(t, vm, 1, "honest"))
	require.NoError(t, built.Verify(ctx))

	// The same bytes, arriving over the network.
	received, err := vm.ParseBlock(ctx, built.Bytes())
	require.NoError(t, err)
	require.Equal(t, built.id, received.ID(), "one block, two ids")
	require.Len(t, received.(*Block).transactions, 1, "the parser dropped the transaction set")
	require.NoError(t, received.Verify(ctx))

	// And a block whose signature does not check must be refused on that same
	// path — the verdict cannot depend on who assembled the object.
	forgedTx := signedTx(t, vm, 2, "forged")
	forgedTx.quantumSignature.Signature[0] ^= 0xFF
	forged := blockOn(vm, parent, forgedTx)

	parsed, err := vm.ParseBlock(ctx, forged.Bytes())
	require.NoError(t, err, "precondition: the bytes are a well-formed block")
	require.ErrorIs(t, parsed.Verify(ctx), errBlockVerificationFailed,
		"a received block with a bad signature verified")
	require.ErrorIs(t, forged.Verify(ctx), errBlockVerificationFailed,
		"the same block verified differently depending on how it was assembled")
}

// TestTheTransactionBlobIsNotMutable. The transactions ride in the block's
// bytes; a byte changed in there either stops being a block or stops verifying,
// and never rides through as the same block.
func TestTheTransactionBlobIsNotMutable(t *testing.T) {
	ctx := context.Background()
	vm, _ := bootVM(t, config.DefaultConfig()) // stamps ON
	parent := advanceSigned(t, vm, 1)

	blk := blockOn(vm, parent, signedTx(t, vm, 1, "honest"))
	wire := blk.Bytes()

	tampered := make([]byte, len(wire))
	copy(tampered, wire)
	tampered[len(tampered)-1] ^= 0xFF

	parsed, err := vm.ParseBlock(ctx, tampered)
	require.NoError(t, err, "precondition: the tampered bytes still decode")
	require.NotEqual(t, blk.id, parsed.ID())
	require.ErrorIs(t, parsed.Verify(ctx), errBlockVerificationFailed,
		"a transaction blob was edited in flight and the block still verified")
}

// TestVerifyRefusesABlockFromAnotherChain.
//
// The wire carried nothing naming a chain, so a block was a block anywhere: one
// built on chain A was accepted verbatim by chain B, and every Q-Chain shared a
// genesis id to build that on.
func TestVerifyRefusesABlockFromAnotherChain(t *testing.T) {
	ctx := context.Background()
	mine, _ := bootVM(t, quietConfig())
	theirs := bootVMAs(t, quietConfig(), memdb.New(), testNetwork, otherChain)

	tip, err := mine.blockAt(tipOf(t, mine))
	require.NoError(t, err)

	// A block naming this node's tip as its parent, stamped for another chain.
	foreign := blockOn(mine, tip, stampedTx(1, "op"))
	foreign.chainID = theirs.blockchainID
	foreign.bytes = nil
	foreign.id = foreign.computeID()

	require.ErrorIs(t, foreign.Verify(ctx), errForeignChain)
	require.ErrorIs(t, foreign.Accept(ctx), errForeignChain,
		"a block belonging to another chain was committed to this one")
	require.Equal(t, tip.id, tipOf(t, mine))

	// The same for a block from another network on this chain id.
	elsewhere := blockOn(mine, tip, stampedTx(2, "op"))
	elsewhere.networkID = mine.NetworkID + 1
	elsewhere.bytes = nil
	elsewhere.id = elsewhere.computeID()
	require.ErrorIs(t, elsewhere.Verify(ctx), errForeignChain)
	require.ErrorIs(t, elsewhere.Accept(ctx), errForeignChain)
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

	blk := blockOn(vm, parent, stampedTx(9999, "op"))

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
