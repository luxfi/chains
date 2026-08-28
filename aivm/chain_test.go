// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// chain_test.go holds the regressions for how an A-Chain block becomes fact:
// where the chain thinks it is, what a block is allowed to sit on, and what is
// durable when a block is accepted, rejected, or fails to commit.
//
// Nine defects were found here by executable probe and every one of them is
// checked below by the scenario that found it, with the assertion the other way
// round.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/stretchr/testify/require"
)

// newVM starts a VM on chain chainID over db.
//
// The chain id is a PARAMETER because it is the thing under test in half of
// these: two nodes of the same chain share one, and production has exactly one
// per chain. A harness that generated a fresh id per node would make a restart
// look like a different chain and quietly pass a test about restarts.
func newVM(t *testing.T, chainID ids.ID, db database.Database) *VM {
	t.Helper()
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: chainID, NetworkID: 96369, Log: log.NewNoOpLogger()},
		DB:       db,
		ToEngine: make(chan vmcore.Message, 8),
		Log:      log.NewNoOpLogger(),
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	}))
	vm.SetCommitVerifier(acceptAll)
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	return vm
}

// oneVM is the common case: a single node on a chain of its own.
func oneVM(t *testing.T) *VM {
	t.Helper()
	return newVM(t, ids.GenerateTestID(), memdb.New())
}

// seedOperators funds a requester and a pool of bonded operators advertising
// model 0xAB, so an intent has somewhere to go.
func seedOperators(t *testing.T, vm *VM, reward *uint256.Int) {
	t.Helper()
	e, st, _ := vm.QuorumEngine()
	requester := addrOf(0xF0)
	opening := map[common.Address]*uint256.Int{
		requester: new(uint256.Int).Mul(reward, uint256.NewInt(64)),
	}
	ops := make([]common.Address, consciousEligible)
	for i := range ops {
		ops[i] = addrOf(byte(0x10 + i))
		opening[ops[i]] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))
	}
	require.NoError(t, vm.FundLedger(opening))
	for i, op := range ops {
		require.NoError(t, e.RegisterOperator(st, vm.qledger, op,
			new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2)), hashOf(0xAB), hashOf(byte(0x80+i))))
	}
}

func oneReward() *uint256.Int { return uint256.NewInt(1_000_000_000_000_000_000) }

// build proposes the next block and returns it as a *Block.
func build(t *testing.T, vm *VM) *Block {
	t.Helper()
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	return blk.(*Block)
}

// advance runs one block all the way through: propose, check, accept.
func advance(t *testing.T, vm *VM) *Block {
	t.Helper()
	ctx := context.Background()
	blk := build(t, vm)
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))
	return blk
}

// seen reports whether the intent's anti-replay marker is in COMMITTED state —
// i.e. whether the chain has durably consumed it.
func seen(vm *VM, intent CIntent) bool {
	return isSet(NewDBState(vm.db).GetState(slotHash(nsIntentSeen, intent.IntentID)))
}

// -----------------------------------------------------------------------------
// Where the chain thinks it is.
// -----------------------------------------------------------------------------

// The tip was held in memory and never written down. Accept moved it, nothing
// stored it, and a node that restarted came back at genesis — then built height
// 1 a second time, on top of engine state it could no longer see.
func TestARestartResumesAtTheAcceptedTip(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	chainID, db := ids.GenerateTestID(), memdb.New()
	vm := newVM(t, chainID, db)
	seedOperators(t, vm, oneReward())
	intent := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())
	vm.EnqueueCommittedIntent(intent)
	blk := advance(t, vm)

	head, err := vm.LastAccepted(ctx)
	require.NoError(err)
	require.Equal(blk.ID(), head)
	escrowed := vm.qledger.GetBalance(EscrowAccount).String()
	requester := vm.qledger.GetBalance(addrOf(0xF0)).String()
	require.NotEqual("0", escrowed, "the bonds and the task escrow are held somewhere")

	// Same chain, same database, new process.
	restarted := newVM(t, chainID, db)
	head2, err := restarted.LastAccepted(ctx)
	require.NoError(err)
	require.Equal(blk.ID(), head2, "the restarted node came back at a different head")
	require.Equal(uint64(1), restarted.lastAccepted.Height_)

	// Custody survives with the records that depend on it. A chain that came
	// back holding the stake records and none of the balances would refuse every
	// withdrawal it owes.
	require.Equal(escrowed, restarted.qledger.GetBalance(EscrowAccount).String())
	require.Equal(requester, restarted.qledger.GetBalance(addrOf(0xF0)).String())
	require.True(seen(restarted, intent), "the consumed intent came back re-importable")
	require.Equal(uint32(1), restarted.quorum.LiveTasks(restarted.qstate))

	// The height index was written in the same commit, so it names what the
	// chain accepted and can serve a bootstrapping peer.
	at1, err := restarted.GetBlockIDAtHeight(ctx, 1)
	require.NoError(err)
	require.Equal(blk.ID(), at1)

	// And the block itself reads back by id.
	got, err := restarted.GetBlock(ctx, blk.ID())
	require.NoError(err)
	require.Equal(blk.ID(), got.ID())
	require.Equal(blk.Bytes(), got.Bytes())

	// The chain continues from there rather than re-proposing height 1.
	next := advance(t, restarted)
	require.Equal(uint64(2), next.Height_)
	require.Equal(blk.ID(), next.ParentID_)
}

// A missing tip means a fresh chain. Every OTHER read failure means this node
// cannot tell where it is, and answering "genesis" to that starts a live chain
// over and builds on state it cannot see.
func TestAnUnreadableTipRefusesToOpen(t *testing.T) {
	require := require.New(t)

	vm := &VM{}
	err := vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: log.NewNoOpLogger()},
		DB:       &unreadable{Database: memdb.New()},
		ToEngine: make(chan vmcore.Message, 8),
		Log:      log.NewNoOpLogger(),
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	})
	require.ErrorIs(err, errUnreadable)
}

// The tip is what names every block after it, so a database whose tip names a
// block that is not there, or whose bytes name a different block, is not a chain
// to resume.
func TestATipThatDoesNotResolveRefusesToOpen(t *testing.T) {
	require := require.New(t)

	chainID, db := ids.GenerateTestID(), memdb.New()
	stray := ids.GenerateTestID()
	require.NoError(db.Put(tipKey, stray[:]))

	vm := &VM{}
	err := vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: chainID, NetworkID: 96369, Log: log.NewNoOpLogger()},
		DB:       db,
		ToEngine: make(chan vmcore.Message, 8),
		Log:      log.NewNoOpLogger(),
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	})
	require.ErrorIs(err, database.ErrNotFound)

	// A tip of the wrong width is not an id at all.
	require.NoError(db.Put(tipKey, []byte{1, 2, 3}))
	require.Error((&VM{}).Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: chainID, NetworkID: 96369, Log: log.NewNoOpLogger()},
		DB:       db,
		ToEngine: make(chan vmcore.Message, 8),
		Log:      log.NewNoOpLogger(),
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	}))
}

// Block ids are derived under the chain id, so a VM without one names its blocks
// the same way every other A-Chain deployment does.
func TestAVMWithNoChainIDRefusesToStart(t *testing.T) {
	vm := &VM{}
	err := vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{NetworkID: 96369, Log: log.NewNoOpLogger()},
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      log.NewNoOpLogger(),
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	})
	require.ErrorIs(t, err, errChainIDRequired)
}

// A VM with no runtime has no logger, no network and no chain. The guard that
// read as defensive used to be defeated one line later.
func TestAVMWithNoRuntimeRefusesToStart(t *testing.T) {
	vm := &VM{}
	require.ErrorIs(t, vm.Initialize(context.Background(), vmcore.Init{DB: memdb.New()}), errRuntimeRequired)
}

// -----------------------------------------------------------------------------
// What a block is allowed to sit on.
// -----------------------------------------------------------------------------

// Verify had no parent check, no height check and no tip check at all: a block
// naming a parent nothing had ever seen, at a height it chose freely, was
// certified.
func TestABlockOffTheTipIsRefused(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	b1 := advance(t, vm)

	// A parent nothing knows, at a height that jumps.
	orphan := &Block{ParentID_: ids.GenerateTestID(), Height_: 99, Timestamp_: vm.clock.Time(), vm: vm}
	require.NoError(orphan.name())
	require.ErrorIs(orphan.Verify(ctx), ErrNotOnTip)

	// A parent the chain has already built past. Its height follows perfectly —
	// which is exactly why height alone is not the check. Accepting it rewinds
	// the chain and leaves the height index naming an orphan as canonical.
	rewind := &Block{ParentID_: b1.ParentID_, Height_: 1, Timestamp_: vm.clock.Time(), vm: vm}
	require.NoError(rewind.name())
	require.ErrorIs(rewind.Verify(ctx), ErrNotOnTip)
	require.ErrorIs(rewind.Accept(ctx), ErrNotOnTip)

	head, err := vm.LastAccepted(ctx)
	require.NoError(err)
	require.Equal(b1.ID(), head, "the head moved to a block that never extended it")
}

// A block whose height does not follow its parent's is refused even when the
// parent is the tip.
func TestAHeightThatDoesNotFollowIsRefused(t *testing.T) {
	require := require.New(t)
	vm := oneVM(t)
	tip := vm.lastAccepted

	skip := &Block{ParentID_: tip.ID_, Height_: 5, Timestamp_: vm.clock.Time(), vm: vm}
	require.NoError(skip.name())
	require.ErrorIs(skip.Verify(context.Background()), ErrInvalidBlock)
}

// Genesis is state, not a proposal. Offering it as one asks the chain to apply
// its own starting point as a transition.
func TestGenesisIsNotAProposal(t *testing.T) {
	vm := oneVM(t)
	require.ErrorIs(t, vm.lastAccepted.Verify(context.Background()), ErrInvalidBlock)
}

// The tip moves between Verify and Accept, so Verify cannot be the last word.
// Two siblings both check out against the tip they shared; the first to be
// accepted moves it, and the second must then be refused — otherwise the chain
// rewinds after consensus has already decided.
func TestATipThatMovesAfterVerifyIsCaughtByAccept(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	a := build(t, vm)
	vm.clock.Set(vm.clock.Time().Add(time.Second))
	b := build(t, vm)
	require.NotEqual(a.ID(), b.ID(), "the two proposals must be distinct blocks")
	require.Equal(a.ParentID_, b.ParentID_)

	require.NoError(a.Verify(ctx))
	require.NoError(b.Verify(ctx))

	require.NoError(a.Accept(ctx))
	require.ErrorIs(b.Accept(ctx), ErrNotOnTip)

	head, err := vm.LastAccepted(ctx)
	require.NoError(err)
	require.Equal(a.ID(), head)
}

// A follower resolves a parent it did not build. Tracking only self-built blocks
// left a node able to verify the first block of a run and unable to verify the
// second, which is the ordinary shape whenever more than one block is in flight.
func TestABlockInFlightCanBeAParent(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	chainID := ids.GenerateTestID()
	proposer := newVM(t, chainID, memdb.New())
	follower := newVM(t, chainID, memdb.New())

	b1 := build(t, proposer)
	proposer.clock.Set(proposer.clock.Time().Add(time.Second))
	require.NoError(b1.Verify(ctx))
	require.NoError(b1.Accept(ctx))
	b2 := build(t, proposer)

	// The follower sees them off the wire, in order, deciding neither yet.
	f1, err := follower.ParseBlock(ctx, b1.Bytes())
	require.NoError(err)
	require.Equal(b1.ID(), f1.ID(), "two nodes of one chain name a block identically")
	require.NoError(f1.Verify(ctx))

	f2, err := follower.ParseBlock(ctx, b2.Bytes())
	require.NoError(err)
	require.Equal(b2.ID(), f2.ID())
	require.NoError(f2.Verify(ctx), "a block whose parent is in flight must still verify")

	require.NoError(f1.Accept(ctx))
	require.NoError(f2.Accept(ctx))
	head, err := follower.LastAccepted(ctx)
	require.NoError(err)
	require.Equal(b2.ID(), head)
}

// A run of blocks in flight has to be a run: each one sits on the one below at
// exactly one less height, or it is not reachable from the tip.
func TestABrokenRunInFlightIsRefused(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	b1 := build(t, vm)
	require.NoError(b1.Verify(ctx))

	// b1 is in flight at height 1. A block naming it as parent at height 3 is
	// asking for a gap nothing fills.
	gap := &Block{ParentID_: b1.ID_, Height_: 3, Timestamp_: vm.clock.Time(), vm: vm}
	require.NoError(gap.name())
	require.ErrorIs(gap.Verify(ctx), ErrInvalidBlock)
}

// -----------------------------------------------------------------------------
// Chain time.
// -----------------------------------------------------------------------------

// Verify bounded the timestamp in neither direction: a stamp a thousand hours
// out verified, and so did one before the parent's.
func TestBlockTimeIsBounded(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	b1 := advance(t, vm)

	future := &Block{ParentID_: b1.ID_, Height_: 2, Timestamp_: vm.clock.Time().Add(1000 * time.Hour), vm: vm}
	require.NoError(future.name())
	require.ErrorIs(future.Verify(ctx), ErrInvalidBlock)

	past := &Block{ParentID_: b1.ID_, Height_: 2, Timestamp_: b1.Timestamp_.Add(-time.Hour), vm: vm}
	require.NoError(past.name())
	require.ErrorIs(past.Verify(ctx), ErrInvalidBlock)

	// Inside the allowance, both directions, is fine.
	ok := &Block{ParentID_: b1.ID_, Height_: 2, Timestamp_: vm.clock.Time().Add(MaxFutureSkew / 2), vm: vm}
	require.NoError(ok.name())
	require.NoError(ok.Verify(ctx))
}

// Chain time never runs backwards, so a proposer whose clock has not moved past
// its parent stamps the parent's time rather than building a block its own
// Verify would refuse.
func TestAStalledClockStillProposes(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	vm.clock.Set(time.Unix(1_700_000_000, 0))
	b1 := advance(t, vm)

	vm.clock.Set(b1.Timestamp_.Add(-time.Second)) // the clock slipped behind its own last block
	b2 := build(t, vm)
	require.Equal(b1.Timestamp_, b2.Timestamp_)
	require.NoError(b2.Verify(ctx))
}

// -----------------------------------------------------------------------------
// One staging layer per block.
// -----------------------------------------------------------------------------

// Every pending block used to write into ONE shared staging layer, and Accept
// committed whatever was in it. Accepting A therefore published the intent that
// only B carried.
func TestAcceptDoesNotCommitASiblingsWork(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	seedOperators(t, vm, oneReward())

	// A carries nothing.
	a := build(t, vm)
	require.NoError(a.Verify(ctx))

	// B carries an intent.
	intent := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())
	vm.EnqueueCommittedIntent(intent)
	b := build(t, vm)
	require.NoError(b.Verify(ctx))
	require.Len(b.ImportedIntents, 1)
	require.Empty(a.ImportedIntents)

	require.NoError(a.Accept(ctx))
	require.False(seen(vm, intent), "accepting A made B's intent durable")
	require.Equal(common.Hash{}, vm.quorum.TaskForIntent(vm.qstate, intent.IntentID))

	// B lost the round; the work it proposed is still available to the next one.
	require.ErrorIs(b.Accept(ctx), ErrNotOnTip)
	require.NoError(b.Reject(ctx))
	next := advance(t, vm)
	require.Len(next.ImportedIntents, 1)
	require.True(seen(vm, intent))
}

// Rejecting a block used to roll back the ONE shared staging layer, taking a
// sibling's writes with it — so Accept(A) after Reject(B) committed nothing at
// all.
func TestRejectingASiblingLeavesTheOtherIntact(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	seedOperators(t, vm, oneReward())

	intent := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())
	vm.EnqueueCommittedIntent(intent)

	a := build(t, vm)
	require.NoError(a.Verify(ctx))
	vm.clock.Set(vm.clock.Time().Add(time.Second))
	b := build(t, vm)
	require.NoError(b.Verify(ctx))
	require.NotEqual(a.ID(), b.ID())

	require.NoError(b.Reject(ctx))
	require.NoError(a.Accept(ctx))
	require.True(seen(vm, intent), "rejecting B discarded A's work")
	require.NotEqual(common.Hash{}, vm.quorum.TaskForIntent(vm.qstate, intent.IntentID))
}

// Verifying a block is a question, not an action. It used to be an action: the
// imports ran against the shared layer, so a block that was checked and lost the
// round had already moved state and value.
func TestVerifyChangesNothing(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	seedOperators(t, vm, oneReward())
	intent := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())
	vm.EnqueueCommittedIntent(intent)

	blk := build(t, vm)
	before := vm.qledger.GetBalance(addrOf(0xF0)).String()
	root := vm.quorum.ReceiptRoot(vm.qstate)

	require.NoError(blk.Verify(ctx))
	require.NoError(blk.Verify(ctx), "verifying twice must reach the same verdict")

	require.False(seen(vm, intent), "Verify consumed the intent")
	require.Equal(before, vm.qledger.GetBalance(addrOf(0xF0)).String())
	require.Equal(root, vm.quorum.ReceiptRoot(vm.qstate))
	require.Equal(common.Hash{}, vm.quorum.TaskForIntent(vm.qstate, intent.IntentID))
}

// Proposing is not consuming. BuildBlock used to drain the buffer, so a proposal
// that never landed destroyed the work it had picked up.
func TestBuildingABlockDoesNotConsumeItsIntents(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	seedOperators(t, vm, oneReward())
	intent := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())
	vm.EnqueueCommittedIntent(intent)

	dropped := build(t, vm)
	require.Len(dropped.ImportedIntents, 1)
	require.NoError(dropped.Reject(ctx)) // the engine abandoned it

	require.Len(vm.pendingIntents, 1, "the buffered intent was thrown away with the proposal")
	landed := advance(t, vm)
	require.Len(landed.ImportedIntents, 1)
	require.True(seen(vm, intent))

	// Once it IS durable, it stops being re-proposed.
	require.Empty(vm.pendingIntents)
	require.Empty(build(t, vm).ImportedIntents)
}

// -----------------------------------------------------------------------------
// One commit per block.
// -----------------------------------------------------------------------------

// Accept used to commit the engine delta FIRST and store the block second. A
// failure between them left the state durable and the block gone: the chain had
// applied a transition it could not name.
func TestAFailedCommitLeavesTheChainWhereItWas(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	db := &breakable{Database: memdb.New()}
	vm := newVM(t, ids.GenerateTestID(), db)
	seedOperators(t, vm, oneReward())

	intent := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())
	vm.EnqueueCommittedIntent(intent)

	genesis := vm.lastAccepted.ID_
	blk := build(t, vm)
	require.NoError(blk.Verify(ctx))

	db.broken.Store(true)
	require.ErrorIs(blk.Accept(ctx), errBroken)
	db.broken.Store(false)

	require.False(seen(vm, intent), "the engine delta outlived the block that carried it")
	_, err := db.Get(blockKey(blk.ID_))
	require.ErrorIs(err, database.ErrNotFound, "a block that did not commit must not be stored")
	_, err = db.Get(heightKey(blk.Height_))
	require.ErrorIs(err, database.ErrNotFound)
	_, err = db.Get(tipKey)
	require.ErrorIs(err, database.ErrNotFound)

	head, err := vm.LastAccepted(ctx)
	require.NoError(err)
	require.Equal(genesis, head, "the chain moved past a block it never committed")

	// Nothing was left staged, so the same block accepts cleanly once the
	// database is back.
	require.NoError(blk.Accept(ctx))
	require.True(seen(vm, intent))
	head, err = vm.LastAccepted(ctx)
	require.NoError(err)
	require.Equal(blk.ID_, head)
}

// The whole block or none of it: after a successful Accept the state, the block,
// the height entry and the tip are all there, and they name each other.
func TestAcceptCommitsTheWholeBlockAtOnce(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	seedOperators(t, vm, oneReward())
	intent := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())
	vm.EnqueueCommittedIntent(intent)

	blk := advance(t, vm)
	require.True(seen(vm, intent))

	raw, err := vm.db.Get(blockKey(blk.ID_))
	require.NoError(err)
	require.Equal(blk.Bytes(), raw)

	at, err := vm.GetBlockIDAtHeight(ctx, blk.Height_)
	require.NoError(err)
	require.Equal(blk.ID_, at)

	tip, err := vm.db.Get(tipKey)
	require.NoError(err)
	require.Equal(blk.ID_[:], tip)

	require.Equal(uint8(1), blk.Status())
	_, err = vm.GetBlockIDAtHeight(ctx, 99)
	require.ErrorIs(err, database.ErrNotFound)
}

// -----------------------------------------------------------------------------
// A block belongs to one chain.
// -----------------------------------------------------------------------------

// A block's id was the hash of its wire and nothing else, so two A-Chains with
// the same genesis timestamp shared a genesis id and a block built on one parsed
// byte-identically on the other — and resolved there as a parent.
func TestABlockDoesNotCrossChains(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	here := newVM(t, ids.GenerateTestID(), memdb.New())
	elsewhere := newVM(t, ids.GenerateTestID(), memdb.New())
	require.NotEqual(here.lastAccepted.ID_, elsewhere.lastAccepted.ID_,
		"two chains shared a genesis id")

	blk := build(t, here)
	foreign, err := elsewhere.ParseBlock(ctx, blk.Bytes())
	require.NoError(err)
	require.NotEqual(blk.ID(), foreign.ID(), "the same bytes named the same block on both chains")

	// And it is not a block the other chain will build on: its parent is a
	// genesis that chain never had.
	require.ErrorIs(foreign.Verify(ctx), ErrNotOnTip)
}

// The other half of the same property: nodes of ONE chain must agree. A test
// that only checked the first half would pass with block ids randomised per
// node, which is a consensus split rather than a fix.
func TestNodesOfOneChainNameBlocksIdentically(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	chainID := ids.GenerateTestID()
	a := newVM(t, chainID, memdb.New())
	b := newVM(t, chainID, memdb.New())
	require.Equal(a.lastAccepted.ID_, b.lastAccepted.ID_)

	blk := build(t, a)
	parsed, err := b.ParseBlock(ctx, blk.Bytes())
	require.NoError(err)
	require.Equal(blk.ID(), parsed.ID())
	require.NoError(parsed.Verify(ctx))
}

// -----------------------------------------------------------------------------
// Concurrency.
// -----------------------------------------------------------------------------

// Read paths run against Shutdown. Run under -race; the assertion is that the
// race detector stays quiet and nothing panics.
func TestReadsRunAlongsideShutdown(t *testing.T) {
	vm := oneVM(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = vm.GetProviders()
				_, _ = vm.HealthCheck(ctx)
				_ = vm.GetMerkleRoot()
				_, _ = vm.LastAccepted(ctx)
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = vm.Shutdown(ctx) }()
	wg.Wait()
}

// -----------------------------------------------------------------------------
// Databases that misbehave.
// -----------------------------------------------------------------------------

var (
	errBroken     = errors.New("test: batch write refused")
	errUnreadable = errors.New("test: database cannot be read")
)

// breakable is a database whose BATCH refuses to write. That is where a commit
// actually fails: versiondb.Commit folds its staged writes into a batch and
// writes that, so a wrapper that only intercepts Put never fires on the path
// under test and the test passes without ever injecting the fault.
type breakable struct {
	database.Database
	broken atomic.Bool
}

func (d *breakable) NewBatch() database.Batch {
	return &breakableBatch{Batch: d.Database.NewBatch(), db: d}
}

type breakableBatch struct {
	database.Batch
	db *breakable
}

func (b *breakableBatch) Write() error {
	if b.db.broken.Load() {
		return errBroken
	}
	return b.Batch.Write()
}

// unreadable fails every read, which is how a closed database or a dead volume
// presents itself.
type unreadable struct{ database.Database }

func (d *unreadable) Get([]byte) ([]byte, error) { return nil, errUnreadable }

// -----------------------------------------------------------------------------
// What a block may record.
// -----------------------------------------------------------------------------

// A proposer chooses what its block records, so it can record the same intent
// more than once. The anti-replay marker is what makes that harmless: the second
// and third copies import into a state that has already consumed the first, so
// one task is created and the receipt root the block claims is the one a
// follower reaches.
func TestAnIntentRecordedTwiceCreatesOneTask(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	seedOperators(t, vm, oneReward())
	intent := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())

	// An honestly-stamped block that happens to name the same intent three times.
	st := newOverlay(vm.qstate)
	root, err := vm.replay(st, newStateLedger(st), []CIntent{intent, intent, intent}, 1)
	require.NoError(err)

	blk := &Block{
		ParentID_:       vm.lastAccepted.ID_,
		Height_:         1,
		Timestamp_:      vm.clock.Time(),
		ImportedIntents: []CIntent{intent, intent, intent},
		ReceiptRoot:     root,
		vm:              vm,
	}
	require.NoError(blk.name())
	require.NoError(blk.Verify(ctx))
	require.NoError(blk.Accept(ctx))

	require.Equal(uint32(1), vm.quorum.LiveTasks(vm.qstate), "one intent recorded three times created more than one task")
	require.True(seen(vm, intent))
}

// A block whose recorded intents do not reproduce the root it claims is refused,
// with no exemption for the zero hash — otherwise the determinism check is
// opt-out and a proposer skips it by stamping zero.
func TestABlockMustReproduceTheRootItClaims(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	seedOperators(t, vm, oneReward())
	intent := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())
	vm.EnqueueCommittedIntent(intent)

	honest := build(t, vm)
	require.NoError(honest.Verify(ctx))

	tampered := *honest
	tampered.ReceiptRoot = hashOf(0xEE)
	require.NoError(tampered.name())
	require.ErrorIs(tampered.Verify(ctx), ErrReceiptRootMismatch)

	// Accept re-checks it, because state can move between the two calls.
	stale := *honest
	stale.ReceiptRoot = hashOf(0xEE)
	stale.ID_, stale.bytes = honest.ID_, honest.bytes // keep it acceptable by lineage
	require.ErrorIs(stale.Accept(ctx), ErrReceiptRootMismatch)

	require.NoError(honest.Accept(ctx))
}

// An intent the verifier will not vouch for creates nothing, and a block that
// records one anyway is refused rather than quietly skipped.
func TestABlockRecordingAnUnvouchedIntentIsRefused(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	seedOperators(t, vm, oneReward())
	intent := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())

	blk := &Block{
		ParentID_:       vm.lastAccepted.ID_,
		Height_:         1,
		Timestamp_:      vm.clock.Time(),
		ImportedIntents: []CIntent{intent},
		vm:              vm,
	}
	require.NoError(blk.name())

	vm.SetCommitVerifier(VerifierFunc(func(CIntent) error { return ErrIntentNotCommitted }))
	require.ErrorIs(blk.Verify(ctx), ErrIntentNotCommitted)

	// And the proposer will not carry one either.
	vm.EnqueueCommittedIntent(intent)
	require.Empty(build(t, vm).ImportedIntents)
}

// -----------------------------------------------------------------------------
// The chain answers about itself.
// -----------------------------------------------------------------------------

// Status is read from what is on disk, not from what the caller hoped. A block
// in flight is processing; one beneath the tip is accepted because its bytes are
// committed, not because anything remembered it.
func TestStatusIsReadFromWhatIsCommitted(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	b1 := build(t, vm)
	require.Equal(uint8(0), b1.Status())
	require.NoError(b1.Verify(ctx))
	require.NoError(b1.Accept(ctx))
	require.Equal(uint8(1), b1.Status())

	b2 := advance(t, vm)
	require.Equal(uint8(1), b2.Status())
	require.Equal(uint8(1), b1.Status(), "a block beneath the tip is still accepted")

	// A block this chain never accepted is not accepted, whatever it says.
	stranger := &Block{ParentID_: b2.ID_, Height_: 3, Timestamp_: vm.clock.Time(), vm: vm}
	require.NoError(stranger.name())
	require.Equal(uint8(0), stranger.Status())

	// GetBlock serves one in flight before it is decided.
	require.NoError(stranger.Verify(ctx))
	got, err := vm.GetBlock(ctx, stranger.ID_)
	require.NoError(err)
	require.Same(stranger, got)
}

// A block with a VM but no encoding was never produced by any path that names
// one, and there is nothing to check it against.
func TestABlockWithNoEncodingIsRefused(t *testing.T) {
	vm := oneVM(t)
	blk := &Block{ParentID_: vm.lastAccepted.ID_, Height_: 1, Timestamp_: vm.clock.Time(), vm: vm}
	require.ErrorIs(t, blk.Verify(context.Background()), ErrInvalidBlock)
}

// A chain with no tip is a chain that does not know where it is, and every
// question about lineage answers that rather than guessing.
func TestAChainWithNoTipAnswersNothing(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	blk := build(t, vm)

	vm.lastAccepted = nil
	vm.flight = map[ids.ID]*Block{}
	require.ErrorIs(blk.Verify(ctx), ErrNotOnTip)
	require.ErrorIs(blk.Accept(ctx), ErrNotOnTip)
	vm.track(blk)
	require.Empty(vm.flight, "a chain with no tip cannot say what is above it")
}

// State can move between Verify and Accept. When it does, the block no longer
// reproduces the root it claims, and Accept refuses rather than persisting a
// state that disagrees with the block the network accepted.
func TestStateMovingBetweenVerifyAndAcceptIsCaught(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	seedOperators(t, vm, oneReward())
	intent := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())
	vm.EnqueueCommittedIntent(intent)

	blk := build(t, vm)
	require.NoError(blk.Verify(ctx))

	// The boundary stops vouching for the intent the block carries.
	vm.SetCommitVerifier(VerifierFunc(func(CIntent) error { return ErrIntentNotCommitted }))
	require.ErrorIs(blk.Accept(ctx), ErrIntentNotCommitted)
	require.False(seen(vm, intent))
	head, err := vm.LastAccepted(ctx)
	require.NoError(err)
	require.Equal(blk.ParentID_, head)
}

// A view that cannot take a write cannot commit one, and the block does not
// happen. The engine writes go through the same view, so this is the same
// failure as a dead volume mid-block.
func TestAViewThatCannotTakeAWriteRefusesTheBlock(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	blk := build(t, vm)
	require.NoError(blk.Verify(ctx))

	require.NoError(vm.view.Close())
	require.ErrorIs(blk.Accept(ctx), database.ErrClosed)
	head, err := vm.LastAccepted(ctx)
	require.NoError(err)
	require.Equal(blk.ParentID_, head)
}

// The tip is the one thing a restart reads before anything else, so every shape
// it can be in has an answer: absent (fresh), genesis (fresh, recorded),
// resolvable (resume), or wrong (refuse).
func TestEveryShapeOfTipHasAnAnswer(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	chainID := ids.GenerateTestID()

	open := func(db database.Database) (*VM, error) {
		vm := &VM{}
		return vm, vm.Initialize(ctx, vmcore.Init{
			Runtime:  &runtime.Runtime{ChainID: chainID, NetworkID: 96369, Log: log.NewNoOpLogger()},
			DB:       db,
			ToEngine: make(chan vmcore.Message, 8),
			Log:      log.NewNoOpLogger(),
			Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
		})
	}

	fresh := memdb.New()
	vm, err := open(fresh)
	require.NoError(err)
	genesis := vm.lastAccepted.ID_

	// A tip that names genesis is a chain that opened and never accepted.
	recorded := memdb.New()
	require.NoError(recorded.Put(tipKey, genesis[:]))
	vm, err = open(recorded)
	require.NoError(err)
	require.Equal(genesis, vm.lastAccepted.ID_)
	require.Equal(uint64(0), vm.lastAccepted.Height_)

	// A tip whose stored bytes are not a block.
	garbled := memdb.New()
	id := ids.GenerateTestID()
	require.NoError(garbled.Put(tipKey, id[:]))
	require.NoError(garbled.Put(blockKey(id), []byte("not a block")))
	_, err = open(garbled)
	require.Error(err)

	// A tip whose stored bytes name a DIFFERENT block: the database belongs to
	// another chain, or the pointer and the payload disagree. Either way it is
	// not a chain to resume.
	swapped := memdb.New()
	real, err := (&Block{ParentID_: genesis, Height_: 1, vm: vm}).named()
	require.NoError(err)
	other := ids.GenerateTestID()
	require.NoError(swapped.Put(tipKey, other[:]))
	require.NoError(swapped.Put(blockKey(other), real.bytes))
	_, err = open(swapped)
	require.ErrorContains(err, "its bytes name")
}

// named encodes a block and hands it back, for tests that need one to exist
// before a VM does.
func (blk *Block) named() (*Block, error) { return blk, blk.name() }
