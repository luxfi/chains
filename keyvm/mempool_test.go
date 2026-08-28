// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
)

// TestGappedNonceCannotWedgeBlockProduction is the regression test for the
// admission/consensus split. Admission used to accept ANY nonce above the
// committed one while Verify demanded exactly committed+1. The consequence was
// not a lost transaction, it was a free and permanent halt: one gapped
// transaction from any funded account entered the mempool, BuildBlock drained
// it into a block along with everyone else's valid work, Verify refused the
// whole block, Reject handed the same transactions back, and the next build
// produced the same doomed block forever.
//
// The chain must survive it. Whichever way the gapped transaction gets in, the
// honest work behind it still reaches a block and that block still verifies.
func TestGappedNonceCannotWedgeBlockProduction(t *testing.T) {
	attacker, honest := newTestKey(t), newTestKey(t)
	vm := newTestVM(t, map[string]uint64{
		attacker.hexAddr(): 1_000_000_000, honest.hexAddr(): 1_000_000_000,
	})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	// Admission now refuses the gap outright — the same answer Verify gives.
	gapped := registerTx(t, attacker, "gap", 300_000, 9)
	_, err := vm.SubmitTx(gapped)
	require.ErrorIs(t, err, ErrBadNonce, "admission and consensus must agree on a nonce")

	// Force it into the mempool anyway, as a peer relay or a future code path
	// could. Block assembly is the second line: it drops what it cannot build.
	vm.mempoolLock.Lock()
	vm.mempool = append(vm.mempool, gapped)
	vm.mempoolLock.Unlock()

	_, err = vm.SubmitTx(registerTx(t, honest, "work", 300_000, 1))
	require.NoError(t, err)

	blk, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.Len(t, blk.(*Block).transactions, 1, "the unbuildable transaction is dropped, not carried")
	require.NoError(t, blk.Verify(ctx), "a block this node built must verify")
	require.NoError(t, blk.Accept(ctx))

	_, ok := vm.KeyByName("work")
	require.True(t, ok, "honest work must not be held hostage by one bad transaction")

	// And the poison is gone rather than requeued: the next build has nothing.
	_, err = vm.BuildBlock(ctx)
	require.ErrorIs(t, err, errNoPendingTxs)
}

// TestBuiltBlockAlwaysVerifies is the invariant behind the fix, stated directly:
// assembly and consensus judge a transaction by the SAME predicate, so a block
// this node builds is never a block this node refuses. It holds even when the
// mempool is full of transactions that individually cannot be applied.
func TestBuiltBlockAlwaysVerifies(t *testing.T) {
	good, broke, stranger := newTestKey(t), newTestKey(t), newTestKey(t)
	vm := newTestVM(t, map[string]uint64{
		good.hexAddr():     1_000_000_000,
		broke.hexAddr():    1_000, // funded far below one operation
		stranger.hexAddr(): 1_000_000_000,
	})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	// A key only `good` may administer.
	acceptOne(t, vm, registerTx(t, good, "owned", 300_000, 1))

	// Now stuff the mempool by hand with four kinds of unbuildable work plus one
	// good transaction: unaffordable, unauthorized, gapped, and under-metered.
	unaffordable := registerTx(t, broke, "poor", 300_000, 1)

	unauthorized := &Transaction{
		Type: TxRevokeKey, Payer: stranger.addr, KeyID: deriveKeyID("owned"),
		GasLimit: 300_000, Nonce: 1, Payload: mustJSON(t, RevokePayload{}),
	}
	stranger.sign(t, unauthorized)

	gapped := registerTx(t, stranger, "gap", 300_000, 44)

	starved := registerTx(t, stranger, "starved", 1, 1) // gas limit of 1

	survivor := registerTx(t, good, "survivor", 300_000, 2)

	vm.mempoolLock.Lock()
	vm.mempool = []*Transaction{unaffordable, unauthorized, gapped, starved, survivor}
	vm.mempoolLock.Unlock()

	blk, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	txs := blk.(*Block).transactions
	require.Len(t, txs, 1)
	require.Equal(t, survivor.ID(), txs[0].ID())
	require.NoError(t, blk.Verify(ctx), "assembly and consensus must never disagree")
	require.NoError(t, blk.Accept(ctx))
}

// TestPayerMayPipelineNonces proves the nonce rule does not cost a payer a block
// per transaction: several transactions from one payer, submitted back to back
// before any of them lands, all enter the same block in order. Admission judges
// each against the backlog it will actually sit behind.
func TestPayerMayPipelineNonces(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 10_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	for n := uint64(1); n <= 4; n++ {
		_, err := vm.SubmitTx(registerTx(t, k, string(rune('a'+n)), 300_000, n))
		require.NoError(t, err, "nonce %d must queue behind its predecessors", n)
	}
	// The next one after the queue is still refused if it skips.
	_, err := vm.SubmitTx(registerTx(t, k, "skip", 300_000, 6))
	require.ErrorIs(t, err, ErrBadNonce)

	blk, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.Len(t, blk.(*Block).transactions, 4)
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))
	require.Equal(t, uint64(4), vm.nonceOf(k.addr), "all four nonces are consumed, in order")
}

// TestAdmissionRefusesWhatTheBacklogCannotAfford proves the running per-payer
// spend is carried across the mempool too: a payer with funds for two operations
// cannot queue three.
func TestAdmissionRefusesWhatTheBacklogCannotAfford(t *testing.T) {
	k := newTestKey(t)
	// Equal-length names so all three transactions price identically.
	one, err := FeeFor(registerTx(t, k, "aaa", 300_000, 1))
	require.NoError(t, err)

	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 2 * one})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	_, err = vm.SubmitTx(registerTx(t, k, "aaa", 300_000, 1))
	require.NoError(t, err)
	_, err = vm.SubmitTx(registerTx(t, k, "bbb", 300_000, 2))
	require.NoError(t, err)
	_, err = vm.SubmitTx(registerTx(t, k, "ccc", 300_000, 3))
	require.ErrorIs(t, err, fee.ErrInsufficientFunds,
		"a payer must not queue more than its balance covers")
}

// TestUnderMeteredTxRefusedAtEveryLayer proves the gas limit is enforced by the
// SAME function everywhere. A payer that signs a limit below the operation's
// real cost is refused at admission, at assembly and in consensus — settlement
// can never be reached with a number nobody checked.
func TestUnderMeteredTxRefusedAtEveryLayer(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	full := registerTx(t, k, "metered", 300_000, 1)
	needed, err := GasFor(full)
	require.NoError(t, err)

	starved := registerTx(t, k, "metered", uint64(needed)-1, 1)
	_, err = vm.SubmitTx(starved)
	require.ErrorIs(t, err, fee.ErrOutOfGas)

	blk := blockAt(vm, vm.lastAccepted, 1, vm.clock.Time(), starved)
	require.ErrorIs(t, blk.Verify(context.Background()), fee.ErrOutOfGas)
	require.ErrorIs(t, blk.Accept(context.Background()), fee.ErrOutOfGas)

	// Exactly the needed limit is enough — the refusal is about the number, not
	// about a margin nobody declared.
	exact := registerTx(t, k, "metered", uint64(needed), 1)
	_, err = vm.SubmitTx(exact)
	require.NoError(t, err)
}

// TestNoWorkNoBlock proves the VM refuses to produce an empty block, both with
// an empty mempool and with a mempool whose every transaction is dropped.
func TestNoWorkNoBlock(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	_, err := vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errNoPendingTxs)

	vm.mempoolLock.Lock()
	vm.mempool = []*Transaction{registerTx(t, k, "doomed", 300_000, 77)}
	vm.mempoolLock.Unlock()
	_, err = vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errNoPendingTxs, "a mempool of only-droppable work yields no block")
}

// TestBuildRefusesWithoutAParent proves block assembly fails closed when the
// chain has no tip to extend, and hands the work back rather than losing it.
func TestBuildRefusesWithoutAParent(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	_, err := vm.SubmitTx(registerTx(t, k, "parentless", 300_000, 1))
	require.NoError(t, err)

	vm.stateLock.Lock()
	vm.lastBlock = nil
	vm.stateLock.Unlock()

	_, err = vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errNoParentBlock)
	require.Len(t, vm.mempool, 1, "work must be returned, not dropped, when the chain cannot build")
}

// TestBlockTimeNeverGoesBackwards proves the proposer clamps its own clock to
// the parent, so a node whose clock has slipped still produces a verifiable
// block instead of one its own Verify would refuse.
func TestBlockTimeNeverGoesBackwards(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 10_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	vm.clock.Set(genesisTime.Add(time.Hour))
	acceptOne(t, vm, registerTx(t, k, "first", 300_000, 1))
	tip := vm.lastBlock.timestamp

	// The node's clock slips an hour backwards.
	vm.clock.Set(genesisTime)
	_, err := vm.SubmitTx(registerTx(t, k, "second", 300_000, 2))
	require.NoError(t, err)
	blk, err := vm.BuildBlock(ctx)
	require.NoError(t, err)

	require.False(t, blk.Timestamp().Before(tip), "a proposer must not stamp before its parent")
	require.NoError(t, blk.Verify(ctx), "the clamped block must verify on this very node")
	require.NoError(t, blk.Accept(ctx))
}
