// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"context"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

// buildTo builds and accepts blocks until the VM's head reaches height h, so a
// test can advance the chain the way the chain advances rather than by calling
// the settlement engine itself.
func buildTo(t *testing.T, vm *VM, h uint64) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 200; i++ {
		head, err := vm.GetBlock(ctx, mustLastAccepted(t, vm))
		require.NoError(t, err)
		if head.Height() >= h {
			return
		}
		blk, err := vm.BuildBlock(ctx)
		require.NoError(t, err, "build block")
		require.NoError(t, blk.Verify(ctx), "verify block")
		require.NoError(t, blk.Accept(ctx), "accept block")
	}
	t.Fatalf("chain did not reach height %d", h)
}

func mustLastAccepted(t *testing.T, vm *VM) ids.ID {
	t.Helper()
	id, err := vm.LastAccepted(context.Background())
	require.NoError(t, err)
	return id
}

// TestATaskSettlesBecauseTheChainAdvanced is what open mining rests on: an
// operator that did the work is paid without anyone asking on its behalf.
//
// The committee commits and reveals, and then nothing else happens except that
// blocks are produced. Past the reveal deadline the verdict is taken, the
// honest majority is credited, and the receipt is folded into the root.
func TestATaskSettlesBecauseTheChainAdvanced(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := newAIVMForFeeTest(t)
	defer vm.Shutdown(ctx)
	vm.SetCommitVerifier(acceptAll)

	e, st, _ := vm.QuorumEngine()
	require.NotNil(e)

	// Fund a requester and a pool of operators, then put one inference intent in.
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	requester := addrOf(0xF0)
	fund := new(uint256.Int).Mul(reward, uint256.NewInt(uint64(consciousN)))
	burn := new(uint256.Int).Mul(RequestFeePerOperator, uint256.NewInt(uint64(consciousN)))
	fund.Add(fund, burn)
	fund.Mul(fund, uint256.NewInt(4))

	opening := map[common.Address]*uint256.Int{requester: fund}
	pool := make([]common.Address, consciousEligible)
	for i := range pool {
		pool[i] = addrOf(byte(0x10 + i))
		opening[pool[i]] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(4))
	}
	vm.FundLedger(opening)

	model := hashOf(0x11)
	for _, op := range pool {
		require.NoError(e.RegisterOperator(st, vm.qledger, op, MinProviderBond, model, hashOf(0x55)))
	}

	intent := buildIntent(e, requester, model, consciousN, consciousThreshold, RequestFeePerOperator, reward)
	vm.EnqueueCommittedIntent(intent)

	// Block 1 imports the intent and creates the task.
	buildTo(t, vm, 1)
	taskID := e.TaskForIntent(st, intent.IntentID)
	require.NotEqual(common.Hash{}, taskID, "the block should have created a task")
	require.Equal(uint32(1), e.LiveTasks(st), "the task should be awaiting a verdict")

	committee, err := e.SelectOperators(st, taskID, model, consciousN)
	require.NoError(err)

	// The committee thinks: everyone commits blind, then reveals the same answer.
	answer, embedding, nonce := hashOf(0x42), hashOf(0x07), hashOf(0x99)
	for _, op := range committee {
		require.NoError(e.CommitResponse(st, taskID, op,
			commitOf(taskID, model, op, answer, embedding, nonce), 2))
	}
	for _, op := range committee {
		require.NoError(e.RevealResponse(st, taskID, op, answer, embedding, nonce, 32))
	}

	// Nothing settles it yet: the reveal window is still open, and an operator
	// that has not answered must still be able to.
	task := readTask(st, taskID)
	buildTo(t, vm, task.RevealDeadline)
	require.Equal(uint32(1), e.LiveTasks(st), "a task settled before its reveal window closed")
	require.False(isSet(st.GetState(slotHash(nsSettled, taskID))))

	before := make([]*uint256.Int, len(committee))
	for i, op := range committee {
		before[i] = new(uint256.Int).Set(readCredit(st, op))
	}

	// One more block, and the window has closed.
	buildTo(t, vm, task.RevealDeadline+1)

	require.True(isSet(st.GetState(slotHash(nsSettled, taskID))),
		"the task passed its reveal deadline and was never settled — the work is unpaid")
	require.Equal(uint32(0), e.LiveTasks(st), "a settled task should no longer be awaiting a verdict")

	paid := 0
	for i, op := range committee {
		if readCredit(st, op).Gt(before[i]) {
			paid++
		}
	}
	require.GreaterOrEqual(paid, int(consciousThreshold),
		"the honest majority answered and was not credited")
}

// The pass is bounded by what is open, not by everything the chain has done: a
// task that reaches a verdict stops being walked.
func TestSettledTasksStopBeingWalked(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := newAIVMForFeeTest(t)
	defer vm.Shutdown(ctx)
	vm.SetCommitVerifier(acceptAll)
	e, st, _ := vm.QuorumEngine()

	// Entries naming tasks that do not exist are dropped rather than retried.
	trackLive(st, hashOf(0xDD))
	trackLive(st, hashOf(0xDE))
	require.Equal(uint32(2), e.LiveTasks(st))

	buildTo(t, vm, 1)
	require.Equal(uint32(0), e.LiveTasks(st),
		"entries naming no task should be dropped, not re-attempted every block")
}
