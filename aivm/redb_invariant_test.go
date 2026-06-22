// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// redb_invariant_test.go — Red-B conservation invariant under adversarial
// INTERLEAVING of many tasks, registrations, slashes, withdrawals. Asserts the
// escrow-account identity and grand-total at EVERY step. This is the strongest
// evidence for value conservation including slashed wei.

import (
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// invHarness tracks every account the engine could custody so the identity can be
// recomputed exactly at any step.
type invHarness struct {
	e   *Engine
	st  *MemState
	lg  *MemLedger
	all map[common.Address]bool // every operator + requester ever seen
}

func (ih *invHarness) note(a common.Address) { ih.all[a] = true }

// check asserts balance(EscrowAccount) == Σstake + Σcredit + Σ(open task escrow)
// over ALL known accounts and ALL known tasks, plus grand-total is whatever the
// caller passes as the constant.
func (ih *invHarness) check(t *testing.T, openTasks []common.Hash, grandTotal *uint256.Int) {
	t.Helper()
	sum := uint256.NewInt(0)
	for a := range ih.all {
		_, _, stake, _, _ := ih.e.GetOperator(ih.st, a)
		sum.Add(sum, stake)
		sum.Add(sum, ih.e.GetCredit(ih.st, a))
	}
	for _, tid := range openTasks {
		sum.Add(sum, readUint(ih.st, slotHash(nsTaskEscrow, tid)))
	}
	require.Equal(t, ih.lg.GetBalance(EscrowAccount).String(), sum.String(),
		"escrow identity must hold at this step")
	require.Equal(t, grandTotal.String(), ih.lg.Total().String(), "grand total constant")
}

func TestInvariant_InterleavedTasks(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)

	e := NewEngine(testCChain, testAChain)
	st := NewMemState()

	// Two requesters, a generous pool of operators.
	reqA := addr(0xF0)
	reqB := addr(0xF1)
	nOps := 12
	opening := map[common.Address]*uint256.Int{
		reqA: new(uint256.Int).Mul(reward, uint256.NewInt(1000)),
		reqB: new(uint256.Int).Mul(reward, uint256.NewInt(1000)),
	}
	ops := make([]common.Address, nOps)
	for i := 0; i < nOps; i++ {
		ops[i] = addr(byte(0x10 + i))
		opening[ops[i]] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(5))
	}
	lg := NewMemLedger(opening)
	ih := &invHarness{e: e, st: st, lg: lg, all: map[common.Address]bool{}}
	ih.note(reqA)
	ih.note(reqB)

	grand := lg.Total()

	// register all operators, checking the identity after each.
	for i, op := range ops {
		ih.note(op)
		require.NoError(e.RegisterOperator(st, lg, op, new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3)), modelSpec, h(byte(0x80+i))))
		ih.check(t, nil, grand)
	}

	open := []common.Hash{}

	mkAndRun := func(req common.Address, nonceTweak byte, settleH uint64, makeQuorum bool) common.Hash {
		intent := mkIntent(e, req, testN, testThr, uint256.NewInt(uint64(nonceTweak)+1), reward)
		// distinct cTx per call so intent ids differ.
		intent.CTxHash = h(nonceTweak)
		intent.IntentID = ComputeIntentID(e.CChainID, e.AChainID, intent.CTxHash, intent.CallIndex, req, modelSpec, promptHash, testN, testThr, intent.Fee)
		taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
		require.NoError(err)
		open = append(open, taskID)
		ih.check(t, open, grand)

		selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)
		out := h(0x42)
		nRev := testThr
		if !makeQuorum {
			nRev = testThr - 1 // sub-threshold -> Failed
		}
		for i := 0; i < nRev; i++ {
			op := selected[i]
			c := opCommit(taskID, op, out, h(0x01), h(0x02))
			require.NoError(e.CommitResponse(st, taskID, op, c, 101))
			require.NoError(e.RevealResponse(st, taskID, op, out, h(0x01), h(0x02), 131))
			ih.check(t, open, grand)
		}
		// the rest withhold (commit only) to create a slashed pool.
		for i := nRev; i < testN; i++ {
			op := selected[i]
			c := opCommit(taskID, op, h(byte(0xE0+i)), h(0x01), h(0x02))
			require.NoError(e.CommitResponse(st, taskID, op, c, 101))
			ih.check(t, open, grand)
		}
		res, err := e.Settle(st, lg, taskID, settleH)
		require.NoError(err)
		if makeQuorum {
			require.Equal(TaskSettled, res.Status)
		} else {
			require.Equal(TaskFailed, res.Status)
		}
		// task escrow is drained at settle; remove from open set.
		for i, x := range open {
			if x == taskID {
				open = append(open[:i], open[i+1:]...)
				break
			}
		}
		ih.check(t, open, grand)
		return taskID
	}

	// Interleave: quorum, failed, quorum from the other requester, etc.
	mkAndRun(reqA, 0x01, 161, true)
	mkAndRun(reqB, 0x02, 161, false)
	mkAndRun(reqA, 0x03, 161, true)
	mkAndRun(reqB, 0x04, 161, true)

	// Now interleave withdrawals: some operators withdraw rewards, some deregister
	// and unbond, checking the identity after each.
	for _, op := range ops {
		if !e.GetCredit(st, op).IsZero() {
			_, err := e.WithdrawRewards(st, lg, op)
			require.NoError(err)
			ih.check(t, open, grand)
		}
	}
	// requesters withdraw refunds.
	for _, r := range []common.Address{reqA, reqB} {
		if !e.GetCredit(st, r).IsZero() {
			_, err := e.WithdrawRewards(st, lg, r)
			require.NoError(err)
			ih.check(t, open, grand)
		}
	}
	// deregister + withdraw a few operators (cooldown elapsed).
	for i := 0; i < 4; i++ {
		op := ops[i]
		require.NoError(e.DeregisterOperator(st, op, 500))
		ih.check(t, open, grand)
		_, err := e.WithdrawStake(st, lg, op, 500+UnbondCooldownBlocks)
		require.NoError(err)
		ih.check(t, open, grand)
	}

	// Final identity + grand total.
	ih.check(t, open, grand)
}
