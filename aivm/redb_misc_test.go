// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// redb_misc_test.go — Red-B remaining probes: fail-closed default verifier,
// over-slash conservation, threshold==N edge, and createTask-via-import only.

import (
	"context"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/stretchr/testify/require"
)

// PROBE — the VM's DEFAULT commit verifier is fail-closed: before SetCommitVerifier
// installs a real one, NO buffered intent can create a task (importPending drops
// them all).
func TestProbe_DefaultVerifierFailClosed(t *testing.T) {
	require := require.New(t)
	logger := log.NewNoOpLogger()
	rt := &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: logger}
	v := &VM{}
	require.NoError(v.Initialize(context.Background(), vmcore.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	}))
	e, _, _ := v.QuorumEngine()
	// fund + register so the ONLY thing stopping a task is the verifier.
	reqr := addr(0xF0)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	fund := new(uint256.Int).Mul(reward, uint256.NewInt(uint64(testN*100)))
	opening := map[common.Address]*uint256.Int{reqr: fund}
	for i := 0; i < eligible; i++ {
		opening[addr(byte(0x10+i))] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))
	}
	require.NoError(v.FundLedger(opening))
	for i := 0; i < eligible; i++ {
		st2 := v.qstate
		require.NoError(e.RegisterOperator(st2, v.qledger, addr(byte(0x10+i)),
			new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2)), modelSpec, h(byte(0x80+i))))
	}
	intent := mkIntent(e, reqr, testN, testThr, uint256.NewInt(1), reward)
	v.EnqueueCommittedIntent(intent)
	blk, err := v.BuildBlock(context.Background())
	require.NoError(err)
	require.Len(blk.(*Block).ImportedIntents, 0, "default fail-closed verifier admits NO intent")
}

// PROBE — over-slash cannot mint or go negative. Set a withholder's stake BELOW
// SlashPerOperator; the slash floors at remaining stake (pool gets only what was
// there) and stake hits zero, never negative. Conservation holds.
func TestProbe_OverSlashFloors(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, allOps := newHarness(t, eligible, reward)
	totalBefore := lg.Total()

	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)

	out := h(0x42)
	for i := 0; i < testThr; i++ {
		op := selected[i]
		c := opCommit(taskID, op, out, h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
		require.NoError(e.RevealResponse(st, taskID, op, out, h(0x01), h(0x02), 131))
	}
	wh := selected[testThr]
	c := opCommit(taskID, wh, h(0xEE), h(0x01), h(0x02))
	require.NoError(e.CommitResponse(st, taskID, wh, c, 101))

	// Poison the withholder's stake to a tiny amount BELOW SlashPerOperator. (This
	// can happen legitimately after prior slashes.) NOTE: we keep the ledger escrow
	// untouched; this only changes the on-state stake accounting, which can DESYNC
	// the escrow identity if the slash math mishandles the floor.
	tiny := uint256.NewInt(1) // 1 wei, below SlashPerOperator (0.1 token)
	writeStake(st, wh, tiny)

	res, err := e.Settle(st, lg, taskID, 161)
	require.NoError(err)
	require.Equal(TaskSettled, res.Status)
	// Slashed pool can be at most `tiny` (floored).
	require.Equal(tiny.String(), res.Slashed.String(), "slash floored at remaining stake")
	_, _, whStake, _, _ := e.GetOperator(st, wh)
	require.True(whStake.IsZero(), "stake floored to zero, never negative")
	// grand total still conserved (we mutated on-state stake, not the ledger, so the
	// ledger total is invariant regardless).
	require.Equal(totalBefore.String(), lg.Total().String())
	_ = allOps
}

// PROBE — threshold == N (unanimity). All N must reveal the same hash to settle;
// one withhold -> Failed.
func TestProbe_ThresholdEqualsN(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testN /* threshold = N */, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)
	out := h(0x42)
	// only N-1 reveal; last withholds.
	for i := 0; i < testN-1; i++ {
		op := selected[i]
		c := opCommit(taskID, op, out, h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
		require.NoError(e.RevealResponse(st, taskID, op, out, h(0x01), h(0x02), 131))
	}
	last := selected[testN-1]
	c := opCommit(taskID, last, h(0xEE), h(0x01), h(0x02))
	require.NoError(e.CommitResponse(st, taskID, last, c, 101))
	res, err := e.Settle(st, lg, taskID, 161)
	require.NoError(err)
	require.Equal(TaskFailed, res.Status, "unanimity not reached -> Failed")
}

// Settlement is a function of the state and the height, so running the same pass
// twice at the same height must be indistinguishable from running it once. If it
// were not, two nodes that reached a height by different routes — one that ran
// the pass while building and again while accepting — would disagree about who
// was paid, and the receipt root would split them.
func TestASecondSettlePassAtTheSameHeightChangesNothing(t *testing.T) {
	require := require.New(t)

	e := NewEngine(h(1), h(2))
	st := NewMemState()
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	requester := addr(0xF0)
	opening := map[common.Address]*uint256.Int{requester: new(uint256.Int).Mul(reward, uint256.NewInt(64))}
	ops := make([]common.Address, eligible)
	for i := range ops {
		ops[i] = addr(byte(0x10 + i))
		opening[ops[i]] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))
	}
	lg := NewMemLedger(opening)
	for i, op := range ops {
		require.NoError(e.RegisterOperator(st, lg, op, new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2)), modelSpec, h(byte(0x80+i))))
	}
	in := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, in, 1)
	require.NoError(err)
	sel, err := e.SelectOperators(st, taskID, modelSpec, testN)
	require.NoError(err)
	out := h(0x42)
	for i := 0; i < testThr; i++ {
		require.NoError(e.CommitResponse(st, taskID, sel[i], opCommit(taskID, sel[i], out, h(7), h(9)), 2))
		require.NoError(e.RevealResponse(st, taskID, sel[i], out, h(7), h(9), 32))
	}

	total := lg.Total().String()
	first := e.SettleDue(st, lg, 62)
	root := e.ReceiptRoot(st)
	paid := lg.Total().String()

	second := e.SettleDue(st, lg, 62)
	require.Equal(uint32(1), first, "the due task should have been settled once")
	require.Equal(uint32(0), second, "a settled task must not be settled again")
	require.Equal(root, e.ReceiptRoot(st), "a second pass moved the receipt root")
	require.Equal(paid, lg.Total().String(), "a second pass moved value")
	require.Equal(total, paid, "settlement is a transfer, not a mint")
}

// An error is a statement about what happened. Refusing a withdrawal because the
// operator has NOT deregistered used to report "operator is unbonding" — the
// opposite of the truth, and an operator reading it would conclude it had
// already started its cooldown and simply wait.
func TestWithdrawSaysWhichWayItRefused(t *testing.T) {
	require := require.New(t)

	e := NewEngine(h(1), h(2))
	st := NewMemState()
	op := addr(1)
	lg := NewMemLedger(map[common.Address]*uint256.Int{op: new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))})
	require.NoError(e.RegisterOperator(st, lg, op, MinProviderBond, modelSpec, h(1)))

	_, err := e.WithdrawStake(st, lg, op, 100)
	require.ErrorIs(err, ErrOperatorBonded, "a bonded operator was told it was unbonding")

	require.NoError(e.DeregisterOperator(st, op, 100))
	_, err = e.WithdrawStake(st, lg, op, 100)
	require.ErrorIs(err, ErrCooldownActive)

	_, err = e.WithdrawStake(st, lg, addr(2), 100)
	require.ErrorIs(err, ErrOperatorUnknown)

	stake, err := e.WithdrawStake(st, lg, op, 100+UnbondCooldownBlocks)
	require.NoError(err)
	require.Equal(MinProviderBond.String(), stake.String())
}
