// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// refusal_test.go walks the engine's refusals: every way a registration, a task,
// a commit, a reveal or a withdrawal can be turned down, and the error each one
// answers with.
//
// The engine is fail-closed by construction — a rejected operation makes NO
// write — so a refusal that returns the wrong error, or returns none at all, is
// how a caller learns the wrong thing about state it cannot see. These are the
// paths a caller actually hits.

import (
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// intentFor builds a correctly-id-bound intent with the fields a test wants to
// vary. buildIntent pins the model and prompt; this does not.
func intentFor(e *Engine, requester common.Address, model, prompt common.Hash, n, threshold uint16, fee, reward *uint256.Int) CIntent {
	cTx, callIdx := h(0x11), uint32(7)
	return CIntent{
		IntentID:          ComputeIntentID(e.CChainID, e.AChainID, cTx, callIdx, requester, model, prompt, n, threshold, fee),
		CChainID:          e.CChainID,
		AChainID:          e.AChainID,
		CTxHash:           cTx,
		CallIndex:         callIdx,
		Caller:            requester,
		ModelSpecHash:     model,
		PromptHash:        prompt,
		N:                 n,
		Threshold:         threshold,
		Fee:               fee,
		RewardPerOperator: reward,
	}
}

// -----------------------------------------------------------------------------
// Registration and stake.
// -----------------------------------------------------------------------------

func TestRegistrationRefusals(t *testing.T) {
	require := require.New(t)
	e := NewEngine(h(1), h(2))
	st := NewMemState()
	op := addr(1)
	lg := NewMemLedger(map[common.Address]*uint256.Int{op: new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))})

	// A registration with no model advertises nothing, so no task could ever
	// select it — and it would sit in the enumeration forever.
	require.ErrorIs(e.RegisterOperator(st, lg, op, MinProviderBond, common.Hash{}, h(1)), ErrEmptyModelSpec)
	// Below the bond there is nothing at risk, which is the whole security claim.
	require.ErrorIs(e.RegisterOperator(st, lg, op, uint256.NewInt(1), modelSpec, h(1)), ErrStakeBelowMin)
	// An operator that cannot fund the bond does not get to skip posting it.
	poor := addr(2)
	require.ErrorIs(e.RegisterOperator(st, NewMemLedger(nil), poor, MinProviderBond, modelSpec, h(1)), ErrInsufficientFunds)
	require.False(e.IsEligible(st, poor, modelSpec))

	require.NoError(e.RegisterOperator(st, lg, op, MinProviderBond, modelSpec, h(1)))
	require.True(e.IsEligible(st, op, modelSpec))
	// One active registration per operator.
	require.ErrorIs(e.RegisterOperator(st, lg, op, MinProviderBond, modelSpec, h(1)), ErrOperatorExists)

	// Deregistering twice is refused, and an unknown operator has nothing to
	// deregister.
	require.ErrorIs(e.DeregisterOperator(st, addr(9), 10), ErrOperatorUnknown)
	require.NoError(e.DeregisterOperator(st, op, 10))
	require.ErrorIs(e.DeregisterOperator(st, op, 10), ErrOperatorUnbonding)
	require.False(e.IsEligible(st, op, modelSpec), "an unbonding operator stops being selectable at once")

	// After the cooldown the bond comes back, and re-registering does not
	// duplicate the enumeration entry.
	_, err := e.WithdrawStake(st, lg, op, 10+UnbondCooldownBlocks)
	require.NoError(err)
	before := modelCount(st, modelSpec)
	require.NoError(e.RegisterOperator(st, lg, op, MinProviderBond, modelSpec, h(1)))
	require.Equal(before, modelCount(st, modelSpec), "re-registration duplicated the enumeration entry")
}

// Eligibility is recomputed from live state, so every reason an operator stops
// being eligible takes effect without anyone rewriting the enumeration.
func TestEligibilityIsRecomputed(t *testing.T) {
	require := require.New(t)
	e := NewEngine(h(1), h(2))
	st := NewMemState()

	ops := make([]common.Address, 4)
	opening := map[common.Address]*uint256.Int{}
	for i := range ops {
		ops[i] = addr(byte(0x10 + i))
		opening[ops[i]] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))
	}
	lg := NewMemLedger(opening)
	for i, op := range ops {
		require.NoError(e.RegisterOperator(st, lg, op, MinProviderBond, modelSpec, h(byte(0x80+i))))
	}
	require.Len(eligibleSet(st, modelSpec), 4)

	// Unbonding drops out.
	require.NoError(e.DeregisterOperator(st, ops[0], 1))
	// Slashed below the bond drops out.
	writeStake(st, ops[1], uint256.NewInt(1))
	// Advertising a different model drops out of THIS model's set.
	st.SetState(opSpecSlot(ops[2]), h(0xEE))

	left := eligibleSet(st, modelSpec)
	require.Equal([]common.Address{ops[3]}, left)
	require.Empty(eligibleSet(st, h(0xDD)), "a model nobody advertises has an empty set")
}

func TestWithdrawRewardsRefusals(t *testing.T) {
	require := require.New(t)
	e := NewEngine(h(1), h(2))
	st := NewMemState()
	op := addr(1)

	_, err := e.WithdrawRewards(st, NewMemLedger(nil), op)
	require.ErrorIs(err, ErrNoCredit)

	// Credit exists but the escrow does not hold it: a hard invariant breach,
	// refused rather than paid out of nothing.
	require.NoError(addCredit(st, op, uint256.NewInt(5)))
	require.Equal("5", e.GetCredit(st, op).String())
	_, err = e.WithdrawRewards(st, NewMemLedger(nil), op)
	require.ErrorIs(err, ErrEscrowUnderflow)
	require.Equal("5", e.GetCredit(st, op).String(), "a failed payout must not zero the credit")

	// Credit arithmetic is fail-closed at the ceiling.
	max := new(uint256.Int).Not(uint256.NewInt(0))
	require.NoError(addCredit(st, addr(2), max))
	require.ErrorIs(addCredit(st, addr(2), uint256.NewInt(1)), ErrCreditOverflow)
	require.Equal(max.String(), e.GetCredit(st, addr(2)).String())
}

// The value arithmetic is one implementation over two stores, so both refuse in
// the same places and neither can drift into paying out of an empty escrow.
func TestCustodyRefusesTheSameWayOnBothStores(t *testing.T) {
	require := require.New(t)
	max := new(uint256.Int).Not(uint256.NewInt(0))
	a, b := addr(1), addr(2)

	for name, lg := range map[string]QuorumLedger{
		"memory": NewMemLedger(nil),
		"state":  newStateLedger(NewMemState()),
	} {
		require.ErrorIs(lg.Pull(a, uint256.NewInt(1)), ErrInsufficientFunds, name)
		require.ErrorIs(lg.Pay(a, uint256.NewInt(1)), ErrEscrowUnderflow, name)

		require.NoError(lg.Credit(a, max), name)
		require.ErrorIs(lg.Credit(a, uint256.NewInt(1)), ErrCreditOverflow, name)
		require.Equal(max.String(), lg.GetBalance(a).String(), name)

		// Escrow at the ceiling cannot take another pull.
		require.NoError(lg.Pull(a, max), name)
		require.NoError(lg.Credit(b, uint256.NewInt(1)), name)
		require.ErrorIs(lg.Pull(b, uint256.NewInt(1)), ErrStakeOverflow, name)

		// Paying out to an account already at the ceiling is refused too.
		c := addr(3)
		require.NoError(lg.Credit(c, max), name)
		require.ErrorIs(lg.Pay(c, uint256.NewInt(1)), ErrCreditOverflow, name)

		require.NoError(lg.Pay(a, uint256.NewInt(7)), name)
		require.Equal("7", lg.GetBalance(a).String(), name)
	}
}

// -----------------------------------------------------------------------------
// Opening a task.
// -----------------------------------------------------------------------------

// Every parameter a task carries is checked before any value moves, so a task
// the engine will not run never costs the requester anything.
func TestTaskParameterRefusals(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, reqr, _ := newHarness(t, eligible, reward)
	fee := RequestFeePerOperator
	escrowed := lg.GetBalance(EscrowAccount).String() // the operators' bonds
	funded := lg.GetBalance(reqr).String()

	open := func(model, prompt common.Hash, n, thr uint16, f, r *uint256.Int) error {
		_, err := e.ImportCommittedIntent(st, lg, acceptAll, intentFor(e, reqr, model, prompt, n, thr, f, r), 100)
		return err
	}

	require.ErrorIs(open(common.Hash{}, h(0xCD), testN, testThr, fee, reward), ErrEmptyModelSpec)
	require.ErrorIs(open(modelSpec, common.Hash{}, testN, testThr, fee, reward), ErrEmptyPromptHash)
	require.ErrorIs(open(modelSpec, h(0xCD), 2, 2, fee, reward), ErrBadN)
	require.ErrorIs(open(modelSpec, h(0xCD), maxN+1, 3, fee, reward), ErrBadN)
	// A threshold below a strict majority is not agreement; above N is unreachable.
	require.ErrorIs(open(modelSpec, h(0xCD), 5, 2, fee, reward), ErrBadThreshold)
	require.ErrorIs(open(modelSpec, h(0xCD), 5, 6, fee, reward), ErrBadThreshold)
	// A reward that cannot be multiplied by N cannot be escrowed.
	max := new(uint256.Int).Not(uint256.NewInt(0))
	require.ErrorIs(open(modelSpec, h(0xCD), testN, testThr, fee, max), ErrRewardOverflow)
	// Nor an escrow the protocol fee cannot be added to: the A-side fee is
	// N*RequestFeePerOperator, not the C-side fee the intent carries.
	require.ErrorIs(open(modelSpec, h(0xCD), testN, testThr, fee,
		new(uint256.Int).Div(max, uint256.NewInt(uint64(testN)))), ErrRewardOverflow)
	// A model nobody advertises has nobody to select.
	require.ErrorIs(open(h(0xDD), h(0xCD), testN, testThr, fee, reward), ErrNotEnoughEligible)
	// A requester who cannot fund escrow plus fee opens nothing.
	require.ErrorIs(open(modelSpec, h(0xCD), testN, testThr, fee, new(uint256.Int).Div(max, uint256.NewInt(64))),
		ErrInsufficientFunds)

	// None of that moved value.
	require.Equal(escrowed, lg.GetBalance(EscrowAccount).String())
	require.Equal(funded, lg.GetBalance(reqr).String())
	require.Equal("0", lg.GetBalance(BurnAddress).String())
	require.Equal(uint32(0), e.LiveTasks(st))

	// The honest shape opens, and burns exactly N fees.
	require.NoError(open(modelSpec, h(0xCD), testN, testThr, fee, reward))
	require.Equal(new(uint256.Int).Mul(fee, uint256.NewInt(uint64(testN))).String(),
		lg.GetBalance(BurnAddress).String())
}

// -----------------------------------------------------------------------------
// Committing and revealing.
// -----------------------------------------------------------------------------

func TestCommitAndRevealRefusals(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, reqr, ops := newHarness(t, eligible, reward)

	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll,
		mkIntent(e, reqr, testN, testThr, RequestFeePerOperator, reward), 100)
	require.NoError(err)
	sel, err := e.SelectOperators(st, taskID, modelSpec, testN)
	require.NoError(err)
	task := readTask(st, taskID)
	out, emb, nonce := h(0x42), h(0x01), h(0x02)

	// A commit has to be a commitment to something.
	require.ErrorIs(e.CommitResponse(st, taskID, sel[0], common.Hash{}, 101), ErrEmptyCommit)
	// To a task that exists,
	require.ErrorIs(e.CommitResponse(st, h(0xDE), sel[0], h(1), 101), ErrTaskUnknown)
	// by an operator the beacon selected,
	unselected := common.Address{}
	for _, op := range ops {
		found := false
		for _, s := range sel {
			found = found || s == op
		}
		if !found {
			unselected = op
			break
		}
	}
	require.NotEqual(common.Address{}, unselected, "the committee must be a strict subset")
	require.ErrorIs(e.CommitResponse(st, taskID, unselected, h(1), 101), ErrNotSelected)
	// before the window closes,
	require.ErrorIs(e.CommitResponse(st, taskID, sel[0], h(1), task.CommitDeadline+1), ErrCommitClosed)
	// and only once.
	c := opCommit(taskID, sel[0], out, emb, nonce)
	require.NoError(e.CommitResponse(st, taskID, sel[0], c, 101))
	require.ErrorIs(e.CommitResponse(st, taskID, sel[0], c, 101), ErrAlreadyCommitted)

	// A reveal has to name an output,
	require.ErrorIs(e.RevealResponse(st, taskID, sel[0], common.Hash{}, emb, nonce, task.RevealDeadline), ErrEmptyOutputHash)
	// on a task that exists,
	require.ErrorIs(e.RevealResponse(st, h(0xDE), sel[0], out, emb, nonce, task.RevealDeadline), ErrTaskUnknown)
	// after a commit,
	require.ErrorIs(e.RevealResponse(st, taskID, sel[1], out, emb, nonce, task.RevealDeadline), ErrNotCommitted)
	// inside the window,
	require.ErrorIs(e.RevealResponse(st, taskID, sel[0], out, emb, nonce, task.CommitDeadline), ErrRevealNotOpen)
	require.ErrorIs(e.RevealResponse(st, taskID, sel[0], out, emb, nonce, task.RevealDeadline+1), ErrRevealClosed)
	// matching what was committed,
	require.ErrorIs(e.RevealResponse(st, taskID, sel[0], h(0xFF), emb, nonce, task.RevealDeadline), ErrCommitMismatch)
	// and only once.
	require.NoError(e.RevealResponse(st, taskID, sel[0], out, emb, nonce, task.RevealDeadline))
	require.ErrorIs(e.RevealResponse(st, taskID, sel[0], out, emb, nonce, task.RevealDeadline), ErrAlreadyRevealed)

	// A settled task takes no further answers.
	for i := 1; i < testThr; i++ {
		require.NoError(e.CommitResponse(st, taskID, sel[i], opCommit(taskID, sel[i], out, emb, nonce), 101))
		require.NoError(e.RevealResponse(st, taskID, sel[i], out, emb, nonce, task.RevealDeadline))
	}
	_, err = e.Settle(st, lg, taskID, task.RevealDeadline+1)
	require.NoError(err)
	require.ErrorIs(e.CommitResponse(st, taskID, sel[0], h(1), 101), ErrTaskNotCommitting)
	require.ErrorIs(e.RevealResponse(st, taskID, sel[0], out, emb, nonce, task.RevealDeadline), ErrTaskNotCommitting)
	_, err = e.Settle(st, lg, taskID, task.RevealDeadline+1)
	require.ErrorIs(err, ErrTaskAlreadySettled)
}

// A receipt can only be exported for an intent that settled.
func TestExportRefusesAnUnsettledIntent(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, reqr, _ := newHarness(t, eligible, reward)

	_, _, _, err := e.ExportReceipt(st, h(0xAB))
	require.ErrorIs(err, ErrReceiptNotFound)

	in := mkIntent(e, reqr, testN, testThr, RequestFeePerOperator, reward)
	_, err = e.ImportCommittedIntent(st, lg, acceptAll, in, 100)
	require.NoError(err)
	_, _, _, err = e.ExportReceipt(st, in.IntentID)
	require.ErrorIs(err, ErrReceiptNotFound, "an imported but unsettled intent has no receipt")
}

// -----------------------------------------------------------------------------
// Small total functions. Each is a rule the whole engine leans on.
// -----------------------------------------------------------------------------

// The margin is a fraction of N with a floor under it, so a small draw still
// gets sampling headroom and a large one gets headroom proportional to itself.
func TestTheMarginIsAFractionWithAFloor(t *testing.T) {
	require := require.New(t)
	require.Equal(RequestMarginFloor, requiredMargin(3), "the floor holds under a small N")
	require.Equal(uint32(4), requiredMargin(8), "half of 8 is above the floor")
	require.Equal(uint32(50), requiredMargin(100))
}

// The tie-break is total and deterministic: every validator has to pick the same
// hash from a tie, or they disagree about the canonical answer.
func TestThePluralityTieBreakIsTotal(t *testing.T) {
	require := require.New(t)

	best, n := plurality([]common.Hash{h(2), h(1), h(2)})
	require.Equal(h(2), best)
	require.Equal(uint32(2), n)

	// A tie goes to the big-endian-smallest hash, both orders.
	a, _ := plurality([]common.Hash{h(9), h(4)})
	b, _ := plurality([]common.Hash{h(4), h(9)})
	require.Equal(h(4), a)
	require.Equal(a, b)

	_, none := plurality(nil)
	require.Equal(uint32(0), none)
}

// The live-task list is walked by index, so removing an entry that is not there
// must be a no-op rather than a swap against nothing.
func TestDroppingAnEntryThatIsNotThereIsANoOp(t *testing.T) {
	require := require.New(t)
	st := NewMemState()
	e := NewEngine(h(1), h(2))

	dropLive(st, 0) // empty list
	require.Equal(uint32(0), e.LiveTasks(st))

	trackLive(st, h(0xAA))
	dropLive(st, 7) // past the end
	require.Equal(uint32(1), e.LiveTasks(st))
	dropLive(st, 0)
	require.Equal(uint32(0), e.LiveTasks(st))
}

// A draw needs more eligible operators than it draws.
func TestADrawNeedsAPoolToDrawFrom(t *testing.T) {
	require := require.New(t)
	e := NewEngine(h(1), h(2))
	st := NewMemState()
	_, err := e.SelectOperators(st, h(1), modelSpec, 3)
	require.ErrorIs(err, ErrNotEnoughEligible)
}

// Export answers only for a settled task, and every way the lookup can fail is
// a refusal rather than a receipt built from whatever was there.
func TestExportRefusesEveryIncompleteLookup(t *testing.T) {
	require := require.New(t)
	e := NewEngine(h(1), h(2))
	st := NewMemState()
	intent := h(0xAB)

	// A receipt index with no task behind it.
	st.SetState(slotHash(nsIntentRcpt, intent), h32(uint256.NewInt(1)))
	_, _, _, err := e.ExportReceipt(st, intent)
	require.ErrorIs(err, ErrReceiptNotFound)

	// A task that exists but never settled.
	st.SetState(slotHash(nsIntentTask, intent), h(0x77))
	_, err = e.reconstructReceipt(st, h(0x77))
	require.ErrorIs(err, ErrTaskUnknown)
	_, _, _, err = e.ExportReceipt(st, intent)
	require.ErrorIs(err, ErrTaskUnknown)
}

// A fee policy is what admits a user task, so a VM without one admits nothing
// rather than everything.
func TestATaskWithNoFeePolicyIsRefused(t *testing.T) {
	require.ErrorContains(t, (&VM{}).gateUserTask(nil), "fee policy not initialized")
}
