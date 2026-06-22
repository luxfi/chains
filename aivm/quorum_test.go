// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// test harness
// ---------------------------------------------------------------------------

func addr(b byte) common.Address {
	var a common.Address
	a[19] = b
	return a
}

func h(b byte) common.Hash {
	var x common.Hash
	x[31] = b
	return x
}

// committed-intent verifier that accepts everything (the proof seam is exercised
// separately by the forged/uncommitted tests).
var acceptAll = VerifierFunc(func(CIntent) error { return nil })
var rejectAll = VerifierFunc(func(CIntent) error { return ErrIntentNotCommitted })

const (
	testN    = 5
	testThr  = 3
	eligible = 8 // > N + requiredMargin(5)=3 -> 8 >= 8, satisfies margin exactly
)

var (
	testCChain = chainIDFromString("c-chain")
	testAChain = chainIDFromString("a-chain")
	modelSpec  = h(0xAB)
	promptHash = h(0xCD)
)

// newHarness builds an engine, in-memory state, and a ledger funded so that the
// requester can pay escrow+fee and each operator can post its bond. Registers
// `nOps` staked operators advertising modelSpec.
func newHarness(t *testing.T, nOps int, reward *uint256.Int) (*Engine, *MemState, *MemLedger, common.Address, []common.Address) {
	t.Helper()
	e := NewEngine(testCChain, testAChain)
	st := NewMemState()

	requester := addr(0xF0)
	// fund requester generously: N*reward + N*fee + slack
	fund := new(uint256.Int).Mul(reward, uint256.NewInt(uint64(testN)))
	fee := new(uint256.Int).Mul(RequestFeePerOperator, uint256.NewInt(uint64(testN)))
	fund.Add(fund, fee)
	fund.Mul(fund, uint256.NewInt(4))

	opening := map[common.Address]*uint256.Int{requester: fund}
	ops := make([]common.Address, nOps)
	for i := 0; i < nOps; i++ {
		ops[i] = addr(byte(0x10 + i))
		opening[ops[i]] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))
	}
	lg := NewMemLedger(opening)

	for i, op := range ops {
		stake := new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2))
		require.NoError(t, e.RegisterOperator(st, lg, op, stake, modelSpec, h(byte(0x80+i))), "register op %d", i)
	}
	return e, st, lg, requester, ops
}

// mkIntent builds a CIntent with a correctly-derived id for the given fields.
func mkIntent(e *Engine, requester common.Address, n, threshold uint16, fee, reward *uint256.Int) CIntent {
	cTx := h(0x11)
	callIdx := uint32(7)
	id := ComputeIntentID(e.CChainID, e.AChainID, cTx, callIdx, requester, modelSpec, promptHash, n, threshold, fee)
	return CIntent{
		IntentID:          id,
		CChainID:          e.CChainID,
		AChainID:          e.AChainID,
		CTxHash:           cTx,
		CallIndex:         callIdx,
		Caller:            requester,
		ModelSpecHash:     modelSpec,
		PromptHash:        promptHash,
		N:                 n,
		Threshold:         threshold,
		Fee:               fee,
		RewardPerOperator: reward,
	}
}

// commitReveal computes the operator-bound commit and the reveal preimage for an
// operator producing `output`.
func opCommit(taskID common.Hash, op common.Address, output, embedding, nonce common.Hash) common.Hash {
	return ComputeCommit(taskID, modelSpec, promptHash, output, embedding, op, nonce)
}

// ---------------------------------------------------------------------------
// FULL LIFECYCLE: import committed intent -> select -> 3 reveal same / 2 withhold
// -> settle -> 3 paid, 2 slashed, value conserved, idempotent, export verifies.
// ---------------------------------------------------------------------------

func TestFullLifecycle(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000) // 1 token
	e, st, lg, requester, allOps := newHarness(t, eligible, reward)

	totalBefore := lg.Total()

	// import a committed C intent -> task created under the verified seam.
	fee := uint256.NewInt(123456) // user-facing C fee (id binding only; A burn is protocol fee)
	intent := mkIntent(e, requester, testN, testThr, fee, reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	require.NotEqual(common.Hash{}, taskID)

	// task is in committing state, N selected, deterministic + reproducible.
	info := e.GetTask(st, taskID)
	require.Equal(TaskCommitting, info.Status)
	require.Equal(uint32(testN), info.N)
	require.Equal(uint32(testThr), info.Threshold)

	// reproducibility: re-derive the selected set independently and match.
	repro, err := e.SelectOperators(st, taskID, modelSpec, testN)
	require.NoError(err)
	require.Len(repro, testN)
	for i, op := range repro {
		require.Equal(op, e.SelectedAt(st, taskID, uint32(i)), "selection index %d", i)
		require.True(e.IsSelected(st, taskID, op))
	}
	selected := repro

	// 3 reveal the SAME output hash; 2 withhold (commit but never reveal).
	majority := h(0x42)
	embedding := h(0x07)
	nonce := h(0x99)

	commitH := uint64(100 + 1) // within commit window (<= commitDeadline=130)
	for i := 0; i < testThr; i++ {
		op := selected[i]
		c := opCommit(taskID, op, majority, embedding, nonce)
		require.NoError(e.CommitResponse(st, taskID, op, c, commitH), "commit winner %d", i)
	}
	withholders := selected[testThr:]
	for i, op := range withholders {
		// withholders DO commit (to be slashable) but will not reveal.
		c := opCommit(taskID, op, h(byte(0xE0+i)), embedding, nonce)
		require.NoError(e.CommitResponse(st, taskID, op, c, commitH), "commit withholder %d", i)
	}

	// reveal window opens strictly after commitDeadline (130). reveal at 131.
	revealH := uint64(131)
	for i := 0; i < testThr; i++ {
		op := selected[i]
		require.NoError(e.RevealResponse(st, taskID, op, majority, embedding, nonce, revealH), "reveal winner %d", i)
	}
	// withholders do nothing.

	// settle after reveal window (revealDeadline=160). settle at 161.
	res, err := e.Settle(st, lg, taskID, 161)
	require.NoError(err)
	require.Equal(TaskSettled, res.Status)
	require.Equal(majority, res.CanonicalHash)
	require.Equal(uint32(testThr), res.WinnerCount)

	// 3 winners each got reward + equal share of slashed pool.
	slashedPool := new(uint256.Int).Mul(SlashPerOperator, uint256.NewInt(uint64(len(withholders))))
	require.Equal(slashedPool, res.Slashed, "slashed pool = 2 * SlashPerOperator")
	for i := 0; i < testThr; i++ {
		op := selected[i]
		cred := e.GetCredit(st, op)
		// reward + floor(pool/3)
		want := new(uint256.Int).Add(reward, new(uint256.Int).Div(slashedPool, uint256.NewInt(uint64(testThr))))
		require.Equal(want, cred, "winner %d credit", i)
	}
	// withholders: stake reduced by SlashPerOperator each.
	for i, op := range withholders {
		_, _, stake, _, _ := e.GetOperator(st, op)
		want := new(uint256.Int).Sub(new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2)), SlashPerOperator)
		require.Equal(want, stake, "withholder %d slashed stake", i)
	}

	// VALUE CONSERVATION: grand total over all accounts unchanged, including the
	// slashed wei (which moved from stake-credit-to-winner inside EscrowAccount)
	// and the burned fee (parked at BurnAddress, still counted).
	require.Equal(totalBefore.String(), lg.Total().String(), "grand total conserved across full lifecycle")

	// escrow-account identity: balance(EscrowAccount) == sum(stake over ALL
	// registered operators) + open escrow + sum(credit). Must include the
	// unselected operators' bonds, which also live in EscrowAccount.
	requireEscrowIdentity(t, e, st, lg, taskID, append(allOps, requester))

	// IDEMPOTENT: re-settle rejected.
	_, err = e.Settle(st, lg, taskID, 162)
	require.ErrorIs(err, ErrTaskAlreadySettled)

	// EXPORT: receipt for the intent verifies under the exported receipt_root,
	// and its canonical encoding byte-matches the shared spec.
	receipt, proof, root, err := e.ExportReceipt(st, intent.IntentID)
	require.NoError(err)
	require.Equal(intent.IntentID, receipt.IntentID)
	require.Equal(taskID, receipt.TaskID)
	require.Equal(StatusCompleted, receipt.Status)
	require.Equal(majority, receipt.CanonicalOutputHash)
	require.Equal(uint16(testN), receipt.N)
	require.Equal(uint16(testThr), receipt.Threshold)

	// receipt_hash verifies under root.
	rh := receipt.Hash()
	require.True(VerifyReceiptProof(rh, proof, root), "exported proof must verify under receipt_root")
	require.Equal(e.ReceiptRoot(st), root)

	// byte-spec: encoding is exactly ReceiptEncodedLen and hash is the exact keccak.
	enc := receipt.Encode()
	require.Len(enc, ReceiptEncodedLen, "receipt encoding must be exactly 355 bytes")
	wantHash := common.BytesToHash(crypto.Keccak256(append([]byte(DomainReceipt), enc...)))
	require.Equal(wantHash, rh, "receipt_hash must equal keccak(DomainReceipt || encoding)")
}

// requireEscrowIdentity asserts balance(EscrowAccount) == sum(stake over the
// given accounts) + open escrow(task) + sum(credit over the given accounts).
func requireEscrowIdentity(t *testing.T, e *Engine, st *MemState, lg *MemLedger, taskID common.Hash, accounts []common.Address) {
	t.Helper()
	sum := uint256.NewInt(0)
	seen := map[common.Address]bool{}
	for _, a := range accounts {
		if seen[a] {
			continue
		}
		seen[a] = true
		_, _, stake, _, _ := e.GetOperator(st, a)
		sum.Add(sum, stake)
		sum.Add(sum, e.GetCredit(st, a))
	}
	open := readUint(st, slotHash(nsTaskEscrow, taskID))
	sum.Add(sum, open)
	require.Equal(t, lg.GetBalance(EscrowAccount).String(), sum.String(), "escrow-account conservation identity")
}

// ---------------------------------------------------------------------------
// NO QUORUM -> Failed + full refund.
// ---------------------------------------------------------------------------

func TestNoQuorumFailedRefund(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	totalBefore := lg.Total()
	reqBalBefore := lg.GetBalance(requester)

	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	selected, err := e.SelectOperators(st, taskID, modelSpec, testN)
	require.NoError(err)

	// All 5 commit but reveal 5 DIFFERENT hashes -> no group reaches threshold 3.
	for i, op := range selected {
		out := h(byte(0x50 + i)) // distinct per operator
		c := opCommit(taskID, op, out, h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
		require.NoError(e.RevealResponse(st, taskID, op, out, h(0x01), h(0x02), 131))
	}

	res, err := e.Settle(st, lg, taskID, 161)
	require.NoError(err)
	require.Equal(TaskFailed, res.Status)
	require.Equal(common.Hash{}, res.CanonicalHash)
	require.Equal(uint32(0), res.WinnerCount)
	require.True(res.Slashed.IsZero(), "no withholders -> nothing slashed")

	// requester refunded the full reward escrow (paid back into credit). The
	// requester's spendable balance dropped by escrow+burn at import; the escrow
	// part is now in credit. Withdraw it and confirm full reward refund.
	refund, err := e.WithdrawRewards(st, lg, requester)
	require.NoError(err)
	wantRefund := new(uint256.Int).Mul(reward, uint256.NewInt(uint64(testN)))
	require.Equal(wantRefund, refund, "failed task refunds full N*reward")

	// only the burned protocol fee is gone from the requester's net worth.
	burned := new(uint256.Int).Mul(RequestFeePerOperator, uint256.NewInt(uint64(testN)))
	netNow := new(uint256.Int).Add(lg.GetBalance(requester), uint256.NewInt(0))
	require.Equal(new(uint256.Int).Sub(reqBalBefore, burned).String(), netNow.String(), "requester loses only the burned fee on a failed task")

	require.Equal(totalBefore.String(), lg.Total().String(), "grand total conserved on no-quorum")

	// failed task still produces a receipt with Status=Failed.
	receipt, proof, root, err := e.ExportReceipt(st, intent.IntentID)
	require.NoError(err)
	require.Equal(StatusFailed, receipt.Status)
	require.Equal(common.Hash{}, receipt.CanonicalOutputHash)
	require.True(VerifyReceiptProof(receipt.Hash(), proof, root))
}

// ---------------------------------------------------------------------------
// reveal-must-match-commit
// ---------------------------------------------------------------------------

func TestRevealMustMatchCommit(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)
	op := selected[0]

	// commit to output A, then try to reveal output B -> mismatch.
	c := opCommit(taskID, op, h(0x42), h(0x01), h(0x02))
	require.NoError(e.CommitResponse(st, taskID, op, c, 101))
	err = e.RevealResponse(st, taskID, op, h(0x43) /* different */, h(0x01), h(0x02), 131)
	require.ErrorIs(err, ErrCommitMismatch)

	// the correct reveal still works.
	require.NoError(e.RevealResponse(st, taskID, op, h(0x42), h(0x01), h(0x02), 131))
}

// ---------------------------------------------------------------------------
// non-selected operator cannot commit
// ---------------------------------------------------------------------------

func TestNonSelectedCannotCommit(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, ops := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)

	// find an eligible operator that was NOT selected.
	var notSelected common.Address
	found := false
	for _, op := range ops {
		if !e.IsSelected(st, taskID, op) {
			notSelected = op
			found = true
			break
		}
	}
	require.True(found, "with E=8 > N=5 there must be an unselected eligible op")

	c := opCommit(taskID, notSelected, h(0x42), h(0x01), h(0x02))
	err = e.CommitResponse(st, taskID, notSelected, c, 101)
	require.ErrorIs(err, ErrNotSelected)
}

// ---------------------------------------------------------------------------
// eligible-set margin rejection
// ---------------------------------------------------------------------------

func TestEligibleSetMarginRejection(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	// Only register N operators (E == N) -> margin (E >= N + requiredMargin) fails.
	// requiredMargin(5) = max(RequestMarginFloor=2, 5*5000/10000=2) = 2, so the
	// pool must be E >= 7; with E == 5 the task is rejected.
	e, st, lg, requester, _ := newHarness(t, testN, reward)
	require.Equal(uint32(2), requiredMargin(testN))
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	_, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.ErrorIs(err, ErrEligibleBelowMargin)
}

// ---------------------------------------------------------------------------
// slash fires on withhold (focused)
// ---------------------------------------------------------------------------

func TestSlashFiresOnWithhold(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)

	// 4 commit+reveal same, 1 commits but withholds.
	out := h(0x42)
	for i := 0; i < 4; i++ {
		op := selected[i]
		c := opCommit(taskID, op, out, h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
		require.NoError(e.RevealResponse(st, taskID, op, out, h(0x01), h(0x02), 131))
	}
	withholder := selected[4]
	c := opCommit(taskID, withholder, h(0xEE), h(0x01), h(0x02))
	require.NoError(e.CommitResponse(st, taskID, withholder, c, 101))

	_, _, stakeBefore, _, _ := e.GetOperator(st, withholder)
	res, err := e.Settle(st, lg, taskID, 161)
	require.NoError(err)
	require.Equal(TaskSettled, res.Status)
	require.Equal(SlashPerOperator, res.Slashed, "exactly one withholder slashed")

	_, _, stakeAfter, _, _ := e.GetOperator(st, withholder)
	require.Equal(new(uint256.Int).Sub(stakeBefore, SlashPerOperator), stakeAfter, "withholder stake reduced by SlashPerOperator")
}

// ---------------------------------------------------------------------------
// dissenters are NOT slashed
// ---------------------------------------------------------------------------

func TestDissentersNotSlashed(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)

	// 3 reveal majority, 2 reveal a DIFFERENT (minority) hash -> dissenters, all revealed.
	maj := h(0x42)
	min := h(0x43)
	for i := 0; i < 3; i++ {
		op := selected[i]
		c := opCommit(taskID, op, maj, h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
		require.NoError(e.RevealResponse(st, taskID, op, maj, h(0x01), h(0x02), 131))
	}
	for i := 3; i < 5; i++ {
		op := selected[i]
		c := opCommit(taskID, op, min, h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
		require.NoError(e.RevealResponse(st, taskID, op, min, h(0x01), h(0x02), 131))
	}

	res, err := e.Settle(st, lg, taskID, 161)
	require.NoError(err)
	require.Equal(TaskSettled, res.Status)
	require.Equal(maj, res.CanonicalHash)
	require.True(res.Slashed.IsZero(), "dissenters who revealed are NOT slashed (default policy)")

	// dissenters keep full stake.
	for i := 3; i < 5; i++ {
		_, _, stake, _, _ := e.GetOperator(st, selected[i])
		require.Equal(new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2)), stake, "dissenter %d keeps stake", i)
	}
}

// ---------------------------------------------------------------------------
// IMPORT SEAM: forged (tampered) intent cannot create a task.
// ---------------------------------------------------------------------------

func TestForgedIntentRejected(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)

	// build a valid intent, then TAMPER a field WITHOUT recomputing the id.
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	intent.N = testN + 1 // attacker wants a different draw; id no longer matches

	_, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.ErrorIs(err, ErrIntentIDMismatch, "tampered intent must fail id binding even with accept-all verifier")

	// tamper threshold instead.
	intent2 := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	intent2.Threshold = testN
	_, err = e.ImportCommittedIntent(st, lg, acceptAll, intent2, 100)
	require.ErrorIs(err, ErrIntentIDMismatch)

	// tamper caller (impersonation).
	intent3 := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	intent3.Caller = addr(0xBE)
	_, err = e.ImportCommittedIntent(st, lg, acceptAll, intent3, 100)
	require.ErrorIs(err, ErrIntentIDMismatch)
}

// ---------------------------------------------------------------------------
// IMPORT SEAM: uncommitted intent (proof rejects) cannot create a task even with
// a perfectly-formed id.
// ---------------------------------------------------------------------------

func TestUncommittedIntentRejected(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)

	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward) // valid id
	_, err := e.ImportCommittedIntent(st, lg, rejectAll, intent, 100)
	require.ErrorIs(err, ErrIntentNotCommitted, "valid id but unproven commitment -> no task")

	// no task, no state change: the intent id is not marked seen.
	require.False(isSet(st.GetState(slotHash(nsIntentSeen, intent.IntentID))))
}

// ---------------------------------------------------------------------------
// IMPORT SEAM: cross-deployment replay (wrong chain ids) rejected.
// ---------------------------------------------------------------------------

func TestCrossChainReplayRejected(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)

	// intent built for a DIFFERENT a-chain id.
	other := NewEngine(testCChain, chainIDFromString("other-a-chain"))
	intent := mkIntent(other, requester, testN, testThr, uint256.NewInt(1), reward)
	_, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.ErrorIs(err, ErrIntentIDMismatch, "intent for another a-chain cannot be replayed here")
}

// ---------------------------------------------------------------------------
// IMPORT SEAM: same committed intent cannot create two tasks (anti-replay).
// ---------------------------------------------------------------------------

func TestIntentReplayRejected(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)

	_, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	_, err = e.ImportCommittedIntent(st, lg, acceptAll, intent, 101)
	require.ErrorIs(err, ErrIntentAlreadyUsed)
}

// ---------------------------------------------------------------------------
// stake/bond enforcement
// ---------------------------------------------------------------------------

func TestBondEnforcement(t *testing.T) {
	require := require.New(t)
	e := NewEngine(testCChain, testAChain)
	st := NewMemState()
	op := addr(0x10)
	lg := NewMemLedger(map[common.Address]*uint256.Int{op: new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2))})

	// below bond -> rejected, no funds moved.
	belowBond := new(uint256.Int).Sub(MinProviderBond, uint256.NewInt(1))
	err := e.RegisterOperator(st, lg, op, belowBond, modelSpec, h(0x80))
	require.ErrorIs(err, ErrStakeBelowMin)
	require.True(lg.GetBalance(EscrowAccount).IsZero(), "no bond pulled on rejected register")

	// exactly bond -> ok, bond locked in escrow.
	require.NoError(e.RegisterOperator(st, lg, op, MinProviderBond, modelSpec, h(0x80)))
	require.Equal(MinProviderBond, lg.GetBalance(EscrowAccount))
	require.True(e.IsEligible(st, op, modelSpec))

	// double register -> rejected.
	require.ErrorIs(e.RegisterOperator(st, lg, op, MinProviderBond, modelSpec, h(0x80)), ErrOperatorExists)
}

// ---------------------------------------------------------------------------
// unstake: deregister -> cooldown -> withdraw
// ---------------------------------------------------------------------------

func TestUnstakeCooldown(t *testing.T) {
	require := require.New(t)
	e := NewEngine(testCChain, testAChain)
	st := NewMemState()
	op := addr(0x10)
	lg := NewMemLedger(map[common.Address]*uint256.Int{op: new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2))})
	require.NoError(e.RegisterOperator(st, lg, op, MinProviderBond, modelSpec, h(0x80)))

	// cannot withdraw before deregister.
	_, err := e.WithdrawStake(st, lg, op, 1000)
	require.ErrorIs(err, ErrOperatorUnbonding)

	require.NoError(e.DeregisterOperator(st, op, 100))
	require.False(e.IsEligible(st, op, modelSpec), "unbonding op is ineligible immediately")

	// cooldown not elapsed.
	_, err = e.WithdrawStake(st, lg, op, 100+UnbondCooldownBlocks-1)
	require.ErrorIs(err, ErrCooldownActive)

	// after cooldown: bond returned.
	got, err := e.WithdrawStake(st, lg, op, 100+UnbondCooldownBlocks)
	require.NoError(err)
	require.Equal(MinProviderBond, got)
	require.Equal(new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2)), lg.GetBalance(op), "bond fully returned")
	require.True(lg.GetBalance(EscrowAccount).IsZero())
}

// ---------------------------------------------------------------------------
// beacon determinism: same task_id -> same selection, every time, any caller.
// ---------------------------------------------------------------------------

func TestBeaconDeterministic(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)

	a, err := e.SelectOperators(st, taskID, modelSpec, testN)
	require.NoError(err)
	b, err := e.SelectOperators(st, taskID, modelSpec, testN)
	require.NoError(err)
	require.Equal(a, b, "beacon must be deterministic")

	// and it matches what createTask recorded.
	for i, op := range a {
		require.Equal(op, e.SelectedAt(st, taskID, uint32(i)))
	}
}
