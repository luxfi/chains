// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// settlement.go is the heart of the engine: Settle finalizes a task after its
// reveal window closes. It tallies revealers by output_hash, applies the quorum
// rule, pays winners from the reward escrow, slashes withholders, emits the
// cross-chain AInferenceReceipt, folds it into the running receipt_root, and
// flips the task to Settled or Failed.
//
// Quorum rule (block height > revealDeadline):
//   - plurality group size >= threshold: canonical := that group's hash; each
//     winner is paid rewardPerOperator from escrow PLUS an equal share of the
//     slashed pool (honest-majority bonus); withholders (selected & committed
//     but never revealed) are slashed; dissenters (revealed a minority hash) are
//     NOT slashed (honest-minority / nondeterministic-model plausible; slashing
//     them enables majority-cartel griefing). Task -> Settled, receipt Completed.
//   - no group reaches threshold: task -> Failed; the requester's full remaining
//     escrow is refunded; withholders are still slashed and that wei is credited
//     to the requester (compensation). Revealers keep their stake. receipt Failed.
//
// Settle is IDEMPOTENT: a settled marker makes a second call a no-op error, so
// it is replay-safe across re-execution.
//
// Money custody: bonded stake and reward escrow both live at EscrowAccount; all
// movement is balance mutation (Pull/Pay) — no value-bearing call, no reentrancy
// surface. Every path is uint256 with checked overflow/underflow; a rejected op
// makes NO state change (fail-closed). Slashed wei is NOT moved out of
// EscrowAccount (it was already bonded there) — it is reassigned from "stake" to
// "credit" inside the same account, so the conservation identity
// balance(EscrowAccount) == sum(stake)+sum(open escrow)+sum(credit) holds across
// the slash, and the grand total over all accounts is constant.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// SettleResult is the outcome of Settle, returned for callers + tests.
type SettleResult struct {
	Status        TaskState     // TaskSettled or TaskFailed
	CanonicalHash common.Hash   // winning output_hash (zero if Failed)
	WinnerCount   uint32        // size of the winning group (0 if Failed)
	Paid          *uint256.Int  // total wei paid out as rewards (0 if Failed)
	Slashed       *uint256.Int  // total wei slashed from withholders
	Receipt       AInferenceReceipt // the emitted cross-chain receipt
	ReceiptHash   common.Hash   // keccak(DomainReceipt || encoding)
	ReceiptRoot   common.Hash   // receipt_root AFTER folding this receipt
}

// Settle finalizes a task. height must be > revealDeadline. Idempotent.
func (e *Engine) Settle(st QuorumState, lg QuorumLedger, taskID common.Hash, height uint64) (SettleResult, error) {
	settledSlot := slotHash(nsSettled, taskID)
	if isSet(st.GetState(settledSlot)) {
		return SettleResult{}, ErrTaskAlreadySettled
	}
	task := readTask(st, taskID)
	if task.Status == TaskNone {
		return SettleResult{}, ErrTaskUnknown
	}
	if task.Status != TaskCommitting {
		return SettleResult{}, ErrTaskAlreadySettled
	}
	if height <= task.RevealDeadline {
		return SettleResult{}, ErrSettleTooEarly
	}

	reward := new(uint256.Int).SetBytes(st.GetState(slotHash(nsTaskReward, taskID)).Bytes())
	escrow := new(uint256.Int).SetBytes(st.GetState(slotHash(nsTaskEscrow, taskID)).Bytes())
	feePaid := new(uint256.Int).SetBytes(st.GetState(slotHash(nsTaskFee, taskID)).Bytes())

	revealers, hashes := tally(st, taskID)
	canonical, winnerSize := plurality(hashes)

	res := SettleResult{Paid: uint256.NewInt(0), Slashed: uint256.NewInt(0)}
	var winners []common.Address

	// ATOMICITY CONTRACT: Settle must be all-or-nothing. The substrate is NOT
	// transactional, so we PLAN the entire settlement as pure reads (no writes,
	// cannot fail), validate every overflow/underflow up front, and only then
	// APPLY (infallible writes). A planning failure returns with ZERO state change
	// (true fail-closed); a planned settlement always runs to completion, so the
	// settled marker can never be left unset after a partial mutation — closing the
	// half-settle re-settle / double-slash hole.

	// Pure dry-run of the slash policy: who is slashed, by how much, and the pool —
	// computed without mutating any stake (applied later in the infallible phase).
	plan, slashedPool := planSlash(st, e, taskID, task, canonical, winnerSize >= task.Threshold)
	res.Slashed = slashedPool

	// creditDelta accumulates the planned credit additions per account so we can
	// pre-validate every addCredit against overflow before applying any of them.
	creditDelta := map[common.Address]*uint256.Int{}
	addPlanned := func(a common.Address, amt *uint256.Int) {
		if cur, ok := creditDelta[a]; ok {
			cur.Add(cur, amt)
		} else {
			creditDelta[a] = new(uint256.Int).Set(amt)
		}
	}

	if winnerSize >= task.Threshold {
		// QUORUM REACHED.
		res.Status = TaskSettled
		res.CanonicalHash = canonical
		res.WinnerCount = winnerSize

		// Winners = revealers whose hash == canonical.
		winners = make([]common.Address, 0, winnerSize)
		for i := range revealers {
			if hashes[i] == canonical {
				winners = append(winners, revealers[i])
			}
		}
		nWin := uint64(len(winners))

		// Each winner: rewardPerOperator from escrow + equal share of slashed
		// pool; the integer-division remainder is refunded to the requester.
		share := uint256.NewInt(0)
		remainder := new(uint256.Int).Set(slashedPool)
		if !slashedPool.IsZero() && nWin > 0 {
			share.Div(slashedPool, uint256.NewInt(nWin))
			distributed := new(uint256.Int).Mul(share, uint256.NewInt(nWin))
			remainder.Sub(slashedPool, distributed)
		}
		// Pre-check escrow can cover all winners (one check) and plan payouts.
		needEscrow := new(uint256.Int)
		if _, overflow := needEscrow.MulOverflow(reward, uint256.NewInt(nWin)); overflow {
			return SettleResult{}, ErrEscrowUnderflow
		}
		if escrow.Lt(needEscrow) {
			return SettleResult{}, ErrEscrowUnderflow
		}
		escrow.Sub(escrow, needEscrow)
		payout := new(uint256.Int).Add(reward, share)
		for _, w := range winners {
			addPlanned(w, payout)
			res.Paid.Add(res.Paid, payout)
		}

		// Refund unspent reward escrow ((N-winnerSize)*reward) + slashed-pool
		// remainder to the requester.
		refund := new(uint256.Int).Add(escrow, remainder)
		if !refund.IsZero() {
			addPlanned(task.Requester, refund)
		}
	} else {
		// NO QUORUM -> Failed. Refund the full remaining escrow + slashed pool
		// (compensation) to the requester.
		res.Status = TaskFailed
		refund := new(uint256.Int).Add(escrow, slashedPool)
		if !refund.IsZero() {
			addPlanned(task.Requester, refund)
		}
	}

	// PRE-VALIDATE every planned credit against overflow (pure read). If any would
	// overflow we abort here with ZERO state change.
	for a, delta := range creditDelta {
		nv := new(uint256.Int)
		if _, overflow := nv.AddOverflow(readCredit(st, a), delta); overflow {
			return SettleResult{}, ErrCreditOverflow
		}
	}

	// ---- APPLY PHASE (infallible: every write below was pre-validated) ----
	for _, pe := range plan {
		writeStake(st, pe.op, new(uint256.Int).Sub(readStake(st, pe.op), pe.slash))
	}
	for a, delta := range creditDelta {
		writeCredit(st, a, new(uint256.Int).Add(readCredit(st, a), delta))
	}

	// Flip task state, record the canonical result, drain the escrow accounting
	// slot, and burn the replay marker.
	task.Status = res.Status
	st.SetState(taskMetaASlot(taskID), packTaskA(task))
	st.SetState(slotHash(nsTaskEscrow, taskID), h32(uint256.NewInt(0)))
	st.SetState(slotHash(nsTaskHeight, taskID), h32(uint256.NewInt(height)))
	if res.Status == TaskSettled {
		st.SetState(slotHash(nsCanonical, taskID), canonical)
	}
	st.SetState(settledSlot, oneHash())

	// Build the cross-chain receipt and fold it into the receipt_root. winners is
	// nil on the Failed path (WinnersRoot = empty root); OperatorsRoot is over the
	// full selected set in selection order.
	receipt := e.buildReceipt(st, taskID, task, res, feePaid, height, winners)
	rh := receipt.Hash()
	newRoot, _ := appendReceipt(st, receipt.IntentID, rh)
	res.Receipt = receipt
	res.ReceiptHash = rh
	res.ReceiptRoot = newRoot
	return res, nil
}

// slashEntry is one planned slash: the culpable operator and the floored amount.
type slashEntry struct {
	op    common.Address
	slash *uint256.Int
}

// planSlash is the PURE slash policy: it decides which selected operators are
// culpable and by how much, WITHOUT mutating any state, and returns the plan plus
// the total pool. Settle applies the plan only in its infallible apply phase, so
// a settlement that aborts during planning/validation leaves stake untouched.
//
// A selected operator is slashed when it committed but never revealed
// (withholding — always); or, only if SlashDissenters is set AND a canonical hash
// exists, when it revealed a hash != canonical (dissent). The slash is floored at
// the operator's remaining stake (never negative); slashed wei stays in
// EscrowAccount (it was bonded there at register time) and is reassigned from
// stake to credit by the apply phase, so the conservation identity holds.
func planSlash(st QuorumState, e *Engine, taskID common.Hash, task taskRecord, canonical common.Hash, haveCanonical bool) ([]slashEntry, *uint256.Int) {
	var plan []slashEntry
	pool := uint256.NewInt(0)
	for i := uint32(0); i < task.N; i++ {
		op := e.SelectedAt(st, taskID, i)
		if op == (common.Address{}) {
			continue
		}
		committed := isSet(st.GetState(slotHashAddr(nsCommit, taskID, op)))
		revealed := isSet(st.GetState(slotHashAddr(nsRevealFlag, taskID, op)))

		slashThis := committed && !revealed // withholding: always
		if !slashThis && SlashDissenters && revealed && haveCanonical {
			revealedHash := st.GetState(slotHashAddr(nsReveal, taskID, op))
			slashThis = revealedHash != canonical
		}
		if !slashThis {
			continue
		}

		stake := readStake(st, op)
		slash := new(uint256.Int).Set(SlashPerOperator)
		if stake.Lt(slash) {
			slash.Set(stake) // floor at remaining stake
		}
		if slash.IsZero() {
			continue
		}
		plan = append(plan, slashEntry{op: op, slash: slash})
		pool.Add(pool, slash)
	}
	return plan, pool
}

// GetCanonicalResult reads a settled task's canonical output_hash (zero if not
// settled or no quorum).
func (e *Engine) GetCanonicalResult(st QuorumState, taskID common.Hash) common.Hash {
	return st.GetState(slotHash(nsCanonical, taskID))
}
