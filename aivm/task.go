// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// task.go defines the A-Chain quorum task: its lifecycle states keyed by
// A-Chain block-height windows, its on-state record, and the internal
// createTask primitive that opens a task (selects operators, escrows reward,
// burns the fee). createTask is the single write path for new tasks and is
// invoked ONLY from import_c_intent.go (under A consensus), never from a live
// off-chain call — that is the import-seam safety property.
//
// Lifecycle (windows by A-Chain height — the only nondeterminism source):
//
//	Requested ─createTask→ Committing ─(commit window)→ Revealing
//	          ─(reveal window)→ Settle ──→ Settled | Failed
//	(Challenged is a settled receipt later disputed; see receipts.go status.)
//
//	commitDeadline = requestHeight + CommitBlocks
//	revealDeadline = commitDeadline + RevealBlocks
//
// Only A-Chain height is consulted. No wall-clock, no RNG.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// TaskState is the on-state lifecycle status byte. Distinct from the
// receipt-level Status (StatusCompleted etc.) which is the cross-chain view.
type TaskState uint8

const (
	TaskNone       TaskState = 0 // zero value: no such task
	TaskCommitting TaskState = 1 // open for commits, then reveals
	TaskSettled    TaskState = 2 // quorum reached, winners paid
	TaskFailed     TaskState = 3 // no quorum, requester refunded
)

// taskRecord is the durable task state. Split across two packed words plus
// sibling slots for the two full-width hashes.
//
//	word A: [ status:1 | N:4 | threshold:4 | requester:20 | _:3 ]
//	word B: [ commitDeadline:8 | revealDeadline:8 | requestHeight:8 | _:8 ]
type taskRecord struct {
	Status         TaskState
	N              uint32
	Threshold      uint32
	Requester      common.Address
	CommitDeadline uint64
	RevealDeadline uint64
	RequestHeight  uint64
	ModelSpecHash  common.Hash
	PromptHash     common.Hash
}

func taskMetaASlot(id common.Hash) common.Hash { return slotHash(nsTask, id) }
func taskMetaBSlot(id common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsTask, id.Bytes(), []byte("B")))
}
func taskSpecSlot(id common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsTask, id.Bytes(), []byte("spec")))
}
func taskPromptSlot(id common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsTask, id.Bytes(), []byte("prompt")))
}

func packTaskA(r taskRecord) common.Hash {
	var w [32]byte
	w[0] = byte(r.Status)
	copy(w[1:5], u32be(r.N))
	copy(w[5:9], u32be(r.Threshold))
	copy(w[9:29], r.Requester.Bytes())
	return common.BytesToHash(w[:])
}

func packTaskB(r taskRecord) common.Hash {
	var w [32]byte
	copy(w[0:8], u64be(r.CommitDeadline))
	copy(w[8:16], u64be(r.RevealDeadline))
	copy(w[16:24], u64be(r.RequestHeight))
	return common.BytesToHash(w[:])
}

func writeTask(st QuorumState, id common.Hash, r taskRecord) {
	st.SetState(taskMetaASlot(id), packTaskA(r))
	st.SetState(taskMetaBSlot(id), packTaskB(r))
	st.SetState(taskSpecSlot(id), r.ModelSpecHash)
	st.SetState(taskPromptSlot(id), r.PromptHash)
}

func readTask(st QuorumState, id common.Hash) taskRecord {
	a := st.GetState(taskMetaASlot(id)).Bytes()
	if a[0] == byte(TaskNone) {
		return taskRecord{Status: TaskNone}
	}
	b := st.GetState(taskMetaBSlot(id)).Bytes()
	return taskRecord{
		Status:         TaskState(a[0]),
		N:              be32(a[1:5]),
		Threshold:      be32(a[5:9]),
		Requester:      common.BytesToAddress(a[9:29]),
		CommitDeadline: be64(b[0:8]),
		RevealDeadline: be64(b[8:16]),
		RequestHeight:  be64(b[16:24]),
		ModelSpecHash:  st.GetState(taskSpecSlot(id)),
		PromptHash:     st.GetState(taskPromptSlot(id)),
	}
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// computeTaskID derives the unique, reproducible task id (and selection beacon
// anchor). It folds in the requester's monotonic nonce and the request height,
// so it is fully reproducible after the task lands and IDENTICAL across every
// validator. There is no in-consensus randomness on this platform, so the beacon
// is anchored only in values fixed at task-creation time; the integrity argument
// is economic (eligible-set margin + MinProviderBond + fee), see selection.go.
func computeTaskID(requester common.Address, nonce common.Hash, modelSpecHash, promptHash common.Hash, requestHeight uint64, n, threshold uint32) common.Hash {
	return common.BytesToHash(crypto.Keccak256(
		nsTask,
		requester.Bytes(),
		nonce.Bytes(),
		modelSpecHash.Bytes(),
		promptHash.Bytes(),
		u64be(requestHeight),
		u32be(n),
		u32be(threshold),
	))
}

// createTask is the single new-task write path. It validates params, enforces
// the eligible-set margin, escrows N*rewardPerOperator (refundable) and burns
// N*fee (non-refundable) from the requester, deterministically selects N
// eligible operators, and records the task in Committing state. Returns the task
// id. Pure given (state, ledger, height); deterministic on every validator.
//
// It is unexported on purpose: the ONLY caller is ImportCommittedIntent, which
// first proves the C intent is committed. There is no public "open a task from a
// live request" method, so a task can never be created from an unverified
// off-chain call.
func (e *Engine) createTask(st QuorumState, lg QuorumLedger, requester common.Address, modelSpecHash, promptHash common.Hash, n, threshold uint32, fee, rewardPerOperator *uint256.Int, height uint64) (common.Hash, error) {
	if modelSpecHash == (common.Hash{}) {
		return common.Hash{}, ErrEmptyModelSpec
	}
	if promptHash == (common.Hash{}) {
		return common.Hash{}, ErrEmptyPromptHash
	}
	if n < minN || n > maxN {
		return common.Hash{}, ErrBadN
	}
	// Strict majority floor(N/2)+1 <= threshold <= N.
	if threshold < n/2+1 || threshold > n {
		return common.Hash{}, ErrBadThreshold
	}

	// Total reward escrow = N * rewardPerOperator (checked).
	totalEscrow := new(uint256.Int)
	if _, overflow := totalEscrow.MulOverflow(rewardPerOperator, uint256.NewInt(uint64(n))); overflow {
		return common.Hash{}, ErrRewardOverflow
	}

	// ELIGIBLE-SET MARGIN: build the eligible universe ONCE and require it to be
	// strictly larger than the draw by requiredMargin(N). Enforced BEFORE any
	// money moves (fail-closed).
	eligible := eligibleSet(st, modelSpecHash)
	if uint32(len(eligible)) < n {
		return common.Hash{}, ErrNotEnoughEligible
	}
	if uint32(len(eligible)) < n+requiredMargin(n) {
		return common.Hash{}, ErrEligibleBelowMargin
	}

	// Derive the task id from the requester's monotonic nonce, then draw N from
	// the SAME eligible set we just margin-checked (one scan, shared) — BEFORE
	// moving money so a selection failure leaves balances untouched.
	nonceSlot := slotAddr(nsReqNonce, requester)
	nonce := st.GetState(nonceSlot)
	taskID := computeTaskID(requester, nonce, modelSpecHash, promptHash, height, n, threshold)

	selected, err := drawFromEligible(eligible, taskID, n)
	if err != nil {
		return common.Hash{}, err
	}

	// Combined affordability check (escrow + fee) BEFORE any move, so the two
	// money operations are all-or-nothing.
	needed := new(uint256.Int)
	if _, overflow := needed.AddOverflow(totalEscrow, fee); overflow {
		return common.Hash{}, ErrRewardOverflow
	}
	if lg.GetBalance(requester).Lt(needed) {
		return common.Hash{}, ErrInsufficientFunds
	}

	// Escrow the reward (refundable). Fails closed.
	if err := lg.Pull(requester, totalEscrow); err != nil {
		return common.Hash{}, err
	}
	// Burn the non-refundable fee: requester -> EscrowAccount -> BurnAddress.
	if !fee.IsZero() {
		if err := lg.Pull(requester, fee); err != nil {
			return common.Hash{}, err
		}
		if err := lg.Pay(BurnAddress, fee); err != nil {
			return common.Hash{}, err
		}
	}

	// Persist the task + escrow + reward-per-operator + fee-paid.
	task := taskRecord{
		Status:         TaskCommitting,
		N:              n,
		Threshold:      threshold,
		Requester:      requester,
		CommitDeadline: height + CommitBlocks,
		RevealDeadline: height + CommitBlocks + RevealBlocks,
		RequestHeight:  height,
		ModelSpecHash:  modelSpecHash,
		PromptHash:     promptHash,
	}
	writeTask(st, taskID, task)
	st.SetState(slotHash(nsTaskReward, taskID), h32(rewardPerOperator))
	st.SetState(slotHash(nsTaskEscrow, taskID), h32(totalEscrow))
	st.SetState(slotHash(nsTaskFee, taskID), h32(fee))

	// Record the selected set: a membership flag (O(1) "are you selected") AND
	// an indexed list (reproducibility / enumeration), index 0..N-1.
	for i, op := range selected {
		st.SetState(slotHashAddr(nsSelected, taskID, op), oneHash())
		st.SetState(slotHashIdx(nsSelList, taskID, uint32(i)), common.BytesToHash(common.LeftPadBytes(op.Bytes(), 32)))
	}

	bumpNonce(st, nonceSlot, nonce)
	return taskID, nil
}

// IsSelected reports whether op was selected for task (O(1) flag read).
func (e *Engine) IsSelected(st QuorumState, taskID common.Hash, op common.Address) bool {
	return isSet(st.GetState(slotHashAddr(nsSelected, taskID, op)))
}

// SelectedAt returns the operator at selection index i (for reproducibility
// checks). idx must be < task.N.
func (e *Engine) SelectedAt(st QuorumState, taskID common.Hash, idx uint32) common.Address {
	return common.BytesToAddress(st.GetState(slotHashIdx(nsSelList, taskID, idx)).Bytes())
}

// selectedOperators returns the selected set in selection order (used by the
// receipt's OperatorsRoot).
func selectedOperators(st QuorumState, taskID common.Hash, n uint32) []common.Address {
	out := make([]common.Address, 0, n)
	for i := uint32(0); i < n; i++ {
		op := common.BytesToAddress(st.GetState(slotHashIdx(nsSelList, taskID, i)).Bytes())
		if op == (common.Address{}) {
			continue
		}
		out = append(out, op)
	}
	return out
}

// TaskInfo is a read-only view of a task's lifecycle state.
type TaskInfo struct {
	Status         TaskState
	N              uint32
	Threshold      uint32
	Requester      common.Address
	ModelSpecHash  common.Hash
	PromptHash     common.Hash
	CommitDeadline uint64
	RevealDeadline uint64
	RequestHeight  uint64
}

// GetTask reads a task's lifecycle state.
func (e *Engine) GetTask(st QuorumState, taskID common.Hash) TaskInfo {
	r := readTask(st, taskID)
	return TaskInfo{
		Status:         r.Status,
		N:              r.N,
		Threshold:      r.Threshold,
		Requester:      r.Requester,
		ModelSpecHash:  r.ModelSpecHash,
		PromptHash:     r.PromptHash,
		CommitDeadline: r.CommitDeadline,
		RevealDeadline: r.RevealDeadline,
		RequestHeight:  r.RequestHeight,
	}
}
