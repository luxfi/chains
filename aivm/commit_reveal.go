// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// commit_reveal.go is the two-phase commit-reveal that prevents operators from
// copying each other's answers:
//
//   - CommitResponse: a SELECTED operator posts a commit hash during the commit
//     window (height <= commitDeadline). One commit per operator per task.
//   - RevealResponse: during the reveal window (commitDeadline < height <=
//     revealDeadline, i.e. strictly AFTER the commit window closes) the operator
//     reveals (output_hash, embedding_hash, nonce); the engine RECOMPUTES the
//     commit (ComputeCommit, operator-bound) and rejects unless it equals the
//     stored commit. One reveal per operator.
//
// Because the reveal window opens only after the commit window closes, no
// operator can observe a peer's revealed output before its own commit is sealed;
// and because the commit binds the operator address, a copied commit cannot be
// revealed by anyone but its author.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// CommitResponse records a selected operator's commit hash within the commit
// window.
func (e *Engine) CommitResponse(st QuorumState, taskID common.Hash, operator common.Address, commit common.Hash, height uint64) error {
	if commit == (common.Hash{}) {
		return ErrEmptyCommit
	}
	task := readTask(st, taskID)
	if task.Status == TaskNone {
		return ErrTaskUnknown
	}
	if task.Status != TaskCommitting {
		return ErrTaskNotCommitting
	}
	if height > task.CommitDeadline {
		return ErrCommitClosed
	}
	if !e.IsSelected(st, taskID, operator) {
		return ErrNotSelected
	}
	commitSlot := slotHashAddr(nsCommit, taskID, operator)
	if isSet(st.GetState(commitSlot)) {
		return ErrAlreadyCommitted
	}
	st.SetState(commitSlot, commit)
	return nil
}

// RevealResponse records a selected operator's revealed (output_hash,
// embedding_hash, nonce) within the reveal window, requiring the recomputed
// operator-bound commit to equal the stored commit.
func (e *Engine) RevealResponse(st QuorumState, taskID common.Hash, operator common.Address, outputHash, embeddingHash, nonce common.Hash, height uint64) error {
	if outputHash == (common.Hash{}) {
		return ErrEmptyOutputHash
	}
	task := readTask(st, taskID)
	if task.Status == TaskNone {
		return ErrTaskUnknown
	}
	if task.Status != TaskCommitting {
		return ErrTaskNotCommitting
	}
	if height <= task.CommitDeadline {
		return ErrRevealNotOpen
	}
	if height > task.RevealDeadline {
		return ErrRevealClosed
	}
	commitSlot := slotHashAddr(nsCommit, taskID, operator)
	stored := st.GetState(commitSlot)
	if !isSet(stored) {
		return ErrNotCommitted
	}
	revealFlagSlot := slotHashAddr(nsRevealFlag, taskID, operator)
	if isSet(st.GetState(revealFlagSlot)) {
		return ErrAlreadyRevealed
	}
	// Recompute the operator-bound commit; must match exactly.
	recomputed := ComputeCommit(taskID, task.ModelSpecHash, task.PromptHash, outputHash, embeddingHash, operator, nonce)
	if recomputed != stored {
		return ErrCommitMismatch
	}
	// Record the reveal: output_hash, the revealed flag, and append the operator
	// to the per-task revealer array (for tally at Settle).
	st.SetState(slotHashAddr(nsReveal, taskID, operator), outputHash)
	st.SetState(revealFlagSlot, oneHash())
	cnt := revealCount(st, taskID)
	st.SetState(slotHashIdx(nsRevealList, taskID, cnt), common.BytesToHash(common.LeftPadBytes(operator.Bytes(), 32)))
	st.SetState(slotHash(nsRevealCount, taskID), h32(uint256.NewInt(uint64(cnt)+1)))
	return nil
}

func revealCount(st QuorumState, taskID common.Hash) uint32 {
	return uint32(new(uint256.Int).SetBytes(st.GetState(slotHash(nsRevealCount, taskID)).Bytes()).Uint64())
}
