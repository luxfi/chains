// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// import_c_intent.go is the C->A INBOUND seam — the SAFE way an A-Chain task is
// born from a C-Chain inference intent. The safety property: a task is created
// ONLY from a COMMITTED C intent, verified under A consensus, never from a live
// C call.
//
// Three structural guarantees make a forged or uncommitted intent unable to
// create a task:
//
//  1. ID BINDING. ImportCommittedIntent recomputes intent_id from the delivered
//     fields (ComputeIntentID, the shared wire spec) and rejects unless it
//     equals the id the C side committed. Tamper with ANY field (N, threshold,
//     fee, caller, modelSpec, prompt, tx hash, call index, chain ids) and the
//     recomputed id differs -> ErrIntentIDMismatch -> no task.
//
//  2. COMMITTEDNESS PROOF. The caller supplies a CCommitVerifier whose
//     VerifyCommitted returns nil ONLY if the intent is actually committed on
//     C-Chain (e.g. a Warp/ZAP message attesting the C tx that emitted the
//     intent reached C finality, or a state-proof against a committed C block).
//     A live, uncommitted, or spoofed intent fails the proof -> no task. The
//     engine does not trust the transport; it trusts the proof the verifier
//     checks.
//
//  3. CONSENSUS-ONLY CALL SITE. ImportCommittedIntent is invoked exclusively
//     from the VM's block production / verification path (BuildBlock / Block.
//     Verify), so task creation is itself an A-Chain consensus event with
//     deterministic state. There is NO public "open a task from a request" RPC;
//     createTask is unexported and reachable only through this verified import.
//     A node cannot mint a task out of band.
//
//  Plus anti-replay: a consumed intent_id is marked, so the same committed
//  intent cannot create two tasks.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// CIntent is a committed C-Chain inference intent delivered to A-Chain across the
// atomic boundary. Its fields are the EXACT preimage of intent_id under the
// shared wire spec; IntentID is the value the C side committed (re-derived and
// checked here). RewardPerOperator is the A-Chain reward escrow per selected
// operator (carried alongside the intent; the C-side Fee is the user-facing fee
// that funds it + the burn).
type CIntent struct {
	IntentID          common.Hash    `json:"intentId"`          // committed on C; must equal ComputeIntentID(...)
	CChainID          common.Hash    `json:"cChainId"`
	AChainID          common.Hash    `json:"aChainId"`
	CTxHash           common.Hash    `json:"cTxHash"`           // C tx that emitted the intent
	CallIndex         uint32         `json:"callIndex"`         // index within that tx
	Caller            common.Address `json:"caller"`            // the C-side requester
	ModelSpecHash     common.Hash    `json:"modelSpecHash"`
	PromptHash        common.Hash    `json:"promptHash"`
	N                 uint16         `json:"n"`
	Threshold         uint16         `json:"threshold"`
	Fee               *uint256.Int   `json:"fee"`               // user-facing fee (funds escrow + burn)
	RewardPerOperator *uint256.Int   `json:"rewardPerOperator"` // A-chain reward escrow per operator
}

// CCommitVerifier proves a C-Chain intent is committed (reached C finality). It
// is the ONLY trust the inbound seam imports from C: the engine creates a task
// only if VerifyCommitted returns nil. A real implementation checks a Warp/ZAP
// attestation or a state proof against a committed C block; it MUST NOT return
// nil for a live/uncommitted/spoofed intent. The interface keeps the proof
// mechanism orthogonal to the state machine.
type CCommitVerifier interface {
	VerifyCommitted(intent CIntent) error
}

// VerifierFunc adapts a function to CCommitVerifier.
type VerifierFunc func(CIntent) error

// VerifyCommitted calls the wrapped function.
func (f VerifierFunc) VerifyCommitted(intent CIntent) error { return f(intent) }

// ImportCommittedIntent is the verified inbound entry point. Called UNDER A
// CONSENSUS (from BuildBlock / Verify), it validates the intent's id binding,
// verifies its committedness via ccv, guards against replay, and creates the
// A-Chain task. Returns the created task id. The requester funding the escrow +
// fee is the C-side Caller address mirrored on A-Chain (its A-Chain balance must
// cover N*RewardPerOperator + N*RequestFeePerOperator).
//
// Order is fail-closed: id check and proof check happen BEFORE any state or
// money is touched, so a rejected intent leaves the chain untouched.
func (e *Engine) ImportCommittedIntent(st QuorumState, lg QuorumLedger, ccv CCommitVerifier, intent CIntent, height uint64) (common.Hash, error) {
	// (0) NIL-AMOUNT GUARD. The intent crosses a trust boundary (untrusted
	// cross-chain bytes), so the *uint256.Int amount pointers must be validated
	// here before any uint256 arithmetic dereferences them. Fee feeds id binding
	// (u256be is nil-safe but a nil reward is NOT in the id and would otherwise
	// nil-panic inside createTask's MulOverflow — a consensus-halt DoS). Fail
	// closed, before any state or money is touched.
	if intent.Fee == nil || intent.RewardPerOperator == nil {
		return common.Hash{}, ErrIntentNilAmount
	}

	// (1) ID BINDING: recompute intent_id and require it to match the committed
	// id. Also pins the intent to THIS engine's chain ids (a cross-deployment
	// replay changes CChainID/AChainID -> id mismatch).
	if intent.CChainID != e.CChainID || intent.AChainID != e.AChainID {
		return common.Hash{}, ErrIntentIDMismatch
	}
	recomputed := ComputeIntentID(
		intent.CChainID, intent.AChainID, intent.CTxHash, intent.CallIndex,
		intent.Caller, intent.ModelSpecHash, intent.PromptHash,
		intent.N, intent.Threshold, intent.Fee,
	)
	if recomputed != intent.IntentID {
		return common.Hash{}, ErrIntentIDMismatch
	}

	// (2) COMMITTEDNESS: the only trust imported from C. Must pass before any
	// state change.
	if err := ccv.VerifyCommitted(intent); err != nil {
		return common.Hash{}, ErrIntentNotCommitted
	}

	// (anti-replay) reject a previously-consumed intent.
	seenSlot := slotHash(nsIntentSeen, intent.IntentID)
	if isSet(st.GetState(seenSlot)) {
		return common.Hash{}, ErrIntentAlreadyUsed
	}

	// Non-refundable fee per the protocol constant (N * RequestFeePerOperator).
	// The intent.Fee is the user-facing fee committed on C; the A-side burn is
	// the protocol fee, funded from the requester's A-balance alongside escrow.
	totalFee := new(uint256.Int)
	if _, overflow := totalFee.MulOverflow(RequestFeePerOperator, uint256.NewInt(uint64(intent.N))); overflow {
		return common.Hash{}, ErrFeeOverflow
	}

	// (3) CREATE THE TASK under consensus. createTask enforces params, the
	// eligible-set margin, escrows reward, burns the fee, and selects operators —
	// all deterministically. Mark the intent consumed and record the
	// intent->task mapping only AFTER the task is created (so a createTask failure
	// does not burn the intent's single-use marker).
	taskID, err := e.createTask(
		st, lg, intent.Caller, intent.ModelSpecHash, intent.PromptHash,
		uint32(intent.N), uint32(intent.Threshold), totalFee, intent.RewardPerOperator, height,
	)
	if err != nil {
		return common.Hash{}, err
	}

	st.SetState(seenSlot, oneHash())
	st.SetState(slotHash(nsTaskIntent, taskID), intent.IntentID)
	st.SetState(slotHash(nsIntentTask, intent.IntentID), taskID)
	return taskID, nil
}
