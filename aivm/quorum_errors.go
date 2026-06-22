// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import "errors"

// Engine errors. Every one is a hard failure that leaves state unchanged
// (fail-closed): a rejected operation makes NO write. Grouped by phase so the
// surface is auditable in one place.
var (
	// registry / stake
	ErrEmptyModelSpec    = errors.New("aivm/quorum: empty model spec hash")
	ErrStakeBelowMin     = errors.New("aivm/quorum: stake below MinProviderBond")
	ErrOperatorExists    = errors.New("aivm/quorum: operator already registered")
	ErrOperatorUnknown   = errors.New("aivm/quorum: operator not registered")
	ErrOperatorUnbonding = errors.New("aivm/quorum: operator is unbonding")
	ErrCooldownActive    = errors.New("aivm/quorum: unbond cooldown not elapsed")

	// custody / conservation
	ErrInsufficientFunds = errors.New("aivm/quorum: insufficient balance")
	ErrLedgerNotFundable = errors.New("aivm/quorum: ledger does not support genesis funding")
	ErrEscrowUnderflow   = errors.New("aivm/quorum: escrow underflow (invariant broken)")
	ErrStakeOverflow     = errors.New("aivm/quorum: stake overflow")
	ErrCreditOverflow    = errors.New("aivm/quorum: credit overflow")
	ErrRewardOverflow    = errors.New("aivm/quorum: reward escrow overflow")
	ErrFeeOverflow       = errors.New("aivm/quorum: request fee overflow")
	ErrNoCredit          = errors.New("aivm/quorum: no credit to withdraw")

	// task params / selection
	ErrEmptyPromptHash     = errors.New("aivm/quorum: empty prompt hash")
	ErrBadN                = errors.New("aivm/quorum: N out of range [minN, maxN]")
	ErrBadThreshold        = errors.New("aivm/quorum: threshold must satisfy floor(N/2)+1 <= threshold <= N")
	ErrNotEnoughEligible   = errors.New("aivm/quorum: fewer eligible operators than N")
	ErrEligibleBelowMargin = errors.New("aivm/quorum: eligible operator set below N + required margin")

	// task lifecycle
	ErrTaskUnknown       = errors.New("aivm/quorum: task not found")
	ErrTaskNotCommitting = errors.New("aivm/quorum: task not in committing state")
	ErrTaskAlreadySettled = errors.New("aivm/quorum: task already settled")
	ErrNotSelected       = errors.New("aivm/quorum: operator not selected for task")
	ErrCommitClosed      = errors.New("aivm/quorum: commit window closed")
	ErrAlreadyCommitted  = errors.New("aivm/quorum: operator already committed")
	ErrNotCommitted      = errors.New("aivm/quorum: operator did not commit")
	ErrRevealNotOpen     = errors.New("aivm/quorum: reveal window not open")
	ErrRevealClosed      = errors.New("aivm/quorum: reveal window closed")
	ErrAlreadyRevealed   = errors.New("aivm/quorum: operator already revealed")
	ErrCommitMismatch    = errors.New("aivm/quorum: reveal does not match commit")
	ErrEmptyCommit       = errors.New("aivm/quorum: empty commit hash")
	ErrEmptyOutputHash   = errors.New("aivm/quorum: empty output hash")
	ErrSettleTooEarly    = errors.New("aivm/quorum: reveal window not closed")

	// cross-chain seam
	ErrIntentNilAmount    = errors.New("aivm/quorum: C-chain intent has a nil fee or reward amount")
	ErrIntentIDMismatch   = errors.New("aivm/quorum: recomputed intent_id does not match delivered id (forged/tampered intent)")
	ErrIntentNotCommitted = errors.New("aivm/quorum: C-chain intent is not committed (proof rejected)")
	ErrIntentAlreadyUsed  = errors.New("aivm/quorum: C-chain intent already consumed (replay)")
	ErrReceiptNotFound    = errors.New("aivm/quorum: no settled receipt for intent")
	ErrProofOutOfRange    = errors.New("aivm/quorum: receipt index out of range")
	ErrReceiptRootMismatch = errors.New("aivm/quorum: block receipt_root does not match re-derived engine state")
)
