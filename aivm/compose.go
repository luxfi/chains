// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// compose.go is the surface a specialised VM builds on. A-Chain is the general
// attested-compute base — providers, bonds, selection, commit-reveal, quorum,
// slashing, settlement, receipts — and a chain that wants those mechanics for its
// own kind of work should not fork them.
//
// What such a VM cannot reuse is A-Chain's POLICY about who may run a task. The
// model path gathers candidates by the model specification an operator
// advertises; another chain gathers them by whatever its own work is about. So
// the policy is the parameter: OpenTask takes the candidate pool already
// gathered, and everything after it — the margin, the escrow, the burn, the draw,
// the record — is the same one mechanism the model path uses.
//
// This does not open a door on A-Chain itself. The A-Chain VM's only task-opening
// call is still importPending -> ImportCommittedIntent, still under consensus,
// still behind a committedness proof; nothing routes an A-Chain request here. A
// composing VM calls OpenTask against ITS OWN QuorumState and QuorumLedger, which
// no A-Chain node serves, so the two chains share code and share no state.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// TaskSpec is what a composing VM opens a task from. Code and Input are the two
// digests the commit preimage binds — a model specification and a prompt on the
// model path, whatever the composing chain's work is about on its own.
type TaskSpec struct {
	// Requester funds the escrow and the fee, and is refunded if no quorum forms.
	Requester common.Address
	// Code is what the operators are asked to run.
	Code common.Hash
	// Input is what they are asked to run it on.
	Input common.Hash
	// Candidates is the pool the draw runs over, already filtered by the
	// composing VM's own policy. Repeats are dropped before anything is counted,
	// so the margin is over distinct addresses and a pool padded with one
	// address cannot buy its way past it.
	Candidates []common.Address
	// N is how many operators answer; Threshold is how many must agree.
	N         uint32
	Threshold uint32
	// Fee is burned and is not refunded. Reward is escrowed per operator.
	Fee    *uint256.Int
	Reward *uint256.Int
}

// OpenTask opens a task over a caller-supplied candidate pool and returns its id.
// It is the same write path the model intent uses: the distinct pool must exceed
// the draw by the margin, the requester must be able to afford escrow plus fee
// before either moves, the draw is the reproducible beacon anchored in the task
// id, and a refusal leaves no state and no value touched.
//
// One guarantee does NOT come along, because it was never in this function. On
// the model path the pool comes from eligibleSet, which reads an append-only set
// and so cannot repeat an address; that is where its distinctness came from. A
// caller's pool carries no such history, and N draws from a pool of one address
// would be one party agreeing with itself N times. createTask therefore drops
// repeats before it counts anything — see distinct() — so the property holds
// here for a different reason than it holds there.
func (e *Engine) OpenTask(st QuorumState, lg QuorumLedger, s TaskSpec, height uint64) (common.Hash, error) {
	if s.Fee == nil || s.Reward == nil {
		return common.Hash{}, ErrIntentNilAmount
	}
	return e.createTask(st, lg, taskSpec{
		requester:  s.Requester,
		code:       s.Code,
		input:      s.Input,
		candidates: s.Candidates,
		n:          s.N,
		threshold:  s.Threshold,
		fee:        s.Fee,
		reward:     s.Reward,
	}, height)
}

// Eligible returns the staked operators advertising a model specification, in
// registry insertion order — the pool the model path draws from.
func (e *Engine) Eligible(st QuorumState, modelSpecHash common.Hash) []common.Address {
	return eligibleSet(st, modelSpecHash)
}

// Staked reports whether an operator is registered, not unbonding, and holds at
// least MinProviderBond. It is what "may be selected at all" means, and a
// composing VM's own filter starts here.
func Staked(st QuorumState, op common.Address) bool {
	rec := readOperator(st, op)
	if !rec.Exists || rec.Unbonding {
		return false
	}
	return !readStake(st, op).Lt(MinProviderBond)
}

// Draw is the reproducible selection beacon over any pool: a Fisher-Yates partial
// shuffle anchored in a 32-byte value, returning the first n. It mutates the
// slice it is given, so callers pass a pool they own. Anyone holding the same
// pool in the same order and the same anchor reproduces the same draw.
func Draw(pool []common.Address, anchor common.Hash, n uint32) ([]common.Address, error) {
	return drawFromEligible(pool, anchor, n)
}

// RequiredMargin is the headroom a candidate pool must have over the draw. A pool
// that is barely the draw is not a draw, and the same floor applies to every VM
// built on this base.
func RequiredMargin(n uint32) uint32 { return requiredMargin(n) }
