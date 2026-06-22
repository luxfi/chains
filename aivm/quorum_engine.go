// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// quorum_engine.go is the A-Chain-native quorum settlement engine: the
// composition root that ties the substrate (QuorumState + QuorumLedger) to the
// lifecycle logic split across provider.go, selection.go, commit_reveal.go,
// quorum.go, settlement.go, receipts.go, import_c_intent.go, export.go.
//
// THIS is "the AI task quorum-settlement state machine living in A-Chain". It is
// the same proven commit-reveal quorum engine that ran as a C-Chain EVM
// precompile (hanzo-evm/precompile/aiquorum), re-expressed in A-Chain types
// (luxfi/geth/common + luxfi/crypto + holiman/uint256) and freed of the EVM
// precompile framing. The settlement RESULT — did >= threshold staked operators
// independently submit the same output_hash under the same ModelSpec — is what
// A-Chain consensus agrees on; validators never run the model.
//
// The engine is a thin handle: it carries no state of its own beyond the two
// substrate interfaces and the configured ChainIDs. All durable state lives in
// QuorumState (committed under A consensus by the VM at Accept). Methods are
// pure functions of (state, ledger, height) so they are deterministic and
// reproducible on every validator.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// Protocol bounds. minN forbids trivial self-quorums; 3 is the smallest set
// where a strict majority (2-of-3) is genuine agreement among independent
// operators. maxN caps the per-task set so selection and tally are bounded.
const (
	minN = 3
	maxN = 256
)

// Window + economic policy — protocol constants (one true configuration, not
// per-call knobs) so every validator computes identical deadlines and identical
// slash math. These realize the aivm Config fields (MinProviderBond,
// ChallengeWindowBlocks, RedundancyFactor) as ENFORCED quantities rather than
// the prior stubs.
var (
	// MinProviderBond is the floor a provider must keep bonded to be eligible
	// for selection. It is also the per-operator SYBIL COST: forging a canonical
	// hash requires controlling >= threshold selected operators, each bonded
	// >= MinProviderBond, so the absolute forgery floor is threshold *
	// MinProviderBond regardless of any selection grinding. Matches the aivm
	// Config default (1000 LUX) expressed in wei.
	MinProviderBond = uint256.NewInt(1_000_000_000_000_000_000) // 1 token (1e18 wei) per unit; scaled by deployment

	// SlashPerOperator is the bonded-stake penalty for a SELECTED operator that
	// committed but never revealed (withholding). Always applied; dissenters
	// (revealed a minority hash) are NOT slashed.
	SlashPerOperator = uint256.NewInt(100_000_000_000_000_000) // 0.1 token

	// RequestFeePerOperator is the NON-REFUNDABLE fee charged per selected
	// operator when a task is created, burned to BurnAddress. Separate from the
	// refundable reward escrow: a task that fails to reach quorum refunds the
	// reward but NOT the fee. It prices REPEATED requests (selection-grind /
	// censorship by resubmission), so the on-chain cost scales with N and with
	// the number of submitted tasks.
	RequestFeePerOperator = uint256.NewInt(10_000_000_000_000_000) // 0.01 token

	// RequestMarginFloor / RequestMarginBps define the ELIGIBLE-SET MARGIN:
	// a task is rejected unless the eligible pool E for the ModelSpec satisfies
	// E >= N + max(RequestMarginFloor, N*RequestMarginBps/1e4). This forbids
	// degenerate pools where selection has no sampling headroom over an
	// independent set, and guarantees the draw is always a strict subset of a
	// larger universe (a single cheap operator is never the whole pool).
	RequestMarginFloor uint32 = 2
	RequestMarginBps   uint32 = 5000 // 50%

	// CommitBlocks / RevealBlocks bound the commit and reveal windows. The
	// reveal window opens strictly AFTER the commit window closes so no operator
	// can see a peer's revealed output before committing.
	CommitBlocks uint64 = 30
	RevealBlocks uint64 = 30

	// UnbondCooldownBlocks is how long after deregistration a stake withdrawal
	// must wait — bounds the window in which an unbonding operator could still be
	// selected for an unsettled task.
	UnbondCooldownBlocks uint64 = 60

	// SlashDissenters: default false. Honest disagreement (nondeterministic
	// model output) must not be punished, and slashing dissenters would let a
	// majority cartel grief an honest minority. Withholding is always slashed.
	SlashDissenters = false
)

// BurnAddress is the unspendable sink the non-refundable request fee is parked
// in. No engine method ever pays OUT of it, so wei that lands here is removed
// from circulation without being destroyed (which would break the grand-total
// conservation invariant). The fee moves requester -> EscrowAccount ->
// BurnAddress, so EscrowAccount nets zero for the fee and its
// stake+escrow+credit identity is untouched.
var BurnAddress = common.HexToAddress("0x000000000000000000000000000000000000dEaD")

// Engine is the A-Chain quorum settlement handle. CChainID / AChainID are the
// 32-byte chain identifiers used in the shared wire spec (intent_id derivation
// and the receipt's CChainID/AChainID fields). They are fixed per deployment.
type Engine struct {
	CChainID common.Hash
	AChainID common.Hash
}

// NewEngine returns an engine bound to the given chain ids.
func NewEngine(cChainID, aChainID common.Hash) *Engine {
	return &Engine{CChainID: cChainID, AChainID: aChainID}
}

// requiredMargin returns the eligible-set headroom required over N. Pure
// function of N and the two policy constants — every validator computes the
// identical value.
func requiredMargin(n uint32) uint32 {
	frac := uint32((uint64(n) * uint64(RequestMarginBps)) / 10_000)
	if frac > RequestMarginFloor {
		return frac
	}
	return RequestMarginFloor
}

// bumpNonce increments a requester's monotonic nonce slot.
func bumpNonce(st QuorumState, nonceSlot, nonce common.Hash) {
	n := new(uint256.Int).SetBytes(nonce.Bytes())
	n.AddUint64(n, 1)
	st.SetState(nonceSlot, h32(n))
}
