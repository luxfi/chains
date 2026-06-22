// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// selection.go is the deterministic provider-selection beacon — reproducible by
// anyone. Selection draws N distinct operators from the eligible set E by a
// Fisher–Yates partial shuffle anchored in the task_id:
//
//	working = E (a copy, in registry-insertion order)
//	for i in 0 .. N-1:
//	    j = i + ( u256(keccak256(task_id || u32be(i))) mod (len(working) - i) )
//	    swap working[i], working[j]      // selected = working[0:N]
//
// task_id = keccak(av/task, requester, nonce, modelSpec, prompt, height, N,
// threshold) (computeTaskID), so the draw is fully reproducible after the task
// lands and identical on every validator. Anyone can rebuild E from the on-chain
// per-ModelSpec operator array, run the identical draw, and reproduce the exact
// selected set.
//
// # Selection threat model (what the beacon does and does NOT guarantee)
//
// Lux exposes NO in-consensus randomness (no blockhash / prevrandao) to this
// layer, so the beacon is anchored only in values knowable at task creation.
// It is unbiased against any party that does not control the requester: a
// third-party operator cannot influence task_id nor its own array index, so it
// cannot self-select. It is NOT a cryptographic defense against a malicious
// requester who grinds the opaque promptHash offline to bias the draw. The
// mitigation is ECONOMIC + SET-SIZE, enforced in createTask:
//
//   (1) ELIGIBLE-SET MARGIN: E >= N + max(RequestMarginFloor, N*RequestMarginBps/1e4)
//       forbids degenerate pools and guarantees the draw is a strict subset of a
//       larger universe.
//   (2) NON-REFUNDABLE FEE: every distinct task costs N*RequestFeePerOperator
//       (burned), pricing repeated/grinding submissions linearly in N and in the
//       number of tasks.
//   (3) MinProviderBond as the SYBIL COST: forging a canonical hash needs >=
//       threshold of the SELECTED set; since selection only ever picks eligible
//       operators, the attacker must hold >= threshold operators each bonded >=
//       MinProviderBond. The absolute forgery floor is threshold*MinProviderBond,
//       independent of any grinding — below it forgery is impossible at any
//       compute budget.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// drawFromEligible is the PURE beacon draw: a Fisher–Yates partial shuffle of
// the given eligible set anchored in task_id, returning the first N. No state
// access (the data is the input), so this is the single place the selection
// MECHANISM lives, independent of how E was gathered. Mutates the passed slice
// in place (callers pass a fresh slice).
func drawFromEligible(eligible []common.Address, taskID common.Hash, n uint32) ([]common.Address, error) {
	if uint32(len(eligible)) < n {
		return nil, ErrNotEnoughEligible
	}
	for i := uint32(0); i < n; i++ {
		span := uint64(len(eligible)) - uint64(i) // remaining choices
		draw := new(uint256.Int).SetBytes(crypto.Keccak256(taskID.Bytes(), u32be(i)))
		j := i + uint32(new(uint256.Int).Mod(draw, uint256.NewInt(span)).Uint64())
		eligible[i], eligible[j] = eligible[j], eligible[i]
	}
	return eligible[:n], nil
}

// SelectOperators is the convenience composition of the one scan (eligibleSet)
// and the pure draw (drawFromEligible): it draws N distinct eligible operators
// from the per-ModelSpec array using the task_id beacon. It does NOT enforce the
// eligible-set margin (that is a createTask policy gate). Exposed for standalone
// callers and the reproducibility tests; createTask does the scan once itself
// (to share E with the margin check) and calls drawFromEligible directly.
func (e *Engine) SelectOperators(st QuorumState, taskID, modelSpecHash common.Hash, n uint32) ([]common.Address, error) {
	return drawFromEligible(eligibleSet(st, modelSpecHash), taskID, n)
}

// ComputeCommit implements the operator-bound commit preimage (fixed width,
// this order):
//
//	commit = keccak256( task_id(32) || model_spec_hash(32) || prompt_hash(32) ||
//	                    output_hash(32) || embedding_hash(32) || operator(20) ||
//	                    nonce(32) )
//
// The operator address is bound INTO the commit — the anti-copy / anti-front-run
// control: a peer who observes operator A's commit cannot replay it as their own
// (recomputation with their own address yields a different digest, so
// RevealResponse rejects it).
func ComputeCommit(taskID, modelSpecHash, promptHash, outputHash, embeddingHash common.Hash, operator common.Address, nonce common.Hash) common.Hash {
	buf := make([]byte, 0, 32*5+20+32)
	buf = append(buf, taskID.Bytes()...)
	buf = append(buf, modelSpecHash.Bytes()...)
	buf = append(buf, promptHash.Bytes()...)
	buf = append(buf, outputHash.Bytes()...)
	buf = append(buf, embeddingHash.Bytes()...)
	buf = append(buf, operator.Bytes()...)
	buf = append(buf, nonce.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(buf))
}
