// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// composeHarness stakes nOps operators against one model spec and funds a
// requester, returning everything OpenTask needs.
func composeHarness(t *testing.T, nOps int) (*Engine, *MemState, *MemLedger, common.Address, []common.Address) {
	t.Helper()
	return newHarness(t, nOps, uint256.NewInt(1_000_000_000_000_000_000))
}

func composeSpec(requester common.Address, pool []common.Address, n, threshold uint32) TaskSpec {
	return TaskSpec{
		Requester:  requester,
		Code:       modelSpec,
		Input:      promptHash,
		Candidates: pool,
		N:          n,
		Threshold:  threshold,
		Fee:        uint256.NewInt(0),
		Reward:     uint256.NewInt(1_000_000_000_000_000_000),
	}
}

// TestOpenTaskRefusesARepeatedPool is the hole a caller-supplied pool opens: the
// draw returns N entries of the pool, so one address repeated N times would be
// drawn N times and a quorum would be one party agreeing with itself. The pool is
// reduced to distinct addresses before anything is counted, so padding buys
// nothing.
func TestOpenTaskRefusesARepeatedPool(t *testing.T) {
	e, st, lg, requester, ops := composeHarness(t, eligible)

	repeated := []common.Address{ops[0], ops[0], ops[0], ops[0], ops[0]}
	_, err := e.OpenTask(st, lg, composeSpec(requester, repeated, 3, 3), 100)
	require.ErrorIs(t, err, ErrNotEnoughEligible,
		"five copies of one address are one candidate, not five")

	// Padding a genuine pool with repeats does not buy margin either: three
	// distinct operators need five, and repeats do not make five.
	padded := []common.Address{ops[0], ops[1], ops[2], ops[0], ops[1], ops[2], ops[0]}
	_, err = e.OpenTask(st, lg, composeSpec(requester, padded, 3, 2), 100)
	require.ErrorIs(t, err, ErrEligibleBelowMargin)

	// A refusal moves nothing.
	require.Equal(t, uint256.NewInt(0).String(), e.GetCredit(st, ops[0]).String())
}

// TestOpenTaskDrawsDistinctOperators: when the pool is large enough, every
// selected slot holds a different operator.
func TestOpenTaskDrawsDistinctOperators(t *testing.T) {
	e, st, lg, requester, ops := composeHarness(t, eligible)

	taskID, err := e.OpenTask(st, lg, composeSpec(requester, ops, 5, 3), 100)
	require.NoError(t, err)

	seen := map[common.Address]bool{}
	for i := uint32(0); i < 5; i++ {
		op := e.SelectedAt(st, taskID, i)
		require.False(t, seen[op], "operator %s drawn twice", op)
		seen[op] = true
	}
	require.Len(t, seen, 5)
}

// TestDistinctPreservesOrder: the draw is reproducible only against a pool every
// validator builds identically, so deduplication must not reorder it.
func TestDistinctPreservesOrder(t *testing.T) {
	a, b, c := addr(0x01), addr(0x02), addr(0x03)
	require.Equal(t, []common.Address{a, b, c}, distinct([]common.Address{a, b, c}))
	require.Equal(t, []common.Address{a, b, c}, distinct([]common.Address{a, b, a, c, b, a}))
	require.Equal(t, []common.Address{c, a, b}, distinct([]common.Address{c, c, a, b, a}))
	require.Empty(t, distinct(nil))

	// The caller's slice is not mutated.
	in := []common.Address{b, a, b}
	_ = distinct(in)
	require.Equal(t, []common.Address{b, a, b}, in)
}

// TestOpenTaskAndTheModelPathAgree: a pool that is already distinct is passed
// through unchanged, so composing gives the same draw the model path gives.
func TestOpenTaskAndTheModelPathAgree(t *testing.T) {
	e, st, _, _, _ := composeHarness(t, eligible)

	pool := e.Eligible(st, modelSpec)
	require.Len(t, pool, eligible)
	require.Equal(t, pool, distinct(pool), "eligibleSet cannot produce a repeat")

	// Draw is a pure function of the pool and the anchor.
	first, err := Draw(append([]common.Address(nil), pool...), h(0x77), 5)
	require.NoError(t, err)
	second, err := Draw(append([]common.Address(nil), pool...), h(0x77), 5)
	require.NoError(t, err)
	require.Equal(t, first, second)
}

// TestOpenTaskRefusesNilAmounts keeps the money path fail-closed at the seam.
func TestOpenTaskRefusesNilAmounts(t *testing.T) {
	e, st, lg, requester, ops := composeHarness(t, eligible)

	spec := composeSpec(requester, ops, 3, 2)
	spec.Fee = nil
	_, err := e.OpenTask(st, lg, spec, 100)
	require.ErrorIs(t, err, ErrIntentNilAmount)

	spec = composeSpec(requester, ops, 3, 2)
	spec.Reward = nil
	_, err = e.OpenTask(st, lg, spec, 100)
	require.ErrorIs(t, err, ErrIntentNilAmount)
}

// TestStakedMatchesEligibility: the exported predicate a composing VM filters
// with is the same one the model path uses.
func TestStakedMatchesEligibility(t *testing.T) {
	e, st, lg, _, ops := composeHarness(t, eligible)

	for _, op := range ops {
		require.True(t, Staked(st, op))
		require.True(t, e.IsEligible(st, op, modelSpec))
	}
	require.False(t, Staked(st, addr(0xEE)), "an address with no bond is not staked")

	// Deregistering removes an operator from both answers at once.
	require.NoError(t, e.DeregisterOperator(st, ops[0], 200))
	require.False(t, Staked(st, ops[0]))
	require.False(t, e.IsEligible(st, ops[0], modelSpec))
	require.NotContains(t, e.Eligible(st, modelSpec), ops[0])
	_ = lg
}
