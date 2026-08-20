// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// custody_set_test.go — who holds a share of a custody key must not be decidable
// by anyone who can generate certificates.
package mpcvm

import (
	"context"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/runtime"
	validators "github.com/luxfi/validators"
	"github.com/luxfi/validators/validatorstest"
)

// weightedState is a validator set with explicit per-node stake.
func weightedState(w map[ids.NodeID]uint64) *validatorstest.TestState {
	return &validatorstest.TestState{
		GetValidatorSetF: func(context.Context, uint64, ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
			out := make(map[ids.NodeID]*validators.GetValidatorOutput, len(w))
			for n, weight := range w {
				out[n] = &validators.GetValidatorOutput{NodeID: n, Weight: weight}
			}
			return out, nil
		},
	}
}

func setVM(vs *validatorstest.TestState) *VM {
	return &VM{rt: &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), NetworkID: 3, ValidatorState: vs}}
}

// TestCustodySetFollowsStakeNotNodeID is the attack this selection exists to
// stop.
//
// Seats used to go to the first N node ids in lexicographic order, and a node id
// is a hash of that node's certificate — so an attacker grinds certificates
// offline until its ids sort first and lands a seat in EVERY key the chain
// generates, for the price of some hashing. Seats now follow stake, which cannot
// be ground: a minimum-stake node sorting first in id order must not displace a
// validator that actually holds stake.
func TestCustodySetFollowsStakeNotNodeID(t *testing.T) {
	// Build ids and use the smallest as the attacker, standing in for a ground
	// certificate: it wins every lexicographic comparison.
	ids4 := make([]ids.NodeID, 0, 4)
	for i := 0; i < 4; i++ {
		ids4 = append(ids4, ids.GenerateTestNodeID())
	}
	attacker := ids4[0]
	for _, n := range ids4 {
		if n.String() < attacker.String() {
			attacker = n
		}
	}

	weights := map[ids.NodeID]uint64{}
	for _, n := range ids4 {
		weights[n] = 1_000_000 // real validators, real stake
	}
	weights[attacker] = 1 // minimum stake, but sorts first by id

	vm := setVM(weightedState(weights))
	got, err := vm.custodySet(context.Background(), 0, 3)
	if err != nil {
		t.Fatalf("custodySet: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("selected %d seats, want 3", len(got))
	}
	for _, p := range got {
		if string(p) == attacker.String() {
			t.Fatal("a minimum-stake node that merely sorts first took a custody seat — " +
				"grinding certificates would buy a share of every key on the chain")
		}
	}
}

// TestCustodySetIsIdenticalOnEveryValidator: selection must be a pure function of
// replicated state, or validators derive different sets and no ceremony id ever
// matches. Map iteration order in Go is randomised, so this catches a selection
// that leaks it.
func TestCustodySetIsIdenticalOnEveryValidator(t *testing.T) {
	weights := map[ids.NodeID]uint64{}
	for i := 0; i < 6; i++ {
		weights[ids.GenerateTestNodeID()] = uint64(100 - i) // distinct stakes
	}
	vs := weightedState(weights)

	first, err := setVM(vs).custodySet(context.Background(), 0, 4)
	if err != nil {
		t.Fatalf("custodySet: %v", err)
	}
	for i := 0; i < 12; i++ {
		again, err := setVM(vs).custodySet(context.Background(), 0, 4)
		if err != nil {
			t.Fatalf("custodySet: %v", err)
		}
		if len(again) != len(first) {
			t.Fatalf("set size differs between validators: %d vs %d", len(again), len(first))
		}
		for j := range first {
			if first[j] != again[j] {
				t.Fatalf("validators derived different custody sets at seat %d: %s vs %s",
					j, first[j], again[j])
			}
		}
	}
}

// TestCustodySetRefusesAnUndersizedValidatorSet: a policy needing more seats than
// there are validators must fail loudly, not silently select fewer and produce a
// key with a smaller quorum than the policy declares.
func TestCustodySetRefusesAnUndersizedValidatorSet(t *testing.T) {
	weights := map[ids.NodeID]uint64{}
	for i := 0; i < 2; i++ {
		weights[ids.GenerateTestNodeID()] = 10
	}
	if _, err := setVM(weightedState(weights)).custodySet(context.Background(), 0, 5); err == nil {
		t.Fatal("a 5-seat policy over 2 validators must refuse, not silently shrink the quorum")
	}
}
