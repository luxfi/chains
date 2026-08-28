// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"bytes"
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
)

// vmWithPending builds a VM holding n transfers ready for a block, and the ids
// they should be carried in.
func vmWithPending(t *testing.T, n int) (*VM, []ids.ID) {
	t.Helper()
	cfg := testConfig()
	cfg.DailyBridgeLimit = 1 << 40
	vm := bootOn(t, memdb.New(), cfg)

	want := make([]ids.ID, 0, n)
	for i := 0; i < n; i++ {
		req := requestFor(uint64(i+1), 1)
		pend(vm, req)
		want = append(want, req.ID)
	}
	sort.Slice(want, func(i, j int) bool { return bytes.Compare(want[i][:], want[j][:]) < 0 })
	return vm, want
}

// TestBuildBlockOrdersRequestsDeterministically proves a block is a function of
// its inputs. BuildBlock collected requests by ranging pendingBridges, a map, so
// Go's randomised iteration decided the order — and that order is hashed into the
// block id (computeID) and written to the wire. The same pending set produced a
// different block on every build.
func TestBuildBlockOrdersRequestsDeterministically(t *testing.T) {
	require := require.New(t)
	vm, want := vmWithPending(t, 24)

	blk := build(t, vm)

	got := make([]ids.ID, 0, len(want))
	for _, req := range blk.BridgeRequests {
		got = append(got, req.ID)
	}
	require.Equal(want, got, "requests must be carried in id order")

	// Rebuilding from the same pending set must reproduce the same block. The
	// timestamp is the one thing that moves, so it is held still.
	again := build(t, vm)
	again.BlockTimestamp = blk.BlockTimestamp
	again.ID_ = again.computeID()
	require.Equal(blk.ID(), again.ID(), "the same pending set must build the same block")
	require.Equal(blk.Bytes(), again.Bytes())
}

// TestBuildBlockCapIsADeterministicPrefix proves the size cap selects a defined
// subset. Applied while ranging a map it picked 100 requests at random out of the
// ready set, so a request could be passed over indefinitely for no reason and two
// builds carried different work.
func TestBuildBlockCapIsADeterministicPrefix(t *testing.T) {
	require := require.New(t)
	vm, want := vmWithPending(t, maxRequestsPerBlock+40)

	blk := build(t, vm)

	got := make([]ids.ID, 0, maxRequestsPerBlock)
	for _, req := range blk.BridgeRequests {
		got = append(got, req.ID)
	}
	require.Len(got, maxRequestsPerBlock)
	require.Equal(want[:maxRequestsPerBlock], got, "the cap must take the lowest ids, not a random draw")
}

// TestBuildBlockRefusesWhenNothingIsReady keeps an empty block off the chain:
// Verify refuses one, so building one would wedge the proposer.
func TestBuildBlockRefusesWhenNothingIsReady(t *testing.T) {
	vm, _ := vmWithPending(t, 0)
	_, err := vm.BuildBlock(context.Background())
	require.Error(t, err)
}

// TestWhatIsBuiltIsWhatVerifies is the property that keeps the chain moving.
//
// Assembly and verification used different rules: the builder filtered on
// confirmation depth alone while Verify also applied the per-transfer cap and
// the daily cap. One oversized transfer in the pending set was therefore
// proposed by the builder, refused by every node, put straight back in the
// pending set by the rejection, and proposed again — block production stopped
// and did not resume.
func TestWhatIsBuiltIsWhatVerifies(t *testing.T) {
	cfg := testConfig()
	cfg.MaxBridgeAmount = 100
	cfg.DailyBridgeLimit = 250
	vm := bootOn(t, memdb.New(), cfg)

	oversized := requestFor(1, 5_000) // over the per-transfer cap
	fine := requestFor(2, 100)
	pend(vm, oversized, fine)

	blk := build(t, vm)
	require.Len(t, blk.BridgeRequests, 1, "the builder must leave behind what Verify would refuse")
	require.Equal(t, fine.ID, blk.BridgeRequests[0].ID)
	require.NoError(t, blk.Verify(context.Background()), "what was built must verify")
	require.NoError(t, blk.Accept(context.Background()))

	// The daily cap is the same rule in the same place: 100 has moved of 250,
	// so the next block carries what fits and stops there.
	pend(vm, requestFor(3, 100), requestFor(4, 100))
	second := build(t, vm)
	require.Len(t, second.BridgeRequests, 1, "the builder stops at the daily cap, as Verify does")
	require.NoError(t, second.Verify(context.Background()))
}
