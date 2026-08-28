// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"bytes"
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// vmWithPending builds a VM holding n ready bridge requests and a stored parent.
func vmWithPending(t *testing.T, n int) (*VM, []ids.ID) {
	t.Helper()

	vm := &VM{
		log:            log.NewNoOpLogger(),
		config:         BridgeConfig{MinConfirmations: 1, MaxBridgeAmount: 1 << 40, DailyBridgeLimit: 1 << 40},
		pendingBridges: make(map[ids.ID]*BridgeRequest, n),
		bridgeRegistry: &BridgeRegistry{DailyVolume: make(map[string]uint64)},
	}
	vm.chain = chain.New[*Block](memdb.New(), nil)

	parent := &Block{BlockHeight: 0, BlockTimestamp: 0, ParentID_: ids.Empty, BridgeRequests: []*BridgeRequest{}, vm: vm}
	parent.ID_ = parent.computeID()
	_, _, err := vm.chain.Open(parent, vm.parseBlock)
	require.NoError(t, err)

	want := make([]ids.ID, 0, n)
	for i := 0; i < n; i++ {
		id := ids.GenerateTestID()
		vm.pendingBridges[id] = &BridgeRequest{
			ID:            id,
			SourceChain:   "C",
			DestChain:     "eth",
			Amount:        1,
			Recipient:     make([]byte, 20),
			Confirmations: 12,
			Status:        "pending",
			CreatedAt:     time.Unix(0, 0),
		}
		want = append(want, id)
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

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(err)

	got := make([]ids.ID, 0, len(want))
	for _, req := range blk.(*Block).BridgeRequests {
		got = append(got, req.ID)
	}
	require.Equal(want, got, "requests must be carried in id order")

	// Rebuilding from the same pending set must reproduce the same block.
	again, err := vm.BuildBlock(context.Background())
	require.NoError(err)
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

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(err)

	got := make([]ids.ID, 0, maxRequestsPerBlock)
	for _, req := range blk.(*Block).BridgeRequests {
		got = append(got, req.ID)
	}
	require.Len(got, maxRequestsPerBlock)
	require.Equal(want[:maxRequestsPerBlock], got, "the cap must take the lowest ids, not a random draw")
}
