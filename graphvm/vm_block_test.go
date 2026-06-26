// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// initVM initializes a fresh G-Chain VM the way the node does, with the given
// genesis bytes, and returns it ready to serve.
func initVM(t *testing.T, genesis []byte) *VM {
	t.Helper()
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime: &runtime.Runtime{NetworkID: 1},
		DB:      memdb.New(),
		Genesis: genesis,
	}))
	return vm
}

// TestInitializeResolvesLastAcceptedBlock reproduces the exact call sequence the
// ZAP VM server performs inside handleInitialize (vm/rpc/vm_server_zap.go:262-270):
// Initialize -> LastAccepted -> GetBlock(lastAccepted). Before the genesis-block
// fix the GetBlock call returned errNotImplemented, surfacing on lux-mainnet as
// "G chain ... failed to initialize VM: zap initialize: remote error: get last
// accepted block: not implemented" and failing the node health check.
func TestInitializeResolvesLastAcceptedBlock(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := initVM(t, []byte(`{"defaultSchema":"type Query { hello: String }","schemaVersion":"1"}`))

	// LastAccepted must be a real, non-empty block ID.
	lastAccepted, err := vm.LastAccepted(ctx)
	require.NoError(err)
	require.NotEqual(ids.Empty, lastAccepted)

	// GetBlock(lastAccepted) is the call that returned "not implemented".
	blk, err := vm.GetBlock(ctx, lastAccepted)
	require.NoError(err)
	require.Equal(lastAccepted, blk.ID())
	require.Equal(uint64(0), blk.Height())
	require.Equal(ids.Empty, blk.Parent())
	require.NotEmpty(blk.Bytes())

	// The ZAP server also reads Timestamp() for the InitializeResponse; it must
	// be deterministic (genesis epoch), never time.Now().
	require.Equal(genesisTimestamp, blk.Timestamp())

	// GetBlockIDAtHeight(0) resolves to the same genesis block.
	at0, err := vm.GetBlockIDAtHeight(ctx, 0)
	require.NoError(err)
	require.Equal(lastAccepted, at0)
}

// TestGenesisBlockRoundTrip proves Bytes()/ParseBlock are inverse and content-
// addressed: re-parsing the genesis block yields a byte- and ID-identical block.
// The engine relies on this when it re-parses the accepted frontier during
// bootstrap.
func TestGenesisBlockRoundTrip(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := initVM(t, []byte(`{"schemaVersion":"1"}`))

	lastAccepted, err := vm.LastAccepted(ctx)
	require.NoError(err)
	orig, err := vm.GetBlock(ctx, lastAccepted)
	require.NoError(err)

	reparsed, err := vm.ParseBlock(ctx, orig.Bytes())
	require.NoError(err)
	require.Equal(orig.ID(), reparsed.ID())
	require.Equal(orig.Bytes(), reparsed.Bytes())
	require.Equal(orig.Height(), reparsed.Height())
	require.Equal(orig.Parent(), reparsed.Parent())
	require.Equal(orig.Timestamp(), reparsed.Timestamp())
}

// TestUnknownBlockNotFound proves a non-genesis ID is reported as a genuine miss
// (database.ErrNotFound), which the ZAP server maps to the wire NotFound code —
// not the old errNotImplemented that broke initialization.
func TestUnknownBlockNotFound(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := initVM(t, []byte(`{"schemaVersion":"1"}`))

	_, err := vm.GetBlock(ctx, ids.GenerateTestID())
	require.ErrorIs(err, database.ErrNotFound)

	_, err = vm.GetBlockIDAtHeight(ctx, 1)
	require.ErrorIs(err, database.ErrNotFound)
}

// TestGenesisDeterministic proves two independent VMs given identical genesis
// bytes derive the SAME genesis block ID — the cross-validator agreement the
// chain needs — while different genesis bytes derive different IDs.
func TestGenesisDeterministic(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	idFor := func(genesis []byte) ids.ID {
		id, err := initVM(t, genesis).LastAccepted(ctx)
		require.NoError(err)
		return id
	}

	a := []byte(`{"defaultSchema":"type Query { a: Int }","schemaVersion":"7"}`)
	b := []byte(`{"defaultSchema":"type Query { b: Int }","schemaVersion":"7"}`)

	require.Equal(idFor(a), idFor(a))
	require.NotEqual(idFor(a), idFor(b))
}
