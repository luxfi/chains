// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// vertex_test.go covers the DAG side: how a vertex is built from pending work,
// named, encoded, and recorded.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"

	aicore "github.com/luxfi/ai/pkg/aivm"
)

func TestAVertexBatchesPendingWork(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)

	// Nothing pending, nothing to batch.
	_, err := vm.BuildVertex(ctx)
	require.ErrorContains(err, "no pending tasks")

	fee := uint64(1_000_000_000_000_000)
	require.NoError(vm.SubmitTask(&aicore.Task{ID: "job-a", Fee: fee}))
	require.NoError(vm.SubmitTask(&aicore.Task{ID: "job-b", Fee: fee}))

	v, err := vm.BuildVertex(ctx)
	require.NoError(err)
	av := v.(*AIVertex)

	require.Equal(uint64(1), av.Height())
	require.Equal(uint32(0), av.Epoch())
	require.Equal([]ids.ID{vm.lastAccepted.ID_}, av.Parents())
	require.Len(av.Txs(), 2)
	require.Len(av.jobIDs, 2)
	require.Equal(choices.Processing, av.Status())
	require.NotEqual(ids.Empty, av.ID())
	require.NotEmpty(av.Bytes())
	require.NoError(av.Verify(ctx))

	// It round-trips through the wire and keeps its name.
	parsed, err := vm.ParseVertex(ctx, av.Bytes())
	require.NoError(err)
	require.Equal(av.ID(), parsed.ID())
	require.True(av.ConflictsVertex(parsed), "the same jobs must still conflict")
	require.False(av.ConflictsVertex(&AIVertex{jobIDs: []string{"elsewhere"}}))

	// A vertex is not a block: recording one stores it under its own prefix and
	// leaves the block chain's head where it was.
	head := vm.lastAccepted.ID_
	require.NoError(av.Accept(ctx))
	require.Equal(choices.Accepted, av.Status())
	stored, err := vm.db.Get(vertexKey(av.ID()))
	require.NoError(err)
	require.Equal(av.Bytes(), stored)
	require.Equal(head, vm.lastAccepted.ID_, "accepting a vertex moved the block chain's tip")
	_, err = vm.db.Get(blockKey(av.ID()))
	require.ErrorIs(err, database.ErrNotFound)

	require.NoError(parsed.Reject(ctx))
	require.Equal(choices.Rejected, parsed.(*AIVertex).Status())
}

// A vertex carrying work with no name is not verifiable: the job id is the
// conflict key, so a task without one conflicts with nothing and commutes with
// everything.
func TestAVertexRefusesUnnamedWork(t *testing.T) {
	v := &AIVertex{tasks: []*aicore.Task{{ID: ""}}}
	require.ErrorContains(t, v.Verify(context.Background()), "task missing ID")
}

// The same wire names different vertices on different chains, for the reason a
// block's id does: the chain id is hashed in and never encoded, so a peer cannot
// supply it.
func TestAVertexDoesNotCrossChains(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	here := oneVM(t)
	elsewhere := oneVM(t)
	require.NoError(here.SubmitTask(&aicore.Task{ID: "job-a", Fee: 1_000_000_000_000_000}))

	v, err := here.BuildVertex(ctx)
	require.NoError(err)
	foreign, err := elsewhere.ParseVertex(ctx, v.Bytes())
	require.NoError(err)
	require.NotEqual(v.ID(), foreign.ID())

	// Malformed bytes are refused rather than decoded into an empty vertex.
	_, err = here.ParseVertex(ctx, []byte("not a vertex"))
	require.Error(err)
}

func TestBuildVertexNeedsARunningChain(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	require.NoError(vm.Shutdown(ctx))
	_, err := vm.BuildVertex(ctx)
	require.ErrorIs(err, ErrNotInitialized)

	// A VM with no tip has no parent to hang a vertex from.
	bare := &VM{running: true, db: memdb.New()}
	_, err = bare.BuildVertex(ctx)
	require.ErrorContains(err, "no parent block")
}

// A vertex carrying work that cannot be encoded cannot be built or recorded:
// the id is derived from the encoding, so a half-written one names a different
// vertex.
func TestAVertexThatCannotBeEncodedIsRefused(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	require.NoError(vm.SubmitTask(&aicore.Task{
		ID: "job-a", Fee: 1_000_000_000_000_000, Input: json.RawMessage(`{`),
	}))
	_, err := vm.BuildVertex(ctx)
	require.ErrorContains(err, "tasks")

	v := &AIVertex{height: 1, jobIDs: []string{"j"}, tasks: []*aicore.Task{{ID: "j", Input: json.RawMessage(`{`)}}, vm: vm}
	require.ErrorContains(v.Accept(ctx), "tasks")

	// Conflict detection is over vertices; anything else conflicts with nothing.
	require.False(v.ConflictsVertex(notAVertex{}))
}

// notAVertex satisfies the engine's vertex interface without being one of ours.
type notAVertex struct{ vertex.Vertex }
