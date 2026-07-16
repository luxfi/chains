// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"

	aicore "github.com/luxfi/ai/pkg/aivm"
)

// mkIntent builds a CIntent whose IntentID is the real ComputeIntentID over its
// own fields — so a wire round-trip that preserves the id-binding invariant is a
// genuine proof the security-critical fields survived byte-for-byte.
func mkWireIntent() CIntent {
	cChain := common.HexToHash("0x0c0c")
	aChain := common.HexToHash("0x0a0a")
	cTx := common.HexToHash("0xdeadbeef")
	caller := common.HexToAddress("0xF00DBABE00000000000000000000000000000001")
	model := common.HexToHash("0x1111")
	prompt := common.HexToHash("0x2222")
	fee := uint256.NewInt(123456789)
	in := CIntent{
		CChainID:          cChain,
		AChainID:          aChain,
		CTxHash:           cTx,
		CallIndex:         7,
		Caller:            caller,
		ModelSpecHash:     model,
		PromptHash:        prompt,
		N:                 5,
		Threshold:         3,
		Fee:               fee,
		RewardPerOperator: uint256.NewInt(1_000_000),
	}
	in.IntentID = ComputeIntentID(cChain, aChain, cTx, in.CallIndex, caller, model, prompt, in.N, in.Threshold, fee)
	return in
}

func TestBlockWireRoundTrip(t *testing.T) {
	require := require.New(t)

	orig := &Block{
		ParentID_:       ids.GenerateTestID(),
		Height_:         42,
		Timestamp_:      time.Unix(1_700_000_123, 456).UTC(),
		MerkleRoot:      [32]byte{1, 2, 3, 9, 9},
		ReceiptRoot:     common.HexToHash("0xabc123"),
		ImportedIntents: []CIntent{mkWireIntent()},
		Tasks: []aicore.Task{{
			ID:     "task-1",
			Type:   aicore.TaskTypeInference,
			Model:  "qwen3-8b",
			Input:  json.RawMessage(`{"b":1,"a":2}`),
			Status: aicore.TaskStatusPending,
			Fee:    99,
		}},
	}

	wire, err := orig.Marshal()
	require.NoError(err)

	got := &Block{}
	require.NoError(parseBlock(wire, got))

	// structural fields
	require.Equal(orig.ParentID_, got.ParentID_)
	require.Equal(orig.Height_, got.Height_)
	require.Equal(orig.Timestamp_.UnixNano(), got.Timestamp_.UnixNano())
	require.Equal(orig.MerkleRoot, got.MerkleRoot)
	require.Equal(orig.ReceiptRoot, got.ReceiptRoot)

	// security-critical CIntent seam: every field survived, AND the id-binding
	// invariant re-derives — exactly what ImportCommittedIntent re-checks.
	require.Len(got.ImportedIntents, 1)
	gi := got.ImportedIntents[0]
	oi := orig.ImportedIntents[0]
	require.Equal(oi.IntentID, gi.IntentID)
	require.Equal(oi.Caller, gi.Caller)
	require.Equal(oi.CallIndex, gi.CallIndex)
	require.Equal(oi.N, gi.N)
	require.Equal(oi.Threshold, gi.Threshold)
	require.Equal(0, oi.Fee.Cmp(gi.Fee), "Fee value preserved")
	require.Equal(0, oi.RewardPerOperator.Cmp(gi.RewardPerOperator), "reward preserved")
	require.Equal(gi.IntentID, ComputeIntentID(
		gi.CChainID, gi.AChainID, gi.CTxHash, gi.CallIndex, gi.Caller,
		gi.ModelSpecHash, gi.PromptHash, gi.N, gi.Threshold, gi.Fee,
	), "id-binding invariant holds after wire round-trip")

	// dynamic JSON payload round-trips verbatim
	require.Len(got.Tasks, 1)
	require.Equal(orig.Tasks[0].ID, got.Tasks[0].ID)
	require.JSONEq(string(orig.Tasks[0].Input), string(got.Tasks[0].Input))

	// block id is stable across the wire round-trip (parse∘marshal is byte-stable)
	require.Equal(orig.computeID(), got.computeID(), "block id stable across round-trip")
}

func TestBlockWireEmpty(t *testing.T) {
	require := require.New(t)
	// A minimal block (BuildBlock's common case: no tasks/results/pregs) must
	// round-trip and produce a deterministic, non-empty id.
	orig := &Block{ParentID_: ids.Empty, Height_: 1, Timestamp_: time.Unix(1, 0).UTC()}
	wire, err := orig.Marshal()
	require.NoError(err)
	got := &Block{}
	require.NoError(parseBlock(wire, got))
	require.Equal(orig.Height_, got.Height_)
	require.Empty(got.ImportedIntents)
	require.Equal(orig.computeID(), got.computeID())
}

func TestVertexWireRoundTrip(t *testing.T) {
	require := require.New(t)

	orig := &AIVertex{
		height:  17,
		epoch:   2,
		parents: []ids.ID{ids.GenerateTestID(), ids.GenerateTestID()},
		txIDs:   []ids.ID{ids.GenerateTestID()},
		jobIDs:  []string{"job-123", "job-456"},
	}
	orig.id = orig.computeID()

	wire := marshalVertex(orig)
	got := &AIVertex{}
	require.NoError(parseVertex(wire, got))

	require.Equal(orig.height, got.height)
	require.Equal(orig.epoch, got.epoch)
	require.Equal(orig.parents, got.parents)
	require.Equal(orig.txIDs, got.txIDs)
	require.Equal(orig.jobIDs, got.jobIDs, "jobIDs survive the wire (previously lost: json of all-unexported fields was {})")

	// vertex id is stable across round-trip, and conflict detection is preserved
	require.Equal(orig.computeID(), got.computeID(), "vertex id stable across round-trip")
	require.True(got.Conflicts(orig), "same jobIDs still conflict after round-trip")
}

func TestWireKindGuards(t *testing.T) {
	require := require.New(t)

	blk := &Block{ParentID_: ids.Empty, Height_: 1, Timestamp_: time.Unix(1, 0).UTC()}
	blkWire, err := blk.Marshal()
	require.NoError(err)
	vtxWire := marshalVertex(&AIVertex{height: 1, jobIDs: []string{"j"}})

	// cross-parsing the wrong kind is rejected (defense-in-depth discriminator)
	require.Error(parseBlock(vtxWire, &Block{}), "vertex bytes must not parse as a block")
	require.Error(parseVertex(blkWire, &AIVertex{}), "block bytes must not parse as a vertex")

	// trailing bytes are rejected (canonical)
	require.Error(parseBlock(append(append([]byte(nil), blkWire...), 0x00), &Block{}))
	require.Error(parseVertex(append(append([]byte(nil), vtxWire...), 0x00), &AIVertex{}))
}
