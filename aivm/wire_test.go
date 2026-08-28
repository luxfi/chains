// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
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

	// The name is a function of the encoding, so parse∘marshal being byte-stable
	// is what keeps a block's id stable across the wire.
	require.NoError(orig.name())
	require.NoError(got.name())
	require.Equal(orig.bytes, got.bytes, "re-encoding a parsed block reproduces the wire")
	require.Equal(orig.ID_, got.ID_, "block id stable across round-trip")
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
	require.NoError(orig.name())
	require.NoError(got.name())
	require.Equal(orig.ID_, got.ID_)
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

	wire, err := marshalVertex(orig)
	require.NoError(err)
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
	vtxWire, err := marshalVertex(&AIVertex{height: 1, jobIDs: []string{"j"}})
	require.NoError(err)

	// cross-parsing the wrong kind is rejected (defense-in-depth discriminator)
	require.Error(parseBlock(vtxWire, &Block{}), "vertex bytes must not parse as a block")
	require.Error(parseVertex(blkWire, &AIVertex{}), "block bytes must not parse as a vertex")

	// trailing bytes are rejected (canonical)
	require.Error(parseBlock(append(append([]byte(nil), blkWire...), 0x00), &Block{}))
	require.Error(parseVertex(append(append([]byte(nil), vtxWire...), 0x00), &AIVertex{}))
}

// The decoder walked the declared lengths and stopped, ignoring whatever
// followed. Two different buffers therefore decoded to the same value — and
// since a block is named by its own canonical re-encoding, the padded one was
// accepted and would have been served under the canonical one's id.
func TestBytesPastTheDeclaredLengthsAreRefused(t *testing.T) {
	require := require.New(t)

	in := CIntent{IntentID: hashOf(1), Fee: uint256.NewInt(1), RewardPerOperator: uint256.NewInt(1)}
	one := marshalCIntent(in)

	wire := func(blob []byte) []byte {
		b := zap.NewBuilder(zap.HeaderSize + blkSize + len(blob) + 256)
		lensOff := writeU32List(b, []uint32{uint32(len(one))})
		ob := b.StartObject(blkSize)
		ob.SetUint8(blkKind, uint8(kindBlock))
		ob.SetUint64(blkHeight, 3)
		ob.SetList(blkIntentLens, lensOff, 1)
		ob.SetBytes(blkIntentBlob, blob)
		ob.FinishAsRoot()
		return b.Finish()
	}

	// The honest encoding of the same object still parses.
	require.NoError(parseBlock(wire(one), &Block{}))

	// Four stray bytes past the one declared length do not.
	padded := append(append([]byte(nil), one...), 0xDE, 0xAD, 0xBE, 0xEF)
	require.ErrorContains(parseBlock(wire(padded), &Block{}), "past the last")

	// So does a length running past the end of the blob it indexes.
	require.ErrorContains(parseBlock(wire(one[:len(one)-4]), &Block{}), "past the blob")
}

// splitIDs rounded the blob length down to a whole number of ids, so a tail
// shorter than one id was discarded and a buffer with bytes the decoder never
// read still decoded.
func TestAShortTailInAnIDListIsRefused(t *testing.T) {
	require := require.New(t)

	v := &AIVertex{height: 3, parents: []ids.ID{ids.GenerateTestID()}, jobIDs: []string{"j"}}
	wire, err := marshalVertex(v)
	require.NoError(err)
	require.NoError(parseVertex(wire, &AIVertex{}))

	ids17 := make([]byte, 33) // one id plus one byte
	_, err = splitIDs(ids17, "parent list")
	require.ErrorContains(err, "not a multiple of 32")

	got, err := splitIDs(nil, "parent list")
	require.NoError(err)
	require.Nil(got)
}

// A block arriving off the wire used to have no size bound at all: a 49 MB
// buffer of nothing but repeated provider registrations was decoded without
// complaint, so a peer chose how much memory this node allocated.
func TestAnOversizedBlockIsRefused(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	big := make([]ProviderReg, 0, 20000)
	for i := 0; i < 20000; i++ {
		big = append(big, ProviderReg{ProviderID: string(make([]byte, 400))})
	}
	blk := &Block{Height_: 1, ProviderRegs: big}
	wire, err := blk.Marshal()
	require.NoError(err)
	require.Greater(len(wire), MaxBlockSize)

	_, err = vm.ParseBlock(ctx, wire)
	require.ErrorIs(err, ErrInvalidBlock)

	// The bound is checked before the decode, so it holds whatever the bytes
	// are — including a buffer that is not a block at all.
	_, err = vm.ParseBlock(ctx, make([]byte, MaxBlockSize+1))
	require.ErrorIs(err, ErrInvalidBlock)

	// A block this node builds is held to the same bound, so a proposer cannot
	// produce one its own peers refuse to parse.
	oversize := &Block{ParentID_: vm.lastAccepted.ID_, Height_: 1, Timestamp_: vm.clock.Time(), ProviderRegs: big, vm: vm}
	require.NoError(oversize.name())
	require.ErrorIs(oversize.Verify(ctx), ErrInvalidBlock)
}

// An element the encoder cannot represent used to become no element at all: the
// marshal error was dropped, a zero length was written, and the block's id was
// computed over an encoding missing work its author believed it carried.
func TestAnUnencodableElementIsReported(t *testing.T) {
	require := require.New(t)

	blk := &Block{Height_: 1, Tasks: []aicore.Task{{ID: "t", Input: json.RawMessage(`{`)}}}
	_, err := blk.Marshal()
	require.ErrorContains(err, "tasks")

	v := &AIVertex{height: 1, results: []*aicore.TaskResult{{TaskID: "t", Output: json.RawMessage(`}`)}}}
	_, err = marshalVertex(v)
	require.ErrorContains(err, "results")
}

// buildBlockWire assembles a block wire by hand so a test can put bytes on it
// that no encoder would produce.
func buildBlockWire(t *testing.T, set func(zap.ObjectBuilder, *zap.Builder)) []byte {
	t.Helper()
	b := zap.NewBuilder(zap.HeaderSize + blkSize + 4096)
	ob := b.StartObject(blkSize)
	ob.SetUint8(blkKind, uint8(kindBlock))
	ob.SetUint64(blkHeight, 1)
	set(ob, b)
	ob.FinishAsRoot()
	return b.Finish()
}

// Every nested payload is decoded, not trusted. A sub-blob that is not what its
// length says it is stops the parse rather than becoming an empty element.
func TestMalformedPayloadsStopTheParse(t *testing.T) {
	require := require.New(t)

	// A C intent that is not a zap message at all.
	junk := []byte("nothing like an intent")
	require.Error(parseBlock(buildBlockWire(t, func(ob zap.ObjectBuilder, b *zap.Builder) {
		ob.SetList(blkIntentLens, writeU32List(b, []uint32{uint32(len(junk))}), 1)
		ob.SetBytes(blkIntentBlob, junk)
	}), &Block{}))

	// One that is, with bytes past its own content: the element's length and the
	// element's encoding have to agree, or two blobs decode to one intent.
	one := marshalCIntent(CIntent{IntentID: hashOf(1), Fee: uint256.NewInt(1), RewardPerOperator: uint256.NewInt(1)})
	padded := append(append([]byte(nil), one...), 0, 0, 0, 0)
	require.ErrorContains(parseBlock(buildBlockWire(t, func(ob zap.ObjectBuilder, b *zap.Builder) {
		ob.SetList(blkIntentLens, writeU32List(b, []uint32{uint32(len(padded))}), 1)
		ob.SetBytes(blkIntentBlob, padded)
	}), &Block{}), "trailing bytes")

	// And the same for each JSON-carried payload.
	bad := []byte("{{{")
	for _, slot := range []struct {
		lens, blob int
		name       string
	}{
		{blkTaskLens, blkTaskBlob, "tasks"},
		{blkResLens, blkResBlob, "results"},
		{blkPRegLens, blkPRegBlob, "provider registrations"},
	} {
		require.Error(parseBlock(buildBlockWire(t, func(ob zap.ObjectBuilder, b *zap.Builder) {
			ob.SetList(slot.lens, writeU32List(b, []uint32{uint32(len(bad))}), 1)
			ob.SetBytes(slot.blob, bad)
		}), &Block{}), slot.name)
	}
}

// The vertex wire is held to the same standard: id lists must be whole ids,
// string and JSON lists must account for their blob exactly.
func TestMalformedVertexPayloadsStopTheParse(t *testing.T) {
	require := require.New(t)

	wire := func(set func(zap.ObjectBuilder, *zap.Builder)) []byte {
		b := zap.NewBuilder(zap.HeaderSize + vxSize + 4096)
		ob := b.StartObject(vxSize)
		ob.SetUint8(vxKind, uint8(kindVertex))
		ob.SetUint64(vxHeight, 1)
		set(ob, b)
		ob.FinishAsRoot()
		return b.Finish()
	}

	require.ErrorContains(parseVertex(wire(func(ob zap.ObjectBuilder, b *zap.Builder) {
		ob.SetBytes(vxParents, make([]byte, 33))
	}), &AIVertex{}), "parent list")

	require.ErrorContains(parseVertex(wire(func(ob zap.ObjectBuilder, b *zap.Builder) {
		ob.SetBytes(vxTxIDs, make([]byte, 31))
	}), &AIVertex{}), "tx list")

	require.ErrorContains(parseVertex(wire(func(ob zap.ObjectBuilder, b *zap.Builder) {
		ob.SetList(vxJobLens, writeU32List(b, []uint32{2}), 1)
		ob.SetBytes(vxJobBlob, []byte("abcd"))
	}), &AIVertex{}), "past the last")

	bad := []byte("{{{")
	require.Error(parseVertex(wire(func(ob zap.ObjectBuilder, b *zap.Builder) {
		ob.SetList(vxTaskLens, writeU32List(b, []uint32{uint32(len(bad))}), 1)
		ob.SetBytes(vxTaskBlob, bad)
	}), &AIVertex{}))
	require.Error(parseVertex(wire(func(ob zap.ObjectBuilder, b *zap.Builder) {
		ob.SetList(vxResLens, writeU32List(b, []uint32{uint32(len(bad))}), 1)
		ob.SetBytes(vxResBlob, bad)
	}), &AIVertex{}))
}

// A block that cannot be encoded cannot be named, and a name derived from a
// half-written encoding is the name of a different block.
func TestABlockThatCannotBeEncodedCannotBeNamed(t *testing.T) {
	require := require.New(t)

	blk := &Block{Height_: 1, Results: []aicore.TaskResult{{TaskID: "r", Output: json.RawMessage(`{`)}}}
	require.ErrorContains(blk.name(), "results")
	require.Empty(blk.Bytes())

	blk = &Block{Height_: 1, ProviderRegs: []ProviderReg{{ProviderID: "p"}}}
	require.NoError(blk.name())
}
