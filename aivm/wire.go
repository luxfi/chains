// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/holiman/uint256"
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"

	aicore "github.com/luxfi/ai/pkg/aivm"
)

// Native-ZAP struct-is-wire for A-Chain (aivm). No encoding/json on the
// block/vertex envelope, no reflection codec, no BigEndian hand-rolling — the
// Block and the AIVertex each own their Marshal/parse over a zap object at
// FIXED field offsets. Re-genesis is authorized, so the on-disk/wire format is
// exactly these offsets (canonical: parse rejects trailing bytes and checks the
// leading kind byte). blockID = sha256(Block.Marshal); vertexID = computeID over
// the structural fields — determinism follows from the deterministic wire.
//
// A 1-byte kind discriminator at object offset 0 separates the two persisted
// wire types (block vs vertex) that share the VM's db keyspace and gives version
// headroom — the same idiom as the node's proposervm blockwire.
//
// Nested/dynamic payloads use the "u32-length list + concatenated blob" idiom.
// Two sub-encodings:
//
//   - CIntent (ImportedIntents) is a FIXED-schema struct and is the
//     security-critical C->A value seam — Block.Verify re-runs it under
//     consensus and its id-binding check re-derives intent_id from these exact
//     bytes. It is encoded NATIVELY (fixed offsets, 32-byte big-endian uint256),
//     which is strictly higher-integrity than JSON: canonical bytes, no parse
//     ambiguity, and the downstream id-binding + receipt-root checks act as a
//     built-in verification of the round-trip.
//
//   - Tasks / Results / ProviderRegs carry irreducibly-dynamic data
//     (aivm.Task.Input/Output are json.RawMessage; ProviderReg embeds opaque
//     external TEE attestation quotes). Following the identityvm Claims
//     precedent, each element rides the wire as one opaque, self-describing
//     canonical-JSON blob in a ZAP bytes slot — encoding arbitrary dynamic JSON
//     "natively" would just re-introduce the reflection codec this migration
//     kills. Go's encoding/json emits struct fields in declaration order with no
//     maps here, so the bytes are deterministic and parse∘marshal is byte-stable
//     (block id stays stable across a wire round-trip).
//
// Boundaries intentionally kept as JSON (NOT block/vertex wire): Config and
// Genesis (config boundary, vm.go Initialize) and the RPC reply types in
// service.go. None of those are block/vertex wire.

// wireKind is the 1-byte discriminator at object offset 0 of every aivm wire
// buffer. parse reads it and rejects a buffer of the wrong kind.
type wireKind uint8

const (
	kindReserved wireKind = iota
	kindBlock
	kindVertex
)

// ---- Block ----
//
//	kind        u8    @ 0    (= kindBlock)   (ID_ is derived: sha256(Marshal); excluded)
//	ParentID    32B   @ 1
//	Height      u64   @ 33
//	Timestamp   i64   @ 41   (UnixNano)
//	MerkleRoot  32B   @ 49
//	ReceiptRoot 32B   @ 81
//	IntentLens  list  @ 113  (u32 per CIntent wire length)
//	IntentBlob  bytes @ 121  (concatenated CIntent wire objects)
//	TaskLens    list  @ 129  (u32 per Task JSON length)
//	TaskBlob    bytes @ 137
//	ResultLens  list  @ 145  (u32 per TaskResult JSON length)
//	ResultBlob  bytes @ 153
//	PRegLens    list  @ 161  (u32 per ProviderReg JSON length)
//	PRegBlob    bytes @ 169
const (
	blkKind       = 0
	blkParent     = 1
	blkHeight     = 33
	blkTime       = 41
	blkMerkle     = 49
	blkReceipt    = 81
	blkIntentLens = 113
	blkIntentBlob = 121
	blkTaskLens   = 129
	blkTaskBlob   = 137
	blkResLens    = 145
	blkResBlob    = 153
	blkPRegLens   = 161
	blkPRegBlob   = 169
	blkSize       = 177
)

// Marshal encodes the block (excluding the derived ID_/cache fields) to
// canonical wire. blockID = sha256(this).
func (blk *Block) Marshal() ([]byte, error) {
	intentLens, intentBlob := packObjs(blk.ImportedIntents, marshalCIntent)
	taskLens, taskBlob, err := packJSON(blk.Tasks)
	if err != nil {
		return nil, fmt.Errorf("aivm block: tasks: %w", err)
	}
	resLens, resBlob, err := packJSON(blk.Results)
	if err != nil {
		return nil, fmt.Errorf("aivm block: results: %w", err)
	}
	pregLens, pregBlob, err := packJSON(blk.ProviderRegs)
	if err != nil {
		return nil, fmt.Errorf("aivm block: provider registrations: %w", err)
	}

	b := zap.NewBuilder(zap.HeaderSize + blkSize + len(intentBlob) + len(taskBlob) +
		len(resBlob) + len(pregBlob) +
		4*(len(intentLens)+len(taskLens)+len(resLens)+len(pregLens)) + 256)
	intentLensOff := writeU32List(b, intentLens)
	taskLensOff := writeU32List(b, taskLens)
	resLensOff := writeU32List(b, resLens)
	pregLensOff := writeU32List(b, pregLens)

	ob := b.StartObject(blkSize)
	ob.SetUint8(blkKind, uint8(kindBlock))
	ob.SetBytesFixed(blkParent, blk.ParentID_[:])
	ob.SetUint64(blkHeight, blk.Height_)
	ob.SetInt64(blkTime, blk.Timestamp_.UnixNano())
	ob.SetBytesFixed(blkMerkle, blk.MerkleRoot[:])
	ob.SetBytesFixed(blkReceipt, blk.ReceiptRoot[:])
	ob.SetList(blkIntentLens, intentLensOff, len(intentLens))
	ob.SetBytes(blkIntentBlob, intentBlob)
	ob.SetList(blkTaskLens, taskLensOff, len(taskLens))
	ob.SetBytes(blkTaskBlob, taskBlob)
	ob.SetList(blkResLens, resLensOff, len(resLens))
	ob.SetBytes(blkResBlob, resBlob)
	ob.SetList(blkPRegLens, pregLensOff, len(pregLens))
	ob.SetBytes(blkPRegBlob, pregBlob)
	ob.FinishAsRoot()
	return b.Finish(), nil
}

// parseBlock fills the wire fields of blk from canonical block bytes. The caller
// sets the non-wire cache fields (vm, bytes, ID_).
func parseBlock(data []byte, blk *Block) error {
	msg, err := zap.Parse(data)
	if err != nil {
		return err
	}
	if msg.Size() != len(data) {
		return fmt.Errorf("aivm block: trailing bytes")
	}
	o := msg.Root()
	if wireKind(o.Uint8(blkKind)) != kindBlock {
		return fmt.Errorf("aivm block: wrong kind byte")
	}
	copy(blk.ParentID_[:], o.BytesFixedSlice(blkParent, 32))
	blk.Height_ = o.Uint64(blkHeight)
	blk.Timestamp_ = time.Unix(0, o.Int64(blkTime)).UTC()
	copy(blk.MerkleRoot[:], o.BytesFixedSlice(blkMerkle, 32))
	copy(blk.ReceiptRoot[:], o.BytesFixedSlice(blkReceipt, 32))

	if blk.ImportedIntents, err = unpackObjs(readU32List(o, blkIntentLens), o.Bytes(blkIntentBlob), parseCIntent); err != nil {
		return err
	}
	if blk.Tasks, err = unpackJSON[aicore.Task](readU32List(o, blkTaskLens), o.Bytes(blkTaskBlob)); err != nil {
		return err
	}
	if blk.Results, err = unpackJSON[aicore.TaskResult](readU32List(o, blkResLens), o.Bytes(blkResBlob)); err != nil {
		return err
	}
	if blk.ProviderRegs, err = unpackJSON[ProviderReg](readU32List(o, blkPRegLens), o.Bytes(blkPRegBlob)); err != nil {
		return err
	}
	return nil
}

// ---- CIntent (nested in Block.ImportedIntents; native, security-critical) ----
//
//	IntentID      32B @ 0
//	CChainID      32B @ 32
//	AChainID      32B @ 64
//	CTxHash       32B @ 96
//	ModelSpecHash 32B @ 128
//	PromptHash    32B @ 160
//	Caller        20B @ 192
//	CallIndex     u32 @ 212
//	N             u16 @ 216
//	Threshold     u16 @ 218
//	Fee           32B @ 220  (uint256 big-endian; nil == zero, u256be-equivalent)
//	RewardPerOp   32B @ 252  (uint256 big-endian; nil == zero)
const (
	ciIntentID = 0
	ciCChain   = 32
	ciAChain   = 64
	ciCTxHash  = 96
	ciModel    = 128
	ciPrompt   = 160
	ciCaller   = 192
	ciCallIdx  = 212
	ciN        = 216
	ciThresh   = 218
	ciFee      = 220
	ciReward   = 252
	ciSize     = 284
)

func marshalCIntent(in CIntent) []byte {
	b := zap.NewBuilder(zap.HeaderSize + ciSize)
	ob := b.StartObject(ciSize)
	ob.SetBytesFixed(ciIntentID, in.IntentID[:])
	ob.SetBytesFixed(ciCChain, in.CChainID[:])
	ob.SetBytesFixed(ciAChain, in.AChainID[:])
	ob.SetBytesFixed(ciCTxHash, in.CTxHash[:])
	ob.SetBytesFixed(ciModel, in.ModelSpecHash[:])
	ob.SetBytesFixed(ciPrompt, in.PromptHash[:])
	ob.SetBytesFixed(ciCaller, in.Caller[:])
	ob.SetUint32(ciCallIdx, in.CallIndex)
	ob.SetUint16(ciN, in.N)
	ob.SetUint16(ciThresh, in.Threshold)
	setU256(ob, ciFee, in.Fee)
	setU256(ob, ciReward, in.RewardPerOperator)
	ob.FinishAsRoot()
	return b.Finish()
}

func parseCIntent(data []byte) (CIntent, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return CIntent{}, err
	}
	if msg.Size() != len(data) {
		return CIntent{}, fmt.Errorf("aivm c-intent: trailing bytes")
	}
	o := msg.Root()
	var in CIntent
	copy(in.IntentID[:], o.BytesFixedSlice(ciIntentID, 32))
	copy(in.CChainID[:], o.BytesFixedSlice(ciCChain, 32))
	copy(in.AChainID[:], o.BytesFixedSlice(ciAChain, 32))
	copy(in.CTxHash[:], o.BytesFixedSlice(ciCTxHash, 32))
	copy(in.ModelSpecHash[:], o.BytesFixedSlice(ciModel, 32))
	copy(in.PromptHash[:], o.BytesFixedSlice(ciPrompt, 32))
	copy(in.Caller[:], o.BytesFixedSlice(ciCaller, 20))
	in.CallIndex = o.Uint32(ciCallIdx)
	in.N = o.Uint16(ciN)
	in.Threshold = o.Uint16(ciThresh)
	in.Fee = new(uint256.Int).SetBytes(o.BytesFixedSlice(ciFee, 32))
	in.RewardPerOperator = new(uint256.Int).SetBytes(o.BytesFixedSlice(ciReward, 32))
	return in, nil
}

// ---- Vertex ----
//
//	kind       u8    @ 0    (= kindVertex)   (id is derived: computeID; excluded.
//	                                          status is a local decision; excluded.)
//	Height     u64   @ 1
//	Epoch      u32   @ 9
//	Parents    bytes @ 13   (concatenated 32-byte ids)
//	TxIDs      bytes @ 21   (concatenated 32-byte ids)
//	JobLens    list  @ 29   (u32 per jobID string length)
//	JobBlob    bytes @ 37   (concatenated jobID strings)
//	TaskLens   list  @ 45   (u32 per Task JSON length)
//	TaskBlob   bytes @ 53
//	ResultLens list  @ 61   (u32 per TaskResult JSON length)
//	ResultBlob bytes @ 69
const (
	vxKind     = 0
	vxHeight   = 1
	vxEpoch    = 9
	vxParents  = 13
	vxTxIDs    = 21
	vxJobLens  = 29
	vxJobBlob  = 37
	vxTaskLens = 45
	vxTaskBlob = 53
	vxResLens  = 61
	vxResBlob  = 69
	vxSize     = 77
)

// marshalVertex encodes the vertex's structural + payload fields (excluding the
// derived id, the local status, and the runtime vm/bytes fields).
func marshalVertex(v *AIVertex) ([]byte, error) {
	parents := concatIDs(v.parents)
	txIDs := concatIDs(v.txIDs)
	jobLens, jobBlob := packStrings(v.jobIDs)
	taskLens, taskBlob, err := packJSON(v.tasks)
	if err != nil {
		return nil, fmt.Errorf("aivm vertex: tasks: %w", err)
	}
	resLens, resBlob, err := packJSON(v.results)
	if err != nil {
		return nil, fmt.Errorf("aivm vertex: results: %w", err)
	}

	b := zap.NewBuilder(zap.HeaderSize + vxSize + len(parents) + len(txIDs) +
		len(jobBlob) + len(taskBlob) + len(resBlob) +
		4*(len(jobLens)+len(taskLens)+len(resLens)) + 256)
	jobLensOff := writeU32List(b, jobLens)
	taskLensOff := writeU32List(b, taskLens)
	resLensOff := writeU32List(b, resLens)

	ob := b.StartObject(vxSize)
	ob.SetUint8(vxKind, uint8(kindVertex))
	ob.SetUint64(vxHeight, v.height)
	ob.SetUint32(vxEpoch, v.epoch)
	ob.SetBytes(vxParents, parents)
	ob.SetBytes(vxTxIDs, txIDs)
	ob.SetList(vxJobLens, jobLensOff, len(jobLens))
	ob.SetBytes(vxJobBlob, jobBlob)
	ob.SetList(vxTaskLens, taskLensOff, len(taskLens))
	ob.SetBytes(vxTaskBlob, taskBlob)
	ob.SetList(vxResLens, resLensOff, len(resLens))
	ob.SetBytes(vxResBlob, resBlob)
	ob.FinishAsRoot()
	return b.Finish(), nil
}

// parseVertex fills the wire fields of v. The caller sets the derived id and the
// runtime vm/bytes fields; status stays at its zero value (a local decision).
func parseVertex(data []byte, v *AIVertex) error {
	msg, err := zap.Parse(data)
	if err != nil {
		return err
	}
	if msg.Size() != len(data) {
		return fmt.Errorf("aivm vertex: trailing bytes")
	}
	o := msg.Root()
	if wireKind(o.Uint8(vxKind)) != kindVertex {
		return fmt.Errorf("aivm vertex: wrong kind byte")
	}
	v.height = o.Uint64(vxHeight)
	v.epoch = o.Uint32(vxEpoch)
	if v.parents, err = splitIDs(o.Bytes(vxParents), "parent list"); err != nil {
		return err
	}
	if v.txIDs, err = splitIDs(o.Bytes(vxTxIDs), "tx list"); err != nil {
		return err
	}
	if v.jobIDs, err = unpackStrings(readU32List(o, vxJobLens), o.Bytes(vxJobBlob)); err != nil {
		return err
	}
	if v.tasks, err = unpackJSON[*aicore.Task](readU32List(o, vxTaskLens), o.Bytes(vxTaskBlob)); err != nil {
		return err
	}
	if v.results, err = unpackJSON[*aicore.TaskResult](readU32List(o, vxResLens), o.Bytes(vxResBlob)); err != nil {
		return err
	}
	return nil
}

// ---- shared helpers ----

// setU256 writes x as 32-byte big-endian. A nil pointer writes zero bytes, which
// is byte-identical to u256be(nil) used in ComputeIntentID — so a nil Fee still
// re-derives the same intent_id (the nil-amount guard rejects it earlier anyway).
func setU256(ob zap.ObjectBuilder, off int, x *uint256.Int) {
	var b [32]byte
	if x != nil {
		b = x.Bytes32()
	}
	ob.SetBytesFixed(off, b[:])
}

func writeU32List(b *zap.Builder, xs []uint32) int {
	lb := b.StartList(4)
	for _, x := range xs {
		lb.AddUint32(x)
	}
	off, _ := lb.Finish()
	return off
}

func readU32List(o zap.Object, ptrOff int) []uint32 {
	l := o.ListStride(ptrOff, 4)
	n := l.Len()
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = l.Uint32(i)
	}
	return out
}

// packObjs marshals each item and returns (per-item lengths, concat blob).
func packObjs[T any](items []T, marshal func(T) []byte) (lens []uint32, blob []byte) {
	if len(items) == 0 {
		return nil, nil
	}
	lens = make([]uint32, len(items))
	for i, it := range items {
		m := marshal(it)
		lens[i] = uint32(len(m))
		blob = append(blob, m...)
	}
	return lens, blob
}

// span walks the declared lengths over a packed blob, handing each element's
// slice to visit, and requires the lengths to account for the blob EXACTLY.
//
// The exactness is the point. A decoder that stops when the lengths run out
// ignores whatever follows, so two different buffers decode to the same value —
// and since a block is named by its own canonical re-encoding, the padded one is
// stored and served under the canonical one's id. Four stray bytes appended to an
// intent blob were read as a well-formed block.
func span(lens []uint32, blob []byte, what string, visit func(i int, elem []byte) error) error {
	pos := 0
	for i, l := range lens {
		if pos+int(l) > len(blob) {
			return fmt.Errorf("aivm: %s %d runs %d bytes past the blob", what, i, pos+int(l)-len(blob))
		}
		if err := visit(i, blob[pos:pos+int(l)]); err != nil {
			return err
		}
		pos += int(l)
	}
	if pos != len(blob) {
		return fmt.Errorf("aivm: %d bytes past the last %s", len(blob)-pos, what)
	}
	return nil
}

// unpackObjs re-splits a packed blob by lengths and parses each sub-object.
func unpackObjs[T any](lens []uint32, blob []byte, parse func([]byte) (T, error)) ([]T, error) {
	out := make([]T, 0, len(lens))
	err := span(lens, blob, "packed object", func(_ int, elem []byte) error {
		v, err := parse(elem)
		if err != nil {
			return err
		}
		out = append(out, v)
		return nil
	})
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return out, nil
}

// packJSON marshals each item to canonical JSON and returns (lengths, concat
// blob). Used only for irreducibly-dynamic payloads (see file header).
//
// A marshal failure is REPORTED. Dropping it wrote a zero-length element, so an
// item the encoder could not represent silently became no item at all — and the
// block's id, computed over that encoding, was the id of a block missing work
// its author believed it carried.
func packJSON[T any](items []T) (lens []uint32, blob []byte, err error) {
	if len(items) == 0 {
		return nil, nil, nil
	}
	lens = make([]uint32, len(items))
	for i, it := range items {
		m, err := json.Marshal(it)
		if err != nil {
			return nil, nil, fmt.Errorf("element %d: %w", i, err)
		}
		lens[i] = uint32(len(m))
		blob = append(blob, m...)
	}
	return lens, blob, nil
}

func unpackJSON[T any](lens []uint32, blob []byte) ([]T, error) {
	out := make([]T, 0, len(lens))
	err := span(lens, blob, "json element", func(_ int, elem []byte) error {
		var v T
		if err := json.Unmarshal(elem, &v); err != nil {
			return err
		}
		out = append(out, v)
		return nil
	})
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return out, nil
}

func packStrings(ss []string) ([]uint32, []byte) {
	if len(ss) == 0 {
		return nil, nil
	}
	lens := make([]uint32, len(ss))
	var blob []byte
	for i, s := range ss {
		lens[i] = uint32(len(s))
		blob = append(blob, s...)
	}
	return lens, blob
}

func unpackStrings(lens []uint32, blob []byte) ([]string, error) {
	out := make([]string, 0, len(lens))
	err := span(lens, blob, "string", func(_ int, elem []byte) error {
		out = append(out, string(elem))
		return nil
	})
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return out, nil
}

func concatIDs(list []ids.ID) []byte {
	if len(list) == 0 {
		return nil
	}
	out := make([]byte, 0, 32*len(list))
	for _, id := range list {
		out = append(out, id[:]...)
	}
	return out
}

// splitIDs re-splits a concatenation of 32-byte ids, and refuses a length that
// is not a whole number of them. Rounding down discarded a short tail, so a
// buffer with bytes the decoder never read still decoded.
func splitIDs(blob []byte, what string) ([]ids.ID, error) {
	if len(blob)%32 != 0 {
		return nil, fmt.Errorf("aivm: %s is %d bytes, not a multiple of 32", what, len(blob))
	}
	n := len(blob) / 32
	if n == 0 {
		return nil, nil
	}
	out := make([]ids.ID, n)
	for i := 0; i < n; i++ {
		copy(out[i][:], blob[i*32:(i+1)*32])
	}
	return out, nil
}
