// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"fmt"
	"time"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for M-Chain (MPC custody VM). No pcodecs, no
// reflection, no codec registry — each persisted type owns its Marshal/parse
// over a zap object. Re-genesis authorized, so the on-disk/wire format is
// these offsets (canonical: parse rejects trailing bytes).
//
// The legacy pcodecs LinearCodec keyed on struct tags;
// every type here carries only `json:` tags, so the old codec marshaled ZERO
// fields (a Block round-tripped to all-zero — a latent corruption bug). This
// wire is the correct, field-preserving replacement.
//
// Boundaries kept as JSON (NOT encoded here): ThresholdConfig (init.Config)
// and Genesis (genesis bytes) — see vm.go. Sessions travel as JSON envelopes
// over transport (see transport.go), not through this wire.

// ---- Operation (nested in Block) ----
//
//	Type        bytes @ 0
//	SessionID   bytes @ 8
//	KeyID       bytes @ 16
//	Protocol    bytes @ 24
//	ReqChain    bytes @ 32
//	MessageHash bytes @ 40
//	Signature   bytes @ 48
//	Error       bytes @ 56
//	Timestamp   i64   @ 64
//	Success     u8    @ 72
const (
	opType    = 0
	opSession = 8
	opKeyID   = 16
	opProto   = 24
	opReqChn  = 32
	opMsgHash = 40
	opSig     = 48
	opErr     = 56
	opTS      = 64
	opSuccess = 72
	opSize    = 73
)

func marshalOperation(op *Operation) []byte {
	b := zap.NewBuilder(zap.HeaderSize + opSize + len(op.Type) + len(op.SessionID) +
		len(op.KeyID) + len(op.Protocol) + len(op.RequestingChain) + len(op.MessageHash) +
		len(op.Signature) + len(op.Error) + 64)
	ob := b.StartObject(opSize)
	ob.SetBytes(opType, []byte(op.Type))
	ob.SetBytes(opSession, []byte(op.SessionID))
	ob.SetBytes(opKeyID, []byte(op.KeyID))
	ob.SetBytes(opProto, []byte(op.Protocol))
	ob.SetBytes(opReqChn, []byte(op.RequestingChain))
	ob.SetBytes(opMsgHash, op.MessageHash)
	ob.SetBytes(opSig, op.Signature)
	ob.SetBytes(opErr, []byte(op.Error))
	ob.SetInt64(opTS, op.Timestamp)
	ob.SetUint8(opSuccess, boolByte(op.Success))
	ob.FinishAsRoot()
	return b.Finish()
}

func readOperation(o zap.Object) *Operation {
	return &Operation{
		Type:            string(o.Bytes(opType)),
		SessionID:       string(o.Bytes(opSession)),
		KeyID:           string(o.Bytes(opKeyID)),
		Protocol:        string(o.Bytes(opProto)),
		RequestingChain: string(o.Bytes(opReqChn)),
		MessageHash:     appendBytes(o.Bytes(opMsgHash)),
		Signature:       appendBytes(o.Bytes(opSig)),
		Error:           string(o.Bytes(opErr)),
		Timestamp:       o.Int64(opTS),
		Success:         o.Uint8(opSuccess) != 0,
	}
}

// ---- Block ----
//
//	ParentID  32B   @ 0    (ID_ is derived: computeID = sha256(Marshal); excluded)
//	Height    u64   @ 32
//	Timestamp i64   @ 40
//	OpLens    list  @ 48   (u32 per Operation wire length)
//	OpBlob    bytes @ 56   (concatenated Operation wire objects)
const (
	blkParent = 0
	blkHeight = 32
	blkTime   = 40
	blkOpLens = 48
	blkOpBlob = 56
	blkSize   = 64
)

// Marshal encodes the block (excluding the derived ID_) to canonical wire.
func (b *Block) Marshal() ([]byte, error) {
	var opBlob []byte
	opLens := make([]uint32, 0, len(b.Operations))
	for _, op := range b.Operations {
		ob := marshalOperation(op)
		opLens = append(opLens, uint32(len(ob)))
		opBlob = append(opBlob, ob...)
	}
	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(opBlob) + 4*len(opLens) + 128)
	opLensOff := writeU32List(bld, opLens)

	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, b.ParentID_[:])
	ob.SetUint64(blkHeight, b.BlockHeight)
	ob.SetInt64(blkTime, b.BlockTimestamp)
	ob.SetList(blkOpLens, opLensOff, len(opLens))
	ob.SetBytes(blkOpBlob, opBlob)
	ob.FinishAsRoot()
	return bld.Finish(), nil
}

func parseBlockBytes(data []byte, blk *Block) error {
	msg, err := zap.Parse(data)
	if err != nil {
		return err
	}
	if msg.Size() != len(data) {
		return fmt.Errorf("mpcvm block: trailing bytes")
	}
	o := msg.Root()
	copy(blk.ParentID_[:], o.BytesFixedSlice(blkParent, 32))
	blk.BlockHeight = o.Uint64(blkHeight)
	blk.BlockTimestamp = o.Int64(blkTime)

	opLens := readU32List(o, blkOpLens)
	if len(opLens) == 0 {
		blk.Operations = nil
		return nil
	}
	opBlob := o.Bytes(blkOpBlob)
	blk.Operations = make([]*Operation, 0, len(opLens))
	pos := 0
	for _, l := range opLens {
		if pos+int(l) > len(opBlob) {
			return fmt.Errorf("mpcvm block: operation blob out of bounds")
		}
		omsg, err := zap.Parse(opBlob[pos : pos+int(l)])
		if err != nil {
			return err
		}
		blk.Operations = append(blk.Operations, readOperation(omsg.Root()))
		pos += int(l)
	}
	return nil
}

// ---- ManagedKey ----
//
//	KeyID     bytes @ 0
//	KeyType   bytes @ 8
//	PublicKey bytes @ 16
//	Address   bytes @ 24
//	Status    bytes @ 32
//	Threshold i64   @ 40
//	Total     i64   @ 48
//	Generation u64  @ 56
//	CreatedAt i64   @ 64   (UnixNano)
//	LastUsedAt i64  @ 72   (UnixNano)
//	SignCount u64   @ 80
//	PartyLens list  @ 88   (u32 per partyID string length)
//	PartyBlob bytes @ 96   (concatenated partyID strings)
//
// Config/CMPConfig (json:"-") are reconstructed off-wire and excluded.
const (
	mkKeyID     = 0
	mkKeyType   = 8
	mkPubKey    = 16
	mkAddr      = 24
	mkStatus    = 32
	mkThreshold = 40
	mkTotal     = 48
	mkGen       = 56
	mkCreated   = 64
	mkLastUsed  = 72
	mkSignCnt   = 80
	mkPartyLens = 88
	mkPartyBlob = 96
	mkSize      = 104
)

func (k *ManagedKey) Marshal() ([]byte, error) {
	partyLens, partyBlob := packStrings(partyIDsToStrings(k.PartyIDs))
	bld := zap.NewBuilder(zap.HeaderSize + mkSize + len(k.KeyID) + len(k.KeyType) +
		len(k.PublicKey) + len(k.Address) + len(k.Status) + len(partyBlob) + 4*len(partyLens) + 128)
	partyLensOff := writeU32List(bld, partyLens)

	ob := bld.StartObject(mkSize)
	ob.SetBytes(mkKeyID, []byte(k.KeyID))
	ob.SetBytes(mkKeyType, []byte(k.KeyType))
	ob.SetBytes(mkPubKey, k.PublicKey)
	ob.SetBytes(mkAddr, k.Address)
	ob.SetBytes(mkStatus, []byte(k.Status))
	ob.SetInt64(mkThreshold, int64(k.Threshold))
	ob.SetInt64(mkTotal, int64(k.TotalParties))
	ob.SetUint64(mkGen, k.Generation)
	ob.SetInt64(mkCreated, k.CreatedAt.UnixNano())
	ob.SetInt64(mkLastUsed, k.LastUsedAt.UnixNano())
	ob.SetUint64(mkSignCnt, k.SignCount)
	ob.SetList(mkPartyLens, partyLensOff, len(partyLens))
	ob.SetBytes(mkPartyBlob, partyBlob)
	ob.FinishAsRoot()
	return bld.Finish(), nil
}

func parseManagedKey(data []byte, k *ManagedKey) error {
	msg, err := zap.Parse(data)
	if err != nil {
		return err
	}
	if msg.Size() != len(data) {
		return fmt.Errorf("mpcvm managed key: trailing bytes")
	}
	o := msg.Root()
	k.KeyID = string(o.Bytes(mkKeyID))
	k.KeyType = string(o.Bytes(mkKeyType))
	k.PublicKey = appendBytes(o.Bytes(mkPubKey))
	k.Address = appendBytes(o.Bytes(mkAddr))
	k.Status = string(o.Bytes(mkStatus))
	k.Threshold = int(o.Int64(mkThreshold))
	k.TotalParties = int(o.Int64(mkTotal))
	k.Generation = o.Uint64(mkGen)
	k.CreatedAt = time.Unix(0, o.Int64(mkCreated)).UTC()
	k.LastUsedAt = time.Unix(0, o.Int64(mkLastUsed)).UTC()
	k.SignCount = o.Uint64(mkSignCnt)
	k.PartyIDs = stringsToPartyIDs(unpackStrings(readU32List(o, mkPartyLens), o.Bytes(mkPartyBlob)))
	return nil
}

// ---- CrossChainMPCRequest ----
//
//	Type        bytes @ 0
//	ReqChain    bytes @ 8
//	KeyID       bytes @ 16
//	KeyType     bytes @ 24
//	MessageHash bytes @ 32
//	MessageType bytes @ 40
const (
	ccType    = 0
	ccReqChn  = 8
	ccKeyID   = 16
	ccKeyType = 24
	ccMsgHash = 32
	ccMsgType = 40
	ccSize    = 48
)

func (r *CrossChainMPCRequest) Marshal() ([]byte, error) {
	b := zap.NewBuilder(zap.HeaderSize + ccSize + len(r.Type) + len(r.RequestingChain) +
		len(r.KeyID) + len(r.KeyType) + len(r.MessageHash) + len(r.MessageType) + 64)
	ob := b.StartObject(ccSize)
	ob.SetBytes(ccType, []byte(r.Type))
	ob.SetBytes(ccReqChn, []byte(r.RequestingChain))
	ob.SetBytes(ccKeyID, []byte(r.KeyID))
	ob.SetBytes(ccKeyType, []byte(r.KeyType))
	ob.SetBytes(ccMsgHash, r.MessageHash)
	ob.SetBytes(ccMsgType, []byte(r.MessageType))
	ob.FinishAsRoot()
	return b.Finish(), nil
}

func parseCrossChainMPCRequest(data []byte, r *CrossChainMPCRequest) error {
	msg, err := zap.Parse(data)
	if err != nil {
		return err
	}
	if msg.Size() != len(data) {
		return fmt.Errorf("mpcvm cross-chain request: trailing bytes")
	}
	o := msg.Root()
	r.Type = string(o.Bytes(ccType))
	r.RequestingChain = string(o.Bytes(ccReqChn))
	r.KeyID = string(o.Bytes(ccKeyID))
	r.KeyType = string(o.Bytes(ccKeyType))
	r.MessageHash = appendBytes(o.Bytes(ccMsgHash))
	r.MessageType = string(o.Bytes(ccMsgType))
	return nil
}

// ---- shared helpers ----

func boolByte(b bool) uint8 {
	if b {
		return 1
	}
	return 0
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

// packStrings returns per-string byte lengths and the concatenated blob.
func packStrings(ss []string) ([]uint32, []byte) {
	lens := make([]uint32, len(ss))
	var blob []byte
	for i, s := range ss {
		lens[i] = uint32(len(s))
		blob = append(blob, s...)
	}
	return lens, blob
}

// unpackStrings re-splits blob by lens. Returns nil (not empty) for no entries.
func unpackStrings(lens []uint32, blob []byte) []string {
	if len(lens) == 0 {
		return nil
	}
	out := make([]string, 0, len(lens))
	pos := 0
	for _, l := range lens {
		if pos+int(l) > len(blob) {
			break
		}
		out = append(out, string(blob[pos:pos+int(l)]))
		pos += int(l)
	}
	return out
}

func partyIDsToStrings(ids []party.ID) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

func stringsToPartyIDs(ss []string) []party.ID {
	if len(ss) == 0 {
		return nil
	}
	out := make([]party.ID, len(ss))
	for i, s := range ss {
		out[i] = party.ID(s)
	}
	return out
}

func appendBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}
