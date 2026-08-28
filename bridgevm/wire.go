// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"bytes"
	"fmt"

	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for B-Chain. No pcodecs, no reflection, no codec
// registry — each type owns its Marshal/Parse over a zap object. Re-genesis
// authorized, so the on-disk/wire format is these offsets.
//
// The encoding is CANONICAL: Parse accepts only bytes Marshal would produce.
// It checks that by encoding what it read and comparing, which covers every
// way a wire object can carry slack at once — trailing bytes, padding inside
// a declared length, a longer list than its contents, signer ids out of
// order. Slack is not cosmetic here: the block id is a hash of the block's
// contents, so a block that tolerates padding has an unbounded number of
// distinct encodings under one id, and two nodes holding "the same" block
// hold different bytes.
//
// Note: Genesis is JSON at the genesis/config boundary (see vm.go), not a
// binary wire type — it is intentionally not encoded here.

// maxBlockBytes bounds what a peer can make this node parse and hash. A block
// is a parent id, a height, a timestamp and at most maxRequestsPerBlock
// transfers of brSize bytes plus a 20-byte recipient — a few tens of
// kilobytes. Anything past this is not a block of this chain, and deciding
// that before decoding is the difference between refusing a message and
// allocating whatever the sender asked for.
const maxBlockBytes = 1 << 17 // 128 KiB

// ---- BridgeRequest ----
//
// Fixed object (Recipient is the one variable field):
//
//	ID           32B  @ 0    (== BridgeTransfer.Digest of the fields below)
//	Asset        32B  @ 32
//	SourceTxID   32B  @ 64
//	SrcChainID   u32  @ 96
//	DstChainID   u32  @ 100
//	Nonce        u64  @ 104
//	Amount       u64  @ 112
//	Recipient    bytes@ 120
//
// Everything but SourceTxID is covered by ID. What is NOT here is as
// deliberate: a confirmation depth and an observation time are each node's own
// reading of a source chain, so carrying them made two nodes encode the same
// block differently and made a follower check the proposer's claim instead of
// its own. A chain label is a local name for a number that is already here.
const (
	brID       = 0
	brAsset    = 32
	brSourceTx = 64
	brSrcChain = 96
	brDstChain = 100
	brNonce    = 104
	brAmount   = 112
	brRecip    = 120
	brSize     = 128
)

// marshalBridgeRequest encodes r into a standalone wire object.
func marshalBridgeRequest(r *BridgeRequest) []byte {
	b := zap.NewBuilder(zap.HeaderSize + brSize + len(r.Recipient) + 64)
	ob := b.StartObject(brSize)
	ob.SetBytesFixed(brID, r.ID[:])
	ob.SetBytesFixed(brAsset, r.Asset[:])
	ob.SetBytesFixed(brSourceTx, r.SourceTxID[:])
	ob.SetUint32(brSrcChain, r.SrcChainID)
	ob.SetUint32(brDstChain, r.DstChainID)
	ob.SetUint64(brNonce, r.Nonce)
	ob.SetUint64(brAmount, r.Amount)
	ob.SetBytes(brRecip, r.Recipient)
	ob.FinishAsRoot()
	return b.Finish()
}

func readBridgeRequest(o zap.Object) *BridgeRequest {
	r := &BridgeRequest{
		SrcChainID: o.Uint32(brSrcChain),
		DstChainID: o.Uint32(brDstChain),
		Nonce:      o.Uint64(brNonce),
		Amount:     o.Uint64(brAmount),
		Recipient:  appendBytes(o.Bytes(brRecip)),
	}
	copy(r.ID[:], o.BytesFixedSlice(brID, 32))
	copy(r.Asset[:], o.BytesFixedSlice(brAsset, 32))
	copy(r.SourceTxID[:], o.BytesFixedSlice(brSourceTx, 32))
	return r
}

// ---- Block ----
//
//	ParentID      32B  @ 0
//	BlockHeight   u64  @ 32
//	BlockTimestamp i64 @ 40
//	ReqLens       list @ 48   (u32 per BridgeRequest wire length)
//	ReqBlob       bytes@ 56   (concatenated BridgeRequest wire objects)
const (
	blkParent  = 0
	blkHeight  = 32
	blkTime    = 40
	blkReqLens = 48
	blkReqBlob = 56
	blkSize    = 64
)

// Marshal encodes b. It cannot fail: every field is fixed-width or a length
// the builder is told in advance, so there is nothing here to refuse.
func (b *Block) Marshal() []byte {
	var reqBlob []byte
	reqLens := make([]uint32, 0, len(b.BridgeRequests))
	for _, r := range b.BridgeRequests {
		rb := marshalBridgeRequest(r)
		reqLens = append(reqLens, uint32(len(rb)))
		reqBlob = append(reqBlob, rb...)
	}

	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(reqBlob) + 4*len(reqLens) + 128)
	reqLensOff := writeU32List(bld, reqLens)

	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, b.ParentID_[:])
	ob.SetUint64(blkHeight, b.BlockHeight)
	ob.SetInt64(blkTime, b.BlockTimestamp)
	ob.SetList(blkReqLens, reqLensOff, len(reqLens))
	ob.SetBytes(blkReqBlob, reqBlob)
	ob.FinishAsRoot()
	return bld.Finish()
}

func parseBlockBytes(data []byte, blk *Block) error {
	if len(data) > maxBlockBytes {
		return fmt.Errorf("bridgevm block: %d bytes over the %d cap", len(data), maxBlockBytes)
	}
	msg, err := zap.Parse(data)
	if err != nil {
		return err
	}
	o := msg.Root()
	copy(blk.ParentID_[:], o.BytesFixedSlice(blkParent, 32))
	blk.BlockHeight = o.Uint64(blkHeight)
	blk.BlockTimestamp = o.Int64(blkTime)

	reqLens := readU32List(o, blkReqLens)
	if len(reqLens) > maxRequestsPerBlock {
		return fmt.Errorf("bridgevm block: %d transfers over the %d cap", len(reqLens), maxRequestsPerBlock)
	}
	reqBlob := o.Bytes(blkReqBlob)
	blk.BridgeRequests = make([]*BridgeRequest, 0, len(reqLens))
	pos := 0
	for _, l := range reqLens {
		if pos+int(l) > len(reqBlob) {
			return fmt.Errorf("bridgevm block: request blob out of bounds")
		}
		rmsg, err := zap.Parse(reqBlob[pos : pos+int(l)])
		if err != nil {
			return err
		}
		blk.BridgeRequests = append(blk.BridgeRequests, readBridgeRequest(rmsg.Root()))
		pos += int(l)
	}

	// Canonical form: the bytes must be what encoding what we read produces.
	// Anything else is a second encoding of one block.
	if !bytes.Equal(blk.Marshal(), data) {
		return fmt.Errorf("bridgevm block: encoding is not canonical")
	}
	blk.bytes = data
	return nil
}

// ---- shared helpers ----

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

func appendBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}
