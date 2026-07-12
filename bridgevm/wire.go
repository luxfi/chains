// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"fmt"
	"sort"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for B-Chain. No pcodecs, no reflection, no codec
// registry — each type owns its Marshal/Parse over a zap object. Re-genesis
// authorized, so the on-disk/wire format is these offsets (canonical: Parse
// rejects trailing bytes).

// Note: Genesis is JSON at the genesis/config boundary (see vm.go), not a
// binary wire type — it is intentionally not encoded here.

// ---- BridgeRequest ----
//
// Fixed object (variable fields are bytes/list ptrs):
//
//	ID           32B  @ 0
//	Asset        32B  @ 32
//	SourceTxID   32B  @ 64
//	SrcChainID   u32  @ 96
//	DstChainID   u32  @ 100
//	Confirmations u32 @ 104
//	Nonce        u64  @ 108
//	Amount       u64  @ 116
//	CreatedAt    i64  @ 124  (unix nanos)
//	SourceChain  bytes@ 132
//	DestChain    bytes@ 140
//	Status       bytes@ 148
//	Recipient    bytes@ 156
//	MPCSigLens   list @ 164  (u32 per sig)
//	MPCSigBlob   bytes@ 172
const (
	brID       = 0
	brAsset    = 32
	brSourceTx = 64
	brSrcChain = 96
	brDstChain = 100
	brConfirm  = 104
	brNonce    = 108
	brAmount   = 116
	brCreated  = 124
	brSrcName  = 132
	brDstName  = 140
	brStatus   = 148
	brRecip    = 156
	brSigLens  = 164
	brSigBlob  = 172
	brSize     = 180
)

// marshalBridgeRequest encodes r into a standalone wire object.
func marshalBridgeRequest(r *BridgeRequest) []byte {
	b := zap.NewBuilder(zap.HeaderSize + brSize + len(r.SourceChain) + len(r.DestChain) +
		len(r.Status) + len(r.Recipient) + sigBlobLen(r.MPCSignatures) + 4*len(r.MPCSignatures) + 128)
	sigLensOff := writeU32List(b, sigLens(r.MPCSignatures))

	ob := b.StartObject(brSize)
	ob.SetBytesFixed(brID, r.ID[:])
	ob.SetBytesFixed(brAsset, r.Asset[:])
	ob.SetBytesFixed(brSourceTx, r.SourceTxID[:])
	ob.SetUint32(brSrcChain, r.SrcChainID)
	ob.SetUint32(brDstChain, r.DstChainID)
	ob.SetUint32(brConfirm, r.Confirmations)
	ob.SetUint64(brNonce, r.Nonce)
	ob.SetUint64(brAmount, r.Amount)
	ob.SetInt64(brCreated, r.CreatedAt.UnixNano())
	ob.SetBytes(brSrcName, []byte(r.SourceChain))
	ob.SetBytes(brDstName, []byte(r.DestChain))
	ob.SetBytes(brStatus, []byte(r.Status))
	ob.SetBytes(brRecip, r.Recipient)
	ob.SetList(brSigLens, sigLensOff, len(r.MPCSignatures))
	ob.SetBytes(brSigBlob, flattenSigs(r.MPCSignatures))
	ob.FinishAsRoot()
	return b.Finish()
}

func readBridgeRequest(o zap.Object) *BridgeRequest {
	r := &BridgeRequest{
		SrcChainID:    o.Uint32(brSrcChain),
		DstChainID:    o.Uint32(brDstChain),
		Confirmations: o.Uint32(brConfirm),
		Nonce:         o.Uint64(brNonce),
		Amount:        o.Uint64(brAmount),
		CreatedAt:     time.Unix(0, o.Int64(brCreated)).UTC(),
		SourceChain:   string(o.Bytes(brSrcName)),
		DestChain:     string(o.Bytes(brDstName)),
		Status:        string(o.Bytes(brStatus)),
		Recipient:     appendBytes(o.Bytes(brRecip)),
		MPCSignatures: readSigs(o, brSigLens, brSigBlob),
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
//	SigNodeIDs    bytes@ 64   (concatenated 20-byte NodeIDs, sorted)
//	SigLens       list @ 72   (u32 per MPC sig)
//	SigBlob       bytes@ 80
const (
	blkParent   = 0
	blkHeight   = 32
	blkTime     = 40
	blkReqLens  = 48
	blkReqBlob  = 56
	blkSigNodes = 64
	blkSigLens  = 72
	blkSigBlob  = 80
	blkSize     = 88
)

func (b *Block) Marshal() ([]byte, error) {
	// per-request wire objects
	var reqBlob []byte
	reqLens := make([]uint32, 0, len(b.BridgeRequests))
	for _, r := range b.BridgeRequests {
		rb := marshalBridgeRequest(r)
		reqLens = append(reqLens, uint32(len(rb)))
		reqBlob = append(reqBlob, rb...)
	}
	// sorted map -> (nodeIDs blob, sigs)
	nodeIDs := make([]ids.NodeID, 0, len(b.MPCSignatures))
	for id := range b.MPCSignatures {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Slice(nodeIDs, func(i, j int) bool { return nodeIDs[i].Compare(nodeIDs[j]) < 0 })
	var nodeBlob []byte
	sigs := make([][]byte, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		nodeBlob = append(nodeBlob, id[:]...)
		sigs = append(sigs, b.MPCSignatures[id])
	}

	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(reqBlob) + len(nodeBlob) +
		sigBlobLen(sigs) + 4*(len(reqLens)+len(sigs)) + 256)
	reqLensOff := writeU32List(bld, reqLens)
	sigLensOff := writeU32List(bld, sigLens(sigs))

	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, b.ParentID_[:])
	ob.SetUint64(blkHeight, b.BlockHeight)
	ob.SetInt64(blkTime, b.BlockTimestamp)
	ob.SetList(blkReqLens, reqLensOff, len(reqLens))
	ob.SetBytes(blkReqBlob, reqBlob)
	ob.SetBytes(blkSigNodes, nodeBlob)
	ob.SetList(blkSigLens, sigLensOff, len(sigs))
	ob.SetBytes(blkSigBlob, flattenSigs(sigs))
	ob.FinishAsRoot()
	return bld.Finish(), nil
}

func parseBlockBytes(data []byte, blk *Block) error {
	msg, err := zap.Parse(data)
	if err != nil {
		return err
	}
	if msg.Size() != len(data) {
		return fmt.Errorf("bridgevm block: trailing bytes")
	}
	o := msg.Root()
	copy(blk.ParentID_[:], o.BytesFixedSlice(blkParent, 32))
	blk.BlockHeight = o.Uint64(blkHeight)
	blk.BlockTimestamp = o.Int64(blkTime)

	// requests
	reqLens := readU32List(o, blkReqLens)
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

	// mpc signatures map
	nodeBlob := o.Bytes(blkSigNodes)
	sigLens := readU32List(o, blkSigLens)
	sigBlob := o.Bytes(blkSigBlob)
	blk.MPCSignatures = make(map[ids.NodeID][]byte, len(sigLens))
	sp := 0
	for i, l := range sigLens {
		var id ids.NodeID
		if (i+1)*20 > len(nodeBlob) {
			return fmt.Errorf("bridgevm block: nodeID blob out of bounds")
		}
		copy(id[:], nodeBlob[i*20:(i+1)*20])
		if sp+int(l) > len(sigBlob) {
			return fmt.Errorf("bridgevm block: sig blob out of bounds")
		}
		blk.MPCSignatures[id] = appendBytes(sigBlob[sp : sp+int(l)])
		sp += int(l)
	}
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

func sigLens(sigs [][]byte) []uint32 {
	out := make([]uint32, len(sigs))
	for i, s := range sigs {
		out[i] = uint32(len(s))
	}
	return out
}

func flattenSigs(sigs [][]byte) []byte {
	var out []byte
	for _, s := range sigs {
		out = append(out, s...)
	}
	return out
}

func sigBlobLen(sigs [][]byte) int {
	n := 0
	for _, s := range sigs {
		n += len(s)
	}
	return n
}

func readSigs(o zap.Object, lensOff, blobOff int) [][]byte {
	lens := readU32List(o, lensOff)
	blob := o.Bytes(blobOff)
	out := make([][]byte, 0, len(lens))
	pos := 0
	for _, l := range lens {
		if pos+int(l) > len(blob) {
			break
		}
		out = append(out, appendBytes(blob[pos:pos+int(l)]))
		pos += int(l)
	}
	return out
}

func appendBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}
