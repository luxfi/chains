// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for Q-Chain (quantumvm). No hand-rolled big-endian —
// the Block and BaseTransaction own their serialization over zap objects at
// FIXED field offsets. Re-genesis authorized, so the on-wire format is exactly
// these offsets (canonical: parse rejects trailing bytes).
//
// The Block wire is the quantum-signature preimage: BuildBlock/Verify sign and
// re-check quantumSigner over Block.Bytes(), so the encoding must be
// deterministic (it is: fixed offsets, ordered tx list). It carries the
// structural fields and the committed transaction bytes, so the block signature
// commits to every transaction. The block id is NOT stored in the wire: it is
// the content hash sha256(Bytes()) (see computeID), matching keyvm/dexvm/aivm —
// one and only one id derivation across every VM in this repo, and the clean
// invariant id == sha256(Bytes()) holds.
//
// parseBlock restores the structural fields (timestamp/height/parentID), derives
// the id from the bytes, and leaves transactions unpopulated: the concrete
// Transaction is an interface with no on-chain deserializer, so the tx blob rides
// the wire for signature coverage only — this preserves the prior parseBlock
// contract for the tx set.

// ---- Block ----
//
//	Timestamp i64   @ 0    (Unix seconds — Q-Chain block-time resolution)
//	Height    u64   @ 8
//	ParentID  32B   @ 16
//	TxLens    list  @ 48   (u32 per Transaction wire length)
//	TxBlob    bytes @ 56   (concatenated Transaction wire bytes)
const (
	blkTime   = 0
	blkHeight = 8
	blkParent = 16
	blkTxLens = 48
	blkTxBlob = 56
	blkSize   = 64
)

// Bytes returns the block's canonical ZAP wire (cached).
func (b *Block) Bytes() []byte {
	if b.bytes != nil {
		return b.bytes
	}

	txLens := make([]uint32, len(b.transactions))
	var txBlob []byte
	for i, tx := range b.transactions {
		txb := tx.Bytes()
		txLens[i] = uint32(len(txb))
		txBlob = append(txBlob, txb...)
	}

	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(txBlob) + 4*len(txLens) + 128)
	txLensOff := writeU32List(bld, txLens)

	ob := bld.StartObject(blkSize)
	ob.SetInt64(blkTime, b.timestamp.Unix())
	ob.SetUint64(blkHeight, b.height)
	ob.SetBytesFixed(blkParent, b.parentID[:])
	ob.SetList(blkTxLens, txLensOff, len(txLens))
	ob.SetBytes(blkTxBlob, txBlob)
	ob.FinishAsRoot()

	b.bytes = bld.Finish()
	return b.bytes
}

// computeID is the block's content id: sha256 over the canonical ZAP wire. The
// id is not stored in the wire, so this invariant holds unconditionally —
// id == sha256(Bytes()) — identically to every other VM in this repo.
func (b *Block) computeID() ids.ID {
	return ids.ID(sha256.Sum256(b.Bytes()))
}

// parseBlockBytes decodes a block's structural fields from its ZAP wire. The
// transaction set is intentionally not reconstructed (see file header); the raw
// wire is retained in b.bytes so the quantum signature can be re-verified over
// the exact bytes.
func parseBlockBytes(vm *VM, data []byte) (*Block, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data) {
		return nil, fmt.Errorf("quantumvm: block trailing bytes")
	}
	o := msg.Root()
	// A field read past the end of the buffer answers zero rather than
	// failing, so a wire too short to hold the header does not decode to
	// nothing — it decodes to height 0, time 0 and the empty parent. Every
	// truncation would name that one value, under as many different ids as
	// there are ways to truncate.
	if o.Offset()+blkSize > msg.Size() {
		return nil, fmt.Errorf("quantumvm: block wire ends %d bytes into a %d-byte header",
			msg.Size()-o.Offset(), blkSize)
	}
	b := &Block{vm: vm, bytes: data}
	b.timestamp = time.Unix(o.Int64(blkTime), 0)
	b.height = o.Uint64(blkHeight)
	copy(b.parentID[:], o.BytesFixedSlice(blkParent, 32))
	b.id = ids.ID(sha256.Sum256(data))
	return b, nil
}

// ---- BaseTransaction ----
//
//	Timestamp i64   @ 0   (Unix seconds)
//	Nonce     u64   @ 8
//	Data      bytes @ 16
const (
	txTime  = 0
	txNonce = 8
	txData  = 16
	txSize  = 24
)

// Bytes returns the transaction's canonical ZAP wire. It excludes the quantum
// signature (which signs over exactly these bytes).
func (tx *BaseTransaction) Bytes() []byte {
	b := zap.NewBuilder(zap.HeaderSize + txSize + len(tx.data) + 32)
	ob := b.StartObject(txSize)
	ob.SetInt64(txTime, tx.timestamp.Unix())
	ob.SetUint64(txNonce, tx.nonce)
	ob.SetBytes(txData, tx.data)
	ob.FinishAsRoot()
	return b.Finish()
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
