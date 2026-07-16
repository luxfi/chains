// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/zap"
)

// Ensure Block implements chain.Block
var _ chain.Block = (*Block)(nil)

// Block represents a DEX VM block that wraps the functional ProcessBlock results.
// It implements the chain.Block interface required for the ChainVM.
type Block struct {
	vm *ChainVM

	// Block header fields
	id        ids.ID
	parentID  ids.ID
	height    uint64
	timestamp time.Time

	// Block body - serialized transactions
	txs [][]byte

	// carriedFills are the d-chain matcher's confirmed fills the PROPOSER obtained
	// once at build (chainvm.go BuildBlock -> VM.BuildBlockResult) and serialized
	// into the block bytes. Every validator parses them and settles purely from
	// them — no validator relays during Verify/Accept (RED finding #9). fillSig is
	// the reserved trustless-path attestation (empty today). See carried_fills.go.
	//
	// CARRYING THESE CHANGES THE BLOCK WIRE FORMAT — a network-upgrade-gated,
	// lockstep validator change (a node on the old format cannot parse a new block).
	carriedFills []carriedFill
	fillSig      []byte

	// Processing result (populated after verification)
	result *BlockResult

	// Block status
	status Status
}

// Status represents block status
type Status uint8

const (
	StatusUnknown Status = iota
	StatusProcessing
	StatusAccepted
	StatusRejected
)

// ID returns the unique identifier for this block
func (b *Block) ID() ids.ID {
	return b.id
}

// Parent returns the parent block's ID (alias for ParentID)
func (b *Block) Parent() ids.ID {
	return b.parentID
}

// ParentID returns the parent block's ID
func (b *Block) ParentID() ids.ID {
	return b.parentID
}

// Height returns the block height
func (b *Block) Height() uint64 {
	return b.height
}

// Timestamp returns the block timestamp
func (b *Block) Timestamp() time.Time {
	return b.timestamp
}

// Block wire (native ZAP, object offsets; RED finding #9). The block carries the
// proposer's confirmed d-chain fills so every validator settles from bytes
// instead of relaying per-validator:
//
//	Height    u64   @ 0
//	Timestamp i64   @ 8    (UnixNano — sub-second cadence preserved, no floor)
//	ParentID  32B   @ 16
//	TxLens    list  @ 48   (u32 per tx; ORDER is the DEX fairness invariant)
//	TxBlob    bytes @ 56   (concatenated raw tx bytes, order preserved)
//	Fills     bytes @ 64   (carried-fills section: encodeCarriedFills output)
//
// blockID = sha256(Bytes()); the fills ride in the bytes, so the id commits to
// them (a peer cannot swap the proposer's fills and keep the same id). Changing
// this wire is a network-upgrade-gated, lockstep validator change.
const (
	blkHeight = 0
	blkTime   = 8
	blkParent = 16
	blkTxLens = 48
	blkTxBlob = 56
	blkFills  = 64
	blkSize   = 72
)

// Bytes returns the serialized block.
func (b *Block) Bytes() []byte {
	txLens := make([]uint32, len(b.txs))
	var txBlob []byte
	for i, tx := range b.txs {
		txLens[i] = uint32(len(tx))
		txBlob = append(txBlob, tx...)
	}
	fillsSection := encodeCarriedFills(b.carriedFills, b.fillSig)

	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(txBlob) + 4*len(txLens) + len(fillsSection) + 128)
	txLensOff := writeU32List(bld, txLens)

	ob := bld.StartObject(blkSize)
	ob.SetUint64(blkHeight, b.height)
	ob.SetInt64(blkTime, b.timestamp.UnixNano())
	ob.SetBytesFixed(blkParent, b.parentID[:])
	ob.SetList(blkTxLens, txLensOff, len(txLens))
	ob.SetBytes(blkTxBlob, txBlob)
	ob.SetBytes(blkFills, fillsSection)
	ob.FinishAsRoot()
	return bld.Finish()
}

// Verify verifies the block is valid by processing it deterministically, then
// attaches the block-CARRIED fills (RED #9) so accept settles from bytes rather
// than relaying. Verify performs NO d-chain I/O on any node — the proposer already
// relayed once at build (BuildBlockResult) and the fills travel in the block bytes.
func (b *Block) Verify(ctx context.Context) error {
	result, err := b.vm.inner.ProcessBlock(ctx, b.height, b.timestamp, b.txs)
	if err != nil {
		return err
	}
	// Settle from the carried fills (parsed from the block bytes on a validator, or
	// produced at build on the proposer). settleCarried (at accept) drives the
	// settlement off result.relays (the deterministic plan) and these carried fills.
	result.carriedFills = b.carriedFills
	result.fillSig = b.fillSig
	b.result = result
	b.status = StatusProcessing
	return nil
}

// Accept marks the block as accepted and commits the proxy's state batch
// ATOMICALLY with the cross-chain shared-memory operations accumulated during
// Verify (the settlement leg) — the single commit point.
func (b *Block) Accept(ctx context.Context) error {
	b.status = StatusAccepted

	// Update VM state
	b.vm.lastAcceptedID = b.id
	b.vm.lastAcceptedHeight = b.height
	b.vm.blocks[b.id] = b

	// Atomic commit: run the deferred relay plan (the irreversible d-chain leg)
	// then commit the state batch + shared-memory import/export requests in one
	// atomic apply. This is the single commit point — the relay never fires
	// during Verify, so a Rejected block never strands a d-chain match.
	return b.vm.inner.acceptBlock(ctx, b.result)
}

// Reject marks the block as rejected
func (b *Block) Reject(ctx context.Context) error {
	b.status = StatusRejected

	// Abort any pending database changes
	if b.vm.inner.db != nil {
		b.vm.inner.db.Abort()
	}

	return nil
}

// Status returns the block's status as uint8
func (b *Block) Status() uint8 {
	return uint8(b.status)
}

// parseBlock deserializes a block from bytes (the inverse of Block.Bytes). It
// parses the header, the txCount-delimited transactions, and the carried-fills
// section (RED #9). Every length is bounds-checked so a malformed block is
// rejected as errInvalidBlock rather than panicking or over-allocating.
func parseBlock(vm *ChainVM, data []byte) (*Block, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return nil, errInvalidBlock
	}
	if msg.Size() != len(data) {
		return nil, errInvalidBlock
	}
	o := msg.Root()

	b := &Block{
		vm:     vm,
		status: StatusUnknown,
	}
	b.height = o.Uint64(blkHeight)
	b.timestamp = time.Unix(0, o.Int64(blkTime))
	copy(b.parentID[:], o.BytesFixedSlice(blkParent, 32))

	// txs in wire order — the DEX fairness/determinism invariant.
	lens := readU32List(o, blkTxLens)
	blob := o.Bytes(blkTxBlob)
	pos := 0
	for _, l := range lens {
		if pos+int(l) > len(blob) {
			return nil, errInvalidBlock
		}
		tx := make([]byte, l)
		copy(tx, blob[pos:pos+int(l)])
		b.txs = append(b.txs, tx)
		pos += int(l)
	}

	// Carried-fills section: the proposer's confirmed fills every validator settles
	// from. Must be exactly consumed within its field (no trailing garbage).
	fills := o.Bytes(blkFills)
	entries, sig, consumed, err := decodeCarriedFills(fills)
	if err != nil || consumed != len(fills) {
		return nil, errInvalidBlock
	}
	b.carriedFills = entries
	b.fillSig = sig

	// Compute block ID from bytes using sha256.
	hash := sha256.Sum256(data)
	copy(b.id[:], hash[:])

	return b, nil
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
