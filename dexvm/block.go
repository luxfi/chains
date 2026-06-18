// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/luxfi/vm/chain"
	"github.com/luxfi/ids"
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

// Bytes returns the serialized block.
//
// WIRE FORMAT (NETWORK-UPGRADE-GATED, LOCKSTEP — RED finding #9). The block now
// carries the proposer's confirmed d-chain fills so every validator settles from
// bytes instead of relaying per-validator. The layout is:
//
//	height[8] | timestamp[8] | parentID[32] |
//	txCount[4] | txCount × ( txLen[4] | txBytes ) |
//	carried-fills section (carried_fills.go encodeCarriedFills):
//	  entryCount[4] | entryCount × ( txIndex[4] | fillCount[4] | fillCount×17 ) |
//	  sigLen[4] | sig[sigLen]   // reserved fill-attestation, empty today
//
// The txCount prefix (NEW) makes the txs self-delimiting so the carried-fills
// section can follow unambiguously; the prior format ran txs to end-of-buffer.
// This is a consensus-breaking change activated in lockstep across the validator
// set behind a network upgrade.
func (b *Block) Bytes() []byte {
	size := 8 + 8 + 32 + 4 // header + txCount
	for _, tx := range b.txs {
		size += 4 + len(tx) // length prefix + tx
	}
	fillsSection := encodeCarriedFills(b.carriedFills, b.fillSig)
	size += len(fillsSection)

	data := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint64(data[offset:], b.height)
	offset += 8

	binary.BigEndian.PutUint64(data[offset:], uint64(b.timestamp.UnixNano()))
	offset += 8

	copy(data[offset:], b.parentID[:])
	offset += 32

	binary.BigEndian.PutUint32(data[offset:], uint32(len(b.txs)))
	offset += 4
	for _, tx := range b.txs {
		binary.BigEndian.PutUint32(data[offset:], uint32(len(tx)))
		offset += 4
		copy(data[offset:], tx)
		offset += len(tx)
	}

	copy(data[offset:], fillsSection)
	offset += len(fillsSection)

	return data
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
	if len(data) < 8+8+32+4 { // header + txCount
		return nil, errInvalidBlock
	}

	b := &Block{
		vm:     vm,
		status: StatusUnknown,
	}

	offset := 0

	b.height = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	ts := binary.BigEndian.Uint64(data[offset:])
	b.timestamp = time.Unix(0, int64(ts))
	offset += 8

	copy(b.parentID[:], data[offset:offset+32])
	offset += 32

	// txCount-delimited transactions (the prefix makes the carried-fills section
	// that follows unambiguous).
	txCount := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	for i := uint32(0); i < txCount; i++ {
		if offset+4 > len(data) {
			return nil, errInvalidBlock
		}
		txLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		if offset+int(txLen) > len(data) {
			return nil, errInvalidBlock
		}
		tx := make([]byte, txLen)
		copy(tx, data[offset:offset+int(txLen)])
		b.txs = append(b.txs, tx)
		offset += int(txLen)
	}

	// Carried-fills section: the proposer's confirmed fills every validator settles
	// from. Must be exactly consumed to end-of-block (no trailing garbage).
	entries, sig, consumed, err := decodeCarriedFills(data[offset:])
	if err != nil {
		return nil, errInvalidBlock
	}
	if offset+consumed != len(data) {
		return nil, errInvalidBlock
	}
	b.carriedFills = entries
	b.fillSig = sig

	// Compute block ID from bytes using sha256.
	hash := sha256.Sum256(data)
	copy(b.id[:], hash[:])

	return b, nil
}
