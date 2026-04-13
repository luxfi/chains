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

// Bytes returns the serialized block
func (b *Block) Bytes() []byte {
	// Simple serialization: height (8) + timestamp (8) + parentID (32) + txs
	size := 8 + 8 + 32
	for _, tx := range b.txs {
		size += 4 + len(tx) // 4 bytes for length prefix
	}

	data := make([]byte, size)
	offset := 0

	// Height
	binary.BigEndian.PutUint64(data[offset:], b.height)
	offset += 8

	// Timestamp
	binary.BigEndian.PutUint64(data[offset:], uint64(b.timestamp.UnixNano()))
	offset += 8

	// Parent ID
	copy(data[offset:], b.parentID[:])
	offset += 32

	// Transactions
	for _, tx := range b.txs {
		binary.BigEndian.PutUint32(data[offset:], uint32(len(tx)))
		offset += 4
		copy(data[offset:], tx)
		offset += len(tx)
	}

	return data
}

// Verify verifies the block is valid by processing it deterministically
func (b *Block) Verify(ctx context.Context) error {
	// Process the block through the functional VM
	result, err := b.vm.inner.ProcessBlock(ctx, b.height, b.timestamp, b.txs)
	if err != nil {
		return err
	}
	b.result = result
	b.status = StatusProcessing
	return nil
}

// Accept marks the block as accepted
func (b *Block) Accept(ctx context.Context) error {
	b.status = StatusAccepted

	// Update VM state
	b.vm.lastAcceptedID = b.id
	b.vm.lastAcceptedHeight = b.height
	b.vm.blocks[b.id] = b

	// Commit database changes
	if b.vm.inner.db != nil {
		if err := b.vm.inner.db.Commit(); err != nil {
			return err
		}
	}

	return nil
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

// parseBlock deserializes a block from bytes
func parseBlock(vm *ChainVM, data []byte) (*Block, error) {
	if len(data) < 48 { // minimum: height + timestamp + parentID
		return nil, errInvalidBlock
	}

	b := &Block{
		vm:     vm,
		status: StatusUnknown,
	}

	offset := 0

	// Height
	b.height = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Timestamp
	ts := binary.BigEndian.Uint64(data[offset:])
	b.timestamp = time.Unix(0, int64(ts))
	offset += 8

	// Parent ID
	copy(b.parentID[:], data[offset:offset+32])
	offset += 32

	// Transactions
	for offset < len(data) {
		if offset+4 > len(data) {
			break
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

	// Compute block ID from bytes using sha256
	hash := sha256.Sum256(data)
	copy(b.id[:], hash[:])

	return b, nil
}
