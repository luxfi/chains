// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/luxfi/ids"
)

// Block represents a K-Chain block containing key management transactions.
type Block struct {
	id           ids.ID
	parentID     ids.ID
	height       uint64
	timestamp    time.Time
	transactions []*Transaction
	stateRoot    ids.ID
	vm           *VM
}

// computeID computes the block ID from its contents.
func (b *Block) computeID() ids.ID {
	h := sha256.New()
	h.Write(b.parentID[:])
	binary.Write(h, binary.BigEndian, b.height)
	binary.Write(h, binary.BigEndian, b.timestamp.Unix())
	for _, tx := range b.transactions {
		txID := tx.ID()
		h.Write(txID[:])
	}
	h.Write(b.stateRoot[:])
	return ids.ID(h.Sum(nil))
}

// ID returns the block's unique identifier.
func (b *Block) ID() ids.ID {
	if b.id == ids.Empty {
		b.id = b.computeID()
	}
	return b.id
}

// ParentID returns the parent block's ID.
func (b *Block) ParentID() ids.ID {
	return b.parentID
}

// Parent returns the parent block's ID (alias for ParentID).
func (b *Block) Parent() ids.ID {
	return b.parentID
}

// Height returns the block's height.
func (b *Block) Height() uint64 {
	return b.height
}

// Timestamp returns the block's timestamp.
func (b *Block) Timestamp() time.Time {
	return b.timestamp
}

// Bytes serializes the block to bytes.
func (b *Block) Bytes() []byte {
	// Serialize block
	data := make([]byte, 0, 256)

	// Parent ID
	data = append(data, b.parentID[:]...)

	// Height
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, b.height)
	data = append(data, heightBytes...)

	// Timestamp
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(b.timestamp.Unix()))
	data = append(data, tsBytes...)

	// Transaction count
	txCountBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(txCountBytes, uint32(len(b.transactions)))
	data = append(data, txCountBytes...)

	// Serialize transactions
	for _, tx := range b.transactions {
		txBytes := tx.Bytes()
		txLenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(txLenBytes, uint32(len(txBytes)))
		data = append(data, txLenBytes...)
		data = append(data, txBytes...)
	}

	return data
}

// Verify verifies the block is valid.
func (b *Block) Verify(ctx context.Context) error {
	// Verify parent exists
	if b.height > 0 {
		if _, err := b.vm.GetBlock(ctx, b.parentID); err != nil {
			return err
		}
	}

	// Verify transactions
	for _, tx := range b.transactions {
		if err := tx.Verify(ctx); err != nil {
			return err
		}
	}

	return nil
}

// Accept accepts the block as final.
func (b *Block) Accept(ctx context.Context) error {
	// Store block
	blockBytes := b.Bytes()
	if err := b.vm.state.Put(b.id[:], blockBytes); err != nil {
		return err
	}

	// Update last accepted and remove from pending under lock
	b.vm.shutdownLock.Lock()
	b.vm.lastAccepted = b.id
	b.vm.lastAccepted_ = b
	b.vm.height = b.height
	delete(b.vm.pendingBlocks, b.id)
	b.vm.shutdownLock.Unlock()

	// Execute transactions
	for _, tx := range b.transactions {
		if err := tx.Execute(ctx, b.vm); err != nil {
			b.vm.log.Warn("transaction execution failed", "txID", tx.ID(), "error", err)
		}
	}

	b.vm.log.Info("accepted block",
		"blockID", b.id,
		"height", b.height,
		"txCount", len(b.transactions),
	)

	return nil
}

// Reject rejects the block.
func (b *Block) Reject(ctx context.Context) error {
	// Remove from pending under lock
	b.vm.shutdownLock.Lock()
	delete(b.vm.pendingBlocks, b.id)
	b.vm.shutdownLock.Unlock()

	b.vm.log.Info("rejected block", "blockID", b.id, "height", b.height)
	return nil
}

// Status returns the block's status (0=Processing, 1=Accepted, 2=Rejected).
func (b *Block) Status() uint8 {
	// Check if block is in database
	_, err := b.vm.state.Get(b.id[:])
	if err != nil {
		return 0 // Processing/Unknown
	}

	if b.id == b.vm.lastAccepted {
		return 1 // Accepted
	}

	return 0 // Processing
}
