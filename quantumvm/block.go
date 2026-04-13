// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/chains/quantumvm/quantum"
)

var (
	errBlockVerificationFailed = errors.New("block verification failed")
	errInvalidBlockHeight      = errors.New("invalid block height")
	errInvalidParentID         = errors.New("invalid parent ID")
)

// Block represents a QVM block with quantum features
type Block struct {
	id               ids.ID
	timestamp        time.Time
	height           uint64
	parentID         ids.ID
	transactions     []Transaction
	quantumSignature *quantum.QuantumSignature
	vm               *VM
	bytes            []byte
}

// ID returns the block ID
func (b *Block) ID() ids.ID {
	return b.id
}

// Accept marks the block as accepted
func (b *Block) Accept(context.Context) error {
	b.vm.lock.Lock()
	defer b.vm.lock.Unlock()

	// Store block in database
	if err := b.vm.state.Put(b.id[:], b.Bytes()); err != nil {
		return err
	}

	// Update last accepted
	if err := b.vm.state.Put([]byte("lastAccepted"), b.id[:]); err != nil {
		return err
	}

	// Update height
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, b.height)
	if err := b.vm.state.Put([]byte("height"), heightBytes); err != nil {
		return err
	}

	// Process transactions
	for _, tx := range b.transactions {
		if err := b.vm.txPool.RemoveTransaction(tx.ID()); err != nil {
			b.vm.log.Error("failed to remove tx from pool", "txID", tx.ID(), "error", err)
		}
	}

	b.vm.log.Info("block accepted",
		"blockID", b.id,
		"height", b.height,
		"txCount", len(b.transactions),
	)

	return nil
}

// Reject marks the block as rejected
func (b *Block) Reject(context.Context) error {
	b.vm.lock.Lock()
	defer b.vm.lock.Unlock()

	// Return transactions to pool
	for _, tx := range b.transactions {
		if err := b.vm.txPool.AddTransaction(tx); err != nil {
			b.vm.log.Error("failed to return tx to pool", "txID", tx.ID(), "error", err)
		}
	}

	b.vm.log.Debug("block rejected", "blockID", b.id, "height", b.height)
	return nil
}

// Verify verifies the block validity
func (b *Block) Verify(ctx context.Context) error {
	b.vm.lock.RLock()
	defer b.vm.lock.RUnlock()

	// Verify height
	if b.height == 0 {
		return errInvalidBlockHeight
	}

	// Verify parent exists (except for genesis)
	if b.height > 1 {
		if _, err := b.vm.GetBlock(ctx, b.parentID); err != nil {
			return errInvalidParentID
		}
	}

	// Verify quantum signature if enabled
	if b.vm.Config.QuantumStampEnabled {
		if b.quantumSignature == nil {
			return errInvalidQuantumStamp
		}
		if err := b.vm.quantumSigner.Verify(b.Bytes(), b.quantumSignature); err != nil {
			return errBlockVerificationFailed
		}
	}

	// Verify transactions in parallel
	if len(b.transactions) > 0 {
		msgs := make([][]byte, len(b.transactions))
		sigs := make([]*quantum.QuantumSignature, len(b.transactions))

		for i, tx := range b.transactions {
			msgs[i] = tx.Bytes()
			sigs[i] = tx.GetQuantumSignature()
		}

		if b.vm.Config.RingtailEnabled {
			if err := b.vm.quantumSigner.ParallelVerify(msgs, sigs); err != nil {
				return errBlockVerificationFailed
			}
		}
	}

	return nil
}

// Parent returns the parent block ID
func (b *Block) Parent() ids.ID {
	return b.parentID
}

// ParentID returns the parent block ID (implements consensus Block interface)
func (b *Block) ParentID() ids.ID {
	return b.parentID
}

// Height returns the block height
func (b *Block) Height() uint64 {
	return b.height
}

// Timestamp returns the block timestamp as Unix time (implements consensus Block interface)
func (b *Block) Timestamp() int64 {
	return b.timestamp.Unix()
}

// Time returns the block timestamp as time.Time
func (b *Block) Time() time.Time {
	return b.timestamp
}

// Bytes returns the block bytes
func (b *Block) Bytes() []byte {
	if b.bytes != nil {
		return b.bytes
	}

	// Serialize block
	size := 32 + 8 + 8 + 32 + 4 // id + timestamp + height + parentID + tx count
	for _, tx := range b.transactions {
		size += len(tx.Bytes())
	}

	bytes := make([]byte, 0, size)
	bytes = append(bytes, b.id[:]...)

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(b.timestamp.Unix()))
	bytes = append(bytes, timestampBytes...)

	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, b.height)
	bytes = append(bytes, heightBytes...)

	bytes = append(bytes, b.parentID[:]...)

	txCountBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(txCountBytes, uint32(len(b.transactions)))
	bytes = append(bytes, txCountBytes...)

	for _, tx := range b.transactions {
		bytes = append(bytes, tx.Bytes()...)
	}

	b.bytes = bytes
	return bytes
}

// String returns a string representation of the block
func (b *Block) String() string {
	return b.id.String()
}
