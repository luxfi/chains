// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thresholdvm

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// Operation types
const (
	OpTypeKeygen  = "keygen"
	OpTypeSign    = "sign"
	OpTypeReshare = "reshare"
	OpTypeRefresh = "refresh"
)

// Operation represents an MPC operation recorded in a block
type Operation struct {
	Type            string `json:"type"` // keygen, sign, reshare, refresh
	SessionID       string `json:"sessionId"`
	KeyID           string `json:"keyId"`
	Protocol        string `json:"protocol,omitempty"`
	RequestingChain string `json:"requestingChain,omitempty"`
	MessageHash     []byte `json:"messageHash,omitempty"`
	Signature       []byte `json:"signature,omitempty"`
	Timestamp       int64  `json:"timestamp"`
	Success         bool   `json:"success"`
	Error           string `json:"error,omitempty"`
}

// Block represents a T-Chain block
type Block struct {
	ID_            ids.ID       `json:"id"`
	ParentID_      ids.ID       `json:"parentId"`
	BlockHeight    uint64       `json:"height"`
	BlockTimestamp int64        `json:"timestamp"`
	Operations     []*Operation `json:"operations"`

	vm     *VM
	status choices.Status
}

// ID returns the block's ID
func (b *Block) ID() ids.ID {
	return b.ID_
}

// Parent returns the parent block's ID (legacy)
func (b *Block) Parent() ids.ID {
	return b.ParentID_
}

// ParentID returns the parent block's ID (implements block.Block interface)
func (b *Block) ParentID() ids.ID {
	return b.ParentID_
}

// Height returns the block's height
func (b *Block) Height() uint64 {
	return b.BlockHeight
}

// Timestamp returns the block's timestamp
func (b *Block) Timestamp() time.Time {
	return time.Unix(b.BlockTimestamp, 0)
}

// Status returns the block's status as uint8 (implements block.Block interface)
func (b *Block) Status() uint8 {
	return uint8(b.status)
}

// ChoicesStatus returns the block's status as choices.Status
func (b *Block) ChoicesStatus() choices.Status {
	return b.status
}

// Bytes returns the block's serialized bytes
func (b *Block) Bytes() []byte {
	bytes, _ := Codec.Marshal(codecVersion, b)
	return bytes
}

// Verify verifies the block is valid
func (b *Block) Verify(ctx context.Context) error {
	// Verify parent exists
	if b.ParentID_ != ids.Empty {
		_, err := b.vm.getBlock(b.ParentID_)
		if err != nil {
			return err
		}
	}

	// Verify operations are valid
	for _, op := range b.Operations {
		if op.SessionID == "" {
			return ErrInvalidOperation
		}
		if op.KeyID == "" {
			return ErrInvalidOperation
		}
	}

	return nil
}

// Accept marks the block as accepted
func (b *Block) Accept(ctx context.Context) error {
	b.status = choices.Accepted

	b.vm.mu.Lock()
	defer b.vm.mu.Unlock()

	// Remove from pending
	delete(b.vm.pendingBlocks, b.ID())

	// Update last accepted
	b.vm.lastAcceptedID = b.ID()

	// Persist block
	if err := b.vm.putBlock(b); err != nil {
		return err
	}

	// Update height index
	b.vm.heightIndex[b.BlockHeight] = b.ID()

	// Clean up completed sessions
	for _, op := range b.Operations {
		switch op.Type {
		case OpTypeSign:
			delete(b.vm.signingSessions, op.SessionID)
		case OpTypeKeygen, OpTypeReshare, OpTypeRefresh:
			delete(b.vm.keygenSessions, op.SessionID)
		}
	}

	b.vm.log.Info("accepted threshold block",
		log.Stringer("blockID", b.ID()),
		log.Uint64("height", b.BlockHeight),
		log.Int("operations", len(b.Operations)),
	)

	return nil
}

// Reject marks the block as rejected
func (b *Block) Reject(ctx context.Context) error {
	b.status = choices.Rejected

	b.vm.mu.Lock()
	defer b.vm.mu.Unlock()

	// Remove from pending
	delete(b.vm.pendingBlocks, b.ID())

	b.vm.log.Info("rejected threshold block",
		log.Stringer("blockID", b.ID()),
	)

	return nil
}

// SetStatus sets the block's status
func (b *Block) SetStatus(status choices.Status) {
	b.status = status
}

// computeID computes the block's ID
func (b *Block) computeID() ids.ID {
	bytes, _ := Codec.Marshal(codecVersion, b)
	hash := sha256.Sum256(bytes)
	return ids.ID(hash)
}

var ErrInvalidOperation = &BlockError{Message: "invalid operation"}

type BlockError struct {
	Message string
}

func (e *BlockError) Error() string {
	return e.Message
}
