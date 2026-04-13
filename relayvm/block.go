// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// Block represents a block in the RelayVM chain
type Block struct {
	ParentID_      ids.ID     `json:"parentId"`
	BlockHeight    uint64     `json:"height"`
	BlockTimestamp int64      `json:"timestamp"`
	Messages       []*Message `json:"messages"`
	Receipts       []*MessageReceipt `json:"receipts,omitempty"`
	StateRoot      []byte     `json:"stateRoot"`

	// Cached values
	ID_    ids.ID
	bytes  []byte
	status choices.Status
	vm     *VM
}

// ID returns the block ID
func (b *Block) ID() ids.ID {
	if b.ID_ == ids.Empty {
		b.ID_ = b.computeID()
	}
	return b.ID_
}

// computeID computes the block ID
func (b *Block) computeID() ids.ID {
	h := sha256.New()
	h.Write(b.ParentID_[:])
	binary.Write(h, binary.BigEndian, b.BlockHeight)
	binary.Write(h, binary.BigEndian, b.BlockTimestamp)

	// Include message IDs
	for _, msg := range b.Messages {
		msgID := msg.ID
		h.Write(msgID[:])
	}

	// Include receipt hashes
	for _, receipt := range b.Receipts {
		h.Write(receipt.MessageID[:])
		h.Write(receipt.ResultHash)
	}

	// Include state root
	h.Write(b.StateRoot)

	return ids.ID(h.Sum(nil))
}

// ParentID returns the parent block ID
func (b *Block) ParentID() ids.ID {
	return b.ParentID_
}

// Parent is an alias for ParentID for compatibility
func (b *Block) Parent() ids.ID {
	return b.ParentID_
}

// Height returns the block height
func (b *Block) Height() uint64 {
	return b.BlockHeight
}

// Timestamp returns the block timestamp
func (b *Block) Timestamp() time.Time {
	return time.Unix(b.BlockTimestamp, 0)
}

// Status returns the block status
func (b *Block) Status() uint8 {
	return uint8(b.status)
}

// Verify verifies the block
func (b *Block) Verify(ctx context.Context) error {
	// Verify height
	if b.BlockHeight == 0 && b.ParentID_ != ids.Empty {
		return errors.New("invalid genesis block")
	}

	// Verify timestamp is not too far in future
	if b.BlockTimestamp > time.Now().Unix()+60 {
		return errors.New("block timestamp too far in future")
	}

	// Verify parent exists and heights are consecutive
	if b.BlockHeight > 0 {
		parent, err := b.vm.GetBlock(ctx, b.ParentID_)
		if err != nil {
			return err
		}

		if b.BlockHeight != parent.Height()+1 {
			return errors.New("non-consecutive block heights")
		}

		if b.BlockTimestamp < parent.Timestamp().Unix() {
			return errors.New("block timestamp before parent")
		}
	}

	// Verify all messages
	for _, msg := range b.Messages {
		if err := b.verifyMessage(msg); err != nil {
			return err
		}
	}

	return nil
}

func (b *Block) verifyMessage(msg *Message) error {
	// Verify message has valid channel
	_, err := b.vm.GetChannel(msg.ChannelID)
	if err != nil {
		return err
	}

	// Verify message size
	if len(msg.Payload) > b.vm.config.MaxMessageSize {
		return errMessageTooLarge
	}

	// Verify message hasn't timed out
	if msg.Timeout > 0 && time.Now().Unix() > msg.Timeout {
		return errors.New("message timeout exceeded")
	}

	return nil
}

// Accept accepts the block
func (b *Block) Accept(ctx context.Context) error {
	b.status = choices.Accepted

	b.vm.mu.Lock()
	defer b.vm.mu.Unlock()

	// Update VM state
	b.vm.lastAccepted = b
	b.vm.lastAcceptedID = b.ID()

	// Save last accepted
	id := b.ID()
	if err := b.vm.db.Put(lastAcceptedKey, id[:]); err != nil {
		return err
	}

	// Save block
	blockBytes := b.Bytes()
	if blockBytes == nil {
		return errors.New("failed to serialize block")
	}

	if err := b.vm.db.Put(id[:], blockBytes); err != nil {
		return err
	}

	// Process messages
	for _, msg := range b.Messages {
		msg.State = MessageDelivered
		msg.ConfirmedAt = b.BlockTimestamp

		// Remove from pending
		destMsgs := b.vm.pendingMsgs[msg.DestChain]
		for i, m := range destMsgs {
			if m.ID == msg.ID {
				b.vm.pendingMsgs[msg.DestChain] = append(destMsgs[:i], destMsgs[i+1:]...)
				break
			}
		}

		// Persist message
		msgBytes, _ := json.Marshal(msg)
		msgKey := append(messagePrefix, msg.ID[:]...)
		b.vm.db.Put(msgKey, msgBytes)
	}

	// Remove from pending blocks
	delete(b.vm.pendingBlocks, b.ID())

	b.vm.log.Info("Block accepted",
		log.Uint64("height", b.BlockHeight),
		log.String("id", b.ID().String()),
		log.Int("messages", len(b.Messages)),
	)

	return nil
}

// Reject rejects the block
func (b *Block) Reject(ctx context.Context) error {
	b.status = choices.Rejected

	b.vm.mu.Lock()
	defer b.vm.mu.Unlock()

	// Remove from pending blocks
	delete(b.vm.pendingBlocks, b.ID())

	// Messages remain in pending pool for next block attempt

	return nil
}

// Bytes returns the block bytes
func (b *Block) Bytes() []byte {
	if b.bytes != nil {
		return b.bytes
	}

	bytes, err := json.Marshal(b)
	if err != nil {
		return nil
	}

	b.bytes = bytes
	return bytes
}
