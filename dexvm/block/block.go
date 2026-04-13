// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package block implements block structure for the DEX VM.
package block

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/chains/dexvm/txs"
)

var (
	ErrBlockTooLarge    = errors.New("block exceeds maximum size")
	ErrTooManyTxs       = errors.New("block contains too many transactions")
	ErrInvalidBlockTime = errors.New("invalid block timestamp")
	ErrInvalidParent    = errors.New("invalid parent block")
	ErrBlockNotVerified = errors.New("block not verified")
)

// Status represents the verification status of a block.
type Status uint8

const (
	StatusPending Status = iota
	StatusProcessing
	StatusAccepted
	StatusRejected
)

func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusProcessing:
		return "processing"
	case StatusAccepted:
		return "accepted"
	case StatusRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

// Block represents a block in the DEX VM.
type Block struct {
	// Header fields
	id        ids.ID
	parentID  ids.ID
	height    uint64
	timestamp int64

	// Block content
	transactions []txs.Tx

	// Merkle roots
	txRoot    ids.ID
	stateRoot ids.ID

	// Producer info
	producer  ids.NodeID
	signature []byte

	// Verification status
	status   Status
	verified bool

	// Serialized bytes
	bytes []byte
}

// NewBlock creates a new block.
func NewBlock(
	parentID ids.ID,
	height uint64,
	timestamp int64,
	transactions []txs.Tx,
	producer ids.NodeID,
) *Block {
	return &Block{
		parentID:     parentID,
		height:       height,
		timestamp:    timestamp,
		transactions: transactions,
		producer:     producer,
		status:       StatusPending,
	}
}

// ID returns the block's unique identifier.
func (b *Block) ID() ids.ID {
	if b.id == ids.Empty {
		b.id = b.computeID()
	}
	return b.id
}

// Parent returns the parent block ID.
func (b *Block) Parent() ids.ID {
	return b.parentID
}

// Height returns the block height.
func (b *Block) Height() uint64 {
	return b.height
}

// Timestamp returns the block timestamp.
func (b *Block) Timestamp() time.Time {
	return time.Unix(0, b.timestamp)
}

// TimestampNano returns the block timestamp in nanoseconds.
func (b *Block) TimestampNano() int64 {
	return b.timestamp
}

// Transactions returns the transactions in the block.
func (b *Block) Transactions() []txs.Tx {
	return b.transactions
}

// TxCount returns the number of transactions in the block.
func (b *Block) TxCount() int {
	return len(b.transactions)
}

// TxRoot returns the merkle root of transactions.
func (b *Block) TxRoot() ids.ID {
	return b.txRoot
}

// StateRoot returns the state root after applying this block.
func (b *Block) StateRoot() ids.ID {
	return b.stateRoot
}

// Producer returns the node that produced this block.
func (b *Block) Producer() ids.NodeID {
	return b.producer
}

// Status returns the verification status.
func (b *Block) Status() Status {
	return b.status
}

// SetStatus sets the verification status.
func (b *Block) SetStatus(status Status) {
	b.status = status
}

// Bytes returns the serialized block.
func (b *Block) Bytes() []byte {
	if b.bytes == nil {
		b.bytes = b.serialize()
	}
	return b.bytes
}

// Verify verifies the block's validity.
func (b *Block) Verify(ctx context.Context) error {
	// Verify timestamp is not in the future
	now := time.Now().UnixNano()
	if b.timestamp > now+int64(time.Second) { // Allow 1 second drift
		return ErrInvalidBlockTime
	}

	// Verify each transaction
	for _, tx := range b.transactions {
		if err := tx.Verify(); err != nil {
			return fmt.Errorf("invalid transaction %s: %w", tx.ID(), err)
		}
	}

	b.verified = true
	return nil
}

// Accept marks the block as accepted.
func (b *Block) Accept(ctx context.Context) error {
	if !b.verified {
		return ErrBlockNotVerified
	}
	b.status = StatusAccepted
	return nil
}

// Reject marks the block as rejected.
func (b *Block) Reject(ctx context.Context) error {
	b.status = StatusRejected
	return nil
}

// computeID computes the block ID from its contents.
func (b *Block) computeID() ids.ID {
	// In production, use proper hashing
	data := b.serialize()
	id, _ := ids.ToID(data)
	return id
}

// serialize serializes the block to bytes.
func (b *Block) serialize() []byte {
	// Calculate size
	// Header: parentID (32) + height (8) + timestamp (8) + txRoot (32) + stateRoot (32) + producer (20) + sigLen (4) + sig
	// Txs: numTxs (4) + [txLen (4) + txBytes]...

	sigLen := len(b.signature)
	txsSize := 4
	for _, tx := range b.transactions {
		txsSize += 4 + len(tx.Bytes())
	}

	headerSize := 32 + 8 + 8 + 32 + 32 + 20 + 4 + sigLen
	totalSize := headerSize + txsSize

	data := make([]byte, totalSize)
	offset := 0

	// Parent ID
	copy(data[offset:], b.parentID[:])
	offset += 32

	// Height
	binary.BigEndian.PutUint64(data[offset:], b.height)
	offset += 8

	// Timestamp
	binary.BigEndian.PutUint64(data[offset:], uint64(b.timestamp))
	offset += 8

	// TX Root
	copy(data[offset:], b.txRoot[:])
	offset += 32

	// State Root
	copy(data[offset:], b.stateRoot[:])
	offset += 32

	// Producer
	copy(data[offset:], b.producer[:])
	offset += 20

	// Signature length and signature
	binary.BigEndian.PutUint32(data[offset:], uint32(sigLen))
	offset += 4
	copy(data[offset:], b.signature)
	offset += sigLen

	// Number of transactions
	binary.BigEndian.PutUint32(data[offset:], uint32(len(b.transactions)))
	offset += 4

	// Transactions
	for _, tx := range b.transactions {
		txBytes := tx.Bytes()
		binary.BigEndian.PutUint32(data[offset:], uint32(len(txBytes)))
		offset += 4
		copy(data[offset:], txBytes)
		offset += len(txBytes)
	}

	return data
}

// BlockParser parses blocks from bytes.
type BlockParser struct {
	txParser *txs.TxParser
}

// NewBlockParser creates a new block parser.
func NewBlockParser() *BlockParser {
	return &BlockParser{
		txParser: &txs.TxParser{},
	}
}

// Parse parses a block from bytes.
func (p *BlockParser) Parse(data []byte) (*Block, error) {
	if len(data) < 136 { // Minimum header size
		return nil, errors.New("block data too short")
	}

	b := &Block{
		bytes: data,
	}

	offset := 0

	// Parent ID
	copy(b.parentID[:], data[offset:offset+32])
	offset += 32

	// Height
	b.height = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Timestamp
	b.timestamp = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	// TX Root
	copy(b.txRoot[:], data[offset:offset+32])
	offset += 32

	// State Root
	copy(b.stateRoot[:], data[offset:offset+32])
	offset += 32

	// Producer
	copy(b.producer[:], data[offset:offset+20])
	offset += 20

	// Signature length and signature
	if offset+4 > len(data) {
		return nil, errors.New("invalid block: missing signature length")
	}
	sigLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if offset+int(sigLen) > len(data) {
		return nil, errors.New("invalid block: signature truncated")
	}
	b.signature = make([]byte, sigLen)
	copy(b.signature, data[offset:offset+int(sigLen)])
	offset += int(sigLen)

	// Number of transactions
	if offset+4 > len(data) {
		return nil, errors.New("invalid block: missing tx count")
	}
	numTxs := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Parse transactions
	b.transactions = make([]txs.Tx, 0, numTxs)
	for i := uint32(0); i < numTxs; i++ {
		if offset+4 > len(data) {
			return nil, errors.New("invalid block: tx length truncated")
		}
		txLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		if offset+int(txLen) > len(data) {
			return nil, errors.New("invalid block: tx data truncated")
		}
		txBytes := data[offset : offset+int(txLen)]
		offset += int(txLen)

		tx, err := p.txParser.Parse(txBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tx %d: %w", i, err)
		}
		b.transactions = append(b.transactions, tx)
	}

	// Compute ID
	b.id = b.computeID()

	return b, nil
}

// Builder builds new blocks.
type Builder struct {
	parentID       ids.ID
	height         uint64
	maxBlockSize   uint64
	maxTxsPerBlock uint32
	transactions   []txs.Tx
	currentSize    uint64
}

// NewBuilder creates a new block builder.
func NewBuilder(parentID ids.ID, height uint64, maxBlockSize uint64, maxTxsPerBlock uint32) *Builder {
	return &Builder{
		parentID:       parentID,
		height:         height,
		maxBlockSize:   maxBlockSize,
		maxTxsPerBlock: maxTxsPerBlock,
		transactions:   make([]txs.Tx, 0, maxTxsPerBlock),
		currentSize:    136, // Base header size
	}
}

// AddTx adds a transaction to the pending block.
func (b *Builder) AddTx(tx txs.Tx) error {
	txSize := uint64(len(tx.Bytes()) + 4) // tx bytes + length prefix

	if b.currentSize+txSize > b.maxBlockSize {
		return ErrBlockTooLarge
	}

	if uint32(len(b.transactions)) >= b.maxTxsPerBlock {
		return ErrTooManyTxs
	}

	b.transactions = append(b.transactions, tx)
	b.currentSize += txSize
	return nil
}

// Build builds the block.
func (b *Builder) Build(producer ids.NodeID) *Block {
	return NewBlock(
		b.parentID,
		b.height,
		time.Now().UnixNano(),
		b.transactions,
		producer,
	)
}

// TxCount returns the number of pending transactions.
func (b *Builder) TxCount() int {
	return len(b.transactions)
}

// CurrentSize returns the current block size.
func (b *Builder) CurrentSize() uint64 {
	return b.currentSize
}

// Clear clears the builder for reuse.
func (b *Builder) Clear(parentID ids.ID, height uint64) {
	b.parentID = parentID
	b.height = height
	b.transactions = b.transactions[:0]
	b.currentSize = 136
}
