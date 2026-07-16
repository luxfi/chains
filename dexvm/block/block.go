// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package block implements block structure for the DEX VM.
package block

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/chains/dexvm/txs"
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
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

// Block wire (native ZAP, object offsets). timestamp is nanoseconds; the
// transaction list preserves proposer order.
//
//	ParentID  32B   @ 0
//	Height    u64   @ 32
//	Timestamp i64   @ 40   (nanoseconds)
//	TxRoot    32B   @ 48
//	StateRoot 32B   @ 80
//	Producer  20B   @ 112
//	Signature bytes @ 132
//	TxLens    list  @ 140  (u32 per tx; order preserved)
//	TxBlob    bytes @ 148  (concatenated tx wire bytes)
const (
	sbParent = 0
	sbHeight = 32
	sbTime   = 40
	sbTxRoot = 48
	sbState  = 80
	sbProd   = 112
	sbSig    = 132
	sbTxLens = 140
	sbTxBlob = 148
	sbSize   = 156
)

// serialize serializes the block to its canonical ZAP wire.
func (b *Block) serialize() []byte {
	txLens := make([]uint32, len(b.transactions))
	var txBlob []byte
	for i, tx := range b.transactions {
		tb := tx.Bytes()
		txLens[i] = uint32(len(tb))
		txBlob = append(txBlob, tb...)
	}

	bld := zap.NewBuilder(zap.HeaderSize + sbSize + len(b.signature) + len(txBlob) + 4*len(txLens) + 128)
	txLensOff := writeU32List(bld, txLens)

	ob := bld.StartObject(sbSize)
	ob.SetBytesFixed(sbParent, b.parentID[:])
	ob.SetUint64(sbHeight, b.height)
	ob.SetInt64(sbTime, b.timestamp)
	ob.SetBytesFixed(sbTxRoot, b.txRoot[:])
	ob.SetBytesFixed(sbState, b.stateRoot[:])
	ob.SetBytesFixed(sbProd, b.producer[:])
	ob.SetBytes(sbSig, b.signature)
	ob.SetList(sbTxLens, txLensOff, len(txLens))
	ob.SetBytes(sbTxBlob, txBlob)
	ob.FinishAsRoot()
	return bld.Finish()
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

// Parse parses a block from its ZAP wire (the inverse of serialize). Every
// length is bounds-checked; a malformed block is rejected rather than panicking.
func (p *BlockParser) Parse(data []byte) (*Block, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data) {
		return nil, errors.New("invalid block: trailing bytes")
	}
	o := msg.Root()

	b := &Block{bytes: data}
	copy(b.parentID[:], o.BytesFixedSlice(sbParent, 32))
	b.height = o.Uint64(sbHeight)
	b.timestamp = o.Int64(sbTime)
	copy(b.txRoot[:], o.BytesFixedSlice(sbTxRoot, 32))
	copy(b.stateRoot[:], o.BytesFixedSlice(sbState, 32))
	copy(b.producer[:], o.BytesFixedSlice(sbProd, 20))
	b.signature = appendBytes(o.Bytes(sbSig))

	lens := readU32List(o, sbTxLens)
	blob := o.Bytes(sbTxBlob)
	b.transactions = make([]txs.Tx, 0, len(lens))
	pos := 0
	for i, l := range lens {
		if pos+int(l) > len(blob) {
			return nil, fmt.Errorf("invalid block: tx %d truncated", i)
		}
		tx, err := p.txParser.Parse(blob[pos : pos+int(l)])
		if err != nil {
			return nil, fmt.Errorf("failed to parse tx %d: %w", i, err)
		}
		b.transactions = append(b.transactions, tx)
		pos += int(l)
	}

	b.id = b.computeID()
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

func appendBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
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
