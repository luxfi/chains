// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schain

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chain"
)

// Ensure Block implements chain.Block.
var _ chain.Block = (*Block)(nil)

// Block is an S-Chain block. It wraps the deterministic ProcessBlock result and
// implements chain.Block. It carries only the storage VM's needs: a header and
// the serialized PutManifest transactions — no cross-chain carried fills (the
// dexvm wire-format complication a storage VM does not have).
type Block struct {
	vm *ChainVM

	id        ids.ID
	parentID  ids.ID
	height    uint64
	timestamp time.Time

	// txs are the serialized transactions (each a txs.PutManifestTx wire image).
	txs [][]byte

	// result is populated after Verify.
	result *BlockResult

	status Status
}

// Status represents block status.
type Status uint8

const (
	StatusUnknown Status = iota
	StatusProcessing
	StatusAccepted
	StatusRejected
)

func (b *Block) ID() ids.ID           { return b.id }
func (b *Block) Parent() ids.ID       { return b.parentID }
func (b *Block) ParentID() ids.ID     { return b.parentID }
func (b *Block) Height() uint64       { return b.height }
func (b *Block) Timestamp() time.Time { return b.timestamp }
func (b *Block) Status() uint8        { return uint8(b.status) }

// Bytes serializes the block. Wire format:
//
//	height[8] | timestamp[8] | parentID[32] |
//	txCount[4] | txCount × ( txLen[4] | txBytes )
//
// The txCount prefix makes the transactions self-delimiting. The block id is the
// sha256 of these bytes, so the id commits to every transaction (a peer cannot
// swap a manifest while keeping the same id).
func (b *Block) Bytes() []byte {
	size := 8 + 8 + 32 + 4
	for _, tx := range b.txs {
		size += 4 + len(tx)
	}

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
	return data
}

// Verify processes the block deterministically against the version layer. It
// performs NO external I/O on any node (mirror of dexvm/block.go:141). The
// manifest writes land in the in-memory version layer and become durable only at
// Accept.
func (b *Block) Verify(ctx context.Context) error {
	result, err := b.vm.inner.ProcessBlock(ctx, b.height, b.timestamp, b.txs)
	if err != nil {
		return err
	}
	b.result = result
	b.status = StatusProcessing
	return nil
}

// Accept marks the block accepted and commits its state batch in ONE atomic
// write (the single commit point — dexvm/block.go:159). After this returns, the
// block's manifests are durable and GetManifest observes them.
func (b *Block) Accept(ctx context.Context) error {
	b.status = StatusAccepted

	b.vm.lastAcceptedID = b.id
	b.vm.lastAcceptedHeight = b.height
	b.vm.blocks[b.id] = b

	return b.vm.inner.acceptBlock(ctx, b.result)
}

// Reject discards the block's staged version-layer changes (dexvm/block.go:175).
func (b *Block) Reject(ctx context.Context) error {
	b.status = StatusRejected
	if b.vm.inner.db != nil {
		b.vm.inner.db.Abort()
	}
	return nil
}

// parseBlock deserializes a block from bytes (the inverse of Block.Bytes). Every
// length is bounds-checked so a malformed block is rejected as errInvalidBlock
// rather than panicking or over-allocating.
func parseBlock(vm *ChainVM, data []byte) (*Block, error) {
	if len(data) < 8+8+32+4 {
		return nil, errInvalidBlock
	}

	b := &Block{vm: vm, status: StatusUnknown}
	offset := 0

	b.height = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	ts := binary.BigEndian.Uint64(data[offset:])
	b.timestamp = time.Unix(0, int64(ts))
	offset += 8

	copy(b.parentID[:], data[offset:offset+32])
	offset += 32

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
	if offset != len(data) {
		return nil, errInvalidBlock
	}

	hash := sha256.Sum256(data)
	copy(b.id[:], hash[:])
	return b, nil
}
