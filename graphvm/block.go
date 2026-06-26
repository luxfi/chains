// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
)

// The consensus engine requires every ChainVM to resolve a real last-accepted
// block at boot (LastAccepted -> GetBlock). This assertion guarantees *Block
// satisfies block.Block; it is what catches the Status() signature mismatch
// (the interface needs a concrete uint8, not the named choices.Status) at
// compile time so GetBlock can actually return a *Block.
var _ block.Block = (*Block)(nil)

var (
	errInvalidBlock = errors.New("invalid block")
)

// Block represents a block in the Graph Chain
type Block struct {
	vm *VM

	id        ids.ID
	parentID  ids.ID
	height    uint64
	timestamp time.Time

	// Graph-specific block data
	schemaUpdates   []*SchemaUpdate
	queryResults    []*QueryResult
	indexUpdates    []*IndexUpdate
	chainSyncEvents []*ChainSyncEvent

	status choices.Status
	bytes  []byte
}

// SchemaUpdate represents an update to a GraphQL schema
type SchemaUpdate struct {
	SchemaID   string `json:"schemaId"`
	Operation  string `json:"operation"` // create, update, delete
	NewVersion string `json:"newVersion,omitempty"`
	Schema     string `json:"schema,omitempty"`
}

// QueryResult represents a query result to be committed
type QueryResult struct {
	QueryID    ids.ID `json:"queryId"`
	ResultHash []byte `json:"resultHash"`
	Status     string `json:"status"`
}

// IndexUpdate represents an index update
type IndexUpdate struct {
	IndexID   string `json:"indexId"`
	ChainID   ids.ID `json:"chainId"`
	Operation string `json:"operation"` // create, update, rebuild
	Status    string `json:"status"`
}

// ChainSyncEvent represents a chain synchronization event
type ChainSyncEvent struct {
	ChainID     ids.ID `json:"chainId"`
	BlockHeight uint64 `json:"blockHeight"`
	BlockHash   ids.ID `json:"blockHash"`
	Timestamp   int64  `json:"timestamp"`
}

// ID implements the chain.Block interface
func (b *Block) ID() ids.ID {
	return b.id
}

// Accept implements the chain.Block interface
func (b *Block) Accept(context.Context) error {
	b.status = choices.Accepted

	// Process schema updates
	b.vm.schemaMu.Lock()
	for _, update := range b.schemaUpdates {
		switch update.Operation {
		case "create", "update":
			if schema, exists := b.vm.schemas[update.SchemaID]; exists {
				schema.Version = update.NewVersion
				schema.Schema = update.Schema
				schema.UpdatedAt = b.timestamp.Unix()
			} else {
				b.vm.schemas[update.SchemaID] = &GraphSchema{
					ID:        update.SchemaID,
					Version:   update.NewVersion,
					Schema:    update.Schema,
					CreatedAt: b.timestamp.Unix(),
					UpdatedAt: b.timestamp.Unix(),
				}
			}
		case "delete":
			delete(b.vm.schemas, update.SchemaID)
		}
	}
	b.vm.schemaMu.Unlock()

	// Process query results
	b.vm.queryMu.Lock()
	for _, result := range b.queryResults {
		if query, exists := b.vm.queries[result.QueryID]; exists {
			query.Status = QueryCompleted
			query.CompletedAt = b.timestamp.Unix()
		}
	}
	b.vm.queryMu.Unlock()

	// Process index updates
	for _, indexUpdate := range b.indexUpdates {
		if index, exists := b.vm.dataIndexes[indexUpdate.IndexID]; exists {
			index.Status = indexUpdate.Status
		}
	}

	// Process chain sync events
	for _, syncEvent := range b.chainSyncEvents {
		if source, exists := b.vm.chainSources[syncEvent.ChainID]; exists {
			source.LastSync = syncEvent.Timestamp
			source.BlockHeight = syncEvent.BlockHeight
		}
	}

	// Update last accepted
	b.vm.lastAcceptedID = b.id
	b.vm.preferredID = b.id

	return nil
}

// Reject implements the chain.Block interface
func (b *Block) Reject(context.Context) error {
	b.status = choices.Rejected
	return nil
}

// Status implements the block.Block interface. The interface requires a
// concrete uint8; choices.Status is `type Status uint8`, so a method returning
// the named type would NOT satisfy block.Block — which is why GetBlock could
// never have returned a *Block before this fix.
func (b *Block) Status() uint8 {
	return uint8(b.status)
}

// Parent implements the chain.Block interface
func (b *Block) Parent() ids.ID {
	return b.parentID
}

// ParentID returns the parent block ID
func (b *Block) ParentID() ids.ID {
	return b.parentID
}

// Height implements the chain.Block interface
func (b *Block) Height() uint64 {
	return b.height
}

// Timestamp implements the chain.Block interface
func (b *Block) Timestamp() time.Time {
	return b.timestamp
}

// Verify implements the chain.Block interface
func (b *Block) Verify(ctx context.Context) error {
	if b.height == 0 && b.parentID != ids.Empty {
		return errInvalidBlock
	}

	for _, update := range b.schemaUpdates {
		if update.Operation != "create" && update.Operation != "update" && update.Operation != "delete" {
			return errors.New("invalid schema operation")
		}
	}

	for _, result := range b.queryResults {
		if _, exists := b.vm.queries[result.QueryID]; !exists {
			return errors.New("result for unknown query")
		}
	}

	b.status = choices.Processing
	return nil
}

// Bytes implements the block.Block interface. It returns the deterministic
// canonical encoding set at construction; the block ID is the SHA-256 of
// exactly these bytes, so ParseBlock(b.Bytes()).ID() == b.ID().
func (b *Block) Bytes() []byte {
	return b.bytes
}

// genesisTimestamp is the deterministic timestamp of the G-Chain genesis block.
// Genesis is the root of trust (accepted by definition), so a fixed,
// node-independent value is used — never time.Now(), which would make the
// genesis block ID diverge across validators and break consensus agreement.
var genesisTimestamp = time.Unix(0, 0).UTC()

// blockWire is the deterministic on-wire encoding of a G-Chain block. The block
// ID is hash.ComputeHash256 of these bytes, so marshal/parse round-trips a
// byte-identical ID across nodes and restarts.
type blockWire struct {
	ParentID  ids.ID `json:"parentID"`
	Height    uint64 `json:"height"`
	Timestamp int64  `json:"timestamp"`
	Payload   []byte `json:"payload,omitempty"`
}

// newGenesisBlock builds the G-Chain genesis block (height 0) deterministically
// from the genesis config bytes. The G-Chain is a read-only query/index chain —
// it never builds blocks past genesis — so this is its permanent last-accepted
// block, the one GetBlock(LastAccepted()) must return during Initialize.
func newGenesisBlock(vm *VM, genesisBytes []byte) (*Block, error) {
	return newBlock(vm, ids.Empty, 0, genesisTimestamp, genesisBytes)
}

// newBlock constructs a block, computes its canonical bytes and content-
// addressed ID, and returns it ready to serve.
func newBlock(vm *VM, parentID ids.ID, height uint64, timestamp time.Time, payload []byte) (*Block, error) {
	raw, err := json.Marshal(blockWire{
		ParentID:  parentID,
		Height:    height,
		Timestamp: timestamp.Unix(),
		Payload:   payload,
	})
	if err != nil {
		return nil, err
	}
	return &Block{
		vm:        vm,
		id:        ids.ID(hash.ComputeHash256(raw)),
		parentID:  parentID,
		height:    height,
		timestamp: timestamp,
		status:    choices.Accepted,
		bytes:     raw,
	}, nil
}

// parseBlock decodes the canonical wire bytes produced by newBlock back into a
// Block whose ID is recomputed from those exact bytes.
func parseBlock(vm *VM, raw []byte) (*Block, error) {
	var wire blockWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, err
	}
	return &Block{
		vm:        vm,
		id:        ids.ID(hash.ComputeHash256(raw)),
		parentID:  wire.ParentID,
		height:    wire.Height,
		timestamp: time.Unix(wire.Timestamp, 0).UTC(),
		status:    choices.Accepted,
		bytes:     raw,
	}, nil
}
