// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"errors"
	"time"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
	"github.com/luxfi/crypto/hash"
)

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
	b.vm.preferredID = b.id

	return nil
}

// Reject implements the chain.Block interface
func (b *Block) Reject(context.Context) error {
	b.status = choices.Rejected
	return nil
}

// Status implements the chain.Block interface
func (b *Block) Status() choices.Status {
	return b.status
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

// Bytes implements the chain.Block interface
func (b *Block) Bytes() []byte {
	if b.bytes == nil {
		b.bytes = hash.ComputeHash256([]byte(b.id.String()))
	}
	return b.bytes
}
