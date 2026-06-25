// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package schain implements the Lux S-Chain — the STORAGE VM.
//
// The S-Chain records object STORAGE MANIFESTS through real Lux consensus: a
// PutManifest mutation enters the mempool, the proposer drains it into a block,
// every validator deterministically applies it to a per-block version layer
// during Verify, and the block COMMITS the version layer to the chain's database
// (zapdb via the luxfi/database interface) in exactly ONE atomic batch at
// Accept. A manifest is durable — and GetManifest returns it — only after
// Accept.
//
// M0 is the smallest end-to-end proof of that contract: no blobs, no pinning, no
// networking beyond the VM↔engine contract. It forks dexvm's structure and
// COMMIT DISCIPLINE (chains/dexvm/vm.go), stripped of the DEX's cross-chain
// relay/settlement machinery, which a storage VM does not have:
//
//   - vm.db (versiondb) is the per-block state layer; vm.baseDB is the durable
//     base it wraps (mirror of dexvm/vm.go:316-318).
//   - ProcessBlock applies txs to the version layer, NO I/O, deterministic
//     (mirror of dexvm/vm.go:542).
//   - acceptBlock does ONE db.CommitBatch() + batch.Write() then db.Abort()
//     (mirror of dexvm/vm.go:1194 — its no-shared-memory branch).
//
// DESIGN: no background goroutines; every operation is block-driven and
// deterministic, so every node produces identical state from identical inputs.
package schain

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/timer/mockable"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"

	"github.com/luxfi/chains/schain/state"
	"github.com/luxfi/chains/schain/txs"
)

var (
	errShutdown = errors.New("VM is shutting down")

	parser = &txs.TxParser{}
)

// BlockResult is the deterministic result of processing one block. For the
// storage VM the per-block output is simply the height/time/blockHash binding —
// the manifest mutations are staged directly into the version layer by
// ProcessBlock and committed at Accept. There is no cross-chain leg to carry.
type BlockResult struct {
	BlockHeight uint64
	Timestamp   time.Time
	blockHash   ids.ID
}

// VM is the inner functional storage VM. It holds the dual-DB layering and the
// typed manifest state; the chain.ChainVM wrapper (ChainVM) drives it.
type VM struct {
	log log.Logger

	// Lock for thread safety (API access; consensus is single-threaded).
	lock sync.RWMutex

	// Consensus runtime — chain identity, network info, logger.
	consensusRuntime *runtime.Runtime
	chainID          ids.ID

	// Database management. db (versiondb) is the per-block state layer committed
	// atomically at Accept; baseDB is the durable base it wraps.
	baseDB database.Database
	db     *versiondb.Database

	// state persists the manifest mapping + last-block pointer.
	state *state.State

	// clock supplies the proposer's block time.
	clock mockable.Clock

	// Block state.
	currentBlockHeight uint64
	lastBlockTime      time.Time

	// Lifecycle.
	isInitialized bool
	shutdown      bool

	// Channel for VM->engine notifications.
	toEngine chan<- vmcore.Message
}

// Initialize sets up the VM with the consensus runtime, database, and channels.
// It establishes the dual-DB layering (baseDB durable, db versiondb) the commit
// discipline depends on — the exact wiring of dexvm/vm.go:311-321.
func (vm *VM) Initialize(ctx context.Context, vmInit vmcore.Init) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	vm.consensusRuntime = vmInit.Runtime
	if vm.consensusRuntime != nil {
		vm.chainID = vm.consensusRuntime.ChainID
	}

	// Logger from runtime, falling back to a no-op.
	if vm.consensusRuntime != nil && vm.consensusRuntime.Log != nil {
		if logger, ok := vm.consensusRuntime.Log.(log.Logger); ok && !logger.IsZero() {
			vm.log = logger
		} else {
			vm.log = log.Noop()
		}
	} else if vm.log.IsZero() {
		vm.log = log.Noop()
	}

	// Database. db (versiondb) is the per-block state layer committed atomically
	// at Accept; baseDB is the durable base it wraps.
	vm.baseDB = vmInit.DB
	vm.db = versiondb.New(vm.baseDB)
	vm.state = state.New(vm.db)
	if err := vm.state.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize storage state: %w", err)
	}

	vm.toEngine = vmInit.ToEngine
	vm.currentBlockHeight = 0
	vm.lastBlockTime = time.Time{}

	vm.isInitialized = true
	if !vm.log.IsZero() {
		vm.log.Info("S-Chain storage VM initialized", "chainID", vm.chainID)
	}
	return nil
}

// ProcessBlock deterministically applies a block's transactions to the version
// layer. It performs NO external I/O — the same inputs produce identical state
// on every node, so Verify is a pure function (mirror of dexvm/vm.go:542). The
// manifest writes land in vm.db's in-memory layer and become durable only when
// acceptBlock commits the batch.
func (vm *VM) ProcessBlock(ctx context.Context, blockHeight uint64, blockTime time.Time, blockTxs [][]byte) (*BlockResult, error) {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.shutdown {
		return nil, errShutdown
	}

	blockHash := deriveBlockHash(blockHeight, blockTime)
	result := &BlockResult{
		BlockHeight: blockHeight,
		Timestamp:   blockTime,
		blockHash:   blockHash,
	}

	for i, txBytes := range blockTxs {
		if err := vm.processTx(txBytes); err != nil {
			// An individual tx failure does not fail the block: a malformed or
			// invalid manifest simply stages no write. Mirrors dexvm's
			// per-tx-failure-continues discipline (dexvm/vm.go:562).
			if !vm.log.IsZero() {
				vm.log.Warn("S-Chain transaction failed", "index", i, "error", err)
			}
		}
	}

	vm.currentBlockHeight = blockHeight
	vm.lastBlockTime = blockTime
	if err := vm.state.SetLastBlock(blockHash, blockHeight); err != nil {
		return nil, fmt.Errorf("failed to persist last block: %w", err)
	}

	if !vm.log.IsZero() {
		vm.log.Debug("S-Chain block processed", "height", blockHeight, "txs", len(blockTxs))
	}
	return result, nil
}

// processTx parses one transaction and applies its mutation to the version
// layer. M0 has a single mutation: PutManifest.
func (vm *VM) processTx(txBytes []byte) error {
	tx, err := parser.Parse(txBytes)
	if err != nil {
		return err
	}
	if err := tx.Verify(); err != nil {
		return err
	}
	switch t := tx.(type) {
	case *txs.PutManifestTx:
		return vm.state.PutManifest(t.Bucket, t.Object, state.Manifest{
			FileIDs: t.FileIDs,
			Size:    t.Size,
			ETag:    t.ETag,
		})
	default:
		return txs.ErrInvalidTxType
	}
}

// acceptBlock is the SINGLE COMMIT POINT. It snapshots the version layer's
// staged writes into one batch and writes that batch atomically, then aborts the
// version layer's in-memory view (the platformvm defer-Abort pattern). This is
// the storage-VM analog of dexvm/vm.go:1194 with the cross-chain leg removed —
// a storage block has no shared-memory operations, so the commit is exactly
// CommitBatch + batch.Write.
func (vm *VM) acceptBlock(ctx context.Context, result *BlockResult) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.db == nil {
		return nil
	}
	_ = result
	_ = ctx

	// Abort clears the versiondb's in-memory layer after the batch is written
	// (the platformvm defer-Abort pattern dexvm follows at vm.go:1231).
	defer vm.db.Abort()
	batch, err := vm.db.CommitBatch()
	if err != nil {
		return fmt.Errorf("schain: commit batch: %w", err)
	}
	if batch == nil {
		return nil
	}
	return batch.Write()
}

// GetManifest returns a committed manifest for (bucket, object). Reads go
// through the version layer, so this observes only state already committed by an
// accepted block (the in-memory staging from an unaccepted block is the
// proposer's transient view, not durable). The M0 proof asserts a manifest is
// visible here ONLY after Accept.
func (vm *VM) GetManifest(bucket, object string) (state.Manifest, bool, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.state.GetManifest(bucket, object)
}

// GetLastBlockTime returns the timestamp of the last processed block.
func (vm *VM) GetLastBlockTime() time.Time {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.lastBlockTime
}

// GetBlockHeight returns the current block height.
func (vm *VM) GetBlockHeight() uint64 {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.currentBlockHeight
}

// Shutdown closes the database.
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if !vm.log.IsZero() {
		vm.log.Info("Shutting down S-Chain storage VM")
	}
	vm.shutdown = true
	if vm.db != nil {
		if err := vm.db.Close(); err != nil {
			return fmt.Errorf("failed to close database: %w", err)
		}
	}
	return nil
}

// Version returns the VM version string.
func (vm *VM) Version(ctx context.Context) (string, error) { return "schain/0.1.0", nil }

// CreateHandlers returns the VM's HTTP handlers. M0 exposes none (the VM
// contract + commit discipline is the deliverable; the S3 API surface is M1+).
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{}, nil
}

// HealthCheck reports the VM healthy once initialized.
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return chain.HealthResult{Healthy: vm.isInitialized}, nil
}

// SetState is a no-op for M0 (no bootstrap state machine to drive).
func (vm *VM) SetState(ctx context.Context, stateNum uint32) error { return nil }

// deriveBlockHash binds a block's per-replay identity to (height, time)
// deterministically, so every validator computes the same blockHash for the same
// block during ProcessBlock (the chain layer's canonical block id is the hash of
// the serialized bytes, set at build/parse). Mirrors dexvm's deriveBlockHash.
func deriveBlockHash(height uint64, blockTime time.Time) ids.ID {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], height)
	binary.BigEndian.PutUint64(buf[8:16], uint64(blockTime.UnixNano()))
	return ids.ID(sha256.Sum256(buf[:]))
}
