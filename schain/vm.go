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

	"github.com/luxfi/chains/schain/pinning"
	"github.com/luxfi/chains/schain/state"
	"github.com/luxfi/chains/schain/txs"
)

var (
	errShutdown = errors.New("VM is shutting down")

	// errNonOwnerAllocate is returned by ProcessBlock/Verify when a block carries
	// an AllocateTx for a range whose HRW owner (under the block's frozen
	// validator set + epoch) is NOT the block's proposer. This is the leaderless
	// pinned-writer safety property: only the one owner of a range may emit an
	// allocation, so two writers for the same range — and therefore a double
	// allocation — are impossible by construction.
	errNonOwnerAllocate = errors.New("allocate: proposer is not the range owner")

	// errNoValidatorSet is returned when a block carries an AllocateTx but the
	// block context supplies no validator set to resolve ownership against.
	// Fail closed: with no set, nobody can be proven the owner, so no allocation
	// may commit (never default to "I am the owner" — see pinning.TestEmptySet).
	errNoValidatorSet = errors.New("allocate: empty validator set in block context")

	parser = &txs.TxParser{}
)

// BlockContext carries the deterministic consensus inputs an AllocateTx's owner
// gate needs: the validator set frozen at the block's epoch (block.pChainHeight)
// and the identity of the block's proposer. Both are pure inputs — every node
// verifying the block resolves the SAME owner against the SAME frozen set, so the
// gate is evaluated inside deterministic block apply with ZERO network I/O
// (the purity premise the whole model rests on — DESIGN_pinned_writer.md §6.4).
//
// WIRE SEAM (master-cutover stage): in Stage 1 BlockContext is an explicit
// parameter threaded from the test harness / proposer. In production it must be
// populated from the REAL consensus runtime, ONCE, at the points the validator
// set + proposer are cleanly available WITHOUT a network round-trip inside
// Verify:
//
//   - Members:  pinning.Member projection of
//     vm.consensusRuntime.ValidatorState.GetValidatorSet(ctx, block.pChainHeight,
//     netID) — id+weight only. This MUST be a LOCAL lookup against already-synced
//     P-Chain state at the historical height; if it can block on the network,
//     resolution moves OUT of Verify (pin in BuildBlock, carry owner+fingerprint
//     in the tx, Verify only re-checks the fingerprint). See §6.4 fallback.
//   - Proposer: the block's proposer NodeID, from the consensus block header
//     (block.pChainHeight's proposer / the engine's BuildBlock identity), NOT
//     vm.consensusRuntime.NodeID — that is "me", which is only the proposer on
//     the building node, not on a verifying node.
//   - Epoch:    block.pChainHeight, the height Members was frozen at, so a peer
//     can recompute pinning.EpochFingerprint and reject an epoch-skewed pin.
//
// An empty BlockContext (nil Members) is the M0/no-allocate path: a block with
// no AllocateTx is unaffected, so existing PutManifest blocks need no context.
type BlockContext struct {
	// Members is the validator set frozen at Epoch, projected to (NodeID, Weight).
	Members []pinning.Member
	// Proposer is the NodeID that built this block — the candidate range owner.
	Proposer ids.NodeID
	// Epoch is the P-Chain height Members was frozen at (block.pChainHeight).
	Epoch uint64
}

// BlockResult is the deterministic result of processing one block. For the
// storage VM the per-block output is simply the height/time/blockHash binding —
// the manifest mutations are staged directly into the version layer by
// ProcessBlock and committed at Accept. There is no cross-chain leg to carry.
type BlockResult struct {
	BlockHeight uint64
	Timestamp   time.Time
	blockHash   ids.ID

	// StateRoot is the deterministic commitment over the manifest keyspace AFTER
	// this block's writes are staged, folded with the block's consensus binding
	// (blockHash + height). It travels in the block header and Block.Verify
	// recomputes it on every validator and rejects a block whose claimed root
	// does not match — the multi-validator safety gate M0 omitted.
	StateRoot ids.ID
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
func (vm *VM) ProcessBlock(ctx context.Context, blockHeight uint64, blockTime time.Time, blockTxs [][]byte, blockCtx BlockContext) (*BlockResult, error) {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.shutdown {
		return nil, errShutdown
	}

	// Apply over COMMITTED state, not accumulated staging. A block is processed
	// twice on the proposer — once in BuildBlock (to compute the claimed root) and
	// again in Block.Verify — and both must produce the identical post-state. For
	// an idempotent write (PutManifest: same key→same value) re-application is
	// harmless, but the allocator is a READ-MODIFY-WRITE: re-applying over the
	// prior staging would double-advance the counter (base 0→Count, then Count→2·
	// Count) and the two roots would diverge. Aborting the versiondb's in-memory
	// layer first discards any uncommitted staging so every ProcessBlock starts
	// from the last-accepted state — making the apply a pure function of COMMITTED
	// state + this block's txs, idempotent for every tx type. (Abort never touches
	// the durable base; CommitBatch at Accept is still the only durability point.)
	if vm.db != nil {
		vm.db.Abort()
	}

	blockHash := deriveBlockHash(blockHeight, blockTime)
	result := &BlockResult{
		BlockHeight: blockHeight,
		Timestamp:   blockTime,
		blockHash:   blockHash,
	}

	for i, txBytes := range blockTxs {
		if err := vm.processTx(txBytes, blockCtx); err != nil {
			// Two failure classes, two dispositions:
			//
			//   - A SAFETY-GATE violation (a non-owner AllocateTx, or an allocate
			//     with no validator set to prove ownership) FAILS THE WHOLE BLOCK.
			//     Letting it through as a skipped tx would silently admit a block a
			//     malicious proposer built to write a range it does not own — the
			//     exact double-write the pinned writer forbids. The block must be
			//     rejected so no validator accepts it.
			//   - Any OTHER per-tx failure (a malformed/invalid manifest) does not
			//     fail the block: it simply stages no write, mirroring dexvm's
			//     per-tx-failure-continues discipline (dexvm/vm.go:562).
			if errors.Is(err, errNonOwnerAllocate) || errors.Is(err, errNoValidatorSet) {
				return nil, err
			}
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

	// Commit the post-apply manifest state into the block's StateRoot. The writes
	// are already staged in the versiondb in-memory layer, so the walk sees this
	// block's mutations merged over the durable base — every validator that
	// applied the identical txs computes the identical root (mirror of
	// dexvm/vm.go:584). Block.Verify compares this against the block's claimed
	// root and rejects a mismatch.
	root, err := vm.computeStateRoot(blockHash)
	if err != nil {
		return nil, err
	}
	result.StateRoot = root

	if !vm.log.IsZero() {
		vm.log.Debug("S-Chain block processed", "height", blockHeight, "txs", len(blockTxs), "root", root)
	}
	return result, nil
}

// computeStateRoot folds the block's consensus binding (blockHash + height) with
// the committed manifest state (state.Root) into the block's StateRoot. The
// blockHash/height fold makes the root unique per block position; the manifest
// fold makes it a FAITHFUL commitment to the object state — two nodes that
// genuinely diverge on any (bucket,object) manifest produce different roots, so
// a matching blockHash alone can no longer forge a matching root. This is the
// storage-VM analog of dexvm/vm.go:1260, narrowed to the manifest keyspace (no
// cross-chain atomic legs to fold). It errors only if the state walk fails (a
// corrupt/closed DB), which callers treat as a block-processing failure.
func (vm *VM) computeStateRoot(blockHash ids.ID) (ids.ID, error) {
	h := sha256.New()

	h.Write(blockHash[:])
	var heightBuf [8]byte
	binary.BigEndian.PutUint64(heightBuf[:], vm.currentBlockHeight)
	h.Write(heightBuf[:])

	manifestRoot, err := vm.state.Root()
	if err != nil {
		return ids.Empty, fmt.Errorf("compute state root: %w", err)
	}
	h.Write(manifestRoot[:])

	return ids.ID(h.Sum(nil)), nil
}

// processTx parses one transaction and applies its mutation to the version
// layer. The S-Chain has two mutations: PutManifest (M0) and Allocate (Stage 1).
func (vm *VM) processTx(txBytes []byte, blockCtx BlockContext) error {
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
	case *txs.AllocateTx:
		return vm.applyAllocate(t, blockCtx)
	default:
		return txs.ErrInvalidTxType
	}
}

// applyAllocate deterministically reserves tx.Count ids in the per-range counter
// alloc/<tx.Range>, gated on the block proposer being the HRW OWNER of the range.
// It mirrors PutManifest's discipline exactly: version-layer only, NO I/O, pure
// function of (committed state, block context) — so every validator that applies
// the same tx against the same frozen validator set derives the IDENTICAL id
// range and the IDENTICAL post-state, and the owner gate resolves to the same
// verdict on every node.
//
// The owner gate is the leaderless-pinned-writer enforcement: a block may carry
// an AllocateTx for range R ONLY if its proposer is pinning.Owner(R, V(epoch)).
// A non-owner allocate is rejected (errNonOwnerAllocate), failing the block — so
// the same range can never have two writers, and the same id can never be
// allocated twice. With no validator set the gate fails closed (errNoValidatorSet):
// ownership cannot be proven, so nothing may be written (never assume self-owner).
//
// The reserved id range is [base, base+Count) where base is the counter's
// committed value before this tx — a pure function of prior committed state, so
// the ids are reproduced identically on every node and continue monotonically
// across blocks AND across owner re-pin (the counter is committed VM state, not
// owner-local memory — DESIGN §6.5).
func (vm *VM) applyAllocate(tx *txs.AllocateTx, blockCtx BlockContext) error {
	// Owner gate. Fail closed when the set is empty: with no validators nobody can
	// be proven the owner (pinning.Owner returns false on an empty set), so we must
	// refuse rather than silently treat the proposer as owner.
	if len(blockCtx.Members) == 0 {
		return errNoValidatorSet
	}
	rangeKey := []byte(tx.Range)
	if !pinning.IsOwner(rangeKey, blockCtx.Proposer, blockCtx.Members) {
		return errNonOwnerAllocate
	}

	base, err := vm.state.GetAlloc(tx.Range)
	if err != nil {
		return fmt.Errorf("allocate: read counter for range %q: %w", tx.Range, err)
	}
	next := base + uint64(tx.Count)
	if next < base {
		// uint64 wraparound — the range has exhausted its 2^64 id space. Refuse
		// rather than reissue ids from 0 (which would violate uniqueness). In
		// practice unreachable, but a silent wrap would be a correctness hole.
		return fmt.Errorf("allocate: range %q counter overflow", tx.Range)
	}
	if err := vm.state.SetAlloc(tx.Range, next); err != nil {
		return fmt.Errorf("allocate: stage counter for range %q: %w", tx.Range, err)
	}
	if !vm.log.IsZero() {
		vm.log.Debug("S-Chain allocate", "range", tx.Range, "base", base, "count", tx.Count, "next", next)
	}
	return nil
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
