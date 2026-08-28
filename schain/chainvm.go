// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schain

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/version"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"

	"github.com/luxfi/chains/schain/pinning"
	"github.com/luxfi/chains/schain/txs"
)

var (
	_ chain.ChainVM = (*ChainVM)(nil)

	errInvalidBlock     = errors.New("invalid block")
	errBlockNotFound    = errors.New("block not found")
	errVMNotInitialized = errors.New("VM not initialized")

	// errBadHeight rejects a block that does not sit exactly one above its parent.
	errBadHeight = errors.New("schain: block height is not parent height + 1")

	// errTimeRewound rejects a block stamped before its parent. Block time is
	// carried in the bytes the block id commits to and is the chain's only clock;
	// a proposer that could rewind it could rewrite the order of the chain's
	// history for anything that reads it.
	errTimeRewound = errors.New("schain: block timestamp is before its parent's")

	// errTimeAhead rejects a block stamped further ahead of the verifying node
	// than the clock-sync allowance. Block time only ever moves forward, so a
	// block accepted far in the future would hold the chain's clock there.
	errTimeAhead = errors.New("schain: block timestamp is too far in the future")

	genesisBlockID = ids.ID{}
)

// maxFutureSkew is how far ahead of the verifying node's clock a proposer may
// stamp a block — the node's usual clock-sync tolerance.
const maxFutureSkew = 10 * time.Second

// ChainVM wraps the functional storage VM to implement chain.ChainVM — the
// interface the chains manager drives. It owns the in-memory block index,
// mempool, and last-accepted pointers; the inner VM owns state + commit. This is
// the dexvm/chainvm.go boilerplate, stripped of the DEX fee gate and DAG hooks
// the storage VM does not need.
type ChainVM struct {
	inner *VM

	log  log.Logger
	lock sync.RWMutex

	// In-memory block index, and the accepted block at each height. blocks holds
	// the accepted chain plus whatever is still processing; prune releases the
	// processing blocks the engine abandoned, which are otherwise retained one
	// per build, forever.
	blocks  map[ids.ID]*Block
	heights map[uint64]ids.ID

	lastAcceptedID     ids.ID
	lastAcceptedHeight uint64
	preferredID        ids.ID

	// Pending transactions for the next block (the mempool).
	pendingTxs [][]byte

	toEngine chan<- vmcore.Message

	initialized bool

	// blockCtxBuilder resolves the deterministic BlockContext (validator set +
	// proposer + epoch) for a block at the given height. It is the SEAM to the
	// real consensus runtime: Stage 1 lets the test/harness inject a deterministic
	// resolver; the master-cutover stage wires it to
	// runtime.ValidatorState.GetValidatorSet(ctx, pChainHeight, netID) + the
	// block's proposer (see BlockContext doc). When nil, blocks build with the
	// empty context — the M0/no-allocate path, where any AllocateTx fails closed.
	blockCtxBuilder BlockContextBuilder

	// allocateSigner signs the AllocateTxs this node OWNS at BuildBlock with its
	// ML-DSA staking key (the pinned-writer authorization). When nil, allocates are
	// left unsigned and therefore fail closed at Verify — a node that cannot sign
	// cannot get an allocation accepted. Installed only on validating nodes.
	allocateSigner *AllocateSigner
}

// BlockContextBuilder resolves the deterministic consensus inputs (validator set,
// proposer, epoch) the AllocateTx owner gate needs for a block at the given
// height. It MUST be a pure local computation (no network I/O) so block Verify
// stays deterministic. height is the S-Chain block height; the implementation
// maps it to the epoch's pChainHeight and the block's proposer.
type BlockContextBuilder func(ctx context.Context, height uint64) (BlockContext, error)

// SetBlockContextBuilder installs the resolver that supplies the AllocateTx owner
// gate its validator set + proposer identity. Stage 1 wire point; production
// installs the real consensus-runtime-backed resolver here.
func (cvm *ChainVM) SetBlockContextBuilder(b BlockContextBuilder) {
	cvm.lock.Lock()
	defer cvm.lock.Unlock()
	cvm.blockCtxBuilder = b
}

// SetAllocateSigner installs the ML-DSA staking key this node signs its owned
// allocates with at BuildBlock. A node only ever produces VALID allocates for the
// ranges it owns (a signed allocate whose signer is not the HRW owner is rejected
// at Verify on every node), so installing a signer never lets a node write a range
// it does not own — it only lets it authorize the ranges it does.
func (cvm *ChainVM) SetAllocateSigner(s *AllocateSigner) {
	cvm.lock.Lock()
	defer cvm.lock.Unlock()
	cvm.allocateSigner = s
}

// NewChainVM constructs a ChainVM wrapping a fresh inner storage VM.
func NewChainVM(logger log.Logger) *ChainVM {
	return &ChainVM{
		inner:   &VM{},
		log:     logger,
		blocks:  make(map[ids.ID]*Block),
		heights: make(map[uint64]ids.ID),
	}
}

// checkPosition validates a block's place in the chain before any of its
// contents are applied: the parent must be a block this node holds, the height
// must be exactly one above it, and the timestamp must not rewind or run past
// the clock-sync allowance. None of that was checked, so a block could name any
// parent, claim any height and carry any time — and the height it claimed became
// the chain's height and part of every state root the chain then computed.
func (cvm *ChainVM) checkPosition(b *Block) error {
	cvm.lock.RLock()
	parent, ok := cvm.blocks[b.parentID]
	cvm.lock.RUnlock()
	if !ok {
		return fmt.Errorf("%w: parent %s", errBlockNotFound, b.parentID)
	}
	if b.height != parent.height+1 {
		return fmt.Errorf("%w: %d after parent %d", errBadHeight, b.height, parent.height)
	}
	if b.timestamp.Before(parent.timestamp) {
		return errTimeRewound
	}
	// The ceiling is the local clock plus the allowance, but never below the
	// parent: the chain already accepted that time, so reusing it stays legal on
	// a node whose own clock has slipped behind the tip.
	ceiling := cvm.inner.clock.Time().Add(maxFutureSkew)
	if parent.timestamp.After(ceiling) {
		ceiling = parent.timestamp
	}
	if b.timestamp.After(ceiling) {
		return errTimeAhead
	}
	return nil
}

// prune releases every processing block at or below the accepted height. The
// engine issues a block per build and is under no obligation to accept or reject
// each one; a block only ever released on those two paths accumulates without
// limit. Nothing at or below the accepted height can still be accepted, so
// nothing reachable is lost. The caller holds cvm.lock.
func (cvm *ChainVM) prune(acceptedHeight uint64) {
	for id, blk := range cvm.blocks {
		if blk.status != StatusAccepted && blk.height <= acceptedHeight {
			delete(cvm.blocks, id)
		}
	}
}

// Initialize wires the inner VM and seeds the genesis block.
func (cvm *ChainVM) Initialize(ctx context.Context, vmInit vmcore.Init) error {
	cvm.lock.Lock()
	defer cvm.lock.Unlock()

	cvm.toEngine = vmInit.ToEngine

	cvm.inner.log = cvm.log
	if err := cvm.inner.Initialize(ctx, vmInit); err != nil {
		return err
	}

	genesisBlock := &Block{
		vm:        cvm,
		id:        genesisBlockID,
		parentID:  ids.Empty,
		height:    0,
		timestamp: time.Unix(0, 0),
		status:    StatusAccepted,
	}
	cvm.blocks[genesisBlockID] = genesisBlock
	cvm.heights[0] = genesisBlockID
	cvm.lastAcceptedID = genesisBlockID
	cvm.lastAcceptedHeight = 0
	cvm.preferredID = genesisBlockID

	cvm.initialized = true
	if !cvm.log.IsZero() {
		cvm.log.Info("S-Chain ChainVM initialized", "genesisID", genesisBlockID)
	}
	return nil
}

// SubmitTx admits a transaction to the mempool and notifies the engine to build
// a block. This is the canonical user-mempool entry. The bytes are validated
// (parse + Verify) before they touch the pending pool, so a malformed manifest
// never enters a block.
func (cvm *ChainVM) SubmitTx(tx []byte) error {
	parsed, err := parser.Parse(tx)
	if err != nil {
		return err
	}
	if err := parsed.Verify(); err != nil {
		return err
	}

	cvm.lock.Lock()
	cvm.pendingTxs = append(cvm.pendingTxs, tx)
	cvm.lock.Unlock()

	if cvm.toEngine != nil {
		select {
		case cvm.toEngine <- vmcore.Message{Type: vmcore.PendingTxs}:
		default:
		}
	}
	return nil
}

// BuildBlock drains the mempool into a new block on top of the preferred tip.
// The proposer chooses the block time (wall clock, clamped non-decreasing) and
// carries it in the bytes — the consensus-agreement point. The block id is the
// hash of the serialized bytes, so it commits to every drained transaction.
func (cvm *ChainVM) BuildBlock(ctx context.Context) (chain.Block, error) {
	cvm.lock.Lock()
	defer cvm.lock.Unlock()

	if !cvm.initialized {
		return nil, errVMNotInitialized
	}

	parent, ok := cvm.blocks[cvm.preferredID]
	if !ok {
		return nil, fmt.Errorf("preferred block not found: %s", cvm.preferredID)
	}

	newHeight := parent.height + 1
	newTimestamp := cvm.inner.clock.Time()
	if last := cvm.inner.GetLastBlockTime(); newTimestamp.Before(last) {
		newTimestamp = last
	}

	drained := cvm.pendingTxs

	// Resolve the deterministic BlockContext (validator set + proposer + epoch)
	// the AllocateTx owner gate needs. The proposer pins against the SAME frozen
	// set every verifier will reconstruct, so the owner verdict is identical
	// network-wide. With no builder installed the context is empty (M0 path); a
	// block carrying an AllocateTx then fails closed in ProcessBlock.
	blockCtx, err := cvm.resolveBlockContext(ctx, newHeight)
	if err != nil {
		return nil, fmt.Errorf("schain: resolve block context: %w", err)
	}

	// Sign the AllocateTxs this node owns: stamp Epoch/Nonce/Fingerprint from the
	// resolved context and ML-DSA-sign with the installed staking key. This is the
	// emitter side of the pinned-writer authorization — the network call (validator
	// set resolution) happens HERE, outside Verify, so block apply stays pure. A
	// node with no signer leaves allocates unsigned; they then fail closed at Verify
	// (and below, the build itself fails so the unsigned intent is not retried).
	blockTxs, err := cvm.signOwnedAllocates(drained, blockCtx, newHeight)
	if err != nil {
		cvm.pendingTxs = nil
		return nil, fmt.Errorf("schain: sign allocates: %w", err)
	}

	// Proposer build: apply the drained txs to the version layer to obtain the
	// post-apply STATE ROOT, then carry that root in the block header so every
	// validator can recompute and check it (mirror of dexvm BuildBlock ->
	// BuildBlockResult, chainvm.go:258). Select puts in the block exactly the
	// transactions that TOOK EFFECT, so a block this node builds is one it
	// verifies — including when a candidate violates the pinned-writer gate,
	// which used to fail the whole build and take every other queued transaction
	// down with it. The SAME timestamp + block context are fed to every
	// validator's ProcessBlock, so the root and the owner verdict are
	// reproducible network-wide.
	cvm.pendingTxs = nil
	result, err := cvm.inner.Select(newHeight, newTimestamp, blockTxs, blockCtx)
	if err != nil {
		return nil, fmt.Errorf("schain: build block result: %w", err)
	}

	block := &Block{
		vm:        cvm,
		parentID:  cvm.preferredID,
		height:    newHeight,
		timestamp: newTimestamp,
		stateRoot: result.StateRoot,
		txs:       result.Applied,
		blockCtx:  blockCtx,
		status:    StatusProcessing,
	}
	hash := sha256.Sum256(block.Bytes())
	copy(block.id[:], hash[:])
	cvm.blocks[block.id] = block

	if !cvm.log.IsZero() {
		cvm.log.Debug("Built block", "id", block.id, "height", newHeight, "txCount", len(block.txs), "root", result.StateRoot)
	}
	return block, nil
}

// signOwnedAllocates returns a copy of rawTxs with every unsigned AllocateTx
// signed by the installed AllocateSigner (stamping Epoch from the block context,
// Nonce from the block height, and the validator-set Fingerprint). PutManifest txs
// and already-signed allocates pass through untouched. With no signer installed, or
// no validator set to pin against, allocates pass through UNSIGNED — they then fail
// closed in ProcessBlock (an unsigned allocate is unauthorized), which fails the
// build and drains the offending intent. The caller holds cvm.lock.
func (cvm *ChainVM) signOwnedAllocates(rawTxs [][]byte, blockCtx BlockContext, height uint64) ([][]byte, error) {
	if cvm.allocateSigner == nil || len(blockCtx.Members) == 0 {
		return rawTxs, nil
	}
	fingerprint := pinning.EpochFingerprint(blockCtx.Epoch, blockCtx.Members)

	out := make([][]byte, len(rawTxs))
	for i, raw := range rawTxs {
		parsed, perr := parser.Parse(raw)
		if perr != nil {
			return nil, perr
		}
		at, ok := parsed.(*txs.AllocateTx)
		if !ok || at.IsSigned() {
			out[i] = raw
			continue
		}
		signed, serr := cvm.allocateSigner.signAllocate(at, blockCtx.Epoch, height, fingerprint)
		if serr != nil {
			return nil, serr
		}
		out[i] = signed.Bytes()
	}
	return out, nil
}

// resolveBlockContext computes the deterministic BlockContext for a block at
// height. It delegates to the installed BlockContextBuilder (the consensus-runtime
// seam); with no builder it returns the empty context (the M0/no-allocate path).
// The caller holds cvm.lock, so this reads cvm.blockCtxBuilder directly without
// re-locking. The builder MUST be pure/local — no network I/O — so the resolved
// context is identical on the proposer and every verifier.
func (cvm *ChainVM) resolveBlockContext(ctx context.Context, height uint64) (BlockContext, error) {
	if cvm.blockCtxBuilder == nil {
		return BlockContext{}, nil
	}
	return cvm.blockCtxBuilder(ctx, height)
}

// ParseBlock parses a block from bytes, deduplicating against the index.
func (cvm *ChainVM) ParseBlock(ctx context.Context, data []byte) (chain.Block, error) {
	cvm.lock.Lock()
	defer cvm.lock.Unlock()

	block, err := parseBlock(cvm, data)
	if err != nil {
		return nil, err
	}
	if existing, ok := cvm.blocks[block.id]; ok {
		return existing, nil
	}
	// Reconstruct the deterministic BlockContext on the verifying side from the
	// block's height (→ epoch + frozen validator set + proposer). This is the same
	// resolver the proposer used, so every node resolves the SAME owner for an
	// AllocateTx in this block. Without it a parsed AllocateTx block fails closed
	// (errNoValidatorSet) — the safe default if the seam is not yet wired.
	blockCtx, err := cvm.resolveBlockContext(ctx, block.height)
	if err != nil {
		return nil, fmt.Errorf("schain: resolve block context for parsed block: %w", err)
	}
	block.blockCtx = blockCtx
	cvm.blocks[block.id] = block
	return block, nil
}

// GetBlock returns a block by id.
func (cvm *ChainVM) GetBlock(ctx context.Context, blkID ids.ID) (chain.Block, error) {
	cvm.lock.RLock()
	defer cvm.lock.RUnlock()
	block, ok := cvm.blocks[blkID]
	if !ok {
		return nil, errBlockNotFound
	}
	return block, nil
}

// SetPreference sets the tip new blocks build on.
func (cvm *ChainVM) SetPreference(ctx context.Context, blkID ids.ID) error {
	cvm.lock.Lock()
	defer cvm.lock.Unlock()
	if _, ok := cvm.blocks[blkID]; !ok {
		return fmt.Errorf("block not found: %s", blkID)
	}
	cvm.preferredID = blkID
	return nil
}

// LastAccepted returns the last accepted block id.
func (cvm *ChainVM) LastAccepted(ctx context.Context) (ids.ID, error) {
	cvm.lock.RLock()
	defer cvm.lock.RUnlock()
	return cvm.lastAcceptedID, nil
}

// GetBlockIDAtHeight returns the accepted block id at a height. It reads an
// index written when the block was accepted, rather than scanning the block map
// and returning whichever matching entry Go's map iteration reached first.
func (cvm *ChainVM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	cvm.lock.RLock()
	defer cvm.lock.RUnlock()
	id, ok := cvm.heights[height]
	if !ok {
		return ids.Empty, errBlockNotFound
	}
	return id, nil
}

// SetState delegates to the inner VM.
func (cvm *ChainVM) SetState(ctx context.Context, stateNum uint32) error {
	return cvm.inner.SetState(ctx, stateNum)
}

// Shutdown delegates to the inner VM.
func (cvm *ChainVM) Shutdown(ctx context.Context) error { return cvm.inner.Shutdown(ctx) }

// Version delegates to the inner VM.
func (cvm *ChainVM) Version(ctx context.Context) (string, error) { return cvm.inner.Version(ctx) }

// NewHTTPHandler returns the chain's HTTP surface. M0 publishes no routes — the
// VM contract and the commit discipline are the deliverable; the S3 API is M1+ —
// so this is an empty mux rather than a nil handler the node would dereference.
func (cvm *ChainVM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	return http.NewServeMux(), nil
}

// HealthCheck delegates to the inner VM.
func (cvm *ChainVM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	return cvm.inner.HealthCheck(ctx)
}

// Connected is a no-op for M0 (no peer-version tracking needed).
func (cvm *ChainVM) Connected(ctx context.Context, nodeID ids.NodeID, v *version.Application) error {
	return nil
}

// Disconnected is a no-op for M0.
func (cvm *ChainVM) Disconnected(ctx context.Context, nodeID ids.NodeID) error { return nil }

// WaitForEvent blocks until an event should trigger block building. M0 triggers
// builds via SubmitTx -> PendingTxs on toEngine, so this simply parks until the
// context is cancelled (mirror of dexvm/chainvm.go:408).
func (cvm *ChainVM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	<-ctx.Done()
	return vmcore.Message{}, ctx.Err()
}

// GetInnerVM exposes the inner VM for direct reads (e.g. GetManifest).
func (cvm *ChainVM) GetInnerVM() *VM { return cvm.inner }
