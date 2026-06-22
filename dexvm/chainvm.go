// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/rpc/v2"
	rpcjson "github.com/gorilla/rpc/v2/json"
	"github.com/luxfi/chains/dexvm/api"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
)

var (
	_ chain.ChainVM = (*ChainVM)(nil)
	_ vertex.DAGVM  = (*ChainVM)(nil)
)

var (
	errInvalidBlock     = errors.New("invalid block")
	errBlockNotFound    = errors.New("block not found")
	errNoBlocksBuilt    = errors.New("no blocks to build")
	errVMNotInitialized = errors.New("VM not initialized")

	// Genesis block ID (all zeros)
	genesisBlockID = ids.ID{}
)

// ChainVM wraps the functional DEX VM to implement the chain.ChainVM interface
// required for running as an L2 chain plugin.
type ChainVM struct {
	// The inner functional VM
	inner *VM

	// Logger
	log log.Logger

	// Lock for thread safety
	lock sync.RWMutex

	// Block storage
	blocks map[ids.ID]*Block

	// Last accepted block info
	lastAcceptedID     ids.ID
	lastAcceptedHeight uint64

	// Preferred block (tip of the chain we're building on)
	preferredID ids.ID

	// Pending transactions for next block
	pendingTxs [][]byte

	// Block building interval
	blockInterval time.Duration

	// Channel to notify consensus of new blocks
	toEngine chan<- vm.Message

	// Initialization state
	initialized bool

	// Fee policy gating user-submitted tx admission. Set at Init time
	// from init.Runtime.NetworkID. user-tx-accepting -> FlatPolicy at
	// MinTxFeeFloor. Internal (consensus engine -> VM) paths bypass
	// this gate; only SubmitTx consults it. See feegate.go.
	feePolicy fee.Policy
	networkID uint32
}

// NewChainVM creates a new ChainVM that wraps a functional DEX VM
func NewChainVM(logger log.Logger) *ChainVM {
	return &ChainVM{
		inner:         &VM{},
		log:           logger,
		blocks:        make(map[ids.ID]*Block),
		blockInterval: 100 * time.Millisecond, // Default 100ms blocks
	}
}

// Initialize implements the VM interface
func (cvm *ChainVM) Initialize(
	ctx context.Context,
	vmInit vm.Init,
) error {
	cvm.lock.Lock()
	defer cvm.lock.Unlock()

	// Store the message channel
	cvm.toEngine = vmInit.ToEngine

	// Pin fee policy from runtime networkID. D-Chain is user-tx-
	// accepting so we attach the canonical FlatPolicy at MinTxFeeFloor;
	// boot-time Validate (fee.Validate) refuses zero-fee user-facing
	// chains before they ever accept a block.
	if vmInit.Runtime != nil {
		cvm.networkID = vmInit.Runtime.NetworkID
	}
	cvm.feePolicy = newFeePolicy(cvm.networkID)
	if err := fee.Validate(cvm.feePolicy); err != nil {
		return fmt.Errorf("dexvm: fee policy: %w", err)
	}

	// Initialize the inner VM
	if err := cvm.inner.Initialize(
		ctx,
		vmInit,
	); err != nil {
		return err
	}

	// Set logger for inner VM
	cvm.inner.log = cvm.log

	// Create genesis block
	genesisBlock := &Block{
		vm:        cvm,
		id:        genesisBlockID,
		parentID:  ids.Empty,
		height:    0,
		timestamp: time.Unix(0, 0),
		txs:       nil,
		status:    StatusAccepted,
	}
	cvm.blocks[genesisBlockID] = genesisBlock
	cvm.lastAcceptedID = genesisBlockID
	cvm.lastAcceptedHeight = 0
	cvm.preferredID = genesisBlockID

	cvm.initialized = true

	if !cvm.log.IsZero() {
		cvm.log.Info("DEX ChainVM initialized",
			"genesisID", genesisBlockID,
		)
	}

	return nil
}

// SetState implements the VM interface
func (cvm *ChainVM) SetState(ctx context.Context, state uint32) error {
	return cvm.inner.SetState(ctx, state)
}

// Shutdown implements the VM interface
func (cvm *ChainVM) Shutdown(ctx context.Context) error {
	return cvm.inner.Shutdown(ctx)
}

// Version implements the VM interface
func (cvm *ChainVM) Version(ctx context.Context) (string, error) {
	return cvm.inner.Version(ctx)
}

// NewHTTPHandler implements the chain.ChainVM interface
func (cvm *ChainVM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	handlers, err := cvm.inner.CreateHandlers(ctx)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	for path, handler := range handlers {
		if path == "" {
			path = "/"
		}
		mux.Handle(path, handler)
	}
	return mux, nil
}

// CreateHandlers implements the interface expected by the chain manager for HTTP
// registration. This is the NODE path (the rpcchainvm harness serves the ChainVM),
// so unlike the inner VM's read-only CreateHandlers it wires the tx-submission
// surface: the dex service is built against an api.TxSubmitter (the ChainVM, which
// owns the pending pool + the engine channel) so dex.submitTx reaches the mempool.
// The inner VM's CreateHandlers stays read-only (Ping/Status/Relay) for the
// standalone/test path that has no pending pool.
//
// This is the seam the C<->D keeper drives: ImportTx + settling RelayOrderTx are
// submitted here; the proposer relays once and settles the D->C proceeds, which the
// C-side Phase-B ImportSettlement consumes to emit DEXFill.
func (cvm *ChainVM) CreateHandlers(_ context.Context) (map[string]http.Handler, error) {
	server := rpc.NewServer()
	server.RegisterCodec(rpcjson.NewCodec(), "application/json")
	server.RegisterCodec(rpcjson.NewCodec(), "application/json;charset=UTF-8")

	// Build the service against the inner VM (IsBootstrapped/Relay) PLUS the
	// ChainVM as the tx submitter (SubmitTx -> pendingTxs + engine notify).
	service := api.NewServiceWithSubmitter(cvm.inner, cvm)
	if err := server.RegisterService(service, "dex"); err != nil {
		return nil, fmt.Errorf("failed to register DEX service: %w", err)
	}
	return map[string]http.Handler{"": server}, nil
}

// HealthCheck implements the VM interface
func (cvm *ChainVM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	return cvm.inner.HealthCheck(ctx)
}

// Connected implements the chain.ChainVM interface
func (cvm *ChainVM) Connected(ctx context.Context, nodeID ids.NodeID, v *chain.VersionInfo) error {
	if v == nil {
		return nil
	}
	// chain.VersionInfo is an alias for version.Application, so we can pass it directly
	return cvm.inner.Connected(ctx, nodeID, v)
}

// Disconnected implements the VM interface
func (cvm *ChainVM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return cvm.inner.Disconnected(ctx, nodeID)
}

// Gossip implements the VM interface
func (cvm *ChainVM) Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	return cvm.inner.Gossip(ctx, nodeID, msg)
}

// Request implements the VM interface
func (cvm *ChainVM) Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, request []byte) error {
	return cvm.inner.Request(ctx, nodeID, requestID, deadline, request)
}

// Response implements the VM interface
func (cvm *ChainVM) Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	return cvm.inner.Response(ctx, nodeID, requestID, response)
}

// BuildBlock implements the chain.ChainVM interface. It builds a new block from
// pending transactions AND, as the block PROPOSER, performs the network-wide-ONCE
// d-chain relay (VM.BuildBlockResult -> obtainFills), carrying the confirmed fills
// in the block bytes so every validator settles from them without relaying (RED
// finding #9). This is the ONLY chain entry point that triggers a d-chain relay;
// Verify and Accept never do.
//
// The proposer chooses the block time here (wall clock, clamped non-decreasing)
// and carries it in the bytes — the consensus-agreement point. The block id is the
// hash of the serialized bytes (header + txs + carried fills), so the id commits to
// the carried fills (a peer cannot swap fills while keeping the same id).
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
	// Proposer-chosen block time, clamped non-decreasing vs the last processed
	// block so time never goes backwards on a re-proposal / clock skew. The SAME
	// value is carried in the bytes and fed to ProcessBlock by every validator.
	newTimestamp := cvm.inner.clock.Time()
	if last := cvm.inner.GetLastBlockTime(); newTimestamp.Before(last) {
		newTimestamp = last
	}

	txs := cvm.pendingTxs

	// Proposer build: plan + relay-once + obtain the carried fills. obtainFills is
	// the single d-chain relay for this block, network-wide.
	result, err := cvm.inner.BuildBlockResult(ctx, newHeight, newTimestamp, txs)
	if err != nil {
		return nil, fmt.Errorf("dexvm: build block result: %w", err)
	}

	block := &Block{
		vm:           cvm,
		parentID:     cvm.preferredID,
		height:       newHeight,
		timestamp:    newTimestamp,
		txs:          txs,
		carriedFills: result.carriedFills,
		fillSig:      result.fillSig,
		result:       result,
		status:       StatusProcessing,
	}
	// Block id = hash of the serialized bytes (commits to the carried fills).
	hash := sha256.Sum256(block.Bytes())
	copy(block.id[:], hash[:])

	cvm.pendingTxs = nil
	cvm.blocks[block.id] = block

	if !cvm.log.IsZero() {
		cvm.log.Debug("Built block",
			"id", block.id,
			"height", newHeight,
			"txCount", len(block.txs),
			"carriedFillEntries", len(block.carriedFills),
		)
	}

	return block, nil
}

// ParseBlock implements the chain.ChainVM interface.
// It parses a block from bytes.
func (cvm *ChainVM) ParseBlock(ctx context.Context, data []byte) (chain.Block, error) {
	cvm.lock.Lock()
	defer cvm.lock.Unlock()

	block, err := parseBlock(cvm, data)
	if err != nil {
		return nil, err
	}

	// Check if we already have this block
	if existingBlock, ok := cvm.blocks[block.id]; ok {
		return existingBlock, nil
	}

	// Store the new block
	cvm.blocks[block.id] = block

	return block, nil
}

// GetBlock implements the chain.ChainVM interface.
// It returns a block by its ID.
func (cvm *ChainVM) GetBlock(ctx context.Context, blkID ids.ID) (chain.Block, error) {
	cvm.lock.RLock()
	defer cvm.lock.RUnlock()

	block, ok := cvm.blocks[blkID]
	if !ok {
		return nil, errBlockNotFound
	}

	return block, nil
}

// SetPreference implements the chain.ChainVM interface.
// It sets the preferred block for building new blocks.
func (cvm *ChainVM) SetPreference(ctx context.Context, blkID ids.ID) error {
	cvm.lock.Lock()
	defer cvm.lock.Unlock()

	if _, ok := cvm.blocks[blkID]; !ok {
		return fmt.Errorf("block not found: %s", blkID)
	}

	cvm.preferredID = blkID

	if !cvm.log.IsZero() {
		cvm.log.Debug("Set preference", "blockID", blkID)
	}

	return nil
}

// LastAccepted implements the chain.ChainVM interface.
// It returns the ID of the last accepted chain.
func (cvm *ChainVM) LastAccepted(ctx context.Context) (ids.ID, error) {
	cvm.lock.RLock()
	defer cvm.lock.RUnlock()

	return cvm.lastAcceptedID, nil
}

// GetBlockIDAtHeight returns the block ID at the given height
func (cvm *ChainVM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	cvm.lock.RLock()
	defer cvm.lock.RUnlock()

	for id, block := range cvm.blocks {
		if block.height == height && block.status == StatusAccepted {
			return id, nil
		}
	}

	return ids.Empty, errBlockNotFound
}

// SubmitTx adds a transaction to the pending pool. This is the canonical
// user-mempool entry on D-Chain — every public submission funnels through
// here. The FeePolicy gate refuses zero-fee tx before the bytes touch
// pendingTxs.
//
// Internal callers (consensus engine -> VM, replay) feed pendingTxs
// directly via BuildBlock; they do NOT route through SubmitTx, so the
// fee gate stays out of the consensus-internal path.
func (cvm *ChainVM) SubmitTx(tx []byte) error {
	if err := cvm.gateUserTxBytes(tx); err != nil {
		return err
	}

	cvm.lock.Lock()
	defer cvm.lock.Unlock()

	cvm.pendingTxs = append(cvm.pendingTxs, tx)

	// Notify consensus that we have pending work
	if cvm.toEngine != nil {
		select {
		case cvm.toEngine <- vm.Message{Type: vm.PendingTxs}:
		default:
			// Channel full, skip notification
		}
	}

	return nil
}

// GetInnerVM returns the inner proxy VM for direct access.
func (cvm *ChainVM) GetInnerVM() *VM {
	return cvm.inner
}

// WaitForEvent implements the chain.ChainVM interface.
// It blocks until an event occurs that should trigger block building.
func (cvm *ChainVM) WaitForEvent(ctx context.Context) (vm.Message, error) {
	// For now, return empty message - block building is triggered via SubmitTx
	// and the PendingTxs message is sent to toEngine
	<-ctx.Done()
	return vm.Message{}, ctx.Err()
}
