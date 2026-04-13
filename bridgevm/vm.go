// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/luxfi/vm/chain"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/version"
	"github.com/luxfi/runtime"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/cmp/config"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/warp"
)

var (
	_ chain.ChainVM = (*VM)(nil)

	Version = &version.Semantic{
		Major: 1,
		Minor: 0,
		Patch: 0,
	}

	errNotImplemented = errors.New("not implemented")
)

// Silence unused variable warning
var _ = errNotImplemented

// BridgeConfig contains VM configuration
type BridgeConfig struct {
	// MPC configuration for secure cross-chain operations
	MPCThreshold    int `json:"mpcThreshold"`    // t: Threshold (t+1 parties needed)
	MPCTotalParties int `json:"mpcTotalParties"` // n: Total number of MPC nodes

	// Bridge parameters
	MinConfirmations uint32 `json:"minConfirmations"` // Confirmations required before bridging
	BridgeFee        uint64 `json:"bridgeFee"`        // Fee in LUX for bridge operations

	// Supported chains
	SupportedChains []string `json:"supportedChains"` // Chain IDs that can be bridged

	// Security settings
	MaxBridgeAmount      uint64 `json:"maxBridgeAmount"`      // Maximum amount per bridge transaction
	DailyBridgeLimit     uint64 `json:"dailyBridgeLimit"`     // Daily limit for bridge operations
	RequireValidatorBond uint64 `json:"requireValidatorBond"` // 1M LUX bond required (slashable, NOT staked)

	// LP-333: Opt-in Signer Set Management
	MaxSigners     int     `json:"maxSigners"`     // Maximum signers before set is frozen (default: 100)
	ThresholdRatio float64 `json:"thresholdRatio"` // Threshold as ratio of signers (default: 0.67 = 2/3)
}

// SignerSet tracks the current MPC signer set (LP-333)
// First 100 validators opt-in without reshare. Reshare ONLY on slot replacement.
type SignerSet struct {
	Signers      []*SignerInfo `json:"signers"`      // Active signers (max 100)
	Waitlist     []ids.NodeID  `json:"waitlist"`     // Validators waiting for a slot
	CurrentEpoch uint64        `json:"currentEpoch"` // Increments ONLY on reshare (slot replacement)
	SetFrozen    bool          `json:"setFrozen"`    // True when len(Signers) >= MaxSigners
	ThresholdT   int           `json:"thresholdT"`   // Current t value (T+1 required to sign)
	PublicKey    []byte        `json:"publicKey"`    // Combined threshold public key
}

// SignerInfo contains information about a signer in the set
type SignerInfo struct {
	NodeID     ids.NodeID `json:"nodeId"`
	PartyID    party.ID   `json:"partyId"`
	BondAmount uint64     `json:"bondAmount"` // 1M LUX bond (slashable, NOT staked)
	MPCPubKey  []byte     `json:"mpcPubKey"`
	Active     bool       `json:"active"`
	JoinedAt   time.Time  `json:"joinedAt"`
	SlotIndex  int        `json:"slotIndex"`
	Slashed    bool       `json:"slashed"`    // True if this signer has been slashed
	SlashCount int        `json:"slashCount"` // Number of times slashed
}

// RegisterValidatorInput is the input for registering as a bridge signer
type RegisterValidatorInput struct {
	NodeID     string `json:"nodeId"`
	BondAmount string `json:"bondAmount,omitempty"` // 1M LUX bond (slashable)
	MPCPubKey  string `json:"mpcPubKey,omitempty"`
}

// RegisterValidatorResult is the result of registering as a bridge signer
type RegisterValidatorResult struct {
	Success        bool   `json:"success"`
	NodeID         string `json:"nodeId"`
	Registered     bool   `json:"registered"`
	Waitlisted     bool   `json:"waitlisted"`
	SignerIndex    int    `json:"signerIndex"`
	WaitlistIndex  int    `json:"waitlistIndex,omitempty"`
	TotalSigners   int    `json:"totalSigners"`
	Threshold      int    `json:"threshold"`
	ReshareNeeded  bool   `json:"reshareNeeded"` // Always false for opt-in (LP-333)
	CurrentEpoch   uint64 `json:"currentEpoch"`
	SetFrozen      bool   `json:"setFrozen"`
	RemainingSlots int    `json:"remainingSlots"`
	Message        string `json:"message"`
}

// SignerSetInfo is the result of getting signer set information
type SignerSetInfo struct {
	TotalSigners   int           `json:"totalSigners"`
	Threshold      int           `json:"threshold"`
	MaxSigners     int           `json:"maxSigners"`
	CurrentEpoch   uint64        `json:"currentEpoch"`
	SetFrozen      bool          `json:"setFrozen"`
	RemainingSlots int           `json:"remainingSlots"`
	WaitlistSize   int           `json:"waitlistSize"`
	Signers        []*SignerInfo `json:"signers"`
	PublicKey      string        `json:"publicKey,omitempty"`
}

// SignerReplacementResult is the result of replacing a failed signer
type SignerReplacementResult struct {
	Success           bool   `json:"success"`
	RemovedNodeID     string `json:"removedNodeId,omitempty"`
	ReplacementNodeID string `json:"replacementNodeId,omitempty"`
	ReshareSession    string `json:"reshareSession,omitempty"`
	NewEpoch          uint64 `json:"newEpoch"`
	ActiveSigners     int    `json:"activeSigners"`
	Threshold         int    `json:"threshold"`
	Message           string `json:"message"`
}

// CrossChainMPCRequest represents a cross-chain request to ThresholdVM for MPC operations
type CrossChainMPCRequest struct {
	Type          MPCRequestType `json:"type"`
	SessionID     string         `json:"sessionId"`
	Epoch         uint64         `json:"epoch"`
	OldPartyIDs   []party.ID     `json:"oldPartyIds"`
	NewPartyIDs   []party.ID     `json:"newPartyIds"`
	Threshold     int            `json:"threshold"`
	SourceChainID []byte         `json:"sourceChainId"`
	Timestamp     int64          `json:"timestamp"`
}

// MPCRequestType defines the type of MPC cross-chain request
type MPCRequestType uint8

const (
	// MPCRequestReshare triggers a key reshare protocol
	MPCRequestReshare MPCRequestType = iota
	// MPCRequestSign triggers a threshold signing operation
	MPCRequestSign
	// MPCRequestRefresh triggers a proactive key refresh
	MPCRequestRefresh
)

// VM implements the Bridge VM for cross-chain interoperability
type VM struct {
	rt       *runtime.Runtime
	db       database.Database
	config   BridgeConfig
	toEngine chan<- vmcore.Message
	log      log.Logger

	// MPC components using threshold protocol
	mpcKeyManager    *MPCKeyManager              // Threshold key management
	mpcCoordinator   *MPCCoordinator             // Signing coordination
	bridgeSigner     *BridgeSigner               // Bridge message signing
	deliverySigner   *DeliveryConfirmationSigner // Delivery confirmation signing
	messageValidator *BridgeMessageValidator     // Message validation

	// Deprecated: Legacy MPC fields (kept for reference)
	mpcConfig   *config.Config // CMP config for this party (after keygen)
	mpcPartyID  party.ID       // This party's ID in MPC protocol
	mpcPartyIDs []party.ID     // All party IDs in the MPC group
	mpcPool     *pool.Pool     // Worker pool for MPC operations

	// LP-333: Signer Set Management (opt-in model)
	signerSet *SignerSet // Active signer set with opt-in management

	// Bridge state
	pendingBridges map[ids.ID]*BridgeRequest
	bridgeRegistry *BridgeRegistry

	// Chain connectivity
	chainClients map[string]ChainClient

	// Block management
	preferred      ids.ID
	lastAcceptedID ids.ID
	pendingBlocks  map[ids.ID]*Block

	mu sync.RWMutex
}

// BridgeRequest represents a cross-chain bridge request
type BridgeRequest struct {
	ID            ids.ID    `json:"id"`
	SourceChain   string    `json:"sourceChain"`
	DestChain     string    `json:"destChain"`
	Asset         ids.ID    `json:"asset"`
	Amount        uint64    `json:"amount"`
	Recipient     []byte    `json:"recipient"`
	SourceTxID    ids.ID    `json:"sourceTxId"`
	Confirmations uint32    `json:"confirmations"`
	Status        string    `json:"status"` // pending, signing, completed, failed
	MPCSignatures [][]byte  `json:"mpcSignatures"`
	CreatedAt     time.Time `json:"createdAt"`
}

// ChainClient interface for interacting with different chains
type ChainClient interface {
	GetTransaction(ctx context.Context, txID ids.ID) (interface{}, error)
	GetConfirmations(ctx context.Context, txID ids.ID) (uint32, error)
	SendTransaction(ctx context.Context, tx interface{}) (ids.ID, error)
	ValidateAddress(address []byte) error
}

// BridgeRegistry tracks bridge operations and validators
type BridgeRegistry struct {
	Validators       map[ids.NodeID]*BridgeValidator
	CompletedBridges map[ids.ID]*CompletedBridge
	DailyVolume      map[string]uint64 // chainID -> volume
	mu               sync.RWMutex
}

// BridgeValidator represents a bridge validator node
type BridgeValidator struct {
	NodeID       ids.NodeID
	StakeAmount  uint64
	MPCPublicKey []byte
	Active       bool
	TotalBridged uint64
	SuccessRate  float64
}

// CompletedBridge represents a completed bridge operation
type CompletedBridge struct {
	RequestID    ids.ID
	SourceTxID   ids.ID
	DestTxID     ids.ID
	CompletedAt  time.Time
	MPCSignature []byte
}

// Initialize implements the chain.ChainVM interface
func (vm *VM) Initialize(
	ctx context.Context,
	vmInit vmcore.Init,
) error {
	// Convert chain runtime to Runtime.
	vm.rt = vmInit.Runtime
	vm.db = vmInit.DB
	vm.toEngine = vmInit.ToEngine

	if logger, ok := vm.rt.Log.(log.Logger); ok {
		vm.log = logger
	} else {
		return errors.New("invalid logger type")
	}

	vm.pendingBlocks = make(map[ids.ID]*Block)
	vm.pendingBridges = make(map[ids.ID]*BridgeRequest)
	vm.chainClients = make(map[string]ChainClient)

	// Parse configuration (use JSON like other VMs)
	if len(vmInit.Config) > 0 {
		if err := json.Unmarshal(vmInit.Config, &vm.config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	}

	// Set LP-333 defaults for signer set management
	if vm.config.MaxSigners == 0 {
		vm.config.MaxSigners = 100 // First 100 validators opt-in, then set freezes
	}
	if vm.config.ThresholdRatio == 0 {
		vm.config.ThresholdRatio = 0.67 // 2/3 threshold for BFT safety
	}
	if vm.config.RequireValidatorBond == 0 {
		vm.config.RequireValidatorBond = 1_000_000 * 1e9 // Default: 1M LUX bond
	}

	// Validate configuration - Bridge validators require 1M LUX BOND (slashable, not stake)
	if vm.config.RequireValidatorBond < 1_000_000*1e9 { // 1M LUX bond
		return errors.New("B-chain requires 1M LUX bond (slashable)")
	}

	// Initialize LP-333 signer set (opt-in model)
	vm.signerSet = &SignerSet{
		Signers:      make([]*SignerInfo, 0, vm.config.MaxSigners),
		Waitlist:     make([]ids.NodeID, 0),
		CurrentEpoch: 0,
		SetFrozen:    false,
		ThresholdT:   0,
	}

	// Initialize MPC components using threshold protocol
	// Party ID is derived from node ID
	vm.mpcPartyID = party.ID(vm.rt.NodeID.String())

	// Create worker pool for MPC operations (8 workers)
	vm.mpcPool = pool.NewPool(8)

	// Note: mpcConfig and mpcPartyIDs will be populated during keygen
	// which happens when validators join the bridge network

	// Initialize new MPC key manager
	keyManager, err := NewMPCKeyManager(vm.log)
	if err != nil {
		return fmt.Errorf("failed to create MPC key manager: %w", err)
	}
	vm.mpcKeyManager = keyManager

	// Initialize MPC coordinator
	vm.mpcCoordinator = NewMPCCoordinator(vm.mpcKeyManager, vm.log)

	// Initialize bridge signer
	vm.bridgeSigner = NewBridgeSigner(vm.mpcKeyManager, vm.mpcCoordinator, vm.log)

	// Initialize delivery confirmation signer
	vm.deliverySigner = NewDeliveryConfirmationSigner(vm.mpcKeyManager, vm.mpcCoordinator, vm.log)

	// Initialize message validator
	vm.messageValidator = NewBridgeMessageValidator(
		vm.bridgeSigner,
		vm.deliverySigner,
		vm.config.MinConfirmations,
		true, // require delivery confirmations
		vm.log,
	)

	// Initialize bridge registry
	vm.bridgeRegistry = &BridgeRegistry{
		Validators:       make(map[ids.NodeID]*BridgeValidator),
		CompletedBridges: make(map[ids.ID]*CompletedBridge),
		DailyVolume:      make(map[string]uint64),
	}

	// Initialize chain clients for supported chains
	for _, chainID := range vm.config.SupportedChains {
		// Initialize appropriate client based on chain type
		// This would be implemented based on specific chain requirements
		vm.log.Info("initializing chain client",
			log.String("chainID", chainID),
		)
	}

	// Parse genesis - use JSON for simple genesis configuration
	genesis := &Genesis{}
	if len(vmInit.Genesis) > 0 {
		if err := json.Unmarshal(vmInit.Genesis, genesis); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}

	// Create genesis block
	genesisBlock := &Block{
		BlockHeight:    0,
		BlockTimestamp: genesis.Timestamp,
		ParentID_:      ids.Empty,
		BridgeRequests: []*BridgeRequest{},
		vm:             vm,
	}

	genesisBlock.ID_ = genesisBlock.computeID()
	vm.lastAcceptedID = genesisBlock.ID()

	return vm.putBlock(genesisBlock)
}

// BuildBlock implements the chain.ChainVM interface
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Check if we have pending bridge requests
	if len(vm.pendingBridges) == 0 {
		return nil, errors.New("no pending bridge requests")
	}

	// Get parent block
	parentID := vm.preferred
	if parentID == ids.Empty {
		parentID = vm.lastAcceptedID
	}

	parent, err := vm.getBlock(parentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get parent block: %w", err)
	}

	// Collect bridge requests that are ready
	var requests []*BridgeRequest
	for _, req := range vm.pendingBridges {
		// Check if request has enough confirmations
		if req.Confirmations >= vm.config.MinConfirmations {
			requests = append(requests, req)
		}

		// Limit block size
		if len(requests) >= 100 {
			break
		}
	}

	if len(requests) == 0 {
		return nil, errors.New("no ready bridge requests")
	}

	// Create new block
	blk := &Block{
		ParentID_:      parentID,
		BlockHeight:    parent.Height() + 1,
		BlockTimestamp: time.Now().Unix(),
		BridgeRequests: requests,
		vm:             vm,
	}

	blk.ID_ = blk.computeID()

	// Store pending block
	vm.pendingBlocks[blk.ID()] = blk

	vm.log.Info("built bridge block",
		log.Stringer("blockID", blk.ID()),
		log.Int("numRequests", len(requests)),
	)

	return blk, nil
}

// GetBlock implements the chain.ChainVM interface
func (vm *VM) GetBlock(ctx context.Context, id ids.ID) (chain.Block, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	// Check pending blocks first (nil-safe for early calls before initialization)
	if vm.pendingBlocks != nil {
		if blk, exists := vm.pendingBlocks[id]; exists {
			return blk, nil
		}
	}

	return vm.getBlock(id)
}

// ParseBlock implements the chain.ChainVM interface
func (vm *VM) ParseBlock(ctx context.Context, bytes []byte) (chain.Block, error) {
	blk := &Block{vm: vm}
	if _, err := Codec.Unmarshal(bytes, blk); err != nil {
		return nil, err
	}

	blk.ID_ = blk.computeID()
	return blk, nil
}

// SetPreference implements the chain.ChainVM interface
func (vm *VM) SetPreference(ctx context.Context, id ids.ID) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	vm.preferred = id
	return nil
}

// LastAccepted implements the chain.ChainVM interface
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	return vm.lastAcceptedID, nil
}

// CreateHandlers implements the common.VM interface
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	handlers := map[string]http.Handler{
		"/bridge":     http.HandlerFunc(vm.handleBridgeRequest),
		"/status":     http.HandlerFunc(vm.handleStatus),
		"/validators": http.HandlerFunc(vm.handleValidators),
	}
	return handlers, nil
}

// HealthCheck implements the common.VM interface
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	return chain.HealthResult{
		Healthy: true,
		Details: map[string]string{"status": "healthy"},
	}, nil
}

// Shutdown implements the common.VM interface
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Clean up resources
	return nil
}

// CreateStaticHandlers implements the common.VM interface
func (vm *VM) CreateStaticHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return nil, nil
}

// Connected implements the common.VM interface
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *chain.VersionInfo) error {
	return nil
}

// Disconnected implements the common.VM interface
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return nil
}

// Request implements the common.VM interface
func (vm *VM) Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, request []byte) error {
	// Bridge VMs may use this for cross-chain communication
	return nil
}

// Response implements the common.VM interface
func (vm *VM) Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	return nil
}

// RequestFailed implements the common.VM interface
func (vm *VM) RequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, appErr *warp.Error) error {
	return nil
}

// Gossip implements the common.VM interface
func (vm *VM) Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	return nil
}

// Version implements the common.VM interface
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version.String(), nil
}

// CrossChainRequest implements the common.VM interface
func (vm *VM) CrossChainRequest(ctx context.Context, chainID ids.ID, requestID uint32, deadline time.Time, request []byte) error {
	// Bridge VMs handle cross-chain requests
	return nil
}

// CrossChainResponse implements the common.VM interface
func (vm *VM) CrossChainResponse(ctx context.Context, chainID ids.ID, requestID uint32, response []byte) error {
	return nil
}

// CrossChainRequestFailed implements the common.VM interface
func (vm *VM) CrossChainRequestFailed(ctx context.Context, chainID ids.ID, requestID uint32, appErr *warp.Error) error {
	return nil
}

// GetBlockIDAtHeight implements the chain.HeightIndexedChainVM interface
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	// For now, return not implemented
	// In production, maintain a height index
	return ids.Empty, errors.New("height index not implemented")
}

// SetState implements the common.VM interface
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	// For now, no-op
	// In production, handle state transitions
	return nil
}

// NewHTTPHandler returns HTTP handlers for the VM
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	handlers, err := vm.CreateHandlers(ctx)
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

// WaitForEvent blocks until an event occurs that should trigger block building
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	// Block until context is cancelled
	// In production, this would wait for bridge requests, etc.
	// CRITICAL: Must block here to avoid notification flood loop in chains/manager.go
	<-ctx.Done()
	return vmcore.Message{}, ctx.Err()
}

// Helper methods

func (vm *VM) putBlock(blk *Block) error {
	bytes, err := Codec.Marshal(codecVersion, blk)
	if err != nil {
		return err
	}
	id := blk.ID()
	return vm.db.Put(id[:], bytes)
}

func (vm *VM) getBlock(id ids.ID) (*Block, error) {
	bytes, err := vm.db.Get(id[:])
	if err != nil {
		return nil, err
	}

	blk := &Block{vm: vm}
	if _, err := Codec.Unmarshal(bytes, blk); err != nil {
		return nil, err
	}

	blk.ID_ = id
	return blk, nil
}

// HTTP handler methods

func (vm *VM) handleBridgeRequest(w http.ResponseWriter, r *http.Request) {
	// Handle bridge request
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "bridge request handler"}`))
}

func (vm *VM) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Handle status request
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "operational"}`))
}

func (vm *VM) handleValidators(w http.ResponseWriter, r *http.Request) {
	// Handle validators request
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"validators": []}`))
}

// Genesis represents the genesis state
type Genesis struct {
	Timestamp int64 `json:"timestamp"`
}

// =============================================================================
// LP-333: Opt-In Signer Set Management
// First 100 validators opt-in without reshare. Reshare ONLY on slot replacement.
// =============================================================================

// RegisterValidator registers a new validator as a bridge signer (opt-in model)
// LP-333: First 100 validators are accepted directly - NO reshare on join.
// After 100 signers, new validators go to waitlist until a slot opens.
func (vm *VM) RegisterValidator(input *RegisterValidatorInput) (*RegisterValidatorResult, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Parse node ID
	nodeID, err := ids.NodeIDFromString(input.NodeID)
	if err != nil {
		return nil, fmt.Errorf("invalid node ID: %w", err)
	}

	// Check if already a signer
	for _, signer := range vm.signerSet.Signers {
		if signer.NodeID == nodeID {
			return &RegisterValidatorResult{
				Success:      false,
				NodeID:       input.NodeID,
				Message:      "already registered as signer",
				TotalSigners: len(vm.signerSet.Signers),
				Threshold:    vm.signerSet.ThresholdT,
				CurrentEpoch: vm.signerSet.CurrentEpoch,
				SetFrozen:    vm.signerSet.SetFrozen,
			}, nil
		}
	}

	// Check if already on waitlist
	for _, wl := range vm.signerSet.Waitlist {
		if wl == nodeID {
			return &RegisterValidatorResult{
				Success:    false,
				NodeID:     input.NodeID,
				Message:    "already on waitlist",
				Waitlisted: true,
			}, nil
		}
	}

	// Parse bond amount (1M LUX required, slashable)
	var bondAmount uint64
	if input.BondAmount != "" {
		if _, err := fmt.Sscanf(input.BondAmount, "%d", &bondAmount); err != nil {
			bondAmount = 0
		}
	}

	// If set is NOT frozen (under max signers), add directly - NO RESHARE
	if !vm.signerSet.SetFrozen && len(vm.signerSet.Signers) < vm.config.MaxSigners {
		// Create signer info
		signerInfo := &SignerInfo{
			NodeID:     nodeID,
			PartyID:    party.ID(nodeID.String()),
			BondAmount: bondAmount, // 1M LUX bond (slashable)
			Active:     true,
			JoinedAt:   time.Now(),
			SlotIndex:  len(vm.signerSet.Signers),
			Slashed:    false,
			SlashCount: 0,
		}

		// Parse MPC public key if provided
		if input.MPCPubKey != "" {
			signerInfo.MPCPubKey = []byte(input.MPCPubKey)
		}

		// Add to signer set
		vm.signerSet.Signers = append(vm.signerSet.Signers, signerInfo)

		// Update threshold: t = floor(n * ratio)
		vm.signerSet.ThresholdT = int(float64(len(vm.signerSet.Signers)) * vm.config.ThresholdRatio)
		if vm.signerSet.ThresholdT < 1 {
			vm.signerSet.ThresholdT = 1
		}

		// Check if set should freeze (reached max signers)
		if len(vm.signerSet.Signers) >= vm.config.MaxSigners {
			vm.signerSet.SetFrozen = true
		}

		remainingSlots := vm.config.MaxSigners - len(vm.signerSet.Signers)

		if vm.log != nil && !vm.log.IsZero() {
			vm.log.Info("validator registered as bridge signer (LP-333 opt-in)",
				log.Stringer("nodeID", nodeID),
				log.Int("signerIndex", signerInfo.SlotIndex),
				log.Int("totalSigners", len(vm.signerSet.Signers)),
				log.Int("threshold", vm.signerSet.ThresholdT),
				log.Bool("setFrozen", vm.signerSet.SetFrozen),
			)
		}

		return &RegisterValidatorResult{
			Success:        true,
			NodeID:         input.NodeID,
			Registered:     true,
			Waitlisted:     false,
			SignerIndex:    signerInfo.SlotIndex,
			TotalSigners:   len(vm.signerSet.Signers),
			Threshold:      vm.signerSet.ThresholdT,
			ReshareNeeded:  false, // LP-333: NO reshare on join
			CurrentEpoch:   vm.signerSet.CurrentEpoch,
			SetFrozen:      vm.signerSet.SetFrozen,
			RemainingSlots: remainingSlots,
			Message:        "registered as bridge signer",
		}, nil
	}

	// Set is frozen - add to waitlist
	vm.signerSet.Waitlist = append(vm.signerSet.Waitlist, nodeID)
	waitlistIndex := len(vm.signerSet.Waitlist) - 1

	if vm.log != nil && !vm.log.IsZero() {
		vm.log.Info("validator added to waitlist (signer set frozen)",
			log.Stringer("nodeID", nodeID),
			log.Int("waitlistIndex", waitlistIndex),
			log.Int("totalSigners", len(vm.signerSet.Signers)),
		)
	}

	return &RegisterValidatorResult{
		Success:        true,
		NodeID:         input.NodeID,
		Registered:     false,
		Waitlisted:     true,
		WaitlistIndex:  waitlistIndex,
		TotalSigners:   len(vm.signerSet.Signers),
		Threshold:      vm.signerSet.ThresholdT,
		ReshareNeeded:  false,
		CurrentEpoch:   vm.signerSet.CurrentEpoch,
		SetFrozen:      vm.signerSet.SetFrozen,
		RemainingSlots: 0,
		Message:        "added to waitlist (signer set frozen at 100)",
	}, nil
}

// GetSignerSetInfo returns information about the current signer set
func (vm *VM) GetSignerSetInfo() *SignerSetInfo {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	remainingSlots := vm.config.MaxSigners - len(vm.signerSet.Signers)
	if remainingSlots < 0 {
		remainingSlots = 0
	}

	info := &SignerSetInfo{
		TotalSigners:   len(vm.signerSet.Signers),
		Threshold:      vm.signerSet.ThresholdT,
		MaxSigners:     vm.config.MaxSigners,
		CurrentEpoch:   vm.signerSet.CurrentEpoch,
		SetFrozen:      vm.signerSet.SetFrozen,
		RemainingSlots: remainingSlots,
		WaitlistSize:   len(vm.signerSet.Waitlist),
		Signers:        vm.signerSet.Signers,
	}

	if len(vm.signerSet.PublicKey) > 0 {
		info.PublicKey = fmt.Sprintf("%x", vm.signerSet.PublicKey)
	}

	return info
}

// RemoveSigner removes a failed/stopped signer and triggers replacement
// LP-333: This is the ONLY operation that triggers a reshare.
// Epoch increments only when a signer is replaced.
func (vm *VM) RemoveSigner(nodeID ids.NodeID, replacementNodeID *ids.NodeID) (*SignerReplacementResult, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Find and remove the signer
	found := false
	var removedSigner *SignerInfo
	for i, signer := range vm.signerSet.Signers {
		if signer.NodeID == nodeID {
			removedSigner = signer
			// Remove from slice
			vm.signerSet.Signers = append(vm.signerSet.Signers[:i], vm.signerSet.Signers[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		return &SignerReplacementResult{
			Success: false,
			Message: fmt.Sprintf("signer %s not found in active set", nodeID),
		}, nil
	}

	// Determine replacement (from parameter or waitlist)
	var replacement ids.NodeID
	var replacementSource string
	if replacementNodeID != nil && *replacementNodeID != ids.EmptyNodeID {
		replacement = *replacementNodeID
		replacementSource = "explicit"
	} else if len(vm.signerSet.Waitlist) > 0 {
		replacement = vm.signerSet.Waitlist[0]
		vm.signerSet.Waitlist = vm.signerSet.Waitlist[1:]
		replacementSource = "waitlist"
	}

	// Add replacement signer if available
	if replacement != ids.EmptyNodeID {
		newSigner := &SignerInfo{
			NodeID:     replacement,
			PartyID:    party.ID(replacement.String()),
			BondAmount: 0, // Will be verified during reshare (1M LUX required)
			Active:     true,
			JoinedAt:   time.Now(),
			SlotIndex:  removedSigner.SlotIndex,
			Slashed:    false,
			SlashCount: 0,
		}
		vm.signerSet.Signers = append(vm.signerSet.Signers, newSigner)
	}

	// Update threshold
	vm.signerSet.ThresholdT = int(float64(len(vm.signerSet.Signers)) * vm.config.ThresholdRatio)
	if vm.signerSet.ThresholdT < 1 && len(vm.signerSet.Signers) > 0 {
		vm.signerSet.ThresholdT = 1
	}

	// INCREMENT EPOCH - This is the ONLY reshare trigger (LP-333)
	vm.signerSet.CurrentEpoch++

	// Generate reshare session ID
	reshareSession := fmt.Sprintf("reshare-epoch-%d-%s", vm.signerSet.CurrentEpoch, time.Now().Format("20060102150405"))

	if vm.log != nil && !vm.log.IsZero() {
		vm.log.Info("signer removed and reshare triggered (LP-333)",
			log.Stringer("removedNodeID", nodeID),
			log.Stringer("replacementNodeID", replacement),
			log.String("replacementSource", replacementSource),
			log.Uint64("newEpoch", vm.signerSet.CurrentEpoch),
			log.Int("activeSigners", len(vm.signerSet.Signers)),
			log.String("reshareSession", reshareSession),
		)
	}

	// Trigger actual reshare protocol via T-Chain (ThresholdVM) using warp messaging
	if err := vm.triggerReshareProtocol(reshareSession, nodeID, replacement); err != nil {
		if vm.log != nil && !vm.log.IsZero() {
			vm.log.Warn("failed to trigger reshare protocol",
				log.String("reshareSession", reshareSession),
				log.String("error", err.Error()),
			)
		}
		// Continue anyway - reshare can be retried
	}

	result := &SignerReplacementResult{
		Success:       true,
		RemovedNodeID: nodeID.String(),
		NewEpoch:      vm.signerSet.CurrentEpoch,
		ActiveSigners: len(vm.signerSet.Signers),
		Threshold:     vm.signerSet.ThresholdT,
		Message:       "signer removed, reshare initiated",
	}

	if replacement != ids.EmptyNodeID {
		result.ReplacementNodeID = replacement.String()
		result.ReshareSession = reshareSession
		result.Message = fmt.Sprintf("signer replaced from %s, reshare initiated", replacementSource)
	}

	return result, nil
}

// HasSigner checks if a node ID is in the active signer set
func (vm *VM) HasSigner(nodeID ids.NodeID) bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	for _, signer := range vm.signerSet.Signers {
		if signer.NodeID == nodeID {
			return true
		}
	}
	return false
}

// triggerReshareProtocol sends a cross-chain request to ThresholdVM to initiate
// the MPC key reshare protocol. This is triggered when a signer is replaced.
func (vm *VM) triggerReshareProtocol(sessionID string, removedNodeID ids.NodeID, newNodeID ids.NodeID) error {
	// Check if runtime is available (may not be in unit tests)
	if vm.rt == nil {
		if vm.log != nil && !vm.log.IsZero() {
			vm.log.Debug("skipping reshare protocol trigger - runtime not initialized")
		}
		return nil
	}

	// Check required warp infrastructure
	if vm.rt.WarpSigner == nil || vm.rt.Sender == nil {
		if vm.log != nil && !vm.log.IsZero() {
			vm.log.Debug("skipping reshare protocol trigger - warp infrastructure not available")
		}
		return nil
	}

	// Build the list of old party IDs (current signers excluding the removed one)
	oldPartyIDs := make([]party.ID, 0, len(vm.signerSet.Signers))
	for _, signer := range vm.signerSet.Signers {
		if signer.NodeID != removedNodeID && signer.NodeID != newNodeID {
			oldPartyIDs = append(oldPartyIDs, signer.PartyID)
		}
	}

	// Build the list of new party IDs (current signers after replacement)
	newPartyIDs := make([]party.ID, 0, len(vm.signerSet.Signers))
	for _, signer := range vm.signerSet.Signers {
		newPartyIDs = append(newPartyIDs, signer.PartyID)
	}

	// Create the cross-chain MPC request
	mpcRequest := &CrossChainMPCRequest{
		Type:          MPCRequestReshare,
		SessionID:     sessionID,
		Epoch:         vm.signerSet.CurrentEpoch,
		OldPartyIDs:   oldPartyIDs,
		NewPartyIDs:   newPartyIDs,
		Threshold:     vm.signerSet.ThresholdT,
		SourceChainID: vm.rt.ChainID[:],
		Timestamp:     time.Now().Unix(),
	}

	// Serialize the request
	requestBytes, err := json.Marshal(mpcRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal MPC request: %w", err)
	}

	// Create warp unsigned message with the reshare request payload
	unsignedMsg, err := warp.NewUnsignedMessage(
		vm.rt.NetworkID,
		vm.rt.ChainID,
		requestBytes,
	)
	if err != nil {
		return fmt.Errorf("failed to create unsigned warp message: %w", err)
	}

	// Sign the message using the node's BLS key
	sigBytes, err := vm.rt.WarpSigner.Sign(unsignedMsg)
	if err != nil {
		return fmt.Errorf("failed to sign warp message: %w", err)
	}

	// Create a BitSetSignature with this node as the sole signer
	// The signature will be aggregated by receiving nodes in ThresholdVM
	var sigArray [96]byte // BLS signature length
	copy(sigArray[:], sigBytes)

	// Create signers bitset with only this node (index 0)
	signers := warp.NewBitSet()
	signers.Add(0)

	signature := warp.NewBitSetSignature(signers, sigArray)

	// Create the signed warp message
	signedMsg, err := warp.NewMessage(unsignedMsg, signature)
	if err != nil {
		return fmt.Errorf("failed to create signed warp message: %w", err)
	}

	// Broadcast the reshare request to all signers via gossip
	// The ThresholdVM nodes will receive this and participate in the reshare protocol
	msgBytes := signedMsg.Bytes()

	config := warp.SendConfig{
		Validators: len(vm.signerSet.Signers), // Send to all validators in signer set
		Peers:      0,
	}

	if err := vm.rt.Sender.SendGossip(context.Background(), config, msgBytes); err != nil {
		return fmt.Errorf("failed to broadcast reshare request: %w", err)
	}

	if vm.log != nil && !vm.log.IsZero() {
		vm.log.Info("reshare protocol triggered",
			log.String("sessionID", sessionID),
			log.Uint64("epoch", vm.signerSet.CurrentEpoch),
			log.Int("oldParties", len(oldPartyIDs)),
			log.Int("newParties", len(newPartyIDs)),
			log.Int("threshold", vm.signerSet.ThresholdT),
		)
	}

	return nil
}

// SlashSignerInput is the input for slashing a bridge signer
type SlashSignerInput struct {
	NodeID       ids.NodeID `json:"nodeId"`
	Reason       string     `json:"reason"`
	SlashPercent int        `json:"slashPercent"` // Percentage of bond to slash (1-100)
	Evidence     []byte     `json:"evidence"`     // Proof of misbehavior
}

// SlashSignerResult is the result of slashing a bridge signer
type SlashSignerResult struct {
	Success         bool   `json:"success"`
	NodeID          string `json:"nodeId"`
	SlashedAmount   uint64 `json:"slashedAmount"`
	RemainingBond   uint64 `json:"remainingBond"`
	TotalSlashCount int    `json:"totalSlashCount"`
	RemovedFromSet  bool   `json:"removedFromSet"`
	Message         string `json:"message"`
}

// SlashSigner slashes a misbehaving bridge signer's bond
// The bond is NOT stake - it's a slashable deposit that can be partially or fully seized
func (vm *VM) SlashSigner(input *SlashSignerInput) (*SlashSignerResult, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Validate slash percentage
	if input.SlashPercent < 1 || input.SlashPercent > 100 {
		return nil, errors.New("slash percent must be between 1 and 100")
	}

	// Find the signer
	var signer *SignerInfo
	var signerIndex int
	for i, s := range vm.signerSet.Signers {
		if s.NodeID == input.NodeID {
			signer = s
			signerIndex = i
			break
		}
	}

	if signer == nil {
		return &SlashSignerResult{
			Success: false,
			NodeID:  input.NodeID.String(),
			Message: "signer not found in active set",
		}, nil
	}

	// Calculate slash amount
	slashAmount := (signer.BondAmount * uint64(input.SlashPercent)) / 100
	remainingBond := signer.BondAmount - slashAmount

	// Update signer state
	signer.BondAmount = remainingBond
	signer.Slashed = true
	signer.SlashCount++

	if vm.log != nil && !vm.log.IsZero() {
		vm.log.Warn("bridge signer slashed",
			log.Stringer("nodeID", input.NodeID),
			log.String("reason", input.Reason),
			log.Int("slashPercent", input.SlashPercent),
			log.Uint64("slashedAmount", slashAmount),
			log.Uint64("remainingBond", remainingBond),
			log.Int("slashCount", signer.SlashCount),
		)
	}

	result := &SlashSignerResult{
		Success:         true,
		NodeID:          input.NodeID.String(),
		SlashedAmount:   slashAmount,
		RemainingBond:   remainingBond,
		TotalSlashCount: signer.SlashCount,
		RemovedFromSet:  false,
		Message:         fmt.Sprintf("slashed %d%% of bond (%d LUX)", input.SlashPercent, slashAmount/1e9),
	}

	// If bond drops below minimum (1M LUX), remove from signer set
	minBond := uint64(1_000_000 * 1e9) // 1M LUX
	if remainingBond < minBond {
		// Remove signer
		vm.signerSet.Signers = append(vm.signerSet.Signers[:signerIndex], vm.signerSet.Signers[signerIndex+1:]...)

		// Update threshold
		vm.signerSet.ThresholdT = int(float64(len(vm.signerSet.Signers)) * vm.config.ThresholdRatio)
		if vm.signerSet.ThresholdT < 1 && len(vm.signerSet.Signers) > 0 {
			vm.signerSet.ThresholdT = 1
		}

		// Increment epoch (removal triggers reshare)
		vm.signerSet.CurrentEpoch++

		result.RemovedFromSet = true
		result.Message = fmt.Sprintf("slashed %d%% of bond, signer removed (bond below 1M LUX minimum)", input.SlashPercent)

		if vm.log != nil && !vm.log.IsZero() {
			vm.log.Warn("bridge signer removed due to insufficient bond after slashing",
				log.Stringer("nodeID", input.NodeID),
				log.Uint64("remainingBond", remainingBond),
				log.Uint64("newEpoch", vm.signerSet.CurrentEpoch),
			)
		}
	}

	return result, nil
}
