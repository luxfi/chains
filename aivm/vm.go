// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package aivm provides the AI Virtual Machine for the Lux network.
// AIVM handles AI compute tasks, provider attestation, and reward distribution.
//
// Key features:
//   - TEE attestation for compute providers (CPU: SGX/SEV-SNP/TDX, GPU: nvtrust)
//   - Local GPU attestation via nvtrust (no cloud dependency)
//   - Task submission and assignment
//   - Mining rewards and merkle anchoring to Q-Chain
package aivm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/luxfi/accel"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"

	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/node/version"

	"github.com/luxfi/ai/pkg/aivm"
	"github.com/luxfi/ai/pkg/attestation"
)

var (
	_ chain.ChainVM = (*VM)(nil)
	_ vertex.DAGVM  = (*VM)(nil)

	Version = &version.Semantic{
		Major: 1,
		Minor: 0,
		Patch: 0,
	}

	ErrNotInitialized   = errors.New("vm not initialized")
	ErrInvalidTask      = errors.New("invalid task")
	ErrProviderNotFound = errors.New("provider not found")
)

// Config contains AIVM configuration
type Config struct {
	// Network settings
	MaxProvidersPerNode int `serialize:"true" json:"maxProvidersPerNode"`
	MaxTasksPerProvider int `serialize:"true" json:"maxTasksPerProvider"`

	// Attestation settings
	RequireTEEAttestation bool   `serialize:"true" json:"requireTEEAttestation"`
	MinTrustScore         uint8  `serialize:"true" json:"minTrustScore"`
	AttestationTimeout    string `serialize:"true" json:"attestationTimeout"`

	// Task settings
	MaxTaskQueueSize int    `serialize:"true" json:"maxTaskQueueSize"`
	TaskTimeout      string `serialize:"true" json:"taskTimeout"`

	// Reward settings
	BaseReward       uint64 `serialize:"true" json:"baseReward"`
	EpochDuration    string `serialize:"true" json:"epochDuration"`
	MerkleAnchorFreq int    `serialize:"true" json:"merkleAnchorFreq"` // Blocks between Q-Chain anchors
}

// DefaultConfig returns default AIVM configuration
func DefaultConfig() Config {
	return Config{
		MaxProvidersPerNode:   100,
		MaxTasksPerProvider:   10,
		RequireTEEAttestation: true,
		MinTrustScore:         50,
		AttestationTimeout:    "30s",
		MaxTaskQueueSize:      1000,
		TaskTimeout:           "5m",
		BaseReward:            1000000000, // 1 LUX in wei
		EpochDuration:         "1h",
		MerkleAnchorFreq:      100,
	}
}

// VM implements the AI Virtual Machine
type VM struct {
	rt     *runtime.Runtime
	config Config

	// Database
	db database.Database

	// Per-VM GPU acceleration session. Reserved for future batch
	// attestation verification and tensor proof checks. Allocated by
	// the factory; safe to be nil in tests.
	accel *accel.VMSession

	// Core AI VM from luxfi/ai package
	core *aivm.VM

	// Attestation verifier (local nvtrust - no cloud dependency)
	verifier *attestation.Verifier

	// Block management
	lastAcceptedID ids.ID
	lastAccepted   *Block
	pendingBlocks  map[ids.ID]*Block

	// Consensus
	toEngine chan<- vmcore.Message

	// Logging
	log log.Logger

	mu      sync.RWMutex
	running bool
}

// Block represents an AIVM block
type Block struct {
	ID_        ids.ID    `json:"id"`
	ParentID_  ids.ID    `json:"parentID"`
	Height_    uint64    `json:"height"`
	Timestamp_ time.Time `json:"timestamp"`

	// AI-specific data
	Tasks        []aivm.Task       `json:"tasks,omitempty"`
	Results      []aivm.TaskResult `json:"results,omitempty"`
	MerkleRoot   [32]byte          `json:"merkleRoot"`
	ProviderRegs []ProviderReg     `json:"providerRegs,omitempty"`

	bytes []byte
	vm    *VM
}

// ProviderReg represents a provider registration in a block
type ProviderReg struct {
	ProviderID     string                        `json:"providerId"`
	WalletAddress  string                        `json:"walletAddress"`
	Endpoint       string                        `json:"endpoint"`
	CPUAttestation *attestation.AttestationQuote `json:"cpuAttestation,omitempty"`
	GPUAttestation *attestation.GPUAttestation   `json:"gpuAttestation,omitempty"`
}

// Initialize initializes the VM with the unified Init struct
func (vm *VM) Initialize(ctx context.Context, init vmcore.Init) error {
	vm.rt = init.Runtime
	vm.db = init.DB
	vm.toEngine = init.ToEngine

	if logger, ok := vm.rt.Log.(log.Logger); ok {
		vm.log = logger
	} else {
		return errors.New("invalid logger type")
	}

	vm.pendingBlocks = make(map[ids.ID]*Block)

	// Parse configuration
	if len(init.Config) > 0 {
		if err := json.Unmarshal(init.Config, &vm.config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	} else {
		vm.config = DefaultConfig()
	}

	// Parse genesis (JSON format)
	genesis := &Genesis{}
	if len(init.Genesis) > 0 {
		if err := json.Unmarshal(init.Genesis, genesis); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}

	// Initialize core AI VM
	vm.core = aivm.NewVM()

	// Initialize attestation verifier (local nvtrust - no cloud dependency)
	vm.verifier = attestation.NewVerifier()

	// Start core VM
	if err := vm.core.Start(ctx); err != nil {
		return fmt.Errorf("failed to start core AI VM: %w", err)
	}

	// Create genesis block
	genesisBlock := &Block{
		ID_:        ids.Empty,
		ParentID_:  ids.Empty,
		Height_:    0,
		Timestamp_: time.Unix(genesis.Timestamp, 0),
		vm:         vm,
	}
	genesisBlock.ID_ = genesisBlock.computeID()
	vm.lastAcceptedID = genesisBlock.ID_
	vm.lastAccepted = genesisBlock

	vm.running = true
	if !vm.log.IsZero() {
		vm.log.Info("AIVM initialized",
			log.Bool("requireTEE", vm.config.RequireTEEAttestation),
			log.Uint8("minTrustScore", vm.config.MinTrustScore),
		)
	}

	return nil
}

// Genesis represents the genesis state
type Genesis struct {
	Version   int    `json:"version"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

// Shutdown shuts down the VM
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return nil
	}

	vm.running = false

	if vm.core != nil {
		return vm.core.Stop()
	}

	return nil
}

// CreateHandlers returns HTTP handlers
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{
		"/rpc": NewService(vm),
	}, nil
}

// Connected notifies the VM about connected nodes
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *chain.VersionInfo) error {
	return nil
}

// Disconnected notifies the VM about disconnected nodes
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return nil
}

// RegisterProvider registers a new AI compute provider
func (vm *VM) RegisterProvider(provider *aivm.Provider) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return ErrNotInitialized
	}

	// Verify attestation meets minimum trust score
	if vm.config.RequireTEEAttestation {
		if provider.GPUAttestation != nil {
			status, err := vm.verifier.VerifyGPUAttestation(provider.GPUAttestation)
			if err != nil {
				return fmt.Errorf("GPU attestation failed: %w", err)
			}
			if status.TrustScore < vm.config.MinTrustScore {
				return fmt.Errorf("trust score %d below minimum %d", status.TrustScore, vm.config.MinTrustScore)
			}
		}
	}

	return vm.core.RegisterProvider(provider)
}

// VerifyGPUAttestation verifies GPU attestation (local nvtrust - no cloud)
func (vm *VM) VerifyGPUAttestation(att *attestation.GPUAttestation) (*attestation.DeviceStatus, error) {
	if !vm.running {
		return nil, ErrNotInitialized
	}
	return vm.verifier.VerifyGPUAttestation(att)
}

// SubmitTask submits a new AI task
func (vm *VM) SubmitTask(task *aivm.Task) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return ErrNotInitialized
	}

	return vm.core.SubmitTask(task)
}

// GetTask returns a task by ID
func (vm *VM) GetTask(taskID string) (*aivm.Task, error) {
	if !vm.running {
		return nil, ErrNotInitialized
	}
	return vm.core.GetTask(taskID)
}

// SubmitResult submits a task result
func (vm *VM) SubmitResult(result *aivm.TaskResult) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return ErrNotInitialized
	}

	return vm.core.SubmitResult(result)
}

// GetProviders returns all registered providers
func (vm *VM) GetProviders() []*aivm.Provider {
	if !vm.running {
		return nil
	}
	return vm.core.GetProviders()
}

// GetModels returns available AI models
func (vm *VM) GetModels() []*aivm.ModelInfo {
	if !vm.running {
		return nil
	}
	return vm.core.GetModels()
}

// GetStats returns VM statistics
func (vm *VM) GetStats() map[string]interface{} {
	if !vm.running {
		return nil
	}
	return vm.core.GetStats()
}

// GetMerkleRoot returns merkle root for Q-Chain anchoring
func (vm *VM) GetMerkleRoot() [32]byte {
	if !vm.running {
		return [32]byte{}
	}
	return vm.core.GetMerkleRoot()
}

// ClaimRewards claims pending rewards for a provider
func (vm *VM) ClaimRewards(providerID string) (string, error) {
	if !vm.running {
		return "", ErrNotInitialized
	}
	return vm.core.ClaimRewards(providerID)
}

// GetRewardStats returns reward statistics for a provider
func (vm *VM) GetRewardStats(providerID string) (map[string]interface{}, error) {
	if !vm.running {
		return nil, ErrNotInitialized
	}
	return vm.core.GetRewardStats(providerID)
}

// =============================================================================
// ChainVM Interface Methods
// =============================================================================

// SetState implements chain.ChainVM interface
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	// Handle state transitions (bootstrapping -> normal operation)
	return nil
}

// BuildBlock implements chain.ChainVM interface
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return nil, ErrNotInitialized
	}

	parent := vm.lastAccepted
	if parent == nil {
		return nil, errors.New("no parent block")
	}

	// Create new block
	blk := &Block{
		ParentID_:  parent.ID_,
		Height_:    parent.Height_ + 1,
		Timestamp_: time.Now(),
		vm:         vm,
	}
	blk.ID_ = blk.computeID()

	vm.pendingBlocks[blk.ID_] = blk
	return blk, nil
}

// ParseBlock implements chain.ChainVM interface
func (vm *VM) ParseBlock(ctx context.Context, bytes []byte) (chain.Block, error) {
	blk := &Block{vm: vm}
	if err := json.Unmarshal(bytes, blk); err != nil {
		return nil, err
	}
	blk.ID_ = blk.computeID()
	return blk, nil
}

// GetBlock implements chain.ChainVM interface
func (vm *VM) GetBlock(ctx context.Context, id ids.ID) (chain.Block, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	// Check pending blocks (nil-safe for early calls before initialization)
	if vm.pendingBlocks != nil {
		if blk, exists := vm.pendingBlocks[id]; exists {
			return blk, nil
		}
	}

	// Check if it's the last accepted
	if vm.lastAccepted != nil && vm.lastAccepted.ID_ == id {
		return vm.lastAccepted, nil
	}

	// Try to get from database
	bytes, err := vm.db.Get(id[:])
	if err != nil {
		return nil, err
	}

	blk := &Block{vm: vm}
	if err := json.Unmarshal(bytes, blk); err != nil {
		return nil, err
	}
	return blk, nil
}

// SetPreference implements chain.ChainVM interface
func (vm *VM) SetPreference(ctx context.Context, id ids.ID) error {
	// For AIVM, we just track this but don't need to do anything special
	return nil
}

// LastAccepted implements chain.ChainVM interface
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.lastAcceptedID, nil
}

// GetBlockIDAtHeight implements chain.ChainVM interface
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	// For now, return error - would need height index for full implementation
	return ids.Empty, errors.New("height index not implemented")
}

// NewHTTPHandler implements chain.ChainVM interface
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

// Version implements chain.ChainVM interface
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version.String(), nil
}

// WaitForEvent implements chain.ChainVM interface
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	// Block until context is cancelled - AIVM doesn't proactively build blocks
	// CRITICAL: Must block here to avoid notification flood loop in chains/manager.go
	<-ctx.Done()
	return vmcore.Message{}, ctx.Err()
}

// HealthCheck implements chain.ChainVM interface
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	return chain.HealthResult{
		Healthy: vm.running,
		Details: map[string]string{"status": "operational"},
	}, nil
}

// =============================================================================
// Block Methods (implements chain.Block interface)
// =============================================================================

// computeID computes the block ID from its contents
func (blk *Block) computeID() ids.ID {
	bytes, _ := json.Marshal(blk)
	hash := sha256.Sum256(bytes)
	return ids.ID(hash)
}

// ID returns the block ID
func (blk *Block) ID() ids.ID {
	return blk.ID_
}

// Parent returns the parent block ID
func (blk *Block) Parent() ids.ID {
	return blk.ParentID_
}

// ParentID returns the parent block ID
func (blk *Block) ParentID() ids.ID {
	return blk.ParentID_
}

// Height returns the block height
func (blk *Block) Height() uint64 {
	return blk.Height_
}

// Timestamp returns the block timestamp
func (blk *Block) Timestamp() time.Time {
	return blk.Timestamp_
}

// Status returns the block status
func (blk *Block) Status() uint8 {
	return 0 // Processing
}

// Verify verifies the block
func (blk *Block) Verify(ctx context.Context) error {
	return nil
}

// Accept accepts the block
func (blk *Block) Accept(ctx context.Context) error {
	blk.vm.mu.Lock()
	defer blk.vm.mu.Unlock()

	// Store in database
	bytes, err := json.Marshal(blk)
	if err != nil {
		return err
	}
	if err := blk.vm.db.Put(blk.ID_[:], bytes); err != nil {
		return err
	}

	// Update last accepted
	blk.vm.lastAcceptedID = blk.ID_
	blk.vm.lastAccepted = blk

	// Remove from pending
	delete(blk.vm.pendingBlocks, blk.ID_)

	return nil
}

// Reject rejects the block
func (blk *Block) Reject(ctx context.Context) error {
	blk.vm.mu.Lock()
	defer blk.vm.mu.Unlock()

	delete(blk.vm.pendingBlocks, blk.ID_)
	return nil
}

// Bytes returns the serialized block
func (blk *Block) Bytes() []byte {
	if blk.bytes == nil {
		blk.bytes, _ = json.Marshal(blk)
	}
	return blk.bytes
}
