// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/luxfi/chains/zkvm/precompiles"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/warp"

	"github.com/luxfi/node/version"
	"github.com/luxfi/node/vms/types/fee"
)

var (
	_ chain.ChainVM = (*VM)(nil)
	_ vertex.DAGVM  = (*VM)(nil)

	Version = &version.Semantic{
		Major: 1,
		Minor: 0,
		Patch: 0,
	}

	errNotImplemented = errors.New("not implemented")
)

// ZConfig contains VM configuration
type ZConfig struct {
	// Privacy configuration
	EnableConfidentialTransfers bool `serialize:"true" json:"enableConfidentialTransfers"`
	EnablePrivateAddresses      bool `serialize:"true" json:"enablePrivateAddresses"`

	// ZK proof configuration
	ProofSystem      string `serialize:"true" json:"proofSystem"` // groth16, plonk, etc.
	CircuitType      string `serialize:"true" json:"circuitType"` // transfer, mint, burn
	VerifyingKeyPath string `serialize:"true" json:"verifyingKeyPath"`
	TrustedSetupPath string `serialize:"true" json:"trustedSetupPath"`

	// VerifyingKeys supplies real (non-dummy) verifying keys per circuit
	// type (keyed by the TransactionType string), in-memory at genesis.
	// When empty, loadVerifyingKeys installs all-zero dummy keys (proof
	// verification disabled, fail-closed). On a strict-PQ chain, supplying
	// a real bn254 verifying key here is REFUSED at construction
	// (errStrictPQRealVKForbidden) — shielded value uses STARK/FRI only.
	VerifyingKeys map[string][]byte `serialize:"true" json:"verifyingKeys"`

	// StrictPQ HARD-DISABLES the classical (bn254 pairing-based) shielded
	// proof systems on this chain. When true, the shielded-tx ProofVerifier
	// REFUSES groth16/plonk/bulletproofs and accepts ONLY the post-quantum
	// STARK/FRI system (delegated to precompile/starkfri, which fails
	// closed until the prover binding exists). Loading a real (non-dummy)
	// bn254 verifying key on a strict-PQ chain is an ERROR. This is the
	// Lux primary-network posture: a CRQC that breaks bn254 cannot forge a
	// shield/unshield proof to mint or steal shielded value.
	StrictPQ bool `serialize:"true" json:"strictPQ"`

	// FHE configuration
	EnableFHE     bool   `serialize:"true" json:"enableFHE"`
	FHEScheme     string `serialize:"true" json:"fheScheme"`     // BFV, CKKS, etc.
	SecurityLevel uint32 `serialize:"true" json:"securityLevel"` // 128, 192, 256

	// Performance
	MaxUTXOsPerBlock         uint32        `serialize:"true" json:"maxUtxosPerBlock"`
	ProofVerificationTimeout time.Duration `serialize:"true" json:"proofVerificationTimeout"`
	ProofCacheSize           uint32        `serialize:"true" json:"proofCacheSize"`
}

// VM implements the Zero-Knowledge UTXO Chain VM
type VM struct {
	rt     *runtime.Runtime
	config ZConfig

	// State management
	db          database.Database
	utxoDB      *UTXODB
	nullifierDB *NullifierDB
	stateTree   *StateTree

	// Privacy components
	proofVerifier  *ProofVerifier
	fheProcessor   *FHEProcessor
	addressManager *AddressManager

	// zkPrecompiles holds the Z-Chain ZK verifier precompiles. It is
	// populated in Initialize by precompiles.RegisterZKPrecompiles, with
	// strictPQ taken from config.StrictPQ — the SAME single field that
	// gates the shielded-proof verifier. One profile bit, both switches:
	// on a strict-PQ chain the classical Groth16/PLONK verifiers (0x80/
	// 0x81) are NOT registered (fail-closed by absence) AND the shielded
	// proof verifier refuses classical systems.
	zkPrecompiles *precompiles.MapRegistry

	// Block management
	genesisBlock   *Block
	lastAcceptedID ids.ID
	lastAccepted   *Block
	pendingBlocks  map[ids.ID]*Block

	// Transaction mempool
	mempool *Mempool

	// Consensus
	toEngine chan<- vmcore.Message

	// Logging
	log log.Logger

	// Fee policy gating user-submitted tx admission. user-tx-accepting
	// (HTTP /sendTransaction -> Mempool.AddTransaction) so attach a
	// FlatPolicy at MinTxFeeFloor; consensus-internal paths bypass.
	feePolicy fee.Policy
	networkID uint32

	mu sync.RWMutex
}

// Initialize initializes the VM
func (vm *VM) Initialize(
	ctx context.Context,
	init vmcore.Init,
) error {
	vm.rt = init.Runtime
	vm.db = init.DB
	vm.toEngine = init.ToEngine
	vm.log = init.Log

	if vm.rt == nil {
		return errors.New("runtime is nil")
	}
	if vm.db == nil {
		return errors.New("database is nil")
	}
	if vm.log == nil {
		// Fallback to runtime log if available, strictly this should be set in init.Log
		if logger, ok := vm.rt.Log.(log.Logger); ok {
			vm.log = logger
		} else {
			return errors.New("invalid logger type")
		}
	}
	vm.pendingBlocks = make(map[ids.ID]*Block)

	// Parse configuration or use defaults
	if len(init.Config) > 0 {
		if _, err := Codec.Unmarshal(init.Config, &vm.config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	} else {
		// Use default config. The Z-Chain is DEFINITIVELY strict-PQ (it is
		// the shielded-settlement chain pinned to the canonical Lux
		// strict-PQ security profile), so the default — used when genesis
		// carries no explicit ZConfig — pins StrictPQ=true and the only
		// accepted shielded system, STARK/FRI ("stark"). A non-strict
		// permissive deployment MUST set StrictPQ=false explicitly in
		// genesis; it is never the default for this chain.
		vm.config = ZConfig{
			EnableConfidentialTransfers: true,
			EnablePrivateAddresses:      true,
			ProofSystem:                 "stark",
			CircuitType:                 "transfer",
			StrictPQ:                    true,
			EnableFHE:                   false,
			MaxUTXOsPerBlock:            100,
			ProofCacheSize:              1000,
		}
	}

	// Ensure ProofCacheSize is positive
	if vm.config.ProofCacheSize <= 0 {
		vm.config.ProofCacheSize = 1000
	}

	// Initialize UTXO database
	utxoDB, err := NewUTXODB(vm.db, vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize UTXO DB: %w", err)
	}
	vm.utxoDB = utxoDB

	// Initialize nullifier database
	nullifierDB, err := NewNullifierDB(vm.db, vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize nullifier DB: %w", err)
	}
	vm.nullifierDB = nullifierDB

	// Initialize state tree
	stateTree, err := NewStateTree(vm.db, vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize state tree: %w", err)
	}
	vm.stateTree = stateTree

	// Initialize proof verifier
	proofVerifier, err := NewProofVerifier(vm.config, vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize proof verifier: %w", err)
	}
	vm.proofVerifier = proofVerifier
	if !proofVerifier.VerifyingKeysLoaded() {
		vm.log.Warn("Z-Chain running without real ZK verifying keys — proof verification disabled")
	}

	// Register the Z-Chain ZK verifier precompiles, deriving strictPQ from
	// the SAME config.StrictPQ field that gates the proof verifier above.
	// One profile bit drives both switches: a strict-PQ Z-Chain omits the
	// classical Groth16 (0x80) / PLONK (0x81) verifiers (fail-closed by
	// absence) so only the post-quantum STARK/FRI verifier (0x82) exists.
	vm.zkPrecompiles = precompiles.NewMapRegistry()
	precompiles.RegisterZKPrecompiles(vm.zkPrecompiles, vm.config.StrictPQ)
	vm.log.Info("Registered Z-Chain ZK precompiles",
		log.Bool("strictPQ", vm.config.StrictPQ),
	)

	// Initialize FHE processor if enabled
	if vm.config.EnableFHE {
		fheProcessor, err := NewFHEProcessor(vm.config, vm.log)
		if err != nil {
			return fmt.Errorf("failed to initialize FHE processor: %w", err)
		}
		vm.fheProcessor = fheProcessor
	}

	// Initialize address manager
	addressManager, err := NewAddressManager(vm.db, vm.config.EnablePrivateAddresses, vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize address manager: %w", err)
	}
	vm.addressManager = addressManager

	// Initialize mempool
	vm.mempool = NewMempool(1000, vm.log) // Max 1000 pending txs

	// Pin fee policy from runtime networkID. Z-Chain accepts user-
	// submitted shielded txs so attach the canonical FlatPolicy at
	// MinTxFeeFloor; fee.Validate refuses zero-fee user-facing chains
	// at boot, before any block is accepted.
	if init.Runtime != nil {
		vm.networkID = init.Runtime.NetworkID
	}
	vm.feePolicy = newFeePolicy(vm.networkID)
	if err := fee.Validate(vm.feePolicy); err != nil {
		return fmt.Errorf("zkvm: fee policy: %w", err)
	}

	// Initialize genesis block
	genesis, err := ParseGenesis(init.Genesis)
	if err != nil {
		return fmt.Errorf("failed to parse genesis: %w", err)
	}

	vm.genesisBlock = &Block{
		BlockHeight:    0,
		BlockTimestamp: genesis.Timestamp,
		Txs:            genesis.InitialTxs,
		vm:             vm,
	}
	vm.genesisBlock.ID_ = vm.genesisBlock.computeID()

	// Load last accepted block
	lastAcceptedBytes, err := vm.db.Get(lastAcceptedKey)
	if err == database.ErrNotFound {
		// First time initialization
		vm.lastAccepted = vm.genesisBlock
		vm.lastAcceptedID = vm.genesisBlock.ID()

		if err := vm.db.Put(lastAcceptedKey, vm.lastAcceptedID[:]); err != nil {
			return err
		}

		// Process genesis transactions
		if err := vm.processGenesisTransactions(genesis); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		vm.lastAcceptedID, _ = ids.ToID(lastAcceptedBytes)
		// Load the block (implementation depends on block storage)
	}

	vm.log.Info("ZK UTXO VM initialized",
		log.String("version", Version.String()),
		log.Bool("confidentialTransfers", vm.config.EnableConfidentialTransfers),
		log.Bool("privateAddresses", vm.config.EnablePrivateAddresses),
		log.String("proofSystem", vm.config.ProofSystem),
		log.Bool("fheEnabled", vm.config.EnableFHE),
	)

	return nil
}

// ZKPrecompiles returns the registered Z-Chain ZK verifier precompiles.
// On a strict-PQ chain the classical Groth16 (0x80) / PLONK (0x81)
// addresses resolve to "no precompile" (fail-closed by absence).
func (vm *VM) ZKPrecompiles() *precompiles.MapRegistry { return vm.zkPrecompiles }

// StrictPQ reports whether this Z-Chain instance is on the strict-PQ
// security profile. It is the single bit that gates both the shielded-
// proof verifier and the classical-precompile registration.
func (vm *VM) StrictPQ() bool { return vm.config.StrictPQ }

// BuildBlock builds a new block
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Get transactions from mempool
	txs := vm.mempool.GetPendingTransactions(int(vm.config.MaxUTXOsPerBlock))
	if len(txs) == 0 {
		return nil, errors.New("no transactions to include in block")
	}

	// Verify all transactions
	validTxs := make([]*Transaction, 0, len(txs))
	for _, tx := range txs {
		if err := vm.verifyTransaction(tx); err != nil {
			vm.log.Debug("Transaction verification failed",
				log.String("txID", tx.ID.String()),
				log.Reflect("error", err),
			)
			continue
		}
		validTxs = append(validTxs, tx)
	}

	if len(validTxs) == 0 {
		return nil, errors.New("no valid transactions to include in block")
	}

	// Create new block
	block := &Block{
		ParentID_:      vm.lastAcceptedID,
		BlockHeight:    vm.lastAccepted.Height() + 1,
		BlockTimestamp: time.Now().Unix(),
		Txs:            validTxs,
		vm:             vm,
	}

	// Compute state root after applying transactions
	stateRoot, err := vm.computeStateRoot(validTxs)
	if err != nil {
		return nil, err
	}
	block.StateRoot = stateRoot

	// Compute block ID
	block.ID_ = block.computeID()

	// Store pending block
	vm.pendingBlocks[block.ID()] = block

	vm.log.Debug("Built new block",
		log.String("blockID", block.ID().String()),
		log.Uint64("height", block.BlockHeight),
		log.Int("txCount", len(validTxs)),
	)

	return block, nil
}

// ParseBlock parses a block from bytes
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (chain.Block, error) {
	block := &Block{vm: vm}
	if _, err := Codec.Unmarshal(blockBytes, block); err != nil {
		return nil, err
	}

	block.ID_ = block.computeID()
	return block, nil
}

// GetBlock retrieves a block by ID
func (vm *VM) GetBlock(ctx context.Context, blkID ids.ID) (chain.Block, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	// Check pending blocks (nil-safe for early calls before initialization)
	if vm.pendingBlocks != nil {
		if block, exists := vm.pendingBlocks[blkID]; exists {
			return block, nil
		}
	}

	// Check if it's genesis
	if blkID == vm.genesisBlock.ID() {
		return vm.genesisBlock, nil
	}

	// Load from database
	blockBytes, err := vm.db.Get(blkID[:])
	if err != nil {
		return nil, err
	}

	return vm.ParseBlock(ctx, blockBytes)
}

// SetState sets the VM state
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	return nil
}

// Shutdown shuts down the VM
func (vm *VM) Shutdown(ctx context.Context) error {
	if !vm.log.IsZero() {
		vm.log.Info("Shutting down ZK UTXO VM")
	}

	if vm.utxoDB != nil {
		vm.utxoDB.Close()
	}

	if vm.nullifierDB != nil {
		vm.nullifierDB.Close()
	}

	if vm.stateTree != nil {
		vm.stateTree.Close()
	}

	if vm.addressManager != nil {
		vm.addressManager.Close()
	}

	if vm.db != nil {
		return vm.db.Close()
	}
	return nil
}

// Version returns the VM version
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version.String(), nil
}

// HealthCheck performs a health check
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	return chain.HealthResult{
		Healthy: true,
		Details: map[string]string{
			"utxoCount":         fmt.Sprintf("%d", vm.utxoDB.GetUTXOCount()),
			"nullifierCount":    fmt.Sprintf("%d", vm.nullifierDB.GetNullifierCount()),
			"lastBlockHeight":   fmt.Sprintf("%d", vm.lastAccepted.Height()),
			"pendingBlockCount": fmt.Sprintf("%d", len(vm.pendingBlocks)),
			"mempoolSize":       fmt.Sprintf("%d", vm.mempool.Size()),
			"proofCacheSize":    fmt.Sprintf("%d", vm.proofVerifier.GetCacheSize()),
		},
	}, nil
}

// Health represents VM health status
type Health struct {
	DatabaseHealthy   bool   `json:"databaseHealthy"`
	UTXOCount         uint64 `json:"utxoCount"`
	NullifierCount    uint64 `json:"nullifierCount"`
	LastBlockHeight   uint64 `json:"lastBlockHeight"`
	PendingBlockCount int    `json:"pendingBlockCount"`
	MempoolSize       int    `json:"mempoolSize"`
	ProofCacheSize    int    `json:"proofCacheSize"`
}

// CreateHandlers returns the VM handlers
func (vm *VM) CreateHandlers(context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{
		"/rpc":     NewRPCHandler(vm),
		"/privacy": NewPrivacyHandler(vm),
		"/proof":   NewProofHandler(vm),
	}, nil
}

// NewHTTPHandler returns HTTP handlers for the VM
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	return NewRPCHandler(vm), nil
}

// WaitForEvent blocks until an event occurs that should trigger block building
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	// CRITICAL: Must block here to avoid notification flood loop in chains/manager.go
	<-ctx.Done()
	return vmcore.Message{}, ctx.Err()
}

// verifyTransaction verifies a transaction including ZK proofs
func (vm *VM) verifyTransaction(tx *Transaction) error {
	// Check nullifiers aren't already spent
	for _, nullifier := range tx.Nullifiers {
		if vm.nullifierDB.IsNullifierSpent(nullifier) {
			return errors.New("nullifier already spent")
		}
	}

	// Verify ZK proof
	if err := vm.proofVerifier.VerifyTransactionProof(tx); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	// Verify FHE operations if enabled
	if vm.config.EnableFHE && tx.HasFHEOperations() {
		if err := vm.fheProcessor.VerifyFHEOperations(tx); err != nil {
			return fmt.Errorf("FHE verification failed: %w", err)
		}
	}

	return nil
}

// computeStateRoot computes the new state root after applying transactions
func (vm *VM) computeStateRoot(txs []*Transaction) ([]byte, error) {
	// Apply transactions to state tree
	for _, tx := range txs {
		if err := vm.stateTree.ApplyTransaction(tx); err != nil {
			return nil, err
		}
	}

	// Compute and return new root
	return vm.stateTree.ComputeRoot()
}

// processGenesisTransactions processes initial transactions from genesis
func (vm *VM) processGenesisTransactions(genesis *Genesis) error {
	for _, tx := range genesis.InitialTxs {
		// Add outputs to UTXO set
		for i, output := range tx.Outputs {
			utxo := &UTXO{
				TxID:        tx.ID,
				OutputIndex: uint32(i),
				Commitment:  output.Commitment,
				Ciphertext:  output.EncryptedNote,
				EphemeralPK: output.EphemeralPubKey,
				Height:      0, // Genesis height
			}
			if err := vm.utxoDB.AddUTXO(utxo); err != nil {
				return err
			}
		}

		// Add to state tree
		if err := vm.stateTree.ApplyTransaction(tx); err != nil {
			return err
		}
	}

	return nil
}

// Additional interface implementations
func (vm *VM) SetPreference(ctx context.Context, blkID ids.ID) error {
	return nil
}

func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.lastAcceptedID, nil
}

func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *chain.VersionInfo) error {
	return nil
}

func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return nil
}

// Request implements the common.VM interface
func (vm *VM) Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, request []byte) error {
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

// CrossChainRequest implements the common.VM interface
func (vm *VM) CrossChainRequest(ctx context.Context, chainID ids.ID, requestID uint32, deadline time.Time, request []byte) error {
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
	return ids.Empty, errors.New("height index not implemented")
}

var lastAcceptedKey = []byte("last_accepted")
