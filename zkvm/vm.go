// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/chains/zkvm/precompiles"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	vmchain "github.com/luxfi/vm/chain"
	"github.com/luxfi/warp"

	"github.com/luxfi/node/version"
	"github.com/luxfi/node/vms/types/fee"
)

var (
	_ vmchain.ChainVM = (*VM)(nil)
	_ vertex.DAGVM    = (*VM)(nil)

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
	EnableConfidentialTransfers bool `json:"enableConfidentialTransfers"`
	EnablePrivateAddresses      bool `json:"enablePrivateAddresses"`

	// ZK proof configuration
	ProofSystem      string `json:"proofSystem"` // groth16, plonk, etc.
	CircuitType      string `json:"circuitType"` // transfer, mint, burn
	VerifyingKeyPath string `json:"verifyingKeyPath"`
	TrustedSetupPath string `json:"trustedSetupPath"`

	// VerifyingKeys supplies real (non-dummy) verifying keys per circuit
	// type (keyed by the TransactionType string), in-memory at genesis.
	// When empty, loadVerifyingKeys installs all-zero dummy keys (proof
	// verification disabled, fail-closed). On a strict-PQ chain, supplying
	// a real bn254 verifying key here is REFUSED at construction
	// (errStrictPQRealVKForbidden) — shielded value uses STARK/FRI only.
	VerifyingKeys map[string][]byte `json:"verifyingKeys"`

	// StrictPQ HARD-DISABLES the classical (bn254 pairing-based) shielded
	// proof systems on this chain. When true, the shielded-tx ProofVerifier
	// REFUSES groth16/plonk/bulletproofs and accepts ONLY the post-quantum
	// STARK/FRI system (delegated to precompile/starkfri, which fails
	// closed until the prover binding exists). Loading a real (non-dummy)
	// bn254 verifying key on a strict-PQ chain is an ERROR. This is the
	// Lux primary-network posture: a CRQC that breaks bn254 cannot forge a
	// shield/unshield proof to mint or steal shielded value.
	StrictPQ bool `json:"strictPQ"`

	// FHE configuration
	EnableFHE     bool   `json:"enableFHE"`
	FHEScheme     string `json:"fheScheme"`     // BFV, CKKS, etc.
	SecurityLevel uint32 `json:"securityLevel"` // 128, 192, 256

	// Performance
	MaxUTXOsPerBlock         uint32        `json:"maxUtxosPerBlock"`
	ProofVerificationTimeout time.Duration `json:"proofVerificationTimeout"`
	ProofCacheSize           uint32        `json:"proofCacheSize"`
}

// VM implements the Zero-Knowledge UTXO Chain VM
type VM struct {
	rt     *runtime.Runtime
	config ZConfig

	// chain is the durable state, the blocks in flight and the tip — and the
	// one lock over all of it. The three stores below write through its view,
	// so their records commit with the decision that made them and are
	// discarded with one that fails.
	//
	// It holds chain.Block rather than *Block because Z-Chain decides in two
	// shapes: a linear block and a DAG vertex. Both change state the same way,
	// which is the whole of what the store needs to know about either.
	chain       *chain.Store[chain.Block]
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
	genesisBlock *Block

	// Transaction mempool
	mempool *Mempool

	// Consensus
	toEngine chan<- vmcore.Message

	// Logging
	log log.Logger

	// fee is what this chain charges to admit a shielded transaction at the
	// HTTP entry, before it reaches the mempool. Consensus-internal paths
	// bypass it.
	fee chain.Fee
}

// Initialize initializes the VM
func (vm *VM) Initialize(
	ctx context.Context,
	init vmcore.Init,
) error {
	vm.rt = init.Runtime
	vm.toEngine = init.ToEngine
	vm.log = init.Log

	if vm.rt == nil {
		return errors.New("runtime is nil")
	}
	if init.DB == nil {
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
	vm.chain = chain.New[chain.Block](init.DB, vm.reload)

	// Parse configuration or use defaults
	if len(init.Config) > 0 {
		if err := json.Unmarshal(init.Config, &vm.config); err != nil {
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
	utxoDB, err := NewUTXODB(vm.chain.View(), vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize UTXO DB: %w", err)
	}
	vm.utxoDB = utxoDB

	// Initialize nullifier database
	nullifierDB, err := NewNullifierDB(vm.chain.View(), vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize nullifier DB: %w", err)
	}
	vm.nullifierDB = nullifierDB

	// Initialize state tree
	stateTree, err := NewStateTree(vm.chain.View(), vm.log)
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
	addressManager, err := NewAddressManager(vm.chain.Base(), vm.config.EnablePrivateAddresses, vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize address manager: %w", err)
	}
	vm.addressManager = addressManager

	// Initialize mempool
	vm.mempool = NewMempool(1000, vm.log) // Max 1000 pending txs

	// Z-Chain accepts user-submitted shielded txs, so it declares the floor;
	// the node's boot-time Validate refuses a zero-fee user-facing chain.
	var networkID uint32
	if init.Runtime != nil {
		networkID = init.Runtime.NetworkID
	}
	vm.fee = chain.Floor(networkID)
	if err := fee.Validate(vm.fee.Policy()); err != nil {
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

	_, fresh, err := vm.chain.Open(vm.genesisBlock, vm.parseBlock)
	if err != nil {
		return err
	}
	if fresh {
		// The genesis allocation is the one mutation outside a block, and it is
		// committed on its own: staged, it would ride on whichever block landed
		// first and vanish from a chain that never accepted one.
		if err := vm.chain.Seed(func(database.Database) error {
			return vm.processGenesisTransactions(genesis)
		}); err != nil {
			return err
		}
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

// BuildBlock builds a new block. Reading the tip and registering the block on
// it happen in one step, so nothing can be accepted in between and leave the
// proposal hanging off a parent that is no longer the tip.
func (vm *VM) BuildBlock(ctx context.Context) (vmchain.Block, error) {
	built, err := vm.chain.Propose(func(parent chain.Block) (chain.Block, error) {
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

		block := &Block{
			ParentID_:      parent.ID(),
			BlockHeight:    parent.Height() + 1,
			BlockTimestamp: time.Now().Unix(),
			Txs:            validTxs,
			vm:             vm,
		}
		block.StateRoot = vm.computeStateRoot(validTxs)
		block.ID_ = block.computeID()

		vm.log.Debug("Built new block",
			log.String("blockID", block.ID().String()),
			log.Uint64("height", block.BlockHeight),
			log.Int("txCount", len(validTxs)),
		)
		return block, nil
	})
	if err != nil {
		return nil, err
	}
	return built.(*Block), nil
}

// ParseBlock parses a block from bytes
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (vmchain.Block, error) {
	block := &Block{vm: vm}
	if err := parseBlockBytes(blockBytes, block); err != nil {
		return nil, err
	}
	block.ID_ = block.computeID()
	return block, nil
}

// parseBlock decodes a block belonging to this VM. The store reads accepted
// blocks back through it, so there is one decoder rather than one per caller.
func (vm *VM) parseBlock(raw []byte) (chain.Block, error) {
	block := &Block{vm: vm}
	if err := parseBlockBytes(raw, block); err != nil {
		return nil, err
	}
	block.ID_ = block.computeID()
	return block, nil
}

// GetBlock retrieves a block by ID
func (vm *VM) GetBlock(ctx context.Context, blkID ids.ID) (vmchain.Block, error) {
	if blkID == vm.genesisBlock.ID() {
		return vm.genesisBlock, nil
	}
	decided, err := vm.chain.Block(blkID, vm.parseBlock)
	if err != nil {
		return nil, err
	}
	// A vertex is a decision this chain makes but not a block the engine can
	// take, so asking for one by block id is answered as a miss rather than
	// with something the caller cannot use.
	blk, ok := decided.(*Block)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a block", chain.ErrNoBlock, blkID)
	}
	return blk, nil
}

// reload rebuilds the caches the three stores keep beside the database. It runs
// after a block's writes have been discarded, so a cache that had already
// recorded that block's spends, outputs or root stops claiming them.
func (vm *VM) reload() error {
	if err := vm.nullifierDB.reload(); err != nil {
		return err
	}
	if err := vm.utxoDB.reload(); err != nil {
		return err
	}
	return vm.stateTree.reload()
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

	if err := vm.chain.Close(); err != nil {
		return err
	}
	return vm.chain.Base().Close()
}

// Version returns the VM version
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version.String(), nil
}

// HealthCheck performs a health check
func (vm *VM) HealthCheck(ctx context.Context) (vmchain.HealthResult, error) {
	_, height := vm.chain.Tip()
	return vmchain.HealthResult{
		Healthy: true,
		Details: map[string]string{
			"utxoCount":       fmt.Sprintf("%d", vm.utxoDB.GetUTXOCount()),
			"nullifierCount":  fmt.Sprintf("%d", vm.nullifierDB.GetNullifierCount()),
			"lastBlockHeight": fmt.Sprintf("%d", height),
			"mempoolSize":     fmt.Sprintf("%d", vm.mempool.Size()),
			"proofCacheSize":  fmt.Sprintf("%d", vm.proofVerifier.GetCacheSize()),
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

// WaitForEvent blocks until there is a transaction to build a block from, or
// the VM stops. Waiting only on the context would mean BuildBlock is never
// called and the chain never leaves genesis, however many transactions the
// mempool has accepted.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	return vm.mempool.WaitForEvent(ctx)
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

// computeStateRoot returns the state root a block carrying txs commits to. It
// reads the tree without mutating it, so BuildBlock and Verify agree and a
// rejected block leaves nothing behind.
func (vm *VM) computeStateRoot(txs []*Transaction) []byte {
	return vm.stateTree.RootAfter(txs)
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
	}

	// Commit genesis to the root so block 1 builds on it, rather than leaving
	// genesis to be re-folded into every later block's root.
	return vm.stateTree.Finalize(vm.stateTree.RootAfter(genesis.InitialTxs))
}

// Additional interface implementations
func (vm *VM) SetPreference(ctx context.Context, blkID ids.ID) error {
	return nil
}

func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	id, _ := vm.chain.Tip()
	return id, nil
}

func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *vmchain.VersionInfo) error {
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
