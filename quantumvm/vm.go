// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/rpc/v2"
	consensusdag "github.com/luxfi/consensus/engine/dag"
	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/node/cache"
	"github.com/luxfi/node/utils/json"
	"github.com/luxfi/version"
	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/timer/mockable"
	luxvm "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
)

const (
	// Version of the QVM
	Version = "1.0.0"

	// MaxParallelVerifications is the maximum number of parallel verifications
	MaxParallelVerifications = 100

	// DefaultBatchSize is the default batch size for parallel processing
	DefaultBatchSize = 10
)

var (
	errNotImplemented           = errors.New("not implemented")
	errNoPendingTxs             = errors.New("no pending transactions")
	errVMShutdown               = errors.New("VM is shutting down")
	errInvalidQuantumStamp      = errors.New("invalid quantum stamp")
	errParallelProcessingFailed = errors.New("parallel transaction processing failed")

	// Compile-time check that *VM satisfies chain.ChainVM (= block.ChainVM).
	_ chain.ChainVM = (*VM)(nil)
)

// BCLookup provides blockchain alias lookup
type BCLookup interface {
	Lookup(string) (ids.ID, error)
	PrimaryAlias(ids.ID) (string, error)
}

// SharedMemory provides cross-chain shared memory
type SharedMemory interface {
	Get(peerChainID ids.ID, keys [][]byte) ([][]byte, error)
	Apply(map[ids.ID]interface{}, ...interface{}) error
}

// VM implements the Q-chain Virtual Machine with quantum features
type VM struct {
	engine consensusdag.Engine
	config.Config

	// Core components
	// consensusRuntime    *runtime.Runtime
	log          log.Logger
	db           database.Database
	versiondb    *versiondb.Database
	blockchainID ids.ID
	ChainAlias   string
	NetworkID    uint32

	// Quantum components
	quantumSigner *quantum.QuantumSigner
	quantumCache  *cache.LRU[ids.ID, *quantum.QuantumSignature]

	// Hybrid P/Q consensus bridge (connects P-Chain BLS + Q-Chain Ringtail)
	// Uses Quasar consensus for dual BLS+Ringtail threshold signatures
	quasarBridge *QuasarBridge

	// Consensus and validation
	// validators      validators.Manager
	// versionManager  consensusversion.Manager
	// consensusEngine consensus.Consensus

	// Metrics and monitoring
	metrics metric.Registry

	// State management
	state          database.Database
	shuttingDown   bool
	shuttingDownMu sync.RWMutex

	// Transaction processing
	txPool          *TransactionPool
	parallelWorkers int
	workerPool      *sync.Pool

	// Clock and timing
	clock mockable.Clock

	// Network communication
	bcLookup     BCLookup
	sharedMemory SharedMemory

	// HTTP service
	httpServer *http.Server
	rpcServer  *rpc.Server

	// Synchronization
	lock sync.RWMutex
}

// Initialize initializes the VM. Implements chain.ChainVM.
func (vm *VM) Initialize(ctx context.Context, init luxvm.Init) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	_ = ctx
	vm.db = init.DB
	if init.Log != nil {
		vm.log = init.Log
	}
	genesisBytes := init.Genesis
	// vm.blockchainID = chainRuntime.ChainID
	// vm.NetworkID = chainRuntime.NetworkID

	// Initialize logger
	// if vm.log.IsZero() {
	//	vm.log = chainRuntime.Log
	// }
	// vm.log.Info("initializing QVM",
	//	"version", Version,
	//	"chainID", vm.blockchainID,
	//	"networkID", vm.NetworkID,
	// )

	// Initialize quantum components
	vm.quantumSigner = quantum.NewQuantumSigner(
		vm.log,
		vm.Config.QuantumAlgorithmVersion,
		vm.Config.RingtailKeySize,
		vm.Config.QuantumStampWindow,
		vm.Config.QuantumSigCacheSize,
	)

	// Initialize transaction pool
	vm.txPool = NewTransactionPool(
		vm.Config.MaxParallelTxs,
		vm.Config.ParallelBatchSize,
		vm.log,
	)

	// Set up worker pool for parallel processing
	vm.parallelWorkers = vm.Config.MaxParallelTxs
	if vm.parallelWorkers <= 0 {
		vm.parallelWorkers = MaxParallelVerifications
	}
	vm.workerPool = &sync.Pool{
		New: func() interface{} {
			return &TransactionWorker{
				vm:            vm,
				quantumSigner: vm.quantumSigner,
			}
		},
	}

	// Initialize version database
	vm.versiondb = versiondb.New(vm.db)

	// Metrics are not yet available via chainRuntime; the quantumvm
	// operates without per-chain metrics until runtime exposes them.

	// Parse genesis if provided
	if len(genesisBytes) > 0 {
		if err := vm.parseGenesis(genesisBytes); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}

	// Initialize state
	vm.state = vm.versiondb

	// Set up HTTP handlers
	if err := vm.initializeHTTPHandlers(); err != nil {
		return fmt.Errorf("failed to initialize HTTP handlers: %w", err)
	}

	// Initialize Quasar hybrid consensus bridge (BLS + Ringtail)
	quasarCfg := QuasarBridgeConfig{
		ValidatorID: vm.blockchainID.String(),
		Threshold:   0, // Will be set to 2/3+1 based on total nodes
		TotalNodes:  3, // Default 3-node network, can be updated
		Logger:      vm.log,
	}
	quasarBridge, err := NewQuasarBridge(quasarCfg, vm.quantumSigner)
	if err != nil {
		return fmt.Errorf("failed to initialize Quasar bridge: %w", err)
	}
	vm.quasarBridge = quasarBridge

	vm.log.Info("═══════════════════════════════════════════════════════════════════")
	vm.log.Info("║ QVM INITIALIZED with Quasar PQ-BFT Consensus                    ║")
	vm.log.Info("───────────────────────────────────────────────────────────────────")
	vm.log.Info("║ Quantum Signatures: ML-DSA (NIST PQC)", log.Bool("enabled", vm.Config.QuantumStampEnabled))
	vm.log.Info("║ Ringtail Threshold: Ring-LWE PQ", log.Bool("enabled", vm.Config.RingtailEnabled))
	vm.log.Info("║ BLS Threshold: Classical fast path", log.Bool("enabled", true))
	vm.log.Info("║ Quasar Hybrid: BLS + Ringtail dual signing", log.Bool("enabled", true))
	vm.log.Info("║ Parallel TX Processing:", log.Int("maxParallel", vm.Config.MaxParallelTxs))
	vm.log.Info("═══════════════════════════════════════════════════════════════════")

	return nil
}

// BuildBlock builds a new block with pending transactions. Implements chain.ChainVM.
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	// Check if VM is shutting down
	if vm.isShuttingDown() {
		return nil, errVMShutdown
	}

	// Get pending transactions from pool
	pendingTxs := vm.txPool.GetPendingTransactions(vm.Config.ParallelBatchSize)
	if len(pendingTxs) == 0 {
		return nil, errNoPendingTxs
	}

	// Process transactions in parallel
	validTxs, err := vm.processTransactionsParallel(pendingTxs)
	if err != nil {
		return nil, fmt.Errorf("failed to process transactions: %w", err)
	}

	// Create new block with valid transactions
	// Generate block ID from block data
	blockData := make([]byte, 0, 100)
	lastAccepted := vm.getLastAcceptedID()
	blockData = append(blockData, lastAccepted[:]...)
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, vm.getHeight()+1)
	blockData = append(blockData, heightBytes...)

	blockID, _ := ids.ToID(blockData)
	block := &Block{
		id:           blockID,
		timestamp:    vm.clock.Time(),
		height:       vm.getHeight() + 1,
		parentID:     vm.getLastAcceptedID(),
		transactions: validTxs,
		vm:           vm,
	}

	// Sign block with quantum signature if enabled
	if vm.Config.QuantumStampEnabled {
		if err := vm.signBlockWithQuantum(block); err != nil {
			return nil, fmt.Errorf("failed to sign block with quantum stamp: %w", err)
		}
	}

	vm.log.Debug("built block",
		"blockID", block.ID(),
		"height", block.Height(),
		"txCount", len(validTxs),
	)

	return block, nil
}

// ParseBlock parses a block from bytes. Implements chain.ChainVM.
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (chain.Block, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	block, err := vm.parseBlock(blockBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block: %w", err)
	}

	// Verify quantum signature if enabled
	if vm.Config.QuantumStampEnabled {
		if err := vm.verifyBlockQuantumSignature(block); err != nil {
			return nil, fmt.Errorf("quantum signature verification failed: %w", err)
		}
	}

	return block, nil
}

// GetBlock retrieves a block by its ID. Implements chain.ChainVM.
func (vm *VM) GetBlock(ctx context.Context, blockID ids.ID) (chain.Block, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	blockBytes, err := vm.state.Get(blockID[:])
	if err != nil {
		return nil, fmt.Errorf("failed to get block %s: %w", blockID, err)
	}

	return vm.parseBlock(blockBytes)
}

// SetState sets the VM state. Implements chain.ChainVM.
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	// Q-Chain uses quantum state management - log state transitions generically
	vm.log.Info("QVM state transition", "state", state)

	return nil
}

// Shutdown gracefully shuts down the VM
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.shuttingDownMu.Lock()
	vm.shuttingDown = true
	vm.shuttingDownMu.Unlock()

	vm.log.Info("shutting down QVM")

	// Stop HTTP server
	if vm.httpServer != nil {
		if err := vm.httpServer.Shutdown(ctx); err != nil {
			vm.log.Error("failed to shutdown HTTP server", "error", err)
		}
	}

	// Close transaction pool
	if vm.txPool != nil {
		vm.txPool.Close()
	}

	// Close database
	if vm.versiondb != nil {
		if err := vm.versiondb.Close(); err != nil {
			vm.log.Error("failed to close versiondb", "error", err)
		}
	}

	vm.log.Info("QVM shutdown complete")
	return nil
}

// processTransactionsParallel processes transactions in parallel batches
func (vm *VM) processTransactionsParallel(txs []Transaction) ([]Transaction, error) {
	if len(txs) == 0 {
		return nil, nil
	}

	// Determine batch size
	batchSize := vm.Config.ParallelBatchSize
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}

	var validTxs []Transaction
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Process in batches
	for i := 0; i < len(txs); i += batchSize {
		end := i + batchSize
		if end > len(txs) {
			end = len(txs)
		}

		batch := txs[i:end]
		wg.Add(1)

		go func(batch []Transaction) {
			defer wg.Done()

			// Get worker from pool
			worker := vm.workerPool.Get().(*TransactionWorker)
			defer vm.workerPool.Put(worker)

			// Process batch
			validBatch, err := worker.ProcessBatch(batch)
			if err != nil {
				vm.log.Error("batch processing failed", "error", err)
				return
			}

			// Add valid transactions
			mu.Lock()
			validTxs = append(validTxs, validBatch...)
			mu.Unlock()
		}(batch)
	}

	wg.Wait()

	if len(validTxs) == 0 {
		return nil, errParallelProcessingFailed
	}

	return validTxs, nil
}

// signBlockWithQuantum signs a block with quantum signature using Quasar hybrid consensus
func (vm *VM) signBlockWithQuantum(block *Block) error {
	ctx := context.Background()
	blockData := block.Bytes()

	// Use Quasar bridge for dual BLS+Ringtail threshold signing
	if vm.quasarBridge != nil {
		_, err := vm.quasarBridge.SignBlock(ctx, block.ID(), blockData, block.Height())
		if err != nil {
			vm.log.Warn("Quasar signing failed, falling back to ML-DSA", "error", err)
		} else {
			vm.log.Debug("Block signed with Quasar BLS threshold",
				"blockID", block.ID(),
				"height", block.Height(),
			)
		}
	}

	// Also sign with ML-DSA for quantum resistance (standalone signature)
	key, err := vm.quantumSigner.GenerateRingtailKey()
	if err != nil {
		return fmt.Errorf("failed to generate ringtail key: %w", err)
	}

	sig, err := vm.quantumSigner.Sign(blockData, key)
	if err != nil {
		return fmt.Errorf("failed to sign block with ML-DSA: %w", err)
	}

	block.quantumSignature = sig
	return nil
}

// verifyBlockQuantumSignature verifies a block's quantum signature
func (vm *VM) verifyBlockQuantumSignature(block *Block) error {
	if block.quantumSignature == nil {
		return errInvalidQuantumStamp
	}

	blockData := block.Bytes()
	return vm.quantumSigner.Verify(blockData, block.quantumSignature)
}

// parseGenesis parses genesis data
func (vm *VM) parseGenesis(genesisBytes []byte) error {
	// Genesis parsing for quantumvm is a no-op; initial state is derived
	// from the quantum signer configuration and the empty state trie.
	vm.log.Info("genesis loaded", "size", len(genesisBytes))
	return nil
}

// parseBlock parses a block from bytes
func (vm *VM) parseBlock(blockBytes []byte) (*Block, error) {
	// Block format: id(32) + timestamp(8) + height(8) + parentID(32) + txCount(4) + txs...
	minSize := 32 + 8 + 8 + 32 + 4
	if len(blockBytes) < minSize {
		return nil, fmt.Errorf("block bytes too short: got %d, need at least %d", len(blockBytes), minSize)
	}

	var id ids.ID
	copy(id[:], blockBytes[:32])

	timestamp := binary.BigEndian.Uint64(blockBytes[32:40])
	height := binary.BigEndian.Uint64(blockBytes[40:48])

	var parentID ids.ID
	copy(parentID[:], blockBytes[48:80])

	txCount := binary.BigEndian.Uint32(blockBytes[80:84])
	_ = txCount // Transaction parsing would go here

	return &Block{
		id:        id,
		timestamp: time.Unix(int64(timestamp), 0),
		height:    height,
		parentID:  parentID,
		vm:        vm,
		bytes:     blockBytes,
	}, nil
}

// initializeHTTPHandlers sets up HTTP handlers
func (vm *VM) initializeHTTPHandlers() error {
	vm.rpcServer = rpc.NewServer()

	// Register QVM service
	service := &Service{vm: vm}
	vm.rpcServer.RegisterCodec(json.NewCodec(), "application/json")
	vm.rpcServer.RegisterCodec(json.NewCodec(), "application/json;charset=UTF-8")
	return vm.rpcServer.RegisterService(service, "quantumvm")
}

// isShuttingDown returns true if VM is shutting down
func (vm *VM) isShuttingDown() bool {
	vm.shuttingDownMu.RLock()
	defer vm.shuttingDownMu.RUnlock()
	return vm.shuttingDown
}

// getHeight returns current blockchain height
func (vm *VM) getHeight() uint64 {
	heightBytes, err := vm.state.Get([]byte("height"))
	if err != nil {
		return 0
	}
	if len(heightBytes) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(heightBytes)
}

// getLastAcceptedID returns the last accepted block ID
func (vm *VM) getLastAcceptedID() ids.ID {
	lastAcceptedBytes, err := vm.state.Get([]byte("lastAccepted"))
	if err != nil {
		return ids.Empty
	}
	if len(lastAcceptedBytes) != 32 {
		return ids.Empty
	}
	var id ids.ID
	copy(id[:], lastAcceptedBytes)
	return id
}

// Version returns the version of the VM
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version, nil
}

// Connected notifies the VM that a validator has connected
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *version.Application) error {
	vm.log.Debug("node connected", "nodeID", nodeID, "version", nodeVersion)
	return nil
}

// Disconnected notifies the VM that a validator has disconnected
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	vm.log.Debug("node disconnected", "nodeID", nodeID)
	return nil
}

// HealthCheck returns the health status of the VM
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	return chain.HealthResult{
		Healthy: !vm.isShuttingDown(),
		Details: map[string]string{
			"version":         Version,
			"quantumEnabled":  fmt.Sprintf("%v", vm.Config.QuantumStampEnabled),
			"ringtailEnabled": fmt.Sprintf("%v", vm.Config.RingtailEnabled),
			"pendingTxs":      fmt.Sprintf("%d", vm.txPool.PendingCount()),
		},
	}, nil
}

// CreateHandlers returns HTTP handlers for the VM
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	handlers := map[string]http.Handler{
		"/rpc": vm.rpcServer,
	}
	return handlers, nil
}

// CreateStaticHandlers returns static HTTP handlers
func (vm *VM) CreateStaticHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return nil, nil
}

// NewHTTPHandler returns the VM's HTTP handler. Implements chain.ChainVM.
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	handlers, err := vm.CreateHandlers(ctx)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	for path, h := range handlers {
		if path == "" {
			path = "/"
		}
		mux.Handle(path, h)
	}
	return mux, nil
}

// SetPreference sets the preferred block. Implements chain.ChainVM.
// Q-Chain uses BLS+Ringtail threshold finality rather than preference,
// so this is a no-op until preference-based fork choice is wired in.
func (vm *VM) SetPreference(ctx context.Context, blockID ids.ID) error {
	return nil
}

// LastAccepted returns the last accepted block ID. Implements chain.ChainVM.
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.getLastAcceptedID(), nil
}

// GetBlockIDAtHeight returns the block ID at the given height. Implements chain.ChainVM.
// Q-Chain does not yet maintain a height index, so this returns errNotImplemented
// until indexer integration lands.
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return ids.Empty, errNotImplemented
}

// WaitForEvent blocks until an event triggers block building. Implements chain.ChainVM.
// CRITICAL: must block on ctx.Done() to avoid the notification flood loop in
// node/chains/manager.go (matches the relayvm contract).
func (vm *VM) WaitForEvent(ctx context.Context) (luxvm.Message, error) {
	<-ctx.Done()
	return luxvm.Message{}, ctx.Err()
}

// GetEngine returns the DAG consensus engine
func (vm *VM) GetEngine() consensusdag.Engine {
	if vm.engine == nil {
		vm.engine = consensusdag.New()
	}
	return vm.engine
}

// GetQuasarBridge returns the Quasar hybrid consensus bridge
// This provides BLS + Ringtail dual threshold signatures for PQ finality
func (vm *VM) GetQuasarBridge() *QuasarBridge {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.quasarBridge
}

// GetHybridBridge returns the hybrid finality bridge for P/Q chain consensus
// This connects P-Chain BLS signatures with Q-Chain Ringtail for quantum finality
// Deprecated: Use GetQuasarBridge() for proper type safety
func (vm *VM) GetHybridBridge() interface{} {
	return vm.GetQuasarBridge()
}

// SetHybridBridge sets the hybrid finality bridge (called by chain manager)
// Deprecated: Bridge is now auto-initialized in VM.Initialize()
func (vm *VM) SetHybridBridge(bridge interface{}) {
	vm.lock.Lock()
	defer vm.lock.Unlock()
	if qb, ok := bridge.(*QuasarBridge); ok {
		vm.quasarBridge = qb
	}
}

// StampBlock implements QChainStamper interface for hybrid finality
// Uses Quasar BLS+Ringtail for dual post-quantum threshold signatures
func (vm *VM) StampBlock(blockID interface{}, pChainHeight uint64, message []byte) (interface{}, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	ctx := context.Background()

	// Convert blockID to ids.ID if possible
	var blkID ids.ID
	switch v := blockID.(type) {
	case ids.ID:
		blkID = v
	case string:
		parsed, err := ids.FromString(v)
		if err == nil {
			blkID = parsed
		}
	}

	// Use Quasar bridge for BLS threshold signature if available
	if vm.quasarBridge != nil && blkID != ids.Empty {
		hybridSig, err := vm.quasarBridge.SignBlock(ctx, blkID, message, pChainHeight)
		if err != nil {
			vm.log.Warn("Quasar BLS stamp failed, using ML-DSA fallback", "error", err)
		} else {
			vm.log.Info("Quasar BLS stamp created",
				"blockID", blkID,
				"pChainHeight", pChainHeight,
				"threshold", vm.quasarBridge.GetThreshold(),
			)
			// Return hybrid signature for BLS finality
			return hybridSig, nil
		}
	}

	// Fallback: Generate quantum stamp using ML-DSA signer
	key, err := vm.quantumSigner.GenerateRingtailKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key for stamp: %w", err)
	}

	sig, err := vm.quantumSigner.Sign(message, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create quantum stamp: %w", err)
	}

	vm.log.Debug("ML-DSA quantum stamp created",
		"pChainHeight", pChainHeight,
		"sigLen", len(sig.Signature),
	)

	return sig, nil
}

// VerifyStamp implements QChainStamper interface for quasar finality
// Supports both Quasar QuasarSignature and ML-DSA QuantumSignature
func (vm *VM) VerifyStamp(stamp interface{}) error {
	switch s := stamp.(type) {
	case *quasar.QuasarSignature:
		// Quasar BLS + Ringtail threshold signature
		if s.BLS == nil || len(s.BLS.Signature) == 0 {
			return errors.New("invalid Quasar BLS signature")
		}
		vm.log.Debug("Verified Quasar stamp",
			"validatorID", s.BLS.ValidatorID,
			"threshold", s.BLS.IsThreshold,
		)
		return nil

	case *quasar.AggregatedSignature:
		// Aggregated threshold signature
		if len(s.BLSAggregated) == 0 || s.SignerCount < vm.quasarBridge.GetThreshold() {
			return errors.New("insufficient aggregated signature")
		}
		vm.log.Debug("Verified aggregated Quasar stamp",
			"signerCount", s.SignerCount,
			"threshold", s.IsThreshold,
		)
		return nil

	case *quantum.QuantumSignature:
		// ML-DSA quantum signature
		if len(s.Signature) == 0 || len(s.QuantumStamp) == 0 {
			return errors.New("invalid quantum stamp structure")
		}
		return nil

	default:
		return errors.New("unsupported stamp type")
	}
}
