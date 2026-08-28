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
	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/chains/quantumvm/quantum"
	consensuschain "github.com/luxfi/consensus/engine/chain"
	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/utils/json"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/timer/mockable"
	"github.com/luxfi/version"
	luxvm "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
)

// Version of the QVM
const Version = "1.0.0"

var (
	errNoPendingTxs             = errors.New("quantumvm: no pending transactions")
	errVMShutdown               = errors.New("quantumvm: VM is shutting down")
	errParallelProcessingFailed = errors.New("quantumvm: no pending transaction survived verification")
	errNoBlockAtHeight          = errors.New("quantumvm: no block at height")

	// Compile-time check that *VM satisfies chain.ChainVM (= block.ChainVM)
	// AND the consensus engine's BlockBuilder. Together these prove Q-Chain
	// takes the LINEAR ⅔-stake cert path in the chain manager (buildChain →
	// consensuschain.NewRuntime), not the DAG path. Do NOT add a
	// GetEngine() consensusdag.Engine method: that would route the manager's
	// type switch back to createDAG and bypass the certificate.
	_ chain.ChainVM               = (*VM)(nil)
	_ consensuschain.BlockBuilder = (*VM)(nil)
)

// Store keys. Every key is a distinct length, so no two can collide: a block
// id is 32 bytes, a height index entry is 9, "lastAccepted" is 12 and
// "height" is 6.
var (
	lastAcceptedKey = []byte("lastAccepted")
	tipHeightKey    = []byte("height")
)

// heightKey indexes the accepted block at a height, so a peer asking for
// height n gets an answer without walking the chain.
func heightKey(h uint64) []byte {
	k := make([]byte, 9)
	k[0] = 'h'
	binary.BigEndian.PutUint64(k[1:], h)
	return k
}

// VM implements the Q-chain Virtual Machine with quantum features
type VM struct {
	config.Config

	log          log.Logger
	db           database.Database
	blockchainID ids.ID
	NetworkID    uint32

	// state is the version layer over db. Writes buffer here and reach db
	// only at Commit, which is what makes a block's writes one unit.
	state *versiondb.Database

	// Quantum components
	quantumSigner *quantum.QuantumSigner

	// Hybrid P/Q consensus bridge (connects P-Chain BLS + Q-Chain Corona)
	// Uses Quasar consensus for dual BLS+Corona threshold signatures
	quasarBridge *QuasarBridge

	shuttingDown   bool
	shuttingDownMu sync.RWMutex

	// Transaction processing
	txPool     *TransactionPool
	workerPool *sync.Pool

	clock mockable.Clock

	rpcServer *rpc.Server

	// Fee policy gating user-submitted tx admission (IssueTx).
	// NoUserTxPolicy on Q-Chain; consensus-internal callers bypass it
	// via txPool.AddTransaction.
	feePolicy fee.Policy

	lock sync.RWMutex
}

// Initialize initializes the VM. Implements chain.ChainVM.
func (vm *VM) Initialize(ctx context.Context, init luxvm.Init) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	_ = ctx
	// One place normalises the config, so nothing downstream has to ask again
	// whether a batch size or a cache size is usable.
	if err := vm.Config.Validate(); err != nil {
		return fmt.Errorf("quantumvm: config: %w", err)
	}
	vm.db = init.DB
	if init.Log != nil {
		vm.log = init.Log
	}
	if vm.log == nil {
		vm.log = log.NewNoOpLogger()
	}

	// The node's own identity, which is what a validator signature is
	// attributed to. Without it every node on the chain signs under the same
	// name — see the ValidatorID note below.
	nodeID := ids.EmptyNodeID
	if init.Runtime != nil {
		vm.NetworkID = init.Runtime.NetworkID
		vm.blockchainID = init.Runtime.ChainID
		nodeID = init.Runtime.NodeID
	}

	vm.quantumSigner = quantum.NewQuantumSigner(
		vm.log,
		vm.Config.QuantumAlgorithmVersion,
		vm.Config.QuantumStampWindow,
	)

	vm.txPool = NewTransactionPool(vm.Config.MaxParallelTxs, vm.log)

	// Q-Chain sells no blockspace, so the policy is the committee-only
	// sentinel — a constant, which is why nothing here re-validates it.
	vm.feePolicy = fee.NoUserTxPolicy{}

	vm.workerPool = &sync.Pool{
		New: func() interface{} {
			return &TransactionWorker{
				vm:            vm,
				quantumSigner: vm.quantumSigner,
			}
		},
	}

	vm.state = versiondb.New(vm.db)

	if len(init.Genesis) > 0 {
		vm.log.Info("genesis loaded", "size", len(init.Genesis))
	}

	// A chain with no block cannot answer the frontier query bootstrap starts
	// with, so write height 0 before anything asks.
	if err := vm.seedGenesis(); err != nil {
		return fmt.Errorf("failed to seed genesis: %w", err)
	}

	if err := vm.initializeHTTPHandlers(); err != nil {
		return fmt.Errorf("failed to initialize HTTP handlers: %w", err)
	}

	// ValidatorID is the NODE's id, not the chain's. Both signature legs count
	// DISTINCT ValidatorIDs against the threshold, so naming the chain here
	// gave every node on Q-Chain the same signer identity: each peer's
	// signature arrived as a duplicate of the first, the count never passed
	// one, and quantum finality was unreachable on any threshold above 1.
	quasarBridge, err := NewQuasarBridge(QuasarBridgeConfig{
		ValidatorID: nodeID.String(),
		TotalNodes:  3, // Default 3-node network, can be updated
		Logger:      vm.log,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize Quasar bridge: %w", err)
	}
	vm.quasarBridge = quasarBridge

	vm.log.Info("QVM initialized",
		"quantumStamps", vm.Config.QuantumStampEnabled,
		"corona", vm.Config.CoronaEnabled,
		"threshold", quasarBridge.GetThreshold(),
		"maxParallel", vm.Config.MaxParallelTxs,
	)

	return nil
}

// BuildBlock builds a new block with pending transactions. Implements chain.ChainVM.
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	block, err := vm.buildBlock()
	if err != nil {
		return nil, err
	}
	// Signing reaches the consensus core and waits on it, so it happens with
	// no VM lock held — a Verify arriving meanwhile must not queue behind it.
	vm.signBlockWithQuasar(block)
	return block, nil
}

func (vm *VM) buildBlock() (*Block, error) {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.isShuttingDown() {
		return nil, errVMShutdown
	}

	// Whatever this call leaves behind in the pool has to wake a builder
	// again. The latch holds one signal: two transactions arriving together
	// wake one build, and work the batch limit left over would otherwise sit
	// there until some unrelated transaction happened to arrive.
	defer vm.txPool.signalIfWork()

	pendingTxs := vm.txPool.GetPendingTransactions(vm.Config.ParallelBatchSize)
	if len(pendingTxs) == 0 {
		return nil, errNoPendingTxs
	}

	validTxs, rejected := vm.processTransactionsParallel(pendingTxs)

	// A transaction that cannot verify now will not verify later — a quantum
	// stamp only gets staler. Left in place it holds a pool slot for good, and
	// enough of them fill the pool and stop the chain accepting anything.
	for _, tx := range rejected {
		// It came out of this pool a moment ago under this same lock, so the
		// removal is the reverse of a step that just happened.
		_ = vm.txPool.RemoveTransaction(tx.ID())
	}
	if len(validTxs) == 0 {
		return nil, errParallelProcessingFailed
	}

	parentID := vm.getLastAcceptedID()
	parent, err := vm.blockAt(parentID)
	if err != nil {
		return nil, fmt.Errorf("quantumvm: read tip %s: %w", parentID, err)
	}

	// Never stamp behind the parent. Verify rejects a block that moves chain
	// time backwards, so a node whose clock trails its own tip would otherwise
	// build blocks that it — and every peer — refuses.
	timestamp := vm.clock.Time()
	if timestamp.Before(parent.timestamp) {
		timestamp = parent.timestamp
	}

	// The id is the content hash of the canonical wire (computeID =
	// sha256(Bytes())); it is derived AFTER the structural fields are set, and
	// the wire does not carry the id, so Bytes()/id are independent of ordering.
	block := &Block{
		timestamp:    timestamp,
		height:       parent.height + 1,
		parentID:     parentID,
		transactions: validTxs,
		vm:           vm,
	}
	block.id = block.computeID()

	vm.log.Debug("built block",
		"blockID", block.ID(),
		"height", block.Height(),
		"txCount", len(validTxs),
	)

	return block, nil
}

// ParseBlock parses a block from bytes. Implements chain.ChainVM.
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (chain.Block, error) {
	block, err := parseBlockBytes(vm, blockBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block: %w", err)
	}
	return block, nil
}

// GetBlock retrieves a block by its ID. Implements chain.ChainVM.
func (vm *VM) GetBlock(ctx context.Context, blockID ids.ID) (chain.Block, error) {
	return vm.block(blockID)
}

// block is GetBlock at the concrete type, so callers inside the VM read a
// *Block without an assertion that cannot fail.
func (vm *VM) block(blockID ids.ID) (*Block, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.blockAt(blockID)
}

// blockAt reads a stored block. It takes no lock, so callers already holding
// one can use it — which is the whole point: the exported GetBlock takes the
// read lock, and a caller that took it too would deadlock against any writer
// that arrived in between.
func (vm *VM) blockAt(blockID ids.ID) (*Block, error) {
	blockBytes, err := vm.state.Get(blockID[:])
	if err != nil {
		return nil, fmt.Errorf("failed to get block %s: %w", blockID, err)
	}
	return parseBlockBytes(vm, blockBytes)
}

// SetState sets the VM state. Implements chain.ChainVM.
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	vm.log.Info("QVM state transition", "state", state)
	return nil
}

// Shutdown gracefully shuts down the VM
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.shuttingDownMu.Lock()
	alreadyDown := vm.shuttingDown
	vm.shuttingDown = true
	vm.shuttingDownMu.Unlock()
	if alreadyDown {
		return nil
	}

	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.txPool != nil {
		vm.txPool.Close()
	}
	if vm.state != nil {
		if err := vm.state.Close(); err != nil {
			vm.log.Error("failed to close state", "error", err)
		}
	}

	vm.log.Info("QVM shutdown complete")
	return nil
}

// processTransactionsParallel verifies and executes the batch, reporting both
// what survived and what did not. The caller needs both: the survivors go in
// the block, and the rest have to leave the pool.
func (vm *VM) processTransactionsParallel(txs []Transaction) (valid, rejected []Transaction) {
	batchSize := vm.Config.ParallelBatchSize

	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < len(txs); i += batchSize {
		end := i + batchSize
		if end > len(txs) {
			end = len(txs)
		}

		wg.Add(1)
		go func(batch []Transaction) {
			defer wg.Done()

			worker := vm.workerPool.Get().(*TransactionWorker)
			defer vm.workerPool.Put(worker)

			okBatch, badBatch := worker.ProcessBatch(batch)

			mu.Lock()
			valid = append(valid, okBatch...)
			rejected = append(rejected, badBatch...)
			mu.Unlock()
		}(txs[i:end])
	}

	wg.Wait()
	return valid, rejected
}

// Quasar signs the block for the CONSENSUS layer, which is where a block-level
// signature belongs: a cert is a quorum's statement about a block, verifiable by
// anyone holding the validator set. It is deliberately not a field on the block.
//
// A per-block stamp cannot be one. The block id is sha256 of its own bytes, so a
// stamp on the wire makes the id depend on WHO signed and two honest nodes compute
// two ids for one block -- a fork by construction, the same hazard seedGenesis
// avoids by refusing to put wall-clock time in a block. Kept off the wire instead,
// it exists only on the object the builder made and is gone the moment the block
// is serialized, which is every time it leaves this process.
func (vm *VM) signBlockWithQuasar(block *Block) {
	bridge := vm.GetQuasarBridge()
	if bridge == nil {
		return
	}
	if _, err := bridge.SignBlock(context.Background(), block.ID(), block.Bytes(), block.Height()); err != nil {
		vm.log.Warn("quasar block signing failed", "blockID", block.ID(), "error", err)
		return
	}
	vm.log.Debug("block signed with quasar BLS threshold", "blockID", block.ID(), "height", block.Height())
}

// commitBlock stores the block, indexes it by height and moves the tip — as one
// versiondb commit. A failure anywhere aborts the whole set, so the pointers can
// never name a block the store does not hold. Caller holds vm.lock.
//
// The commit is what makes the write durable. Buffered in the version layer and
// never committed, an accepted block is gone at the next start and the node
// rewinds to genesis, having told its peers it held a tip it cannot serve.
func (vm *VM) commitBlock(b *Block) error {
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, b.height)

	for _, w := range []struct {
		key, value []byte
	}{
		{b.id[:], b.Bytes()},
		{heightKey(b.height), b.id[:]},
		{lastAcceptedKey, b.id[:]},
		{tipHeightKey, heightBytes},
	} {
		if err := vm.state.Put(w.key, w.value); err != nil {
			vm.state.Abort()
			return fmt.Errorf("quantumvm: stage block %s: %w", b.id, err)
		}
	}
	if err := vm.state.Commit(); err != nil {
		vm.state.Abort()
		return fmt.Errorf("quantumvm: commit block %s: %w", b.id, err)
	}
	return nil
}

// seedGenesis writes the height-0 block on a chain that has none, so the VM can
// name a tip the moment it starts.
//
// A VM whose last-accepted is empty answers the bootstrap frontier query with no
// block, and an answer naming no block is not a responder — it neither backs a
// tip nor counts toward the response floor (see tally in the node's
// chains/bootstrap_trust.go). Every node then reads every other node as silent,
// so the beacon floor is unreachable and each waits on the others for as long as
// the chain runs. State derived lazily from config is enough to EXECUTE against,
// but consensus starts by asking what block you hold, and "none" is not an
// answer it can build a quorum from.
//
// The block is a constant, so every node computes one id alone: fixed timestamp,
// height 0, empty parent, no transactions. Wall-clock time here would give each
// node a different id for the same block and make the repair a fork.
func (vm *VM) seedGenesis() error {
	if vm.getLastAcceptedID() != ids.Empty {
		return nil
	}

	block := &Block{
		timestamp: time.Unix(0, 0).UTC(),
		height:    0,
		parentID:  ids.Empty,
		vm:        vm,
	}
	block.id = block.computeID()

	if err := vm.commitBlock(block); err != nil {
		return err
	}

	vm.log.Info("genesis block written", "blockID", block.id, "height", block.height)
	return nil
}

// rpcPath is where the VM's JSON-RPC service is mounted.
const rpcPath = "/rpc"

// initializeHTTPHandlers sets up HTTP handlers
func (vm *VM) initializeHTTPHandlers() error {
	vm.rpcServer = rpc.NewServer()

	vm.rpcServer.RegisterCodec(json.NewCodec(), "application/json")
	vm.rpcServer.RegisterCodec(json.NewCodec(), "application/json;charset=UTF-8")
	return vm.rpcServer.RegisterService(&Service{vm: vm}, "quantumvm")
}

// isShuttingDown returns true if VM is shutting down
func (vm *VM) isShuttingDown() bool {
	vm.shuttingDownMu.RLock()
	defer vm.shuttingDownMu.RUnlock()
	return vm.shuttingDown
}

// getHeight returns current blockchain height
func (vm *VM) getHeight() uint64 {
	heightBytes, err := vm.state.Get(tipHeightKey)
	if err != nil || len(heightBytes) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(heightBytes)
}

// getLastAcceptedID returns the last accepted block ID
func (vm *VM) getLastAcceptedID() ids.ID {
	lastAcceptedBytes, err := vm.state.Get(lastAcceptedKey)
	if err != nil || len(lastAcceptedBytes) != 32 {
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

// HealthCheck returns the health status of the VM. Implements chain.ChainVM,
// whose signature carries an error the VM has no way to produce.
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	return vm.health(), nil
}

// health is the one place the VM says how it is doing.
func (vm *VM) health() chain.HealthResult {
	return chain.HealthResult{
		Healthy: !vm.isShuttingDown(),
		Details: map[string]string{
			"version":        Version,
			"quantumEnabled": fmt.Sprintf("%v", vm.Config.QuantumStampEnabled),
			"coronaEnabled":  fmt.Sprintf("%v", vm.Config.CoronaEnabled),
			"pendingTxs":     fmt.Sprintf("%d", vm.txPool.PendingCount()),
		},
	}
}

// CreateHandlers returns HTTP handlers for the VM
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{rpcPath: vm.rpcServer}, nil
}

// CreateStaticHandlers returns static HTTP handlers
func (vm *VM) CreateStaticHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return nil, nil
}

// NewHTTPHandler returns the VM's HTTP handler. Implements chain.ChainVM.
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.Handle(rpcPath, vm.rpcServer)
	return mux, nil
}

// SetPreference sets the preferred block. Implements chain.ChainVM.
// Q-Chain uses BLS+Corona threshold finality rather than preference,
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

// GetBlockIDAtHeight answers what block this node accepted at a height, from
// the index Accept writes in the same commit as the block itself. A peer
// catching up asks by height; the index is what lets the answer be one read
// rather than a walk back from the tip.
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	raw, err := vm.state.Get(heightKey(height))
	if err != nil {
		return ids.Empty, fmt.Errorf("%w %d: %w", errNoBlockAtHeight, height, err)
	}
	if len(raw) != 32 {
		return ids.Empty, fmt.Errorf("%w %d: index holds %d bytes", errNoBlockAtHeight, height, len(raw))
	}
	var id ids.ID
	copy(id[:], raw)
	return id, nil
}

// WaitForEvent blocks until there is a transaction to build a block from, or
// the VM stops. Waiting only on the context would mean BuildBlock is never
// called and the chain never leaves genesis, however many transactions the pool
// has accepted.
func (vm *VM) WaitForEvent(ctx context.Context) (luxvm.Message, error) {
	return vm.txPool.WaitForEvent(ctx)
}

// GetQuasarBridge returns the Quasar hybrid consensus bridge
// This provides BLS + Corona dual threshold signatures for PQ finality
func (vm *VM) GetQuasarBridge() *QuasarBridge {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.quasarBridge
}

// StampBlock implements QChainStamper for hybrid finality: a Quasar BLS+Corona
// threshold signature when the bridge is up, an ML-DSA signature otherwise.
func (vm *VM) StampBlock(blockID ids.ID, pChainHeight uint64, message []byte) (interface{}, error) {
	ctx := context.Background()

	if bridge := vm.GetQuasarBridge(); bridge != nil && blockID != ids.Empty {
		hybridSig, err := bridge.SignBlock(ctx, blockID, message, pChainHeight)
		if err == nil {
			vm.log.Info("Quasar BLS stamp created",
				"blockID", blockID,
				"pChainHeight", pChainHeight,
				"threshold", bridge.GetThreshold(),
			)
			return hybridSig, nil
		}
		vm.log.Warn("Quasar BLS stamp failed, using ML-DSA fallback", "error", err)
	}

	key, err := vm.quantumSigner.GenerateCoronaKey()
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

// VerifyStamp implements QChainStamper for quasar finality
// Supports both Quasar QuasarSignature and ML-DSA QuantumSignature
func (vm *VM) VerifyStamp(stamp interface{}) error {
	switch s := stamp.(type) {
	case *quasar.QuasarSignature:
		if s.BLS == nil || len(s.BLS.Signature) == 0 {
			return errors.New("quantumvm: invalid Quasar BLS signature")
		}
		return nil

	case *quasar.AggregatedSignature:
		bridge := vm.GetQuasarBridge()
		if bridge == nil {
			return errors.New("quantumvm: no Quasar bridge to check the threshold against")
		}
		if len(s.BLSAggregated) == 0 || s.SignerCount < bridge.GetThreshold() {
			return errors.New("quantumvm: insufficient aggregated signature")
		}
		return nil

	case *quantum.QuantumSignature:
		if len(s.Signature) == 0 || len(s.QuantumStamp) == 0 {
			return errors.New("quantumvm: invalid quantum stamp structure")
		}
		return nil

	default:
		return errors.New("quantumvm: unsupported stamp type")
	}
}
