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
	"github.com/luxfi/chains/internal/codec"
	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/chains/quantumvm/quantum"
	consensuschain "github.com/luxfi/consensus/engine/chain"
	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
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
	errNoIdentity               = errors.New("quantumvm: the node has no identity to sign under")
	errTipUnreadable            = errors.New("quantumvm: the chain tip cannot be read")
	errNotTheTip                = errors.New("quantumvm: block does not extend the tip")
	errClockBehindTip           = errors.New("quantumvm: the node's clock trails its own tip beyond the skew allowance")
	errNoStamp                  = errors.New("quantumvm: no stamp to check")

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
	// attributed to, and the chain it is serving, which is what its blocks
	// belong to. A VM with neither runs, signs as nobody and produces blocks
	// every other Q-Chain will also accept — so it does not run.
	if init.Runtime == nil || init.Runtime.NodeID == ids.EmptyNodeID {
		return errNoIdentity
	}
	vm.NetworkID = init.Runtime.NetworkID
	vm.blockchainID = init.Runtime.ChainID
	nodeID := init.Runtime.NodeID

	signer, err := quantum.NewQuantumSigner(
		vm.log,
		vm.Config.QuantumAlgorithmVersion,
		vm.Config.QuantumStampWindow,
	)
	if err != nil {
		return fmt.Errorf("quantumvm: signer: %w", err)
	}
	vm.quantumSigner = signer

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

	// ValidatorID is the NODE's id, not the chain's. The threshold counts
	// DISTINCT ValidatorIDs, so naming the chain here gave every node on
	// Q-Chain the same signer identity: each peer's signature arrived as a
	// duplicate of the first, the count never passed one, and quantum finality
	// was unreachable on any threshold above 1.
	quasarBridge, err := NewQuasarBridge(QuasarBridgeConfig{
		ValidatorID: nodeID.String(),
		Committee:   vm.Config.Committee,
		Logger:      vm.log,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize Quasar bridge: %w", err)
	}
	vm.quasarBridge = quasarBridge

	vm.log.Info("QVM initialized",
		"quantumStamps", vm.Config.QuantumStampEnabled,
		"corona", vm.Config.CoronaEnabled,
		"committee", quasarBridge.Committee(),
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

	parentID, err := vm.tip()
	if err != nil {
		return nil, err
	}
	parent, err := vm.blockAt(parentID)
	if err != nil {
		return nil, fmt.Errorf("quantumvm: read tip %s: %w", parentID, err)
	}

	// Never stamp behind the parent, and never stamp where Verify will refuse
	// it. A clock that trails the tip by less than the skew allowance is a peer
	// that ran fast, and clamping forward covers it. A clock that trails by
	// MORE is this node's clock being wrong: every block it could build now
	// carries a timestamp its own Verify rejects for exceeding now+skew, so it
	// says so rather than producing blocks nobody — itself included — accepts.
	now := vm.clock.Time()
	if parent.timestamp.After(now.Add(MaxFutureSkew)) {
		return nil, fmt.Errorf("%w: tip is stamped %s, this node reads %s",
			errClockBehindTip, parent.timestamp, now)
	}
	timestamp := now
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
		chainID:      vm.blockchainID,
		networkID:    vm.NetworkID,
		transactions: validTxs,
		vm:           vm,
	}
	if len(block.Bytes()) > MaxBlockSize {
		return nil, fmt.Errorf("%w: %d bytes over %d", errBlockTooLarge, len(block.Bytes()), MaxBlockSize)
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

// processTransactionsParallel verifies the batch, reporting both what survived
// and what did not. The caller needs both: the survivors go in the block, and
// the rest have to leave the pool.
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
	vm.log.Debug("block signed with quasar threshold signature", "blockID", block.ID(), "height", block.Height())
}

// commitBlock makes a block the tip: it admits the block, applies it, stores
// it, indexes it by height and moves the tip pointer. Caller holds vm.lock.
//
// One order, one place, so a block cannot be applied without being admitted or
// stored without being applied. Everything that advances this chain — Accept and
// the genesis seed — comes through here.
//
// A commit EXTENDS the tip: the block names the last-accepted block as its
// parent and sits one height above it. Without that, any block that merely
// verified could be committed — a verified sibling of an old block rewound the
// chain to its height, left every height above indexed to an abandoned branch,
// and served those to bootstrapping peers as canonical. Re-accepting a block
// already accepted did the same, and two siblings both verified, both committed,
// the second silently replacing the first.
//
// The writes then land as ONE versiondb commit: block, height index and tip
// pointer move together or not at all, so a node never restarts holding a tip
// pointer to a block it did not store. And the version layer holds nothing
// across this call: staged writes not discarded here are not discarded at all,
// they are flushed by the next commit that succeeds — an orphan block and a live
// height index arriving with an unrelated block.
func (vm *VM) commitBlock(b *Block) error {
	defer vm.state.Abort()

	if err := b.onThisChain(); err != nil {
		return err
	}
	if err := vm.extendsTip(b); err != nil {
		return err
	}
	if err := b.apply(); err != nil {
		return err
	}

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
			return fmt.Errorf("quantumvm: stage block %s: %w", b.id, err)
		}
	}
	if err := vm.state.Commit(); err != nil {
		return fmt.Errorf("quantumvm: commit block %s: %w", b.id, err)
	}
	return nil
}

// extendsTip is the linear-chain invariant: exactly one block may follow the
// one this node last accepted. An empty chain's tip is no block at no height,
// and the only block that follows it is genesis.
func (vm *VM) extendsTip(b *Block) error {
	tip, err := vm.tip()
	if err != nil {
		return err
	}
	if b.parentID != tip {
		return fmt.Errorf("%w: parent %s, tip %s", errNotTheTip, b.parentID, tip)
	}

	next := uint64(0)
	if tip != ids.Empty {
		h, err := vm.tipHeight()
		if err != nil {
			return err
		}
		next = h + 1
	}
	if b.height != next {
		return fmt.Errorf("%w: height %d, tip expects %d", errNotTheTip, b.height, next)
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
// The block is a constant of the chain it belongs to, so every node on that
// chain computes one id alone: fixed timestamp, height 0, empty parent, no
// transactions, this chain and this network. Wall-clock time here would give
// each node a different id for the same block and make the repair a fork.
func (vm *VM) seedGenesis() error {
	tip, err := vm.tip()
	if err != nil {
		return err
	}
	if tip != ids.Empty {
		return nil
	}

	block := &Block{
		timestamp: time.Unix(0, 0).UTC(),
		height:    0,
		parentID:  ids.Empty,
		chainID:   vm.blockchainID,
		networkID: vm.NetworkID,
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

	vm.rpcServer.RegisterCodec(codec.New(), "application/json")
	vm.rpcServer.RegisterCodec(codec.New(), "application/json;charset=UTF-8")
	return vm.rpcServer.RegisterService(&Service{vm: vm}, "quantumvm")
}

// isShuttingDown returns true if VM is shutting down
func (vm *VM) isShuttingDown() bool {
	vm.shuttingDownMu.RLock()
	defer vm.shuttingDownMu.RUnlock()
	return vm.shuttingDown
}

// tipHeight is the height of the last accepted block, or 0 on a chain that
// holds only genesis.
//
// A read that failed and a height of zero are different facts and this reports
// them differently. Answering 0 for both is what let one transient failure look
// like a chain that had not started: the next block was built at height 1 on a
// chain a thousand blocks long.
func (vm *VM) tipHeight() (uint64, error) {
	raw, err := vm.state.Get(tipHeightKey)
	if errors.Is(err, database.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%w: height: %w", errTipUnreadable, err)
	}
	if len(raw) != 8 {
		return 0, fmt.Errorf("%w: height holds %d bytes", errTipUnreadable, len(raw))
	}
	return binary.BigEndian.Uint64(raw), nil
}

// tip is the id of the last accepted block. It answers ids.Empty with no error
// for exactly one reason — the chain holds no block at all — and an error for
// every other reason it could not read one.
//
// Collapsing those was how a single failed read destroyed a chain: seedGenesis
// reads ids.Empty as "fresh chain" and writes genesis, so one transient error at
// boot committed genesis over a live tip and Initialize returned success. A
// short read did it identically.
func (vm *VM) tip() (ids.ID, error) {
	raw, err := vm.state.Get(lastAcceptedKey)
	if errors.Is(err, database.ErrNotFound) {
		return ids.Empty, nil
	}
	if err != nil {
		return ids.Empty, fmt.Errorf("%w: last accepted: %w", errTipUnreadable, err)
	}
	if len(raw) != 32 {
		return ids.Empty, fmt.Errorf("%w: last accepted holds %d bytes", errTipUnreadable, len(raw))
	}
	var id ids.ID
	copy(id[:], raw)
	return id, nil
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
// Q-Chain finalizes on a verified threshold signature rather than preference,
// so this is a no-op until preference-based fork choice is wired in.
func (vm *VM) SetPreference(ctx context.Context, blockID ids.ID) error {
	return nil
}

// LastAccepted returns the last accepted block ID. Implements chain.ChainVM.
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.tip()
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

// GetQuasarBridge returns the Quasar threshold-signature bridge.
func (vm *VM) GetQuasarBridge() *QuasarBridge {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.quasarBridge
}

// StampBlock attests to a message for the finality bridge: a Quasar validator
// signature when the bridge is up, an ML-DSA signature otherwise.
func (vm *VM) StampBlock(blockID ids.ID, pChainHeight uint64, message []byte) (interface{}, error) {
	ctx := context.Background()

	if bridge := vm.GetQuasarBridge(); bridge != nil && blockID != ids.Empty {
		sig, err := bridge.SignBlock(ctx, blockID, message, pChainHeight)
		if err == nil {
			vm.log.Info("Quasar stamp created",
				"blockID", blockID,
				"pChainHeight", pChainHeight,
				"threshold", bridge.GetThreshold(),
			)
			return sig, nil
		}
		vm.log.Warn("Quasar stamp failed, using ML-DSA fallback", "error", err)
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

// VerifyStamp checks a stamp against the message it claims to attest.
//
// The message is the argument that makes this a verification. Without it there
// was nothing to check a signature against, so each arm could only look at the
// stamp's own shape — and shape is what the sender chose: a two-byte aggregate
// declaring three signers passed, and so did a one-byte BLS signature. A
// self-declared signer count is not evidence of anything.
func (vm *VM) VerifyStamp(message []byte, stamp interface{}) error {
	bridge := vm.GetQuasarBridge()

	switch s := stamp.(type) {
	case *quasar.QuasarSig:
		if bridge == nil {
			return errors.New("quantumvm: no Quasar bridge to check the signature against")
		}
		if !bridge.VerifySignature(message, s) {
			return fmt.Errorf("quantumvm: Quasar signature from %s does not check out", s.ValidatorID)
		}
		return nil

	case *quasar.AggregatedSignature:
		if bridge == nil {
			return errors.New("quantumvm: no Quasar bridge to check the aggregate against")
		}
		if !bridge.VerifyAggregate(context.Background(), message, s) {
			return errors.New("quantumvm: aggregated signature does not check out")
		}
		return nil

	case *quantum.QuantumSignature:
		return vm.quantumSigner.Verify(message, s)

	case nil:
		return errNoStamp

	default:
		return fmt.Errorf("quantumvm: unsupported stamp type %T", stamp)
	}
}
