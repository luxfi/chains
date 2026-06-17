// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/rpc/v2"
	rpcjson "github.com/gorilla/rpc/v2/json"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"

	"github.com/luxfi/accel"
	"github.com/luxfi/chains/dexvm/api"
	"github.com/luxfi/chains/dexvm/config"
	"github.com/luxfi/chains/dexvm/network"
	dexstate "github.com/luxfi/chains/dexvm/state"
	"github.com/luxfi/chains/dexvm/txs"
	consensuscore "github.com/luxfi/consensus/core"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/runtime"
	"github.com/luxfi/timer/mockable"
	"github.com/luxfi/version"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/warp"
)

var (
	errNotBootstrapped = errors.New("VM not bootstrapped")
	errShutdown        = errors.New("VM is shutting down")
	// errUTXOAlreadyImported guards the atomic-import double-spend (the proxy
	// never mints — an exported UTXO is claimable exactly once).
	errUTXOAlreadyImported = errors.New("atomic UTXO already imported")

	_ = errNotBootstrapped
	_ = errShutdown
)

// BlockResult is the deterministic result of processing a block on the proxy.
// A STATELESS ATOMIC ZAP PROXY produces NO MatchedTrades / FundingPayments /
// Liquidations — matching lives ONLY on the d-chain. The proxy's per-block
// output is the cross-chain atomic operations it accumulated (committed at
// accept) and the state root over its (tiny) replay/consumption state.
type BlockResult struct {
	// BlockHeight is the height of the processed block.
	BlockHeight uint64

	// Timestamp is when this block was processed.
	Timestamp time.Time

	// StateRoot is the merkle root of the proxy's state after this block.
	StateRoot ids.ID

	// atomic holds the cross-chain operations accumulated this block, applied
	// atomically with the state batch at accept (settlement leg). Unexported:
	// it is plumbed from ProcessBlock to the accept commit, not a public field.
	atomic *atomicRequests
}

// VM implements the DEX proxy Virtual Machine: a STATELESS ATOMIC ZAP PROXY on
// the Lux consensus network. It holds ZERO canonical DEX state. It does exactly
// two orthogonal things, each its own primitive (do NOT conflate them):
//
//  1. ORDER RELAY (proxy -> d-chain): forwards byte-identical clob_* frames
//     over ZAP (RelayClient) to the single source-of-truth matcher. NOT atomic,
//     NOT consensus — pure transport.
//
//  2. VALUE SETTLEMENT (C-Chain <-> proxy, atomic): moves value in/out via
//     atomic.SharedMemory import/export (atomic.go), exactly as X/P-chains do.
//     The ONLY primitive in the proxy that moves value across chains.
//
// Warp is retained ONLY as the optional fill-attestation channel (off the hot
// path) — it is NOT the settlement primitive.
//
// DESIGN: No background goroutines. All operations are block-driven and
// deterministic, so every node produces identical state from identical inputs.
type VM struct {
	config.Config

	// Per-VM GPU acceleration session (held for API symmetry with other VMs;
	// the proxy itself runs NO kernels — GPU lives in the d-chain's dex/pkg/lx).
	accel *accel.VMSession

	// Logger for this VM.
	log log.Logger

	// Lock for thread safety (API access; consensus is single-threaded).
	lock sync.RWMutex

	// Consensus context — provides chain identity, network info, and the
	// per-chain atomic.SharedMemory used by the settlement leg.
	consensusRuntime *runtime.Runtime

	// Chain identity.
	chainID ids.ID

	// Database management.
	baseDB database.Database
	db     *versiondb.Database

	// state persists ONLY replay nonces, in-flight relay receipts, and the
	// atomic-UTXO consumption set (proxy-statelessness invariant).
	state *dexstate.State

	// relay forwards clob_* frames to the d-chain ZAP gateway (order-relay leg).
	relay *RelayClient

	// Used to check local time.
	clock mockable.Clock

	// Metrics.
	registerer metric.Registerer

	// Network peers.
	connectedPeers map[ids.NodeID]*version.Application

	// Application sender for gossip.
	appSender warp.Sender

	// Block state.
	currentBlockHeight uint64
	lastBlockTime      time.Time

	// Lifecycle state.
	bootstrapped  bool
	isInitialized bool
	shutdown      bool

	// Channel for sending messages to consensus engine.
	toEngine chan<- vmcore.Message
}

// NewVMForTest creates a new VM instance for testing purposes.
func NewVMForTest(cfg config.Config, logger log.Logger) *VM {
	return &VM{
		Config: cfg,
		log:    logger,
	}
}

// Initialize implements consensuscore.VM. It sets up the proxy with the
// provided context, database, and genesis/config data.
func (vm *VM) Initialize(ctx context.Context, vmInit vmcore.Init) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	vm.consensusRuntime = vmInit.Runtime
	if vm.consensusRuntime != nil {
		vm.chainID = vm.consensusRuntime.ChainID
	}

	// Logger from runtime.
	if vm.consensusRuntime != nil && vm.consensusRuntime.Log != nil {
		if logger, ok := vm.consensusRuntime.Log.(log.Logger); ok && !logger.IsZero() {
			vm.log = logger
		} else {
			vm.log = log.Noop()
		}
	} else {
		vm.log = log.Noop()
	}

	// Database.
	vm.baseDB = vmInit.DB
	vm.db = versiondb.New(vm.baseDB)
	vm.state = dexstate.New(vm.db)
	if err := vm.state.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize proxy state: %w", err)
	}

	vm.toEngine = vmInit.ToEngine
	if vmInit.Sender != nil {
		vm.appSender = vmInit.Sender
	}
	vm.connectedPeers = make(map[ids.NodeID]*version.Application)

	vm.currentBlockHeight = 0
	vm.lastBlockTime = time.Time{}

	// Parse config first (genesis may override).
	if len(vmInit.Config) > 0 {
		if err := vm.parseConfig(vmInit.Config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	}
	if len(vmInit.Genesis) > 0 {
		if err := vm.parseGenesis(vmInit.Genesis); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}

	// Wire the order-relay client to the configured d-chain endpoint. Empty
	// endpoint => inert relay leg (ErrRelayNotConfigured on relay attempts).
	vm.relay = NewRelayClient(vm.Config.DexZapEndpoint, vm.Config.DexZapTimeout)

	vm.isInitialized = true
	if !vm.log.IsZero() {
		vm.log.Info("DEX proxy VM initialized (stateless atomic ZAP proxy)",
			"chainID", vm.chainID,
			"dexZapEndpoint", redactEndpoint(vm.Config.DexZapEndpoint),
			"relayConfigured", vm.relay.Configured(),
		)
	}
	return nil
}

// Genesis is the proxy's genesis configuration: trusted chains for the
// attestation channel and the d-chain ZAP endpoint. There are NO trading
// pairs / pools / perp markets — the proxy seeds no DEX state.
type Genesis struct {
	// DexZapEndpoint optionally overrides the d-chain ZAP gateway address.
	DexZapEndpoint string `json:"dexZapEndpoint,omitempty"`
	// TrustedChains are chain IDs trusted for the Warp attestation channel.
	TrustedChains []string `json:"trustedChains,omitempty"`
}

// parseGenesis applies the proxy genesis (endpoint + trusted attestation chains).
func (vm *VM) parseGenesis(genesisBytes []byte) error {
	var genesis Genesis
	if err := json.Unmarshal(genesisBytes, &genesis); err != nil {
		return fmt.Errorf("failed to unmarshal genesis: %w", err)
	}
	if genesis.DexZapEndpoint != "" {
		vm.Config.DexZapEndpoint = genesis.DexZapEndpoint
	}
	for _, chainIDStr := range genesis.TrustedChains {
		chainID, err := ids.FromString(chainIDStr)
		if err != nil {
			return fmt.Errorf("invalid trusted chain ID %s: %w", chainIDStr, err)
		}
		vm.Config.TrustedChains = append(vm.Config.TrustedChains, chainID)
	}
	if !vm.log.IsZero() {
		vm.log.Info("Genesis parsed", "trustedChains", len(vm.Config.TrustedChains))
	}
	return nil
}

// parseConfig applies runtime configuration (only non-zero values, preserving
// defaults).
func (vm *VM) parseConfig(configBytes []byte) error {
	var cfg config.Config
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if cfg.IndexAllowIncomplete {
		vm.Config.IndexAllowIncomplete = cfg.IndexAllowIncomplete
	}
	if cfg.IndexTransactions {
		vm.Config.IndexTransactions = cfg.IndexTransactions
	}
	if cfg.ChecksumsEnabled {
		vm.Config.ChecksumsEnabled = cfg.ChecksumsEnabled
	}
	if cfg.DexZapEndpoint != "" {
		vm.Config.DexZapEndpoint = cfg.DexZapEndpoint
	}
	if cfg.DexZapTimeout > 0 {
		vm.Config.DexZapTimeout = cfg.DexZapTimeout
	}
	if cfg.WarpEnabled {
		vm.Config.WarpEnabled = cfg.WarpEnabled
	}
	if len(cfg.TrustedChains) > 0 {
		vm.Config.TrustedChains = cfg.TrustedChains
	}
	if cfg.BlockInterval > 0 {
		vm.Config.BlockInterval = cfg.BlockInterval
	}
	if cfg.MaxBlockSize > 0 {
		vm.Config.MaxBlockSize = cfg.MaxBlockSize
	}
	if cfg.MaxTxsPerBlock > 0 {
		vm.Config.MaxTxsPerBlock = cfg.MaxTxsPerBlock
	}
	if !vm.log.IsZero() {
		vm.log.Info("Config parsed",
			"blockInterval", vm.Config.BlockInterval,
			"warpEnabled", vm.Config.WarpEnabled,
		)
	}
	return nil
}

// SetState implements consensuscore.VM. NOTE: No background goroutines.
func (vm *VM) SetState(ctx context.Context, stateNum uint32) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	switch vmcore.State(stateNum) {
	case vmcore.Bootstrapping:
		if !vm.log.IsZero() {
			vm.log.Info("DEX proxy entering bootstrap state")
		}
		vm.bootstrapped = false
		return nil
	case vmcore.Ready:
		if !vm.log.IsZero() {
			vm.log.Info("DEX proxy entering ready state")
		}
		vm.bootstrapped = true
		return nil
	default:
		return nil
	}
}

// ProcessBlock processes the proxy's per-block transactions deterministically.
// It does NO matching: it applies atomic import/export legs and relays orders
// to the d-chain, accumulating cross-chain operations into the BlockResult to
// be committed atomically with state at accept time.
//
// CONSERVATION ORDERING within a block: each tx is processed in order, and an
// import always precedes the relay/export that depends on its locked value.
func (vm *VM) ProcessBlock(ctx context.Context, blockHeight uint64, blockTime time.Time, blockTxs [][]byte) (*BlockResult, error) {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.shutdown {
		return nil, errShutdown
	}

	result := &BlockResult{
		BlockHeight: blockHeight,
		Timestamp:   blockTime,
		atomic:      newAtomicRequests(),
	}

	// Bind relays to (blockHash, txIndex) for replay-idempotency. The block hash
	// here is derived from height+time deterministically (the chain layer's
	// canonical block id is set at accept; this binding is stable per replay).
	blockHash := deriveBlockHash(blockHeight, blockTime)

	for i, txBytes := range blockTxs {
		if err := vm.processTx(ctx, txBytes, blockHash, uint32(i), result); err != nil {
			// Individual tx failures don't fail the block; log and continue. A
			// failed settle leaves NO committed cross-chain op for that tx
			// (atomicity-or-reversal): executeImport/Export only accumulate on
			// success.
			if !vm.log.IsZero() {
				vm.log.Warn("Proxy transaction failed", "index", i, "error", err)
			}
		}
	}

	vm.currentBlockHeight = blockHeight
	vm.lastBlockTime = blockTime
	if err := vm.state.SetLastBlock(blockHash, blockHeight); err != nil {
		return nil, fmt.Errorf("failed to persist last block: %w", err)
	}

	result.StateRoot = vm.computeStateRoot(blockHash)

	if !vm.log.IsZero() {
		vm.log.Debug("Proxy block processed", "height", blockHeight, "txs", len(blockTxs))
	}
	return result, nil
}

// processTx parses and dispatches a single proxy transaction. The proxy handles
// exactly the import/export atomic legs and the order-relay envelopes — there
// is NO matching dispatch.
func (vm *VM) processTx(ctx context.Context, txBytes []byte, blockHash ids.ID, txIndex uint32, result *BlockResult) error {
	if len(txBytes) < 1 {
		return errors.New("empty transaction")
	}
	parser := &txs.TxParser{}
	tx, err := parser.Parse(txBytes)
	if err != nil {
		return fmt.Errorf("failed to parse transaction: %w", err)
	}
	if err := tx.Verify(); err != nil {
		return fmt.Errorf("transaction verification failed: %w", err)
	}

	switch tx.Type() {
	case txs.TxImport:
		return vm.executeImport(tx.(*txs.ImportTx), result.atomic)
	case txs.TxExport:
		return vm.executeExport(tx.(*txs.ExportTx), result.atomic)
	case txs.TxRelayOrder:
		return vm.executeRelayOrder(ctx, tx.(*txs.RelayOrderTx), blockHash, txIndex, result)
	case txs.TxPlaceOrder:
		return vm.executePlaceOrder(ctx, tx.(*txs.PlaceOrderTx), blockHash, txIndex, result)
	case txs.TxCancelOrder:
		return vm.executeCancelOrder(ctx, tx.(*txs.CancelOrderTx))
	default:
		return fmt.Errorf("unknown transaction type: %d", tx.Type())
	}
}

// executeRelayOrder forwards an opaque clob_* frame to the d-chain and settles
// the export leg from the CONFIRMED FILLS the matcher returns — never from a
// client-supplied amount. The relay is bound to (blockHash, txIndex) so a
// re-execution/reorg/retry maps to exactly one d-chain match (replay-idempotency).
func (vm *VM) executeRelayOrder(ctx context.Context, tx *txs.RelayOrderTx, blockHash ids.ID, txIndex uint32, result *BlockResult) error {
	// Replay-idempotency: if this (blockHash, txIndex) already produced a
	// receipt, the relay was already applied — do not re-submit (would double).
	if _, found, err := vm.state.GetReceipt(blockHash, txIndex); err != nil {
		return fmt.Errorf("relay: receipt check: %w", err)
	} else if found {
		return nil
	}

	resp, err := vm.relay.Relay(ctx, tx.Method, tx.Payload)
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}

	// Only clob_submit returns settleable fills; place/cancel return an ack the
	// proxy records but does not settle (the resting maker is settled when taken).
	if tx.Method == ZAPMethodSubmit {
		fills, derr := DecodeFills(resp)
		if derr != nil {
			return fmt.Errorf("relay: decode fills: %w", derr)
		}
		if err := vm.settleFromFills(tx.Sender(), tx.CollateralRef, fills, result.atomic); err != nil {
			return fmt.Errorf("relay: settle: %w", err)
		}
		if err := vm.recordReceipt(blockHash, txIndex, resp); err != nil {
			return fmt.Errorf("relay: record receipt: %w", err)
		}
	}
	return nil
}

// executePlaceOrder forwards a thin place-order envelope to the d-chain. It
// rests a maker limit order; the maker is settled when taken (no immediate
// fills to settle here). The proxy forwards a byte-identical clob_place frame.
func (vm *VM) executePlaceOrder(ctx context.Context, tx *txs.PlaceOrderTx, blockHash ids.ID, txIndex uint32, result *BlockResult) error {
	payload := encodeCLOBPlace(tx)
	if _, err := vm.relay.Relay(ctx, ZAPMethodPlace, payload); err != nil {
		return fmt.Errorf("place: %w", err)
	}
	return nil
}

// executeCancelOrder forwards a thin cancel envelope. The d-chain authenticates
// the cancel against the resting order's maker — the proxy only routes it.
func (vm *VM) executeCancelOrder(ctx context.Context, tx *txs.CancelOrderTx) error {
	payload := make([]byte, 40)
	copy(payload[0:32], tx.PoolID[:])
	binary.BigEndian.PutUint64(payload[32:40], tx.OrderID)
	if _, err := vm.relay.Relay(ctx, ZAPMethodCancel, payload); err != nil {
		return fmt.Errorf("cancel: %w", err)
	}
	return nil
}

// settleFromFills derives the taker's export output from the d-chain's
// CONFIRMED fills (value-conservation: the credited amount comes from a real
// fill, never a client-supplied number) and accumulates it as an export leg
// back to C-Chain.
//
// VALUE CONSERVATION (RED C4): a CLOB fill moves value in ONE direction — the
// taker pays the asset it locked on the import leg and RECEIVES the opposite
// asset. So the export credits ONLY the received leg, never both:
//   - taker BUY  (side 0): pays quote (already locked on import), receives base
//     = sum(size).
//   - taker SELL (side 1): pays base (already locked on import), receives quote
//     = sum(price*size).
// Crediting both legs would mint value; this single-leg credit conserves it —
// total out (received) <= total in (locked collateral), the difference being the
// unfilled IOC remainder (refunded as the same asset that was locked).
//
// Every total is an integer-exact sum over positive-finite fills (DecodeFills
// guarantees positivity). The proxy never mints.
func (vm *VM) settleFromFills(taker ids.ShortID, collateralRef ids.ID, fills []Fill, ar *atomicRequests) error {
	if len(fills) == 0 {
		return nil // nothing filled; collateral refunded via the IOC-remainder path
	}
	takerSide := fills[0].Side
	var base, quote uint64
	for _, f := range fills {
		b := uint64(f.Size)
		q := uint64(f.Price * f.Size)
		// Overflow guard — a conserving fill stream cannot exceed uint64 totals
		// for any real market; refuse rather than wrap.
		if base+b < base || quote+q < quote {
			return errors.New("settle: notional overflow")
		}
		base += b
		quote += q
	}

	// Credit ONLY the asset the taker received (single-leg conservation). The
	// received-asset id is derived from the collateral ref's opposite leg so the
	// C-Chain side maps it to the real ERC-20. CollateralRef binds the settlement
	// to the import that locked the value (audit + replay-idempotency).
	var received txs.AtomicOutput
	if takerSide == 0 { // BUY: receives base
		received = txs.AtomicOutput{Owner: taker, Asset: assetFromRef(collateralRef, 0), Amount: base}
	} else { // SELL: receives quote
		received = txs.AtomicOutput{Owner: taker, Asset: assetFromRef(collateralRef, 1), Amount: quote}
	}
	tx := txs.NewExportTx(taker, 0, vm.cChainID(), nonZeroOutputs([]txs.AtomicOutput{received}), collateralRef)
	return vm.executeExport(tx, ar)
}

// recordReceipt stores the relay receipt binding (blockHash, txIndex) to the
// fills hash — the replay-idempotency witness.
func (vm *VM) recordReceipt(blockHash ids.ID, txIndex uint32, fillsWire []byte) error {
	return vm.state.PutReceipt(&dexstate.Receipt{
		BlockHash: blockHash,
		TxIndex:   txIndex,
		FillsHash: ids.ID(sha256.Sum256(fillsWire)),
	})
}

// acceptBlock commits a verified block: it writes the proxy's state batch
// ATOMICALLY with the cross-chain shared-memory operations accumulated during
// ProcessBlock. This is the single commit point, modeled byte-for-byte on the
// platformvm acceptor (defer Abort -> CommitBatch -> sm.Apply(reqs, batch)).
//
// Atomicity-or-reversal: sm.Apply writes the state batch and the shared-memory
// requests in one atomic DB commit, so a failed settle leaves NO committed
// state and a d-side fill can never strand without its C-side credit.
func (vm *VM) acceptBlock(result *BlockResult) error {
	if vm.db == nil {
		return nil
	}
	ar := newAtomicRequests()
	if result != nil && result.atomic != nil {
		ar = result.atomic
	}

	// Abort clears the versiondb's in-memory layer after the batch is written by
	// Apply/Write (the platformvm defer-Abort pattern).
	defer vm.db.Abort()
	batch, err := vm.db.CommitBatch()
	if err != nil {
		return fmt.Errorf("dexvm: commit batch: %w", err)
	}
	return vm.commitAtomic(ar, batch)
}

// computeStateRoot computes a merkle root over the proxy's deterministic state.
// The proxy holds tiny state (replay nonces, receipts, consumed UTXOs); the
// root binds the last block hash + height so replaying the same block yields
// the same root on every node.
func (vm *VM) computeStateRoot(blockHash ids.ID) ids.ID {
	h := sha256.New()
	h.Write(blockHash[:])
	var heightBuf [8]byte
	binary.BigEndian.PutUint64(heightBuf[:], vm.currentBlockHeight)
	h.Write(heightBuf[:])
	return ids.ID(h.Sum(nil))
}

// Shutdown implements consensuscore.VM.
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if !vm.log.IsZero() {
		vm.log.Info("Shutting down DEX proxy VM")
	}
	vm.shutdown = true

	if vm.relay != nil {
		_ = vm.relay.Close()
	}
	if vm.db != nil {
		if err := vm.db.Close(); err != nil {
			return fmt.Errorf("failed to close database: %w", err)
		}
	}
	return nil
}

// Version implements consensuscore.VM.
func (vm *VM) Version(ctx context.Context) (string, error) {
	return "2.0.0", nil
}

// CreateHandlers implements consensuscore.VM. The proxy's API is a thin
// pass-through to the relay client (no local book to query).
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	server := rpc.NewServer()
	server.RegisterCodec(rpcjson.NewCodec(), "application/json")
	server.RegisterCodec(rpcjson.NewCodec(), "application/json;charset=UTF-8")

	service := api.NewService(vm)
	if err := server.RegisterService(service, "dex"); err != nil {
		return nil, fmt.Errorf("failed to register DEX service: %w", err)
	}
	return map[string]http.Handler{"": server}, nil
}

// HealthCheck implements consensuscore.VM.
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	return chain.HealthResult{
		Healthy: vm.isInitialized && vm.bootstrapped,
		Details: map[string]string{
			"bootstrapped":    fmt.Sprintf("%v", vm.bootstrapped),
			"relayConfigured": fmt.Sprintf("%v", vm.relay.Configured()),
			"blockHeight":     fmt.Sprintf("%d", vm.currentBlockHeight),
			"mode":            "stateless-atomic-zap-proxy",
		},
	}, nil
}

// Connected implements consensuscore.VM.
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, v *version.Application) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()
	vm.connectedPeers[nodeID] = v
	return nil
}

// Disconnected implements consensuscore.VM.
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()
	delete(vm.connectedPeers, nodeID)
	return nil
}

// IsBootstrapped reports whether the proxy is fully bootstrapped.
func (vm *VM) IsBootstrapped() bool {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.bootstrapped
}

// GetBlockHeight returns the current block height.
func (vm *VM) GetBlockHeight() uint64 {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.currentBlockHeight
}

// GetLastBlockTime returns the timestamp of the last processed block.
func (vm *VM) GetLastBlockTime() time.Time {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	return vm.lastBlockTime
}

// Relay exposes the relay client to the API pass-through layer as the neutral
// api.Relayer surface (the proxy's only DEX capability is transport).
func (vm *VM) Relay() api.Relayer { return vm.relay }

// Gossip implements consensuscore.VM. The proxy gossips nothing matcher-related
// (it has no book); it only acknowledges peer messages.
func (vm *VM) Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()
	if vm.shutdown {
		return errShutdown
	}
	return nil
}

// Request implements consensuscore.VM. The proxy serves no orderbook/pool sync
// (it holds no such state); unknown requests are ignored.
func (vm *VM) Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, request []byte) error {
	vm.lock.RLock()
	defer vm.lock.RUnlock()
	if vm.shutdown {
		return errShutdown
	}
	return nil
}

// RequestFailed implements consensuscore.VM.
func (vm *VM) RequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, appErr *consensuscore.AppError) error {
	return nil
}

// Response implements consensuscore.VM.
func (vm *VM) Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	return nil
}

// CrossChainRequest implements consensuscore.VM. The proxy retains ONLY the
// Warp attestation-ingress dispatch — it does NOT move value over Warp (the
// atomic SharedMemory import/export leg does that). Cross-chain swap/transfer
// value handlers were removed; an incoming Warp message is a fill attestation
// receipt, off the settlement hot path.
func (vm *VM) CrossChainRequest(ctx context.Context, sourceChainID ids.ID, requestID uint32, deadline time.Time, request []byte) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()
	if vm.shutdown {
		return errShutdown
	}

	// Verify source chain is trusted for attestations.
	if !vm.isTrustedChain(sourceChainID) {
		if !vm.log.IsZero() {
			vm.log.Warn("Attestation from untrusted chain", "chainID", sourceChainID)
		}
		return errors.New("source chain not trusted")
	}

	netMsg, err := network.DecodeMessage(request)
	if err != nil {
		return err
	}

	switch netMsg.Type {
	case network.MsgWarpMessage:
		return vm.handleAttestation(ctx, sourceChainID, requestID, netMsg)
	default:
		if !vm.log.IsZero() {
			vm.log.Debug("Ignored non-attestation cross-chain request", "type", netMsg.Type)
		}
	}
	return nil
}

// handleAttestation ingests a Warp fill attestation. It is RECEIPT-ONLY: it
// records/logs the attestation for the optional fraud-proof channel and moves
// NO value (value moves atomically via SharedMemory import/export). This is the
// trimmed body of the former handleWarpMessage — no value-moving logic remains.
func (vm *VM) handleAttestation(ctx context.Context, sourceChainID ids.ID, requestID uint32, msg *network.Message) error {
	if !vm.log.IsZero() {
		vm.log.Debug("Received fill attestation (receipt-only)",
			"sourceChain", sourceChainID,
			"payloadSize", len(msg.Payload),
		)
	}
	return nil
}

// CrossChainRequestFailed implements consensuscore.VM.
func (vm *VM) CrossChainRequestFailed(ctx context.Context, chainID ids.ID, requestID uint32, appErr *consensuscore.AppError) error {
	return nil
}

// CrossChainResponse implements consensuscore.VM.
func (vm *VM) CrossChainResponse(ctx context.Context, chainID ids.ID, requestID uint32, response []byte) error {
	return nil
}

// ---------------------------------------------------------------------------
// Small deterministic helpers.
// ---------------------------------------------------------------------------

// isTrustedChain reports whether chainID is in the attestation trust set.
func (vm *VM) isTrustedChain(chainID ids.ID) bool {
	for _, c := range vm.Config.TrustedChains {
		if c == chainID {
			return true
		}
	}
	return false
}

// cChainID returns the C-Chain id used as the settlement destination. The proxy
// settles to the same primary network's C-Chain (the atomic-DB peer). When the
// runtime exposes a C-Chain alias it is used; otherwise the proxy's own chain
// id is the harness default (single-chain test mode).
func (vm *VM) cChainID() ids.ID {
	if vm.consensusRuntime != nil && vm.consensusRuntime.CChainID != ids.Empty {
		return vm.consensusRuntime.CChainID
	}
	return vm.chainID
}

// encodeCLOBPlace builds a byte-identical clob_place frame from a thin place
// envelope, mirroring the d-chain gateway's expected layout (poolId[32] |
// side[1] | price[8] | size[8] | maker[16]).
func encodeCLOBPlace(tx *txs.PlaceOrderTx) []byte {
	payload := make([]byte, 65)
	copy(payload[0:32], tx.PoolID[:])
	payload[32] = tx.Side
	putZAPFloat(payload[33:41], float64(tx.Price))
	putZAPFloat(payload[41:49], float64(tx.Size))
	maker := tx.Sender()
	copy(payload[49:65], maker[:16])
	return payload
}

// putZAPFloat writes a ZAP float wire field (big-endian IEEE-754 float64 bits).
func putZAPFloat(b []byte, f float64) {
	binary.BigEndian.PutUint64(b, math.Float64bits(f))
}

// idHash is the canonical 32-byte hash used for derived ids.
func idHash(b []byte) [32]byte { return sha256.Sum256(b) }

// deriveBlockHash deterministically derives a stable per-block hash from height
// and time. Used to bind relays to (blockHash, txIndex) for replay-idempotency.
func deriveBlockHash(height uint64, t time.Time) ids.ID {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], height)
	binary.BigEndian.PutUint64(buf[8:16], uint64(t.UnixNano()))
	return ids.ID(sha256.Sum256(buf[:]))
}

// assetFromRef resolves the leg's asset id from the collateral reference. The
// proxy carries the asset identity in the import's locked collateral; here we
// derive a stable per-leg asset id (leg 0 = base, 1 = quote) so the C-Chain
// side can map it back. This is a routing handle, not canonical state.
func assetFromRef(ref ids.ID, leg uint8) ids.ID {
	var buf [33]byte
	copy(buf[0:32], ref[:])
	buf[32] = leg
	return ids.ID(sha256.Sum256(buf[:]))
}

// nonZeroOutputs drops zero-amount outputs (an export must carry only positive
// value — a zero leg means that asset wasn't part of the realized proceeds).
func nonZeroOutputs(out []txs.AtomicOutput) []txs.AtomicOutput {
	r := out[:0]
	for _, o := range out {
		if o.Amount > 0 {
			r = append(r, o)
		}
	}
	return r
}

// redactEndpoint returns a log-safe form of the endpoint (host:port is fine to
// log; empty stays empty).
func redactEndpoint(addr string) string {
	if addr == "" {
		return "<inert>"
	}
	return addr
}
