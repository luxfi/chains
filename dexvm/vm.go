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
	// errFillRefAlreadyExported guards the WITHDRAW rail's double-export (R2). The
	// settlement fillRef is unique per genuine withdraw; consuming it exactly once
	// (mirroring the import UTXO consume-once, same state consumed-set) stops a
	// duplicate fillRef from exporting twice (a drain) regardless of how the proxy
	// BuildBlock rail is later wired. Note: the swap-settle export (settleFromFills)
	// is NOT gated this way — it is bounded by the escrow ledger and intentionally
	// reuses the collateral ref across partial settles.
	errFillRefAlreadyExported = errors.New("settlement fillRef already exported")

	// errImportAssetMismatch guards the native-aliasing import (CRITICAL): an
	// import must credit the asset of the UTXO it ACTUALLY consumes, not an asset
	// it merely declares. The consumed UTXO's recorded asset (read back from shared
	// memory — the export side wrote owner|asset|amount) is authoritative; a tx
	// whose declared input asset disagrees is rejected, so a bogus-token UTXO can
	// never be imported as native (or any other) value.
	errImportAssetMismatch = errors.New("import: declared input asset != consumed UTXO asset")
	// errImportAmountMismatch guards an import that declares more (or less) than the
	// consumed UTXO actually holds — the same authoritative bind on the amount axis.
	errImportAmountMismatch = errors.New("import: declared input amount != consumed UTXO amount")
	// errImportMixedAssets rejects an import that consumes UTXOs of DIFFERENT assets:
	// a deposit credits one (owner,asset) ledger row, so every consumed UTXO must be
	// the same asset.
	errImportMixedAssets = errors.New("import: consumed UTXOs span multiple assets")
	// errImportMixedRails guards the RAIL (lane) axis of the import bind: an import
	// funds a SINGLE lane (swap or LP), so every consumed UTXO and every credited
	// output must share the consumed UTXO's recorded rail. Mixing lanes would let a
	// swap-fill object and an LP-collect object be claimed in one credit — the
	// cross-rail consume H1 closes. The recorded rail (written by the export side via
	// encodeExportedOutput) is authoritative.
	errImportMixedRails = errors.New("import: consumed/credited rails mismatch (cross-rail consume)")
	// errImportOutputAsset rejects an import whose credited output names a different
	// asset than the consumed UTXO — the credit must be denominated in the imported
	// asset (the native-aliasing fix's structural half, also enforced in Verify).
	errImportOutputAsset = errors.New("import: output asset != consumed UTXO asset")
	// errImportUTXOValueMalformed rejects a shared-memory UTXO value that is not the
	// canonical owner(20)|asset(32)|amount(8) image — a corrupt record must never be
	// silently reinterpreted into a credit.
	errImportUTXOValueMalformed = errors.New("import: source UTXO value malformed")
	// errImportWrongOwner guards the OWNER axis of the import bind (the cross-chain
	// analog of the settlement-identity collision): an import must credit the account
	// AUTHORIZED by the consumed UTXO's recorded owner, not an owner the importing tx
	// freely chooses. The consumed UTXO's recorded owner (written by the export side
	// via encodeExportedOutput) is authoritative; every consumed UTXO must share that
	// owner and every credited output must name it — so an attacker cannot consume a
	// victim's exported UTXO and credit it to their own account.
	errImportWrongOwner = errors.New("import: credited owner != consumed UTXO owner")

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

	// blockHash is the deterministic (height, time) binding ProcessBlock used to
	// key relay receipts. Accept reuses it so a relay maps to exactly one
	// (blockHash, txIndex) receipt across re-execution.
	blockHash ids.ID

	// atomic holds the cross-chain IMPORT operations accumulated during Verify
	// (deterministic, no I/O). The EXPORT (settlement) legs are appended at
	// accept by settleCarried, derived from the block-CARRIED fills. Applied
	// atomically with the state batch at the single accept commit point.
	atomic *atomicRequests

	// relays is the deterministic ORDER-RELAY PLAN built during Verify. Verify is
	// a PURE DETERMINISTIC PLANNER — it performs NO d-chain I/O at all. The plan
	// records which txIndex is a settling submit (so settleCarried knows which
	// carried-fills entry drives an export) and the per-relay settle context
	// (sender, collateralRef). The actual relay (the irreversible, non-
	// deterministic d-chain leg) is NOT executed from this plan on the
	// verify/accept path — it is performed exactly once by the PROPOSER at build
	// time (VM.obtainFills), and its fills are CARRIED in the block bytes.
	relays []plannedRelay

	// carriedFills are the d-chain matcher's confirmed fills carried in the block
	// /vertex bytes (see carried_fills.go). On the PROPOSER they are produced at
	// build by obtainFills (one relay per order, network-wide); on every other
	// validator they are parsed from the block bytes. settleCarried settles purely
	// from these — NO validator ever relays during Verify/Accept — so block output
	// is a pure function of (height, carried time, tx bytes, carried fills) and
	// every node reproduces the identical StateRoot (RED finding #9 fix).
	carriedFills []carriedFill

	// fillSig is the RESERVED d-chain fill-attestation signature carried alongside
	// the fills (see carried_fills.go). Empty today; the trustless upgrade (d-chain
	// signs its fills, P3Q -> starkfri verifies) populates and checks it WITHOUT a
	// further wire-format change.
	fillSig []byte
}

// plannedRelay is one clob_* relay captured deterministically during Verify. It
// binds the relay to (blockHash, txIndex) for replay-idempotency and carries
// everything BOTH the proposer's build-time relay (obtainFills) AND every
// validator's accept-time settle-from-carried (settleCarried) need — no tx
// re-parse at either point.
type plannedRelay struct {
	// txIndex is the relay's position in the block (the receipt-binding key).
	txIndex uint32
	// method is the ZAP CLOB method ("clob_submit" / "clob_place" / "clob_cancel").
	method string
	// payload is the opaque, byte-identical clob_* frame forwarded verbatim.
	payload []byte
	// sender is the taker/maker address (settle owner for clob_submit).
	sender ids.ShortID
	// collateralRef binds a clob_submit to the Import escrow it settles against.
	collateralRef ids.ID
	// settle is true only for clob_submit: its returned fills drive an export.
	// place/cancel are acks the proxy relays but does not settle.
	settle bool
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

	// Database. The proxy keeps two layers: vm.db (versiondb) is the per-block
	// state committed atomically at accept; vm.baseDB is the durable base the
	// versiondb wraps. Relay receipts are write-ahead intents that gate an
	// irreversible d-chain side effect, so they route through the durable base
	// (receiptDB) and survive a crash-before-accept that db.Abort would discard.
	vm.baseDB = vmInit.DB
	vm.db = versiondb.New(vm.baseDB)
	vm.state = dexstate.New(vm.db, vm.baseDB)
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

// ProcessBlock is the proxy's PURE DETERMINISTIC VERIFY: it validates the
// block's transactions and builds a plan, performing ZERO d-chain I/O.
// Concretely it applies the atomic IMPORT legs (consuming UTXOs into the
// versiondb in-memory layer, accumulating RemoveRequests) and the EXPORT legs,
// and it records every order RELAY as a plannedRelay. Matching is NEVER done
// here — it lives only on the d-chain.
//
// Why no relay here (RED finding #9): a Verified block is later decided Accept OR
// Reject, and Reject must undo everything Verify did with a plain db.Abort(). But
// more fundamentally, Verify runs on EVERY validator: a clob_submit issued here
// would be relayed per-validator against a MOVING d-chain book, so each validator
// would observe independently-timed fills => divergent settlement => divergent
// StateRoot => the network forks. The relay is therefore performed exactly ONCE,
// by the block PROPOSER at build (VM.obtainFills), and the confirmed fills are
// CARRIED in the block bytes; every validator settles purely from those carried
// fills (settleCarried at accept). Block output is thus a pure function of
// (height, carried time, tx bytes, carried fills).
//
// CONSERVATION ORDERING within a block: each tx is processed in order, and an
// import always precedes the relay/export that depends on its locked value. The
// plan preserves that order (settleCarried settles in capture order at accept).
func (vm *VM) ProcessBlock(ctx context.Context, blockHeight uint64, blockTime time.Time, blockTxs [][]byte) (*BlockResult, error) {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.shutdown {
		return nil, errShutdown
	}

	// Bind relays to (blockHash, txIndex) for replay-idempotency. The block hash
	// here is derived from height+time deterministically (the chain layer's
	// canonical block id is set at accept; this binding is stable per replay).
	blockHash := deriveBlockHash(blockHeight, blockTime)

	result := &BlockResult{
		BlockHeight: blockHeight,
		Timestamp:   blockTime,
		blockHash:   blockHash,
		atomic:      newAtomicRequests(),
	}

	for i, txBytes := range blockTxs {
		if err := vm.processTx(txBytes, blockHash, uint32(i), result); err != nil {
			// Individual tx failures don't fail the block; log and continue. A
			// failed import leaves NO committed cross-chain op for that tx
			// (atomicity-or-reversal): executeImport/Export only accumulate on
			// success, and a relay that fails to PLAN is simply not enqueued.
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

	// VERIFY-time root: commits the post-verify state (imports' consumed/escrow
	// staged in the versiondb in-memory layer) and the import legs accumulated so
	// far. The settlement EXPORT legs and relay receipts are produced at accept;
	// acceptBlock recomputes the root over that final state (see acceptBlock).
	root, err := vm.computeStateRoot(blockHash, result)
	if err != nil {
		return nil, err
	}
	result.StateRoot = root

	if !vm.log.IsZero() {
		vm.log.Debug("Proxy block processed", "height", blockHeight, "txs", len(blockTxs))
	}
	return result, nil
}

// BuildBlockResult is the PROPOSER's full build of a block: it plans the block
// (the deterministic ProcessBlock pass) and then performs the network-wide-ONCE
// d-chain relay (obtainFills), attaching the confirmed fills to the result. The
// caller (BuildBlock / BuildVertex) serializes result.carriedFills + result.fillSig
// into the block/vertex bytes so every validator settles from them — the matcher
// is hit exactly once for the whole network (RED finding #9).
//
// This is the ONLY method that triggers a d-chain relay. Verify (ProcessBlock) and
// Accept (acceptBlock) never relay. A non-proposer obtains the same fills by
// parsing the block bytes, not by calling this.
//
// The relay is best-effort per order: obtainFills carries a zero-fill entry for any
// order whose relay failed, so the build always yields a valid block (the escrow is
// refunded at settle). It returns an error only on a fault that should abort the
// proposal entirely (e.g. the planning pass failed).
func (vm *VM) BuildBlockResult(ctx context.Context, blockHeight uint64, blockTime time.Time, blockTxs [][]byte) (*BlockResult, error) {
	result, err := vm.ProcessBlock(ctx, blockHeight, blockTime, blockTxs)
	if err != nil {
		return nil, err
	}
	// Relay exactly once (proposer) and carry the fills. obtainFills locks nothing
	// in vm (it only touches the durable receiptDB + the relay socket); ProcessBlock
	// already released vm.lock.
	entries, err := vm.obtainFills(ctx, result.blockHash, result.relays)
	if err != nil {
		return nil, fmt.Errorf("build: obtain fills: %w", err)
	}
	result.carriedFills = entries
	// result.fillSig stays empty: the reserved trustless-path signature is not
	// produced by the proxy (the d-chain signs its fills in the future upgrade).
	return result, nil
}

// processTx parses and dispatches a single proxy transaction during VERIFY. The
// proxy handles exactly the import/export atomic legs (deterministic, staged in
// the versiondb in-memory layer + accumulated atomic requests) and the order-
// relay envelopes (captured as a deferred plan — NO d-chain I/O here). There is
// NO matching dispatch.
func (vm *VM) processTx(txBytes []byte, blockHash ids.ID, txIndex uint32, result *BlockResult) error {
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
		return vm.planRelayOrder(tx.(*txs.RelayOrderTx), blockHash, txIndex, result)
	case txs.TxPlaceOrder:
		return vm.planPlaceOrder(tx.(*txs.PlaceOrderTx), blockHash, txIndex, result)
	case txs.TxCancelOrder:
		return vm.planCancelOrder(tx.(*txs.CancelOrderTx), blockHash, txIndex, result)
	default:
		return fmt.Errorf("unknown transaction type: %d", tx.Type())
	}
}

// planRelayOrder records an opaque clob_* relay as a plannedRelay. A clob_submit's
// confirmed fills drive an export leg, so it is flagged settle=true; place/cancel
// framed as a RelayOrderTx are acks only (settle=false). The plan is bound to
// (blockHash, txIndex) — the coordinate that keys both the build-time relay's
// idempotency receipt and the deterministic settlement export identity.
//
// PURE PLANNER (RED #9): planning is a deterministic, side-effect-free fold over
// the tx — it does NOT consult the receipt and does NOT relay. The plan MUST be
// reproduced identically on every validator (the proposer at build, and every node
// at Verify/parse) because settleCarried drives the settlement off it; gating the
// plan on a per-validator receipt would make a validator that lacks the receipt
// plan differently from the proposer. Relay-idempotency lives where the relay is —
// inside obtainFills (relaySubmit/relayAck check the receipt), run once by the
// proposer.
func (vm *VM) planRelayOrder(tx *txs.RelayOrderTx, blockHash ids.ID, txIndex uint32, result *BlockResult) error {
	result.relays = append(result.relays, plannedRelay{
		txIndex:       txIndex,
		method:        tx.Method,
		payload:       tx.Payload,
		sender:        tx.Sender(),
		collateralRef: tx.CollateralRef,
		settle:        tx.Method == ZAPMethodSubmit,
	})
	return nil
}

// planPlaceOrder records a thin place-order envelope as a clob_place relay. It
// rests a maker limit order when relayed by the proposer; the maker is settled
// when taken (no immediate fills to settle here), so settle=false.
//
// Replay-idempotency (RED double-place): the relay itself is gated by the durable
// receipt inside obtainFills and is performed exactly once by the PROPOSER. Verify
// never relays, so re-verifying the same block (reorg, restart-before-accept,
// normal re-verification) sends ZERO clob_place frames — one PlaceOrderTx rests
// exactly one maker order on the d-chain, never N copies. Planning here is the pure
// deterministic fold, not the relay.
func (vm *VM) planPlaceOrder(tx *txs.PlaceOrderTx, blockHash ids.ID, txIndex uint32, result *BlockResult) error {
	result.relays = append(result.relays, plannedRelay{
		txIndex: txIndex,
		method:  ZAPMethodPlace,
		payload: encodeCLOBPlace(tx),
		sender:  tx.Sender(),
	})
	return nil
}

// planCancelOrder records a thin cancel envelope as a clob_cancel relay. The
// d-chain authenticates the cancel against the resting order's maker — the proxy
// only routes it; settle=false.
//
// Replay-idempotency (RED double-cancel): like place, the relay is gated by the
// durable receipt inside obtainFills and fires once on the proposer; Verify never
// relays, so re-verifying never re-sends clob_cancel (which on the d-chain could
// cancel a DIFFERENT order that re-used the id, or spuriously fail an already-
// cancelled one). One CancelOrderTx => one cancel.
func (vm *VM) planCancelOrder(tx *txs.CancelOrderTx, blockHash ids.ID, txIndex uint32, result *BlockResult) error {
	payload := make([]byte, 40)
	copy(payload[0:32], tx.PoolID[:])
	binary.BigEndian.PutUint64(payload[32:40], tx.OrderID)
	result.relays = append(result.relays, plannedRelay{
		txIndex: txIndex,
		method:  ZAPMethodCancel,
		payload: payload,
		sender:  tx.Sender(),
	})
	return nil
}

// obtainFills is the PROPOSER-ONLY relay step, run at BuildBlock/BuildVertex
// (chainvm.go / dag_vertex.go) — the single point where the proxy performs the
// irreversible, non-deterministic d-chain I/O for a block. For each planned relay
// it forwards the byte-identical clob_* frame to the d-chain EXACTLY ONCE and, for
// a settling submit, decodes the confirmed fills into a carriedFill entry. The
// returned entries are serialized into the block/vertex bytes (carried_fills.go),
// so every validator settles from them without ever relaying — the matcher is hit
// at most once per order, network-wide (RED finding #9).
//
// Idempotency: the relay is gated by the SAME durable two-phase write-ahead
// receipt the proxy has always used, keyed by (blockHash, txIndex). A re-build of
// the same block coordinate (proposer restart) finds the intent and skips the
// re-relay — no double-submit to the source-of-truth matcher. (The receipt is
// finalized with the response hash for provenance.)
//
// A per-relay failure (transport error, undecodable fills) is LOGGED and the
// order is carried with NO fills (an explicit zero-fill entry for a submit), so
// the block still validates and the taker's escrow is fully refunded at settle —
// recoverable by a later order. obtainFills never returns a fatal error for a
// single relay failure; it returns an error only on a programming/receipt fault.
//
// place/cancel return an ack the proxy records but does not settle (the resting
// maker is settled when taken), so they produce no carriedFill entry.
//
// NOTE ON THE TRUST SURFACE: relaying at build means the PROPOSER reports the
// fills the rest of the network settles from. This is the interim
// conservation-bounded model documented in carried_fills.go: a lying proposer is
// bounded by settleFromFills' spent>locked refusal (no mint; blast radius = one
// taker's own escrow). The trustless path uses the reserved fill-signature field.
func (vm *VM) obtainFills(ctx context.Context, blockHash ids.ID, relays []plannedRelay) ([]carriedFill, error) {
	var entries []carriedFill
	for _, r := range relays {
		// Only a settling submit produces fills the network must carry+settle.
		// place/cancel are relayed for their side effect (rest/cancel a maker) but
		// carry nothing to settle.
		if !r.settle {
			if err := vm.relayAck(ctx, blockHash, r); err != nil && !vm.log.IsZero() {
				vm.log.Warn("Proxy build relay (ack) failed", "txIndex", r.txIndex, "method", r.method, "error", err)
			}
			continue
		}
		fills, err := vm.relaySubmit(ctx, blockHash, r)
		if err != nil {
			// Carry an explicit zero-fill entry so the validator settles a full
			// refund rather than inferring intent; the order is recoverable later.
			if !vm.log.IsZero() {
				vm.log.Warn("Proxy build relay (submit) failed; carrying zero fills (escrow refunded at settle)",
					"txIndex", r.txIndex, "error", err)
			}
			entries = append(entries, carriedFill{txIndex: r.txIndex, fills: nil})
			continue
		}
		entries = append(entries, carriedFill{txIndex: r.txIndex, fills: fills})
	}
	return entries, nil
}

// relaySubmit performs one idempotent clob_submit relay and decodes its fills.
// The two-phase durable receipt makes the irreversible d-chain leg fire AT MOST
// ONCE across a proposer crash mid-build:
//
//	GetReceipt  — a witness already present (intent OR finalized) => no relay,
//	              treat as zero-fill (the prior relay's fills are not re-derivable
//	              from the hash; a re-built block carries nothing for this tx and
//	              the escrow is refunded — a bounded proposer-local liveness cost,
//	              never a consensus-safety or double-submit issue).
//	phase 1     — RecordRelayIntent: durable intent BEFORE the relay.
//	relay       — the irreversible d-chain leg.
//	phase 2     — recordReceipt: finalize with the response hash (provenance).
func (vm *VM) relaySubmit(ctx context.Context, blockHash ids.ID, r plannedRelay) ([]Fill, error) {
	if _, found, err := vm.state.GetReceipt(blockHash, r.txIndex); err != nil {
		return nil, fmt.Errorf("relay: receipt check: %w", err)
	} else if found {
		return nil, nil
	}
	if err := vm.state.RecordRelayIntent(blockHash, r.txIndex); err != nil {
		return nil, fmt.Errorf("relay: record intent: %w", err)
	}
	resp, err := vm.relay.Relay(ctx, r.method, r.payload)
	if err != nil {
		return nil, fmt.Errorf("relay %s: %w", r.method, err)
	}
	fills, derr := DecodeFills(resp)
	if derr != nil {
		return nil, fmt.Errorf("relay: decode fills: %w", derr)
	}
	if err := vm.recordReceipt(blockHash, r.txIndex, resp); err != nil {
		return nil, fmt.Errorf("relay: record receipt: %w", err)
	}
	return fills, nil
}

// relayAck performs one idempotent place/cancel relay (no fills to settle). Same
// durable receipt discipline as relaySubmit; the ack is recorded for provenance.
func (vm *VM) relayAck(ctx context.Context, blockHash ids.ID, r plannedRelay) error {
	if _, found, err := vm.state.GetReceipt(blockHash, r.txIndex); err != nil {
		return fmt.Errorf("relay: receipt check: %w", err)
	} else if found {
		return nil
	}
	if err := vm.state.RecordRelayIntent(blockHash, r.txIndex); err != nil {
		return fmt.Errorf("relay: record intent: %w", err)
	}
	resp, err := vm.relay.Relay(ctx, r.method, r.payload)
	if err != nil {
		return fmt.Errorf("relay %s: %w", r.method, err)
	}
	return vm.recordReceipt(blockHash, r.txIndex, resp)
}

// settleCarried turns the block-CARRIED fills into export legs at ACCEPT. It is a
// PURE DETERMINISTIC FUNCTION of (planned relays, carried fills, escrow state):
// it performs NO d-chain I/O, so it runs identically on every validator and yields
// byte-identical export UTXO keys => identical StateRoot (RED finding #9).
//
// For each planned settling submit it looks up the carried fills bound to that
// txIndex and settles them via settleFromFills (unchanged: directional rounding,
// spent>locked refused, escrow consumed once). An absent or empty carried entry
// settles a full refund of the locked collateral — the conservation-safe default
// when the proposer carried no fills (a failed build relay, or a non-settling
// block). A per-settle refusal (e.g. a lying proposer's spent>locked) is LOGGED
// and SKIPPED, leaving the escrow intact and recoverable — never fatal to the
// block, and bounded to that one taker's collateral.
func (vm *VM) settleCarried(result *BlockResult, ar *atomicRequests) {
	for _, r := range result.relays {
		if !r.settle {
			continue
		}
		fills, _ := fillsForTx(result.carriedFills, r.txIndex)
		if err := vm.settleFromFills(r.sender, r.collateralRef, fills, result.blockHash, r.txIndex, ar); err != nil {
			if !vm.log.IsZero() {
				vm.log.Warn("Proxy settle from carried fills failed (collateral remains escrowed)",
					"txIndex", r.txIndex, "error", err)
			}
		}
	}
}

// settleFromFills derives the taker's export output from the d-chain's
// CONFIRMED fills (value-conservation: the credited amount comes from a real
// fill, never a client-supplied number) and accumulates it as an export leg
// back to C-Chain.
//
// VALUE CONSERVATION (RED C4): the proxy must return EVERY locked unit — as
// proceeds or as a refund — so value_in == value_out exactly. A CLOB fill moves
// value in one direction: the taker pays the asset it locked on import and
// RECEIVES the opposite asset. The settle therefore exports TWO legs:
//
//	PROCEEDS leg — the received (opposite) asset:
//	  - taker BUY  (side 0): receives base  = sum(size).
//	  - taker SELL (side 1): receives quote = sum(price*size).
//	REFUND leg — the unfilled remainder of the LOCKED asset:
//	  - taker BUY  locked quote; spent = sum(price*size); refund = locked - spent.
//	  - taker SELL locked base;  spent = sum(size);       refund = locked - spent.
//
// Crediting only the proceeds leg (the prior behavior) DESTROYED the unfilled
// remainder on every partial/zero fill. The refund leg closes that leak: the
// locked-collateral amount comes from the escrow recorded at import, the spent
// amount from the confirmed fills, and refund = locked - spent is exported in
// the SAME asset that was locked. The escrow is consumed so it cannot be
// refunded twice. With no escrow (a relay not backed by a proxy-side import),
// there is no locked collateral to refund — proceeds only.
//
// FRACTIONAL-NOTIONAL ROUNDING (RED escrow-truncation mint): fills cross the ZAP
// wire as float64, so base = sum(size) and quote = sum(price*size) are generally
// FRACTIONAL while on-chain value moves in integer asset units. The float->uint
// conversion is ASYMMETRIC by purpose, to preserve "the proxy never mints"
// (atomic.go quantToCredit/quantToCharge):
//   - PROCEEDS (the opposite asset the taker RECEIVES) round DOWN — never credit
//     a unit that was not realized.
//   - SPENT (the locked asset consumed, which REDUCES the refund) round UP —
//     never UNDERstate spend. Understating spend is exactly this bug: a BUY's
//     spent = floor(notional) inflates refund = locked - spent, so the taker
//     keeps the base proceeds AND a refund larger than the true unspent quote =>
//     quote minted out of escrow.
//
// Totals are summed over the fills ONCE as exact floats, then rounded ONCE at the
// asset boundary. The prior per-fill uint64(price*size) truncated DOWN on every
// fill and summed the error: 100 fills of notional 0.99 recorded spent=0 and
// refunded the entire lock. Aggregate ceiling gives spent=ceil(99.0)=99, so the
// refund is capped at the true unspent value — no extraction. spent > locked is
// still refused (minting against the proxy's own escrow).
//
// DETERMINISM (RED split): the export this settle constructs is reconstructed
// independently on every validator, so its shared-memory UTXO keys MUST be a
// pure function of consensus-agreed inputs. The settlement export is therefore
// built via NewSettlementExportTx seeded by (blockHash, txIndex) — the SAME
// coordinate that keys the idempotency receipt — never by wall-clock time. A
// time.Now() in the export identity would make deriveUTXOID(tx.ID(), i) differ
// per node and split the atomic commit on accept.
func (vm *VM) settleFromFills(taker ids.ShortID, collateralRef ids.ID, fills []Fill, blockHash ids.ID, txIndex uint32, ar *atomicRequests) error {
	// Resolve the locked collateral this settle must conserve. Absent escrow =>
	// nothing locked on the proxy side; fall back to proceeds-only settlement.
	lockedAsset, locked, haveEscrow, err := vm.state.GetEscrow(collateralRef)
	if err != nil {
		return fmt.Errorf("settle: escrow lookup: %w", err)
	}

	// Taker side: from the fills if any, else (zero-fill) from the locked-asset
	// identity recorded at import so a fully-unfilled order still refunds. A single
	// marketable submit takes exactly ONE side, so fills[0].Side governs the whole
	// stream. Per-fill side validity (0=BUY, 1=SELL) is a WIRE property enforced at
	// the boundary (DecodeFills); this defensive re-check covers callers that build
	// fills directly (tests) and keeps settle self-protecting at the policy edge.
	takerSide := uint8(0)
	if len(fills) > 0 {
		takerSide = fills[0].Side
	}
	if takerSide > 1 {
		return fmt.Errorf("settle: invalid taker side %d", takerSide)
	}

	// Aggregate the fill totals ONCE as exact floats (base = sum(size), quote =
	// sum(price*size)). Rounding to integer asset units happens later, in the
	// direction proper to each leg — NOT per-fill, which would truncate DOWN on
	// every fill and sum a directional leak (the escrow-truncation mint).
	//
	// SINGLE-SIDE GUARD (RED mixed-side over-credit): the proceeds/spent split
	// below applies ONE direction (takerSide) to the WHOLE aggregate, so a fill
	// stream that mixes sides would be credited as if every fill took takerSide —
	// minting the opposite-side volume (a lying/MITM backend returns [BUY 10,
	// SELL 1000] and the proxy credits base = 1010). A submit cannot legitimately
	// fill both sides; refuse the stream rather than over-credit.
	var baseFloat, quoteFloat float64
	for _, f := range fills {
		if f.Side != takerSide {
			return fmt.Errorf("settle: mixed-side fills (fill side %d != taker side %d)", f.Side, takerSide)
		}
		baseFloat += f.Size
		quoteFloat += f.Price * f.Size
	}

	// Directional rounding by purpose (atomic.go): a RECEIVED quantity rounds DOWN
	// (never over-credit); a SPENT quantity rounds UP (never inflate the refund).
	// BUY  receives base, spends quote. SELL receives quote, spends base.
	var proceeds uint64 // the opposite asset the taker receives
	var spent uint64    // the locked asset consumed (reduces the refund)
	if takerSide == 0 { // BUY
		if proceeds, err = quantToCredit(baseFloat); err != nil {
			return err
		}
		if spent, err = quantToCharge(quoteFloat); err != nil {
			return err
		}
	} else { // SELL
		if proceeds, err = quantToCredit(quoteFloat); err != nil {
			return err
		}
		if spent, err = quantToCharge(baseFloat); err != nil {
			return err
		}
	}

	outs := make([]txs.AtomicOutput, 0, 2)

	// PROCEEDS leg — the opposite asset the taker received (ref-derived routing
	// handle; the C-Chain side maps it to the real ERC-20).
	if takerSide == 0 { // BUY: receives base
		outs = append(outs, txs.AtomicOutput{Owner: taker, Asset: assetFromRef(collateralRef, 0), Amount: proceeds})
	} else { // SELL: receives quote
		outs = append(outs, txs.AtomicOutput{Owner: taker, Asset: assetFromRef(collateralRef, 1), Amount: proceeds})
	}

	// REFUND leg — the unfilled remainder of the locked asset.
	if haveEscrow {
		// A settle can never consume more than was locked; that would be the
		// proxy minting against its own escrow. Refuse rather than underflow.
		if spent > locked {
			return fmt.Errorf("settle: spent %d exceeds locked collateral %d (would mint)", spent, locked)
		}
		if refund := locked - spent; refund > 0 {
			outs = append(outs, txs.AtomicOutput{Owner: taker, Asset: lockedAsset, Amount: refund})
		}
		// Consume the escrow exactly once — the locked collateral is now fully
		// accounted for (proceeds + refund) and must not be refundable again.
		if err := vm.state.ConsumeEscrow(collateralRef); err != nil {
			return fmt.Errorf("settle: consume escrow: %w", err)
		}
	}

	outs = nonZeroOutputs(outs)
	if len(outs) == 0 {
		// Nothing realized and nothing locked — no value to move. (Both proceeds
		// and refund were zero, e.g. a zero-fill with no escrow.)
		return nil
	}
	// Deterministic settlement identity: seed CreatedAt from the block hash (a
	// consensus-agreed value, NOT wall-clock) and the txIndex via Nonce. Every
	// validator that replays this block builds byte-identical export wire bytes,
	// so tx.ID() — and every export UTXO key derived from it — is identical
	// network-wide. This is the fix for the time.Now() shared-memory-key split.
	createdAt := int64(binary.BigEndian.Uint64(blockHash[:8]))
	tx := txs.NewSettlementExportTx(taker, txIndex, vm.cChainID(), outs, collateralRef, createdAt)
	return vm.executeExport(tx, ar)
}

// recordReceipt stores the relay receipt binding (blockHash, txIndex) to the
// hash of the d-chain's response — the replay-idempotency witness. The response
// is a clob_submit fills frame, or a clob_place / clob_cancel ack; the witness
// is the same primitive either way (one relay per (blockHash, txIndex)).
func (vm *VM) recordReceipt(blockHash ids.ID, txIndex uint32, respWire []byte) error {
	return vm.state.PutReceipt(&dexstate.Receipt{
		BlockHash: blockHash,
		TxIndex:   txIndex,
		RespHash:  ids.ID(sha256.Sum256(respWire)),
	})
}

// acceptBlock is the proxy's SINGLE COMMIT POINT — and, by the RED #9 fix, a
// PURE DETERMINISTIC FUNCTION of the block (it performs NO d-chain I/O; the relay
// already happened once at the proposer's build, and the fills are carried in the
// block bytes). It commits the C-side settlement atomically with the proxy state:
//
//  1. settleCarried — turn the block-CARRIED fills into export legs (settle from
//     bytes, never from a fresh relay). Runs identically on every validator, so
//     the export keys — and the root — are byte-identical network-wide. A node
//     never relays here, so two validators can no longer diverge on per-call fills
//     (the per-validator-relay fork is structurally impossible).
//  2. CommitBatch — snapshot every versiondb write made during Verify (consumed
//     UTXOs, escrow) AND during step 1 (escrow-consume).
//  3. commitAtomic — apply that state batch together with the cross-chain
//     requests (import removes from Verify + export puts from step 1) in one
//     atomic shared-memory commit (the platformvm acceptor pattern).
//
// Atomicity-or-reversal: the C-side credit and the escrow-consume land in the same
// atomic apply, so a settle never half-applies. A Rejected block reaches a plain
// db.Abort (Reject) and commits nothing on the C-side. (The d-chain relay for a
// rejected block happened at the proposer's build and is the documented, bounded
// proposer-trust cost — see carried_fills.go.)
func (vm *VM) acceptBlock(ctx context.Context, result *BlockResult) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.db == nil {
		return nil
	}
	ar := newAtomicRequests()
	if result != nil && result.atomic != nil {
		ar = result.atomic
	}

	// Settle from the block-carried fills now (deterministic; NO d-chain I/O),
	// accumulating settlement exports into ar and consuming escrow in the versiondb
	// in-memory layer that CommitBatch is about to snapshot.
	if result != nil {
		vm.settleCarried(result, ar)
	}

	// FINAL root: recompute over the post-accept state — escrow consumed by the
	// settle and the settlement EXPORT legs now present in ar (neither existed at
	// Verify, which only staged the imports). Because settleCarried is a pure
	// function of the carried fills, two validators processing the same block bytes
	// reach the IDENTICAL post-accept state and ar, hence the identical root. The
	// versiondb in-memory layer still holds these writes (CommitBatch has not run
	// yet), so the walk sees them.
	if result != nil {
		root, err := vm.computeStateRoot(result.blockHash, result)
		if err != nil {
			return err
		}
		result.StateRoot = root
	}
	_ = ctx

	// Abort clears the versiondb's in-memory layer after the batch is written by
	// Apply/Write (the platformvm defer-Abort pattern).
	defer vm.db.Abort()
	batch, err := vm.db.CommitBatch()
	if err != nil {
		return fmt.Errorf("dexvm: commit batch: %w", err)
	}
	return vm.commitAtomic(ar, batch)
}

// computeStateRoot computes the block's StateRoot as a FAITHFUL commitment to
// the proxy's mutated state — not just an identifier of the block. It folds
// together, in fixed order:
//
//  1. blockHash + height — the consensus binding (kept from the original root).
//  2. state.StateHash()  — every persisted key/value: the consumed-UTXO set,
//     collateral escrow, replay nonces, relay receipts, last-block pointer.
//  3. result.atomic      — the cross-chain operations this block produces (the
//     import UTXO removes and export UTXO puts that move value across chains).
//
// Because (2) and (3) are the ACTUAL state and the ACTUAL settlement output,
// two nodes that genuinely diverge — one consumed an escrow / committed an
// import+export, a peer whose relay failed committed no cross-chain op — can no
// longer emit an identical root: the divergent escrow/receipt key (2) or the
// missing export leg (3) changes the digest. A matching blockHash is no longer
// sufficient to forge a matching root, so the root-based safety check actually
// witnesses real divergence.
//
// It returns an error only if the state walk fails (a corrupt/closed DB);
// callers treat that as a block-processing failure rather than silently
// committing an unverifiable root.
func (vm *VM) computeStateRoot(blockHash ids.ID, result *BlockResult) (ids.ID, error) {
	h := sha256.New()

	h.Write(blockHash[:])
	var heightBuf [8]byte
	binary.BigEndian.PutUint64(heightBuf[:], vm.currentBlockHeight)
	h.Write(heightBuf[:])

	// (2) Every persisted key/value (consumed-UTXO set, escrow, replay nonces,
	// relay receipts, last-block pointer) via the state's own deterministic walk.
	stateHash, err := vm.state.StateHash()
	if err != nil {
		return ids.Empty, fmt.Errorf("compute state root: %w", err)
	}
	h.Write(stateHash[:])

	// (3) The cross-chain operations this block produces — the import UTXO removes
	// accumulated at Verify and the export UTXO puts appended at accept. These are
	// the block's OTHER mutated output (alongside persisted state); a node whose
	// relay failed accumulates no export leg, so this fold is what makes its root
	// differ from a peer that settled. nil-safe for blocks with no atomic legs.
	if result != nil && result.atomic != nil {
		result.atomic.hashInto(h)
	}
	return ids.ID(h.Sum(nil)), nil
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
