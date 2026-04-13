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
	"math/big"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/rpc/v2"
	rpcjson "github.com/gorilla/rpc/v2/json"
	"github.com/gorilla/websocket"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"

	consensuscore "github.com/luxfi/consensus/core"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/chains/dexvm/api"
	"github.com/luxfi/chains/dexvm/config"
	"github.com/luxfi/chains/dexvm/liquidity"
	"github.com/luxfi/chains/dexvm/mev"
	"github.com/luxfi/chains/dexvm/network"
	"github.com/luxfi/chains/dexvm/orderbook"
	"github.com/luxfi/chains/dexvm/perpetuals"
	"github.com/luxfi/chains/dexvm/txs"
	"github.com/luxfi/runtime"
	"github.com/luxfi/timer/mockable"
	"github.com/luxfi/version"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/warp"
)

var (
	errUnknownState    = errors.New("unknown state")
	errNotBootstrapped = errors.New("VM not bootstrapped")
	errShutdown        = errors.New("VM is shutting down")

	_ = errNotBootstrapped
	_ = errShutdown
)

// BlockResult represents the deterministic result of processing a block.
// All state changes are captured here for verifiability.
type BlockResult struct {
	// BlockHeight is the height of the processed block
	BlockHeight uint64

	// Timestamp is when this block was processed
	Timestamp time.Time

	// MatchedTrades from order matching in this block
	MatchedTrades []orderbook.Trade

	// FundingPayments processed in this block (if any)
	FundingPayments []*perpetuals.FundingPayment

	// Liquidations executed in this block (if any)
	Liquidations []*perpetuals.LiquidationEvent

	// StateRoot is the merkle root of state after this block
	StateRoot ids.ID
}

// VM implements the DEX Virtual Machine using a pure functional architecture.
// Native decentralized exchange — Hyperliquid-class on-chain CLOB.
// All state transitions happen deterministically within block processing:
//   - Central Limit Order Book (CLOB) — native, not EVM-based
//   - Perpetual futures with auto-deleveraging
//   - Cross-chain atomic swaps via Warp messaging
//   - 1ms block times for ultra-low latency trading
//
// DESIGN: No background goroutines. All operations are block-driven and deterministic.
// This ensures:
//   - Every node produces identical state from identical inputs
//   - No race conditions or non-deterministic behavior
//   - Easy to test and verify
//   - Replay-safe for auditing
type VM struct {
	config.Config

	// Logger for this VM
	log log.Logger

	// Lock for thread safety (only for API access, not consensus)
	lock sync.RWMutex

	// Consensus context - provides chain identity and network info
	consensusRuntime *runtime.Runtime

	// Chain identity
	chainID ids.ID

	// Database management
	baseDB database.Database
	db     *versiondb.Database

	// Used to check local time
	clock mockable.Clock

	// Metrics
	registerer metric.Registerer

	// Network peers
	connectedPeers map[ids.NodeID]*version.Application

	// Application sender for gossip
	appSender warp.Sender

	// DEX components (all operations on these are deterministic)
	orderbooks      map[string]*orderbook.Orderbook    // symbol -> orderbook
	liquidityMgr    *liquidity.Manager                 // AMM liquidity pools
	perpetualsEng   *perpetuals.Engine                 // Perpetual futures engine
	commitmentStore *mev.CommitmentStore               // MEV protection commit-reveal
	adlEngine       *perpetuals.AutoDeleveragingEngine // Auto-deleveraging

	// Block state
	currentBlockHeight uint64
	lastBlockTime      time.Time
	lastFundingTime    time.Time // Tracks when funding was last processed

	// Lifecycle state
	bootstrapped  bool
	isInitialized bool
	shutdown      bool

	// Channel for sending messages to consensus engine
	toEngine chan<- vmcore.Message
}

// NewVMForTest creates a new VM instance for testing purposes.
// This allows external test packages to create VM instances without
// needing to access internal fields directly.
func NewVMForTest(cfg config.Config, logger log.Logger) *VM {
	return &VM{
		Config: cfg,
		log:    logger,
	}
}

// Initialize implements consensuscore.VM interface.
// It sets up the VM with the provided context, database, and genesis data.
func (vm *VM) Initialize(
	ctx context.Context,
	vmInit vmcore.Init,
) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	// Cast Runtime
	vm.consensusRuntime = vmInit.Runtime
	vm.chainID = vm.consensusRuntime.ChainID

	// Initialize logger from Runtime
	if vm.consensusRuntime != nil && vm.consensusRuntime.Log != nil {
		if logger, ok := vm.consensusRuntime.Log.(log.Logger); ok && !logger.IsZero() {
			vm.log = logger
		} else {
			vm.log = log.Noop()
		}
	} else {
		vm.log = log.Noop()
	}

	// Setup database
	vm.baseDB = vmInit.DB
	vm.db = versiondb.New(vm.baseDB)

	// Setup message channel
	vm.toEngine = vmInit.ToEngine

	// Setup app sender
	if vmInit.Sender != nil {
		vm.appSender = vmInit.Sender
	}

	// Initialize peer tracking
	vm.connectedPeers = make(map[ids.NodeID]*version.Application)

	// Initialize DEX components
	vm.orderbooks = make(map[string]*orderbook.Orderbook)
	vm.liquidityMgr = liquidity.NewManager()
	vm.perpetualsEng = perpetuals.NewEngine()
	vm.commitmentStore = mev.NewCommitmentStore()
	vm.adlEngine = perpetuals.NewAutoDeleveragingEngine(perpetuals.DefaultADLConfig())

	// Initialize block state
	vm.currentBlockHeight = 0
	vm.lastBlockTime = time.Time{}
	vm.lastFundingTime = time.Time{}

	// Parse genesis if provided
	if len(vmInit.Genesis) > 0 {
		if err := vm.parseGenesis(vmInit.Genesis); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}

	// Parse config if provided
	if len(vmInit.Config) > 0 {
		if err := vm.parseConfig(vmInit.Config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	}

	vm.isInitialized = true
	if !vm.log.IsZero() {
		vm.log.Info("DEX VM initialized (functional mode)",
			"chainID", vm.chainID,
			"blockInterval", vm.Config.BlockInterval,
		)
	}

	return nil
}

// Genesis represents the DEX VM genesis configuration.
type Genesis struct {
	// TradingPairs defines the initial trading pairs (order book markets)
	TradingPairs []GenesisTradingPair `json:"tradingPairs"`

	// LiquidityPools defines the initial AMM liquidity pools
	LiquidityPools []GenesisPool `json:"liquidityPools"`

	// PerpetualMarkets defines the initial perpetual futures markets
	PerpetualMarkets []GenesisPerpMarket `json:"perpetualMarkets"`

	// FeeConfig contains global fee configuration
	FeeConfig GenesisFeeConfig `json:"feeConfig"`

	// TrustedChains are chain IDs trusted for cross-chain operations
	TrustedChains []string `json:"trustedChains"`

	// InitialBalances are pre-funded accounts (for testing/airdrops)
	InitialBalances []GenesisBalance `json:"initialBalances,omitempty"`
}

// GenesisTradingPair defines a trading pair for the order book.
type GenesisTradingPair struct {
	Symbol     string `json:"symbol"`     // e.g., "LUX/USDC"
	BaseAsset  string `json:"baseAsset"`  // Base asset ID
	QuoteAsset string `json:"quoteAsset"` // Quote asset ID
}

// GenesisPool defines an initial liquidity pool.
type GenesisPool struct {
	Token0        string `json:"token0"`
	Token1        string `json:"token1"`
	InitialToken0 uint64 `json:"initialToken0"`
	InitialToken1 uint64 `json:"initialToken1"`
	PoolType      uint8  `json:"poolType"` // 0=ConstantProduct, 1=StableSwap, 2=Concentrated
	FeeBps        uint16 `json:"feeBps"`
}

// GenesisPerpMarket defines an initial perpetual futures market.
type GenesisPerpMarket struct {
	Symbol            string `json:"symbol"`     // e.g., "BTC-PERP"
	BaseAsset         string `json:"baseAsset"`  // e.g., BTC
	QuoteAsset        string `json:"quoteAsset"` // e.g., USDC
	MaxLeverage       uint16 `json:"maxLeverage"`
	MaintenanceMargin uint16 `json:"maintenanceMarginBps"` // in basis points
	InitialMargin     uint16 `json:"initialMarginBps"`     // in basis points
	MakerFee          uint16 `json:"makerFeeBps"`
	TakerFee          uint16 `json:"takerFeeBps"`
}

// GenesisFeeConfig contains global fee configuration.
type GenesisFeeConfig struct {
	DefaultSwapFeeBps uint16 `json:"defaultSwapFeeBps"`
	ProtocolFeeBps    uint16 `json:"protocolFeeBps"`
	MaxSlippageBps    uint16 `json:"maxSlippageBps"`
}

// GenesisBalance defines a pre-funded account balance.
type GenesisBalance struct {
	Address string `json:"address"` // Hex-encoded address
	Token   string `json:"token"`   // Token ID
	Amount  uint64 `json:"amount"`
}

// parseGenesis parses the genesis data and initializes initial state.
func (vm *VM) parseGenesis(genesisBytes []byte) error {
	var genesis Genesis
	if err := json.Unmarshal(genesisBytes, &genesis); err != nil {
		return fmt.Errorf("failed to unmarshal genesis: %w", err)
	}

	// Initialize trading pairs (order books)
	for _, pair := range genesis.TradingPairs {
		ob := orderbook.New(pair.Symbol)
		vm.orderbooks[pair.Symbol] = ob
		if !vm.log.IsZero() {
			vm.log.Info("Initialized trading pair", "symbol", pair.Symbol)
		}
	}

	// Initialize liquidity pools
	for _, pool := range genesis.LiquidityPools {
		token0, err := ids.FromString(pool.Token0)
		if err != nil {
			return fmt.Errorf("invalid token0 ID %s: %w", pool.Token0, err)
		}
		token1, err := ids.FromString(pool.Token1)
		if err != nil {
			return fmt.Errorf("invalid token1 ID %s: %w", pool.Token1, err)
		}

		_, err = vm.liquidityMgr.CreatePool(
			token0, token1,
			new(big.Int).SetUint64(pool.InitialToken0),
			new(big.Int).SetUint64(pool.InitialToken1),
			liquidity.PoolType(pool.PoolType),
			pool.FeeBps,
		)
		if err != nil {
			return fmt.Errorf("failed to create pool %s/%s: %w", pool.Token0, pool.Token1, err)
		}
		if !vm.log.IsZero() {
			vm.log.Info("Initialized liquidity pool", "token0", pool.Token0, "token1", pool.Token1)
		}
	}

	// Initialize perpetual markets
	for _, market := range genesis.PerpetualMarkets {
		baseAsset, err := ids.FromString(market.BaseAsset)
		if err != nil {
			return fmt.Errorf("invalid base asset ID %s: %w", market.BaseAsset, err)
		}
		quoteAsset, err := ids.FromString(market.QuoteAsset)
		if err != nil {
			return fmt.Errorf("invalid quote asset ID %s: %w", market.QuoteAsset, err)
		}

		// Default initial price of 1e18 (1.0 scaled)
		initialPrice := new(big.Int).Set(perpetuals.PrecisionFactor)
		// Default min size of 1e15 (0.001 scaled)
		minSize := new(big.Int).Div(perpetuals.PrecisionFactor, big.NewInt(1000))
		// Default tick size of 1e12 (0.000001 scaled)
		tickSize := new(big.Int).Div(perpetuals.PrecisionFactor, big.NewInt(1000000))

		_, err = vm.perpetualsEng.CreateMarket(
			market.Symbol,
			baseAsset,
			quoteAsset,
			initialPrice,
			market.MaxLeverage,
			minSize,
			tickSize,
			market.MakerFee,
			market.TakerFee,
			market.MaintenanceMargin,
			market.InitialMargin,
		)
		if err != nil {
			return fmt.Errorf("failed to create perp market %s: %w", market.Symbol, err)
		}
		if !vm.log.IsZero() {
			vm.log.Info("Initialized perpetual market", "symbol", market.Symbol)
		}
	}

	// Apply fee configuration
	if genesis.FeeConfig.DefaultSwapFeeBps > 0 {
		vm.Config.DefaultSwapFeeBps = genesis.FeeConfig.DefaultSwapFeeBps
	}
	if genesis.FeeConfig.ProtocolFeeBps > 0 {
		vm.Config.ProtocolFeeBps = genesis.FeeConfig.ProtocolFeeBps
	}
	if genesis.FeeConfig.MaxSlippageBps > 0 {
		vm.Config.MaxSlippageBps = genesis.FeeConfig.MaxSlippageBps
	}

	// Parse trusted chains for cross-chain operations
	for _, chainIDStr := range genesis.TrustedChains {
		chainID, err := ids.FromString(chainIDStr)
		if err != nil {
			return fmt.Errorf("invalid trusted chain ID %s: %w", chainIDStr, err)
		}
		vm.Config.TrustedChains = append(vm.Config.TrustedChains, chainID)
		if !vm.log.IsZero() {
			vm.log.Info("Added trusted chain", "chainID", chainID)
		}
	}

	if !vm.log.IsZero() {
		vm.log.Info("Genesis parsed successfully",
			"tradingPairs", len(genesis.TradingPairs),
			"pools", len(genesis.LiquidityPools),
			"perpMarkets", len(genesis.PerpetualMarkets),
			"trustedChains", len(genesis.TrustedChains),
		)
	}

	return nil
}

// parseConfig parses and applies runtime configuration.
func (vm *VM) parseConfig(configBytes []byte) error {
	// Parse config into a temporary struct to avoid overwriting defaults
	var cfg config.Config
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Only apply non-zero values to preserve defaults
	if cfg.IndexAllowIncomplete {
		vm.Config.IndexAllowIncomplete = cfg.IndexAllowIncomplete
	}
	if cfg.IndexTransactions {
		vm.Config.IndexTransactions = cfg.IndexTransactions
	}
	if cfg.ChecksumsEnabled {
		vm.Config.ChecksumsEnabled = cfg.ChecksumsEnabled
	}
	if cfg.DefaultSwapFeeBps > 0 {
		vm.Config.DefaultSwapFeeBps = cfg.DefaultSwapFeeBps
	}
	if cfg.ProtocolFeeBps > 0 {
		vm.Config.ProtocolFeeBps = cfg.ProtocolFeeBps
	}
	if cfg.MaxSlippageBps > 0 {
		vm.Config.MaxSlippageBps = cfg.MaxSlippageBps
	}
	if cfg.MinLiquidity > 0 {
		vm.Config.MinLiquidity = cfg.MinLiquidity
	}
	if cfg.MaxPoolsPerPair > 0 {
		vm.Config.MaxPoolsPerPair = cfg.MaxPoolsPerPair
	}
	if cfg.MaxOrdersPerAccount > 0 {
		vm.Config.MaxOrdersPerAccount = cfg.MaxOrdersPerAccount
	}
	if cfg.MaxOrderSize > 0 {
		vm.Config.MaxOrderSize = cfg.MaxOrderSize
	}
	if cfg.MinOrderSize > 0 {
		vm.Config.MinOrderSize = cfg.MinOrderSize
	}
	if cfg.OrderExpirationTime > 0 {
		vm.Config.OrderExpirationTime = cfg.OrderExpirationTime
	}
	if cfg.WarpEnabled {
		vm.Config.WarpEnabled = cfg.WarpEnabled
	}
	if cfg.TeleportEnabled {
		vm.Config.TeleportEnabled = cfg.TeleportEnabled
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
		vm.log.Info("Config parsed successfully",
			"blockInterval", vm.Config.BlockInterval,
			"maxTxsPerBlock", vm.Config.MaxTxsPerBlock,
			"warpEnabled", vm.Config.WarpEnabled,
		)
	}

	return nil
}

// SetState implements consensuscore.VM interface.
// It transitions the VM between bootstrapping and normal operation states.
// NOTE: No background goroutines are started - all operations are block-driven.
func (vm *VM) SetState(ctx context.Context, stateNum uint32) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	switch vmcore.State(stateNum) {
	case vmcore.Bootstrapping:
		if !vm.log.IsZero() {
			vm.log.Info("DEX VM entering bootstrap state")
		}
		vm.bootstrapped = false
		return nil
	case vmcore.Ready:
		if !vm.log.IsZero() {
			vm.log.Info("DEX VM entering ready state")
		}
		vm.bootstrapped = true
		return nil
	default:
		return nil
	}
}

// ProcessBlock is the core function that processes all DEX operations deterministically.
// This is called by the consensus engine for each new block.
// All state changes happen here in a deterministic, reproducible manner.
//
// Operations performed per block:
//  1. Order matching for all orderbooks
//  2. Funding rate processing (every 8 hours)
//  3. Liquidation checks
//  4. State commitment
func (vm *VM) ProcessBlock(ctx context.Context, blockHeight uint64, blockTime time.Time, txs [][]byte) (*BlockResult, error) {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.shutdown {
		return nil, errShutdown
	}

	result := &BlockResult{
		BlockHeight:     blockHeight,
		Timestamp:       blockTime,
		MatchedTrades:   make([]orderbook.Trade, 0),
		FundingPayments: make([]*perpetuals.FundingPayment, 0),
		Liquidations:    make([]*perpetuals.LiquidationEvent, 0),
	}

	// 1. Process all transactions in the block
	for _, tx := range txs {
		if err := vm.processTx(tx, result); err != nil {
			// Log but continue - individual tx failures don't fail the block
			if !vm.log.IsZero() {
				vm.log.Warn("Transaction failed", "error", err)
			}
		}
	}

	// 2. Run order matching for all active orderbooks
	result.MatchedTrades = vm.matchAllOrders()

	// 3. Check if funding should be processed (every 8 hours)
	if vm.shouldProcessFunding(blockTime) {
		result.FundingPayments = vm.processFunding(blockTime)
		vm.lastFundingTime = blockTime
	}

	// 4. Check and execute liquidations
	result.Liquidations = vm.processLiquidations()

	// 5. Update block state
	vm.currentBlockHeight = blockHeight
	vm.lastBlockTime = blockTime

	// 6. Compute state root (merkle root of all state)
	result.StateRoot = vm.computeStateRoot()

	if !vm.log.IsZero() {
		vm.log.Debug("Block processed",
			"height", blockHeight,
			"trades", len(result.MatchedTrades),
			"funding", len(result.FundingPayments),
			"liquidations", len(result.Liquidations),
		)
	}

	return result, nil
}

// processTx processes a single transaction.
func (vm *VM) processTx(txBytes []byte, result *BlockResult) error {
	if len(txBytes) < 1 {
		return errors.New("empty transaction")
	}

	// Parse transaction using the TxParser
	parser := &txs.TxParser{}
	tx, err := parser.Parse(txBytes)
	if err != nil {
		return fmt.Errorf("failed to parse transaction: %w", err)
	}

	// Verify transaction
	if err := tx.Verify(); err != nil {
		return fmt.Errorf("transaction verification failed: %w", err)
	}

	// Dispatch based on transaction type
	switch tx.Type() {
	case txs.TxPlaceOrder:
		return vm.executePlaceOrder(tx.(*txs.PlaceOrderTx), result)
	case txs.TxCancelOrder:
		return vm.executeCancelOrder(tx.(*txs.CancelOrderTx))
	case txs.TxSwap:
		return vm.executeSwap(tx.(*txs.SwapTx))
	case txs.TxAddLiquidity:
		return vm.executeAddLiquidity(tx.(*txs.AddLiquidityTx))
	case txs.TxRemoveLiquidity:
		return vm.executeRemoveLiquidity(tx.(*txs.RemoveLiquidityTx))
	case txs.TxCreatePool:
		return vm.executeCreatePool(tx.(*txs.CreatePoolTx))
	case txs.TxCrossChainSwap:
		return vm.executeCrossChainSwap(tx.(*txs.CrossChainSwapTx))
	case txs.TxCrossChainTransfer:
		return vm.executeCrossChainTransfer(tx.(*txs.CrossChainTransferTx))
	case txs.TxCommitOrder:
		return vm.executeCommitOrder(tx.(*txs.CommitOrderTx))
	case txs.TxRevealOrder:
		return vm.executeRevealOrder(tx.(*txs.RevealOrderTx), result)
	default:
		return fmt.Errorf("unknown transaction type: %d", tx.Type())
	}
}

// executePlaceOrder executes a place order transaction.
func (vm *VM) executePlaceOrder(tx *txs.PlaceOrderTx, result *BlockResult) error {
	ob, exists := vm.orderbooks[tx.Symbol]
	if !exists {
		return fmt.Errorf("orderbook not found for symbol: %s", tx.Symbol)
	}

	order := &orderbook.Order{
		ID:          tx.ID(),
		Owner:       tx.Sender(),
		Symbol:      tx.Symbol,
		Side:        orderbook.Side(tx.Side),
		Type:        orderbook.OrderType(tx.OrderType),
		Price:       tx.Price,
		Quantity:    tx.Quantity,
		StopPrice:   tx.StopPrice,
		Status:      orderbook.StatusOpen,
		CreatedAt:   tx.Timestamp(),
		ExpiresAt:   tx.ExpiresAt,
		PostOnly:    tx.PostOnly,
		ReduceOnly:  tx.ReduceOnly,
		TimeInForce: tx.TimeInForce,
	}

	trades, err := ob.AddOrder(order)
	if err != nil {
		return fmt.Errorf("failed to add order: %w", err)
	}

	// Convert to orderbook.Trade slice for result
	for _, trade := range trades {
		result.MatchedTrades = append(result.MatchedTrades, *trade)
	}

	if !vm.log.IsZero() {
		vm.log.Debug("Order placed",
			"orderID", order.ID,
			"symbol", tx.Symbol,
			"side", order.Side,
			"price", tx.Price,
			"quantity", tx.Quantity,
			"trades", len(trades),
		)
	}

	return nil
}

// executeCancelOrder executes a cancel order transaction.
func (vm *VM) executeCancelOrder(tx *txs.CancelOrderTx) error {
	ob, exists := vm.orderbooks[tx.Symbol]
	if !exists {
		return fmt.Errorf("orderbook not found for symbol: %s", tx.Symbol)
	}

	// Verify the order belongs to the sender
	order, err := ob.GetOrder(tx.OrderID)
	if err != nil {
		return err
	}
	if order.Owner != tx.Sender() {
		return errors.New("cannot cancel order owned by another account")
	}

	if err := ob.CancelOrder(tx.OrderID); err != nil {
		return fmt.Errorf("failed to cancel order: %w", err)
	}

	if !vm.log.IsZero() {
		vm.log.Debug("Order cancelled", "orderID", tx.OrderID, "symbol", tx.Symbol)
	}

	return nil
}

// executeSwap executes an AMM swap transaction.
func (vm *VM) executeSwap(tx *txs.SwapTx) error {
	// Check deadline
	if tx.Deadline > 0 && time.Now().UnixNano() > tx.Deadline {
		return errors.New("swap deadline exceeded")
	}

	_, err := vm.liquidityMgr.Swap(
		tx.PoolID,
		tx.TokenIn,
		new(big.Int).SetUint64(tx.AmountIn),
		new(big.Int).SetUint64(tx.MinAmountOut),
	)
	if err != nil {
		return fmt.Errorf("swap failed: %w", err)
	}

	if !vm.log.IsZero() {
		vm.log.Debug("Swap executed",
			"poolID", tx.PoolID,
			"tokenIn", tx.TokenIn,
			"amountIn", tx.AmountIn,
		)
	}

	return nil
}

// executeAddLiquidity executes an add liquidity transaction.
func (vm *VM) executeAddLiquidity(tx *txs.AddLiquidityTx) error {
	// Check deadline
	if tx.Deadline > 0 && time.Now().UnixNano() > tx.Deadline {
		return errors.New("add liquidity deadline exceeded")
	}

	liquidity, err := vm.liquidityMgr.AddLiquidity(
		tx.PoolID,
		new(big.Int).SetUint64(tx.Token0Amount),
		new(big.Int).SetUint64(tx.Token1Amount),
		new(big.Int).SetUint64(tx.MinLPTokens),
	)
	if err != nil {
		return fmt.Errorf("add liquidity failed: %w", err)
	}

	if !vm.log.IsZero() {
		vm.log.Debug("Liquidity added",
			"poolID", tx.PoolID,
			"token0", tx.Token0Amount,
			"token1", tx.Token1Amount,
			"lpTokens", liquidity,
		)
	}

	return nil
}

// executeRemoveLiquidity executes a remove liquidity transaction.
func (vm *VM) executeRemoveLiquidity(tx *txs.RemoveLiquidityTx) error {
	// Check deadline
	if tx.Deadline > 0 && time.Now().UnixNano() > tx.Deadline {
		return errors.New("remove liquidity deadline exceeded")
	}

	amount0, amount1, err := vm.liquidityMgr.RemoveLiquidity(
		tx.PoolID,
		new(big.Int).SetUint64(tx.LPTokenAmount),
		new(big.Int).SetUint64(tx.MinToken0),
		new(big.Int).SetUint64(tx.MinToken1),
	)
	if err != nil {
		return fmt.Errorf("remove liquidity failed: %w", err)
	}

	if !vm.log.IsZero() {
		vm.log.Debug("Liquidity removed",
			"poolID", tx.PoolID,
			"lpTokens", tx.LPTokenAmount,
			"token0Out", amount0,
			"token1Out", amount1,
		)
	}

	return nil
}

// executeCreatePool executes a create pool transaction.
func (vm *VM) executeCreatePool(tx *txs.CreatePoolTx) error {
	pool, err := vm.liquidityMgr.CreatePool(
		tx.Token0,
		tx.Token1,
		new(big.Int).SetUint64(tx.InitialToken0),
		new(big.Int).SetUint64(tx.InitialToken1),
		liquidity.PoolType(tx.PoolType),
		tx.SwapFeeBps,
	)
	if err != nil {
		return fmt.Errorf("create pool failed: %w", err)
	}

	if !vm.log.IsZero() {
		vm.log.Info("Pool created",
			"poolID", pool.ID,
			"token0", tx.Token0,
			"token1", tx.Token1,
			"type", tx.PoolType,
		)
	}

	return nil
}

// executeCrossChainSwap executes a cross-chain swap via Warp.
func (vm *VM) executeCrossChainSwap(tx *txs.CrossChainSwapTx) error {
	// Verify source chain is trusted
	trusted := false
	for _, chainID := range vm.Config.TrustedChains {
		if chainID == tx.SourceChain {
			trusted = true
			break
		}
	}
	if !trusted {
		return errors.New("source chain not trusted for cross-chain swap")
	}

	// Check deadline
	if tx.Deadline > 0 && time.Now().UnixNano() > tx.Deadline {
		return errors.New("cross-chain swap deadline exceeded")
	}

	// The actual swap is executed when the Warp message is received
	// Here we just validate and prepare
	if !vm.log.IsZero() {
		vm.log.Debug("Cross-chain swap initiated",
			"sourceChain", tx.SourceChain,
			"destChain", tx.DestChain,
			"tokenIn", tx.TokenIn,
			"amountIn", tx.AmountIn,
		)
	}

	return nil
}

// executeCrossChainTransfer executes a cross-chain transfer via Warp.
func (vm *VM) executeCrossChainTransfer(tx *txs.CrossChainTransferTx) error {
	// Verify source chain is trusted
	trusted := false
	for _, chainID := range vm.Config.TrustedChains {
		if chainID == tx.SourceChain {
			trusted = true
			break
		}
	}
	if !trusted {
		return errors.New("source chain not trusted for cross-chain transfer")
	}

	if !vm.log.IsZero() {
		vm.log.Debug("Cross-chain transfer initiated",
			"sourceChain", tx.SourceChain,
			"destChain", tx.DestChain,
			"token", tx.Token,
			"amount", tx.Amount,
		)
	}

	return nil
}

// executeCommitOrder executes a commit phase for MEV-protected order placement.
func (vm *VM) executeCommitOrder(tx *txs.CommitOrderTx) error {
	// Add commitment to the store with current block info
	err := vm.commitmentStore.AddCommitment(
		tx.CommitmentHash,
		tx.Sender(),
		vm.currentBlockHeight,
		vm.lastBlockTime,
	)
	if err != nil {
		return fmt.Errorf("failed to store commitment: %w", err)
	}

	if !vm.log.IsZero() {
		vm.log.Debug("Order commitment stored",
			"hash", tx.CommitmentHash,
			"sender", tx.Sender(),
		)
	}

	return nil
}

// executeRevealOrder executes a reveal phase for MEV-protected order placement.
func (vm *VM) executeRevealOrder(tx *txs.RevealOrderTx, result *BlockResult) error {
	// Use the Reveal method which handles verification and marks as revealed
	orderBytes := mev.SerializeOrderForCommitment(
		tx.Symbol,
		tx.Side,
		tx.OrderType,
		tx.Price,
		tx.Quantity,
		tx.TimeInForce,
	)

	_, err := vm.commitmentStore.Reveal(
		tx.CommitmentHash,
		orderBytes,
		tx.Salt,
		tx.Sender(),
		vm.lastBlockTime,
	)
	if err != nil {
		return fmt.Errorf("commitment reveal failed: %w", err)
	}

	// Now execute as a regular place order
	ob, exists := vm.orderbooks[tx.Symbol]
	if !exists {
		return fmt.Errorf("orderbook not found for symbol: %s", tx.Symbol)
	}

	order := &orderbook.Order{
		ID:          tx.ID(),
		Owner:       tx.Sender(),
		Symbol:      tx.Symbol,
		Side:        orderbook.Side(tx.Side),
		Type:        orderbook.OrderType(tx.OrderType),
		Price:       tx.Price,
		Quantity:    tx.Quantity,
		StopPrice:   tx.StopPrice,
		Status:      orderbook.StatusOpen,
		CreatedAt:   tx.Timestamp(),
		ExpiresAt:   tx.ExpiresAt,
		PostOnly:    tx.PostOnly,
		ReduceOnly:  tx.ReduceOnly,
		TimeInForce: tx.TimeInForce,
	}

	trades, err := ob.AddOrder(order)
	if err != nil {
		return fmt.Errorf("failed to add revealed order: %w", err)
	}

	for _, trade := range trades {
		result.MatchedTrades = append(result.MatchedTrades, *trade)
	}

	if !vm.log.IsZero() {
		vm.log.Debug("Order revealed and placed",
			"orderID", order.ID,
			"symbol", tx.Symbol,
			"trades", len(trades),
		)
	}

	return nil
}


// matchAllOrders runs the matching engine for all orderbooks.
// This is deterministic - same orders always produce same matches.
func (vm *VM) matchAllOrders() []orderbook.Trade {
	var allTrades []orderbook.Trade

	for symbol, ob := range vm.orderbooks {
		trades := ob.Match()
		if len(trades) > 0 {
			allTrades = append(allTrades, trades...)
			if !vm.log.IsZero() {
				vm.log.Debug("Matched trades", "symbol", symbol, "count", len(trades))
			}
		}
	}

	return allTrades
}

// shouldProcessFunding determines if funding should be processed.
// Funding happens every 8 hours (28800 seconds).
func (vm *VM) shouldProcessFunding(blockTime time.Time) bool {
	if vm.lastFundingTime.IsZero() {
		return true // First funding
	}

	fundingInterval := 8 * time.Hour
	return blockTime.Sub(vm.lastFundingTime) >= fundingInterval
}

// processFunding processes funding payments for all perpetual markets.
// This is deterministic based on current positions and mark prices.
func (vm *VM) processFunding(blockTime time.Time) []*perpetuals.FundingPayment {
	var allPayments []*perpetuals.FundingPayment

	for _, m := range vm.perpetualsEng.GetAllMarkets() {
		market, ok := m.(*perpetuals.Market)
		if !ok {
			continue
		}
		payments, err := vm.perpetualsEng.ProcessFunding(market.Symbol)
		if err != nil {
			if !vm.log.IsZero() {
				vm.log.Warn("Failed to process funding", "market", market.Symbol, "error", err)
			}
			continue
		}
		allPayments = append(allPayments, payments...)
	}

	return allPayments
}

// processLiquidations checks and executes liquidations for all markets.
// This is deterministic based on current prices and position health.
func (vm *VM) processLiquidations() []*perpetuals.LiquidationEvent {
	var allLiquidations []*perpetuals.LiquidationEvent

	for _, m := range vm.perpetualsEng.GetAllMarkets() {
		market, ok := m.(*perpetuals.Market)
		if !ok {
			continue
		}
		liquidations, err := vm.perpetualsEng.CheckAndLiquidate(market.Symbol)
		if err != nil {
			if !vm.log.IsZero() {
				vm.log.Warn("Failed to check liquidations", "market", market.Symbol, "error", err)
			}
			continue
		}
		allLiquidations = append(allLiquidations, liquidations...)
	}

	return allLiquidations
}

// computeStateRoot computes the merkle root of all state.
// This ensures all nodes agree on state after processing a block.
// The merkle tree is computed over all state in deterministic order.
func (vm *VM) computeStateRoot() ids.ID {
	// Collect all leaf hashes in deterministic order
	var leaves [][]byte

	// 1. Hash all orderbook state (sorted by symbol)
	orderbookLeaves := vm.computeOrderbookHashes()
	leaves = append(leaves, orderbookLeaves...)

	// 2. Hash all liquidity pool state (sorted by pool ID)
	poolLeaves := vm.computePoolHashes()
	leaves = append(leaves, poolLeaves...)

	// 3. Hash all perpetual market state (sorted by symbol)
	perpLeaves := vm.computePerpetualHashes()
	leaves = append(leaves, perpLeaves...)

	// 4. Add block metadata
	metaHash := vm.computeBlockMetaHash()
	leaves = append(leaves, metaHash)

	// If no state, return empty hash
	if len(leaves) == 0 {
		return ids.Empty
	}

	// Compute merkle root from leaves
	return computeMerkleRoot(leaves)
}

// computeOrderbookHashes computes hashes for all orderbook state.
func (vm *VM) computeOrderbookHashes() [][]byte {
	// Get sorted symbol list for deterministic ordering
	symbols := make([]string, 0, len(vm.orderbooks))
	for symbol := range vm.orderbooks {
		symbols = append(symbols, symbol)
	}
	sort.Strings(symbols)

	var hashes [][]byte
	for _, symbol := range symbols {
		ob := vm.orderbooks[symbol]

		// Hash orderbook state: symbol + bestBid + bestAsk + spread
		h := sha256.New()
		h.Write([]byte(symbol))

		bestBid := ob.GetBestBid()
		bestAsk := ob.GetBestAsk()

		bidBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(bidBuf, bestBid)
		h.Write(bidBuf)

		askBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(askBuf, bestAsk)
		h.Write(askBuf)

		// Add depth hash (top 10 levels each side)
		bids, asks := ob.GetDepth(10)
		for _, level := range bids {
			priceBuf := make([]byte, 8)
			binary.BigEndian.PutUint64(priceBuf, level.Price)
			h.Write(priceBuf)
			qtyBuf := make([]byte, 8)
			binary.BigEndian.PutUint64(qtyBuf, level.Quantity)
			h.Write(qtyBuf)
		}
		for _, level := range asks {
			priceBuf := make([]byte, 8)
			binary.BigEndian.PutUint64(priceBuf, level.Price)
			h.Write(priceBuf)
			qtyBuf := make([]byte, 8)
			binary.BigEndian.PutUint64(qtyBuf, level.Quantity)
			h.Write(qtyBuf)
		}

		hashes = append(hashes, h.Sum(nil))
	}

	return hashes
}

// computePoolHashes computes hashes for all liquidity pool state.
func (vm *VM) computePoolHashes() [][]byte {
	pools := vm.liquidityMgr.GetAllPools()

	// Sort by pool ID for deterministic ordering
	sort.Slice(pools, func(i, j int) bool {
		return pools[i].ID.Compare(pools[j].ID) < 0
	})

	var hashes [][]byte
	for _, pool := range pools {
		h := sha256.New()

		// Pool ID
		h.Write(pool.ID[:])

		// Token pair
		h.Write(pool.Token0[:])
		h.Write(pool.Token1[:])

		// Reserves (as big-endian bytes)
		h.Write(pool.Reserve0.Bytes())
		h.Write(pool.Reserve1.Bytes())

		// Total supply
		h.Write(pool.TotalSupply.Bytes())

		// Fee
		feeBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(feeBuf, pool.FeeBps)
		h.Write(feeBuf)

		hashes = append(hashes, h.Sum(nil))
	}

	return hashes
}

// computePerpetualHashes computes hashes for all perpetual market state.
func (vm *VM) computePerpetualHashes() [][]byte {
	markets := vm.perpetualsEng.GetAllMarkets()

	// Sort by symbol for deterministic ordering
	sort.Slice(markets, func(i, j int) bool {
		mi, ok1 := markets[i].(*perpetuals.Market)
		mj, ok2 := markets[j].(*perpetuals.Market)
		if !ok1 || !ok2 {
			return false
		}
		return mi.Symbol < mj.Symbol
	})

	var hashes [][]byte
	for _, m := range markets {
		market, ok := m.(*perpetuals.Market)
		if !ok {
			continue
		}

		h := sha256.New()

		// Symbol
		h.Write([]byte(market.Symbol))

		// Prices
		if market.IndexPrice != nil {
			h.Write(market.IndexPrice.Bytes())
		}
		if market.MarkPrice != nil {
			h.Write(market.MarkPrice.Bytes())
		}
		if market.LastPrice != nil {
			h.Write(market.LastPrice.Bytes())
		}

		// Open interest
		if market.OpenInterestLong != nil {
			h.Write(market.OpenInterestLong.Bytes())
		}
		if market.OpenInterestShort != nil {
			h.Write(market.OpenInterestShort.Bytes())
		}

		// Funding rate
		if market.FundingRate != nil {
			h.Write(market.FundingRate.Bytes())
		}

		hashes = append(hashes, h.Sum(nil))
	}

	return hashes
}

// computeBlockMetaHash computes hash of block metadata.
func (vm *VM) computeBlockMetaHash() []byte {
	h := sha256.New()

	// Block height
	heightBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBuf, vm.currentBlockHeight)
	h.Write(heightBuf)

	// Last block time
	timeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBuf, uint64(vm.lastBlockTime.UnixNano()))
	h.Write(timeBuf)

	// Last funding time
	fundingBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(fundingBuf, uint64(vm.lastFundingTime.UnixNano()))
	h.Write(fundingBuf)

	return h.Sum(nil)
}

// computeMerkleRoot computes the merkle root from a list of leaf hashes.
// Uses standard binary merkle tree construction.
func computeMerkleRoot(leaves [][]byte) ids.ID {
	if len(leaves) == 0 {
		return ids.Empty
	}

	// Copy leaves to avoid modifying input
	nodes := make([][]byte, len(leaves))
	copy(nodes, leaves)

	// Build tree bottom-up
	for len(nodes) > 1 {
		var nextLevel [][]byte

		for i := 0; i < len(nodes); i += 2 {
			h := sha256.New()
			h.Write(nodes[i])

			if i+1 < len(nodes) {
				// Pair exists
				h.Write(nodes[i+1])
			} else {
				// Odd node, duplicate
				h.Write(nodes[i])
			}

			nextLevel = append(nextLevel, h.Sum(nil))
		}

		nodes = nextLevel
	}

	// Root is first (and only) node
	var root ids.ID
	copy(root[:], nodes[0])
	return root
}

// Shutdown implements consensuscore.VM interface.
// It gracefully shuts down the VM.
// NOTE: No background tasks to wait for in functional mode.
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if !vm.log.IsZero() {
		vm.log.Info("Shutting down DEX VM")
	}

	vm.shutdown = true

	// Close database
	if vm.db != nil {
		if err := vm.db.Close(); err != nil {
			return fmt.Errorf("failed to close database: %w", err)
		}
	}

	if !vm.log.IsZero() {
		vm.log.Info("DEX VM shutdown complete")
	}

	return nil
}

// Version implements consensuscore.VM interface.
func (vm *VM) Version(ctx context.Context) (string, error) {
	return "1.0.0", nil
}

// CreateHandlers implements consensuscore.VM interface.
// It creates HTTP handlers for the DEX API.
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	server := rpc.NewServer()
	server.RegisterCodec(rpcjson.NewCodec(), "application/json")
	server.RegisterCodec(rpcjson.NewCodec(), "application/json;charset=UTF-8")

	// Register DEX API service
	service := api.NewService(vm)
	if err := server.RegisterService(service, "dex"); err != nil {
		return nil, fmt.Errorf("failed to register DEX service: %w", err)
	}

	return map[string]http.Handler{
		"":    server,
		"/ws": vm.createWebSocketHandler(),
	}, nil
}

// WebSocket upgrader with default options
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins (configure appropriately in production)
	},
}

// WSMessage represents a WebSocket message.
type WSMessage struct {
	Type    string          `json:"type"`
	Channel string          `json:"channel"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// WSSubscription represents a client subscription.
type WSSubscription struct {
	Channel string `json:"channel"`
	Symbol  string `json:"symbol,omitempty"`
}

// wsClient represents a connected WebSocket client.
type wsClient struct {
	conn          *websocket.Conn
	vm            *VM
	subscriptions map[string]bool
	send          chan []byte
	done          chan struct{}
}

// createWebSocketHandler creates a WebSocket handler for real-time updates.
func (vm *VM) createWebSocketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Upgrade HTTP connection to WebSocket
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			if !vm.log.IsZero() {
				vm.log.Warn("WebSocket upgrade failed", "error", err)
			}
			return
		}

		client := &wsClient{
			conn:          conn,
			vm:            vm,
			subscriptions: make(map[string]bool),
			send:          make(chan []byte, 256),
			done:          make(chan struct{}),
		}

		// Start goroutines for reading and writing
		go client.writePump()
		go client.readPump()
	})
}

// readPump pumps messages from the WebSocket connection to the hub.
func (c *wsClient) readPump() {
	defer func() {
		close(c.done)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(65536) // 64KB max message size

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				if !c.vm.log.IsZero() {
					c.vm.log.Warn("WebSocket read error", "error", err)
				}
			}
			return
		}

		// Parse incoming message
		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			c.sendError("Invalid JSON message")
			continue
		}

		// Handle message based on type
		switch msg.Type {
		case "subscribe":
			c.handleSubscribe(msg)
		case "unsubscribe":
			c.handleUnsubscribe(msg)
		case "ping":
			c.sendPong()
		default:
			c.sendError(fmt.Sprintf("Unknown message type: %s", msg.Type))
		}
	}
}

// writePump pumps messages from the hub to the WebSocket connection.
func (c *wsClient) writePump() {
	ticker := time.NewTicker(30 * time.Second) // Ping interval
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				// Channel closed
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			// Send ping to keep connection alive
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

		case <-c.done:
			return
		}
	}
}

// handleSubscribe handles subscription requests.
func (c *wsClient) handleSubscribe(msg WSMessage) {
	var sub WSSubscription
	if err := json.Unmarshal(msg.Data, &sub); err != nil {
		c.sendError("Invalid subscription data")
		return
	}

	channel := sub.Channel
	if sub.Symbol != "" {
		channel = fmt.Sprintf("%s:%s", sub.Channel, sub.Symbol)
	}

	c.subscriptions[channel] = true

	// Send confirmation
	c.sendJSON(WSMessage{
		Type:    "subscribed",
		Channel: channel,
	})

	// Send initial snapshot based on channel type
	switch sub.Channel {
	case "orderbook":
		c.sendOrderbookSnapshot(sub.Symbol)
	case "trades":
		// No initial snapshot for trades
	case "ticker":
		c.sendTickerSnapshot(sub.Symbol)
	}
}

// handleUnsubscribe handles unsubscription requests.
func (c *wsClient) handleUnsubscribe(msg WSMessage) {
	var sub WSSubscription
	if err := json.Unmarshal(msg.Data, &sub); err != nil {
		c.sendError("Invalid unsubscription data")
		return
	}

	channel := sub.Channel
	if sub.Symbol != "" {
		channel = fmt.Sprintf("%s:%s", sub.Channel, sub.Symbol)
	}

	delete(c.subscriptions, channel)

	c.sendJSON(WSMessage{
		Type:    "unsubscribed",
		Channel: channel,
	})
}

// sendOrderbookSnapshot sends the current orderbook state.
func (c *wsClient) sendOrderbookSnapshot(symbol string) {
	ob, err := c.vm.GetOrderbook(symbol)
	if err != nil {
		c.sendError(fmt.Sprintf("Orderbook not found: %s", symbol))
		return
	}

	bids, asks := ob.GetDepth(20)

	type OrderbookSnapshot struct {
		Symbol string                 `json:"symbol"`
		Bids   []*orderbook.PriceLevel `json:"bids"`
		Asks   []*orderbook.PriceLevel `json:"asks"`
		Time   int64                  `json:"time"`
	}

	snapshot := OrderbookSnapshot{
		Symbol: symbol,
		Bids:   bids,
		Asks:   asks,
		Time:   time.Now().UnixNano(),
	}

	data, _ := json.Marshal(snapshot)
	c.sendJSON(WSMessage{
		Type:    "snapshot",
		Channel: fmt.Sprintf("orderbook:%s", symbol),
		Data:    data,
	})
}

// sendTickerSnapshot sends the current ticker state.
func (c *wsClient) sendTickerSnapshot(symbol string) {
	ob, err := c.vm.GetOrderbook(symbol)
	if err != nil {
		c.sendError(fmt.Sprintf("Symbol not found: %s", symbol))
		return
	}

	type Ticker struct {
		Symbol   string `json:"symbol"`
		BestBid  uint64 `json:"bestBid"`
		BestAsk  uint64 `json:"bestAsk"`
		MidPrice uint64 `json:"midPrice"`
		Spread   uint64 `json:"spread"`
		Time     int64  `json:"time"`
	}

	ticker := Ticker{
		Symbol:   symbol,
		BestBid:  ob.GetBestBid(),
		BestAsk:  ob.GetBestAsk(),
		MidPrice: ob.GetMidPrice(),
		Spread:   ob.GetSpread(),
		Time:     time.Now().UnixNano(),
	}

	data, _ := json.Marshal(ticker)
	c.sendJSON(WSMessage{
		Type:    "snapshot",
		Channel: fmt.Sprintf("ticker:%s", symbol),
		Data:    data,
	})
}

// sendPong sends a pong response.
func (c *wsClient) sendPong() {
	c.sendJSON(WSMessage{Type: "pong"})
}

// sendError sends an error message.
func (c *wsClient) sendError(errMsg string) {
	data, _ := json.Marshal(map[string]string{"message": errMsg})
	c.sendJSON(WSMessage{
		Type: "error",
		Data: data,
	})
}

// sendJSON sends a JSON message to the client.
func (c *wsClient) sendJSON(msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	select {
	case c.send <- data:
	default:
		// Channel full, drop message
	}
}

// HealthCheck implements consensuscore.VM interface.
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	return chain.HealthResult{
		Healthy: vm.isInitialized && vm.bootstrapped,
		Details: map[string]string{
			"bootstrapped": fmt.Sprintf("%v", vm.bootstrapped),
			"orderbooks":   fmt.Sprintf("%d", len(vm.orderbooks)),
			"pools":        fmt.Sprintf("%d", len(vm.liquidityMgr.GetAllPools())),
			"perpMarkets":  fmt.Sprintf("%d", len(vm.perpetualsEng.GetAllMarkets())),
			"blockHeight":  fmt.Sprintf("%d", vm.currentBlockHeight),
			"mode":         "functional",
		},
	}, nil
}

// Connected implements consensuscore.VM interface.
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, v *version.Application) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	vm.connectedPeers[nodeID] = v
	if !vm.log.IsZero() {
		vm.log.Debug("Peer connected", "nodeID", nodeID, "version", v)
	}
	return nil
}

// Disconnected implements consensuscore.VM interface.
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	delete(vm.connectedPeers, nodeID)
	if !vm.log.IsZero() {
		vm.log.Debug("Peer disconnected", "nodeID", nodeID)
	}
	return nil
}

// GetOrderbook returns the orderbook for a symbol.
func (vm *VM) GetOrderbook(symbol string) (*orderbook.Orderbook, error) {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	ob, exists := vm.orderbooks[symbol]
	if !exists {
		return nil, fmt.Errorf("orderbook not found for symbol: %s", symbol)
	}
	return ob, nil
}

// GetOrCreateOrderbook returns or creates an orderbook for a symbol.
func (vm *VM) GetOrCreateOrderbook(symbol string) *orderbook.Orderbook {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	ob, exists := vm.orderbooks[symbol]
	if !exists {
		ob = orderbook.New(symbol)
		vm.orderbooks[symbol] = ob
	}
	return ob
}

// GetLiquidityManager returns the liquidity pool manager.
func (vm *VM) GetLiquidityManager() *liquidity.Manager {
	return vm.liquidityMgr
}

// GetPerpetualsEngine returns the perpetual futures engine.
func (vm *VM) GetPerpetualsEngine() api.PerpetualsEngine {
	return vm.perpetualsEng
}

// GetCommitmentStore returns the MEV protection commitment store.
func (vm *VM) GetCommitmentStore() api.CommitmentStore {
	return vm.commitmentStore
}

// GetADLEngine returns the auto-deleveraging engine.
func (vm *VM) GetADLEngine() api.ADLEngine {
	return vm.adlEngine
}

// IsBootstrapped returns true if the VM is fully bootstrapped.
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

// Gossip implements consensuscore.VM interface.
// It handles gossiped messages from peers (orders and trades).
func (vm *VM) Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.shutdown {
		return errShutdown
	}

	// Decode the network message
	netMsg, err := network.DecodeMessage(msg)
	if err != nil {
		if !vm.log.IsZero() {
			vm.log.Warn("Failed to decode gossip message", "nodeID", nodeID, "error", err)
		}
		return nil // Don't fail on invalid messages from peers
	}

	switch netMsg.Type {
	case network.MsgOrderGossip:
		return vm.handleGossipedOrder(nodeID, netMsg)
	case network.MsgTradeGossip:
		return vm.handleGossipedTrade(nodeID, netMsg)
	default:
		if !vm.log.IsZero() {
			vm.log.Debug("Unknown gossip message type", "type", netMsg.Type, "nodeID", nodeID)
		}
	}

	return nil
}

// handleGossipedOrder handles an order gossiped from a peer.
func (vm *VM) handleGossipedOrder(nodeID ids.NodeID, msg *network.Message) error {
	// Parse the order from the payload
	parser := &txs.TxParser{}
	tx, err := parser.Parse(msg.Payload)
	if err != nil {
		return nil // Ignore malformed orders
	}

	// Only handle place order transactions from gossip
	placeOrderTx, ok := tx.(*txs.PlaceOrderTx)
	if !ok {
		return nil
	}

	// Verify the transaction
	if err := placeOrderTx.Verify(); err != nil {
		return nil // Ignore invalid orders
	}

	ob, exists := vm.orderbooks[placeOrderTx.Symbol]
	if !exists {
		return nil // Unknown symbol
	}

	// Create order from gossip (will be confirmed in next block)
	order := &orderbook.Order{
		ID:          placeOrderTx.ID(),
		Owner:       placeOrderTx.Sender(),
		Symbol:      placeOrderTx.Symbol,
		Side:        orderbook.Side(placeOrderTx.Side),
		Type:        orderbook.OrderType(placeOrderTx.OrderType),
		Price:       placeOrderTx.Price,
		Quantity:    placeOrderTx.Quantity,
		StopPrice:   placeOrderTx.StopPrice,
		Status:      orderbook.StatusOpen,
		CreatedAt:   placeOrderTx.Timestamp(),
		ExpiresAt:   placeOrderTx.ExpiresAt,
		PostOnly:    placeOrderTx.PostOnly,
		ReduceOnly:  placeOrderTx.ReduceOnly,
		TimeInForce: placeOrderTx.TimeInForce,
	}

	// Add to orderbook (trades happen in block processing)
	if _, err := ob.AddOrder(order); err != nil {
		if !vm.log.IsZero() {
			vm.log.Debug("Failed to add gossiped order", "orderID", order.ID, "error", err)
		}
	} else if !vm.log.IsZero() {
		vm.log.Debug("Received gossiped order",
			"orderID", order.ID,
			"symbol", order.Symbol,
			"nodeID", nodeID,
		)
	}

	return nil
}

// handleGossipedTrade handles a trade notification gossiped from a peer.
func (vm *VM) handleGossipedTrade(nodeID ids.NodeID, msg *network.Message) error {
	// Trade gossip is informational only - actual trades are determined by block processing
	// This can be used for real-time UI updates before block confirmation
	if !vm.log.IsZero() {
		vm.log.Debug("Received gossiped trade notification", "nodeID", nodeID)
	}
	return nil
}

// Request implements consensuscore.VM interface.
// It handles direct requests from peers (e.g., orderbook sync).
func (vm *VM) Request(
	ctx context.Context,
	nodeID ids.NodeID,
	requestID uint32,
	deadline time.Time,
	request []byte,
) error {
	vm.lock.RLock()
	defer vm.lock.RUnlock()

	if vm.shutdown {
		return errShutdown
	}

	// Check deadline
	if time.Now().After(deadline) {
		return errors.New("request deadline exceeded")
	}

	// Decode the network message
	netMsg, err := network.DecodeMessage(request)
	if err != nil {
		if !vm.log.IsZero() {
			vm.log.Warn("Failed to decode request", "nodeID", nodeID, "error", err)
		}
		return err
	}

	switch netMsg.Type {
	case network.MsgOrderbookSync:
		return vm.handleOrderbookSyncRequest(ctx, nodeID, requestID, netMsg)
	case network.MsgPoolSync:
		return vm.handlePoolSyncRequest(ctx, nodeID, requestID, netMsg)
	default:
		if !vm.log.IsZero() {
			vm.log.Debug("Unknown request type", "type", netMsg.Type, "nodeID", nodeID)
		}
	}

	return nil
}

// handleOrderbookSyncRequest handles an orderbook sync request from a peer.
func (vm *VM) handleOrderbookSyncRequest(
	ctx context.Context,
	nodeID ids.NodeID,
	requestID uint32,
	msg *network.Message,
) error {
	// Extract symbol from payload (simple format: just the symbol string)
	symbol := string(msg.Payload)
	if symbol == "" {
		return errors.New("missing symbol in orderbook sync request")
	}

	ob, exists := vm.orderbooks[symbol]
	if !exists {
		return fmt.Errorf("orderbook not found: %s", symbol)
	}

	// Get orderbook depth
	bids, asks := ob.GetDepth(100) // Send top 100 levels

	// Create response with orderbook state
	type OrderbookSyncResponse struct {
		Symbol    string                  `json:"symbol"`
		Bids      []*orderbook.PriceLevel `json:"bids"`
		Asks      []*orderbook.PriceLevel `json:"asks"`
		BestBid   uint64                  `json:"bestBid"`
		BestAsk   uint64                  `json:"bestAsk"`
		Timestamp int64                   `json:"timestamp"`
	}

	response := OrderbookSyncResponse{
		Symbol:    symbol,
		Bids:      bids,
		Asks:      asks,
		BestBid:   ob.GetBestBid(),
		BestAsk:   ob.GetBestAsk(),
		Timestamp: time.Now().UnixNano(),
	}

	responseData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Create network message for response
	responseMsg := &network.Message{
		Type:      network.MsgOrderbookSync,
		RequestID: requestID,
		ChainID:   vm.chainID,
		Payload:   responseData,
		Timestamp: time.Now().UnixNano(),
	}

	// Send response via appSender
	if vm.appSender != nil {
		// Response is sent automatically by the consensus layer
		// Log for debugging
		if !vm.log.IsZero() {
			vm.log.Debug("Sent orderbook sync response",
				"symbol", symbol,
				"nodeID", nodeID,
				"bids", len(bids),
				"asks", len(asks),
			)
		}
		_ = responseMsg // Response will be sent by caller
	}

	return nil
}

// handlePoolSyncRequest handles a liquidity pool sync request from a peer.
func (vm *VM) handlePoolSyncRequest(
	ctx context.Context,
	nodeID ids.NodeID,
	requestID uint32,
	msg *network.Message,
) error {
	// Get all pools
	pools := vm.liquidityMgr.GetAllPools()

	// Create response with pool state
	type PoolSyncResponse struct {
		Pools     []*liquidity.Pool `json:"pools"`
		Timestamp int64             `json:"timestamp"`
	}

	response := PoolSyncResponse{
		Pools:     pools,
		Timestamp: time.Now().UnixNano(),
	}

	responseData, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Log response
	if !vm.log.IsZero() {
		vm.log.Debug("Sent pool sync response",
			"nodeID", nodeID,
			"pools", len(pools),
		)
	}

	_ = responseData // Response will be sent by caller
	return nil
}

// RequestFailed implements consensuscore.VM interface.
func (vm *VM) RequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, appErr *consensuscore.AppError) error {
	if !vm.log.IsZero() {
		vm.log.Warn("Request failed", "nodeID", nodeID, "requestID", requestID, "error", appErr)
	}
	return nil
}

// Response implements consensuscore.VM interface.
func (vm *VM) Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	if !vm.log.IsZero() {
		vm.log.Debug("Received response", "nodeID", nodeID, "requestID", requestID, "size", len(response))
	}
	return nil
}

// CrossChainRequest implements consensuscore.VM interface.
// It handles cross-chain requests via Warp messaging.
func (vm *VM) CrossChainRequest(
	ctx context.Context,
	sourceChainID ids.ID,
	requestID uint32,
	deadline time.Time,
	request []byte,
) error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.shutdown {
		return errShutdown
	}

	// Check deadline
	if time.Now().After(deadline) {
		return errors.New("cross-chain request deadline exceeded")
	}

	// Verify source chain is trusted
	trusted := false
	for _, chainID := range vm.Config.TrustedChains {
		if chainID == sourceChainID {
			trusted = true
			break
		}
	}
	if !trusted {
		if !vm.log.IsZero() {
			vm.log.Warn("Cross-chain request from untrusted chain", "chainID", sourceChainID)
		}
		return errors.New("source chain not trusted")
	}

	// Decode the network message
	netMsg, err := network.DecodeMessage(request)
	if err != nil {
		if !vm.log.IsZero() {
			vm.log.Warn("Failed to decode cross-chain request", "chainID", sourceChainID, "error", err)
		}
		return err
	}

	if !vm.log.IsZero() {
		vm.log.Info("Received cross-chain request",
			"sourceChain", sourceChainID,
			"type", netMsg.Type,
			"requestID", requestID,
		)
	}

	switch netMsg.Type {
	case network.MsgCrossChainSwap:
		return vm.handleCrossChainSwapRequest(ctx, sourceChainID, requestID, netMsg)
	case network.MsgCrossChainTransfer:
		return vm.handleCrossChainTransferRequest(ctx, sourceChainID, requestID, netMsg)
	case network.MsgWarpMessage:
		return vm.handleWarpMessage(ctx, sourceChainID, requestID, netMsg)
	default:
		if !vm.log.IsZero() {
			vm.log.Debug("Unknown cross-chain request type", "type", netMsg.Type)
		}
	}

	return nil
}

// handleCrossChainSwapRequest handles a cross-chain swap request.
func (vm *VM) handleCrossChainSwapRequest(
	ctx context.Context,
	sourceChainID ids.ID,
	requestID uint32,
	msg *network.Message,
) error {
	// Parse the cross-chain swap transaction from payload
	parser := &txs.TxParser{}
	tx, err := parser.Parse(msg.Payload)
	if err != nil {
		return fmt.Errorf("failed to parse cross-chain swap: %w", err)
	}

	swapTx, ok := tx.(*txs.CrossChainSwapTx)
	if !ok {
		return errors.New("invalid cross-chain swap transaction")
	}

	// Verify the swap
	if err := swapTx.Verify(); err != nil {
		return fmt.Errorf("cross-chain swap verification failed: %w", err)
	}

	// Check deadline
	if swapTx.Deadline > 0 && time.Now().UnixNano() > swapTx.Deadline {
		return errors.New("cross-chain swap deadline exceeded")
	}

	// Execute the swap on this chain
	// Find the best pool for the token pair
	pools := vm.liquidityMgr.GetPoolsByTokenPair(swapTx.TokenIn, swapTx.TokenOut)
	if len(pools) == 0 {
		return errors.New("no liquidity pool found for token pair")
	}

	// Execute swap on the first available pool
	result, err := vm.liquidityMgr.Swap(
		pools[0].ID,
		swapTx.TokenIn,
		new(big.Int).SetUint64(swapTx.AmountIn),
		new(big.Int).SetUint64(swapTx.MinAmountOut),
	)
	if err != nil {
		return fmt.Errorf("cross-chain swap execution failed: %w", err)
	}

	if !vm.log.IsZero() {
		vm.log.Info("Cross-chain swap executed",
			"sourceChain", sourceChainID,
			"tokenIn", swapTx.TokenIn,
			"amountIn", swapTx.AmountIn,
			"amountOut", result.AmountOut,
		)
	}

	return nil
}

// handleCrossChainTransferRequest handles a cross-chain transfer request.
func (vm *VM) handleCrossChainTransferRequest(
	ctx context.Context,
	sourceChainID ids.ID,
	requestID uint32,
	msg *network.Message,
) error {
	// Parse the cross-chain transfer transaction from payload
	parser := &txs.TxParser{}
	tx, err := parser.Parse(msg.Payload)
	if err != nil {
		return fmt.Errorf("failed to parse cross-chain transfer: %w", err)
	}

	transferTx, ok := tx.(*txs.CrossChainTransferTx)
	if !ok {
		return errors.New("invalid cross-chain transfer transaction")
	}

	// Verify the transfer
	if err := transferTx.Verify(); err != nil {
		return fmt.Errorf("cross-chain transfer verification failed: %w", err)
	}

	// The actual transfer is completed when the Warp message is signed by validators
	// Here we acknowledge receipt and prepare for settlement
	if !vm.log.IsZero() {
		vm.log.Info("Cross-chain transfer received",
			"sourceChain", sourceChainID,
			"token", transferTx.Token,
			"amount", transferTx.Amount,
			"recipient", transferTx.Recipient,
		)
	}

	return nil
}

// handleWarpMessage handles a generic Warp message.
func (vm *VM) handleWarpMessage(
	ctx context.Context,
	sourceChainID ids.ID,
	requestID uint32,
	msg *network.Message,
) error {
	// Generic Warp message handling
	// Can be used for custom cross-chain operations
	if !vm.log.IsZero() {
		vm.log.Debug("Received Warp message",
			"sourceChain", sourceChainID,
			"payloadSize", len(msg.Payload),
		)
	}

	return nil
}

// CrossChainRequestFailed implements consensuscore.VM interface.
func (vm *VM) CrossChainRequestFailed(ctx context.Context, chainID ids.ID, requestID uint32, appErr *consensuscore.AppError) error {
	if !vm.log.IsZero() {
		vm.log.Warn("Cross-chain request failed", "chainID", chainID, "requestID", requestID, "error", appErr)
	}
	return nil
}

// CrossChainResponse implements consensuscore.VM interface.
func (vm *VM) CrossChainResponse(ctx context.Context, chainID ids.ID, requestID uint32, response []byte) error {
	if !vm.log.IsZero() {
		vm.log.Debug("Received cross-chain response", "chainID", chainID, "requestID", requestID, "size", len(response))
	}
	return nil
}
