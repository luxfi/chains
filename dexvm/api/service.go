// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package api provides RPC and REST API handlers for the DEX VM.
package api

import (
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/luxfi/ids"

	"github.com/luxfi/chains/dexvm/liquidity"
	"github.com/luxfi/chains/dexvm/orderbook"
)

var (
	ErrNotBootstrapped     = errors.New("DEX not bootstrapped")
	ErrInvalidRequest      = errors.New("invalid request")
	ErrOrderNotFound       = errors.New("order not found")
	ErrPoolNotFound        = errors.New("pool not found")
	ErrInsufficientBalance = errors.New("insufficient balance")
)

// VM interface for the API service.
type VM interface {
	IsBootstrapped() bool
	GetOrderbook(symbol string) (*orderbook.Orderbook, error)
	GetOrCreateOrderbook(symbol string) *orderbook.Orderbook
	GetLiquidityManager() *liquidity.Manager
	GetPerpetualsEngine() PerpetualsEngine
	GetCommitmentStore() CommitmentStore
	GetADLEngine() ADLEngine
}

// PerpetualsEngine interface for perpetuals trading.
type PerpetualsEngine interface {
	GetMarket(symbol string) (interface{}, error)
	GetAllMarkets() []interface{}
	GetAccount(traderID ids.ID) (interface{}, error)
	GetPosition(traderID ids.ID, market string) (interface{}, error)
	GetAllPositions(traderID ids.ID) ([]interface{}, error)
	GetInsuranceFund() *big.Int
	GetMarginRatio(traderID ids.ID) (*big.Int, error)
}

// CommitmentStore interface for MEV protection.
type CommitmentStore interface {
	GetCommitment(hash ids.ID) (interface{}, bool)
	GetSenderCommitments(sender ids.ShortID) []interface{}
	Statistics() interface{}
}

// ADLEngine interface for auto-deleveraging.
type ADLEngine interface {
	GetCandidateCount(symbol string) (longs, shorts int)
	Statistics() interface{}
	GetEvents(limit int) []interface{}
	ShouldTriggerADL(currentFund, targetFund *big.Int) bool
}

// Service provides the RPC API for the DEX VM.
type Service struct {
	vm VM
}

// NewService creates a new API service.
func NewService(vm VM) *Service {
	return &Service{vm: vm}
}

// ============================================
// Health and Status APIs
// ============================================

// PingArgs is the argument for the Ping API.
type PingArgs struct{}

// PingReply is the reply for the Ping API.
type PingReply struct {
	Success bool `json:"success"`
}

// Ping returns a simple health check response.
func (s *Service) Ping(_ *http.Request, _ *PingArgs, reply *PingReply) error {
	reply.Success = true
	return nil
}

// StatusArgs is the argument for the Status API.
type StatusArgs struct{}

// StatusReply is the reply for the Status API.
type StatusReply struct {
	Bootstrapped bool   `json:"bootstrapped"`
	Version      string `json:"version"`
	Uptime       int64  `json:"uptime"`
}

// Status returns the DEX status.
func (s *Service) Status(_ *http.Request, _ *StatusArgs, reply *StatusReply) error {
	reply.Bootstrapped = s.vm.IsBootstrapped()
	reply.Version = "1.0.0"
	return nil
}

// ============================================
// Orderbook APIs
// ============================================

// GetOrderbookArgs is the argument for the GetOrderbook API.
type GetOrderbookArgs struct {
	Symbol string `json:"symbol"`
	Depth  int    `json:"depth"`
}

// GetOrderbookReply is the reply for the GetOrderbook API.
type GetOrderbookReply struct {
	Symbol    string                  `json:"symbol"`
	Bids      []*orderbook.PriceLevel `json:"bids"`
	Asks      []*orderbook.PriceLevel `json:"asks"`
	BestBid   uint64                  `json:"bestBid"`
	BestAsk   uint64                  `json:"bestAsk"`
	Spread    uint64                  `json:"spread"`
	MidPrice  uint64                  `json:"midPrice"`
	Timestamp int64                   `json:"timestamp"`
}

// GetOrderbook returns the current orderbook for a symbol.
func (s *Service) GetOrderbook(_ *http.Request, args *GetOrderbookArgs, reply *GetOrderbookReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	if args.Symbol == "" {
		return fmt.Errorf("%w: symbol required", ErrInvalidRequest)
	}

	depth := args.Depth
	if depth <= 0 {
		depth = 20
	}

	ob, err := s.vm.GetOrderbook(args.Symbol)
	if err != nil {
		return err
	}

	bids, asks := ob.GetDepth(depth)

	reply.Symbol = args.Symbol
	reply.Bids = bids
	reply.Asks = asks
	reply.BestBid = ob.GetBestBid()
	reply.BestAsk = ob.GetBestAsk()
	reply.Spread = ob.GetSpread()
	reply.MidPrice = ob.GetMidPrice()
	reply.Timestamp = time.Now().UnixNano()

	return nil
}

// PlaceOrderArgs is the argument for the PlaceOrder API.
type PlaceOrderArgs struct {
	Owner       string `json:"owner"` // hex-encoded address
	Symbol      string `json:"symbol"`
	Side        string `json:"side"` // "buy" or "sell"
	Type        string `json:"type"` // "limit", "market", etc.
	Price       uint64 `json:"price"`
	Quantity    uint64 `json:"quantity"`
	TimeInForce string `json:"timeInForce"` // "GTC", "IOC", "FOK"
	PostOnly    bool   `json:"postOnly"`
	ReduceOnly  bool   `json:"reduceOnly"`
}

// PlaceOrderReply is the reply for the PlaceOrder API.
type PlaceOrderReply struct {
	OrderID   string             `json:"orderId"`
	Status    string             `json:"status"`
	FilledQty uint64             `json:"filledQty"`
	Trades    []*orderbook.Trade `json:"trades"`
}

// PlaceOrder places a new order on the orderbook.
func (s *Service) PlaceOrder(_ *http.Request, args *PlaceOrderArgs, reply *PlaceOrderReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	if args.Symbol == "" {
		return fmt.Errorf("%w: symbol required", ErrInvalidRequest)
	}
	if args.Quantity == 0 {
		return fmt.Errorf("%w: quantity required", ErrInvalidRequest)
	}

	// Parse owner address
	ownerBytes, err := ids.ShortFromString(args.Owner)
	if err != nil {
		return fmt.Errorf("%w: invalid owner address", ErrInvalidRequest)
	}

	// Parse side
	var side orderbook.Side
	switch args.Side {
	case "buy":
		side = orderbook.Buy
	case "sell":
		side = orderbook.Sell
	default:
		return fmt.Errorf("%w: invalid side (must be 'buy' or 'sell')", ErrInvalidRequest)
	}

	// Parse order type
	var orderType orderbook.OrderType
	switch args.Type {
	case "limit":
		orderType = orderbook.Limit
	case "market":
		orderType = orderbook.Market
	case "stop_loss":
		orderType = orderbook.StopLoss
	case "take_profit":
		orderType = orderbook.TakeProfit
	case "stop_limit":
		orderType = orderbook.StopLimit
	default:
		orderType = orderbook.Limit
	}

	// Create order
	order := &orderbook.Order{
		ID:          ids.GenerateTestID(),
		Owner:       ownerBytes,
		Symbol:      args.Symbol,
		Side:        side,
		Type:        orderType,
		Price:       args.Price,
		Quantity:    args.Quantity,
		TimeInForce: args.TimeInForce,
		PostOnly:    args.PostOnly,
		ReduceOnly:  args.ReduceOnly,
		CreatedAt:   time.Now().UnixNano(),
		Status:      orderbook.StatusOpen,
	}

	// Get or create orderbook
	ob := s.vm.GetOrCreateOrderbook(args.Symbol)

	// Add order
	trades, err := ob.AddOrder(order)
	if err != nil {
		return err
	}

	reply.OrderID = order.ID.String()
	reply.Status = order.Status.String()
	reply.FilledQty = order.FilledQty
	reply.Trades = trades

	return nil
}

// CancelOrderArgs is the argument for the CancelOrder API.
type CancelOrderArgs struct {
	OrderID string `json:"orderId"`
	Symbol  string `json:"symbol"`
}

// CancelOrderReply is the reply for the CancelOrder API.
type CancelOrderReply struct {
	Success bool `json:"success"`
}

// CancelOrder cancels an existing order.
func (s *Service) CancelOrder(_ *http.Request, args *CancelOrderArgs, reply *CancelOrderReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	orderID, err := ids.FromString(args.OrderID)
	if err != nil {
		return fmt.Errorf("%w: invalid order ID", ErrInvalidRequest)
	}

	ob, err := s.vm.GetOrderbook(args.Symbol)
	if err != nil {
		return err
	}

	if err := ob.CancelOrder(orderID); err != nil {
		return err
	}

	reply.Success = true
	return nil
}

// GetOrderArgs is the argument for the GetOrder API.
type GetOrderArgs struct {
	OrderID string `json:"orderId"`
	Symbol  string `json:"symbol"`
}

// GetOrderReply is the reply for the GetOrder API.
type GetOrderReply struct {
	Order *orderbook.Order `json:"order"`
}

// GetOrder returns an order by ID.
func (s *Service) GetOrder(_ *http.Request, args *GetOrderArgs, reply *GetOrderReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	orderID, err := ids.FromString(args.OrderID)
	if err != nil {
		return fmt.Errorf("%w: invalid order ID", ErrInvalidRequest)
	}

	ob, err := s.vm.GetOrderbook(args.Symbol)
	if err != nil {
		return err
	}

	order, err := ob.GetOrder(orderID)
	if err != nil {
		return err
	}

	reply.Order = order
	return nil
}

// ============================================
// Liquidity Pool APIs
// ============================================

// GetPoolsArgs is the argument for the GetPools API.
type GetPoolsArgs struct{}

// GetPoolsReply is the reply for the GetPools API.
type GetPoolsReply struct {
	Pools []*liquidity.Pool `json:"pools"`
}

// GetPools returns all liquidity pools.
func (s *Service) GetPools(_ *http.Request, _ *GetPoolsArgs, reply *GetPoolsReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	reply.Pools = s.vm.GetLiquidityManager().GetAllPools()
	return nil
}

// GetPoolArgs is the argument for the GetPool API.
type GetPoolArgs struct {
	PoolID string `json:"poolId"`
}

// GetPoolReply is the reply for the GetPool API.
type GetPoolReply struct {
	Pool *liquidity.Pool `json:"pool"`
}

// GetPool returns a specific liquidity pool.
func (s *Service) GetPool(_ *http.Request, args *GetPoolArgs, reply *GetPoolReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	poolID, err := ids.FromString(args.PoolID)
	if err != nil {
		return fmt.Errorf("%w: invalid pool ID", ErrInvalidRequest)
	}

	pool, err := s.vm.GetLiquidityManager().GetPool(poolID)
	if err != nil {
		return err
	}

	reply.Pool = pool
	return nil
}

// GetQuoteArgs is the argument for the GetQuote API.
type GetQuoteArgs struct {
	PoolID   string `json:"poolId"`
	TokenIn  string `json:"tokenIn"`
	AmountIn string `json:"amountIn"` // String for big.Int
}

// GetQuoteReply is the reply for the GetQuote API.
type GetQuoteReply struct {
	AmountOut     string `json:"amountOut"`
	EffectiveRate string `json:"effectiveRate"`
}

// GetQuote returns a swap quote.
func (s *Service) GetQuote(_ *http.Request, args *GetQuoteArgs, reply *GetQuoteReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	poolID, err := ids.FromString(args.PoolID)
	if err != nil {
		return fmt.Errorf("%w: invalid pool ID", ErrInvalidRequest)
	}

	tokenIn, err := ids.FromString(args.TokenIn)
	if err != nil {
		return fmt.Errorf("%w: invalid token ID", ErrInvalidRequest)
	}

	amountIn, ok := new(big.Int).SetString(args.AmountIn, 10)
	if !ok {
		return fmt.Errorf("%w: invalid amount", ErrInvalidRequest)
	}

	amountOut, err := s.vm.GetLiquidityManager().GetQuote(poolID, tokenIn, amountIn)
	if err != nil {
		return err
	}

	reply.AmountOut = amountOut.String()
	if amountIn.Sign() > 0 {
		rate := new(big.Float).Quo(
			new(big.Float).SetInt(amountOut),
			new(big.Float).SetInt(amountIn),
		)
		reply.EffectiveRate = rate.Text('f', 8)
	}

	return nil
}

// SwapArgs is the argument for the Swap API.
type SwapArgs struct {
	PoolID       string `json:"poolId"`
	TokenIn      string `json:"tokenIn"`
	AmountIn     string `json:"amountIn"`
	MinAmountOut string `json:"minAmountOut"`
}

// SwapReply is the reply for the Swap API.
type SwapReply struct {
	AmountOut string `json:"amountOut"`
	Fee       string `json:"fee"`
}

// Swap executes a swap on a liquidity pool.
func (s *Service) Swap(_ *http.Request, args *SwapArgs, reply *SwapReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	poolID, err := ids.FromString(args.PoolID)
	if err != nil {
		return fmt.Errorf("%w: invalid pool ID", ErrInvalidRequest)
	}

	tokenIn, err := ids.FromString(args.TokenIn)
	if err != nil {
		return fmt.Errorf("%w: invalid token ID", ErrInvalidRequest)
	}

	amountIn, ok := new(big.Int).SetString(args.AmountIn, 10)
	if !ok {
		return fmt.Errorf("%w: invalid amountIn", ErrInvalidRequest)
	}

	minAmountOut, ok := new(big.Int).SetString(args.MinAmountOut, 10)
	if !ok {
		return fmt.Errorf("%w: invalid minAmountOut", ErrInvalidRequest)
	}

	result, err := s.vm.GetLiquidityManager().Swap(poolID, tokenIn, amountIn, minAmountOut)
	if err != nil {
		return err
	}

	reply.AmountOut = result.AmountOut.String()
	reply.Fee = result.Fee.String()

	return nil
}

// AddLiquidityArgs is the argument for the AddLiquidity API.
type AddLiquidityArgs struct {
	PoolID       string `json:"poolId"`
	Amount0      string `json:"amount0"`
	Amount1      string `json:"amount1"`
	MinLiquidity string `json:"minLiquidity"`
}

// AddLiquidityReply is the reply for the AddLiquidity API.
type AddLiquidityReply struct {
	LPTokens string `json:"lpTokens"`
}

// AddLiquidity adds liquidity to a pool.
func (s *Service) AddLiquidity(_ *http.Request, args *AddLiquidityArgs, reply *AddLiquidityReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	poolID, err := ids.FromString(args.PoolID)
	if err != nil {
		return fmt.Errorf("%w: invalid pool ID", ErrInvalidRequest)
	}

	amount0, ok := new(big.Int).SetString(args.Amount0, 10)
	if !ok {
		return fmt.Errorf("%w: invalid amount0", ErrInvalidRequest)
	}

	amount1, ok := new(big.Int).SetString(args.Amount1, 10)
	if !ok {
		return fmt.Errorf("%w: invalid amount1", ErrInvalidRequest)
	}

	minLiquidity, ok := new(big.Int).SetString(args.MinLiquidity, 10)
	if !ok {
		return fmt.Errorf("%w: invalid minLiquidity", ErrInvalidRequest)
	}

	lpTokens, err := s.vm.GetLiquidityManager().AddLiquidity(poolID, amount0, amount1, minLiquidity)
	if err != nil {
		return err
	}

	reply.LPTokens = lpTokens.String()

	return nil
}

// RemoveLiquidityArgs is the argument for the RemoveLiquidity API.
type RemoveLiquidityArgs struct {
	PoolID     string `json:"poolId"`
	Liquidity  string `json:"liquidity"`
	MinAmount0 string `json:"minAmount0"`
	MinAmount1 string `json:"minAmount1"`
}

// RemoveLiquidityReply is the reply for the RemoveLiquidity API.
type RemoveLiquidityReply struct {
	Amount0 string `json:"amount0"`
	Amount1 string `json:"amount1"`
}

// RemoveLiquidity removes liquidity from a pool.
func (s *Service) RemoveLiquidity(_ *http.Request, args *RemoveLiquidityArgs, reply *RemoveLiquidityReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	poolID, err := ids.FromString(args.PoolID)
	if err != nil {
		return fmt.Errorf("%w: invalid pool ID", ErrInvalidRequest)
	}

	liquidity, ok := new(big.Int).SetString(args.Liquidity, 10)
	if !ok {
		return fmt.Errorf("%w: invalid liquidity", ErrInvalidRequest)
	}

	minAmount0, ok := new(big.Int).SetString(args.MinAmount0, 10)
	if !ok {
		return fmt.Errorf("%w: invalid minAmount0", ErrInvalidRequest)
	}

	minAmount1, ok := new(big.Int).SetString(args.MinAmount1, 10)
	if !ok {
		return fmt.Errorf("%w: invalid minAmount1", ErrInvalidRequest)
	}

	amount0, amount1, err := s.vm.GetLiquidityManager().RemoveLiquidity(poolID, liquidity, minAmount0, minAmount1)
	if err != nil {
		return err
	}

	reply.Amount0 = amount0.String()
	reply.Amount1 = amount1.String()

	return nil
}

// ============================================
// Statistics APIs
// ============================================

// GetStatsArgs is the argument for the GetStats API.
type GetStatsArgs struct {
	Symbol string `json:"symbol"`
}

// GetStatsReply is the reply for the GetStats API.
type GetStatsReply struct {
	TotalVolume   uint64 `json:"totalVolume"`
	TradeCount    uint64 `json:"tradeCount"`
	LastTradeTime int64  `json:"lastTradeTime"`
}

// GetStats returns trading statistics for a symbol.
func (s *Service) GetStats(_ *http.Request, args *GetStatsArgs, reply *GetStatsReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	ob, err := s.vm.GetOrderbook(args.Symbol)
	if err != nil {
		return err
	}

	totalVolume, tradeCount, lastTradeTime := ob.GetStats()

	reply.TotalVolume = totalVolume
	reply.TradeCount = tradeCount
	reply.LastTradeTime = lastTradeTime

	return nil
}

// ============================================
// Perpetuals APIs (dex.*)
// ============================================

// GetMarketsArgs is the argument for the GetMarkets API.
type GetMarketsArgs struct{}

// GetMarketsReply is the reply for the GetMarkets API.
type GetMarketsReply struct {
	Markets []interface{} `json:"markets"`
}

// GetMarkets returns all perpetual markets.
func (s *Service) GetMarkets(_ *http.Request, _ *GetMarketsArgs, reply *GetMarketsReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	engine := s.vm.GetPerpetualsEngine()
	if engine == nil {
		return errors.New("perpetuals engine not available")
	}

	reply.Markets = engine.GetAllMarkets()
	return nil
}

// GetMarketArgs is the argument for the GetMarket API.
type GetMarketArgs struct {
	Symbol string `json:"symbol"`
}

// GetMarketReply is the reply for the GetMarket API.
type GetMarketReply struct {
	Market interface{} `json:"market"`
}

// GetMarket returns a specific perpetual market.
func (s *Service) GetMarket(_ *http.Request, args *GetMarketArgs, reply *GetMarketReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	if args.Symbol == "" {
		return fmt.Errorf("%w: symbol required", ErrInvalidRequest)
	}

	engine := s.vm.GetPerpetualsEngine()
	if engine == nil {
		return errors.New("perpetuals engine not available")
	}

	market, err := engine.GetMarket(args.Symbol)
	if err != nil {
		return err
	}

	reply.Market = market
	return nil
}

// GetPositionArgs is the argument for the GetPosition API.
type GetPositionArgs struct {
	TraderID string `json:"traderId"`
	Symbol   string `json:"symbol"`
}

// GetPositionReply is the reply for the GetPosition API.
type GetPositionReply struct {
	Position interface{} `json:"position"`
}

// GetPosition returns a trader's position for a market.
func (s *Service) GetPosition(_ *http.Request, args *GetPositionArgs, reply *GetPositionReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	traderID, err := ids.FromString(args.TraderID)
	if err != nil {
		return fmt.Errorf("%w: invalid trader ID", ErrInvalidRequest)
	}

	engine := s.vm.GetPerpetualsEngine()
	if engine == nil {
		return errors.New("perpetuals engine not available")
	}

	position, err := engine.GetPosition(traderID, args.Symbol)
	if err != nil {
		return err
	}

	reply.Position = position
	return nil
}

// GetPositionsArgs is the argument for the GetPositions API.
type GetPositionsArgs struct {
	TraderID string `json:"traderId"`
}

// GetPositionsReply is the reply for the GetPositions API.
type GetPositionsReply struct {
	Positions []interface{} `json:"positions"`
}

// GetPositions returns all positions for a trader.
func (s *Service) GetPositions(_ *http.Request, args *GetPositionsArgs, reply *GetPositionsReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	traderID, err := ids.FromString(args.TraderID)
	if err != nil {
		return fmt.Errorf("%w: invalid trader ID", ErrInvalidRequest)
	}

	engine := s.vm.GetPerpetualsEngine()
	if engine == nil {
		return errors.New("perpetuals engine not available")
	}

	positions, err := engine.GetAllPositions(traderID)
	if err != nil {
		return err
	}

	reply.Positions = positions
	return nil
}

// GetAccountArgs is the argument for the GetAccount API.
type GetAccountArgs struct {
	TraderID string `json:"traderId"`
}

// GetAccountReply is the reply for the GetAccount API.
type GetAccountReply struct {
	Account     interface{} `json:"account"`
	MarginRatio string      `json:"marginRatio"`
}

// GetAccount returns a trader's margin account.
func (s *Service) GetAccount(_ *http.Request, args *GetAccountArgs, reply *GetAccountReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	traderID, err := ids.FromString(args.TraderID)
	if err != nil {
		return fmt.Errorf("%w: invalid trader ID", ErrInvalidRequest)
	}

	engine := s.vm.GetPerpetualsEngine()
	if engine == nil {
		return errors.New("perpetuals engine not available")
	}

	account, err := engine.GetAccount(traderID)
	if err != nil {
		return err
	}

	marginRatio, err := engine.GetMarginRatio(traderID)
	if err != nil {
		marginRatio = big.NewInt(0)
	}

	reply.Account = account
	reply.MarginRatio = marginRatio.String()
	return nil
}

// GetFundingRateArgs is the argument for the GetFundingRate API.
type GetFundingRateArgs struct {
	Symbol string `json:"symbol"`
}

// GetFundingRateReply is the reply for the GetFundingRate API.
type GetFundingRateReply struct {
	FundingRate     string `json:"fundingRate"`
	NextFundingTime int64  `json:"nextFundingTime"`
}

// GetFundingRate returns the funding rate for a perpetual market.
func (s *Service) GetFundingRate(_ *http.Request, args *GetFundingRateArgs, reply *GetFundingRateReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	engine := s.vm.GetPerpetualsEngine()
	if engine == nil {
		return errors.New("perpetuals engine not available")
	}

	market, err := engine.GetMarket(args.Symbol)
	if err != nil {
		return err
	}

	// Market is an interface{}, we'll return it as JSON
	// The actual struct contains FundingRate and NextFundingTime
	reply.FundingRate = "0" // Will be populated from market data
	reply.NextFundingTime = time.Now().Add(8 * time.Hour).Unix()

	// Type assertion to get actual values if possible
	if m, ok := market.(interface{ GetFundingInfo() (string, int64) }); ok {
		reply.FundingRate, reply.NextFundingTime = m.GetFundingInfo()
	}

	return nil
}

// GetInsuranceFundArgs is the argument for the GetInsuranceFund API.
type GetInsuranceFundArgs struct{}

// GetInsuranceFundReply is the reply for the GetInsuranceFund API.
type GetInsuranceFundReply struct {
	Balance string `json:"balance"`
}

// GetInsuranceFund returns the insurance fund balance.
func (s *Service) GetInsuranceFund(_ *http.Request, _ *GetInsuranceFundArgs, reply *GetInsuranceFundReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	engine := s.vm.GetPerpetualsEngine()
	if engine == nil {
		return errors.New("perpetuals engine not available")
	}

	balance := engine.GetInsuranceFund()
	reply.Balance = balance.String()
	return nil
}

// ============================================
// MEV Protection APIs (dex.*)
// ============================================

// GetCommitmentArgs is the argument for the GetCommitment API.
type GetCommitmentArgs struct {
	CommitmentHash string `json:"commitmentHash"`
}

// GetCommitmentReply is the reply for the GetCommitment API.
type GetCommitmentReply struct {
	Commitment interface{} `json:"commitment"`
	Found      bool        `json:"found"`
}

// GetCommitment returns a commitment by hash.
func (s *Service) GetCommitment(_ *http.Request, args *GetCommitmentArgs, reply *GetCommitmentReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	hash, err := ids.FromString(args.CommitmentHash)
	if err != nil {
		return fmt.Errorf("%w: invalid commitment hash", ErrInvalidRequest)
	}

	store := s.vm.GetCommitmentStore()
	if store == nil {
		return errors.New("MEV protection not available")
	}

	commitment, found := store.GetCommitment(hash)
	reply.Commitment = commitment
	reply.Found = found
	return nil
}

// GetCommitmentsArgs is the argument for the GetCommitments API.
type GetCommitmentsArgs struct {
	Sender string `json:"sender"`
}

// GetCommitmentsReply is the reply for the GetCommitments API.
type GetCommitmentsReply struct {
	Commitments []interface{} `json:"commitments"`
}

// GetCommitments returns all pending commitments for a sender.
func (s *Service) GetCommitments(_ *http.Request, args *GetCommitmentsArgs, reply *GetCommitmentsReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	sender, err := ids.ShortFromString(args.Sender)
	if err != nil {
		return fmt.Errorf("%w: invalid sender address", ErrInvalidRequest)
	}

	store := s.vm.GetCommitmentStore()
	if store == nil {
		return errors.New("MEV protection not available")
	}

	reply.Commitments = store.GetSenderCommitments(sender)
	return nil
}

// GetMEVStatsArgs is the argument for the GetMEVStats API.
type GetMEVStatsArgs struct{}

// GetMEVStatsReply is the reply for the GetMEVStats API.
type GetMEVStatsReply struct {
	Stats interface{} `json:"stats"`
}

// GetMEVStats returns MEV protection statistics.
func (s *Service) GetMEVStats(_ *http.Request, _ *GetMEVStatsArgs, reply *GetMEVStatsReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	store := s.vm.GetCommitmentStore()
	if store == nil {
		return errors.New("MEV protection not available")
	}

	reply.Stats = store.Statistics()
	return nil
}

// ============================================
// Auto-Deleveraging (ADL) APIs (dex.*)
// ============================================

// GetADLStatusArgs is the argument for the GetADLStatus API.
type GetADLStatusArgs struct {
	Symbol string `json:"symbol"`
}

// GetADLStatusReply is the reply for the GetADLStatus API.
type GetADLStatusReply struct {
	LongCandidates  int  `json:"longCandidates"`
	ShortCandidates int  `json:"shortCandidates"`
	ShouldTrigger   bool `json:"shouldTrigger"`
}

// GetADLStatus returns ADL status for a symbol.
func (s *Service) GetADLStatus(_ *http.Request, args *GetADLStatusArgs, reply *GetADLStatusReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	adl := s.vm.GetADLEngine()
	if adl == nil {
		return errors.New("ADL engine not available")
	}

	engine := s.vm.GetPerpetualsEngine()

	longs, shorts := adl.GetCandidateCount(args.Symbol)
	reply.LongCandidates = longs
	reply.ShortCandidates = shorts

	// Check if ADL should trigger based on insurance fund
	if engine != nil {
		insuranceFund := engine.GetInsuranceFund()
		targetFund := big.NewInt(10_000_000_000000) // $10M target
		reply.ShouldTrigger = adl.ShouldTriggerADL(insuranceFund, targetFund)
	}

	return nil
}

// GetADLStatsArgs is the argument for the GetADLStats API.
type GetADLStatsArgs struct{}

// GetADLStatsReply is the reply for the GetADLStats API.
type GetADLStatsReply struct {
	Stats interface{} `json:"stats"`
}

// GetADLStats returns ADL engine statistics.
func (s *Service) GetADLStats(_ *http.Request, _ *GetADLStatsArgs, reply *GetADLStatsReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	adl := s.vm.GetADLEngine()
	if adl == nil {
		return errors.New("ADL engine not available")
	}

	reply.Stats = adl.Statistics()
	return nil
}

// GetADLEventsArgs is the argument for the GetADLEvents API.
type GetADLEventsArgs struct {
	Limit int `json:"limit"`
}

// GetADLEventsReply is the reply for the GetADLEvents API.
type GetADLEventsReply struct {
	Events []interface{} `json:"events"`
}

// GetADLEvents returns recent ADL events.
func (s *Service) GetADLEvents(_ *http.Request, args *GetADLEventsArgs, reply *GetADLEventsReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}

	adl := s.vm.GetADLEngine()
	if adl == nil {
		return errors.New("ADL engine not available")
	}

	limit := args.Limit
	if limit <= 0 {
		limit = 10
	}

	reply.Events = adl.GetEvents(limit)
	return nil
}
