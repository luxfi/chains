// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package perpetuals

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/chains/dexvm/oracle"
)

// Retention caps for in-memory event logs. Aggregate totals are retained
// on the engine's Position / MarginAccount records; these slices are only
// for recent-activity inspection APIs. See papers/oom-audit-2026-04-12.tex.
const (
	maxRecentLiquidations     = 10_000
	maxRecentFundingPayments  = 10_000
)

var (
	// Errors
	ErrMarketNotFound         = errors.New("market not found")
	ErrMarketExists           = errors.New("market already exists")
	ErrPositionNotFound       = errors.New("position not found")
	ErrInsufficientMargin     = errors.New("insufficient margin")
	ErrInsufficientBalance    = errors.New("insufficient balance")
	ErrExceedsMaxLeverage     = errors.New("exceeds maximum leverage")
	ErrOrderSizeTooSmall      = errors.New("order size below minimum")
	ErrInvalidPrice           = errors.New("invalid price")
	ErrReduceOnlyViolation    = errors.New("reduce-only order would increase position")
	ErrPositionWouldLiquidate = errors.New("position would be immediately liquidatable")
	ErrNoOpenPosition         = errors.New("no open position to close")
	ErrInvalidLeverage        = errors.New("invalid leverage")

	// Constants
	PrecisionFactor = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil) // 1e18 for price precision
	BasisPointDenom = big.NewInt(10000)                                     // 10000 basis points = 100%
)

// Engine is the main perpetuals trading engine
type Engine struct {
	mu              sync.RWMutex
	markets         map[string]*Market
	accounts        map[ids.ID]*MarginAccount
	positions       map[ids.ID]*Position
	orders          map[ids.ID]*Order
	ordersByMarket  map[string][]*Order // Active orders by market
	liquidations    []*LiquidationEvent
	fundingPayments []*FundingPayment
	insuranceFund   *big.Int // Global insurance fund
	lastFundingTime time.Time
	priceOracle     PriceOracle
	twapOracle      *oracle.TWAPOracle // TWAP oracle for manipulation-resistant pricing
}

// PriceOracle provides price feeds for the engine
type PriceOracle interface {
	GetIndexPrice(market string) (*big.Int, error)
	GetMarkPrice(market string) (*big.Int, error)
}

// DefaultPriceOracle uses last traded price as mark price
type DefaultPriceOracle struct {
	engine *Engine
}

func (o *DefaultPriceOracle) GetIndexPrice(market string) (*big.Int, error) {
	o.engine.mu.RLock()
	defer o.engine.mu.RUnlock()
	m, ok := o.engine.markets[market]
	if !ok {
		return nil, ErrMarketNotFound
	}
	return new(big.Int).Set(m.IndexPrice), nil
}

func (o *DefaultPriceOracle) GetMarkPrice(market string) (*big.Int, error) {
	o.engine.mu.RLock()
	defer o.engine.mu.RUnlock()
	m, ok := o.engine.markets[market]
	if !ok {
		return nil, ErrMarketNotFound
	}
	// Mark price = Index price + EMA of (Last - Index)
	// For simplicity, we use index price as mark price
	return new(big.Int).Set(m.MarkPrice), nil
}

// NewEngine creates a new perpetuals trading engine
func NewEngine() *Engine {
	e := &Engine{
		markets:         make(map[string]*Market),
		accounts:        make(map[ids.ID]*MarginAccount),
		positions:       make(map[ids.ID]*Position),
		orders:          make(map[ids.ID]*Order),
		ordersByMarket:  make(map[string][]*Order),
		liquidations:    make([]*LiquidationEvent, 0),
		fundingPayments: make([]*FundingPayment, 0),
		insuranceFund:   big.NewInt(0),
		lastFundingTime: time.Now(),
		twapOracle:      oracle.NewTWAPOracle(30 * time.Minute), // 30-minute TWAP window
	}
	e.priceOracle = &DefaultPriceOracle{engine: e}
	return e
}

// SetPriceOracle sets a custom price oracle
func (e *Engine) SetPriceOracle(oracle PriceOracle) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.priceOracle = oracle
}

// GetTWAPPrice returns the time-weighted average price for a market.
// This should be used for liquidations to prevent flash crash manipulation.
func (e *Engine) GetTWAPPrice(market string) (*big.Int, error) {
	price, err := e.twapOracle.GetPrice(market)
	if err != nil {
		return nil, err
	}
	return price, nil
}

// CreateMarket creates a new perpetual market
func (e *Engine) CreateMarket(
	symbol string,
	baseAsset, quoteAsset ids.ID,
	initialPrice *big.Int,
	maxLeverage uint16,
	minSize *big.Int,
	tickSize *big.Int,
	makerFee, takerFee uint16,
	maintenanceMargin, initialMargin uint16,
) (*Market, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.markets[symbol]; exists {
		return nil, ErrMarketExists
	}

	if maxLeverage < 1 || maxLeverage > 100 {
		return nil, ErrInvalidLeverage
	}

	market := &Market{
		Symbol:            symbol,
		BaseAsset:         baseAsset,
		QuoteAsset:        quoteAsset,
		IndexPrice:        new(big.Int).Set(initialPrice),
		MarkPrice:         new(big.Int).Set(initialPrice),
		LastPrice:         new(big.Int).Set(initialPrice),
		FundingRate:       big.NewInt(0),
		NextFundingTime:   time.Now().Add(8 * time.Hour),
		OpenInterestLong:  big.NewInt(0),
		OpenInterestShort: big.NewInt(0),
		Volume24h:         big.NewInt(0),
		MaxLeverage:       maxLeverage,
		MinSize:           new(big.Int).Set(minSize),
		TickSize:          new(big.Int).Set(tickSize),
		MakerFee:          makerFee,
		TakerFee:          takerFee,
		MaintenanceMargin: maintenanceMargin,
		InitialMargin:     initialMargin,
		MaxFundingRate:    new(big.Int).Div(PrecisionFactor, big.NewInt(1000)), // 0.1% max funding
		FundingInterval:   8 * time.Hour,
		InsuranceFund:     big.NewInt(0),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	e.markets[symbol] = market
	e.ordersByMarket[symbol] = make([]*Order, 0)

	return market, nil
}

// GetMarket returns a market by symbol. Returns interface{} for API compatibility.
func (e *Engine) GetMarket(symbol string) (interface{}, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	market, ok := e.markets[symbol]
	if !ok {
		return nil, ErrMarketNotFound
	}
	return market, nil
}

// GetAllMarkets returns all markets as interface{} slice for API compatibility.
func (e *Engine) GetAllMarkets() []interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	markets := make([]interface{}, 0, len(e.markets))
	for _, m := range e.markets {
		markets = append(markets, m)
	}
	return markets
}

// CreateAccount creates or gets a margin account for a trader
func (e *Engine) CreateAccount(traderID ids.ID) *MarginAccount {
	e.mu.Lock()
	defer e.mu.Unlock()

	if account, exists := e.accounts[traderID]; exists {
		return account
	}

	account := NewMarginAccount(traderID)
	e.accounts[traderID] = account
	return account
}

// GetAccount returns a trader's margin account. Returns interface{} for API compatibility.
func (e *Engine) GetAccount(traderID ids.ID) (interface{}, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	account, ok := e.accounts[traderID]
	if !ok {
		return nil, errors.New("account not found")
	}
	return account, nil
}

// Deposit adds funds to a margin account
func (e *Engine) Deposit(traderID ids.ID, amount *big.Int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	account, ok := e.accounts[traderID]
	if !ok {
		account = NewMarginAccount(traderID)
		e.accounts[traderID] = account
	}

	account.Balance.Add(account.Balance, amount)
	account.AvailableBalance.Add(account.AvailableBalance, amount)
	account.UpdatedAt = time.Now()

	return nil
}

// Withdraw removes funds from a margin account
func (e *Engine) Withdraw(traderID ids.ID, amount *big.Int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	account, ok := e.accounts[traderID]
	if !ok {
		return errors.New("account not found")
	}

	if account.AvailableBalance.Cmp(amount) < 0 {
		return ErrInsufficientBalance
	}

	account.Balance.Sub(account.Balance, amount)
	account.AvailableBalance.Sub(account.AvailableBalance, amount)
	account.UpdatedAt = time.Now()

	return nil
}

// OpenPosition opens or increases a position
func (e *Engine) OpenPosition(
	traderID ids.ID,
	market string,
	side Side,
	size *big.Int,
	leverage uint16,
	marginMode MarginMode,
) (*Position, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Validate market
	mkt, ok := e.markets[market]
	if !ok {
		return nil, ErrMarketNotFound
	}

	// Validate leverage
	if leverage < 1 || leverage > mkt.MaxLeverage {
		return nil, ErrExceedsMaxLeverage
	}

	// Validate size
	if size.Cmp(mkt.MinSize) < 0 {
		return nil, ErrOrderSizeTooSmall
	}

	// Get account
	account, ok := e.accounts[traderID]
	if !ok {
		return nil, ErrInsufficientBalance
	}

	// Calculate required margin
	// Margin = (Size * MarkPrice) / Leverage
	notionalValue := new(big.Int).Mul(size, mkt.MarkPrice)
	notionalValue.Div(notionalValue, PrecisionFactor)

	requiredMargin := new(big.Int).Div(notionalValue, big.NewInt(int64(leverage)))

	// Check available balance
	if account.AvailableBalance.Cmp(requiredMargin) < 0 {
		return nil, ErrInsufficientMargin
	}

	// Calculate liquidation price
	liquidationPrice := e.calculateLiquidationPrice(mkt, side, mkt.MarkPrice, leverage)

	// Check position wouldn't be immediately liquidatable
	if side == Long && mkt.MarkPrice.Cmp(liquidationPrice) <= 0 {
		return nil, ErrPositionWouldLiquidate
	}
	if side == Short && mkt.MarkPrice.Cmp(liquidationPrice) >= 0 {
		return nil, ErrPositionWouldLiquidate
	}

	// Check for existing position
	existingPos, hasExisting := account.Positions[market]

	var position *Position
	now := time.Now()

	if hasExisting && existingPos.Side == side {
		// Increase existing position
		oldNotional := new(big.Int).Mul(existingPos.Size, existingPos.EntryPrice)
		newNotional := new(big.Int).Mul(size, mkt.MarkPrice)
		totalSize := new(big.Int).Add(existingPos.Size, size)

		// Calculate new average entry price
		totalNotional := new(big.Int).Add(oldNotional, newNotional)
		newEntryPrice := new(big.Int).Div(totalNotional, totalSize)

		existingPos.Size = totalSize
		existingPos.EntryPrice = newEntryPrice
		existingPos.Margin.Add(existingPos.Margin, requiredMargin)
		existingPos.LiquidationPrice = e.calculateLiquidationPrice(mkt, side, newEntryPrice, existingPos.Leverage)
		existingPos.UpdatedAt = now

		position = existingPos
	} else if hasExisting && existingPos.Side != side {
		// Reduce or flip position
		if size.Cmp(existingPos.Size) >= 0 {
			// Close existing and open new
			e.closePositionInternal(account, existingPos, mkt)

			remainingSize := new(big.Int).Sub(size, existingPos.Size)
			if remainingSize.Sign() > 0 {
				// Open new position with remaining size
				position = e.createNewPosition(traderID, market, side, remainingSize, mkt.MarkPrice, leverage, marginMode, mkt)
				e.positions[position.ID] = position
				account.Positions[market] = position
			}
		} else {
			// Reduce existing position
			existingPos.Size.Sub(existingPos.Size, size)
			existingPos.UpdatedAt = now
			position = existingPos
		}
	} else {
		// Create new position
		position = e.createNewPosition(traderID, market, side, size, mkt.MarkPrice, leverage, marginMode, mkt)
		e.positions[position.ID] = position
		account.Positions[market] = position
	}

	// Update account balances
	account.AvailableBalance.Sub(account.AvailableBalance, requiredMargin)
	account.LockedMargin.Add(account.LockedMargin, requiredMargin)
	account.UpdatedAt = now

	// Update market open interest
	if side == Long {
		mkt.OpenInterestLong.Add(mkt.OpenInterestLong, size)
	} else {
		mkt.OpenInterestShort.Add(mkt.OpenInterestShort, size)
	}
	mkt.UpdatedAt = now

	return position, nil
}

func (e *Engine) createNewPosition(
	traderID ids.ID,
	market string,
	side Side,
	size, entryPrice *big.Int,
	leverage uint16,
	marginMode MarginMode,
	mkt *Market,
) *Position {
	now := time.Now()

	notionalValue := new(big.Int).Mul(size, entryPrice)
	notionalValue.Div(notionalValue, PrecisionFactor)
	requiredMargin := new(big.Int).Div(notionalValue, big.NewInt(int64(leverage)))

	return &Position{
		ID:               ids.GenerateTestID(),
		Trader:           traderID,
		Market:           market,
		Side:             side,
		Size:             new(big.Int).Set(size),
		EntryPrice:       new(big.Int).Set(entryPrice),
		Margin:           requiredMargin,
		MarginMode:       marginMode,
		Leverage:         leverage,
		LiquidationPrice: e.calculateLiquidationPrice(mkt, side, entryPrice, leverage),
		UnrealizedPnL:    big.NewInt(0),
		RealizedPnL:      big.NewInt(0),
		FundingPaid:      big.NewInt(0),
		OpenedAt:         now,
		UpdatedAt:        now,
	}
}

// ClosePosition closes a position
func (e *Engine) ClosePosition(traderID ids.ID, market string) (*big.Int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	account, ok := e.accounts[traderID]
	if !ok {
		return nil, errors.New("account not found")
	}

	position, ok := account.Positions[market]
	if !ok {
		return nil, ErrNoOpenPosition
	}

	mkt, ok := e.markets[market]
	if !ok {
		return nil, ErrMarketNotFound
	}

	pnl := e.closePositionInternal(account, position, mkt)
	return pnl, nil
}

func (e *Engine) closePositionInternal(account *MarginAccount, position *Position, mkt *Market) *big.Int {
	now := time.Now()

	// Calculate P&L
	pnl := e.calculatePnL(position, mkt.MarkPrice)

	// Update account
	account.Balance.Add(account.Balance, pnl)
	account.Balance.Add(account.Balance, position.Margin)
	account.AvailableBalance.Add(account.AvailableBalance, position.Margin)
	account.AvailableBalance.Add(account.AvailableBalance, pnl)
	account.LockedMargin.Sub(account.LockedMargin, position.Margin)
	delete(account.Positions, position.Market)
	account.UpdatedAt = now

	// Update market open interest
	if position.Side == Long {
		mkt.OpenInterestLong.Sub(mkt.OpenInterestLong, position.Size)
	} else {
		mkt.OpenInterestShort.Sub(mkt.OpenInterestShort, position.Size)
	}
	mkt.UpdatedAt = now

	// Remove from positions map
	delete(e.positions, position.ID)

	return pnl
}

// GetPosition returns a position. Returns interface{} for API compatibility.
func (e *Engine) GetPosition(traderID ids.ID, market string) (interface{}, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	account, ok := e.accounts[traderID]
	if !ok {
		return nil, errors.New("account not found")
	}

	position, ok := account.Positions[market]
	if !ok {
		return nil, ErrPositionNotFound
	}

	// Update unrealized PnL
	mkt := e.markets[market]
	position.UnrealizedPnL = e.calculatePnL(position, mkt.MarkPrice)

	return position, nil
}

// GetAllPositions returns all positions for a trader. Returns []interface{} for API compatibility.
func (e *Engine) GetAllPositions(traderID ids.ID) ([]interface{}, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	account, ok := e.accounts[traderID]
	if !ok {
		return nil, errors.New("account not found")
	}

	positions := make([]interface{}, 0, len(account.Positions))
	for market, pos := range account.Positions {
		mkt := e.markets[market]
		pos.UnrealizedPnL = e.calculatePnL(pos, mkt.MarkPrice)
		positions = append(positions, pos)
	}

	return positions, nil
}

func (e *Engine) calculatePnL(position *Position, currentPrice *big.Int) *big.Int {
	// PnL = (Current Price - Entry Price) * Size / PrecisionFactor
	// For shorts, negate the result
	priceDiff := new(big.Int).Sub(currentPrice, position.EntryPrice)
	pnl := new(big.Int).Mul(priceDiff, position.Size)
	pnl.Div(pnl, PrecisionFactor)

	if position.Side == Short {
		pnl.Neg(pnl)
	}

	return pnl
}

func (e *Engine) calculateLiquidationPrice(mkt *Market, side Side, entryPrice *big.Int, leverage uint16) *big.Int {
	// For Long: LiqPrice = EntryPrice * (1 - 1/Leverage + MaintenanceMargin)
	// For Short: LiqPrice = EntryPrice * (1 + 1/Leverage - MaintenanceMargin)

	maintenanceMarginRate := new(big.Int).Mul(big.NewInt(int64(mkt.MaintenanceMargin)), PrecisionFactor)
	maintenanceMarginRate.Div(maintenanceMarginRate, BasisPointDenom)

	leverageEffect := new(big.Int).Div(PrecisionFactor, big.NewInt(int64(leverage)))

	var multiplier *big.Int
	if side == Long {
		// 1 - 1/leverage + maintenance margin
		multiplier = new(big.Int).Sub(PrecisionFactor, leverageEffect)
		multiplier.Add(multiplier, maintenanceMarginRate)
	} else {
		// 1 + 1/leverage - maintenance margin
		multiplier = new(big.Int).Add(PrecisionFactor, leverageEffect)
		multiplier.Sub(multiplier, maintenanceMarginRate)
	}

	liquidationPrice := new(big.Int).Mul(entryPrice, multiplier)
	liquidationPrice.Div(liquidationPrice, PrecisionFactor)

	return liquidationPrice
}

// UpdateMarkPrice updates the mark price for a market
func (e *Engine) UpdateMarkPrice(symbol string, newPrice *big.Int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	mkt, ok := e.markets[symbol]
	if !ok {
		return ErrMarketNotFound
	}

	mkt.MarkPrice = new(big.Int).Set(newPrice)
	mkt.IndexPrice = new(big.Int).Set(newPrice) // Simplified: use same as mark price
	mkt.LastPrice = new(big.Int).Set(newPrice)
	mkt.UpdatedAt = time.Now()

	return nil
}

// CheckAndLiquidate checks positions for liquidation and executes if needed
func (e *Engine) CheckAndLiquidate(market string) ([]*LiquidationEvent, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	mkt, ok := e.markets[market]
	if !ok {
		return nil, ErrMarketNotFound
	}

	// SECURITY: Use TWAP price for liquidations to prevent flash crash manipulation
	twapPrice, err := e.twapOracle.GetPrice(market)
	if err != nil {
		// Fallback to mark price if TWAP unavailable (e.g., insufficient history)
		twapPrice = mkt.MarkPrice
	}

	var liquidations []*LiquidationEvent

	for _, account := range e.accounts {
		position, ok := account.Positions[market]
		if !ok {
			continue
		}

		shouldLiquidate := false
		if position.Side == Long && twapPrice.Cmp(position.LiquidationPrice) <= 0 {
			shouldLiquidate = true
		}
		if position.Side == Short && twapPrice.Cmp(position.LiquidationPrice) >= 0 {
			shouldLiquidate = true
		}

		if shouldLiquidate {
			event := e.liquidatePosition(account, position, mkt)
			liquidations = append(liquidations, event)
			// Ring-buffered: bound in-memory history (oom-audit F-3 sibling).
			e.liquidations = append(e.liquidations, event)
			if len(e.liquidations) > maxRecentLiquidations {
				e.liquidations = e.liquidations[len(e.liquidations)-maxRecentLiquidations:]
			}
		}
	}

	return liquidations, nil
}

func (e *Engine) liquidatePosition(account *MarginAccount, position *Position, mkt *Market) *LiquidationEvent {
	now := time.Now()

	// Calculate P&L at liquidation
	pnl := e.calculatePnL(position, mkt.MarkPrice)

	// If P&L is worse than margin, use insurance fund
	var insurancePayout *big.Int
	if pnl.Sign() < 0 && new(big.Int).Abs(pnl).Cmp(position.Margin) > 0 {
		shortfall := new(big.Int).Sub(new(big.Int).Abs(pnl), position.Margin)
		if e.insuranceFund.Cmp(shortfall) >= 0 {
			insurancePayout = shortfall
			e.insuranceFund.Sub(e.insuranceFund, shortfall)
		} else {
			insurancePayout = new(big.Int).Set(e.insuranceFund)
			e.insuranceFund = big.NewInt(0)
			// ADL (Auto-Deleveraging) would happen here in a real system
		}
	} else {
		insurancePayout = big.NewInt(0)
		// Position has remaining margin, add to insurance fund
		if pnl.Sign() < 0 {
			remaining := new(big.Int).Add(position.Margin, pnl)
			if remaining.Sign() > 0 {
				e.insuranceFund.Add(e.insuranceFund, remaining)
			}
		}
	}

	event := &LiquidationEvent{
		ID:               ids.GenerateTestID(),
		Position:         position.Clone(),
		LiquidationPrice: new(big.Int).Set(mkt.MarkPrice),
		LiquidationSize:  new(big.Int).Set(position.Size),
		InsurancePayout:  insurancePayout,
		PnL:              pnl,
		Liquidator:       ids.Empty, // System liquidation
		Timestamp:        now,
	}

	// Clean up position
	account.LockedMargin.Sub(account.LockedMargin, position.Margin)
	delete(account.Positions, position.Market)
	account.UpdatedAt = now

	// Update market
	if position.Side == Long {
		mkt.OpenInterestLong.Sub(mkt.OpenInterestLong, position.Size)
	} else {
		mkt.OpenInterestShort.Sub(mkt.OpenInterestShort, position.Size)
	}
	mkt.UpdatedAt = now

	delete(e.positions, position.ID)

	return event
}

// ProcessFunding processes funding payments for all positions
func (e *Engine) ProcessFunding(market string) ([]*FundingPayment, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	mkt, ok := e.markets[market]
	if !ok {
		return nil, ErrMarketNotFound
	}

	now := time.Now()
	if now.Before(mkt.NextFundingTime) {
		return nil, nil // Not time for funding yet
	}

	// Calculate funding rate based on mark vs index price difference
	// Funding Rate = (Mark Price - Index Price) / Index Price * factor
	priceDiff := new(big.Int).Sub(mkt.MarkPrice, mkt.IndexPrice)
	fundingRate := new(big.Int).Mul(priceDiff, PrecisionFactor)
	fundingRate.Div(fundingRate, mkt.IndexPrice)
	fundingRate.Div(fundingRate, big.NewInt(24)) // 8 hour interval = 1/3 day

	// Clamp to max funding rate
	if fundingRate.Cmp(mkt.MaxFundingRate) > 0 {
		fundingRate = new(big.Int).Set(mkt.MaxFundingRate)
	}
	if new(big.Int).Neg(fundingRate).Cmp(mkt.MaxFundingRate) > 0 {
		fundingRate = new(big.Int).Neg(mkt.MaxFundingRate)
	}

	mkt.FundingRate = fundingRate
	mkt.NextFundingTime = now.Add(mkt.FundingInterval)

	var payments []*FundingPayment

	for _, account := range e.accounts {
		position, ok := account.Positions[market]
		if !ok {
			continue
		}

		// Funding payment = Position Size * Mark Price * Funding Rate / PrecisionFactor
		notional := new(big.Int).Mul(position.Size, mkt.MarkPrice)
		notional.Div(notional, PrecisionFactor)

		payment := new(big.Int).Mul(notional, fundingRate)
		payment.Div(payment, PrecisionFactor)

		// Longs pay shorts when funding is positive
		// Shorts pay longs when funding is negative
		if position.Side == Long {
			// Long pays
			payment.Neg(payment)
		}
		// Short receives (payment stays positive if funding is positive)

		// Apply payment
		account.Balance.Add(account.Balance, payment)
		account.AvailableBalance.Add(account.AvailableBalance, payment)
		position.FundingPaid.Add(position.FundingPaid, payment)
		position.UpdatedAt = now
		account.UpdatedAt = now

		fundingPayment := &FundingPayment{
			ID:          ids.GenerateTestID(),
			Position:    position.ID,
			Market:      market,
			Trader:      account.TraderID,
			Amount:      new(big.Int).Set(payment),
			FundingRate: new(big.Int).Set(fundingRate),
			Timestamp:   now,
		}
		payments = append(payments, fundingPayment)
		// Ring-buffered: bound in-memory history (oom-audit F-3 sibling).
		e.fundingPayments = append(e.fundingPayments, fundingPayment)
		if len(e.fundingPayments) > maxRecentFundingPayments {
			e.fundingPayments = e.fundingPayments[len(e.fundingPayments)-maxRecentFundingPayments:]
		}
	}

	mkt.UpdatedAt = now

	return payments, nil
}

// GetInsuranceFund returns the current insurance fund balance
func (e *Engine) GetInsuranceFund() *big.Int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return new(big.Int).Set(e.insuranceFund)
}

// AddToInsuranceFund adds funds to the insurance fund
func (e *Engine) AddToInsuranceFund(amount *big.Int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.insuranceFund.Add(e.insuranceFund, amount)
}

// GetLiquidations returns all liquidation events
func (e *Engine) GetLiquidations() []*LiquidationEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*LiquidationEvent, len(e.liquidations))
	copy(result, e.liquidations)
	return result
}

// GetFundingPayments returns all funding payments
func (e *Engine) GetFundingPayments() []*FundingPayment {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*FundingPayment, len(e.fundingPayments))
	copy(result, e.fundingPayments)
	return result
}

// GetMarginRatio calculates the margin ratio for an account
func (e *Engine) GetMarginRatio(traderID ids.ID) (*big.Int, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	account, ok := e.accounts[traderID]
	if !ok {
		return nil, errors.New("account not found")
	}

	totalNotional := big.NewInt(0)
	totalUnrealizedPnL := big.NewInt(0)

	for market, position := range account.Positions {
		mkt := e.markets[market]
		notional := new(big.Int).Mul(position.Size, mkt.MarkPrice)
		notional.Div(notional, PrecisionFactor)
		totalNotional.Add(totalNotional, notional)

		pnl := e.calculatePnL(position, mkt.MarkPrice)
		totalUnrealizedPnL.Add(totalUnrealizedPnL, pnl)
	}

	if totalNotional.Sign() == 0 {
		return PrecisionFactor, nil // 100% margin ratio when no positions
	}

	// Margin Ratio = (Balance + UnrealizedPnL) / Total Notional
	equity := new(big.Int).Add(account.Balance, totalUnrealizedPnL)
	marginRatio := new(big.Int).Mul(equity, PrecisionFactor)
	marginRatio.Div(marginRatio, totalNotional)

	return marginRatio, nil
}
