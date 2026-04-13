// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package lending

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/ids"
)

var (
	// Errors
	ErrPoolNotFound           = errors.New("lending pool not found")
	ErrPoolAlreadyExists      = errors.New("lending pool already exists")
	ErrInsufficientLiquidity  = errors.New("insufficient liquidity in pool")
	ErrInsufficientCollateral = errors.New("insufficient collateral for borrow")
	ErrInsufficientBalance    = errors.New("insufficient balance")
	ErrInvalidAmount          = errors.New("invalid amount")
	ErrAccountNotFound        = errors.New("account not found")
	ErrHealthFactorTooLow     = errors.New("health factor would be too low")
	ErrNotLiquidatable        = errors.New("position is not liquidatable")
	ErrCollateralNotEnabled   = errors.New("collateral not enabled for this asset")
	ErrZeroPrice              = errors.New("asset price is zero")

	// Scale factor
	scale18 = big.NewInt(1e18)
)

// PriceOracle provides asset prices for the lending protocol.
type PriceOracle interface {
	GetPrice(asset string) (*big.Int, error) // Returns price in USD (scaled by 1e18)
}

// SimplePriceOracle is a simple in-memory price oracle for testing.
type SimplePriceOracle struct {
	prices map[string]*big.Int
	mu     sync.RWMutex
}

// NewSimplePriceOracle creates a new simple price oracle.
func NewSimplePriceOracle() *SimplePriceOracle {
	return &SimplePriceOracle{
		prices: make(map[string]*big.Int),
	}
}

// SetPrice sets the price for an asset.
func (o *SimplePriceOracle) SetPrice(asset string, price *big.Int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.prices[asset] = new(big.Int).Set(price)
}

// GetPrice returns the price for an asset.
func (o *SimplePriceOracle) GetPrice(asset string) (*big.Int, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	price, ok := o.prices[asset]
	if !ok {
		return nil, ErrZeroPrice
	}
	return new(big.Int).Set(price), nil
}

// Engine is the core lending protocol engine.
type Engine struct {
	pools        map[string]*LendingPool      // Asset -> Pool
	accounts     map[ids.ShortID]*UserAccount // User -> Account
	liquidations []*LiquidationEvent          // Liquidation history
	oracle       PriceOracle                  // Price oracle
	mu           sync.RWMutex
}

// NewEngine creates a new lending engine.
func NewEngine(oracle PriceOracle) *Engine {
	return &Engine{
		pools:        make(map[string]*LendingPool),
		accounts:     make(map[ids.ShortID]*UserAccount),
		liquidations: make([]*LiquidationEvent, 0),
		oracle:       oracle,
	}
}

// CreatePool creates a new lending pool for an asset.
func (e *Engine) CreatePool(config *PoolConfig) (*LendingPool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.pools[config.Asset]; exists {
		return nil, ErrPoolAlreadyExists
	}

	now := time.Now()
	pool := &LendingPool{
		ID:                   ids.GenerateTestID(),
		Asset:                config.Asset,
		TotalSupply:          big.NewInt(0),
		TotalBorrows:         big.NewInt(0),
		AvailableLiquidity:   big.NewInt(0),
		SupplyRate:           big.NewInt(0),
		BorrowRate:           new(big.Int).Set(config.BaseRate),
		UtilizationRate:      big.NewInt(0),
		BaseRate:             new(big.Int).Set(config.BaseRate),
		Multiplier:           new(big.Int).Set(config.Multiplier),
		JumpMultiplier:       new(big.Int).Set(config.JumpMultiplier),
		Kink:                 new(big.Int).Set(config.Kink),
		CollateralFactor:     new(big.Int).Set(config.CollateralFactor),
		LiquidationBonus:     new(big.Int).Set(config.LiquidationBonus),
		LiquidationThreshold: new(big.Int).Set(config.LiquidationThreshold),
		ReserveFactor:        new(big.Int).Set(config.ReserveFactor),
		TotalReserves:        big.NewInt(0),
		LastUpdateTime:       now,
		CreatedAt:            now,
	}

	e.pools[config.Asset] = pool
	return pool, nil
}

// GetPool returns a lending pool by asset.
func (e *Engine) GetPool(asset string) (*LendingPool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	pool, ok := e.pools[asset]
	if !ok {
		return nil, ErrPoolNotFound
	}
	return pool, nil
}

// GetAllPools returns all lending pools.
func (e *Engine) GetAllPools() []*LendingPool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	pools := make([]*LendingPool, 0, len(e.pools))
	for _, pool := range e.pools {
		pools = append(pools, pool)
	}
	return pools
}

// getOrCreateAccount gets or creates a user account.
func (e *Engine) getOrCreateAccount(user ids.ShortID) *UserAccount {
	account, ok := e.accounts[user]
	if !ok {
		now := time.Now()
		account = &UserAccount{
			User:               user,
			Supplies:           make(map[string]*UserSupply),
			Borrows:            make(map[string]*UserBorrow),
			Collateral:         make(map[string]*CollateralPosition),
			HealthFactor:       new(big.Int).Set(scale18), // Start with max health
			TotalCollateralUSD: big.NewInt(0),
			TotalBorrowsUSD:    big.NewInt(0),
			BorrowCapacityUSD:  big.NewInt(0),
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		e.accounts[user] = account
	}
	return account
}

// Supply adds liquidity to a lending pool.
func (e *Engine) Supply(user ids.ShortID, asset string, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return ErrInvalidAmount
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	pool, ok := e.pools[asset]
	if !ok {
		return ErrPoolNotFound
	}

	// Update interest before modifying pool
	e.accrueInterest(pool)

	// Update pool state
	pool.TotalSupply.Add(pool.TotalSupply, amount)
	pool.AvailableLiquidity.Add(pool.AvailableLiquidity, amount)

	// Update user supply position
	account := e.getOrCreateAccount(user)
	supply, ok := account.Supplies[asset]
	if !ok {
		supply = &UserSupply{
			User:        user,
			Pool:        pool.ID,
			Asset:       asset,
			Principal:   big.NewInt(0),
			Balance:     big.NewInt(0),
			SupplyIndex: new(big.Int).Set(scale18),
			UpdatedAt:   time.Now(),
		}
		account.Supplies[asset] = supply
	}

	supply.Principal.Add(supply.Principal, amount)
	supply.Balance.Add(supply.Balance, amount)
	supply.UpdatedAt = time.Now()

	// Enable as collateral by default
	collateral, ok := account.Collateral[asset]
	if !ok {
		collateral = &CollateralPosition{
			User:      user,
			Asset:     asset,
			Amount:    big.NewInt(0),
			IsEnabled: true,
			UpdatedAt: time.Now(),
		}
		account.Collateral[asset] = collateral
	}
	collateral.Amount.Add(collateral.Amount, amount)
	collateral.UpdatedAt = time.Now()

	// Update pool rates
	e.updatePoolRates(pool)

	// Update account health
	e.updateAccountHealth(account)

	return nil
}

// Withdraw removes liquidity from a lending pool.
func (e *Engine) Withdraw(user ids.ShortID, asset string, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return ErrInvalidAmount
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	pool, ok := e.pools[asset]
	if !ok {
		return ErrPoolNotFound
	}

	// Update interest before modifying pool
	e.accrueInterest(pool)

	// Check user balance
	account, ok := e.accounts[user]
	if !ok {
		return ErrAccountNotFound
	}

	supply, ok := account.Supplies[asset]
	if !ok || supply.Balance.Cmp(amount) < 0 {
		return ErrInsufficientBalance
	}

	// Check liquidity
	if pool.AvailableLiquidity.Cmp(amount) < 0 {
		return ErrInsufficientLiquidity
	}

	// Check health factor after withdrawal
	collateral := account.Collateral[asset]
	if collateral != nil && collateral.IsEnabled {
		// Calculate new health factor
		newCollateralAmount := new(big.Int).Sub(collateral.Amount, amount)
		if newCollateralAmount.Sign() < 0 {
			newCollateralAmount = big.NewInt(0)
		}

		// Temporarily update to check health
		oldAmount := new(big.Int).Set(collateral.Amount)
		collateral.Amount = newCollateralAmount
		e.updateAccountHealth(account)

		if account.HealthFactor.Cmp(scale18) < 0 && account.TotalBorrowsUSD.Sign() > 0 {
			// Restore and return error
			collateral.Amount = oldAmount
			e.updateAccountHealth(account)
			return ErrHealthFactorTooLow
		}

		// Keep the new amount
	}

	// Update pool state
	pool.TotalSupply.Sub(pool.TotalSupply, amount)
	pool.AvailableLiquidity.Sub(pool.AvailableLiquidity, amount)

	// Update user supply position
	supply.Principal.Sub(supply.Principal, amount)
	supply.Balance.Sub(supply.Balance, amount)
	supply.UpdatedAt = time.Now()

	// Update collateral
	if collateral != nil {
		collateral.Amount.Sub(collateral.Amount, amount)
		if collateral.Amount.Sign() < 0 {
			collateral.Amount = big.NewInt(0)
		}
		collateral.UpdatedAt = time.Now()
	}

	// Update pool rates
	e.updatePoolRates(pool)

	// Update account health
	e.updateAccountHealth(account)

	return nil
}

// Borrow takes a loan from a lending pool.
func (e *Engine) Borrow(user ids.ShortID, asset string, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return ErrInvalidAmount
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	pool, ok := e.pools[asset]
	if !ok {
		return ErrPoolNotFound
	}

	// Update interest before modifying pool
	e.accrueInterest(pool)

	// Check liquidity
	if pool.AvailableLiquidity.Cmp(amount) < 0 {
		return ErrInsufficientLiquidity
	}

	// Get/create account
	account := e.getOrCreateAccount(user)

	// Calculate borrow value in USD
	price, err := e.oracle.GetPrice(asset)
	if err != nil {
		return err
	}

	borrowValueUSD := new(big.Int).Mul(amount, price)
	borrowValueUSD.Div(borrowValueUSD, scale18)

	// Check if user has enough collateral
	newTotalBorrowsUSD := new(big.Int).Add(account.TotalBorrowsUSD, borrowValueUSD)
	if newTotalBorrowsUSD.Cmp(account.BorrowCapacityUSD) > 0 {
		return ErrInsufficientCollateral
	}

	// Update pool state
	pool.TotalBorrows.Add(pool.TotalBorrows, amount)
	pool.AvailableLiquidity.Sub(pool.AvailableLiquidity, amount)

	// Update user borrow position
	borrow, ok := account.Borrows[asset]
	if !ok {
		borrow = &UserBorrow{
			User:        user,
			Pool:        pool.ID,
			Asset:       asset,
			Principal:   big.NewInt(0),
			Balance:     big.NewInt(0),
			BorrowIndex: new(big.Int).Set(scale18),
			UpdatedAt:   time.Now(),
		}
		account.Borrows[asset] = borrow
	}

	borrow.Principal.Add(borrow.Principal, amount)
	borrow.Balance.Add(borrow.Balance, amount)
	borrow.UpdatedAt = time.Now()

	// Update pool rates
	e.updatePoolRates(pool)

	// Update account health
	e.updateAccountHealth(account)

	return nil
}

// Repay pays back a loan.
func (e *Engine) Repay(user ids.ShortID, asset string, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return ErrInvalidAmount
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	pool, ok := e.pools[asset]
	if !ok {
		return ErrPoolNotFound
	}

	// Update interest before modifying pool
	e.accrueInterest(pool)

	// Check user borrow
	account, ok := e.accounts[user]
	if !ok {
		return ErrAccountNotFound
	}

	borrow, ok := account.Borrows[asset]
	if !ok || borrow.Balance.Sign() == 0 {
		return ErrInsufficientBalance
	}

	// Cap repayment at borrow balance
	repayAmount := new(big.Int).Set(amount)
	if repayAmount.Cmp(borrow.Balance) > 0 {
		repayAmount.Set(borrow.Balance)
	}

	// Update pool state
	pool.TotalBorrows.Sub(pool.TotalBorrows, repayAmount)
	pool.AvailableLiquidity.Add(pool.AvailableLiquidity, repayAmount)

	// Update user borrow position
	borrow.Principal.Sub(borrow.Principal, repayAmount)
	if borrow.Principal.Sign() < 0 {
		borrow.Principal = big.NewInt(0)
	}
	borrow.Balance.Sub(borrow.Balance, repayAmount)
	borrow.UpdatedAt = time.Now()

	// Update pool rates
	e.updatePoolRates(pool)

	// Update account health
	e.updateAccountHealth(account)

	return nil
}

// Liquidate liquidates an undercollateralized position.
func (e *Engine) Liquidate(
	liquidator ids.ShortID,
	borrower ids.ShortID,
	debtAsset string,
	collateralAsset string,
	debtAmount *big.Int,
) (*LiquidationEvent, error) {
	if debtAmount.Sign() <= 0 {
		return nil, ErrInvalidAmount
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Get borrower account
	account, ok := e.accounts[borrower]
	if !ok {
		return nil, ErrAccountNotFound
	}

	// Check if position is liquidatable
	e.updateAccountHealth(account)
	if account.HealthFactor.Cmp(scale18) >= 0 {
		return nil, ErrNotLiquidatable
	}

	// Get debt pool
	debtPool, ok := e.pools[debtAsset]
	if !ok {
		return nil, ErrPoolNotFound
	}

	// Get borrow position
	borrow, ok := account.Borrows[debtAsset]
	if !ok || borrow.Balance.Sign() == 0 {
		return nil, ErrInsufficientBalance
	}

	// Cap debt amount at 50% of borrow (close factor)
	maxDebt := new(big.Int).Div(borrow.Balance, big.NewInt(2))
	actualDebtAmount := new(big.Int).Set(debtAmount)
	if actualDebtAmount.Cmp(maxDebt) > 0 {
		actualDebtAmount.Set(maxDebt)
	}

	// Get collateral position
	collateral, ok := account.Collateral[collateralAsset]
	if !ok || !collateral.IsEnabled || collateral.Amount.Sign() == 0 {
		return nil, ErrCollateralNotEnabled
	}

	// Calculate collateral to seize
	debtPrice, err := e.oracle.GetPrice(debtAsset)
	if err != nil {
		return nil, err
	}
	collateralPrice, err := e.oracle.GetPrice(collateralAsset)
	if err != nil {
		return nil, err
	}

	// Debt value in USD
	debtValueUSD := new(big.Int).Mul(actualDebtAmount, debtPrice)
	debtValueUSD.Div(debtValueUSD, scale18)

	// Collateral to seize (including liquidation bonus)
	liquidationBonus := debtPool.LiquidationBonus
	bonusMultiplier := new(big.Int).Add(scale18, liquidationBonus)
	collateralValueUSD := new(big.Int).Mul(debtValueUSD, bonusMultiplier)
	collateralValueUSD.Div(collateralValueUSD, scale18)

	collateralToSeize := new(big.Int).Mul(collateralValueUSD, scale18)
	collateralToSeize.Div(collateralToSeize, collateralPrice)

	// Cap at available collateral
	if collateralToSeize.Cmp(collateral.Amount) > 0 {
		collateralToSeize.Set(collateral.Amount)
	}

	// Execute liquidation
	// 1. Repay debt
	borrow.Balance.Sub(borrow.Balance, actualDebtAmount)
	borrow.Principal.Sub(borrow.Principal, actualDebtAmount)
	if borrow.Principal.Sign() < 0 {
		borrow.Principal = big.NewInt(0)
	}

	// 2. Seize collateral
	collateral.Amount.Sub(collateral.Amount, collateralToSeize)

	// 3. Update debt pool
	debtPool.TotalBorrows.Sub(debtPool.TotalBorrows, actualDebtAmount)
	debtPool.AvailableLiquidity.Add(debtPool.AvailableLiquidity, actualDebtAmount)

	// 4. Update supply in collateral pool (reduce borrower's supply)
	collateralPool := e.pools[collateralAsset]
	if collateralPool != nil {
		if supply, ok := account.Supplies[collateralAsset]; ok {
			supply.Balance.Sub(supply.Balance, collateralToSeize)
			if supply.Balance.Sign() < 0 {
				supply.Balance = big.NewInt(0)
			}
		}
	}

	// Calculate liquidator bonus
	bonusAmount := new(big.Int).Mul(collateralToSeize, liquidationBonus)
	bonusAmount.Div(bonusAmount, scale18)

	// Update account health
	e.updateAccountHealth(account)

	// Create liquidation event
	event := &LiquidationEvent{
		ID:               ids.GenerateTestID(),
		Liquidator:       liquidator,
		Borrower:         borrower,
		DebtAsset:        debtAsset,
		CollateralAsset:  collateralAsset,
		DebtRepaid:       actualDebtAmount,
		CollateralSeized: collateralToSeize,
		LiquidatorBonus:  bonusAmount,
		Timestamp:        time.Now(),
	}
	e.liquidations = append(e.liquidations, event)

	return event, nil
}

// EnableCollateral enables or disables an asset as collateral.
func (e *Engine) EnableCollateral(user ids.ShortID, asset string, enabled bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	account, ok := e.accounts[user]
	if !ok {
		return ErrAccountNotFound
	}

	collateral, ok := account.Collateral[asset]
	if !ok {
		return ErrCollateralNotEnabled
	}

	// If disabling, check health factor
	if !enabled && collateral.IsEnabled {
		oldEnabled := collateral.IsEnabled
		collateral.IsEnabled = false
		e.updateAccountHealth(account)

		if account.HealthFactor.Cmp(scale18) < 0 && account.TotalBorrowsUSD.Sign() > 0 {
			// Restore and return error
			collateral.IsEnabled = oldEnabled
			e.updateAccountHealth(account)
			return ErrHealthFactorTooLow
		}
	}

	collateral.IsEnabled = enabled
	collateral.UpdatedAt = time.Now()

	return nil
}

// GetAccount returns a user's lending account.
func (e *Engine) GetAccount(user ids.ShortID) (*UserAccount, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	account, ok := e.accounts[user]
	if !ok {
		return nil, ErrAccountNotFound
	}
	return account, nil
}

// GetStats returns aggregate lending statistics.
func (e *Engine) GetStats() *LendingStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := &LendingStats{
		TotalSupplyUSD:   big.NewInt(0),
		TotalBorrowsUSD:  big.NewInt(0),
		TotalReservesUSD: big.NewInt(0),
		PoolCount:        len(e.pools),
		UserCount:        len(e.accounts),
		LiquidationCount: len(e.liquidations),
	}

	for asset, pool := range e.pools {
		price, err := e.oracle.GetPrice(asset)
		if err != nil {
			continue
		}

		supplyUSD := new(big.Int).Mul(pool.TotalSupply, price)
		supplyUSD.Div(supplyUSD, scale18)
		stats.TotalSupplyUSD.Add(stats.TotalSupplyUSD, supplyUSD)

		borrowsUSD := new(big.Int).Mul(pool.TotalBorrows, price)
		borrowsUSD.Div(borrowsUSD, scale18)
		stats.TotalBorrowsUSD.Add(stats.TotalBorrowsUSD, borrowsUSD)

		reservesUSD := new(big.Int).Mul(pool.TotalReserves, price)
		reservesUSD.Div(reservesUSD, scale18)
		stats.TotalReservesUSD.Add(stats.TotalReservesUSD, reservesUSD)
	}

	return stats
}

// accrueInterest updates interest for a pool based on time elapsed.
func (e *Engine) accrueInterest(pool *LendingPool) {
	now := time.Now()
	elapsed := now.Sub(pool.LastUpdateTime).Seconds()
	if elapsed <= 0 {
		return
	}

	// Calculate interest accrued
	if pool.TotalBorrows.Sign() > 0 {
		// Interest = borrows * borrowRate * elapsed / secondsPerYear
		interest := new(big.Int).Mul(pool.TotalBorrows, pool.BorrowRate)
		interest.Mul(interest, big.NewInt(int64(elapsed)))
		interest.Div(interest, big.NewInt(SecondsPerYear))
		interest.Div(interest, scale18)

		// Add interest to borrows
		pool.TotalBorrows.Add(pool.TotalBorrows, interest)

		// Calculate reserve portion
		reserveInterest := new(big.Int).Mul(interest, pool.ReserveFactor)
		reserveInterest.Div(reserveInterest, scale18)
		pool.TotalReserves.Add(pool.TotalReserves, reserveInterest)

		// Add rest to supply (for suppliers)
		supplierInterest := new(big.Int).Sub(interest, reserveInterest)
		pool.TotalSupply.Add(pool.TotalSupply, supplierInterest)
	}

	pool.LastUpdateTime = now
}

// updatePoolRates recalculates interest rates based on utilization.
func (e *Engine) updatePoolRates(pool *LendingPool) {
	if pool.TotalSupply.Sign() == 0 {
		pool.UtilizationRate = big.NewInt(0)
		pool.BorrowRate = new(big.Int).Set(pool.BaseRate)
		pool.SupplyRate = big.NewInt(0)
		return
	}

	// Utilization = borrows / supply
	utilization := new(big.Int).Mul(pool.TotalBorrows, scale18)
	utilization.Div(utilization, pool.TotalSupply)
	pool.UtilizationRate = utilization

	// Calculate borrow rate using jump rate model
	var borrowRate *big.Int
	if utilization.Cmp(pool.Kink) <= 0 {
		// Normal rate: baseRate + utilization * multiplier
		borrowRate = new(big.Int).Mul(utilization, pool.Multiplier)
		borrowRate.Div(borrowRate, scale18)
		borrowRate.Add(borrowRate, pool.BaseRate)
	} else {
		// Jump rate: normalRate + (utilization - kink) * jumpMultiplier
		normalRate := new(big.Int).Mul(pool.Kink, pool.Multiplier)
		normalRate.Div(normalRate, scale18)
		normalRate.Add(normalRate, pool.BaseRate)

		excessUtilization := new(big.Int).Sub(utilization, pool.Kink)
		jumpRate := new(big.Int).Mul(excessUtilization, pool.JumpMultiplier)
		jumpRate.Div(jumpRate, scale18)

		borrowRate = new(big.Int).Add(normalRate, jumpRate)
	}
	pool.BorrowRate = borrowRate

	// Supply rate = borrowRate * utilization * (1 - reserveFactor)
	supplyRate := new(big.Int).Mul(borrowRate, utilization)
	supplyRate.Div(supplyRate, scale18)
	oneMinusReserve := new(big.Int).Sub(scale18, pool.ReserveFactor)
	supplyRate.Mul(supplyRate, oneMinusReserve)
	supplyRate.Div(supplyRate, scale18)
	pool.SupplyRate = supplyRate

	// Update available liquidity
	pool.AvailableLiquidity = new(big.Int).Sub(pool.TotalSupply, pool.TotalBorrows)
}

// updateAccountHealth recalculates a user's health factor and borrow capacity.
func (e *Engine) updateAccountHealth(account *UserAccount) {
	totalCollateralUSD := big.NewInt(0)
	totalBorrowsUSD := big.NewInt(0)
	borrowCapacityUSD := big.NewInt(0)

	// Calculate collateral value
	for asset, collateral := range account.Collateral {
		if !collateral.IsEnabled || collateral.Amount.Sign() == 0 {
			continue
		}

		price, err := e.oracle.GetPrice(asset)
		if err != nil {
			continue
		}

		pool := e.pools[asset]
		if pool == nil {
			continue
		}

		// Collateral value in USD
		valueUSD := new(big.Int).Mul(collateral.Amount, price)
		valueUSD.Div(valueUSD, scale18)
		totalCollateralUSD.Add(totalCollateralUSD, valueUSD)

		// Borrow capacity = collateral * collateralFactor
		capacity := new(big.Int).Mul(valueUSD, pool.CollateralFactor)
		capacity.Div(capacity, scale18)
		borrowCapacityUSD.Add(borrowCapacityUSD, capacity)
	}

	// Calculate borrow value
	for asset, borrow := range account.Borrows {
		if borrow.Balance.Sign() == 0 {
			continue
		}

		price, err := e.oracle.GetPrice(asset)
		if err != nil {
			continue
		}

		valueUSD := new(big.Int).Mul(borrow.Balance, price)
		valueUSD.Div(valueUSD, scale18)
		totalBorrowsUSD.Add(totalBorrowsUSD, valueUSD)
	}

	account.TotalCollateralUSD = totalCollateralUSD
	account.TotalBorrowsUSD = totalBorrowsUSD
	account.BorrowCapacityUSD = borrowCapacityUSD

	// Calculate health factor = collateral * liquidationThreshold / borrows
	if totalBorrowsUSD.Sign() == 0 {
		account.HealthFactor = new(big.Int).Mul(scale18, big.NewInt(1000)) // Max health
	} else {
		// Need to calculate weighted liquidation threshold
		weightedThreshold := big.NewInt(0)
		for asset, collateral := range account.Collateral {
			if !collateral.IsEnabled || collateral.Amount.Sign() == 0 {
				continue
			}

			pool := e.pools[asset]
			if pool == nil {
				continue
			}

			price, _ := e.oracle.GetPrice(asset)
			if price == nil {
				continue
			}

			valueUSD := new(big.Int).Mul(collateral.Amount, price)
			valueUSD.Div(valueUSD, scale18)

			threshold := new(big.Int).Mul(valueUSD, pool.LiquidationThreshold)
			threshold.Div(threshold, scale18)
			weightedThreshold.Add(weightedThreshold, threshold)
		}

		healthFactor := new(big.Int).Mul(weightedThreshold, scale18)
		healthFactor.Div(healthFactor, totalBorrowsUSD)
		account.HealthFactor = healthFactor
	}

	account.UpdatedAt = time.Now()
}

// AccrueAllInterest accrues interest for all pools (called during block processing).
func (e *Engine) AccrueAllInterest() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, pool := range e.pools {
		e.accrueInterest(pool)
		e.updatePoolRates(pool)
	}
}
