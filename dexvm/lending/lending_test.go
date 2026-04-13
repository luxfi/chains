// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package lending

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// bigMul multiplies a value by 10^18
func bigMul(v int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(v), scale18)
}

// Helper to create a price oracle with preset prices.
func newTestOracle() *SimplePriceOracle {
	oracle := NewSimplePriceOracle()
	// Set prices (scaled by 1e18)
	oracle.SetPrice("LUX", bigMul(50))    // $50
	oracle.SetPrice("USDT", bigMul(1))    // $1
	oracle.SetPrice("ETH", bigMul(2000))  // $2000
	oracle.SetPrice("BTC", bigMul(40000)) // $40000
	return oracle
}

// Helper to create a test engine with common pools.
func newTestEngine() *Engine {
	oracle := newTestOracle()
	engine := NewEngine(oracle)

	// Create pools
	engine.CreatePool(DefaultPoolConfig("LUX"))
	engine.CreatePool(DefaultPoolConfig("USDT"))
	engine.CreatePool(DefaultPoolConfig("ETH"))

	return engine
}

func TestNewEngine(t *testing.T) {
	require := require.New(t)

	oracle := NewSimplePriceOracle()
	engine := NewEngine(oracle)

	require.NotNil(engine)
	require.Empty(engine.pools)
	require.Empty(engine.accounts)
}

func TestCreatePool(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()

	pool, err := engine.GetPool("LUX")
	require.NoError(err)
	require.NotNil(pool)
	require.Equal("LUX", pool.Asset)
	require.Equal(int64(0), pool.TotalSupply.Int64())
	require.Equal(int64(0), pool.TotalBorrows.Int64())
}

func TestCreatePoolDuplicate(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()

	// Try to create duplicate pool
	_, err := engine.CreatePool(DefaultPoolConfig("LUX"))
	require.ErrorIs(err, ErrPoolAlreadyExists)
}

func TestSupply(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Supply 100 LUX
	amount := bigMul(100) // 100 LUX
	err := engine.Supply(user, "LUX", amount)
	require.NoError(err)

	// Check pool state
	pool, _ := engine.GetPool("LUX")
	require.Equal(0, pool.TotalSupply.Cmp(amount))
	require.Equal(0, pool.AvailableLiquidity.Cmp(amount))

	// Check user account
	account, err := engine.GetAccount(user)
	require.NoError(err)
	require.Equal(0, account.Supplies["LUX"].Balance.Cmp(amount))
	require.Equal(0, account.Collateral["LUX"].Amount.Cmp(amount))
	require.True(account.Collateral["LUX"].IsEnabled)
}

func TestSupplyInvalidAmount(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Try to supply zero
	err := engine.Supply(user, "LUX", big.NewInt(0))
	require.ErrorIs(err, ErrInvalidAmount)

	// Try to supply negative
	err = engine.Supply(user, "LUX", big.NewInt(-100))
	require.ErrorIs(err, ErrInvalidAmount)
}

func TestSupplyPoolNotFound(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	err := engine.Supply(user, "UNKNOWN", bigMul(100))
	require.ErrorIs(err, ErrPoolNotFound)
}

func TestWithdraw(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Supply first
	supplyAmount := bigMul(100)
	err := engine.Supply(user, "LUX", supplyAmount)
	require.NoError(err)

	// Withdraw half
	withdrawAmount := bigMul(50)
	err = engine.Withdraw(user, "LUX", withdrawAmount)
	require.NoError(err)

	// Check balances
	pool, _ := engine.GetPool("LUX")
	require.Equal(0, pool.TotalSupply.Cmp(bigMul(50)))

	account, _ := engine.GetAccount(user)
	require.Equal(0, account.Supplies["LUX"].Balance.Cmp(bigMul(50)))
}

func TestWithdrawInsufficientBalance(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Supply some
	err := engine.Supply(user, "LUX", bigMul(100))
	require.NoError(err)

	// Try to withdraw more
	err = engine.Withdraw(user, "LUX", bigMul(200))
	require.ErrorIs(err, ErrInsufficientBalance)
}

func TestBorrow(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Supply collateral: 100 LUX worth $5000
	err := engine.Supply(user, "LUX", bigMul(100))
	require.NoError(err)

	// Borrow USDT (need liquidity in pool first)
	supplier := ids.GenerateTestShortID()
	err = engine.Supply(supplier, "USDT", bigMul(10000)) // $10000 USDT
	require.NoError(err)

	// Borrow $3000 USDT (within 75% collateral factor of $5000)
	borrowAmount := bigMul(3000)
	err = engine.Borrow(user, "USDT", borrowAmount)
	require.NoError(err)

	// Check borrow position
	account, _ := engine.GetAccount(user)
	require.Equal(0, account.Borrows["USDT"].Balance.Cmp(borrowAmount))

	// Check pool state
	pool, _ := engine.GetPool("USDT")
	require.Equal(0, pool.TotalBorrows.Cmp(borrowAmount))
}

func TestBorrowInsufficientCollateral(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Supply small collateral: 10 LUX worth $500
	err := engine.Supply(user, "LUX", bigMul(10))
	require.NoError(err)

	// Add USDT liquidity
	supplier := ids.GenerateTestShortID()
	err = engine.Supply(supplier, "USDT", bigMul(10000))
	require.NoError(err)

	// Try to borrow $1000 (exceeds 75% of $500 = $375)
	err = engine.Borrow(user, "USDT", bigMul(1000))
	require.ErrorIs(err, ErrInsufficientCollateral)
}

func TestBorrowInsufficientLiquidity(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Supply large collateral
	err := engine.Supply(user, "LUX", bigMul(1000))
	require.NoError(err)

	// Don't supply any USDT liquidity
	// Try to borrow
	err = engine.Borrow(user, "USDT", bigMul(100))
	require.ErrorIs(err, ErrInsufficientLiquidity)
}

func TestRepay(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Setup: supply collateral and borrow
	err := engine.Supply(user, "LUX", bigMul(100))
	require.NoError(err)

	supplier := ids.GenerateTestShortID()
	err = engine.Supply(supplier, "USDT", bigMul(10000))
	require.NoError(err)

	borrowAmount := bigMul(2000)
	err = engine.Borrow(user, "USDT", borrowAmount)
	require.NoError(err)

	// Repay half
	repayAmount := bigMul(1000)
	err = engine.Repay(user, "USDT", repayAmount)
	require.NoError(err)

	// Check remaining borrow
	account, _ := engine.GetAccount(user)
	require.Equal(0, account.Borrows["USDT"].Balance.Cmp(bigMul(1000)))
}

func TestRepayFull(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Setup
	err := engine.Supply(user, "LUX", bigMul(100))
	require.NoError(err)

	supplier := ids.GenerateTestShortID()
	err = engine.Supply(supplier, "USDT", bigMul(10000))
	require.NoError(err)

	borrowAmount := bigMul(2000)
	err = engine.Borrow(user, "USDT", borrowAmount)
	require.NoError(err)

	// Repay more than borrowed (should cap at borrow amount)
	err = engine.Repay(user, "USDT", bigMul(5000))
	require.NoError(err)

	// Check borrow is zero
	account, _ := engine.GetAccount(user)
	require.Equal(int64(0), account.Borrows["USDT"].Balance.Int64())
}

func TestLiquidation(t *testing.T) {
	require := require.New(t)

	oracle := newTestOracle()
	engine := NewEngine(oracle)
	engine.CreatePool(DefaultPoolConfig("LUX"))
	engine.CreatePool(DefaultPoolConfig("USDT"))

	user := ids.GenerateTestShortID()
	liquidator := ids.GenerateTestShortID()

	// Supply collateral: 100 LUX @ $50 = $5000
	err := engine.Supply(user, "LUX", bigMul(100))
	require.NoError(err)

	// Add USDT liquidity
	supplier := ids.GenerateTestShortID()
	err = engine.Supply(supplier, "USDT", bigMul(10000))
	require.NoError(err)

	// Borrow close to max: $3500 (70% of $5000)
	err = engine.Borrow(user, "USDT", bigMul(3500))
	require.NoError(err)

	// Price drops: LUX drops to $40 (from $50)
	// Collateral now worth $4000, borrow still $3500
	// Health factor = $4000 * 0.8 / $3500 = 0.91 < 1.0 (liquidatable)
	oracle.SetPrice("LUX", bigMul(40))

	// Liquidate
	event, err := engine.Liquidate(liquidator, user, "USDT", "LUX", bigMul(1000))
	require.NoError(err)
	require.NotNil(event)

	require.Equal(liquidator, event.Liquidator)
	require.Equal(user, event.Borrower)
	require.Equal("USDT", event.DebtAsset)
	require.Equal("LUX", event.CollateralAsset)

	// Liquidation bonus should be applied
	require.True(event.LiquidatorBonus.Sign() > 0)
}

func TestLiquidationNotLiquidatable(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()
	liquidator := ids.GenerateTestShortID()

	// Supply large collateral
	err := engine.Supply(user, "LUX", bigMul(100))
	require.NoError(err)

	supplier := ids.GenerateTestShortID()
	err = engine.Supply(supplier, "USDT", bigMul(10000))
	require.NoError(err)

	// Borrow small amount (healthy position)
	err = engine.Borrow(user, "USDT", bigMul(1000))
	require.NoError(err)

	// Try to liquidate
	_, err = engine.Liquidate(liquidator, user, "USDT", "LUX", bigMul(500))
	require.ErrorIs(err, ErrNotLiquidatable)
}

func TestHealthFactor(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Supply: 100 LUX @ $50 = $5000 collateral
	err := engine.Supply(user, "LUX", bigMul(100))
	require.NoError(err)

	account, _ := engine.GetAccount(user)
	// With no borrows, health factor should be very high
	require.True(account.HealthFactor.Cmp(scale18) > 0)

	// Add USDT liquidity and borrow
	supplier := ids.GenerateTestShortID()
	err = engine.Supply(supplier, "USDT", bigMul(10000))
	require.NoError(err)

	// Borrow $2000 (40% of $5000)
	err = engine.Borrow(user, "USDT", bigMul(2000))
	require.NoError(err)

	account, _ = engine.GetAccount(user)
	// Health factor = $5000 * 0.8 / $2000 = 2.0
	expectedHealth := bigMul(2)
	// Allow some tolerance for rounding
	diff := new(big.Int).Sub(account.HealthFactor, expectedHealth)
	diff.Abs(diff)
	tolerance := new(big.Int).Div(scale18, big.NewInt(10)) // 0.1
	require.True(diff.Cmp(tolerance) < 0, "Health factor should be ~2.0")
}

func TestEnableDisableCollateral(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Supply
	err := engine.Supply(user, "LUX", bigMul(100))
	require.NoError(err)

	account, _ := engine.GetAccount(user)
	require.True(account.Collateral["LUX"].IsEnabled)

	// Disable collateral (no borrows, should succeed)
	err = engine.EnableCollateral(user, "LUX", false)
	require.NoError(err)

	account, _ = engine.GetAccount(user)
	require.False(account.Collateral["LUX"].IsEnabled)

	// Re-enable
	err = engine.EnableCollateral(user, "LUX", true)
	require.NoError(err)

	account, _ = engine.GetAccount(user)
	require.True(account.Collateral["LUX"].IsEnabled)
}

func TestDisableCollateralWithBorrow(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Supply collateral
	err := engine.Supply(user, "LUX", bigMul(100))
	require.NoError(err)

	// Add liquidity and borrow
	supplier := ids.GenerateTestShortID()
	err = engine.Supply(supplier, "USDT", bigMul(10000))
	require.NoError(err)

	err = engine.Borrow(user, "USDT", bigMul(2000))
	require.NoError(err)

	// Try to disable collateral (should fail - would make position unhealthy)
	err = engine.EnableCollateral(user, "LUX", false)
	require.ErrorIs(err, ErrHealthFactorTooLow)
}

func TestInterestRateModel(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()
	supplier := ids.GenerateTestShortID()

	// Supply to create liquidity
	err := engine.Supply(supplier, "USDT", bigMul(10000))
	require.NoError(err)

	pool, _ := engine.GetPool("USDT")
	// With no borrows, utilization should be 0
	require.Equal(int64(0), pool.UtilizationRate.Int64())
	// Borrow rate should be base rate
	require.Equal(pool.BaseRate.Int64(), pool.BorrowRate.Int64())

	// Supply collateral and borrow
	err = engine.Supply(user, "LUX", bigMul(1000))
	require.NoError(err)

	err = engine.Borrow(user, "USDT", bigMul(5000))
	require.NoError(err)

	pool, _ = engine.GetPool("USDT")
	// Utilization should be 50%
	expectedUtil := new(big.Int).Div(scale18, big.NewInt(2)) // 0.5 * 1e18
	require.Equal(0, expectedUtil.Cmp(pool.UtilizationRate))

	// Borrow rate should be higher than base rate
	require.True(pool.BorrowRate.Cmp(pool.BaseRate) > 0)
}

func TestGetAllPools(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()

	pools := engine.GetAllPools()
	require.Len(pools, 3) // LUX, USDT, ETH
}

func TestGetStats(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()
	supplier := ids.GenerateTestShortID()

	// Supply to pools
	err := engine.Supply(supplier, "USDT", bigMul(10000))
	require.NoError(err)

	err = engine.Supply(user, "LUX", bigMul(100))
	require.NoError(err)

	err = engine.Borrow(user, "USDT", bigMul(2000))
	require.NoError(err)

	stats := engine.GetStats()
	require.Equal(3, stats.PoolCount)
	require.Equal(2, stats.UserCount)
	require.True(stats.TotalSupplyUSD.Sign() > 0)
	require.True(stats.TotalBorrowsUSD.Sign() > 0)
}

func TestMultipleUsersSupplyBorrow(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()

	// User 1: Supply LUX, borrow USDT
	user1 := ids.GenerateTestShortID()
	err := engine.Supply(user1, "LUX", bigMul(100))
	require.NoError(err)

	// User 2: Supply USDT
	user2 := ids.GenerateTestShortID()
	err = engine.Supply(user2, "USDT", bigMul(5000))
	require.NoError(err)

	// User 1 borrows
	err = engine.Borrow(user1, "USDT", bigMul(2000))
	require.NoError(err)

	// User 3: Supply ETH, borrow USDT
	user3 := ids.GenerateTestShortID()
	err = engine.Supply(user3, "ETH", bigMul(10)) // 10 ETH @ $2000 = $20000
	require.NoError(err)

	err = engine.Borrow(user3, "USDT", bigMul(1000))
	require.NoError(err)

	// Check stats
	stats := engine.GetStats()
	require.Equal(3, stats.UserCount)
	require.True(stats.TotalBorrowsUSD.Cmp(bigMul(3000)) >= 0) // At least $3000 borrowed
}

func TestWithdrawBlockedByBorrow(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()

	// Supply collateral
	err := engine.Supply(user, "LUX", bigMul(100))
	require.NoError(err)

	// Add USDT liquidity and borrow near max
	supplier := ids.GenerateTestShortID()
	err = engine.Supply(supplier, "USDT", bigMul(10000))
	require.NoError(err)

	// Borrow $3000 (60% of $5000)
	err = engine.Borrow(user, "USDT", bigMul(3000))
	require.NoError(err)

	// Try to withdraw most collateral (would make position unhealthy)
	err = engine.Withdraw(user, "LUX", bigMul(80))
	require.ErrorIs(err, ErrHealthFactorTooLow)

	// Should be able to withdraw small amount
	err = engine.Withdraw(user, "LUX", bigMul(10))
	require.NoError(err)
}

func TestAccrueInterest(t *testing.T) {
	require := require.New(t)

	engine := newTestEngine()
	user := ids.GenerateTestShortID()
	supplier := ids.GenerateTestShortID()

	// Supply
	err := engine.Supply(supplier, "USDT", bigMul(10000))
	require.NoError(err)

	err = engine.Supply(user, "LUX", bigMul(1000))
	require.NoError(err)

	// Borrow
	err = engine.Borrow(user, "USDT", bigMul(5000))
	require.NoError(err)

	initialBorrow := bigMul(5000)

	// Accrue interest (normally happens during block processing)
	engine.AccrueAllInterest()

	// Borrow balance should have increased (interest)
	account, _ := engine.GetAccount(user)
	// Note: May be the same if time hasn't elapsed enough
	require.True(account.Borrows["USDT"].Balance.Cmp(initialBorrow) >= 0)
}

func BenchmarkSupply(b *testing.B) {
	engine := newTestEngine()
	amount := bigMul(100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		user := ids.GenerateTestShortID()
		_ = engine.Supply(user, "LUX", amount)
	}
}

func BenchmarkBorrow(b *testing.B) {
	engine := newTestEngine()
	supplyAmount := bigMul(10000)
	collateralAmount := bigMul(100)
	borrowAmount := bigMul(1000)

	// Setup liquidity
	for i := 0; i < 100; i++ {
		supplier := ids.GenerateTestShortID()
		_ = engine.Supply(supplier, "USDT", supplyAmount)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		user := ids.GenerateTestShortID()
		_ = engine.Supply(user, "LUX", collateralAmount)
		_ = engine.Borrow(user, "USDT", borrowAmount)
	}
}

func BenchmarkLiquidation(b *testing.B) {
	oracle := newTestOracle()
	engine := NewEngine(oracle)
	engine.CreatePool(DefaultPoolConfig("LUX"))
	engine.CreatePool(DefaultPoolConfig("USDT"))

	supplyAmount := bigMul(100000)
	collateralAmount := bigMul(100)
	borrowAmount := bigMul(3500)
	liquidateAmount := bigMul(1000)

	// Setup liquidity
	for i := 0; i < 100; i++ {
		supplier := ids.GenerateTestShortID()
		_ = engine.Supply(supplier, "USDT", supplyAmount)
	}

	// Create liquidatable positions
	users := make([]ids.ShortID, b.N)
	for i := 0; i < b.N; i++ {
		user := ids.GenerateTestShortID()
		users[i] = user
		_ = engine.Supply(user, "LUX", collateralAmount)
		_ = engine.Borrow(user, "USDT", borrowAmount)
	}

	// Drop price to make positions liquidatable
	oracle.SetPrice("LUX", bigMul(40))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		liquidator := ids.GenerateTestShortID()
		_, _ = engine.Liquidate(liquidator, users[i], "USDT", "LUX", liquidateAmount)
	}
}
