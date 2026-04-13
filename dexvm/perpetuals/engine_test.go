// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package perpetuals

import (
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func TestNewEngine(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()
	require.NotNil(engine)
	require.NotNil(engine.markets)
	require.NotNil(engine.accounts)
	require.NotNil(engine.positions)
}

func TestCreateMarket(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10) // $50,000

	market, err := engine.CreateMarket(
		"BTC-PERP",
		baseAsset,
		quoteAsset,
		initialPrice,
		100,                   // 100x max leverage
		big.NewInt(100000),    // 0.0001 BTC min size
		big.NewInt(100000000), // 0.0001 BTC tick size
		2,                     // 0.02% maker fee
		5,                     // 0.05% taker fee
		50,                    // 0.5% maintenance margin
		100,                   // 1% initial margin
	)
	require.NoError(err)
	require.NotNil(market)
	require.Equal("BTC-PERP", market.Symbol)
	require.Equal(uint16(100), market.MaxLeverage)
	require.Equal(initialPrice.Int64(), market.MarkPrice.Int64())
}

func TestCreateMarketDuplicate(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice := big.NewInt(50000)

	_, err := engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)
	require.NoError(err)

	// Try to create duplicate
	_, err = engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)
	require.Error(err)
	require.Equal(ErrMarketExists, err)
}

func TestCreateAccountAndDeposit(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	traderID := ids.GenerateTestID()
	account := engine.CreateAccount(traderID)
	require.NotNil(account)
	require.Equal(traderID, account.TraderID)
	require.Equal(int64(0), account.Balance.Int64())

	// Deposit
	depositAmount, _ := new(big.Int).SetString("10000000000000000000000", 10) // $10,000
	err := engine.Deposit(traderID, depositAmount)
	require.NoError(err)

	var accountIface interface{}
	accountIface, err = engine.GetAccount(traderID)
	require.NoError(err)
	account = accountIface.(*MarginAccount)
	require.Equal(depositAmount.Int64(), account.Balance.Int64())
	require.Equal(depositAmount.Int64(), account.AvailableBalance.Int64())
}

func TestWithdraw(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)

	depositAmount, _ := new(big.Int).SetString("10000000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	// Withdraw half
	withdrawAmount, _ := new(big.Int).SetString("5000000000000000000000", 10)
	err := engine.Withdraw(traderID, withdrawAmount)
	require.NoError(err)

	accountIface, _ := engine.GetAccount(traderID)
	account := accountIface.(*MarginAccount)
	expected, _ := new(big.Int).SetString("5000000000000000000000", 10)
	require.Equal(expected.Int64(), account.Balance.Int64())

	// Try to withdraw more than available
	err = engine.Withdraw(traderID, depositAmount)
	require.Error(err)
	require.Equal(ErrInsufficientBalance, err)
}

func TestOpenLongPosition(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	// Create market
	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10) // $50,000

	_, err := engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)
	require.NoError(err)

	// Create account and deposit
	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("100000000000000000000000", 10) // $100,000
	engine.Deposit(traderID, depositAmount)

	// Open 1 BTC long with 10x leverage
	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10) // 1 BTC

	position, err := engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)
	require.NoError(err)
	require.NotNil(position)
	require.Equal(Long, position.Side)
	require.Equal(uint16(10), position.Leverage)
	require.Equal("BTC-PERP", position.Market)

	// Check account
	accountIface, _ := engine.GetAccount(traderID)
	account := accountIface.(*MarginAccount)
	require.True(account.LockedMargin.Sign() > 0)
	require.True(account.AvailableBalance.Cmp(depositAmount) < 0)
}

func TestOpenShortPosition(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	// Create market
	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	_, err := engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)
	require.NoError(err)

	// Create account and deposit
	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("100000000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	// Open short position
	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)

	position, err := engine.OpenPosition(traderID, "BTC-PERP", Short, positionSize, 10, CrossMargin)
	require.NoError(err)
	require.NotNil(position)
	require.Equal(Short, position.Side)
}

func TestClosePosition(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	// Setup market
	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	// Setup trader
	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("100000000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	// Open position
	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)
	engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)

	// Close position
	pnl, err := engine.ClosePosition(traderID, "BTC-PERP")
	require.NoError(err)
	require.NotNil(pnl)

	// Verify position is closed
	_, err = engine.GetPosition(traderID, "BTC-PERP")
	require.Error(err)
	require.Equal(ErrPositionNotFound, err)

	// Verify margin is unlocked
	accountIface, _ := engine.GetAccount(traderID)
	account := accountIface.(*MarginAccount)
	require.Equal(int64(0), account.LockedMargin.Int64())
}

func TestPositionPnLCalculation(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	// Setup market at $50,000
	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	// Setup trader
	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("100000000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	// Open 1 BTC long at $50,000
	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)
	engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)

	// Price goes up to $55,000 (10% increase)
	newPrice, _ := new(big.Int).SetString("55000000000000000000000", 10)
	err := engine.UpdateMarkPrice("BTC-PERP", newPrice)
	require.NoError(err)

	// Check P&L
	posIface, err := engine.GetPosition(traderID, "BTC-PERP")
	require.NoError(err)
	position := posIface.(*Position)

	// Expected P&L: (55000 - 50000) * 1 = $5000
	expectedPnL, _ := new(big.Int).SetString("5000000000000000000000", 10)
	require.Equal(expectedPnL.Int64(), position.UnrealizedPnL.Int64())
}

func TestLiquidation(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	// Setup market with 50% maintenance margin
	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 10, big.NewInt(100000), big.NewInt(100000000), 2, 5, 500, 1000)

	// Setup trader with just enough for 10x position
	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("10000000000000000000000", 10) // $10,000
	engine.Deposit(traderID, depositAmount)

	// Open 1 BTC long with 10x leverage (notional = $50,000, margin = $5,000)
	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)
	position, err := engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)
	require.NoError(err)

	// Store liquidation price
	liquidationPrice := new(big.Int).Set(position.LiquidationPrice)

	// Drop price below liquidation price
	dropAmount, _ := new(big.Int).SetString("1000000000000000000000", 10)
	belowLiquidation := new(big.Int).Sub(liquidationPrice, dropAmount)
	err = engine.UpdateMarkPrice("BTC-PERP", belowLiquidation)
	require.NoError(err)

	// Check for liquidations
	liquidations, err := engine.CheckAndLiquidate("BTC-PERP")
	require.NoError(err)
	require.Len(liquidations, 1)
	require.Equal(position.ID, liquidations[0].Position.ID)

	// Verify position is closed
	_, err = engine.GetPosition(traderID, "BTC-PERP")
	require.Error(err)
}

func TestFundingPayments(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	// Setup market
	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	market, _ := engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	// Setup two traders - one long, one short
	longTrader := ids.GenerateTestID()
	shortTrader := ids.GenerateTestID()
	depositAmount, _ := new(big.Int).SetString("100000000000000000000000", 10)

	engine.CreateAccount(longTrader)
	engine.CreateAccount(shortTrader)
	engine.Deposit(longTrader, depositAmount)
	engine.Deposit(shortTrader, depositAmount)

	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)
	engine.OpenPosition(longTrader, "BTC-PERP", Long, positionSize, 10, CrossMargin)
	engine.OpenPosition(shortTrader, "BTC-PERP", Short, positionSize, 10, CrossMargin)

	// Set mark price higher than index to create positive funding rate
	// We need to set them separately since UpdateMarkPrice sets both to same value
	engine.mu.Lock()
	higherPrice, _ := new(big.Int).SetString("51000000000000000000000", 10)
	market.MarkPrice = higherPrice
	// Keep index price at initial (lower) to create funding rate difference
	market.NextFundingTime = time.Now().Add(-1 * time.Second)
	engine.mu.Unlock()

	// Process funding
	payments, err := engine.ProcessFunding("BTC-PERP")
	require.NoError(err)
	require.Len(payments, 2)

	// Long pays (negative amount), short receives (positive amount)
	var longPayment, shortPayment *FundingPayment
	for _, p := range payments {
		if p.Trader == longTrader {
			longPayment = p
		} else {
			shortPayment = p
		}
	}

	require.NotNil(longPayment)
	require.NotNil(shortPayment)
	require.True(longPayment.Amount.Sign() < 0)  // Long pays
	require.True(shortPayment.Amount.Sign() > 0) // Short receives
}

func TestMaxLeverageExceeded(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	// Create market with 10x max leverage
	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 10, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("100000000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)

	// Try to open with 20x leverage (exceeds 10x max)
	_, err := engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 20, CrossMargin)
	require.Error(err)
	require.Equal(ErrExceedsMaxLeverage, err)
}

func TestInsufficientMargin(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	// Only deposit $100 (not enough for a $50,000 position even at 100x)
	depositAmount, _ := new(big.Int).SetString("100000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)

	_, err := engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 1, CrossMargin)
	require.Error(err)
	require.Equal(ErrInsufficientMargin, err)
}

func TestPositionSizeTooSmall(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	// Min size is 100000 (0.0001 BTC)
	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("100000000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	// Try to open position below min size
	_, err := engine.OpenPosition(traderID, "BTC-PERP", Long, big.NewInt(10), 10, CrossMargin)
	require.Error(err)
	require.Equal(ErrOrderSizeTooSmall, err)
}

func TestIncreaseExistingPosition(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("100000000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)

	// Open initial position
	position1, err := engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)
	require.NoError(err)

	// Increase position
	position2, err := engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)
	require.NoError(err)

	// Should be same position ID with increased size
	require.Equal(position1.ID, position2.ID)
	doubleSize, _ := new(big.Int).SetString("2000000000000000000", 10)
	require.Equal(doubleSize.Int64(), position2.Size.Int64())
}

func TestReducePosition(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("200000000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	// Open 2 BTC long
	positionSize, _ := new(big.Int).SetString("2000000000000000000", 10)
	_, err := engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)
	require.NoError(err)

	// Reduce by opening 1 BTC short
	reduceSize, _ := new(big.Int).SetString("1000000000000000000", 10)
	position, err := engine.OpenPosition(traderID, "BTC-PERP", Short, reduceSize, 10, CrossMargin)
	require.NoError(err)

	// Position should be 1 BTC long now
	require.Equal(Long, position.Side)
	require.Equal(reduceSize.Int64(), position.Size.Int64())
}

func TestFlipPosition(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("200000000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	// Open 1 BTC long
	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)
	_, err := engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)
	require.NoError(err)

	// Flip by opening 2 BTC short
	flipSize, _ := new(big.Int).SetString("2000000000000000000", 10)
	position, err := engine.OpenPosition(traderID, "BTC-PERP", Short, flipSize, 10, CrossMargin)
	require.NoError(err)

	// Position should be 1 BTC short now
	require.Equal(Short, position.Side)
	require.Equal(positionSize.Int64(), position.Size.Int64())
}

func TestMarginRatio(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	initialPrice, _ := new(big.Int).SetString("50000000000000000000000", 10)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, initialPrice, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("100000000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	// Open position
	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)
	engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)

	marginRatio, err := engine.GetMarginRatio(traderID)
	require.NoError(err)
	require.NotNil(marginRatio)
	require.True(marginRatio.Sign() > 0)
}

func TestInsuranceFund(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	// Add to insurance fund
	addAmount, _ := new(big.Int).SetString("1000000000000000000000", 10)
	engine.AddToInsuranceFund(addAmount)

	fund := engine.GetInsuranceFund()
	require.Equal(addAmount.Int64(), fund.Int64())
}

func TestGetAllMarkets(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	price := big.NewInt(50000)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, price, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)
	engine.CreateMarket("ETH-PERP", baseAsset, quoteAsset, price, 50, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	markets := engine.GetAllMarkets()
	require.Len(markets, 2)
}

func TestGetAllPositions(t *testing.T) {
	require := require.New(t)

	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	price, _ := new(big.Int).SetString("50000000000000000000000", 10)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, price, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)
	engine.CreateMarket("ETH-PERP", baseAsset, quoteAsset, price, 50, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	traderID := ids.GenerateTestID()
	engine.CreateAccount(traderID)
	depositAmount, _ := new(big.Int).SetString("200000000000000000000000", 10)
	engine.Deposit(traderID, depositAmount)

	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)
	engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)
	engine.OpenPosition(traderID, "ETH-PERP", Short, positionSize, 10, CrossMargin)

	positions, err := engine.GetAllPositions(traderID)
	require.NoError(err)
	require.Len(positions, 2)
}

func TestSideString(t *testing.T) {
	require := require.New(t)

	require.Equal("long", Long.String())
	require.Equal("short", Short.String())
	require.Equal("short", Long.Opposite().String())
	require.Equal("long", Short.Opposite().String())
}

func TestMarginModeString(t *testing.T) {
	require := require.New(t)

	require.Equal("cross", CrossMargin.String())
	require.Equal("isolated", IsolatedMargin.String())
}

func BenchmarkOpenPosition(b *testing.B) {
	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	price, _ := new(big.Int).SetString("50000000000000000000000", 10)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, price, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)
	depositAmount, _ := new(big.Int).SetString("100000000000000000000000000", 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		traderID := ids.GenerateTestID()
		engine.CreateAccount(traderID)
		engine.Deposit(traderID, depositAmount)
		engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)
	}
}

func BenchmarkCheckLiquidation(b *testing.B) {
	engine := NewEngine()

	baseAsset := ids.GenerateTestID()
	quoteAsset := ids.GenerateTestID()
	price, _ := new(big.Int).SetString("50000000000000000000000", 10)

	engine.CreateMarket("BTC-PERP", baseAsset, quoteAsset, price, 100, big.NewInt(100000), big.NewInt(100000000), 2, 5, 50, 100)

	positionSize, _ := new(big.Int).SetString("1000000000000000000", 10)
	depositAmount, _ := new(big.Int).SetString("100000000000000000000000", 10)

	// Create 100 positions
	for i := 0; i < 100; i++ {
		traderID := ids.GenerateTestID()
		engine.CreateAccount(traderID)
		engine.Deposit(traderID, depositAmount)
		engine.OpenPosition(traderID, "BTC-PERP", Long, positionSize, 10, CrossMargin)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.CheckAndLiquidate("BTC-PERP")
	}
}
