// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package orderbook

import (
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func TestNewOrderbook(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")
	require.NotNil(ob)
	require.Equal("LUX/USDT", ob.Symbol())
	require.Equal(uint64(0), ob.GetBestBid())
	require.Equal(uint64(0), ob.GetBestAsk())
}

func TestAddLimitOrder(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	// Create a buy order
	order := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       ids.GenerateTestShortID(),
		Symbol:      "LUX/USDT",
		Side:        Buy,
		Type:        Limit,
		Price:       100000000000000000,  // 0.1 USDT
		Quantity:    1000000000000000000, // 1 LUX
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	trades, err := ob.AddOrder(order)
	require.NoError(err)
	require.Empty(trades)
	require.Equal(order.Price, ob.GetBestBid())

	// Verify order is in book
	fetchedOrder, err := ob.GetOrder(order.ID)
	require.NoError(err)
	require.Equal(order.ID, fetchedOrder.ID)
}

func TestAddSellOrder(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	// Create a sell order
	order := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       ids.GenerateTestShortID(),
		Symbol:      "LUX/USDT",
		Side:        Sell,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    1000000000000000000,
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	trades, err := ob.AddOrder(order)
	require.NoError(err)
	require.Empty(trades)
	require.Equal(order.Price, ob.GetBestAsk())
}

func TestOrderMatching(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	maker := ids.GenerateTestShortID()
	taker := ids.GenerateTestShortID()

	// Add sell order (maker)
	sellOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       maker,
		Symbol:      "LUX/USDT",
		Side:        Sell,
		Type:        Limit,
		Price:       100000000000000000,  // 0.1 USDT
		Quantity:    1000000000000000000, // 1 LUX
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	trades, err := ob.AddOrder(sellOrder)
	require.NoError(err)
	require.Empty(trades)

	// Add buy order (taker) that matches
	buyOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       taker,
		Symbol:      "LUX/USDT",
		Side:        Buy,
		Type:        Limit,
		Price:       100000000000000000,  // 0.1 USDT
		Quantity:    1000000000000000000, // 1 LUX
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	trades, err = ob.AddOrder(buyOrder)
	require.NoError(err)
	require.Len(trades, 1)

	trade := trades[0]
	require.Equal(sellOrder.ID, trade.MakerOrder)
	require.Equal(buyOrder.ID, trade.TakerOrder)
	require.Equal(sellOrder.Price, trade.Price)
	require.Equal(uint64(1000000000000000000), trade.Quantity)

	// Both orders should be filled
	require.Equal(StatusFilled, sellOrder.Status)
	require.Equal(StatusFilled, buyOrder.Status)
}

func TestPartialFill(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	maker := ids.GenerateTestShortID()
	taker := ids.GenerateTestShortID()

	// Add sell order for 2 LUX
	sellOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       maker,
		Symbol:      "LUX/USDT",
		Side:        Sell,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    2000000000000000000, // 2 LUX
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	trades, err := ob.AddOrder(sellOrder)
	require.NoError(err)
	require.Empty(trades)

	// Add buy order for 1 LUX
	buyOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       taker,
		Symbol:      "LUX/USDT",
		Side:        Buy,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    1000000000000000000, // 1 LUX
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	trades, err = ob.AddOrder(buyOrder)
	require.NoError(err)
	require.Len(trades, 1)

	// Sell order should be partially filled
	require.Equal(StatusPartiallyFilled, sellOrder.Status)
	require.Equal(uint64(1000000000000000000), sellOrder.FilledQty)
	require.Equal(uint64(1000000000000000000), sellOrder.RemainingQuantity())

	// Buy order should be filled
	require.Equal(StatusFilled, buyOrder.Status)
}

func TestCancelOrder(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	order := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       ids.GenerateTestShortID(),
		Symbol:      "LUX/USDT",
		Side:        Buy,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    1000000000000000000,
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	_, err := ob.AddOrder(order)
	require.NoError(err)

	// Cancel the order
	err = ob.CancelOrder(order.ID)
	require.NoError(err)
	require.Equal(StatusCancelled, order.Status)

	// Order should not be in book anymore
	_, err = ob.GetOrder(order.ID)
	require.Error(err)
}

func TestSelfTradePreventionm(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	user := ids.GenerateTestShortID()

	// Add sell order
	sellOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       user,
		Symbol:      "LUX/USDT",
		Side:        Sell,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    1000000000000000000,
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	_, err := ob.AddOrder(sellOrder)
	require.NoError(err)

	// Try to match with own order
	buyOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       user, // Same user
		Symbol:      "LUX/USDT",
		Side:        Buy,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    1000000000000000000,
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	trades, err := ob.AddOrder(buyOrder)
	require.NoError(err)
	require.Empty(trades) // No trades should occur

	// Both orders should still be in book
	require.Equal(StatusOpen, sellOrder.Status)
	require.Equal(StatusOpen, buyOrder.Status)
}

func TestIOCOrder(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	// Add IOC order with no matching orders
	iocOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       ids.GenerateTestShortID(),
		Symbol:      "LUX/USDT",
		Side:        Buy,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    1000000000000000000,
		TimeInForce: "IOC", // Immediate or Cancel
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	trades, err := ob.AddOrder(iocOrder)
	require.NoError(err)
	require.Empty(trades)

	// IOC order should not be in book
	_, err = ob.GetOrder(iocOrder.ID)
	require.Error(err)
}

func TestFOKOrder(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	maker := ids.GenerateTestShortID()
	taker := ids.GenerateTestShortID()

	// Add sell order for only 0.5 LUX
	sellOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       maker,
		Symbol:      "LUX/USDT",
		Side:        Sell,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    500000000000000000, // 0.5 LUX
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	_, err := ob.AddOrder(sellOrder)
	require.NoError(err)

	// Add FOK order for 1 LUX (can't be fully filled)
	fokOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       taker,
		Symbol:      "LUX/USDT",
		Side:        Buy,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    1000000000000000000, // 1 LUX
		TimeInForce: "FOK",               // Fill or Kill
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	_, err = ob.AddOrder(fokOrder)
	require.NoError(err)

	// FOK order should be cancelled if partially filled
	if fokOrder.FilledQty > 0 && fokOrder.RemainingQuantity() > 0 {
		require.Equal(StatusCancelled, fokOrder.Status)
	}
}

func TestGetDepth(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	// Add multiple buy orders at different prices
	prices := []uint64{95000000000000000, 96000000000000000, 97000000000000000, 98000000000000000, 99000000000000000}
	for _, price := range prices {
		order := &Order{
			ID:          ids.GenerateTestID(),
			Owner:       ids.GenerateTestShortID(),
			Symbol:      "LUX/USDT",
			Side:        Buy,
			Type:        Limit,
			Price:       price,
			Quantity:    1000000000000000000,
			TimeInForce: "GTC",
			CreatedAt:   time.Now().UnixNano(),
			Status:      StatusOpen,
		}
		_, err := ob.AddOrder(order)
		require.NoError(err)
	}

	// Add multiple sell orders
	sellPrices := []uint64{100000000000000000, 101000000000000000, 102000000000000000}
	for _, price := range sellPrices {
		order := &Order{
			ID:          ids.GenerateTestID(),
			Owner:       ids.GenerateTestShortID(),
			Symbol:      "LUX/USDT",
			Side:        Sell,
			Type:        Limit,
			Price:       price,
			Quantity:    1000000000000000000,
			TimeInForce: "GTC",
			CreatedAt:   time.Now().UnixNano(),
			Status:      StatusOpen,
		}
		_, err := ob.AddOrder(order)
		require.NoError(err)
	}

	// Get depth
	bids, asks := ob.GetDepth(3)
	require.Len(bids, 3)
	require.Len(asks, 3)

	// Bids should be sorted descending
	require.Equal(uint64(99000000000000000), bids[0].Price)
	require.Equal(uint64(98000000000000000), bids[1].Price)
	require.Equal(uint64(97000000000000000), bids[2].Price)

	// Asks should be sorted ascending
	require.Equal(uint64(100000000000000000), asks[0].Price)
	require.Equal(uint64(101000000000000000), asks[1].Price)
	require.Equal(uint64(102000000000000000), asks[2].Price)
}

func TestSpreadCalculation(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	// Add bid
	bidOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       ids.GenerateTestShortID(),
		Symbol:      "LUX/USDT",
		Side:        Buy,
		Type:        Limit,
		Price:       99000000000000000, // 0.099
		Quantity:    1000000000000000000,
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}
	_, err := ob.AddOrder(bidOrder)
	require.NoError(err)

	// Add ask
	askOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       ids.GenerateTestShortID(),
		Symbol:      "LUX/USDT",
		Side:        Sell,
		Type:        Limit,
		Price:       101000000000000000, // 0.101
		Quantity:    1000000000000000000,
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}
	_, err = ob.AddOrder(askOrder)
	require.NoError(err)

	// Check spread
	require.Equal(uint64(99000000000000000), ob.GetBestBid())
	require.Equal(uint64(101000000000000000), ob.GetBestAsk())
	require.Equal(uint64(2000000000000000), ob.GetSpread())
	require.Equal(uint64(100000000000000000), ob.GetMidPrice())
}

func TestMarketOrder(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	maker := ids.GenerateTestShortID()
	taker := ids.GenerateTestShortID()

	// Add sell order (maker)
	sellOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       maker,
		Symbol:      "LUX/USDT",
		Side:        Sell,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    1000000000000000000,
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	_, err := ob.AddOrder(sellOrder)
	require.NoError(err)

	// Add market buy order (taker) - no price, just matches best ask
	marketOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       taker,
		Symbol:      "LUX/USDT",
		Side:        Buy,
		Type:        Market,
		Price:       0, // No price for market order
		Quantity:    1000000000000000000,
		TimeInForce: "IOC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}

	trades, err := ob.AddOrder(marketOrder)
	require.NoError(err)
	require.Len(trades, 1)
	require.Equal(sellOrder.Price, trades[0].Price) // Executes at maker's price
}

func TestOrderStats(t *testing.T) {
	require := require.New(t)

	ob := New("LUX/USDT")

	maker := ids.GenerateTestShortID()
	taker := ids.GenerateTestShortID()

	// Add and match orders
	sellOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       maker,
		Symbol:      "LUX/USDT",
		Side:        Sell,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    1000000000000000000,
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}
	_, err := ob.AddOrder(sellOrder)
	require.NoError(err)

	buyOrder := &Order{
		ID:          ids.GenerateTestID(),
		Owner:       taker,
		Symbol:      "LUX/USDT",
		Side:        Buy,
		Type:        Limit,
		Price:       100000000000000000,
		Quantity:    1000000000000000000,
		TimeInForce: "GTC",
		CreatedAt:   time.Now().UnixNano(),
		Status:      StatusOpen,
	}
	_, err = ob.AddOrder(buyOrder)
	require.NoError(err)

	// Check stats
	totalVolume, tradeCount, lastTradeTime := ob.GetStats()
	require.Equal(uint64(1000000000000000000), totalVolume)
	require.Equal(uint64(1), tradeCount)
	require.Greater(lastTradeTime, int64(0))
}

func BenchmarkAddOrder(b *testing.B) {
	ob := New("LUX/USDT")

	orders := make([]*Order, b.N)
	for i := 0; i < b.N; i++ {
		orders[i] = &Order{
			ID:          ids.GenerateTestID(),
			Owner:       ids.GenerateTestShortID(),
			Symbol:      "LUX/USDT",
			Side:        Buy,
			Type:        Limit,
			Price:       uint64(100000000000000000 - i), // Different prices
			Quantity:    1000000000000000000,
			TimeInForce: "GTC",
			CreatedAt:   time.Now().UnixNano(),
			Status:      StatusOpen,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ob.AddOrder(orders[i])
	}
}

func BenchmarkOrderMatching(b *testing.B) {
	ob := New("LUX/USDT")

	// Pre-populate with sell orders
	for i := 0; i < 1000; i++ {
		order := &Order{
			ID:          ids.GenerateTestID(),
			Owner:       ids.GenerateTestShortID(),
			Symbol:      "LUX/USDT",
			Side:        Sell,
			Type:        Limit,
			Price:       uint64(100000000000000000 + i*1000),
			Quantity:    1000000000000000000,
			TimeInForce: "GTC",
			CreatedAt:   time.Now().UnixNano(),
			Status:      StatusOpen,
		}
		ob.AddOrder(order)
	}

	// Benchmark matching
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		order := &Order{
			ID:          ids.GenerateTestID(),
			Owner:       ids.GenerateTestShortID(),
			Symbol:      "LUX/USDT",
			Side:        Buy,
			Type:        Market,
			Quantity:    1000000000000000000,
			TimeInForce: "IOC",
			CreatedAt:   time.Now().UnixNano(),
			Status:      StatusOpen,
		}
		ob.AddOrder(order)
	}
}
