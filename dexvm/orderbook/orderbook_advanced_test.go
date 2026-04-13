// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package orderbook

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// Price scaling: 6 decimal places (1e6) - matches P/X chain
// Max uint64 = 18.4 × 10^18, so 18.4T units with 6 decimals
const priceScale = 1000000

func TestIcebergOrder(t *testing.T) {
	require := require.New(t)

	order := &Order{
		ID:       ids.GenerateTestID(),
		Owner:    ids.GenerateTestShortID(),
		Symbol:   "BTC-USD",
		Side:     Buy,
		Type:     Limit,
		Price:    50000 * priceScale, // $50,000
		Quantity: 1000,               // 1000 units total
	}

	// Create iceberg with 100 visible
	iceberg, err := NewIcebergOrder(order, 100)
	require.NoError(err)
	require.Equal(uint64(1000), iceberg.TotalSize)
	require.Equal(uint64(100), iceberg.DisplaySize)
	require.Equal(uint64(900), iceberg.RemainingHiddenSize)
	require.Equal(0, iceberg.RefillCount)

	// Visible quantity should be display size
	require.Equal(uint64(100), iceberg.VisibleQuantity())

	// Simulate partial fill - visible quantity remains at display size
	// because remaining (950) > display size (100)
	order.FilledQty = 50
	require.Equal(uint64(100), iceberg.VisibleQuantity())

	// Fill more - still returns display size since remaining (900) > display (100)
	order.FilledQty = 100
	require.True(iceberg.NeedsRefill())

	// Refill
	refilled := iceberg.Refill()
	require.Equal(uint64(100), refilled)
	require.Equal(uint64(800), iceberg.RemainingHiddenSize)
	require.Equal(1, iceberg.RefillCount)
}

func TestIcebergOrderValidation(t *testing.T) {
	require := require.New(t)

	order := &Order{
		ID:       ids.GenerateTestID(),
		Quantity: 100,
	}

	// Display size too large
	_, err := NewIcebergOrder(order, 200)
	require.ErrorIs(err, ErrIcebergDisplayTooLarge)

	// Display size zero
	_, err = NewIcebergOrder(order, 0)
	require.ErrorIs(err, ErrIcebergDisplayTooSmall)

	// Valid iceberg
	iceberg, err := NewIcebergOrder(order, 50)
	require.NoError(err)
	require.NotNil(iceberg)
}

func TestHiddenOrder(t *testing.T) {
	require := require.New(t)

	order := &Order{
		ID:       ids.GenerateTestID(),
		Owner:    ids.GenerateTestShortID(),
		Symbol:   "ETH-USD",
		Side:     Sell,
		Type:     Limit,
		Price:    3000 * priceScale,
		Quantity: 500,
	}

	hidden := NewHiddenOrder(order)
	require.True(hidden.IsHidden)
	require.Equal(order.ID, hidden.ID)
}

func TestPeggedOrder(t *testing.T) {
	require := require.New(t)

	order := &Order{
		ID:     ids.GenerateTestID(),
		Side:   Buy,
		Price:  0, // Will be set by peg
		Symbol: "BTC-USD",
	}

	// Create pegged order at midpoint
	pegged, err := NewPeggedOrder(order, "mid", 0)
	require.NoError(err)

	// Calculate price with bid=49000, ask=51000
	price := pegged.CalculatePegPrice(49000*priceScale, 51000*priceScale)
	require.Equal(uint64(50000*priceScale), price) // Midpoint

	// Create pegged order at primary with offset
	order2 := &Order{ID: ids.GenerateTestID(), Side: Buy}
	pegged2, err := NewPeggedOrder(order2, "primary", 100)
	require.NoError(err)

	price2 := pegged2.CalculatePegPrice(49000*priceScale, 51000*priceScale)
	require.Equal(uint64(49000*priceScale+100), price2) // Best bid + 100

	// Invalid peg type
	_, err = NewPeggedOrder(order, "invalid", 0)
	require.Error(err)
}

func TestTrailingStopOrder(t *testing.T) {
	require := require.New(t)

	order := &Order{
		ID:        ids.GenerateTestID(),
		Side:      Sell,
		StopPrice: 48000 * priceScale, // Initial stop
		Quantity:  100,
	}

	// Create trailing stop with $1000 trail
	trailAmount := uint64(1000 * priceScale)
	trailing, err := NewTrailingStopOrder(order, trailAmount, 0)
	require.NoError(err)

	// Initial high water mark
	require.Equal(order.StopPrice+trailAmount, trailing.HighWaterMark)

	// Price rises to 52000 - should update stop
	updated := trailing.UpdateTrailingPrice(52000 * priceScale)
	require.True(updated)
	require.Equal(uint64(52000*priceScale), trailing.HighWaterMark)
	require.Equal(uint64(51000*priceScale), trailing.StopPrice) // 52000 - 1000

	// Price drops but stays above stop - no update
	updated = trailing.UpdateTrailingPrice(51500 * priceScale)
	require.False(updated)
	require.Equal(uint64(52000*priceScale), trailing.HighWaterMark) // Unchanged

	// Check trigger - price drops to stop level
	require.True(trailing.ShouldTrigger(51000 * priceScale))

	// Already triggered
	trailing.Activated = true
	require.False(trailing.ShouldTrigger(50000 * priceScale))
}

func TestTrailingStopWithPercent(t *testing.T) {
	require := require.New(t)

	order := &Order{
		ID:        ids.GenerateTestID(),
		Side:      Sell,
		StopPrice: 50000 * priceScale,
		Quantity:  100,
	}

	// 2% trailing stop (200 basis points)
	trailing, err := NewTrailingStopOrder(order, 0, 200)
	require.NoError(err)

	// Update to 52000
	trailing.UpdateTrailingPrice(52000 * priceScale)

	// Stop should be 2% below high water mark
	// 52000 * 200 / 10000 = 1040
	expectedStop := uint64(52000*priceScale) - uint64(1040*priceScale)
	require.Equal(expectedStop, trailing.StopPrice)
}

func TestAdvancedOrderbook(t *testing.T) {
	require := require.New(t)

	aob := NewAdvancedOrderbook("BTC-USD", true, true)
	require.NotNil(aob)
	require.True(aob.allowHiddenOrders)
	require.True(aob.allowIceberg)
}

func TestAdvancedOrderbookIceberg(t *testing.T) {
	require := require.New(t)

	aob := NewAdvancedOrderbook("BTC-USD", true, true)

	order := &Order{
		ID:        ids.GenerateTestID(),
		Owner:     ids.GenerateTestShortID(),
		Symbol:    "BTC-USD",
		Side:      Buy,
		Type:      Limit,
		Price:     50000 * priceScale,
		Quantity:  1000,
		CreatedAt: time.Now().UnixNano(),
	}

	// Add iceberg order
	trades, err := aob.AddIcebergOrder(order, 100)
	require.NoError(err)
	require.Empty(trades) // No matching orders

	// Check iceberg stats
	count, totalHidden := aob.GetIcebergStats()
	require.Equal(1, count)
	require.Equal(uint64(900), totalHidden)
}

func TestAdvancedOrderbookHidden(t *testing.T) {
	require := require.New(t)

	aob := NewAdvancedOrderbook("ETH-USD", true, true)

	order := &Order{
		ID:        ids.GenerateTestID(),
		Owner:     ids.GenerateTestShortID(),
		Symbol:    "ETH-USD",
		Side:      Sell,
		Type:      Limit,
		Price:     3000 * priceScale,
		Quantity:  500,
		CreatedAt: time.Now().UnixNano(),
	}

	// Add hidden order
	trades, err := aob.AddHiddenOrder(order)
	require.NoError(err)
	require.Empty(trades)

	// Check hidden order count
	require.Equal(1, aob.GetHiddenOrderCount())

	// Hidden orders not allowed
	aob2 := NewAdvancedOrderbook("BTC-USD", false, true)
	_, err = aob2.AddHiddenOrder(order)
	require.ErrorIs(err, ErrHiddenOrderNotAllowed)
}

func TestAdvancedOrderbookTrailingStop(t *testing.T) {
	require := require.New(t)

	aob := NewAdvancedOrderbook("BTC-USD", true, true)

	order := &Order{
		ID:        ids.GenerateTestID(),
		Owner:     ids.GenerateTestShortID(),
		Symbol:    "BTC-USD",
		Side:      Sell,
		Type:      StopLoss,
		Price:     0,
		StopPrice: 48000 * priceScale,
		Quantity:  100,
		CreatedAt: time.Now().UnixNano(),
	}

	// Add trailing stop
	err := aob.AddTrailingStop(order, 1000*priceScale, 0)
	require.NoError(err)

	// Update price and check triggers
	triggered := aob.UpdateTrailingStops(52000 * priceScale)
	require.Empty(triggered) // Price went up, stop adjusted

	// Price drops but still above adjusted stop (51000)
	triggered = aob.UpdateTrailingStops(51500 * priceScale)
	require.Empty(triggered) // Still above new stop
}

func TestDepthWithHidden(t *testing.T) {
	require := require.New(t)

	aob := NewAdvancedOrderbook("BTC-USD", true, true)

	// Add regular order
	regularOrder := &Order{
		ID:        ids.GenerateTestID(),
		Owner:     ids.GenerateTestShortID(),
		Symbol:    "BTC-USD",
		Side:      Buy,
		Type:      Limit,
		Price:     50000 * priceScale,
		Quantity:  500,
		CreatedAt: time.Now().UnixNano(),
	}
	_, err := aob.AddOrder(regularOrder)
	require.NoError(err)

	// Add hidden order at same price
	hiddenOrder := &Order{
		ID:        ids.GenerateTestID(),
		Owner:     ids.GenerateTestShortID(),
		Symbol:    "BTC-USD",
		Side:      Buy,
		Type:      Limit,
		Price:     50000 * priceScale,
		Quantity:  300,
		CreatedAt: time.Now().UnixNano(),
	}
	_, err = aob.AddHiddenOrder(hiddenOrder)
	require.NoError(err)

	// Depth without hidden
	bids, asks := aob.GetDepthWithHidden(10, false)
	require.Len(bids, 1)
	require.Equal(uint64(500), bids[0].Quantity) // Only regular order
	require.Empty(asks)

	// Depth with hidden (includes all)
	bids, asks = aob.GetDepthWithHidden(10, true)
	require.Len(bids, 1)
	require.Equal(uint64(800), bids[0].Quantity) // 500 + 300
}

func BenchmarkIcebergOrder(b *testing.B) {
	order := &Order{
		ID:       ids.GenerateTestID(),
		Owner:    ids.GenerateTestShortID(),
		Symbol:   "BTC-USD",
		Side:     Buy,
		Type:     Limit,
		Price:    50000 * priceScale,
		Quantity: 10000,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		iceberg, _ := NewIcebergOrder(order, 100)
		for iceberg.RemainingHiddenSize > 0 {
			order.FilledQty = order.Quantity
			iceberg.Refill()
		}
	}
}

func BenchmarkTrailingStopUpdate(b *testing.B) {
	order := &Order{
		ID:        ids.GenerateTestID(),
		Side:      Sell,
		StopPrice: 48000 * priceScale,
		Quantity:  100,
	}
	trailing, _ := NewTrailingStopOrder(order, 1000*priceScale, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		trailing.UpdateTrailingPrice(uint64(52000+i) * priceScale)
	}
}
