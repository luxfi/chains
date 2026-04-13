// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package orderbook

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// Price scaling: 6 decimal places (1e6) - matches P/X chain
const stopPriceScale = 1000000

func TestNewStopOrder(t *testing.T) {
	require := require.New(t)

	order := &Order{
		ID:        ids.GenerateTestID(),
		Symbol:    "BTC-USD",
		Side:      Sell,
		StopPrice: 48000 * stopPriceScale,
		Quantity:  100,
	}

	// Valid stop order
	stopOrder, err := NewStopOrder(order, TriggerOnLastPrice, 0)
	require.NoError(err)
	require.NotNil(stopOrder)
	require.False(stopOrder.IsStopLimit())

	// Stop-limit order
	stopLimitOrder, err := NewStopOrder(order, TriggerOnMarkPrice, 47500*stopPriceScale)
	require.NoError(err)
	require.True(stopLimitOrder.IsStopLimit())
	require.Equal(uint64(47500*stopPriceScale), stopLimitOrder.LimitPrice)

	// Missing stop price
	badOrder := &Order{ID: ids.GenerateTestID(), StopPrice: 0}
	_, err = NewStopOrder(badOrder, TriggerOnLastPrice, 0)
	require.ErrorIs(err, ErrStopPriceRequired)
}

func TestStopOrderTrigger(t *testing.T) {
	require := require.New(t)

	// Sell stop - triggers when price falls below stop
	sellStop := &StopOrder{
		Order: &Order{
			ID:        ids.GenerateTestID(),
			Side:      Sell,
			StopPrice: 48000 * stopPriceScale,
		},
	}

	require.False(sellStop.ShouldTrigger(50000 * stopPriceScale)) // Above stop
	require.False(sellStop.ShouldTrigger(49000 * stopPriceScale)) // Still above
	require.True(sellStop.ShouldTrigger(48000 * stopPriceScale))  // At stop
	require.True(sellStop.ShouldTrigger(47000 * stopPriceScale))  // Below stop

	// Already triggered
	sellStop.Triggered = true
	require.False(sellStop.ShouldTrigger(46000 * stopPriceScale))

	// Buy stop - triggers when price rises above stop
	buyStop := &StopOrder{
		Order: &Order{
			ID:        ids.GenerateTestID(),
			Side:      Buy,
			StopPrice: 52000 * stopPriceScale,
		},
	}

	require.False(buyStop.ShouldTrigger(50000 * stopPriceScale)) // Below stop
	require.True(buyStop.ShouldTrigger(52000 * stopPriceScale))  // At stop
	require.True(buyStop.ShouldTrigger(53000 * stopPriceScale))  // Above stop
}

func TestStopEngine(t *testing.T) {
	require := require.New(t)

	engine := NewStopEngine()
	require.NotNil(engine)

	order := &Order{
		ID:        ids.GenerateTestID(),
		Symbol:    "BTC-USD",
		Side:      Sell,
		StopPrice: 48000 * stopPriceScale,
		Quantity:  100,
	}

	// Add stop order
	err := engine.AddStopOrder(order, TriggerOnLastPrice, 0)
	require.NoError(err)

	// Verify stats
	total, pending, triggered := engine.GetStats()
	require.Equal(1, total)
	require.Equal(1, pending)
	require.Equal(0, triggered)

	// Get the stop order
	stopOrder, err := engine.GetStopOrder(order.ID)
	require.NoError(err)
	require.Equal(order.ID, stopOrder.ID)
}

func TestStopEngineUpdatePrice(t *testing.T) {
	require := require.New(t)

	engine := NewStopEngine()

	// Add sell stop
	sellOrder := &Order{
		ID:        ids.GenerateTestID(),
		Symbol:    "BTC-USD",
		Side:      Sell,
		StopPrice: 48000 * stopPriceScale,
		Quantity:  100,
	}
	err := engine.AddStopOrder(sellOrder, TriggerOnLastPrice, 0)
	require.NoError(err)

	// Add buy stop
	buyOrder := &Order{
		ID:        ids.GenerateTestID(),
		Symbol:    "BTC-USD",
		Side:      Buy,
		StopPrice: 52000 * stopPriceScale,
		Quantity:  50,
	}
	err = engine.AddStopOrder(buyOrder, TriggerOnLastPrice, 0)
	require.NoError(err)

	// Price at 50000 - neither should trigger
	triggered := engine.UpdatePrice("BTC-USD", 50000*stopPriceScale, 0, 0)
	require.Empty(triggered)

	// Price drops to 47000 - sell stop should trigger
	triggered = engine.UpdatePrice("BTC-USD", 47000*stopPriceScale, 0, 0)
	require.Len(triggered, 1)
	require.Equal(sellOrder.ID, triggered[0].ID)

	// Verify stats
	total, pending, triggeredCount := engine.GetStats()
	require.Equal(2, total)
	require.Equal(1, pending)
	require.Equal(1, triggeredCount)

	// Price rises to 53000 - buy stop should trigger
	triggered = engine.UpdatePrice("BTC-USD", 53000*stopPriceScale, 0, 0)
	require.Len(triggered, 1)
	require.Equal(buyOrder.ID, triggered[0].ID)
}

func TestStopEngineMultipleTriggerTypes(t *testing.T) {
	require := require.New(t)

	engine := NewStopEngine()

	// Last price trigger
	order1 := &Order{
		ID:        ids.GenerateTestID(),
		Symbol:    "ETH-USD",
		Side:      Sell,
		StopPrice: 2800 * stopPriceScale,
		Quantity:  10,
	}
	err := engine.AddStopOrder(order1, TriggerOnLastPrice, 0)
	require.NoError(err)

	// Mark price trigger
	order2 := &Order{
		ID:        ids.GenerateTestID(),
		Symbol:    "ETH-USD",
		Side:      Sell,
		StopPrice: 2850 * stopPriceScale,
		Quantity:  10,
	}
	err = engine.AddStopOrder(order2, TriggerOnMarkPrice, 0)
	require.NoError(err)

	// Index price trigger
	order3 := &Order{
		ID:        ids.GenerateTestID(),
		Symbol:    "ETH-USD",
		Side:      Sell,
		StopPrice: 2900 * stopPriceScale,
		Quantity:  10,
	}
	err = engine.AddStopOrder(order3, TriggerOnIndexPrice, 0)
	require.NoError(err)

	// Last=2750, Mark=2900, Index=3000
	// Should only trigger order1 (last price)
	triggered := engine.UpdatePrice("ETH-USD",
		2750*stopPriceScale, // last
		2900*stopPriceScale, // mark
		3000*stopPriceScale, // index
	)
	require.Len(triggered, 1)
	require.Equal(order1.ID, triggered[0].ID)

	// Last=2900, Mark=2800, Index=2880
	// Should trigger order2 (mark price at 2850) and order3 (index price at 2900)
	// Mark=2800 <= 2850 (order2 triggers)
	// Index=2880 <= 2900 (order3 triggers)
	triggered = engine.UpdatePrice("ETH-USD",
		2900*stopPriceScale,
		2800*stopPriceScale,
		2880*stopPriceScale,
	)
	require.Len(triggered, 2)
}

func TestStopEngineRemove(t *testing.T) {
	require := require.New(t)

	engine := NewStopEngine()

	order := &Order{
		ID:        ids.GenerateTestID(),
		Symbol:    "BTC-USD",
		Side:      Sell,
		StopPrice: 48000 * stopPriceScale,
		Quantity:  100,
	}

	err := engine.AddStopOrder(order, TriggerOnLastPrice, 0)
	require.NoError(err)

	// Remove the stop
	err = engine.RemoveStopOrder(order.ID)
	require.NoError(err)

	// Should not find it
	_, err = engine.GetStopOrder(order.ID)
	require.ErrorIs(err, ErrStopOrderNotFound)

	// Remove non-existent
	err = engine.RemoveStopOrder(ids.GenerateTestID())
	require.ErrorIs(err, ErrStopOrderNotFound)
}

func TestStopEngineCallback(t *testing.T) {
	require := require.New(t)

	engine := NewStopEngine()

	var triggeredOrders []*StopOrder
	engine.SetTriggerCallback(func(order *StopOrder) {
		triggeredOrders = append(triggeredOrders, order)
	})

	order := &Order{
		ID:        ids.GenerateTestID(),
		Symbol:    "BTC-USD",
		Side:      Sell,
		StopPrice: 48000 * stopPriceScale,
		Quantity:  100,
	}

	err := engine.AddStopOrder(order, TriggerOnLastPrice, 0)
	require.NoError(err)

	// Trigger
	engine.UpdatePrice("BTC-USD", 47000*stopPriceScale, 0, 0)

	require.Len(triggeredOrders, 1)
	require.Equal(order.ID, triggeredOrders[0].ID)
}

func TestStopEngineGetStopsBySymbol(t *testing.T) {
	require := require.New(t)

	engine := NewStopEngine()

	// Add orders for BTC
	for i := 0; i < 3; i++ {
		order := &Order{
			ID:        ids.GenerateTestID(),
			Symbol:    "BTC-USD",
			Side:      Sell,
			StopPrice: uint64((48000 + i*100) * 1e18),
			Quantity:  100,
		}
		err := engine.AddStopOrder(order, TriggerOnLastPrice, 0)
		require.NoError(err)
	}

	// Add orders for ETH
	for i := 0; i < 2; i++ {
		order := &Order{
			ID:        ids.GenerateTestID(),
			Symbol:    "ETH-USD",
			Side:      Sell,
			StopPrice: uint64((2800 + i*50) * 1e18),
			Quantity:  50,
		}
		err := engine.AddStopOrder(order, TriggerOnLastPrice, 0)
		require.NoError(err)
	}

	btcStops := engine.GetStopsBySymbol("BTC-USD")
	require.Len(btcStops, 3)

	ethStops := engine.GetStopsBySymbol("ETH-USD")
	require.Len(ethStops, 2)

	solStops := engine.GetStopsBySymbol("SOL-USD")
	require.Empty(solStops)
}

func TestStopEngineClearTriggered(t *testing.T) {
	require := require.New(t)

	engine := NewStopEngine()

	// Add multiple stops
	for i := 0; i < 5; i++ {
		order := &Order{
			ID:        ids.GenerateTestID(),
			Symbol:    "BTC-USD",
			Side:      Sell,
			StopPrice: uint64((48000 + i*100) * stopPriceScale),
			Quantity:  100,
		}
		engine.AddStopOrder(order, TriggerOnLastPrice, 0)
	}

	// Trigger some - price at 48250 triggers stops at 48300 and 48400
	// (sell stops trigger when price <= stop price)
	engine.UpdatePrice("BTC-USD", 48250*stopPriceScale, 0, 0)

	total, pending, triggered := engine.GetStats()
	require.Equal(5, total)
	require.Equal(3, pending)
	require.Equal(2, triggered)

	// Clear triggered
	cleared := engine.ClearTriggered()
	require.Equal(2, cleared)

	total, pending, triggered = engine.GetStats()
	require.Equal(3, total)
	require.Equal(3, pending)
	require.Equal(0, triggered)
}

func TestOCOEngine(t *testing.T) {
	require := require.New(t)

	cancelledOrders := make(map[ids.ID]bool)
	cancelCallback := func(orderID ids.ID) error {
		cancelledOrders[orderID] = true
		return nil
	}

	engine := NewOCOEngine(cancelCallback)
	require.NotNil(engine)

	primaryID := ids.GenerateTestID()
	secondaryID := ids.GenerateTestID()
	owner := ids.GenerateTestShortID()

	// Create OCO
	oco, err := engine.CreateOCO(primaryID, secondaryID, "BTC-USD", owner)
	require.NoError(err)
	require.NotNil(oco)
	require.Equal("active", oco.Status)

	// Get OCO by order
	foundOCO := engine.GetOCOByOrder(primaryID)
	require.NotNil(foundOCO)
	require.Equal(oco.ID, foundOCO.ID)

	foundOCO = engine.GetOCOByOrder(secondaryID)
	require.NotNil(foundOCO)
	require.Equal(oco.ID, foundOCO.ID)

	// Primary order filled - should cancel secondary
	err = engine.OnOrderFilled(primaryID)
	require.NoError(err)
	require.True(cancelledOrders[secondaryID])
	require.Equal("triggered", oco.Status)
}

func TestOCOEngineCancel(t *testing.T) {
	require := require.New(t)

	cancelledOrders := make(map[ids.ID]bool)
	cancelCallback := func(orderID ids.ID) error {
		cancelledOrders[orderID] = true
		return nil
	}

	engine := NewOCOEngine(cancelCallback)

	primaryID := ids.GenerateTestID()
	secondaryID := ids.GenerateTestID()
	owner := ids.GenerateTestShortID()

	oco, err := engine.CreateOCO(primaryID, secondaryID, "BTC-USD", owner)
	require.NoError(err)

	// Cancel OCO - should cancel both
	err = engine.CancelOCO(oco.ID)
	require.NoError(err)
	require.True(cancelledOrders[primaryID])
	require.True(cancelledOrders[secondaryID])
	require.Equal("cancelled", oco.Status)
}

func TestGetNextTriggerPrice(t *testing.T) {
	require := require.New(t)

	engine := NewStopEngine()

	// Add buy stop at 52000
	buyOrder := &Order{
		ID:        ids.GenerateTestID(),
		Symbol:    "BTC-USD",
		Side:      Buy,
		StopPrice: 52000 * stopPriceScale,
		Quantity:  100,
	}
	engine.AddStopOrder(buyOrder, TriggerOnLastPrice, 0)

	// Add sell stop at 48000
	sellOrder := &Order{
		ID:        ids.GenerateTestID(),
		Symbol:    "BTC-USD",
		Side:      Sell,
		StopPrice: 48000 * stopPriceScale,
		Quantity:  100,
	}
	engine.AddStopOrder(sellOrder, TriggerOnLastPrice, 0)

	// Current price at 50000
	// Next buy trigger would be at 52000
	// Next sell trigger would be at 48000
	price, side, exists := engine.GetNextTriggerPrice("BTC-USD", 50000*stopPriceScale)
	require.True(exists)
	// Returns the first one found (buy stop at 52000)
	require.Equal(uint64(52000*stopPriceScale), price)
	require.Equal(Buy, side)
}

func BenchmarkStopEngineAdd(b *testing.B) {
	engine := NewStopEngine()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		order := &Order{
			ID:        ids.ID{byte(i), byte(i >> 8), byte(i >> 16)},
			Symbol:    "BTC-USD",
			Side:      Sell,
			StopPrice: uint64(48000+i) * stopPriceScale,
			Quantity:  100,
		}
		engine.AddStopOrder(order, TriggerOnLastPrice, 0)
	}
}

func BenchmarkStopEngineTriggerCheck(b *testing.B) {
	engine := NewStopEngine()

	// Add 1000 stops
	for i := 0; i < 1000; i++ {
		order := &Order{
			ID:        ids.ID{byte(i), byte(i >> 8), byte(i >> 16)},
			Symbol:    "BTC-USD",
			Side:      Sell,
			StopPrice: uint64(45000+i) * stopPriceScale,
			Quantity:  100,
		}
		engine.AddStopOrder(order, TriggerOnLastPrice, 0)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.CheckStops("BTC-USD", 50000*stopPriceScale)
	}
}
