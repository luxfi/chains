// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package perpetuals

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

func TestValidateTPSL(t *testing.T) {
	require := require.New(t)

	entryPrice := notional(50000) // $50,000

	// Valid long TP/SL
	tpLong := notional(55000) // TP above entry
	slLong := notional(48000) // SL below entry
	err := ValidateTPSL(Long, entryPrice, tpLong, slLong)
	require.NoError(err)

	// Invalid long TP (below entry)
	invalidTPLong := notional(45000)
	err = ValidateTPSL(Long, entryPrice, invalidTPLong, nil)
	require.ErrorIs(err, ErrTPBelowEntry)

	// Invalid long SL (above entry)
	invalidSLLong := notional(52000)
	err = ValidateTPSL(Long, entryPrice, nil, invalidSLLong)
	require.ErrorIs(err, ErrSLAboveEntry)

	// Valid short TP/SL
	tpShort := notional(45000) // TP below entry
	slShort := notional(52000) // SL above entry
	err = ValidateTPSL(Short, entryPrice, tpShort, slShort)
	require.NoError(err)

	// Invalid short TP (above entry)
	invalidTPShort := notional(55000)
	err = ValidateTPSL(Short, entryPrice, invalidTPShort, nil)
	require.ErrorIs(err, ErrTPBelowEntry)
}

func TestCalculateTPPrice(t *testing.T) {
	require := require.New(t)

	entryPrice := notional(50000) // $50,000

	// Long +10% TP
	tpLong := CalculateTPPrice(Long, entryPrice, 1000) // 10% = 1000 basis points
	expected := notional(55000)                        // $55,000
	require.Equal(expected, tpLong)

	// Short +10% TP (below entry)
	tpShort := CalculateTPPrice(Short, entryPrice, 1000)
	expectedShort := notional(45000) // $45,000
	require.Equal(expectedShort, tpShort)

	// 300% TP (for the Aster DEX example)
	tpLong300 := CalculateTPPrice(Long, entryPrice, 30000) // 300%
	require.Equal(notional(200000), tpLong300)             // $50K + 300% = $200K
}

func TestCalculateSLPrice(t *testing.T) {
	require := require.New(t)

	entryPrice := notional(50000) // $50,000

	// Long -10% SL
	slLong := CalculateSLPrice(Long, entryPrice, 1000)
	expected := notional(45000) // $45,000
	require.Equal(expected, slLong)

	// Short +10% SL (above entry)
	slShort := CalculateSLPrice(Short, entryPrice, 1000)
	expectedShort := notional(55000)
	require.Equal(expectedShort, slShort)
}

func TestCalculateTPPercent(t *testing.T) {
	require := require.New(t)

	entryPrice := notional(50000)
	tpPrice := notional(55000) // 10% above

	percent := CalculateTPPercent(Long, entryPrice, tpPrice)
	require.Equal(uint16(1000), percent) // 10% = 1000 bp

	// Short
	tpPriceShort := notional(45000) // 10% below
	percentShort := CalculateTPPercent(Short, entryPrice, tpPriceShort)
	require.Equal(uint16(1000), percentShort)
}

func TestShouldTriggerTP(t *testing.T) {
	require := require.New(t)

	tpPrice := notional(55000)

	// Long: triggers when price >= TP
	require.True(ShouldTriggerTP(Long, notional(55000), tpPrice))
	require.True(ShouldTriggerTP(Long, notional(60000), tpPrice))
	require.False(ShouldTriggerTP(Long, notional(54000), tpPrice))

	// Short: triggers when price <= TP
	tpPriceShort := notional(45000)
	require.True(ShouldTriggerTP(Short, notional(45000), tpPriceShort))
	require.True(ShouldTriggerTP(Short, notional(40000), tpPriceShort))
	require.False(ShouldTriggerTP(Short, notional(46000), tpPriceShort))

	// Nil TP
	require.False(ShouldTriggerTP(Long, notional(60000), nil))
}

func TestShouldTriggerSL(t *testing.T) {
	require := require.New(t)

	slPrice := notional(45000)

	// Long: triggers when price <= SL
	require.True(ShouldTriggerSL(Long, notional(45000), slPrice))
	require.True(ShouldTriggerSL(Long, notional(40000), slPrice))
	require.False(ShouldTriggerSL(Long, notional(46000), slPrice))

	// Short: triggers when price >= SL
	slPriceShort := notional(55000)
	require.True(ShouldTriggerSL(Short, notional(55000), slPriceShort))
	require.True(ShouldTriggerSL(Short, notional(60000), slPriceShort))
	require.False(ShouldTriggerSL(Short, notional(54000), slPriceShort))
}

func TestUpdateTrailingStop(t *testing.T) {
	require := require.New(t)

	// Create trailing stop for long position
	trailingDelta := notional(1000) // $1000 trail
	order := &TPSLOrder{
		ID:            ids.GenerateTestID(),
		Type:          TrailingStopOrder,
		TrailingDelta: trailingDelta,
	}

	// Initial update
	updated := UpdateTrailingStop(order, Long, notional(50000))
	require.True(updated)
	require.Equal(notional(50000), order.HighestPrice)
	require.Equal(notional(49000), order.TriggerPrice) // 50000 - 1000

	// Price goes up
	updated = UpdateTrailingStop(order, Long, notional(52000))
	require.True(updated)
	require.Equal(notional(52000), order.HighestPrice)
	require.Equal(notional(51000), order.TriggerPrice) // 52000 - 1000

	// Price goes down (no update to highest)
	updated = UpdateTrailingStop(order, Long, notional(51500))
	require.False(updated)
	require.Equal(notional(52000), order.HighestPrice) // Still 52000
}

func TestUpdateTrailingStopWithPercent(t *testing.T) {
	require := require.New(t)

	// Create trailing stop with 2% trail
	order := &TPSLOrder{
		ID:              ids.GenerateTestID(),
		Type:            TrailingStopOrder,
		TrailingPercent: 200, // 2%
	}

	// Initial update at $50,000
	updated := UpdateTrailingStop(order, Long, notional(50000))
	require.True(updated)
	require.Equal(notional(50000), order.HighestPrice)

	// Trigger price should be $50,000 - 2% = $49,000
	require.Equal(notional(49000), order.TriggerPrice)
}

func TestTrailingStopWithActivation(t *testing.T) {
	require := require.New(t)

	// Create trailing stop that activates at $55,000
	order := &TPSLOrder{
		ID:              ids.GenerateTestID(),
		Type:            TrailingStopOrder,
		TrailingDelta:   notional(1000),
		ActivationPrice: notional(55000),
	}

	// Price below activation - should not update
	updated := UpdateTrailingStop(order, Long, notional(53000))
	require.False(updated)
	require.Nil(order.HighestPrice)

	// Price at activation - should update
	updated = UpdateTrailingStop(order, Long, notional(55000))
	require.True(updated)
	require.Equal(notional(55000), order.HighestPrice)
}

func TestTPSLManagerCreate(t *testing.T) {
	require := require.New(t)

	manager := NewTPSLManager()
	positionID := ids.GenerateTestID()
	traderID := ids.GenerateTestID()
	entryPrice := notional(50000)

	// Create take profit
	tp, err := manager.CreateTPSL(
		positionID,
		traderID,
		"BTC-PERP",
		Long,
		entryPrice,
		TakeProfitOrder,
		notional(55000), // TP at $55K
		TriggerOnMarkPrice,
		nil,   // Market order
		nil,   // Full position
		10000, // 100%
	)
	require.NoError(err)
	require.NotNil(tp)
	require.Equal(TakeProfitOrder, tp.Type)
	require.Equal(Short, tp.Side) // Close side is opposite

	// Create stop loss
	sl, err := manager.CreateTPSL(
		positionID,
		traderID,
		"BTC-PERP",
		Long,
		entryPrice,
		StopLossOrder,
		notional(48000), // SL at $48K
		TriggerOnMarkPrice,
		nil,
		nil,
		10000,
	)
	require.NoError(err)
	require.NotNil(sl)
	require.Equal(StopLossOrder, sl.Type)
}

func TestTPSLManagerInvalidTP(t *testing.T) {
	require := require.New(t)

	manager := NewTPSLManager()
	positionID := ids.GenerateTestID()
	traderID := ids.GenerateTestID()
	entryPrice := notional(50000)

	// Invalid: TP below entry for long
	_, err := manager.CreateTPSL(
		positionID,
		traderID,
		"BTC-PERP",
		Long,
		entryPrice,
		TakeProfitOrder,
		notional(45000), // Below entry!
		TriggerOnMarkPrice,
		nil,
		nil,
		10000,
	)
	require.ErrorIs(err, ErrTPBelowEntry)
}

func TestTPSLManagerCheckTriggers(t *testing.T) {
	require := require.New(t)

	manager := NewTPSLManager()
	positionID := ids.GenerateTestID()
	traderID := ids.GenerateTestID()
	entryPrice := notional(50000)

	// Create TP at $55K
	_, err := manager.CreateTPSL(
		positionID,
		traderID,
		"BTC-PERP",
		Long,
		entryPrice,
		TakeProfitOrder,
		notional(55000),
		TriggerOnMarkPrice,
		nil,
		nil,
		10000,
	)
	require.NoError(err)

	// Mock position side getter
	getPositionSide := func(id ids.ID) (Side, bool) {
		if id == positionID {
			return Long, true
		}
		return Long, false
	}

	// Price below TP - should not trigger
	triggered := manager.CheckTriggers("BTC-PERP", notional(54000), notional(54000), notional(54000), getPositionSide)
	require.Empty(triggered)

	// Price at TP - should trigger
	triggered = manager.CheckTriggers("BTC-PERP", notional(55000), notional(55000), notional(55000), getPositionSide)
	require.Len(triggered, 1)
	require.Equal(TPSLTriggered, triggered[0].Status)
}

func TestTPSLManagerCancelOrders(t *testing.T) {
	require := require.New(t)

	manager := NewTPSLManager()
	positionID := ids.GenerateTestID()
	traderID := ids.GenerateTestID()
	entryPrice := notional(50000)

	// Create orders
	tp, _ := manager.CreateTPSL(positionID, traderID, "BTC-PERP", Long, entryPrice, TakeProfitOrder, notional(55000), TriggerOnMarkPrice, nil, nil, 10000)
	sl, _ := manager.CreateTPSL(positionID, traderID, "BTC-PERP", Long, entryPrice, StopLossOrder, notional(48000), TriggerOnMarkPrice, nil, nil, 10000)

	// Cancel single order
	err := manager.CancelOrder(tp.ID)
	require.NoError(err)
	require.Equal(TPSLCancelled, tp.Status)

	// SL should still be active
	require.Equal(TPSLActive, sl.Status)

	// Cancel all for position
	manager.CancelOrdersForPosition(positionID)
	require.Equal(TPSLCancelled, sl.Status)
}

func TestTPSLClone(t *testing.T) {
	require := require.New(t)

	original := &TPSLOrder{
		ID:           ids.GenerateTestID(),
		TriggerPrice: notional(55000),
		Type:         TakeProfitOrder,
	}

	clone := original.Clone()
	require.Equal(original.ID, clone.ID)
	require.Equal(original.TriggerPrice, clone.TriggerPrice)

	// Modify clone shouldn't affect original
	clone.TriggerPrice = notional(60000)
	require.NotEqual(original.TriggerPrice, clone.TriggerPrice)
}

func BenchmarkCheckTriggers(b *testing.B) {
	manager := NewTPSLManager()

	// Create 1000 orders
	for i := 0; i < 1000; i++ {
		positionID := ids.GenerateTestID()
		traderID := ids.GenerateTestID()
		manager.CreateTPSL(positionID, traderID, "BTC-PERP", Long, notional(50000), TakeProfitOrder, notional(55000), TriggerOnMarkPrice, nil, nil, 10000)
	}

	getPositionSide := func(id ids.ID) (Side, bool) {
		return Long, true
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.CheckTriggers("BTC-PERP", notional(54000), notional(54000), notional(54000), getPositionSide)
	}
}
