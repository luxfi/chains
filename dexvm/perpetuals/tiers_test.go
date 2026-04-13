// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package perpetuals

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Helper to create notional values
func notional(v int64) *big.Int {
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	return new(big.Int).Mul(big.NewInt(v), scale)
}

func TestDefaultLeverageTiers(t *testing.T) {
	require := require.New(t)

	tiers := DefaultLeverageTiers()

	require.Len(tiers, 15, "Should have 15 tiers")

	// First tier should allow 1001x
	require.Equal(uint16(1001), tiers[0].MaxLeverage)
	require.Equal(uint16(10), tiers[0].MaintenanceMargin) // 0.1%

	// Last tier should be 1x
	require.Equal(uint16(1), tiers[len(tiers)-1].MaxLeverage)
}

func TestTierConfigGetTierForNotional(t *testing.T) {
	require := require.New(t)

	tc := NewTierConfig()

	tests := []struct {
		name             string
		notional         *big.Int
		expectedLeverage uint16
	}{
		{"tiny position", notional(100), 1001},
		{"$500 position", notional(500), 500},
		{"$5000 position", notional(5000), 250},
		{"$25000 position", notional(25000), 200},
		{"$100K position", notional(100000), 100},
		{"$750K position", notional(750000), 75},
		{"$1.5M position", notional(1500000), 50},
		{"$3M position", notional(3000000), 25},
		{"$7M position", notional(7000000), 20},
		{"$15M position", notional(15000000), 10},
		{"$50M position", notional(50000000), 5},
		{"$100M position", notional(100000000), 4},
		{"$150M position", notional(150000000), 3},
		{"$225M position", notional(225000000), 2},
		{"$500M position", notional(500000000), 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maxLev := tc.GetMaxLeverageForNotional(tt.notional)
			require.Equal(tt.expectedLeverage, maxLev, "Expected %dx leverage for %s", tt.expectedLeverage, tt.name)
		})
	}
}

func TestTierConfigMaintenanceMargin(t *testing.T) {
	require := require.New(t)

	tc := NewTierConfig()

	// Small position: 0.1% maintenance margin (tier 0: $0-$200)
	mmRate, mmAmount := tc.GetMaintenanceMarginForNotional(notional(100))
	require.Equal(uint16(10), mmRate) // 0.1% = 10 basis points
	require.Equal(int64(0), mmAmount.Int64())

	// $750K position: 1.5% maintenance margin (tier 5: $500K-$1M)
	mmRate, mmAmount = tc.GetMaintenanceMarginForNotional(notional(750000))
	require.Equal(uint16(150), mmRate) // 1.5% = 150 basis points
	require.True(mmAmount.Sign() > 0)
}

func TestCalculateInitialMargin(t *testing.T) {
	require := require.New(t)

	notionalValue := notional(10000) // $10,000

	tests := []struct {
		leverage uint16
		expected *big.Int
	}{
		{10, notional(1000)}, // 10x -> $1,000 margin
		{20, notional(500)},  // 20x -> $500 margin
		{100, notional(100)}, // 100x -> $100 margin
		{500, notional(20)},  // 500x -> $20 margin
		{1000, notional(10)}, // 1000x -> $10 margin
	}

	for _, tt := range tests {
		t.Run("leverage", func(t *testing.T) {
			margin := CalculateInitialMargin(notionalValue, tt.leverage)
			require.Equal(tt.expected, margin)
		})
	}
}

func TestCalculateMaintenanceMargin(t *testing.T) {
	require := require.New(t)

	notionalValue := notional(1000000) // $1M

	// 0.5% rate, $276 maintenance amount
	mmRate := uint16(50)
	mmAmount := notional(276)

	mm := CalculateMaintenanceMargin(notionalValue, mmRate, mmAmount)

	// Expected: $1M * 0.5% - $276 = $5000 - $276 = $4724
	expected := new(big.Int).Sub(notional(5000), notional(276))
	require.Equal(expected, mm)
}

func TestCalculateLiquidationPriceTiered(t *testing.T) {
	require := require.New(t)

	tc := NewTierConfig()
	entryPrice := notional(50000) // $50,000 (e.g., BTC)

	// Long with 20x leverage, $100K notional (tier 4: 1% maintenance margin)
	// Initial margin = 5% (1/20), Maintenance margin = 1%
	// Long liq formula: EntryPrice * (1 - InitialMargin + MaintenanceMargin)
	// = 50000 * (1 - 0.05 + 0.01) = 50000 * 0.96 = 48000
	notionalValue := notional(100000)
	liqPriceLong := CalculateLiquidationPriceTiered(Long, entryPrice, notionalValue, 20, tc)

	// Liquidation price should be below entry for long
	require.True(liqPriceLong.Cmp(entryPrice) < 0, "Long liquidation price should be below entry")

	// Short with 20x leverage
	// Short liq formula: EntryPrice * (1 + InitialMargin - MaintenanceMargin)
	// = 50000 * (1 + 0.05 - 0.01) = 50000 * 1.04 = 52000
	liqPriceShort := CalculateLiquidationPriceTiered(Short, entryPrice, notionalValue, 20, tc)

	// Liquidation price should be above entry for short
	require.True(liqPriceShort.Cmp(entryPrice) > 0, "Short liquidation price should be above entry")

	// Higher leverage = closer liquidation price
	liqPriceLong10x := CalculateLiquidationPriceTiered(Long, entryPrice, notionalValue, 10, tc)
	liqPriceLong20x := CalculateLiquidationPriceTiered(Long, entryPrice, notionalValue, 20, tc)

	// 20x liq price should be closer to entry than 10x
	diff10x := new(big.Int).Sub(entryPrice, liqPriceLong10x)
	diff20x := new(big.Int).Sub(entryPrice, liqPriceLong20x)
	require.True(diff20x.Cmp(diff10x) < 0, "Higher leverage should have closer liquidation price")
}

func Test1001xLeverage(t *testing.T) {
	require := require.New(t)

	tc := NewTierConfig()

	// Very small position should allow 1001x
	smallNotional := notional(100) // $100
	maxLev := tc.GetMaxLeverageForNotional(smallNotional)
	require.Equal(uint16(1001), maxLev, "Should allow 1001x for tiny positions")

	// Calculate margin for 1001x
	margin := CalculateInitialMargin(smallNotional, 1001)

	// $100 / 1001 = ~$0.099 margin required
	expectedMargin := new(big.Int).Div(smallNotional, big.NewInt(1001))

	require.Equal(expectedMargin, margin)

	// Margin should be ~0.1% of notional
	marginPercent := new(big.Int).Mul(margin, big.NewInt(10000))
	marginPercent.Div(marginPercent, smallNotional)
	require.True(marginPercent.Int64() < 100, "1001x should require less than 1% margin")
}

func TestGlobalMaxLeverageOverride(t *testing.T) {
	require := require.New(t)

	tc := NewTierConfig()

	// Default is 1001x
	require.Equal(uint16(1001), tc.GlobalMaxLeverage)

	// Override to 500x
	tc.GlobalMaxLeverage = 500

	// Small position should now be capped at 500x
	smallNotional := notional(100)
	maxLev := tc.GetMaxLeverageForNotional(smallNotional)
	require.Equal(uint16(500), maxLev, "Should be capped at global max")
}

func BenchmarkGetTierForNotional(b *testing.B) {
	tc := NewTierConfig()
	testNotional := notional(1000000) // $1M

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tc.GetTierForNotional(testNotional)
	}
}

func BenchmarkCalculateLiquidationPrice(b *testing.B) {
	tc := NewTierConfig()
	entryPrice := notional(50000)
	notionalValue := notional(500000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculateLiquidationPriceTiered(Long, entryPrice, notionalValue, 100, tc)
	}
}
