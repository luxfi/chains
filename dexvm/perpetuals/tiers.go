// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package perpetuals

import (
	"math/big"
)

// LeverageTier represents a tier in the tiered leverage system
// Based on position notional value, max leverage decreases
type LeverageTier struct {
	MinNotional       *big.Int // Minimum notional value (in quote asset, e.g., USDT)
	MaxNotional       *big.Int // Maximum notional value
	MaxLeverage       uint16   // Maximum leverage for this tier
	MaintenanceMargin uint16   // Maintenance margin rate in basis points
	MaintenanceAmount *big.Int // Maintenance amount deduction
}

// DefaultLeverageTiers returns the standard Aster DEX-style tiered leverage system
// Supports up to 1001x leverage for small positions
func DefaultLeverageTiers() []*LeverageTier {
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

	// Helper to create notional values
	notional := func(v int64) *big.Int {
		return new(big.Int).Mul(big.NewInt(v), scale)
	}

	return []*LeverageTier{
		{
			MinNotional:       big.NewInt(0),
			MaxNotional:       notional(200),
			MaxLeverage:       1001, // Up to 1001x for tiny positions
			MaintenanceMargin: 10,   // 0.1%
			MaintenanceAmount: big.NewInt(0),
		},
		{
			MinNotional:       notional(200),
			MaxNotional:       notional(2000),
			MaxLeverage:       500,                                    // 500x
			MaintenanceMargin: 20,                                     // 0.2%
			MaintenanceAmount: new(big.Int).Div(scale, big.NewInt(5)), // 0.2
		},
		{
			MinNotional:       notional(2000),
			MaxNotional:       notional(10000),
			MaxLeverage:       250,                                    // 250x
			MaintenanceMargin: 25,                                     // 0.25%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(1)), // 1
		},
		{
			MinNotional:       notional(10000),
			MaxNotional:       notional(50000),
			MaxLeverage:       200,                                     // 200x
			MaintenanceMargin: 50,                                      // 0.5%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(26)), // 26
		},
		{
			MinNotional:       notional(50000),
			MaxNotional:       notional(500000),
			MaxLeverage:       100,                                      // 100x
			MaintenanceMargin: 100,                                      // 1%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(276)), // 276
		},
		{
			MinNotional:       notional(500000),
			MaxNotional:       notional(1000000),
			MaxLeverage:       75,                                        // 75x
			MaintenanceMargin: 150,                                       // 1.5%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(2776)), // 2,776
		},
		{
			MinNotional:       notional(1000000),
			MaxNotional:       notional(2500000),
			MaxLeverage:       50,                                        // 50x
			MaintenanceMargin: 200,                                       // 2%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(7776)), // 7,776
		},
		{
			MinNotional:       notional(2500000),
			MaxNotional:       notional(5000000),
			MaxLeverage:       25,                                         // 25x
			MaintenanceMargin: 250,                                        // 2.5%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(20276)), // 20,276
		},
		{
			MinNotional:       notional(5000000),
			MaxNotional:       notional(12500000),
			MaxLeverage:       20,                                         // 20x
			MaintenanceMargin: 300,                                        // 3%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(45276)), // 45,276
		},
		{
			MinNotional:       notional(12500000),
			MaxNotional:       notional(25000000),
			MaxLeverage:       10,                                          // 10x
			MaintenanceMargin: 500,                                         // 5%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(295276)), // 295,276
		},
		{
			MinNotional:       notional(25000000),
			MaxNotional:       notional(75000000),
			MaxLeverage:       5,                                            // 5x
			MaintenanceMargin: 1000,                                         // 10%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(1545276)), // 1,545,276
		},
		{
			MinNotional:       notional(75000000),
			MaxNotional:       notional(125000000),
			MaxLeverage:       4,                                            // 4x
			MaintenanceMargin: 1250,                                         // 12.5%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(3420276)), // 3,420,276
		},
		{
			MinNotional:       notional(125000000),
			MaxNotional:       notional(200000000),
			MaxLeverage:       3,                                            // 3x
			MaintenanceMargin: 1500,                                         // 15%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(6545276)), // 6,545,276
		},
		{
			MinNotional:       notional(200000000),
			MaxNotional:       notional(250000000),
			MaxLeverage:       2,                                             // 2x
			MaintenanceMargin: 2500,                                          // 25%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(26545276)), // 26,545,276
		},
		{
			MinNotional:       notional(250000000),
			MaxNotional:       nil,                                           // Unlimited
			MaxLeverage:       1,                                             // 1x (spot-like)
			MaintenanceMargin: 5000,                                          // 50%
			MaintenanceAmount: new(big.Int).Mul(scale, big.NewInt(89045276)), // 89,045,276
		},
	}
}

// TierConfig stores the leverage tier configuration for a market
type TierConfig struct {
	Tiers             []*LeverageTier
	GlobalMaxLeverage uint16 // Global max leverage (can be lower than tier max)
}

// NewTierConfig creates a new tier configuration with default tiers
func NewTierConfig() *TierConfig {
	return &TierConfig{
		Tiers:             DefaultLeverageTiers(),
		GlobalMaxLeverage: 1001,
	}
}

// GetTierForNotional returns the leverage tier for a given notional value
func (tc *TierConfig) GetTierForNotional(notional *big.Int) *LeverageTier {
	for _, tier := range tc.Tiers {
		if notional.Cmp(tier.MinNotional) >= 0 {
			if tier.MaxNotional == nil || notional.Cmp(tier.MaxNotional) < 0 {
				return tier
			}
		}
	}
	// Return last tier as fallback
	return tc.Tiers[len(tc.Tiers)-1]
}

// GetMaxLeverageForNotional returns the maximum leverage allowed for a notional position size
func (tc *TierConfig) GetMaxLeverageForNotional(notional *big.Int) uint16 {
	tier := tc.GetTierForNotional(notional)
	if tier.MaxLeverage > tc.GlobalMaxLeverage {
		return tc.GlobalMaxLeverage
	}
	return tier.MaxLeverage
}

// GetMaintenanceMarginForNotional returns the maintenance margin rate and amount
func (tc *TierConfig) GetMaintenanceMarginForNotional(notional *big.Int) (uint16, *big.Int) {
	tier := tc.GetTierForNotional(notional)
	return tier.MaintenanceMargin, tier.MaintenanceAmount
}

// CalculateInitialMargin calculates the required initial margin for a position
// Initial Margin = Notional Value / Leverage
func CalculateInitialMargin(notional *big.Int, leverage uint16) *big.Int {
	if leverage == 0 {
		leverage = 1
	}
	return new(big.Int).Div(notional, big.NewInt(int64(leverage)))
}

// CalculateMaintenanceMargin calculates the maintenance margin for a position
// Maintenance Margin = Notional Value * Maintenance Margin Rate - Maintenance Amount
func CalculateMaintenanceMargin(notional *big.Int, mmRate uint16, mmAmount *big.Int) *big.Int {
	// mmRate is in basis points (10000 = 100%)
	margin := new(big.Int).Mul(notional, big.NewInt(int64(mmRate)))
	margin.Div(margin, BasisPointDenom)
	margin.Sub(margin, mmAmount)
	if margin.Sign() < 0 {
		margin = big.NewInt(0)
	}
	return margin
}

// CalculateLiquidationPriceTiered calculates liquidation price with tiered margins
func CalculateLiquidationPriceTiered(
	side Side,
	entryPrice *big.Int,
	notional *big.Int,
	leverage uint16,
	tc *TierConfig,
) *big.Int {
	mmRate, mmAmount := tc.GetMaintenanceMarginForNotional(notional)

	// For Long: LiqPrice = EntryPrice * (1 - InitialMarginRate + MaintenanceMarginRate)
	// For Short: LiqPrice = EntryPrice * (1 + InitialMarginRate - MaintenanceMarginRate)

	initialMarginRate := new(big.Int).Div(PrecisionFactor, big.NewInt(int64(leverage)))
	maintenanceMarginRate := new(big.Int).Mul(big.NewInt(int64(mmRate)), PrecisionFactor)
	maintenanceMarginRate.Div(maintenanceMarginRate, BasisPointDenom)

	var multiplier *big.Int
	if side == Long {
		// 1 - 1/leverage + maintenance margin rate
		multiplier = new(big.Int).Sub(PrecisionFactor, initialMarginRate)
		multiplier.Add(multiplier, maintenanceMarginRate)
	} else {
		// 1 + 1/leverage - maintenance margin rate
		multiplier = new(big.Int).Add(PrecisionFactor, initialMarginRate)
		multiplier.Sub(multiplier, maintenanceMarginRate)
	}

	liquidationPrice := new(big.Int).Mul(entryPrice, multiplier)
	liquidationPrice.Div(liquidationPrice, PrecisionFactor)

	// Adjust for maintenance amount (simplified)
	if mmAmount != nil && mmAmount.Sign() > 0 {
		// Maintenance amount adjustment
		// This is more complex in practice, simplified here
		adjustment := new(big.Int).Div(mmAmount, notional)
		adjustment.Mul(adjustment, entryPrice)
		adjustment.Div(adjustment, PrecisionFactor)

		if side == Long {
			liquidationPrice.Add(liquidationPrice, adjustment)
		} else {
			liquidationPrice.Sub(liquidationPrice, adjustment)
		}
	}

	return liquidationPrice
}
