// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package lending provides a DeFi lending protocol for the DEX VM.
// It supports collateralized borrowing with dynamic interest rates.
package lending

import (
	"math/big"
	"time"

	"github.com/luxfi/ids"
)

// LendingPool represents a single asset lending pool.
type LendingPool struct {
	// Pool identification
	ID    ids.ID `json:"id"`
	Asset string `json:"asset"` // Asset symbol (e.g., "LUX", "USDT")

	// Supply side
	TotalSupply        *big.Int `json:"totalSupply"`        // Total assets supplied
	TotalBorrows       *big.Int `json:"totalBorrows"`       // Total assets borrowed
	AvailableLiquidity *big.Int `json:"availableLiquidity"` // Supply - Borrows

	// Interest rates (scaled by 1e18)
	SupplyRate *big.Int `json:"supplyRate"` // APY for suppliers
	BorrowRate *big.Int `json:"borrowRate"` // APY for borrowers

	// Utilization (scaled by 1e18)
	UtilizationRate *big.Int `json:"utilizationRate"` // Borrows / Supply

	// Interest rate model parameters
	BaseRate       *big.Int `json:"baseRate"`       // Base interest rate
	Multiplier     *big.Int `json:"multiplier"`     // Rate increase per utilization
	JumpMultiplier *big.Int `json:"jumpMultiplier"` // Rate increase above kink
	Kink           *big.Int `json:"kink"`           // Utilization threshold for jump

	// Collateral parameters
	CollateralFactor     *big.Int `json:"collateralFactor"`     // Max borrow against collateral (e.g., 0.75 = 75%)
	LiquidationBonus     *big.Int `json:"liquidationBonus"`     // Bonus for liquidators (e.g., 0.08 = 8%)
	LiquidationThreshold *big.Int `json:"liquidationThreshold"` // Health factor threshold

	// Reserve
	ReserveFactor *big.Int `json:"reserveFactor"` // Fraction of interest to reserves
	TotalReserves *big.Int `json:"totalReserves"` // Accumulated reserves

	// Timestamps
	LastUpdateTime time.Time `json:"lastUpdateTime"`
	CreatedAt      time.Time `json:"createdAt"`
}

// UserSupply represents a user's supply position in a pool.
type UserSupply struct {
	User        ids.ShortID `json:"user"`
	Pool        ids.ID      `json:"pool"`
	Asset       string      `json:"asset"`
	Principal   *big.Int    `json:"principal"`   // Initial supply amount
	Balance     *big.Int    `json:"balance"`     // Current balance with interest
	SupplyIndex *big.Int    `json:"supplyIndex"` // Index at last update
	UpdatedAt   time.Time   `json:"updatedAt"`
}

// UserBorrow represents a user's borrow position in a pool.
type UserBorrow struct {
	User        ids.ShortID `json:"user"`
	Pool        ids.ID      `json:"pool"`
	Asset       string      `json:"asset"`
	Principal   *big.Int    `json:"principal"`   // Initial borrow amount
	Balance     *big.Int    `json:"balance"`     // Current balance with interest
	BorrowIndex *big.Int    `json:"borrowIndex"` // Index at last update
	UpdatedAt   time.Time   `json:"updatedAt"`
}

// CollateralPosition represents a user's collateral in the lending system.
type CollateralPosition struct {
	User      ids.ShortID `json:"user"`
	Asset     string      `json:"asset"`
	Amount    *big.Int    `json:"amount"`    // Collateral amount
	IsEnabled bool        `json:"isEnabled"` // Whether used as collateral
	UpdatedAt time.Time   `json:"updatedAt"`
}

// UserAccount represents a user's complete lending account.
type UserAccount struct {
	User               ids.ShortID                    `json:"user"`
	Supplies           map[string]*UserSupply         `json:"supplies"`           // Asset -> Supply
	Borrows            map[string]*UserBorrow         `json:"borrows"`            // Asset -> Borrow
	Collateral         map[string]*CollateralPosition `json:"collateral"`         // Asset -> Collateral
	HealthFactor       *big.Int                       `json:"healthFactor"`       // Account health (scaled by 1e18)
	TotalCollateralUSD *big.Int                       `json:"totalCollateralUSD"` // In USD value
	TotalBorrowsUSD    *big.Int                       `json:"totalBorrowsUSD"`    // In USD value
	BorrowCapacityUSD  *big.Int                       `json:"borrowCapacityUSD"`  // Max additional borrow
	CreatedAt          time.Time                      `json:"createdAt"`
	UpdatedAt          time.Time                      `json:"updatedAt"`
}

// LiquidationEvent represents a liquidation that occurred.
type LiquidationEvent struct {
	ID               ids.ID      `json:"id"`
	Liquidator       ids.ShortID `json:"liquidator"`
	Borrower         ids.ShortID `json:"borrower"`
	DebtAsset        string      `json:"debtAsset"`
	CollateralAsset  string      `json:"collateralAsset"`
	DebtRepaid       *big.Int    `json:"debtRepaid"`
	CollateralSeized *big.Int    `json:"collateralSeized"`
	LiquidatorBonus  *big.Int    `json:"liquidatorBonus"`
	Timestamp        time.Time   `json:"timestamp"`
}

// InterestRateModel defines the interest rate calculation model.
type InterestRateModel struct {
	BaseRate       *big.Int // Base rate at 0% utilization
	Multiplier     *big.Int // Slope below kink
	JumpMultiplier *big.Int // Slope above kink
	Kink           *big.Int // Utilization rate at kink point
}

// PoolConfig holds configuration for creating a new lending pool.
type PoolConfig struct {
	Asset                string
	BaseRate             *big.Int
	Multiplier           *big.Int
	JumpMultiplier       *big.Int
	Kink                 *big.Int
	CollateralFactor     *big.Int
	LiquidationBonus     *big.Int
	LiquidationThreshold *big.Int
	ReserveFactor        *big.Int
}

// LendingStats provides aggregate statistics for the lending protocol.
type LendingStats struct {
	TotalSupplyUSD   *big.Int `json:"totalSupplyUSD"`
	TotalBorrowsUSD  *big.Int `json:"totalBorrowsUSD"`
	TotalReservesUSD *big.Int `json:"totalReservesUSD"`
	PoolCount        int      `json:"poolCount"`
	UserCount        int      `json:"userCount"`
	LiquidationCount int      `json:"liquidationCount"`
}

// Constants for scaling
const (
	// Scale factors
	Scale18 = 1e18 // Standard 18 decimal scaling
	Scale8  = 1e8  // 8 decimal scaling for some rates

	// Seconds per year for interest calculations
	SecondsPerYear = 365 * 24 * 60 * 60

	// Default parameters (scaled by 1e18)
	DefaultBaseRate             = 0.02e18 // 2% base rate
	DefaultMultiplier           = 0.1e18  // 10% multiplier
	DefaultJumpMultiplier       = 3e18    // 300% jump multiplier
	DefaultKink                 = 0.8e18  // 80% utilization kink
	DefaultCollateralFactor     = 0.75e18 // 75% collateral factor
	DefaultLiquidationBonus     = 0.08e18 // 8% liquidation bonus
	DefaultLiquidationThreshold = 0.8e18  // 80% liquidation threshold
	DefaultReserveFactor        = 0.1e18  // 10% reserve factor

	// Minimum health factor before liquidation
	MinHealthFactor = 1e18 // 1.0
)

// NewBigInt creates a new big.Int from an int64.
func NewBigInt(v int64) *big.Int {
	return big.NewInt(v)
}

// Scale18Int returns a big.Int scaled by 1e18.
func Scale18Int(v int64) *big.Int {
	scale := big.NewInt(1e18)
	return new(big.Int).Mul(big.NewInt(v), scale)
}

// DefaultPoolConfig returns a default configuration for a lending pool.
func DefaultPoolConfig(asset string) *PoolConfig {
	return &PoolConfig{
		Asset:                asset,
		BaseRate:             big.NewInt(int64(DefaultBaseRate)),
		Multiplier:           big.NewInt(int64(DefaultMultiplier)),
		JumpMultiplier:       big.NewInt(int64(DefaultJumpMultiplier)),
		Kink:                 big.NewInt(int64(DefaultKink)),
		CollateralFactor:     big.NewInt(int64(DefaultCollateralFactor)),
		LiquidationBonus:     big.NewInt(int64(DefaultLiquidationBonus)),
		LiquidationThreshold: big.NewInt(int64(DefaultLiquidationThreshold)),
		ReserveFactor:        big.NewInt(int64(DefaultReserveFactor)),
	}
}
