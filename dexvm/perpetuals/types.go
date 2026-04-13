// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package perpetuals

import (
	"math/big"
	"time"

	"github.com/luxfi/ids"
)

// Side represents the position side (long or short)
type Side uint8

const (
	Long Side = iota
	Short
)

func (s Side) String() string {
	switch s {
	case Long:
		return "long"
	case Short:
		return "short"
	default:
		return "unknown"
	}
}

// Opposite returns the opposite side
func (s Side) Opposite() Side {
	if s == Long {
		return Short
	}
	return Long
}

// MarginMode represents the margin mode for a position
type MarginMode uint8

const (
	CrossMargin MarginMode = iota
	IsolatedMargin
)

func (m MarginMode) String() string {
	switch m {
	case CrossMargin:
		return "cross"
	case IsolatedMargin:
		return "isolated"
	default:
		return "unknown"
	}
}

// Position represents a perpetual futures position
type Position struct {
	ID               ids.ID     // Unique position ID
	Trader           ids.ID     // Trader account ID
	Market           string     // Market symbol (e.g., "BTC-PERP")
	Side             Side       // Long or Short
	Size             *big.Int   // Position size in base units (e.g., satoshis)
	EntryPrice       *big.Int   // Average entry price (scaled by 1e18)
	Margin           *big.Int   // Margin collateral locked
	MarginMode       MarginMode // Cross or Isolated
	Leverage         uint16     // Leverage multiplier (e.g., 10 = 10x)
	LiquidationPrice *big.Int   // Price at which position is liquidated
	TakeProfit       *big.Int   // Optional take profit price
	StopLoss         *big.Int   // Optional stop loss price
	UnrealizedPnL    *big.Int   // Current unrealized P&L
	RealizedPnL      *big.Int   // Total realized P&L
	FundingPaid      *big.Int   // Total funding payments made/received
	OpenedAt         time.Time  // When position was opened
	UpdatedAt        time.Time  // Last update time
}

// Clone creates a deep copy of the position
func (p *Position) Clone() *Position {
	return &Position{
		ID:               p.ID,
		Trader:           p.Trader,
		Market:           p.Market,
		Side:             p.Side,
		Size:             new(big.Int).Set(p.Size),
		EntryPrice:       new(big.Int).Set(p.EntryPrice),
		Margin:           new(big.Int).Set(p.Margin),
		MarginMode:       p.MarginMode,
		Leverage:         p.Leverage,
		LiquidationPrice: new(big.Int).Set(p.LiquidationPrice),
		TakeProfit:       cloneBigInt(p.TakeProfit),
		StopLoss:         cloneBigInt(p.StopLoss),
		UnrealizedPnL:    new(big.Int).Set(p.UnrealizedPnL),
		RealizedPnL:      new(big.Int).Set(p.RealizedPnL),
		FundingPaid:      new(big.Int).Set(p.FundingPaid),
		OpenedAt:         p.OpenedAt,
		UpdatedAt:        p.UpdatedAt,
	}
}

// Market represents a perpetual futures market
type Market struct {
	Symbol            string        // Market symbol (e.g., "BTC-PERP")
	BaseAsset         ids.ID        // Base asset ID
	QuoteAsset        ids.ID        // Quote asset ID (usually USDC)
	IndexPrice        *big.Int      // Current index price from oracle
	MarkPrice         *big.Int      // Current mark price
	LastPrice         *big.Int      // Last traded price
	FundingRate       *big.Int      // Current funding rate (scaled by 1e18)
	NextFundingTime   time.Time     // Next funding payment time
	OpenInterestLong  *big.Int      // Total long open interest
	OpenInterestShort *big.Int      // Total short open interest
	Volume24h         *big.Int      // 24h trading volume
	MaxLeverage       uint16        // Maximum allowed leverage
	MinSize           *big.Int      // Minimum position size
	TickSize          *big.Int      // Minimum price tick
	MakerFee          uint16        // Maker fee in basis points
	TakerFee          uint16        // Taker fee in basis points
	MaintenanceMargin uint16        // Maintenance margin ratio in basis points
	InitialMargin     uint16        // Initial margin ratio in basis points
	MaxFundingRate    *big.Int      // Maximum funding rate per period
	FundingInterval   time.Duration // Funding interval (typically 8 hours)
	InsuranceFund     *big.Int      // Insurance fund balance for this market
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// MarginAccount represents a trader's margin account
type MarginAccount struct {
	TraderID         ids.ID               // Trader ID
	Balance          *big.Int             // Total account balance
	AvailableBalance *big.Int             // Available balance for new positions
	LockedMargin     *big.Int             // Margin locked in positions
	UnrealizedPnL    *big.Int             // Total unrealized P&L across all positions
	MarginRatio      *big.Int             // Current margin ratio (scaled by 1e18)
	Positions        map[string]*Position // Active positions by market
	Mode             MarginMode           // Default margin mode
	UpdatedAt        time.Time
}

// NewMarginAccount creates a new margin account
func NewMarginAccount(traderID ids.ID) *MarginAccount {
	return &MarginAccount{
		TraderID:         traderID,
		Balance:          big.NewInt(0),
		AvailableBalance: big.NewInt(0),
		LockedMargin:     big.NewInt(0),
		UnrealizedPnL:    big.NewInt(0),
		MarginRatio:      big.NewInt(0),
		Positions:        make(map[string]*Position),
		Mode:             CrossMargin,
		UpdatedAt:        time.Now(),
	}
}

// Order represents a perpetual futures order
type Order struct {
	ID           ids.ID   // Order ID
	Trader       ids.ID   // Trader ID
	Market       string   // Market symbol
	Side         Side     // Long or Short
	Size         *big.Int // Order size
	Price        *big.Int // Limit price (nil for market orders)
	IsMarket     bool     // True for market orders
	ReduceOnly   bool     // Only reduce position, don't increase
	PostOnly     bool     // Only maker, reject if would take
	TimeInForce  TimeInForce
	Leverage     uint16 // Desired leverage
	MarginMode   MarginMode
	FilledSize   *big.Int // Amount filled
	AvgFillPrice *big.Int // Average fill price
	Status       OrderStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// TimeInForce specifies how long an order remains active
type TimeInForce uint8

const (
	GTC TimeInForce = iota // Good Till Cancel
	IOC                    // Immediate or Cancel
	FOK                    // Fill or Kill
)

// OrderStatus represents the status of an order
type OrderStatus uint8

const (
	OrderPending OrderStatus = iota
	OrderOpen
	OrderPartiallyFilled
	OrderFilled
	OrderCancelled
	OrderExpired
	OrderRejected
)

// Trade represents an executed trade
type Trade struct {
	ID         ids.ID    // Trade ID
	Market     string    // Market symbol
	MakerOrder ids.ID    // Maker order ID
	TakerOrder ids.ID    // Taker order ID
	Maker      ids.ID    // Maker trader ID
	Taker      ids.ID    // Taker trader ID
	Side       Side      // Taker side
	Price      *big.Int  // Execution price
	Size       *big.Int  // Trade size
	MakerFee   *big.Int  // Fee paid by maker
	TakerFee   *big.Int  // Fee paid by taker
	Timestamp  time.Time // Execution time
}

// LiquidationEvent represents a liquidation
type LiquidationEvent struct {
	ID               ids.ID    // Event ID
	Position         *Position // Liquidated position (snapshot)
	LiquidationPrice *big.Int  // Price at liquidation
	LiquidationSize  *big.Int  // Size liquidated
	InsurancePayout  *big.Int  // Amount from insurance fund
	PnL              *big.Int  // P&L of liquidated position
	Liquidator       ids.ID    // Liquidator (can be system or keeper)
	Timestamp        time.Time
}

// FundingPayment represents a funding payment
type FundingPayment struct {
	ID          ids.ID   // Payment ID
	Position    ids.ID   // Position ID
	Market      string   // Market symbol
	Trader      ids.ID   // Trader ID
	Amount      *big.Int // Payment amount (negative = paid, positive = received)
	FundingRate *big.Int // Funding rate at time of payment
	Timestamp   time.Time
}

// Helper function to clone big.Int or return nil
func cloneBigInt(v *big.Int) *big.Int {
	if v == nil {
		return nil
	}
	return new(big.Int).Set(v)
}
