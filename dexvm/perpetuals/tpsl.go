// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package perpetuals

import (
	"errors"
	"math/big"
	"time"

	"github.com/luxfi/ids"
)

var (
	ErrInvalidTPSL       = errors.New("invalid take profit/stop loss configuration")
	ErrTPSLAlreadyExists = errors.New("TP/SL order already exists for position")
	ErrTPSLNotFound      = errors.New("TP/SL order not found")
	ErrTPBelowEntry      = errors.New("take profit must be above entry for long, below for short")
	ErrSLAboveEntry      = errors.New("stop loss must be below entry for long, above for short")
)

// TPSLType represents the type of TP/SL order
type TPSLType uint8

const (
	TakeProfitOrder TPSLType = iota
	StopLossOrder
	TrailingStopOrder
)

func (t TPSLType) String() string {
	switch t {
	case TakeProfitOrder:
		return "take_profit"
	case StopLossOrder:
		return "stop_loss"
	case TrailingStopOrder:
		return "trailing_stop"
	default:
		return "unknown"
	}
}

// TriggerType specifies when TP/SL triggers
type TriggerType uint8

const (
	TriggerOnMarkPrice TriggerType = iota
	TriggerOnLastPrice
	TriggerOnIndexPrice
)

// TPSLOrder represents a Take Profit or Stop Loss order
type TPSLOrder struct {
	ID           ids.ID      // Unique order ID
	PositionID   ids.ID      // Associated position
	TraderID     ids.ID      // Trader who owns this
	Market       string      // Market symbol
	Type         TPSLType    // Take profit or Stop loss
	Side         Side        // Side to close (opposite of position side)
	TriggerPrice *big.Int    // Price at which to trigger
	TriggerType  TriggerType // What price to watch
	OrderPrice   *big.Int    // Execution price (nil = market order)
	Size         *big.Int    // Size to close (nil = full position)
	SizePercent  uint16      // Size as percentage (0-10000 basis points)

	// Trailing stop specific
	TrailingDelta   *big.Int // Distance to trail from high/low
	TrailingPercent uint16   // Trail as percentage
	ActivationPrice *big.Int // Price at which trailing starts
	HighestPrice    *big.Int // Highest price since activation (for long)
	LowestPrice     *big.Int // Lowest price since activation (for short)

	// Metadata
	Status      TPSLStatus
	TriggeredAt *time.Time
	ExecutedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// TPSLStatus represents the status of a TP/SL order
type TPSLStatus uint8

const (
	TPSLPending TPSLStatus = iota
	TPSLActive
	TPSLTriggered
	TPSLExecuted
	TPSLCancelled
	TPSLExpired
)

func (s TPSLStatus) String() string {
	switch s {
	case TPSLPending:
		return "pending"
	case TPSLActive:
		return "active"
	case TPSLTriggered:
		return "triggered"
	case TPSLExecuted:
		return "executed"
	case TPSLCancelled:
		return "cancelled"
	case TPSLExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// TPSLConfig holds the configuration for TP/SL orders on a position
type TPSLConfig struct {
	TakeProfit *TPSLOrder
	StopLoss   *TPSLOrder
}

// Clone creates a deep copy of TPSLConfig
func (c *TPSLConfig) Clone() *TPSLConfig {
	if c == nil {
		return nil
	}
	clone := &TPSLConfig{}
	if c.TakeProfit != nil {
		clone.TakeProfit = c.TakeProfit.Clone()
	}
	if c.StopLoss != nil {
		clone.StopLoss = c.StopLoss.Clone()
	}
	return clone
}

// Clone creates a deep copy of TPSLOrder
func (o *TPSLOrder) Clone() *TPSLOrder {
	if o == nil {
		return nil
	}
	return &TPSLOrder{
		ID:              o.ID,
		PositionID:      o.PositionID,
		TraderID:        o.TraderID,
		Market:          o.Market,
		Type:            o.Type,
		Side:            o.Side,
		TriggerPrice:    cloneBigInt(o.TriggerPrice),
		TriggerType:     o.TriggerType,
		OrderPrice:      cloneBigInt(o.OrderPrice),
		Size:            cloneBigInt(o.Size),
		SizePercent:     o.SizePercent,
		TrailingDelta:   cloneBigInt(o.TrailingDelta),
		TrailingPercent: o.TrailingPercent,
		ActivationPrice: cloneBigInt(o.ActivationPrice),
		HighestPrice:    cloneBigInt(o.HighestPrice),
		LowestPrice:     cloneBigInt(o.LowestPrice),
		Status:          o.Status,
		TriggeredAt:     o.TriggeredAt,
		ExecutedAt:      o.ExecutedAt,
		CreatedAt:       o.CreatedAt,
		UpdatedAt:       o.UpdatedAt,
	}
}

// ValidateTPSL validates a TP/SL order configuration
func ValidateTPSL(positionSide Side, entryPrice, tpPrice, slPrice *big.Int) error {
	if positionSide == Long {
		// For long: TP must be above entry, SL must be below entry
		if tpPrice != nil && tpPrice.Cmp(entryPrice) <= 0 {
			return ErrTPBelowEntry
		}
		if slPrice != nil && slPrice.Cmp(entryPrice) >= 0 {
			return ErrSLAboveEntry
		}
	} else {
		// For short: TP must be below entry, SL must be above entry
		if tpPrice != nil && tpPrice.Cmp(entryPrice) >= 0 {
			return ErrTPBelowEntry
		}
		if slPrice != nil && slPrice.Cmp(entryPrice) <= 0 {
			return ErrSLAboveEntry
		}
	}
	return nil
}

// CalculateTPPrice calculates take profit price from percentage
// For long: TP = Entry * (1 + percent/10000)
// For short: TP = Entry * (1 - percent/10000)
func CalculateTPPrice(positionSide Side, entryPrice *big.Int, percent uint16) *big.Int {
	delta := new(big.Int).Mul(entryPrice, big.NewInt(int64(percent)))
	delta.Div(delta, BasisPointDenom)

	if positionSide == Long {
		return new(big.Int).Add(entryPrice, delta)
	}
	return new(big.Int).Sub(entryPrice, delta)
}

// CalculateSLPrice calculates stop loss price from percentage
// For long: SL = Entry * (1 - percent/10000)
// For short: SL = Entry * (1 + percent/10000)
func CalculateSLPrice(positionSide Side, entryPrice *big.Int, percent uint16) *big.Int {
	delta := new(big.Int).Mul(entryPrice, big.NewInt(int64(percent)))
	delta.Div(delta, BasisPointDenom)

	if positionSide == Long {
		return new(big.Int).Sub(entryPrice, delta)
	}
	return new(big.Int).Add(entryPrice, delta)
}

// CalculateTPPercent calculates take profit percentage from target price
func CalculateTPPercent(positionSide Side, entryPrice, tpPrice *big.Int) uint16 {
	var diff *big.Int
	if positionSide == Long {
		diff = new(big.Int).Sub(tpPrice, entryPrice)
	} else {
		diff = new(big.Int).Sub(entryPrice, tpPrice)
	}

	percent := new(big.Int).Mul(diff, BasisPointDenom)
	percent.Div(percent, entryPrice)

	if percent.Sign() < 0 {
		return 0
	}
	if percent.Cmp(big.NewInt(10000)) > 0 {
		return 10000
	}
	return uint16(percent.Int64())
}

// ShouldTriggerTP checks if take profit should trigger at current price
func ShouldTriggerTP(positionSide Side, currentPrice, tpPrice *big.Int) bool {
	if tpPrice == nil {
		return false
	}
	if positionSide == Long {
		return currentPrice.Cmp(tpPrice) >= 0
	}
	return currentPrice.Cmp(tpPrice) <= 0
}

// ShouldTriggerSL checks if stop loss should trigger at current price
func ShouldTriggerSL(positionSide Side, currentPrice, slPrice *big.Int) bool {
	if slPrice == nil {
		return false
	}
	if positionSide == Long {
		return currentPrice.Cmp(slPrice) <= 0
	}
	return currentPrice.Cmp(slPrice) >= 0
}

// UpdateTrailingStop updates trailing stop based on current price
func UpdateTrailingStop(order *TPSLOrder, positionSide Side, currentPrice *big.Int) bool {
	if order == nil || order.Type != TrailingStopOrder {
		return false
	}

	updated := false

	// Check if trailing has been activated
	if order.ActivationPrice != nil {
		if positionSide == Long && currentPrice.Cmp(order.ActivationPrice) < 0 {
			return false // Not yet activated
		}
		if positionSide == Short && currentPrice.Cmp(order.ActivationPrice) > 0 {
			return false // Not yet activated
		}
	}

	if positionSide == Long {
		// Track highest price
		if order.HighestPrice == nil || currentPrice.Cmp(order.HighestPrice) > 0 {
			order.HighestPrice = new(big.Int).Set(currentPrice)

			// Update trigger price
			if order.TrailingDelta != nil {
				order.TriggerPrice = new(big.Int).Sub(order.HighestPrice, order.TrailingDelta)
			} else if order.TrailingPercent > 0 {
				delta := new(big.Int).Mul(order.HighestPrice, big.NewInt(int64(order.TrailingPercent)))
				delta.Div(delta, BasisPointDenom)
				order.TriggerPrice = new(big.Int).Sub(order.HighestPrice, delta)
			}
			updated = true
		}
	} else {
		// Track lowest price
		if order.LowestPrice == nil || currentPrice.Cmp(order.LowestPrice) < 0 {
			order.LowestPrice = new(big.Int).Set(currentPrice)

			// Update trigger price
			if order.TrailingDelta != nil {
				order.TriggerPrice = new(big.Int).Add(order.LowestPrice, order.TrailingDelta)
			} else if order.TrailingPercent > 0 {
				delta := new(big.Int).Mul(order.LowestPrice, big.NewInt(int64(order.TrailingPercent)))
				delta.Div(delta, BasisPointDenom)
				order.TriggerPrice = new(big.Int).Add(order.LowestPrice, delta)
			}
			updated = true
		}
	}

	if updated {
		order.UpdatedAt = time.Now()
	}
	return updated
}

// TPSLManager manages TP/SL orders
type TPSLManager struct {
	orders         map[ids.ID]*TPSLOrder   // All TP/SL orders by ID
	ordersByPos    map[ids.ID][]*TPSLOrder // Orders by position ID
	ordersByTrader map[ids.ID][]*TPSLOrder // Orders by trader ID
}

// NewTPSLManager creates a new TP/SL manager
func NewTPSLManager() *TPSLManager {
	return &TPSLManager{
		orders:         make(map[ids.ID]*TPSLOrder),
		ordersByPos:    make(map[ids.ID][]*TPSLOrder),
		ordersByTrader: make(map[ids.ID][]*TPSLOrder),
	}
}

// CreateTPSL creates a new TP/SL order
func (m *TPSLManager) CreateTPSL(
	positionID ids.ID,
	traderID ids.ID,
	market string,
	positionSide Side,
	entryPrice *big.Int,
	tpslType TPSLType,
	triggerPrice *big.Int,
	triggerType TriggerType,
	orderPrice *big.Int,
	size *big.Int,
	sizePercent uint16,
) (*TPSLOrder, error) {
	// Validate trigger price
	if triggerPrice == nil {
		return nil, ErrInvalidTPSL
	}

	// Validate TP/SL direction
	if tpslType == TakeProfitOrder {
		if positionSide == Long && triggerPrice.Cmp(entryPrice) <= 0 {
			return nil, ErrTPBelowEntry
		}
		if positionSide == Short && triggerPrice.Cmp(entryPrice) >= 0 {
			return nil, ErrTPBelowEntry
		}
	} else if tpslType == StopLossOrder {
		if positionSide == Long && triggerPrice.Cmp(entryPrice) >= 0 {
			return nil, ErrSLAboveEntry
		}
		if positionSide == Short && triggerPrice.Cmp(entryPrice) <= 0 {
			return nil, ErrSLAboveEntry
		}
	}

	now := time.Now()
	order := &TPSLOrder{
		ID:           ids.GenerateTestID(),
		PositionID:   positionID,
		TraderID:     traderID,
		Market:       market,
		Type:         tpslType,
		Side:         positionSide.Opposite(), // Close side is opposite
		TriggerPrice: new(big.Int).Set(triggerPrice),
		TriggerType:  triggerType,
		OrderPrice:   cloneBigInt(orderPrice),
		Size:         cloneBigInt(size),
		SizePercent:  sizePercent,
		Status:       TPSLActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	m.orders[order.ID] = order
	m.ordersByPos[positionID] = append(m.ordersByPos[positionID], order)
	m.ordersByTrader[traderID] = append(m.ordersByTrader[traderID], order)

	return order, nil
}

// CreateTrailingStop creates a trailing stop order
func (m *TPSLManager) CreateTrailingStop(
	positionID ids.ID,
	traderID ids.ID,
	market string,
	positionSide Side,
	trailingDelta *big.Int,
	trailingPercent uint16,
	activationPrice *big.Int,
	size *big.Int,
	sizePercent uint16,
) (*TPSLOrder, error) {
	if trailingDelta == nil && trailingPercent == 0 {
		return nil, ErrInvalidTPSL
	}

	now := time.Now()
	order := &TPSLOrder{
		ID:              ids.GenerateTestID(),
		PositionID:      positionID,
		TraderID:        traderID,
		Market:          market,
		Type:            TrailingStopOrder,
		Side:            positionSide.Opposite(),
		TriggerType:     TriggerOnMarkPrice,
		TrailingDelta:   cloneBigInt(trailingDelta),
		TrailingPercent: trailingPercent,
		ActivationPrice: cloneBigInt(activationPrice),
		Size:            cloneBigInt(size),
		SizePercent:     sizePercent,
		Status:          TPSLActive,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	m.orders[order.ID] = order
	m.ordersByPos[positionID] = append(m.ordersByPos[positionID], order)
	m.ordersByTrader[traderID] = append(m.ordersByTrader[traderID], order)

	return order, nil
}

// GetOrdersForPosition returns all TP/SL orders for a position
func (m *TPSLManager) GetOrdersForPosition(positionID ids.ID) []*TPSLOrder {
	return m.ordersByPos[positionID]
}

// CancelOrder cancels a TP/SL order
func (m *TPSLManager) CancelOrder(orderID ids.ID) error {
	order, ok := m.orders[orderID]
	if !ok {
		return ErrTPSLNotFound
	}
	order.Status = TPSLCancelled
	order.UpdatedAt = time.Now()
	return nil
}

// CancelOrdersForPosition cancels all TP/SL orders for a position
func (m *TPSLManager) CancelOrdersForPosition(positionID ids.ID) {
	orders := m.ordersByPos[positionID]
	now := time.Now()
	for _, order := range orders {
		if order.Status == TPSLActive || order.Status == TPSLPending {
			order.Status = TPSLCancelled
			order.UpdatedAt = now
		}
	}
}

// CheckTriggers checks all TP/SL orders against current prices
func (m *TPSLManager) CheckTriggers(
	market string,
	markPrice, lastPrice, indexPrice *big.Int,
	getPositionSide func(positionID ids.ID) (Side, bool),
) []*TPSLOrder {
	var triggered []*TPSLOrder

	for _, order := range m.orders {
		if order.Market != market || order.Status != TPSLActive {
			continue
		}

		positionSide, exists := getPositionSide(order.PositionID)
		if !exists {
			order.Status = TPSLCancelled
			continue
		}

		// Get the price to check against
		var checkPrice *big.Int
		switch order.TriggerType {
		case TriggerOnMarkPrice:
			checkPrice = markPrice
		case TriggerOnLastPrice:
			checkPrice = lastPrice
		case TriggerOnIndexPrice:
			checkPrice = indexPrice
		default:
			checkPrice = markPrice
		}

		// Update trailing stops
		if order.Type == TrailingStopOrder {
			UpdateTrailingStop(order, positionSide, checkPrice)
		}

		// Check if should trigger
		shouldTrigger := false
		if order.Type == TakeProfitOrder {
			shouldTrigger = ShouldTriggerTP(positionSide, checkPrice, order.TriggerPrice)
		} else {
			shouldTrigger = ShouldTriggerSL(positionSide, checkPrice, order.TriggerPrice)
		}

		if shouldTrigger {
			now := time.Now()
			order.Status = TPSLTriggered
			order.TriggeredAt = &now
			order.UpdatedAt = now
			triggered = append(triggered, order)
		}
	}

	return triggered
}
