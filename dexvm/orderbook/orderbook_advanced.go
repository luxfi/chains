// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package orderbook

import (
	"errors"
	"sync/atomic"

	"github.com/luxfi/ids"
)

// Additional order types for advanced trading
const (
	Iceberg   OrderType = 10 // Iceberg order - partially hidden
	Hidden    OrderType = 11 // Fully hidden order
	Peg       OrderType = 12 // Pegged to best bid/ask
	Bracket   OrderType = 13 // Trailing stop order
	PostOnly  OrderType = 14 // Post-only order (explicit type)
	ReduceOnl OrderType = 15 // Reduce-only order (explicit type)
)

var (
	ErrIcebergDisplayTooLarge = errors.New("iceberg display size exceeds total")
	ErrIcebergDisplayTooSmall = errors.New("iceberg display size must be positive")
	ErrHiddenOrderNotAllowed  = errors.New("hidden orders not allowed for this market")
	ErrPegOffsetInvalid       = errors.New("peg offset invalid")
	ErrTrailAmountInvalid     = errors.New("trail amount must be positive")
)

// IcebergOrder extends Order with iceberg-specific fields
type IcebergOrder struct {
	*Order

	// TotalSize is the full hidden size of the order
	TotalSize uint64 `json:"totalSize"`

	// DisplaySize is the visible portion
	DisplaySize uint64 `json:"displaySize"`

	// RemainingHiddenSize is what's left in the hidden pool
	RemainingHiddenSize uint64 `json:"remainingHiddenSize"`

	// RefillCount tracks how many times the order has been refilled
	RefillCount int `json:"refillCount"`
}

// NewIcebergOrder creates a new iceberg order
func NewIcebergOrder(order *Order, displaySize uint64) (*IcebergOrder, error) {
	if displaySize > order.Quantity {
		return nil, ErrIcebergDisplayTooLarge
	}
	if displaySize == 0 {
		return nil, ErrIcebergDisplayTooSmall
	}

	return &IcebergOrder{
		Order:               order,
		TotalSize:           order.Quantity,
		DisplaySize:         displaySize,
		RemainingHiddenSize: order.Quantity - displaySize,
		RefillCount:         0,
	}, nil
}

// VisibleQuantity returns the quantity visible in the order book
func (io *IcebergOrder) VisibleQuantity() uint64 {
	remaining := io.RemainingQuantity()
	if remaining <= io.DisplaySize {
		return remaining
	}
	return io.DisplaySize
}

// NeedsRefill returns true if the visible portion is depleted but hidden remains
func (io *IcebergOrder) NeedsRefill() bool {
	// Current visible exhausted AND hidden pool has more
	return io.FilledQty > 0 && io.RemainingHiddenSize > 0
}

// Refill replenishes the visible portion from the hidden pool
func (io *IcebergOrder) Refill() uint64 {
	if io.RemainingHiddenSize == 0 {
		return 0
	}

	refillAmount := io.DisplaySize
	if refillAmount > io.RemainingHiddenSize {
		refillAmount = io.RemainingHiddenSize
	}

	io.RemainingHiddenSize -= refillAmount
	io.RefillCount++

	return refillAmount
}

// HiddenOrder represents a fully hidden order
type HiddenOrder struct {
	*Order

	// Hidden flag
	IsHidden bool `json:"isHidden"`

	// MinDisplayQuantity for partially hidden orders
	MinDisplayQuantity uint64 `json:"minDisplayQty"`
}

// NewHiddenOrder creates a new hidden order
func NewHiddenOrder(order *Order) *HiddenOrder {
	return &HiddenOrder{
		Order:    order,
		IsHidden: true,
	}
}

// PeggedOrder represents an order pegged to the best bid/ask
type PeggedOrder struct {
	*Order

	// PegType: "primary" (same side), "market" (opposite), "mid" (midpoint)
	PegType string `json:"pegType"`

	// PegOffset is the distance from the peg price (in price units)
	// Positive = more aggressive, Negative = less aggressive
	PegOffset int64 `json:"pegOffset"`

	// LastPegPrice tracks the last calculated peg price
	LastPegPrice uint64 `json:"lastPegPrice"`
}

// NewPeggedOrder creates a new pegged order
func NewPeggedOrder(order *Order, pegType string, pegOffset int64) (*PeggedOrder, error) {
	if pegType != "primary" && pegType != "market" && pegType != "mid" {
		return nil, ErrPegOffsetInvalid
	}

	return &PeggedOrder{
		Order:     order,
		PegType:   pegType,
		PegOffset: pegOffset,
	}, nil
}

// CalculatePegPrice determines the pegged price based on current market
func (po *PeggedOrder) CalculatePegPrice(bestBid, bestAsk uint64) uint64 {
	var basePrice uint64

	switch po.PegType {
	case "primary":
		// Same side as order
		if po.Side == Buy {
			basePrice = bestBid
		} else {
			basePrice = bestAsk
		}
	case "market":
		// Opposite side (more aggressive)
		if po.Side == Buy {
			basePrice = bestAsk
		} else {
			basePrice = bestBid
		}
	case "mid":
		// Midpoint
		if bestBid > 0 && bestAsk > 0 {
			basePrice = (bestBid + bestAsk) / 2
		}
	}

	// Apply offset
	if po.PegOffset >= 0 {
		basePrice += uint64(po.PegOffset)
	} else if uint64(-po.PegOffset) < basePrice {
		basePrice -= uint64(-po.PegOffset)
	} else {
		basePrice = 0
	}

	po.LastPegPrice = basePrice
	return basePrice
}

// TrailingStopOrder represents a trailing stop order
type TrailingStopOrder struct {
	*Order

	// TrailAmount is the fixed trailing distance
	TrailAmount uint64 `json:"trailAmount"`

	// TrailPercent is the percentage trailing distance (basis points)
	TrailPercent uint64 `json:"trailPercent"`

	// HighWaterMark is the best price seen (for sell stops)
	HighWaterMark uint64 `json:"highWaterMark"`

	// LowWaterMark is the best price seen (for buy stops)
	LowWaterMark uint64 `json:"lowWaterMark"`

	// Activated indicates the stop has been triggered
	Activated bool `json:"activated"`
}

// NewTrailingStopOrder creates a new trailing stop order
func NewTrailingStopOrder(order *Order, trailAmount, trailPercent uint64) (*TrailingStopOrder, error) {
	if trailAmount == 0 && trailPercent == 0 {
		return nil, ErrTrailAmountInvalid
	}

	tso := &TrailingStopOrder{
		Order:        order,
		TrailAmount:  trailAmount,
		TrailPercent: trailPercent,
	}

	// Initialize water marks
	if order.Side == Sell {
		tso.HighWaterMark = order.StopPrice + trailAmount
	} else {
		tso.LowWaterMark = order.StopPrice - trailAmount
	}

	return tso, nil
}

// UpdateTrailingPrice updates the stop price based on market movement
func (tso *TrailingStopOrder) UpdateTrailingPrice(currentPrice uint64) bool {
	if tso.Side == Sell {
		// For sell stops, we trail upward
		if currentPrice > tso.HighWaterMark {
			tso.HighWaterMark = currentPrice
			tso.StopPrice = tso.calculateStopPrice(currentPrice)
			return true
		}
	} else {
		// For buy stops, we trail downward
		if currentPrice < tso.LowWaterMark || tso.LowWaterMark == 0 {
			tso.LowWaterMark = currentPrice
			tso.StopPrice = tso.calculateStopPrice(currentPrice)
			return true
		}
	}
	return false
}

// calculateStopPrice calculates stop price based on trail settings
func (tso *TrailingStopOrder) calculateStopPrice(currentPrice uint64) uint64 {
	var trailDistance uint64

	if tso.TrailPercent > 0 {
		// Trail by percentage (basis points / 10000)
		trailDistance = (currentPrice * tso.TrailPercent) / 10000
	} else {
		trailDistance = tso.TrailAmount
	}

	if tso.Side == Sell {
		// Stop is below high water mark
		if trailDistance < currentPrice {
			return currentPrice - trailDistance
		}
		return 0
	}
	// Stop is above low water mark
	return currentPrice + trailDistance
}

// ShouldTrigger checks if the trailing stop should activate
func (tso *TrailingStopOrder) ShouldTrigger(currentPrice uint64) bool {
	if tso.Activated {
		return false // Already triggered
	}

	if tso.Side == Sell {
		// Sell stop triggers when price falls to stop level
		return currentPrice <= tso.StopPrice
	}
	// Buy stop triggers when price rises to stop level
	return currentPrice >= tso.StopPrice
}

// AdvancedOrderbook extends Orderbook with advanced order type support
type AdvancedOrderbook struct {
	*Orderbook

	// Iceberg order state
	icebergOrders map[ids.ID]*IcebergOrder

	// Hidden orders (not displayed in depth)
	hiddenOrders map[ids.ID]*HiddenOrder

	// Pegged orders (need price updates)
	peggedOrders map[ids.ID]*PeggedOrder

	// Trailing stop orders
	trailingStops map[ids.ID]*TrailingStopOrder

	// Sequence number for order priority
	sequenceNumber atomic.Uint64

	// Configuration
	allowHiddenOrders bool
	allowIceberg      bool
	maxIcebergRatio   float64 // Max hidden/visible ratio (e.g., 10.0 = 10:1)
}

// NewAdvancedOrderbook creates an orderbook with advanced order support
func NewAdvancedOrderbook(symbol string, allowHidden, allowIceberg bool) *AdvancedOrderbook {
	return &AdvancedOrderbook{
		Orderbook:         New(symbol),
		icebergOrders:     make(map[ids.ID]*IcebergOrder),
		hiddenOrders:      make(map[ids.ID]*HiddenOrder),
		peggedOrders:      make(map[ids.ID]*PeggedOrder),
		trailingStops:     make(map[ids.ID]*TrailingStopOrder),
		allowHiddenOrders: allowHidden,
		allowIceberg:      allowIceberg,
		maxIcebergRatio:   10.0,
	}
}

// AddIcebergOrder adds an iceberg order to the book
func (aob *AdvancedOrderbook) AddIcebergOrder(order *Order, displaySize uint64) ([]*Trade, error) {
	if !aob.allowIceberg {
		return nil, errors.New("iceberg orders not allowed")
	}

	iceberg, err := NewIcebergOrder(order, displaySize)
	if err != nil {
		return nil, err
	}

	// Store iceberg state
	aob.mu.Lock()
	aob.icebergOrders[order.ID] = iceberg
	aob.mu.Unlock()

	// Set visible quantity for matching
	order.Quantity = displaySize

	// Add to book
	trades, err := aob.AddOrder(order)
	if err != nil {
		return nil, err
	}

	// Check for refill
	aob.checkIcebergRefill(order.ID)

	return trades, nil
}

// checkIcebergRefill checks if an iceberg order needs refilling
func (aob *AdvancedOrderbook) checkIcebergRefill(orderID ids.ID) {
	aob.mu.Lock()
	defer aob.mu.Unlock()

	iceberg, exists := aob.icebergOrders[orderID]
	if !exists {
		return
	}

	order := iceberg.Order
	if order.RemainingQuantity() == 0 && iceberg.RemainingHiddenSize > 0 {
		// Refill the order
		refillAmount := iceberg.Refill()
		if refillAmount > 0 {
			// Reset order quantity and re-add to book
			order.Quantity = order.FilledQty + refillAmount
			order.Status = StatusOpen
			aob.addToBook(order)
		}
	}
}

// AddHiddenOrder adds a hidden order to the book
func (aob *AdvancedOrderbook) AddHiddenOrder(order *Order) ([]*Trade, error) {
	if !aob.allowHiddenOrders {
		return nil, ErrHiddenOrderNotAllowed
	}

	hidden := NewHiddenOrder(order)

	aob.mu.Lock()
	aob.hiddenOrders[order.ID] = hidden
	aob.mu.Unlock()

	// Hidden orders still participate in matching
	return aob.AddOrder(order)
}

// AddTrailingStop adds a trailing stop order
func (aob *AdvancedOrderbook) AddTrailingStop(order *Order, trailAmount, trailPercent uint64) error {
	tso, err := NewTrailingStopOrder(order, trailAmount, trailPercent)
	if err != nil {
		return err
	}

	aob.mu.Lock()
	aob.trailingStops[order.ID] = tso
	aob.mu.Unlock()

	return nil
}

// UpdateTrailingStops updates all trailing stop prices based on current market
func (aob *AdvancedOrderbook) UpdateTrailingStops(currentPrice uint64) []*Order {
	aob.mu.Lock()
	defer aob.mu.Unlock()

	var triggeredOrders []*Order

	for _, tso := range aob.trailingStops {
		// Update trailing price
		tso.UpdateTrailingPrice(currentPrice)

		// Check for trigger
		if tso.ShouldTrigger(currentPrice) {
			tso.Activated = true
			triggeredOrders = append(triggeredOrders, tso.Order)
		}
	}

	return triggeredOrders
}

// UpdatePeggedOrders updates all pegged order prices
func (aob *AdvancedOrderbook) UpdatePeggedOrders() {
	aob.mu.Lock()
	defer aob.mu.Unlock()

	for _, po := range aob.peggedOrders {
		newPrice := po.CalculatePegPrice(aob.bestBid, aob.bestAsk)
		if newPrice != po.Price && newPrice > 0 {
			// Remove from old price level
			aob.removeFromBook(po.Order)
			// Update price
			po.Price = newPrice
			// Add to new price level
			aob.addToBook(po.Order)
		}
	}
}

// GetDepthWithHidden returns depth including/excluding hidden orders
func (aob *AdvancedOrderbook) GetDepthWithHidden(maxLevels int, includeHidden bool) (bids, asks []*PriceLevel) {
	if includeHidden {
		return aob.GetDepth(maxLevels)
	}

	// Filter out hidden orders
	aob.mu.RLock()
	defer aob.mu.RUnlock()

	bidPrices := aob.getSortedPrices(aob.bids, false)
	askPrices := aob.getSortedPrices(aob.asks, true)

	for i, price := range bidPrices {
		if i >= maxLevels {
			break
		}
		level := aob.bids[price]
		visibleQty := aob.visibleQuantityAtLevel(level)
		if visibleQty > 0 {
			bids = append(bids, &PriceLevel{
				Price:    level.Price,
				Quantity: visibleQty,
			})
		}
	}

	for i, price := range askPrices {
		if i >= maxLevels {
			break
		}
		level := aob.asks[price]
		visibleQty := aob.visibleQuantityAtLevel(level)
		if visibleQty > 0 {
			asks = append(asks, &PriceLevel{
				Price:    level.Price,
				Quantity: visibleQty,
			})
		}
	}

	return bids, asks
}

// visibleQuantityAtLevel calculates visible quantity (excluding hidden orders)
func (aob *AdvancedOrderbook) visibleQuantityAtLevel(level *PriceLevel) uint64 {
	var visible uint64
	for _, order := range level.Orders {
		if _, isHidden := aob.hiddenOrders[order.ID]; !isHidden {
			visible += order.RemainingQuantity()
		}
	}
	return visible
}

// GetIcebergStats returns statistics about iceberg orders
func (aob *AdvancedOrderbook) GetIcebergStats() (count int, totalHidden uint64) {
	aob.mu.RLock()
	defer aob.mu.RUnlock()

	count = len(aob.icebergOrders)
	for _, iceberg := range aob.icebergOrders {
		totalHidden += iceberg.RemainingHiddenSize
	}
	return
}

// GetHiddenOrderCount returns the number of hidden orders
func (aob *AdvancedOrderbook) GetHiddenOrderCount() int {
	aob.mu.RLock()
	defer aob.mu.RUnlock()
	return len(aob.hiddenOrders)
}
