// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package orderbook

import (
	"errors"
	"sort"
	"sync"

	"github.com/luxfi/ids"
)

var (
	ErrStopPriceRequired = errors.New("stop price required for stop orders")
	ErrStopOrderNotFound = errors.New("stop order not found")
	ErrStopAlreadyActive = errors.New("stop order already triggered")
)

// TriggerType defines how the stop is triggered
type TriggerType uint8

const (
	TriggerOnLastPrice  TriggerType = iota // Last traded price
	TriggerOnMarkPrice                     // Mark price (index/oracle)
	TriggerOnIndexPrice                    // Index price only
)

// StopOrder represents a stop order waiting to be triggered
type StopOrder struct {
	*Order

	// TriggerType defines the price type that triggers this stop
	TriggerType TriggerType `json:"triggerType"`

	// LimitPrice for stop-limit orders (0 = market order when triggered)
	LimitPrice uint64 `json:"limitPrice"`

	// TriggeredPrice is the price that caused the trigger
	TriggeredPrice uint64 `json:"triggeredPrice"`

	// Triggered indicates the stop has been activated
	Triggered bool `json:"triggered"`

	// TriggeredAt is the timestamp when triggered
	TriggeredAt int64 `json:"triggeredAt"`
}

// NewStopOrder creates a new stop order
func NewStopOrder(order *Order, triggerType TriggerType, limitPrice uint64) (*StopOrder, error) {
	if order.StopPrice == 0 {
		return nil, ErrStopPriceRequired
	}

	return &StopOrder{
		Order:       order,
		TriggerType: triggerType,
		LimitPrice:  limitPrice,
	}, nil
}

// IsStopLimit returns true if this is a stop-limit order
func (so *StopOrder) IsStopLimit() bool {
	return so.LimitPrice > 0
}

// ShouldTrigger checks if the stop should be triggered at the given price
func (so *StopOrder) ShouldTrigger(price uint64) bool {
	if so.Triggered {
		return false
	}

	switch so.Side {
	case Buy:
		// Buy stop triggers when price rises above stop price
		return price >= so.StopPrice
	case Sell:
		// Sell stop triggers when price falls below stop price
		return price <= so.StopPrice
	}
	return false
}

// StopEngine manages stop orders and triggers them based on price movements
type StopEngine struct {
	mu sync.RWMutex

	// Stop orders indexed by symbol
	stopOrders map[string]map[ids.ID]*StopOrder

	// Sorted stop prices for efficient triggering
	// buyStops[symbol] = sorted ascending (trigger when price >= stop)
	// sellStops[symbol] = sorted descending (trigger when price <= stop)
	buyStops  map[string][]uint64
	sellStops map[string][]uint64

	// Order ID to symbol mapping for fast lookup
	orderSymbols map[ids.ID]string

	// Callback for triggered orders
	onTrigger func(order *StopOrder)
}

// NewStopEngine creates a new stop order engine
func NewStopEngine() *StopEngine {
	return &StopEngine{
		stopOrders:   make(map[string]map[ids.ID]*StopOrder),
		buyStops:     make(map[string][]uint64),
		sellStops:    make(map[string][]uint64),
		orderSymbols: make(map[ids.ID]string),
	}
}

// SetTriggerCallback sets the callback for when stops are triggered
func (se *StopEngine) SetTriggerCallback(callback func(order *StopOrder)) {
	se.onTrigger = callback
}

// AddStopOrder adds a stop order to the engine
func (se *StopEngine) AddStopOrder(order *Order, triggerType TriggerType, limitPrice uint64) error {
	stopOrder, err := NewStopOrder(order, triggerType, limitPrice)
	if err != nil {
		return err
	}

	se.mu.Lock()
	defer se.mu.Unlock()

	symbol := order.Symbol

	// Initialize symbol maps if needed
	if se.stopOrders[symbol] == nil {
		se.stopOrders[symbol] = make(map[ids.ID]*StopOrder)
	}

	// Add the stop order
	se.stopOrders[symbol][order.ID] = stopOrder
	se.orderSymbols[order.ID] = symbol

	// Update sorted price arrays
	if order.Side == Buy {
		se.buyStops[symbol] = se.insertSorted(se.buyStops[symbol], order.StopPrice, true)
	} else {
		se.sellStops[symbol] = se.insertSorted(se.sellStops[symbol], order.StopPrice, false)
	}

	return nil
}

// RemoveStopOrder removes a stop order from the engine
func (se *StopEngine) RemoveStopOrder(orderID ids.ID) error {
	se.mu.Lock()
	defer se.mu.Unlock()

	symbol, exists := se.orderSymbols[orderID]
	if !exists {
		return ErrStopOrderNotFound
	}

	stopOrder := se.stopOrders[symbol][orderID]
	if stopOrder == nil {
		return ErrStopOrderNotFound
	}

	// Remove from stop orders map
	delete(se.stopOrders[symbol], orderID)
	delete(se.orderSymbols, orderID)

	// Remove from sorted arrays
	if stopOrder.Side == Buy {
		se.buyStops[symbol] = se.removePrice(se.buyStops[symbol], stopOrder.StopPrice)
	} else {
		se.sellStops[symbol] = se.removePrice(se.sellStops[symbol], stopOrder.StopPrice)
	}

	return nil
}

// UpdatePrice updates the price and triggers any stops
func (se *StopEngine) UpdatePrice(symbol string, lastPrice, markPrice, indexPrice uint64) []*StopOrder {
	se.mu.Lock()
	defer se.mu.Unlock()

	var triggered []*StopOrder

	stops := se.stopOrders[symbol]
	if stops == nil {
		return nil
	}

	for _, stopOrder := range stops {
		if stopOrder.Triggered {
			continue
		}

		// Get the relevant price based on trigger type
		var triggerPrice uint64
		switch stopOrder.TriggerType {
		case TriggerOnLastPrice:
			triggerPrice = lastPrice
		case TriggerOnMarkPrice:
			triggerPrice = markPrice
		case TriggerOnIndexPrice:
			triggerPrice = indexPrice
		}

		if stopOrder.ShouldTrigger(triggerPrice) {
			stopOrder.Triggered = true
			stopOrder.TriggeredPrice = triggerPrice
			triggered = append(triggered, stopOrder)

			if se.onTrigger != nil {
				se.onTrigger(stopOrder)
			}
		}
	}

	return triggered
}

// CheckStops checks all stops against a single price (simpler version)
func (se *StopEngine) CheckStops(symbol string, price uint64) []*StopOrder {
	return se.UpdatePrice(symbol, price, price, price)
}

// GetStopOrder returns a stop order by ID
func (se *StopEngine) GetStopOrder(orderID ids.ID) (*StopOrder, error) {
	se.mu.RLock()
	defer se.mu.RUnlock()

	symbol, exists := se.orderSymbols[orderID]
	if !exists {
		return nil, ErrStopOrderNotFound
	}

	stopOrder := se.stopOrders[symbol][orderID]
	if stopOrder == nil {
		return nil, ErrStopOrderNotFound
	}

	return stopOrder, nil
}

// GetStopsBySymbol returns all stop orders for a symbol
func (se *StopEngine) GetStopsBySymbol(symbol string) []*StopOrder {
	se.mu.RLock()
	defer se.mu.RUnlock()

	stops := se.stopOrders[symbol]
	result := make([]*StopOrder, 0, len(stops))
	for _, stop := range stops {
		result = append(result, stop)
	}
	return result
}

// GetPendingStops returns all non-triggered stops for a symbol
func (se *StopEngine) GetPendingStops(symbol string) []*StopOrder {
	se.mu.RLock()
	defer se.mu.RUnlock()

	stops := se.stopOrders[symbol]
	var pending []*StopOrder
	for _, stop := range stops {
		if !stop.Triggered {
			pending = append(pending, stop)
		}
	}
	return pending
}

// GetNextTriggerPrice returns the next stop price that would trigger
// Returns (price, side, exists)
func (se *StopEngine) GetNextTriggerPrice(symbol string, currentPrice uint64) (uint64, Side, bool) {
	se.mu.RLock()
	defer se.mu.RUnlock()

	// Check buy stops (price rises above stop)
	buyStops := se.buyStops[symbol]
	for _, stopPrice := range buyStops {
		if stopPrice > currentPrice {
			// This stop hasn't triggered yet
			return stopPrice, Buy, true
		}
	}

	// Check sell stops (price falls below stop)
	sellStops := se.sellStops[symbol]
	for _, stopPrice := range sellStops {
		if stopPrice < currentPrice {
			// This stop hasn't triggered yet
			return stopPrice, Sell, true
		}
	}

	return 0, Buy, false
}

// GetStats returns engine statistics
func (se *StopEngine) GetStats() (totalStops, pendingStops, triggeredStops int) {
	se.mu.RLock()
	defer se.mu.RUnlock()

	for _, stops := range se.stopOrders {
		for _, stop := range stops {
			totalStops++
			if stop.Triggered {
				triggeredStops++
			} else {
				pendingStops++
			}
		}
	}
	return
}

// ClearTriggered removes all triggered stop orders
func (se *StopEngine) ClearTriggered() int {
	se.mu.Lock()
	defer se.mu.Unlock()

	count := 0
	for symbol, stops := range se.stopOrders {
		for id, stop := range stops {
			if stop.Triggered {
				delete(stops, id)
				delete(se.orderSymbols, id)
				count++
			}
		}
		// Clean up empty symbol maps
		if len(stops) == 0 {
			delete(se.stopOrders, symbol)
		}
	}
	return count
}

// insertSorted inserts a price into a sorted slice
// ascending=true for buy stops, false for sell stops
func (se *StopEngine) insertSorted(prices []uint64, price uint64, ascending bool) []uint64 {
	n := len(prices)
	i := sort.Search(n, func(i int) bool {
		if ascending {
			return prices[i] >= price
		}
		return prices[i] <= price
	})

	// Insert at position i
	prices = append(prices, 0)
	copy(prices[i+1:], prices[i:])
	prices[i] = price
	return prices
}

// removePrice removes a price from a sorted slice
func (se *StopEngine) removePrice(prices []uint64, price uint64) []uint64 {
	for i, p := range prices {
		if p == price {
			return append(prices[:i], prices[i+1:]...)
		}
	}
	return prices
}

// OCOOrder represents a One-Cancels-Other order pair
type OCOOrder struct {
	ID          ids.ID      `json:"id"`
	PrimaryID   ids.ID      `json:"primaryId"`   // The limit order
	SecondaryID ids.ID      `json:"secondaryId"` // The stop order
	Symbol      string      `json:"symbol"`
	Owner       ids.ShortID `json:"owner"`
	Status      string      `json:"status"` // "active", "triggered", "cancelled"
}

// OCOEngine manages OCO (One-Cancels-Other) order pairs
type OCOEngine struct {
	mu sync.RWMutex

	// OCO pairs by ID
	ocoOrders map[ids.ID]*OCOOrder

	// Order ID to OCO ID mapping
	orderToOCO map[ids.ID]ids.ID

	// Callbacks
	onCancel func(orderID ids.ID) error
}

// NewOCOEngine creates a new OCO engine
func NewOCOEngine(cancelCallback func(orderID ids.ID) error) *OCOEngine {
	return &OCOEngine{
		ocoOrders:  make(map[ids.ID]*OCOOrder),
		orderToOCO: make(map[ids.ID]ids.ID),
		onCancel:   cancelCallback,
	}
}

// CreateOCO creates a new OCO pair
func (oe *OCOEngine) CreateOCO(primaryID, secondaryID ids.ID, symbol string, owner ids.ShortID) (*OCOOrder, error) {
	oe.mu.Lock()
	defer oe.mu.Unlock()

	oco := &OCOOrder{
		ID:          ids.GenerateTestID(),
		PrimaryID:   primaryID,
		SecondaryID: secondaryID,
		Symbol:      symbol,
		Owner:       owner,
		Status:      "active",
	}

	oe.ocoOrders[oco.ID] = oco
	oe.orderToOCO[primaryID] = oco.ID
	oe.orderToOCO[secondaryID] = oco.ID

	return oco, nil
}

// OnOrderFilled handles when one side of an OCO is filled/triggered
func (oe *OCOEngine) OnOrderFilled(orderID ids.ID) error {
	oe.mu.Lock()
	defer oe.mu.Unlock()

	ocoID, exists := oe.orderToOCO[orderID]
	if !exists {
		return nil // Not part of an OCO
	}

	oco := oe.ocoOrders[ocoID]
	if oco == nil || oco.Status != "active" {
		return nil
	}

	oco.Status = "triggered"

	// Cancel the other order
	var otherID ids.ID
	if orderID == oco.PrimaryID {
		otherID = oco.SecondaryID
	} else {
		otherID = oco.PrimaryID
	}

	if oe.onCancel != nil {
		return oe.onCancel(otherID)
	}
	return nil
}

// CancelOCO cancels both sides of an OCO
func (oe *OCOEngine) CancelOCO(ocoID ids.ID) error {
	oe.mu.Lock()
	defer oe.mu.Unlock()

	oco, exists := oe.ocoOrders[ocoID]
	if !exists {
		return errors.New("OCO not found")
	}

	oco.Status = "cancelled"

	// Cancel both orders
	if oe.onCancel != nil {
		if err := oe.onCancel(oco.PrimaryID); err != nil {
			return err
		}
		if err := oe.onCancel(oco.SecondaryID); err != nil {
			return err
		}
	}

	return nil
}

// GetOCO returns an OCO by ID
func (oe *OCOEngine) GetOCO(ocoID ids.ID) *OCOOrder {
	oe.mu.RLock()
	defer oe.mu.RUnlock()
	return oe.ocoOrders[ocoID]
}

// GetOCOByOrder returns the OCO containing a specific order
func (oe *OCOEngine) GetOCOByOrder(orderID ids.ID) *OCOOrder {
	oe.mu.RLock()
	defer oe.mu.RUnlock()

	ocoID, exists := oe.orderToOCO[orderID]
	if !exists {
		return nil
	}
	return oe.ocoOrders[ocoID]
}
