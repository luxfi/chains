// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package orderbook implements a high-performance order book for the DEX VM.
package orderbook

import (
	"errors"
	"sync"
	"time"

	"github.com/luxfi/ids"
)

var (
	ErrInsufficientLiquidity = errors.New("insufficient liquidity")
	ErrOrderNotFound         = errors.New("order not found")
	ErrInvalidPrice          = errors.New("invalid price")
	ErrInvalidQuantity       = errors.New("invalid quantity")
	ErrOrderExpired          = errors.New("order expired")
	ErrSelfTrade             = errors.New("self-trade not allowed")
)

// Side represents the order side (buy or sell).
type Side uint8

const (
	Buy Side = iota
	Sell
)

func (s Side) String() string {
	if s == Buy {
		return "buy"
	}
	return "sell"
}

// OrderType represents the type of order.
type OrderType uint8

const (
	Limit OrderType = iota
	Market
	StopLoss
	TakeProfit
	StopLimit
)

func (t OrderType) String() string {
	switch t {
	case Limit:
		return "limit"
	case Market:
		return "market"
	case StopLoss:
		return "stop_loss"
	case TakeProfit:
		return "take_profit"
	case StopLimit:
		return "stop_limit"
	default:
		return "unknown"
	}
}

// OrderStatus represents the status of an order.
type OrderStatus uint8

const (
	StatusOpen OrderStatus = iota
	StatusPartiallyFilled
	StatusFilled
	StatusCancelled
	StatusExpired
)

func (s OrderStatus) String() string {
	switch s {
	case StatusOpen:
		return "open"
	case StatusPartiallyFilled:
		return "partially_filled"
	case StatusFilled:
		return "filled"
	case StatusCancelled:
		return "cancelled"
	case StatusExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// Order represents a trading order in the orderbook.
type Order struct {
	ID          ids.ID      `json:"id"`
	Owner       ids.ShortID `json:"owner"`
	Symbol      string      `json:"symbol"`
	Side        Side        `json:"side"`
	Type        OrderType   `json:"type"`
	Price       uint64      `json:"price"`     // Price in quote asset (scaled by 1e18)
	Quantity    uint64      `json:"quantity"`  // Quantity in base asset (scaled by 1e18)
	FilledQty   uint64      `json:"filledQty"` // Already filled quantity
	StopPrice   uint64      `json:"stopPrice"` // For stop orders
	Status      OrderStatus `json:"status"`
	CreatedAt   int64       `json:"createdAt"`   // Unix timestamp in nanoseconds
	ExpiresAt   int64       `json:"expiresAt"`   // Unix timestamp in nanoseconds
	PostOnly    bool        `json:"postOnly"`    // Only add liquidity
	ReduceOnly  bool        `json:"reduceOnly"`  // Only reduce position
	TimeInForce string      `json:"timeInForce"` // GTC, IOC, FOK
}

// RemainingQuantity returns the unfilled quantity.
func (o *Order) RemainingQuantity() uint64 {
	return o.Quantity - o.FilledQty
}

// IsActive returns true if the order can still be filled.
func (o *Order) IsActive() bool {
	return o.Status == StatusOpen || o.Status == StatusPartiallyFilled
}

// PriceLevel represents a price level in the orderbook with aggregated quantity.
type PriceLevel struct {
	Price    uint64   `json:"price"`
	Quantity uint64   `json:"quantity"`
	Orders   []*Order `json:"-"` // Orders at this level
}

// Trade represents a filled trade between two orders.
type Trade struct {
	ID          ids.ID      `json:"id"`
	Symbol      string      `json:"symbol"`
	MakerOrder  ids.ID      `json:"makerOrder"`
	TakerOrder  ids.ID      `json:"takerOrder"`
	Maker       ids.ShortID `json:"maker"`
	Taker       ids.ShortID `json:"taker"`
	Side        Side        `json:"side"`        // Taker's side
	Price       uint64      `json:"price"`       // Execution price
	Quantity    uint64      `json:"quantity"`    // Filled quantity
	MakerFee    uint64      `json:"makerFee"`    // Fee paid by maker
	TakerFee    uint64      `json:"takerFee"`    // Fee paid by taker
	Timestamp   int64       `json:"timestamp"`   // Execution timestamp
	BlockNumber uint64      `json:"blockNumber"` // Block where trade occurred
}

// Orderbook maintains the bid and ask sides for a trading pair.
type Orderbook struct {
	mu     sync.RWMutex
	symbol string

	// Price -> PriceLevel mapping
	bids map[uint64]*PriceLevel // Buy orders (sorted descending)
	asks map[uint64]*PriceLevel // Sell orders (sorted ascending)

	// Order ID -> Order mapping for fast lookup
	orders map[ids.ID]*Order

	// Best bid/ask prices for fast access
	bestBid uint64
	bestAsk uint64

	// Statistics
	totalVolume   uint64
	tradeCount    uint64
	lastTradeTime int64
}

// New creates a new orderbook for the given symbol.
func New(symbol string) *Orderbook {
	return &Orderbook{
		symbol: symbol,
		bids:   make(map[uint64]*PriceLevel),
		asks:   make(map[uint64]*PriceLevel),
		orders: make(map[ids.ID]*Order),
	}
}

// Symbol returns the trading pair symbol.
func (ob *Orderbook) Symbol() string {
	return ob.symbol
}

// AddOrder adds a new order to the orderbook.
// Returns executed trades if the order is matched.
func (ob *Orderbook) AddOrder(order *Order) ([]*Trade, error) {
	ob.mu.Lock()
	defer ob.mu.Unlock()

	// Validate order
	if order.Price == 0 && order.Type == Limit {
		return nil, ErrInvalidPrice
	}
	if order.Quantity == 0 {
		return nil, ErrInvalidQuantity
	}
	if order.ExpiresAt > 0 && order.ExpiresAt < time.Now().UnixNano() {
		return nil, ErrOrderExpired
	}

	var trades []*Trade

	// Try to match the order
	if order.Type == Market || order.Type == Limit {
		trades = ob.matchOrder(order)
	}

	// If order still has remaining quantity and is not IOC/FOK, add to book
	if order.RemainingQuantity() > 0 && order.TimeInForce != "IOC" {
		if order.TimeInForce == "FOK" && order.FilledQty > 0 {
			// FOK orders must be completely filled
			order.Status = StatusCancelled
		} else if !order.PostOnly || len(trades) == 0 {
			ob.addToBook(order)
		}
	}

	return trades, nil
}

// matchOrder attempts to match an incoming order against the book.
func (ob *Orderbook) matchOrder(order *Order) []*Trade {
	var trades []*Trade
	var oppositeSide map[uint64]*PriceLevel
	var priceCheck func(orderPrice, bookPrice uint64) bool

	if order.Side == Buy {
		oppositeSide = ob.asks
		priceCheck = func(orderPrice, bookPrice uint64) bool {
			return order.Type == Market || orderPrice >= bookPrice
		}
	} else {
		oppositeSide = ob.bids
		priceCheck = func(orderPrice, bookPrice uint64) bool {
			return order.Type == Market || orderPrice <= bookPrice
		}
	}

	// Sort price levels (we need to iterate in order)
	sortedPrices := ob.getSortedPrices(oppositeSide, order.Side == Buy)

	for _, price := range sortedPrices {
		if order.RemainingQuantity() == 0 {
			break
		}

		if !priceCheck(order.Price, price) {
			break
		}

		level := oppositeSide[price]
		for _, makerOrder := range level.Orders {
			if order.RemainingQuantity() == 0 {
				break
			}

			// Prevent self-trading
			if makerOrder.Owner == order.Owner {
				continue
			}

			// Calculate fill quantity
			fillQty := min(order.RemainingQuantity(), makerOrder.RemainingQuantity())

			// Create trade
			trade := &Trade{
				ID:         ids.GenerateTestID(), // In production, use proper ID generation
				Symbol:     ob.symbol,
				MakerOrder: makerOrder.ID,
				TakerOrder: order.ID,
				Maker:      makerOrder.Owner,
				Taker:      order.Owner,
				Side:       order.Side,
				Price:      price,
				Quantity:   fillQty,
				Timestamp:  time.Now().UnixNano(),
			}
			trades = append(trades, trade)

			// Update orders
			order.FilledQty += fillQty
			makerOrder.FilledQty += fillQty

			if makerOrder.RemainingQuantity() == 0 {
				makerOrder.Status = StatusFilled
				ob.removeFromBook(makerOrder)
			} else {
				makerOrder.Status = StatusPartiallyFilled
			}

			// Update statistics
			ob.totalVolume += fillQty
			ob.tradeCount++
			ob.lastTradeTime = trade.Timestamp
		}
	}

	// Update order status
	if order.FilledQty > 0 {
		if order.RemainingQuantity() == 0 {
			order.Status = StatusFilled
		} else {
			order.Status = StatusPartiallyFilled
		}
	}

	return trades
}

// addToBook adds an order to the appropriate side of the book.
func (ob *Orderbook) addToBook(order *Order) {
	var side map[uint64]*PriceLevel
	if order.Side == Buy {
		side = ob.bids
	} else {
		side = ob.asks
	}

	level, exists := side[order.Price]
	if !exists {
		level = &PriceLevel{
			Price:  order.Price,
			Orders: make([]*Order, 0, 16),
		}
		side[order.Price] = level
	}

	level.Orders = append(level.Orders, order)
	level.Quantity += order.RemainingQuantity()
	ob.orders[order.ID] = order

	// Update best bid/ask
	if order.Side == Buy {
		if order.Price > ob.bestBid {
			ob.bestBid = order.Price
		}
	} else {
		if ob.bestAsk == 0 || order.Price < ob.bestAsk {
			ob.bestAsk = order.Price
		}
	}
}

// removeFromBook removes an order from the book.
func (ob *Orderbook) removeFromBook(order *Order) {
	var side map[uint64]*PriceLevel
	if order.Side == Buy {
		side = ob.bids
	} else {
		side = ob.asks
	}

	level, exists := side[order.Price]
	if !exists {
		return
	}

	// Remove order from level
	for i, o := range level.Orders {
		if o.ID == order.ID {
			level.Orders = append(level.Orders[:i], level.Orders[i+1:]...)
			level.Quantity -= order.RemainingQuantity()
			break
		}
	}

	// Remove level if empty
	if len(level.Orders) == 0 {
		delete(side, order.Price)
	}

	delete(ob.orders, order.ID)

	// Recalculate best bid/ask if needed
	if order.Side == Buy && order.Price == ob.bestBid {
		ob.recalculateBestBid()
	} else if order.Side == Sell && order.Price == ob.bestAsk {
		ob.recalculateBestAsk()
	}
}

// CancelOrder cancels an order by ID.
func (ob *Orderbook) CancelOrder(orderID ids.ID) error {
	ob.mu.Lock()
	defer ob.mu.Unlock()

	order, exists := ob.orders[orderID]
	if !exists {
		return ErrOrderNotFound
	}

	order.Status = StatusCancelled
	ob.removeFromBook(order)
	return nil
}

// GetOrder returns an order by ID.
func (ob *Orderbook) GetOrder(orderID ids.ID) (*Order, error) {
	ob.mu.RLock()
	defer ob.mu.RUnlock()

	order, exists := ob.orders[orderID]
	if !exists {
		return nil, ErrOrderNotFound
	}
	return order, nil
}

// GetBestBid returns the best (highest) bid price.
func (ob *Orderbook) GetBestBid() uint64 {
	ob.mu.RLock()
	defer ob.mu.RUnlock()
	return ob.bestBid
}

// GetBestAsk returns the best (lowest) ask price.
func (ob *Orderbook) GetBestAsk() uint64 {
	ob.mu.RLock()
	defer ob.mu.RUnlock()
	return ob.bestAsk
}

// GetSpread returns the bid-ask spread.
func (ob *Orderbook) GetSpread() uint64 {
	ob.mu.RLock()
	defer ob.mu.RUnlock()
	if ob.bestBid == 0 || ob.bestAsk == 0 {
		return 0
	}
	return ob.bestAsk - ob.bestBid
}

// GetMidPrice returns the mid-market price.
func (ob *Orderbook) GetMidPrice() uint64 {
	ob.mu.RLock()
	defer ob.mu.RUnlock()
	if ob.bestBid == 0 || ob.bestAsk == 0 {
		return 0
	}
	return (ob.bestBid + ob.bestAsk) / 2
}

// GetDepth returns the orderbook depth up to maxLevels.
func (ob *Orderbook) GetDepth(maxLevels int) (bids, asks []*PriceLevel) {
	ob.mu.RLock()
	defer ob.mu.RUnlock()

	bidPrices := ob.getSortedPrices(ob.bids, false) // Descending
	askPrices := ob.getSortedPrices(ob.asks, true)  // Ascending

	for i, price := range bidPrices {
		if i >= maxLevels {
			break
		}
		level := ob.bids[price]
		bids = append(bids, &PriceLevel{
			Price:    level.Price,
			Quantity: level.Quantity,
		})
	}

	for i, price := range askPrices {
		if i >= maxLevels {
			break
		}
		level := ob.asks[price]
		asks = append(asks, &PriceLevel{
			Price:    level.Price,
			Quantity: level.Quantity,
		})
	}

	return bids, asks
}

// GetStats returns orderbook statistics.
func (ob *Orderbook) GetStats() (totalVolume, tradeCount uint64, lastTradeTime int64) {
	ob.mu.RLock()
	defer ob.mu.RUnlock()
	return ob.totalVolume, ob.tradeCount, ob.lastTradeTime
}

// Match runs the matching engine and returns all trades from crossed orders.
// This is called per-block for deterministic matching.
// It processes all resting orders that can cross with each other.
func (ob *Orderbook) Match() []Trade {
	ob.mu.Lock()
	defer ob.mu.Unlock()

	var trades []Trade

	// Continue matching while there are crossed orders (bid >= ask)
	for ob.bestBid > 0 && ob.bestAsk > 0 && ob.bestBid >= ob.bestAsk {
		bidLevel := ob.bids[ob.bestBid]
		askLevel := ob.asks[ob.bestAsk]

		if bidLevel == nil || askLevel == nil || len(bidLevel.Orders) == 0 || len(askLevel.Orders) == 0 {
			break
		}

		// Match orders FIFO within price levels
		for len(bidLevel.Orders) > 0 && len(askLevel.Orders) > 0 {
			bidOrder := bidLevel.Orders[0]
			askOrder := askLevel.Orders[0]

			// Prevent self-trading
			if bidOrder.Owner == askOrder.Owner {
				// Remove one of them (taker is the newer order)
				if bidOrder.CreatedAt > askOrder.CreatedAt {
					bidOrder.Status = StatusCancelled
					ob.removeOrderFromLevel(bidLevel, 0, bidOrder.RemainingQuantity())
					delete(ob.orders, bidOrder.ID)
				} else {
					askOrder.Status = StatusCancelled
					ob.removeOrderFromLevel(askLevel, 0, askOrder.RemainingQuantity())
					delete(ob.orders, askOrder.ID)
				}
				continue
			}

			// Calculate fill quantity
			fillQty := min(bidOrder.RemainingQuantity(), askOrder.RemainingQuantity())

			// Price is the maker's price (older order - price-time priority)
			var execPrice uint64
			if bidOrder.CreatedAt < askOrder.CreatedAt {
				execPrice = bidOrder.Price // Bid was resting
			} else {
				execPrice = askOrder.Price // Ask was resting
			}

			// Create trade
			trade := Trade{
				ID:         ids.GenerateTestID(),
				Symbol:     ob.symbol,
				MakerOrder: bidOrder.ID, // Can be either, simplified
				TakerOrder: askOrder.ID,
				Maker:      bidOrder.Owner,
				Taker:      askOrder.Owner,
				Side:       Sell, // Ask order is taker
				Price:      execPrice,
				Quantity:   fillQty,
				Timestamp:  time.Now().UnixNano(),
			}
			trades = append(trades, trade)

			// Update orders
			bidOrder.FilledQty += fillQty
			askOrder.FilledQty += fillQty

			// Update statistics
			ob.totalVolume += fillQty
			ob.tradeCount++
			ob.lastTradeTime = trade.Timestamp

			// Remove filled orders
			if bidOrder.RemainingQuantity() == 0 {
				bidOrder.Status = StatusFilled
				ob.removeOrderFromLevel(bidLevel, 0, 0)
				delete(ob.orders, bidOrder.ID)
			} else {
				bidOrder.Status = StatusPartiallyFilled
				bidLevel.Quantity -= fillQty
			}

			if askOrder.RemainingQuantity() == 0 {
				askOrder.Status = StatusFilled
				ob.removeOrderFromLevel(askLevel, 0, 0)
				delete(ob.orders, askOrder.ID)
			} else {
				askOrder.Status = StatusPartiallyFilled
				askLevel.Quantity -= fillQty
			}
		}

		// Remove empty price levels
		if len(bidLevel.Orders) == 0 {
			delete(ob.bids, ob.bestBid)
			ob.recalculateBestBid()
		}
		if len(askLevel.Orders) == 0 {
			delete(ob.asks, ob.bestAsk)
			ob.recalculateBestAsk()
		}
	}

	return trades
}

// removeOrderFromLevel removes an order from a price level by index.
func (ob *Orderbook) removeOrderFromLevel(level *PriceLevel, index int, subtractQty uint64) {
	if index < len(level.Orders) {
		level.Orders = append(level.Orders[:index], level.Orders[index+1:]...)
		level.Quantity -= subtractQty
	}
}

// recalculateBestBid finds the new best bid price.
func (ob *Orderbook) recalculateBestBid() {
	ob.bestBid = 0
	for price := range ob.bids {
		if price > ob.bestBid {
			ob.bestBid = price
		}
	}
}

// recalculateBestAsk finds the new best ask price.
func (ob *Orderbook) recalculateBestAsk() {
	ob.bestAsk = 0
	for price := range ob.asks {
		if ob.bestAsk == 0 || price < ob.bestAsk {
			ob.bestAsk = price
		}
	}
}

// getSortedPrices returns sorted price levels.
func (ob *Orderbook) getSortedPrices(side map[uint64]*PriceLevel, ascending bool) []uint64 {
	prices := make([]uint64, 0, len(side))
	for price := range side {
		prices = append(prices, price)
	}

	// Simple insertion sort for small arrays (usually < 100 levels)
	for i := 1; i < len(prices); i++ {
		key := prices[i]
		j := i - 1
		if ascending {
			for j >= 0 && prices[j] > key {
				prices[j+1] = prices[j]
				j--
			}
		} else {
			for j >= 0 && prices[j] < key {
				prices[j+1] = prices[j]
				j--
			}
		}
		prices[j+1] = key
	}

	return prices
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
