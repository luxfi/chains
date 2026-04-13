// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package oracle provides price oracle implementations for the DEX VM.
package oracle

import (
	"errors"
	"math/big"
	"sync"
	"time"
)

var (
	// ErrNoObservations indicates no price observations are available.
	ErrNoObservations = errors.New("no price observations available")

	// ErrInsufficientHistory indicates not enough history for TWAP calculation.
	ErrInsufficientHistory = errors.New("insufficient price history for TWAP")

	// ErrInvalidWindow indicates an invalid TWAP window duration.
	ErrInvalidWindow = errors.New("TWAP window must be positive")

	// DefaultTWAPWindow is the default TWAP calculation window.
	DefaultTWAPWindow = 30 * time.Minute

	// MinTWAPWindow is the minimum allowed TWAP window.
	MinTWAPWindow = 5 * time.Minute

	// MaxObservations is the maximum number of observations to keep.
	MaxObservations = 1000

	// PrecisionFactor for price calculations (1e18).
	PrecisionFactor = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
)

// PricePoint represents a single price observation at a specific time.
type PricePoint struct {
	Price     *big.Int  // Price scaled by PrecisionFactor
	Timestamp time.Time // When the price was observed
}

// TWAP implements a time-weighted average price oracle.
// It maintains a rolling window of price observations and calculates
// the time-weighted average to resist price manipulation.
type TWAP struct {
	mu           sync.RWMutex
	observations []PricePoint
	window       time.Duration
	market       string
}

// NewTWAP creates a new TWAP oracle with the specified window duration.
func NewTWAP(market string, window time.Duration) (*TWAP, error) {
	if window <= 0 {
		return nil, ErrInvalidWindow
	}
	if window < MinTWAPWindow {
		window = MinTWAPWindow
	}
	return &TWAP{
		observations: make([]PricePoint, 0, 64),
		window:       window,
		market:       market,
	}, nil
}

// NewDefaultTWAP creates a TWAP oracle with the default 30-minute window.
func NewDefaultTWAP(market string) *TWAP {
	twap, _ := NewTWAP(market, DefaultTWAPWindow)
	return twap
}

// Record adds a new price observation.
func (t *TWAP) Record(price *big.Int, timestamp time.Time) {
	if price == nil || price.Sign() <= 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Add new observation
	t.observations = append(t.observations, PricePoint{
		Price:     new(big.Int).Set(price),
		Timestamp: timestamp,
	})

	// Prune old observations beyond window + buffer
	t.pruneOldObservations(timestamp)
}

// RecordNow adds a new price observation with the current time.
func (t *TWAP) RecordNow(price *big.Int) {
	t.Record(price, time.Now())
}

// pruneOldObservations removes observations older than 2x the window.
// Must be called with lock held.
func (t *TWAP) pruneOldObservations(now time.Time) {
	cutoff := now.Add(-2 * t.window)

	// Find first observation that's within the window
	startIdx := 0
	for i, obs := range t.observations {
		if obs.Timestamp.After(cutoff) {
			startIdx = i
			break
		}
		startIdx = i + 1
	}

	// Prune old observations
	if startIdx > 0 && startIdx < len(t.observations) {
		copy(t.observations, t.observations[startIdx:])
		t.observations = t.observations[:len(t.observations)-startIdx]
	} else if startIdx >= len(t.observations) {
		t.observations = t.observations[:0]
	}

	// Also limit total observations
	if len(t.observations) > MaxObservations {
		excess := len(t.observations) - MaxObservations
		copy(t.observations, t.observations[excess:])
		t.observations = t.observations[:MaxObservations]
	}
}

// GetPrice returns the time-weighted average price over the configured window.
// This is the primary method for getting manipulation-resistant prices.
func (t *TWAP) GetPrice() (*big.Int, error) {
	return t.GetPriceAt(time.Now())
}

// GetPriceAt returns the TWAP calculated at a specific point in time.
func (t *TWAP) GetPriceAt(at time.Time) (*big.Int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.observations) == 0 {
		return nil, ErrNoObservations
	}

	windowStart := at.Add(-t.window)

	// Find relevant observations
	var relevantObs []PricePoint
	for _, obs := range t.observations {
		if obs.Timestamp.After(windowStart) && !obs.Timestamp.After(at) {
			relevantObs = append(relevantObs, obs)
		}
	}

	if len(relevantObs) == 0 {
		// Fall back to the most recent observation before windowStart
		for i := len(t.observations) - 1; i >= 0; i-- {
			if !t.observations[i].Timestamp.After(at) {
				return new(big.Int).Set(t.observations[i].Price), nil
			}
		}
		return nil, ErrNoObservations
	}

	if len(relevantObs) == 1 {
		return new(big.Int).Set(relevantObs[0].Price), nil
	}

	// Calculate time-weighted average
	// TWAP = Σ(price_i * duration_i) / total_duration
	totalWeightedPrice := big.NewInt(0)
	totalDuration := int64(0)

	for i := 0; i < len(relevantObs)-1; i++ {
		duration := relevantObs[i+1].Timestamp.Sub(relevantObs[i].Timestamp)
		durationSecs := int64(duration.Seconds())
		if durationSecs > 0 {
			// weightedPrice = price * duration
			weightedPrice := new(big.Int).Mul(relevantObs[i].Price, big.NewInt(durationSecs))
			totalWeightedPrice.Add(totalWeightedPrice, weightedPrice)
			totalDuration += durationSecs
		}
	}

	// Include the last observation up to the query time
	lastObs := relevantObs[len(relevantObs)-1]
	lastDuration := at.Sub(lastObs.Timestamp)
	lastDurationSecs := int64(lastDuration.Seconds())
	if lastDurationSecs > 0 {
		weightedPrice := new(big.Int).Mul(lastObs.Price, big.NewInt(lastDurationSecs))
		totalWeightedPrice.Add(totalWeightedPrice, weightedPrice)
		totalDuration += lastDurationSecs
	}

	if totalDuration == 0 {
		// Edge case: all observations at same timestamp
		return new(big.Int).Set(relevantObs[len(relevantObs)-1].Price), nil
	}

	// TWAP = totalWeightedPrice / totalDuration
	twap := new(big.Int).Div(totalWeightedPrice, big.NewInt(totalDuration))
	return twap, nil
}

// GetLastPrice returns the most recent observed price.
func (t *TWAP) GetLastPrice() (*big.Int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.observations) == 0 {
		return nil, ErrNoObservations
	}

	return new(big.Int).Set(t.observations[len(t.observations)-1].Price), nil
}

// GetVolatility returns a measure of price volatility over the window.
// Returns the ratio of (max - min) / average as a percentage.
func (t *TWAP) GetVolatility() (uint64, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.observations) < 2 {
		return 0, ErrInsufficientHistory
	}

	windowStart := time.Now().Add(-t.window)

	var minPrice, maxPrice, sumPrice *big.Int
	count := 0

	for _, obs := range t.observations {
		if obs.Timestamp.After(windowStart) {
			if minPrice == nil || obs.Price.Cmp(minPrice) < 0 {
				minPrice = new(big.Int).Set(obs.Price)
			}
			if maxPrice == nil || obs.Price.Cmp(maxPrice) > 0 {
				maxPrice = new(big.Int).Set(obs.Price)
			}
			if sumPrice == nil {
				sumPrice = new(big.Int).Set(obs.Price)
			} else {
				sumPrice.Add(sumPrice, obs.Price)
			}
			count++
		}
	}

	if count < 2 || sumPrice == nil || sumPrice.Sign() == 0 {
		return 0, ErrInsufficientHistory
	}

	// volatility = (max - min) * 10000 / average (in basis points)
	avgPrice := new(big.Int).Div(sumPrice, big.NewInt(int64(count)))
	if avgPrice.Sign() == 0 {
		return 0, ErrInsufficientHistory
	}

	spread := new(big.Int).Sub(maxPrice, minPrice)
	volatility := new(big.Int).Mul(spread, big.NewInt(10000))
	volatility.Div(volatility, avgPrice)

	return volatility.Uint64(), nil
}

// ObservationCount returns the number of price observations.
func (t *TWAP) ObservationCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.observations)
}

// Window returns the TWAP window duration.
func (t *TWAP) Window() time.Duration {
	return t.window
}

// Market returns the market symbol.
func (t *TWAP) Market() string {
	return t.market
}

// Clear removes all observations.
func (t *TWAP) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.observations = t.observations[:0]
}

// TWAPOracle manages TWAP oracles for multiple markets.
type TWAPOracle struct {
	mu      sync.RWMutex
	oracles map[string]*TWAP
	window  time.Duration
}

// NewTWAPOracle creates a new multi-market TWAP oracle.
func NewTWAPOracle(window time.Duration) *TWAPOracle {
	if window <= 0 {
		window = DefaultTWAPWindow
	}
	return &TWAPOracle{
		oracles: make(map[string]*TWAP),
		window:  window,
	}
}

// GetOrCreate returns the TWAP oracle for a market, creating one if needed.
func (o *TWAPOracle) GetOrCreate(market string) *TWAP {
	o.mu.Lock()
	defer o.mu.Unlock()

	if twap, exists := o.oracles[market]; exists {
		return twap
	}

	twap := NewDefaultTWAP(market)
	twap.window = o.window
	o.oracles[market] = twap
	return twap
}

// RecordPrice records a price for a market.
func (o *TWAPOracle) RecordPrice(market string, price *big.Int, timestamp time.Time) {
	twap := o.GetOrCreate(market)
	twap.Record(price, timestamp)
}

// GetPrice returns the TWAP for a market.
func (o *TWAPOracle) GetPrice(market string) (*big.Int, error) {
	o.mu.RLock()
	twap, exists := o.oracles[market]
	o.mu.RUnlock()

	if !exists {
		return nil, ErrNoObservations
	}
	return twap.GetPrice()
}

// GetLastPrice returns the last observed price for a market.
func (o *TWAPOracle) GetLastPrice(market string) (*big.Int, error) {
	o.mu.RLock()
	twap, exists := o.oracles[market]
	o.mu.RUnlock()

	if !exists {
		return nil, ErrNoObservations
	}
	return twap.GetLastPrice()
}
