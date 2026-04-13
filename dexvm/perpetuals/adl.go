// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package perpetuals provides perpetual futures trading functionality for the DEX VM.
// This file implements Auto-Deleveraging (ADL) for when the insurance fund is depleted.
//
// ADL Flow:
// 1. Liquidation occurs but insurance fund cannot cover the loss
// 2. ADL engine identifies profitable opposing positions (sorted by PnL ranking)
// 3. Positions are partially closed against the liquidated position at bankruptcy price
// 4. Affected users are compensated from remaining insurance fund
// 5. This prevents socialized losses from affecting all traders
//
// Priority Ranking:
// - Positions are ranked by profitability (highest profit first)
// - Only opposing positions (shorts for long liquidation, longs for short liquidation) are eligible
// - Maximum reduction per position is configurable (default 50%)
package perpetuals

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/luxfi/ids"
)

// maxRecentADLEvents bounds the in-memory ADL event log. Lifetime totals
// are retained in totalEvents / totalReduced / totalCompensation; this
// slice is only for recent-activity inspection. See oom-audit F-3.
const maxRecentADLEvents = 10_000

var (
	ErrNoADLCandidates      = errors.New("no ADL candidates available")
	ErrADLDisabled          = errors.New("ADL is disabled")
	ErrInsufficientADL      = errors.New("insufficient ADL capacity to cover loss")
	ErrInvalidADLPercentage = errors.New("invalid ADL reduction percentage")
)

// ADLConfig configures the auto-deleveraging engine.
type ADLConfig struct {
	// Enabled controls whether ADL is active
	Enabled bool

	// Threshold is the insurance fund depletion ratio that triggers ADL
	// When insurance fund falls below this percentage of target, ADL activates
	// Default: 0.2 (20%)
	Threshold float64

	// MaxReductionPerPosition is the maximum percentage of any single position
	// that can be reduced in a single ADL event
	// Default: 0.5 (50%)
	MaxReductionPerPosition float64

	// MinProfitForADL is the minimum unrealized profit required for a position
	// to be eligible for ADL (protects small profitable positions)
	// Default: $100
	MinProfitForADL *big.Int

	// CompensationRate is the percentage of mark price paid as compensation
	// Default: 0.001 (0.1%)
	CompensationRate float64
}

// DefaultADLConfig returns the default ADL configuration.
func DefaultADLConfig() ADLConfig {
	return ADLConfig{
		Enabled:                 true,
		Threshold:               0.20,                    // 20% of target insurance fund
		MaxReductionPerPosition: 0.50,                    // 50% max reduction
		MinProfitForADL:         big.NewInt(100_000_000), // $100 in 6 decimals
		CompensationRate:        0.001,                   // 0.1%
	}
}

// ADLCandidate represents a position eligible for auto-deleveraging.
type ADLCandidate struct {
	// PositionID uniquely identifies the position
	PositionID ids.ID

	// UserID is the owner of the position
	UserID ids.ShortID

	// Symbol is the trading pair
	Symbol string

	// Side is the position side (true = long, false = short)
	Side bool

	// Size is the current position size
	Size uint64

	// EntryPrice is the average entry price
	EntryPrice uint64

	// UnrealizedPnL is the current unrealized profit/loss
	UnrealizedPnL *big.Int

	// PnLRanking is the profit ranking score (higher = more profitable)
	PnLRanking float64

	// Leverage is the current leverage
	Leverage uint64

	// MarginBalance is the current margin balance
	MarginBalance *big.Int
}

// ADLEvent represents an auto-deleveraging event.
type ADLEvent struct {
	// EventID uniquely identifies this ADL event
	EventID ids.ID

	// Timestamp is when the ADL occurred
	Timestamp time.Time

	// Symbol is the affected trading pair
	Symbol string

	// LiquidatedPositionID is the position that triggered ADL
	LiquidatedPositionID ids.ID

	// TriggerReason describes why ADL was triggered
	TriggerReason string

	// AffectedPositions lists all positions affected by this ADL
	AffectedPositions []*ADLAffectedPosition

	// TotalReduced is the total position size reduced
	TotalReduced uint64

	// TotalCompensation is the total compensation paid
	TotalCompensation *big.Int

	// InsuranceFundBefore is the insurance fund balance before ADL
	InsuranceFundBefore *big.Int

	// InsuranceFundAfter is the insurance fund balance after ADL
	InsuranceFundAfter *big.Int
}

// ADLAffectedPosition represents a position affected by auto-deleveraging.
type ADLAffectedPosition struct {
	// PositionID is the affected position
	PositionID ids.ID

	// UserID is the position owner
	UserID ids.ShortID

	// OriginalSize is the size before ADL
	OriginalSize uint64

	// ReducedSize is the amount reduced by ADL
	ReducedSize uint64

	// ReductionPercentage is the percentage of position reduced
	ReductionPercentage float64

	// ExecutionPrice is the price at which the reduction occurred
	ExecutionPrice uint64

	// CompensationPaid is the compensation paid to the user
	CompensationPaid *big.Int

	// PnLRealized is the PnL realized from the reduction
	PnLRealized *big.Int
}

// AutoDeleveragingEngine manages auto-deleveraging for the DEX.
type AutoDeleveragingEngine struct {
	mu sync.RWMutex

	// Configuration
	config ADLConfig

	// Candidate queues per symbol (opposite side from trigger)
	longCandidates  map[string][]*ADLCandidate
	shortCandidates map[string][]*ADLCandidate

	// Recent event history (ring-buffered at maxRecentADLEvents to bound
	// memory; totalEvents retains the lifetime count).
	// See papers/oom-audit-2026-04-12.tex F-3.
	events []*ADLEvent

	// Statistics
	totalEvents       uint64
	totalReduced      *big.Int
	totalCompensation *big.Int
}

// NewAutoDeleveragingEngine creates a new ADL engine.
func NewAutoDeleveragingEngine(config ADLConfig) *AutoDeleveragingEngine {
	return &AutoDeleveragingEngine{
		config:            config,
		longCandidates:    make(map[string][]*ADLCandidate),
		shortCandidates:   make(map[string][]*ADLCandidate),
		events:            make([]*ADLEvent, 0),
		totalReduced:      big.NewInt(0),
		totalCompensation: big.NewInt(0),
	}
}

// UpdateCandidate adds or updates an ADL candidate.
func (e *AutoDeleveragingEngine) UpdateCandidate(candidate *ADLCandidate) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Calculate PnL ranking
	if candidate.Size > 0 {
		candidate.PnLRanking = float64(candidate.UnrealizedPnL.Int64()) / float64(candidate.Size)
	}

	var queue []*ADLCandidate
	var isLong bool
	if candidate.Side {
		queue = e.longCandidates[candidate.Symbol]
		isLong = true
	} else {
		queue = e.shortCandidates[candidate.Symbol]
		isLong = false
	}

	// Remove existing if present
	for i, c := range queue {
		if c.PositionID == candidate.PositionID {
			queue = append(queue[:i], queue[i+1:]...)
			break
		}
	}

	// Add if profitable enough
	if candidate.UnrealizedPnL.Cmp(e.config.MinProfitForADL) >= 0 {
		queue = append(queue, candidate)
		e.sortCandidates(queue)
	}

	// Store back in map
	if isLong {
		e.longCandidates[candidate.Symbol] = queue
	} else {
		e.shortCandidates[candidate.Symbol] = queue
	}
}

// RemoveCandidate removes an ADL candidate (position closed).
func (e *AutoDeleveragingEngine) RemoveCandidate(positionID ids.ID, symbol string, side bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var queue []*ADLCandidate
	if side {
		queue = e.longCandidates[symbol]
	} else {
		queue = e.shortCandidates[symbol]
	}

	for i, c := range queue {
		if c.PositionID == positionID {
			queue = append(queue[:i], queue[i+1:]...)
			if side {
				e.longCandidates[symbol] = queue
			} else {
				e.shortCandidates[symbol] = queue
			}
			return
		}
	}
}

// sortCandidates sorts candidates by PnL ranking (highest first).
func (e *AutoDeleveragingEngine) sortCandidates(candidates []*ADLCandidate) {
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].PnLRanking > candidates[j].PnLRanking
	})
}

// Execute performs auto-deleveraging for a liquidated position.
// liquidatedSide: true = long being liquidated (need to match with shorts)
// sizeToDeleverage: the size that needs to be covered
// bankruptcyPrice: the price at which the liquidated position is bankrupt
func (e *AutoDeleveragingEngine) Execute(
	symbol string,
	liquidatedPositionID ids.ID,
	liquidatedSide bool,
	sizeToDeleverage uint64,
	bankruptcyPrice uint64,
	insuranceFundBefore *big.Int,
) (*ADLEvent, error) {
	if !e.config.Enabled {
		return nil, ErrADLDisabled
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Get opposing candidates (if long is liquidated, we need shorts to take the other side)
	var candidates []*ADLCandidate
	if liquidatedSide { // Long liquidated, need shorts
		candidates = e.shortCandidates[symbol]
	} else { // Short liquidated, need longs
		candidates = e.longCandidates[symbol]
	}

	if len(candidates) == 0 {
		return nil, ErrNoADLCandidates
	}

	// Create event
	event := &ADLEvent{
		EventID:              ids.GenerateTestID(),
		Timestamp:            time.Now(),
		Symbol:               symbol,
		LiquidatedPositionID: liquidatedPositionID,
		TriggerReason: fmt.Sprintf(
			"Insurance fund below threshold, liquidating position %s",
			liquidatedPositionID,
		),
		AffectedPositions:   make([]*ADLAffectedPosition, 0),
		InsuranceFundBefore: new(big.Int).Set(insuranceFundBefore),
		TotalCompensation:   big.NewInt(0),
	}

	remainingSize := sizeToDeleverage
	totalCompensation := big.NewInt(0)

	for _, candidate := range candidates {
		if remainingSize == 0 {
			break
		}

		// Calculate reduction for this position
		maxReduction := uint64(float64(candidate.Size) * e.config.MaxReductionPerPosition)
		reductionSize := min(maxReduction, remainingSize)
		if reductionSize == 0 {
			continue
		}

		reductionPercentage := float64(reductionSize) / float64(candidate.Size)

		// Calculate compensation (based on mark price deviation from bankruptcy price)
		// In a real system, this would be more sophisticated
		compensationPerUnit := big.NewInt(int64(float64(bankruptcyPrice) * e.config.CompensationRate))
		compensation := new(big.Int).Mul(compensationPerUnit, big.NewInt(int64(reductionSize)))

		// Calculate realized PnL
		pnlPerUnit := new(big.Int).Sub(
			big.NewInt(int64(bankruptcyPrice)),
			big.NewInt(int64(candidate.EntryPrice)),
		)
		if !candidate.Side { // Short
			pnlPerUnit.Neg(pnlPerUnit)
		}
		pnlRealized := new(big.Int).Mul(pnlPerUnit, big.NewInt(int64(reductionSize)))

		affected := &ADLAffectedPosition{
			PositionID:          candidate.PositionID,
			UserID:              candidate.UserID,
			OriginalSize:        candidate.Size,
			ReducedSize:         reductionSize,
			ReductionPercentage: reductionPercentage,
			ExecutionPrice:      bankruptcyPrice,
			CompensationPaid:    compensation,
			PnLRealized:         pnlRealized,
		}

		event.AffectedPositions = append(event.AffectedPositions, affected)
		totalCompensation.Add(totalCompensation, compensation)

		// Update candidate size
		candidate.Size -= reductionSize
		remainingSize -= reductionSize

		// Remove candidate if fully reduced
		if candidate.Size == 0 {
			e.RemoveCandidateNoLock(candidate.PositionID, symbol, candidate.Side)
		}
	}

	if remainingSize > 0 {
		// Couldn't fully deleverage - this should trigger socialized loss
		return event, ErrInsufficientADL
	}

	event.TotalReduced = sizeToDeleverage - remainingSize
	event.TotalCompensation = totalCompensation
	event.InsuranceFundAfter = new(big.Int).Sub(insuranceFundBefore, totalCompensation)

	// Record event — ring-buffered to keep memory bounded (oom-audit F-3).
	e.events = append(e.events, event)
	if len(e.events) > maxRecentADLEvents {
		e.events = e.events[len(e.events)-maxRecentADLEvents:]
	}
	e.totalEvents++
	e.totalReduced.Add(e.totalReduced, big.NewInt(int64(event.TotalReduced)))
	e.totalCompensation.Add(e.totalCompensation, totalCompensation)

	return event, nil
}

// RemoveCandidateNoLock removes a candidate without acquiring lock.
func (e *AutoDeleveragingEngine) RemoveCandidateNoLock(positionID ids.ID, symbol string, side bool) {
	var queue []*ADLCandidate
	if side {
		queue = e.longCandidates[symbol]
	} else {
		queue = e.shortCandidates[symbol]
	}

	for i, c := range queue {
		if c.PositionID == positionID {
			queue = append(queue[:i], queue[i+1:]...)
			if side {
				e.longCandidates[symbol] = queue
			} else {
				e.shortCandidates[symbol] = queue
			}
			return
		}
	}
}

// ShouldTriggerADL checks if ADL should be triggered based on insurance fund ratio.
func (e *AutoDeleveragingEngine) ShouldTriggerADL(currentFund, targetFund *big.Int) bool {
	if !e.config.Enabled || targetFund.Sign() == 0 {
		return false
	}

	ratio := new(big.Float).Quo(
		new(big.Float).SetInt(currentFund),
		new(big.Float).SetInt(targetFund),
	)

	threshold := new(big.Float).SetFloat64(e.config.Threshold)
	return ratio.Cmp(threshold) < 0
}

// GetCandidateCount returns the number of ADL candidates for a symbol.
func (e *AutoDeleveragingEngine) GetCandidateCount(symbol string) (longs, shorts int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.longCandidates[symbol]), len(e.shortCandidates[symbol])
}

// GetEvents returns recent ADL events as interface{} slice for API compatibility.
func (e *AutoDeleveragingEngine) GetEvents(limit int) []interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if limit <= 0 || limit > len(e.events) {
		limit = len(e.events)
	}

	// Return most recent events
	start := len(e.events) - limit
	if start < 0 {
		start = 0
	}

	result := make([]interface{}, limit)
	for i, event := range e.events[start:] {
		result[i] = event
	}
	return result
}

// ADLStatistics contains ADL engine statistics.
type ADLStatistics struct {
	TotalEvents       uint64   `json:"totalEvents"`
	TotalReduced      *big.Int `json:"totalReduced"`
	TotalCompensation *big.Int `json:"totalCompensation"`
	LongCandidates    int      `json:"longCandidates"`
	ShortCandidates   int      `json:"shortCandidates"`
}

// Statistics returns ADL engine statistics as interface{} for API compatibility.
func (e *AutoDeleveragingEngine) Statistics() interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	longCount := 0
	shortCount := 0
	for _, candidates := range e.longCandidates {
		longCount += len(candidates)
	}
	for _, candidates := range e.shortCandidates {
		shortCount += len(candidates)
	}

	return ADLStatistics{
		TotalEvents:       e.totalEvents,
		TotalReduced:      new(big.Int).Set(e.totalReduced),
		TotalCompensation: new(big.Int).Set(e.totalCompensation),
		LongCandidates:    longCount,
		ShortCandidates:   shortCount,
	}
}

// min returns the minimum of two uint64 values.
func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
