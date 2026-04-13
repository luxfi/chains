// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package perpetuals

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

func TestNewAutoDeleveragingEngine(t *testing.T) {
	require := require.New(t)

	config := DefaultADLConfig()
	engine := NewAutoDeleveragingEngine(config)

	require.NotNil(engine)
	require.True(engine.config.Enabled)
	require.Equal(0.20, engine.config.Threshold)
	require.Equal(0.50, engine.config.MaxReductionPerPosition)
}

func TestADLUpdateCandidate(t *testing.T) {
	require := require.New(t)

	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	// Add a profitable long position
	candidate := &ADLCandidate{
		PositionID:    ids.GenerateTestID(),
		UserID:        ids.GenerateTestShortID(),
		Symbol:        "BTC-USD",
		Side:          true, // Long
		Size:          1000,
		EntryPrice:    50000_000000,
		UnrealizedPnL: big.NewInt(500_000000), // $500 profit
		Leverage:      10,
		MarginBalance: big.NewInt(5000_000000),
	}

	engine.UpdateCandidate(candidate)

	longs, shorts := engine.GetCandidateCount("BTC-USD")
	require.Equal(1, longs)
	require.Equal(0, shorts)

	// Add a profitable short position
	shortCandidate := &ADLCandidate{
		PositionID:    ids.GenerateTestID(),
		UserID:        ids.GenerateTestShortID(),
		Symbol:        "BTC-USD",
		Side:          false, // Short
		Size:          2000,
		EntryPrice:    52000_000000,
		UnrealizedPnL: big.NewInt(1000_000000), // $1000 profit
		Leverage:      20,
		MarginBalance: big.NewInt(2500_000000),
	}

	engine.UpdateCandidate(shortCandidate)

	longs, shorts = engine.GetCandidateCount("BTC-USD")
	require.Equal(1, longs)
	require.Equal(1, shorts)
}

func TestADLRemoveCandidate(t *testing.T) {
	require := require.New(t)

	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	posID := ids.GenerateTestID()
	candidate := &ADLCandidate{
		PositionID:    posID,
		UserID:        ids.GenerateTestShortID(),
		Symbol:        "ETH-USD",
		Side:          true,
		Size:          500,
		EntryPrice:    3000_000000,
		UnrealizedPnL: big.NewInt(200_000000),
		Leverage:      5,
		MarginBalance: big.NewInt(1000_000000),
	}

	engine.UpdateCandidate(candidate)
	longs, _ := engine.GetCandidateCount("ETH-USD")
	require.Equal(1, longs)

	engine.RemoveCandidate(posID, "ETH-USD", true)
	longs, _ = engine.GetCandidateCount("ETH-USD")
	require.Equal(0, longs)
}

func TestADLMinProfitThreshold(t *testing.T) {
	require := require.New(t)

	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	// Add position with profit below threshold
	lowProfitCandidate := &ADLCandidate{
		PositionID:    ids.GenerateTestID(),
		UserID:        ids.GenerateTestShortID(),
		Symbol:        "BTC-USD",
		Side:          true,
		Size:          100,
		EntryPrice:    50000_000000,
		UnrealizedPnL: big.NewInt(50_000000), // $50 < $100 threshold
		Leverage:      10,
		MarginBalance: big.NewInt(500_000000),
	}

	engine.UpdateCandidate(lowProfitCandidate)

	longs, _ := engine.GetCandidateCount("BTC-USD")
	require.Equal(0, longs) // Should not be added
}

func TestADLExecute(t *testing.T) {
	require := require.New(t)

	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	// Add short candidates (to match against long liquidation)
	for i := 0; i < 3; i++ {
		candidate := &ADLCandidate{
			PositionID:    ids.GenerateTestID(),
			UserID:        ids.GenerateTestShortID(),
			Symbol:        "BTC-USD",
			Side:          false, // Short
			Size:          1000,
			EntryPrice:    52000_000000,
			UnrealizedPnL: big.NewInt(int64((i + 1) * 500_000000)), // Varying profits
			Leverage:      10,
			MarginBalance: big.NewInt(5000_000000),
		}
		engine.UpdateCandidate(candidate)
	}

	_, shorts := engine.GetCandidateCount("BTC-USD")
	require.Equal(3, shorts)

	// Execute ADL for a liquidated long position
	liquidatedPosID := ids.GenerateTestID()
	insuranceFund := big.NewInt(1000_000000) // $1000

	event, err := engine.Execute(
		"BTC-USD",
		liquidatedPosID,
		true,         // Long liquidated
		500,          // Size to deleverage
		48000_000000, // Bankruptcy price
		insuranceFund,
	)

	require.NoError(err)
	require.NotNil(event)
	require.Equal("BTC-USD", event.Symbol)
	require.Equal(liquidatedPosID, event.LiquidatedPositionID)
	require.Greater(len(event.AffectedPositions), 0)
	require.Equal(uint64(500), event.TotalReduced)
}

func TestADLNoCandidates(t *testing.T) {
	require := require.New(t)

	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	liquidatedPosID := ids.GenerateTestID()
	insuranceFund := big.NewInt(1000_000000)

	_, err := engine.Execute(
		"BTC-USD",
		liquidatedPosID,
		true,
		500,
		48000_000000,
		insuranceFund,
	)

	require.ErrorIs(err, ErrNoADLCandidates)
}

func TestADLDisabled(t *testing.T) {
	require := require.New(t)

	config := DefaultADLConfig()
	config.Enabled = false
	engine := NewAutoDeleveragingEngine(config)

	_, err := engine.Execute(
		"BTC-USD",
		ids.GenerateTestID(),
		true,
		500,
		48000_000000,
		big.NewInt(1000_000000),
	)

	require.ErrorIs(err, ErrADLDisabled)
}

func TestADLInsufficientCapacity(t *testing.T) {
	require := require.New(t)

	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	// Add only one small short candidate
	candidate := &ADLCandidate{
		PositionID:    ids.GenerateTestID(),
		UserID:        ids.GenerateTestShortID(),
		Symbol:        "BTC-USD",
		Side:          false,
		Size:          100, // Small position
		EntryPrice:    52000_000000,
		UnrealizedPnL: big.NewInt(500_000000),
		Leverage:      10,
		MarginBalance: big.NewInt(5000_000000),
	}
	engine.UpdateCandidate(candidate)

	// Try to deleverage more than available
	_, err := engine.Execute(
		"BTC-USD",
		ids.GenerateTestID(),
		true,
		1000, // Much larger than candidate
		48000_000000,
		big.NewInt(1000_000000),
	)

	// Should succeed but return partial error
	require.ErrorIs(err, ErrInsufficientADL)
}

func TestADLShouldTrigger(t *testing.T) {
	require := require.New(t)

	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	targetFund := big.NewInt(10_000_000000) // $10,000 target

	// Fund at 15% - should trigger (below 20%)
	currentFund := big.NewInt(1_500_000000)
	require.True(engine.ShouldTriggerADL(currentFund, targetFund))

	// Fund at 25% - should not trigger (above 20%)
	currentFund = big.NewInt(2_500_000000)
	require.False(engine.ShouldTriggerADL(currentFund, targetFund))

	// Fund at 10% - should trigger (well below threshold)
	currentFund = big.NewInt(1_000_000000)
	require.True(engine.ShouldTriggerADL(currentFund, targetFund))

	// Fund at 50% - should not trigger (well above threshold)
	currentFund = big.NewInt(5_000_000000)
	require.False(engine.ShouldTriggerADL(currentFund, targetFund))
}

func TestADLStatistics(t *testing.T) {
	require := require.New(t)

	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	// Add candidates
	for i := 0; i < 5; i++ {
		engine.UpdateCandidate(&ADLCandidate{
			PositionID:    ids.GenerateTestID(),
			UserID:        ids.GenerateTestShortID(),
			Symbol:        "BTC-USD",
			Side:          i%2 == 0, // Alternate sides
			Size:          1000,
			EntryPrice:    50000_000000,
			UnrealizedPnL: big.NewInt(500_000000),
			Leverage:      10,
			MarginBalance: big.NewInt(5000_000000),
		})
	}

	statsIface := engine.Statistics()
	stats := statsIface.(ADLStatistics)
	require.Equal(uint64(0), stats.TotalEvents)
	require.True(stats.LongCandidates+stats.ShortCandidates == 5)
}

func TestADLMaxReductionPerPosition(t *testing.T) {
	require := require.New(t)

	config := DefaultADLConfig()
	config.MaxReductionPerPosition = 0.25 // 25% max reduction
	engine := NewAutoDeleveragingEngine(config)

	// Add one short candidate
	candidate := &ADLCandidate{
		PositionID:    ids.GenerateTestID(),
		UserID:        ids.GenerateTestShortID(),
		Symbol:        "BTC-USD",
		Side:          false,
		Size:          1000,
		EntryPrice:    52000_000000,
		UnrealizedPnL: big.NewInt(500_000000),
		Leverage:      10,
		MarginBalance: big.NewInt(5000_000000),
	}
	engine.UpdateCandidate(candidate)

	// Try to deleverage 500 (50% of position)
	event, err := engine.Execute(
		"BTC-USD",
		ids.GenerateTestID(),
		true,
		500,
		48000_000000,
		big.NewInt(1000_000000),
	)

	// Should only reduce 25% (250)
	require.ErrorIs(err, ErrInsufficientADL) // Couldn't fully deleverage
	require.NotNil(event)
	require.Len(event.AffectedPositions, 1)
	require.Equal(uint64(250), event.AffectedPositions[0].ReducedSize)
}

func TestADLEventHistory(t *testing.T) {
	require := require.New(t)

	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	// Execute multiple ADL events
	for i := 0; i < 5; i++ {
		// Add candidate
		engine.UpdateCandidate(&ADLCandidate{
			PositionID:    ids.GenerateTestID(),
			UserID:        ids.GenerateTestShortID(),
			Symbol:        "BTC-USD",
			Side:          false,
			Size:          1000,
			EntryPrice:    52000_000000,
			UnrealizedPnL: big.NewInt(500_000000),
			Leverage:      10,
			MarginBalance: big.NewInt(5000_000000),
		})

		// Execute
		_, _ = engine.Execute(
			"BTC-USD",
			ids.GenerateTestID(),
			true,
			100,
			48000_000000,
			big.NewInt(1000_000000),
		)
	}

	// Get last 3 events
	events := engine.GetEvents(3)
	require.Len(events, 3)

	// Get all events
	allEvents := engine.GetEvents(0)
	require.Len(allEvents, 5)
}

func TestADLPnLRanking(t *testing.T) {
	require := require.New(t)

	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	// Add candidates with different profits
	candidates := []*ADLCandidate{
		{
			PositionID:    ids.ID{1},
			UserID:        ids.GenerateTestShortID(),
			Symbol:        "BTC-USD",
			Side:          false,
			Size:          1000,
			EntryPrice:    52000_000000,
			UnrealizedPnL: big.NewInt(100_000000), // Low profit
			Leverage:      10,
			MarginBalance: big.NewInt(5000_000000),
		},
		{
			PositionID:    ids.ID{2},
			UserID:        ids.GenerateTestShortID(),
			Symbol:        "BTC-USD",
			Side:          false,
			Size:          1000,
			EntryPrice:    52000_000000,
			UnrealizedPnL: big.NewInt(1000_000000), // Highest profit
			Leverage:      10,
			MarginBalance: big.NewInt(5000_000000),
		},
		{
			PositionID:    ids.ID{3},
			UserID:        ids.GenerateTestShortID(),
			Symbol:        "BTC-USD",
			Side:          false,
			Size:          1000,
			EntryPrice:    52000_000000,
			UnrealizedPnL: big.NewInt(500_000000), // Medium profit
			Leverage:      10,
			MarginBalance: big.NewInt(5000_000000),
		},
	}

	for _, c := range candidates {
		engine.UpdateCandidate(c)
	}

	// Execute ADL - should hit highest profit first
	event, err := engine.Execute(
		"BTC-USD",
		ids.GenerateTestID(),
		true,
		100, // Small amount
		48000_000000,
		big.NewInt(1000_000000),
	)

	require.NoError(err)
	require.Len(event.AffectedPositions, 1)
	// The highest profit position (ID {2}) should be affected first
	require.Equal(ids.ID{2}, event.AffectedPositions[0].PositionID)
}

func BenchmarkADLUpdateCandidate(b *testing.B) {
	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	candidate := &ADLCandidate{
		PositionID:    ids.GenerateTestID(),
		UserID:        ids.GenerateTestShortID(),
		Symbol:        "BTC-USD",
		Side:          true,
		Size:          1000,
		EntryPrice:    50000_000000,
		UnrealizedPnL: big.NewInt(500_000000),
		Leverage:      10,
		MarginBalance: big.NewInt(5000_000000),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		candidate.PositionID = ids.ID{byte(i % 256)}
		engine.UpdateCandidate(candidate)
	}
}

func BenchmarkADLExecute(b *testing.B) {
	engine := NewAutoDeleveragingEngine(DefaultADLConfig())

	// Pre-populate with candidates
	for i := 0; i < 100; i++ {
		engine.UpdateCandidate(&ADLCandidate{
			PositionID:    ids.ID{byte(i)},
			UserID:        ids.GenerateTestShortID(),
			Symbol:        "BTC-USD",
			Side:          false,
			Size:          1000,
			EntryPrice:    52000_000000,
			UnrealizedPnL: big.NewInt(int64((i + 1) * 100_000000)),
			Leverage:      10,
			MarginBalance: big.NewInt(5000_000000),
		})
	}

	insuranceFund := big.NewInt(10000_000000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Re-add candidate to replace executed ones
		engine.UpdateCandidate(&ADLCandidate{
			PositionID:    ids.ID{byte(i % 256)},
			UserID:        ids.GenerateTestShortID(),
			Symbol:        "BTC-USD",
			Side:          false,
			Size:          1000,
			EntryPrice:    52000_000000,
			UnrealizedPnL: big.NewInt(500_000000),
			Leverage:      10,
			MarginBalance: big.NewInt(5000_000000),
		})

		engine.Execute(
			"BTC-USD",
			ids.GenerateTestID(),
			true,
			100,
			48000_000000,
			insuranceFund,
		)
	}
}
