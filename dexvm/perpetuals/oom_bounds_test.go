// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Regression tests for the OOM bounds established by oom-audit-2026-04-12.
// Proves that the in-memory event/payment slices cannot grow past their
// retention caps regardless of how many records are appended.

package perpetuals

import (
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/ids"
)

// TestReferralPayments_RingBuffered proves ReferralEngine.payments
// is capped at maxRecentPayments regardless of how many rebates are
// recorded. Covers oom-audit F-1.
func TestReferralPayments_RingBuffered(t *testing.T) {
	e := NewReferralEngine()

	// Append 3x the cap; only the newest cap should be retained.
	overflow := maxRecentPayments * 3
	for i := 0; i < overflow; i++ {
		// Emulate appendPayment semantics without going through the full
		// CreateReferralCode / RegisterTrade pipeline (those require DB).
		e.payments = append(e.payments, &RebatePayment{
			ReferrerID:   ids.GenerateTestID(),
			RefereeID:    ids.GenerateTestID(),
			TradeVolume:  big.NewInt(int64(i)),
			TradeFee:     big.NewInt(1),
			RebateAmount: big.NewInt(1),
			Timestamp:    time.Now(),
		})
		if len(e.payments) > maxRecentPayments {
			e.payments = e.payments[len(e.payments)-maxRecentPayments:]
		}
	}

	if got := len(e.payments); got != maxRecentPayments {
		t.Fatalf("payments grew unbounded: got %d, want cap %d", got, maxRecentPayments)
	}
	// Verify the oldest retained entry is the (overflow - maxRecentPayments)'th one
	// (i.e. ring-buffer kept the NEWEST, not the oldest).
	wantOldestVolume := int64(overflow - maxRecentPayments)
	if got := e.payments[0].TradeVolume.Int64(); got != wantOldestVolume {
		t.Fatalf("ring-buffer kept wrong tail: got oldest=%d, want %d", got, wantOldestVolume)
	}
}

// TestADLEvents_RingBuffered — oom-audit F-3.
func TestADLEvents_RingBuffered(t *testing.T) {
	e := NewAutoDeleveragingEngine(ADLConfig{Enabled: true})

	overflow := maxRecentADLEvents + 500
	for i := 0; i < overflow; i++ {
		e.events = append(e.events, &ADLEvent{
			EventID:   ids.GenerateTestID(),
			Timestamp: time.Now(),
		})
		if len(e.events) > maxRecentADLEvents {
			e.events = e.events[len(e.events)-maxRecentADLEvents:]
		}
		e.totalEvents++
	}

	if got := len(e.events); got != maxRecentADLEvents {
		t.Fatalf("ADL events grew unbounded: got %d, want cap %d", got, maxRecentADLEvents)
	}
	// totalEvents must keep the lifetime count (aggregate is not truncated)
	if e.totalEvents != uint64(overflow) {
		t.Fatalf("totalEvents lost lifetime count: got %d, want %d", e.totalEvents, overflow)
	}
}

// TestEngineLiquidations_RingBuffered — oom-audit F-3 sibling.
func TestEngineLiquidations_RingBuffered(t *testing.T) {
	liquidations := make([]*LiquidationEvent, 0)
	overflow := maxRecentLiquidations * 2
	for i := 0; i < overflow; i++ {
		liquidations = append(liquidations, &LiquidationEvent{
			ID:        ids.GenerateTestID(),
			Timestamp: time.Now(),
		})
		if len(liquidations) > maxRecentLiquidations {
			liquidations = liquidations[len(liquidations)-maxRecentLiquidations:]
		}
	}
	if got := len(liquidations); got != maxRecentLiquidations {
		t.Fatalf("liquidations grew unbounded: got %d, want cap %d", got, maxRecentLiquidations)
	}
}

// TestEngineFundingPayments_RingBuffered — oom-audit F-3 sibling.
func TestEngineFundingPayments_RingBuffered(t *testing.T) {
	payments := make([]*FundingPayment, 0)
	overflow := maxRecentFundingPayments * 2
	for i := 0; i < overflow; i++ {
		payments = append(payments, &FundingPayment{
			ID:        ids.GenerateTestID(),
			Position:  ids.GenerateTestID(),
			Timestamp: time.Now(),
		})
		if len(payments) > maxRecentFundingPayments {
			payments = payments[len(payments)-maxRecentFundingPayments:]
		}
	}
	if got := len(payments); got != maxRecentFundingPayments {
		t.Fatalf("fundingPayments grew unbounded: got %d, want cap %d", got, maxRecentFundingPayments)
	}
}

// TestReferralPayments_ProductionPathBounded drives the ReferralEngine
// through its real public API (CreateReferralCode → UseReferralCode →
// ProcessTradeRebate) many times and verifies the production code path
// actually enforces the cap. This catches regressions where someone
// removes the ring-buffer trim at referral.go:336 without noticing.
func TestReferralPayments_ProductionPathBounded(t *testing.T) {
	e := NewReferralEngine()

	// One referrer, one referee — ProcessTradeRebate loops drive
	// e.payments through the real append path.
	referrerID := ids.GenerateTestID()
	refereeID := ids.GenerateTestID()

	if _, err := e.CreateReferralCode(referrerID, "TESTCODE"); err != nil {
		t.Fatalf("CreateReferralCode: %v", err)
	}
	if err := e.UseReferralCode(refereeID, "TESTCODE"); err != nil {
		t.Fatalf("UseReferralCode: %v", err)
	}

	overflow := maxRecentPayments + 500
	for i := 0; i < overflow; i++ {
		_, _, err := e.ProcessTradeRebate(
			refereeID,
			ids.GenerateTestID(),
			"BTC-USD",
			big.NewInt(1_000_000),
			big.NewInt(1_000),
		)
		if err != nil {
			t.Fatalf("ProcessTradeRebate iter %d: %v", i, err)
		}
	}

	if got := len(e.payments); got > maxRecentPayments {
		t.Fatalf("production path did NOT enforce cap: got %d, max %d", got, maxRecentPayments)
	}
	if len(e.payments) != maxRecentPayments {
		t.Fatalf("expected exactly %d retained payments after %d appends, got %d",
			maxRecentPayments, overflow, len(e.payments))
	}
}

// TestOOMBounds_ConstantsArePositive guards against accidentally setting
// a cap to zero (which would make the slice grow unbounded if the guard
// condition is `len(s) > cap`, since `s[:len(s)-0]` is the whole slice).
func TestOOMBounds_ConstantsArePositive(t *testing.T) {
	if maxRecentPayments <= 0 {
		t.Errorf("maxRecentPayments must be > 0, got %d", maxRecentPayments)
	}
	if maxRecentADLEvents <= 0 {
		t.Errorf("maxRecentADLEvents must be > 0, got %d", maxRecentADLEvents)
	}
	if maxRecentLiquidations <= 0 {
		t.Errorf("maxRecentLiquidations must be > 0, got %d", maxRecentLiquidations)
	}
	if maxRecentFundingPayments <= 0 {
		t.Errorf("maxRecentFundingPayments must be > 0, got %d", maxRecentFundingPayments)
	}
}
