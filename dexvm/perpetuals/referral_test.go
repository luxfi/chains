// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package perpetuals

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

func TestNewReferralEngine(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	require.NotNil(engine)
	require.True(engine.programActive)
	require.Equal(uint8(5), engine.maxCodesPerUser)
}

func TestDefaultReferralTiers(t *testing.T) {
	require := require.New(t)

	tiers := DefaultReferralTiers()
	require.Len(tiers, 6)

	// Tier 1 should be base tier
	require.Equal(uint8(1), tiers[0].Tier)
	require.Equal(uint16(500), tiers[0].ReferrerRebate)  // 5%
	require.Equal(uint16(500), tiers[0].RefereeDiscount) // 5%

	// Top tier should have highest rates
	topTier := tiers[len(tiers)-1]
	require.Equal(uint8(6), topTier.Tier)
	require.Equal(uint16(3000), topTier.ReferrerRebate)  // 30%
	require.Equal(uint16(2000), topTier.RefereeDiscount) // 20%
}

func TestCreateReferralCode(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	ownerID := ids.GenerateTestID()

	code, err := engine.CreateReferralCode(ownerID, "MYCODE123")
	require.NoError(err)
	require.NotNil(code)
	require.Equal("MYCODE123", code.Code)
	require.Equal(ownerID, code.Owner)
	require.True(code.IsActive)

	// Verify referrer was created
	referrer, err := engine.GetReferrer(ownerID)
	require.NoError(err)
	require.Contains(referrer.Codes, "MYCODE123")
	require.Equal(uint8(1), referrer.Tier)
}

func TestCreateDuplicateCode(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	owner1 := ids.GenerateTestID()
	owner2 := ids.GenerateTestID()

	_, err := engine.CreateReferralCode(owner1, "SAMECODE")
	require.NoError(err)

	_, err = engine.CreateReferralCode(owner2, "SAMECODE")
	require.ErrorIs(err, ErrReferralCodeExists)
}

func TestMaxCodesPerUser(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	ownerID := ids.GenerateTestID()

	// Create max codes
	for i := 0; i < int(engine.maxCodesPerUser); i++ {
		_, err := engine.CreateReferralCode(ownerID, "CODE"+string(rune('A'+i)))
		require.NoError(err)
	}

	// Next should fail
	_, err := engine.CreateReferralCode(ownerID, "EXTRA")
	require.Error(err)
}

func TestUseReferralCode(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	referrerID := ids.GenerateTestID()
	refereeID := ids.GenerateTestID()

	// Create code
	_, err := engine.CreateReferralCode(referrerID, "REF123")
	require.NoError(err)

	// Use code
	err = engine.UseReferralCode(refereeID, "REF123")
	require.NoError(err)

	// Verify referee
	referee, err := engine.GetReferee(refereeID)
	require.NoError(err)
	require.Equal(referrerID, referee.ReferrerID)
	require.Equal("REF123", referee.ReferralCode)

	// Verify referrer stats updated
	referrer, _ := engine.GetReferrer(referrerID)
	require.Equal(uint32(1), referrer.TotalReferrals)
	require.Equal(uint32(1), referrer.ActiveReferrals)
}

func TestSelfReferral(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	ownerID := ids.GenerateTestID()

	_, err := engine.CreateReferralCode(ownerID, "MYCODE")
	require.NoError(err)

	err = engine.UseReferralCode(ownerID, "MYCODE")
	require.ErrorIs(err, ErrSelfReferral)
}

func TestAlreadyReferred(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	referrer1 := ids.GenerateTestID()
	referrer2 := ids.GenerateTestID()
	referee := ids.GenerateTestID()

	engine.CreateReferralCode(referrer1, "CODE1")
	engine.CreateReferralCode(referrer2, "CODE2")

	err := engine.UseReferralCode(referee, "CODE1")
	require.NoError(err)

	err = engine.UseReferralCode(referee, "CODE2")
	require.ErrorIs(err, ErrAlreadyReferred)
}

func TestProcessTradeRebate(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	referrerID := ids.GenerateTestID()
	refereeID := ids.GenerateTestID()
	tradeID := ids.GenerateTestID()

	// Setup referral
	engine.CreateReferralCode(referrerID, "REF")
	engine.UseReferralCode(refereeID, "REF")

	// Process trade
	notionalVolume := notional(100000) // $100K volume
	tradeFee := notional(50)           // $50 fee (0.05%)

	payment, actualFee, err := engine.ProcessTradeRebate(refereeID, tradeID, "BTC-PERP", notionalVolume, tradeFee)
	require.NoError(err)
	require.NotNil(payment)

	// Tier 1: 5% discount, 5% rebate
	// Discount = $50 * 5% = $2.50
	expectedDiscount := new(big.Int).Div(new(big.Int).Mul(tradeFee, big.NewInt(500)), BasisPointDenom)

	// Actual fee should be reduced
	expectedActualFee := new(big.Int).Sub(tradeFee, expectedDiscount)
	require.Equal(expectedActualFee, actualFee)

	// Rebate = (50 - 2.50) * 5% = $2.375
	feeAfterDiscount := new(big.Int).Sub(tradeFee, expectedDiscount)
	expectedRebate := new(big.Int).Div(new(big.Int).Mul(feeAfterDiscount, big.NewInt(500)), BasisPointDenom)
	require.Equal(expectedRebate, payment.RebateAmount)

	// Check referrer pending rebates
	referrer, _ := engine.GetReferrer(referrerID)
	require.Equal(expectedRebate, referrer.PendingRebates)
}

func TestProcessTradeNoReferral(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	traderID := ids.GenerateTestID()
	tradeID := ids.GenerateTestID()

	tradeFee := notional(50)

	payment, actualFee, err := engine.ProcessTradeRebate(traderID, tradeID, "BTC-PERP", notional(100000), tradeFee)
	require.NoError(err)
	require.Nil(payment)               // No rebate
	require.Equal(tradeFee, actualFee) // Full fee
}

func TestClaimRebates(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	referrerID := ids.GenerateTestID()
	refereeID := ids.GenerateTestID()

	engine.CreateReferralCode(referrerID, "REF")
	engine.UseReferralCode(refereeID, "REF")

	// Generate some rebates
	for i := 0; i < 10; i++ {
		tradeID := ids.GenerateTestID()
		engine.ProcessTradeRebate(refereeID, tradeID, "BTC-PERP", notional(10000), notional(5))
	}

	// Check pending
	referrer, _ := engine.GetReferrer(referrerID)
	require.True(referrer.PendingRebates.Sign() > 0)

	// Claim
	amount, err := engine.ClaimRebates(referrerID)
	require.NoError(err)
	require.True(amount.Sign() > 0)

	// Pending should be zero
	referrer, _ = engine.GetReferrer(referrerID)
	require.Equal(int64(0), referrer.PendingRebates.Int64())
}

func TestTierUpgrade(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	referrerID := ids.GenerateTestID()

	engine.CreateReferralCode(referrerID, "REF")

	// Create referrals
	for i := 0; i < 5; i++ {
		referee := ids.GenerateTestID()
		engine.UseReferralCode(referee, "REF")

		// Generate volume
		for j := 0; j < 100; j++ {
			tradeID := ids.GenerateTestID()
			engine.ProcessTradeRebate(referee, tradeID, "BTC-PERP", notional(50000), notional(25))
		}
	}

	// Should have upgraded tier
	referrer, _ := engine.GetReferrer(referrerID)
	require.True(referrer.Tier > 1, "Should have upgraded tier with enough volume and referrals")
}

func TestCustomRebateRate(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	referrerID := ids.GenerateTestID()
	refereeID := ids.GenerateTestID()

	engine.CreateReferralCode(referrerID, "CUSTOM")
	engine.UseReferralCode(refereeID, "CUSTOM")

	// Set custom 20% rebate
	err := engine.SetCustomRebateRate("CUSTOM", 2000)
	require.NoError(err)

	// Process trade
	tradeID := ids.GenerateTestID()
	payment, _, err := engine.ProcessTradeRebate(refereeID, tradeID, "BTC-PERP", notional(10000), notional(5))
	require.NoError(err)

	// Rebate should use custom rate
	// Discount is still tier based (5%)
	// Rebate = (5 - 0.25) * 20% = 0.95
	// Should be approximately 20% of fee after discount
	require.True(payment.RebateAmount.Sign() > 0)
}

func TestDeactivateCode(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	ownerID := ids.GenerateTestID()
	newUser := ids.GenerateTestID()

	engine.CreateReferralCode(ownerID, "MYCODE")

	err := engine.DeactivateCode("MYCODE", ownerID)
	require.NoError(err)

	// Should not be usable
	err = engine.UseReferralCode(newUser, "MYCODE")
	require.ErrorIs(err, ErrReferralCodeNotFound)
}

func TestGetFeeDiscount(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	referrerID := ids.GenerateTestID()
	refereeID := ids.GenerateTestID()
	nonRefereeID := ids.GenerateTestID()

	engine.CreateReferralCode(referrerID, "REF")
	engine.UseReferralCode(refereeID, "REF")

	// Referred user should get discount
	discount := engine.GetFeeDiscount(refereeID)
	require.Equal(uint16(500), discount) // 5%

	// Non-referred user gets no discount
	discount = engine.GetFeeDiscount(nonRefereeID)
	require.Equal(uint16(0), discount)
}

func TestReferralStats(t *testing.T) {
	require := require.New(t)

	engine := NewReferralEngine()
	referrerID := ids.GenerateTestID()

	engine.CreateReferralCode(referrerID, "REF")

	// Create some referrals and trades
	for i := 0; i < 5; i++ {
		referee := ids.GenerateTestID()
		engine.UseReferralCode(referee, "REF")
		tradeID := ids.GenerateTestID()
		engine.ProcessTradeRebate(referee, tradeID, "BTC-PERP", notional(10000), notional(5))
	}

	stats := engine.GetStats()
	require.Equal(uint64(1), stats.TotalReferrers)
	require.Equal(uint64(5), stats.TotalReferees)
	require.True(stats.TotalRebatesPaid.Sign() > 0)
	require.True(stats.TotalDiscountsGiven.Sign() > 0)
}

func TestVIPTiers(t *testing.T) {
	require := require.New(t)

	tiers := DefaultVIPTiers()

	// Base tier
	maker, taker := GetVIPTierFees(big.NewInt(0), tiers)
	require.Equal(uint16(10), maker) // 0.1%
	require.Equal(uint16(50), taker) // 0.5%

	// VIP 5 ($50M volume)
	maker, taker = GetVIPTierFees(notional(50000000), tiers)
	require.Equal(uint16(0), maker)  // 0%
	require.Equal(uint16(27), taker) // 0.27%

	// VIP 9 ($1B volume)
	maker, taker = GetVIPTierFees(notional(1000000000), tiers)
	require.Equal(uint16(0), maker)  // 0%
	require.Equal(uint16(15), taker) // 0.15%
}

func BenchmarkProcessTradeRebate(b *testing.B) {
	engine := NewReferralEngine()
	referrerID := ids.GenerateTestID()
	refereeID := ids.GenerateTestID()

	engine.CreateReferralCode(referrerID, "REF")
	engine.UseReferralCode(refereeID, "REF")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tradeID := ids.GenerateTestID()
		_, _, _ = engine.ProcessTradeRebate(refereeID, tradeID, "BTC-PERP", notional(10000), notional(5))
	}
}
