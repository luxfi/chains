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
	ErrReferralCodeExists   = errors.New("referral code already exists")
	ErrReferralCodeNotFound = errors.New("referral code not found")
	ErrSelfReferral         = errors.New("cannot use own referral code")
	ErrAlreadyReferred      = errors.New("user already has a referrer")
	ErrInvalidRebateRate    = errors.New("invalid rebate rate")
	ErrReferralNotActive    = errors.New("referral program not active")
)

// ReferralTier represents a tier in the referral program
type ReferralTier struct {
	Tier            uint8    // Tier level (1-6)
	MinVolume       *big.Int // Minimum 30-day trading volume
	MinReferrals    uint32   // Minimum active referrals
	ReferrerRebate  uint16   // Rebate % for referrer (basis points, 10000 = 100%)
	RefereeDiscount uint16   // Fee discount % for referee (basis points)
}

// DefaultReferralTiers returns the standard referral tiers
func DefaultReferralTiers() []*ReferralTier {
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

	return []*ReferralTier{
		{
			Tier:            1,
			MinVolume:       big.NewInt(0),
			MinReferrals:    0,
			ReferrerRebate:  500, // 5% rebate to referrer
			RefereeDiscount: 500, // 5% discount for referee
		},
		{
			Tier:            2,
			MinVolume:       new(big.Int).Mul(scale, big.NewInt(1000000)), // $1M volume
			MinReferrals:    3,
			ReferrerRebate:  1000, // 10%
			RefereeDiscount: 1000, // 10%
		},
		{
			Tier:            3,
			MinVolume:       new(big.Int).Mul(scale, big.NewInt(5000000)), // $5M volume
			MinReferrals:    10,
			ReferrerRebate:  1500, // 15%
			RefereeDiscount: 1000, // 10%
		},
		{
			Tier:            4,
			MinVolume:       new(big.Int).Mul(scale, big.NewInt(25000000)), // $25M volume
			MinReferrals:    25,
			ReferrerRebate:  2000, // 20%
			RefereeDiscount: 1000, // 10%
		},
		{
			Tier:            5,
			MinVolume:       new(big.Int).Mul(scale, big.NewInt(100000000)), // $100M volume
			MinReferrals:    50,
			ReferrerRebate:  2500, // 25%
			RefereeDiscount: 1500, // 15%
		},
		{
			Tier:            6,
			MinVolume:       new(big.Int).Mul(scale, big.NewInt(500000000)), // $500M volume
			MinReferrals:    100,
			ReferrerRebate:  3000, // 30%
			RefereeDiscount: 2000, // 20%
		},
	}
}

// ReferralCode represents a referral code
type ReferralCode struct {
	Code         string // Unique referral code
	Owner        ids.ID // Owner of the code
	CustomRebate uint16 // Custom rebate rate (0 = use tier default)
	IsActive     bool   // Whether code is active
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Referrer represents a referrer in the system
type Referrer struct {
	ID              ids.ID   // Referrer ID
	Codes           []string // Active referral codes
	Tier            uint8    // Current tier
	TotalReferrals  uint32   // Total number of referrals
	ActiveReferrals uint32   // Active referrals (traded in last 30 days)
	TotalVolume     *big.Int // Total referred volume
	Volume30d       *big.Int // Last 30 day referred volume
	TotalRebates    *big.Int // Total rebates earned
	PendingRebates  *big.Int // Pending rebates to claim
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Referee represents a referred user
type Referee struct {
	ID            ids.ID   // Referee ID
	ReferrerID    ids.ID   // Who referred them
	ReferralCode  string   // Code used
	TotalVolume   *big.Int // Total trading volume
	TotalDiscount *big.Int // Total fee discounts received
	IsActive      bool     // Active in last 30 days
	ReferredAt    time.Time
	LastActiveAt  time.Time
}

// RebatePayment represents a rebate payment
type RebatePayment struct {
	ID           ids.ID   // Payment ID
	ReferrerID   ids.ID   // Recipient
	RefereeID    ids.ID   // Source trader
	TradeID      ids.ID   // Associated trade
	Market       string   // Market
	TradeVolume  *big.Int // Trade notional volume
	TradeFee     *big.Int // Original trade fee
	RebateAmount *big.Int // Rebate amount
	Tier         uint8    // Tier at time of payment
	Timestamp    time.Time
}

// ReferralStats provides statistics for the referral program
type ReferralStats struct {
	TotalReferrers      uint64   // Total number of referrers
	TotalReferees       uint64   // Total referred users
	TotalRebatesPaid    *big.Int // Total rebates paid out
	TotalDiscountsGiven *big.Int // Total discounts given
	ActiveReferrers30d  uint64   // Referrers active in 30 days
	Volume30d           *big.Int // Total referred volume in 30 days
}

// maxRecentPayments bounds the in-memory rebate payment log.
// Aggregate totals are retained on each Referrer; this slice is only a
// recent-activity inspection buffer. Prior unbounded append was an OOM
// vector (oom-audit-2026-04-12.tex F-1).
const maxRecentPayments = 10_000

// ReferralEngine manages the referral/rebate system
type ReferralEngine struct {
	tiers        []*ReferralTier
	codes        map[string]*ReferralCode // Code -> ReferralCode
	referrers    map[ids.ID]*Referrer     // ReferrerID -> Referrer
	referees     map[ids.ID]*Referee      // RefereeID -> Referee
	codesByOwner map[ids.ID][]string      // OwnerID -> []codes
	payments     []*RebatePayment         // Recent rebate payments (ring-buffered, cap maxRecentPayments)
	stats        *ReferralStats

	// Configuration
	maxCodesPerUser uint8
	defaultDiscount uint16 // Default referee discount (basis points)
	defaultRebate   uint16 // Default referrer rebate (basis points)
	programActive   bool
}

// NewReferralEngine creates a new referral engine
func NewReferralEngine() *ReferralEngine {
	return &ReferralEngine{
		tiers:        DefaultReferralTiers(),
		codes:        make(map[string]*ReferralCode),
		referrers:    make(map[ids.ID]*Referrer),
		referees:     make(map[ids.ID]*Referee),
		codesByOwner: make(map[ids.ID][]string),
		payments:     make([]*RebatePayment, 0),
		stats: &ReferralStats{
			TotalRebatesPaid:    big.NewInt(0),
			TotalDiscountsGiven: big.NewInt(0),
			Volume30d:           big.NewInt(0),
		},
		maxCodesPerUser: 5,
		defaultDiscount: 500, // 5%
		defaultRebate:   500, // 5%
		programActive:   true,
	}
}

// CreateReferralCode creates a new referral code for a user
func (e *ReferralEngine) CreateReferralCode(ownerID ids.ID, code string) (*ReferralCode, error) {
	if !e.programActive {
		return nil, ErrReferralNotActive
	}

	if _, exists := e.codes[code]; exists {
		return nil, ErrReferralCodeExists
	}

	// Check max codes per user
	existingCodes := e.codesByOwner[ownerID]
	if len(existingCodes) >= int(e.maxCodesPerUser) {
		return nil, errors.New("maximum referral codes reached")
	}

	now := time.Now()
	refCode := &ReferralCode{
		Code:      code,
		Owner:     ownerID,
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	e.codes[code] = refCode
	e.codesByOwner[ownerID] = append(e.codesByOwner[ownerID], code)

	// Create or update referrer
	referrer, exists := e.referrers[ownerID]
	if !exists {
		referrer = &Referrer{
			ID:             ownerID,
			Codes:          []string{code},
			Tier:           1,
			TotalVolume:    big.NewInt(0),
			Volume30d:      big.NewInt(0),
			TotalRebates:   big.NewInt(0),
			PendingRebates: big.NewInt(0),
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		e.referrers[ownerID] = referrer
		e.stats.TotalReferrers++
	} else {
		referrer.Codes = append(referrer.Codes, code)
		referrer.UpdatedAt = now
	}

	return refCode, nil
}

// UseReferralCode links a new user to a referrer
func (e *ReferralEngine) UseReferralCode(userID ids.ID, code string) error {
	if !e.programActive {
		return ErrReferralNotActive
	}

	refCode, exists := e.codes[code]
	if !exists || !refCode.IsActive {
		return ErrReferralCodeNotFound
	}

	// Check for self-referral
	if refCode.Owner == userID {
		return ErrSelfReferral
	}

	// Check if already referred
	if _, exists := e.referees[userID]; exists {
		return ErrAlreadyReferred
	}

	now := time.Now()
	referee := &Referee{
		ID:            userID,
		ReferrerID:    refCode.Owner,
		ReferralCode:  code,
		TotalVolume:   big.NewInt(0),
		TotalDiscount: big.NewInt(0),
		IsActive:      true,
		ReferredAt:    now,
		LastActiveAt:  now,
	}
	e.referees[userID] = referee

	// Update referrer stats
	if referrer, exists := e.referrers[refCode.Owner]; exists {
		referrer.TotalReferrals++
		referrer.ActiveReferrals++
		referrer.UpdatedAt = now
		e.updateReferrerTier(referrer)
	}

	e.stats.TotalReferees++

	return nil
}

// ProcessTradeRebate calculates and records rebates for a trade
func (e *ReferralEngine) ProcessTradeRebate(
	traderID ids.ID,
	tradeID ids.ID,
	market string,
	notionalVolume *big.Int,
	tradeFee *big.Int,
) (*RebatePayment, *big.Int, error) {
	if !e.programActive {
		return nil, tradeFee, nil // Return full fee if program not active
	}

	referee, isReferred := e.referees[traderID]
	if !isReferred {
		return nil, tradeFee, nil // No referral, full fee
	}

	referrer, exists := e.referrers[referee.ReferrerID]
	if !exists {
		return nil, tradeFee, nil
	}

	// Get tier rates
	tier := e.getTier(referrer.Tier)
	rebateRate := tier.ReferrerRebate
	discountRate := tier.RefereeDiscount

	// Check for custom rebate on the code
	if code, exists := e.codes[referee.ReferralCode]; exists && code.CustomRebate > 0 {
		rebateRate = code.CustomRebate
	}

	// Calculate discount for referee
	discount := new(big.Int).Mul(tradeFee, big.NewInt(int64(discountRate)))
	discount.Div(discount, BasisPointDenom)

	// Calculate rebate for referrer (from the fee after discount)
	feeAfterDiscount := new(big.Int).Sub(tradeFee, discount)
	rebate := new(big.Int).Mul(feeAfterDiscount, big.NewInt(int64(rebateRate)))
	rebate.Div(rebate, BasisPointDenom)

	now := time.Now()

	// Record payment
	payment := &RebatePayment{
		ID:           ids.GenerateTestID(),
		ReferrerID:   referee.ReferrerID,
		RefereeID:    traderID,
		TradeID:      tradeID,
		Market:       market,
		TradeVolume:  new(big.Int).Set(notionalVolume),
		TradeFee:     new(big.Int).Set(tradeFee),
		RebateAmount: rebate,
		Tier:         referrer.Tier,
		Timestamp:    now,
	}
	// Ring-buffered append: drop the oldest once we hit the retention cap
	// to keep memory bounded (oom-audit F-1).
	e.payments = append(e.payments, payment)
	if len(e.payments) > maxRecentPayments {
		e.payments = e.payments[len(e.payments)-maxRecentPayments:]
	}

	// Update referrer
	referrer.TotalVolume.Add(referrer.TotalVolume, notionalVolume)
	referrer.Volume30d.Add(referrer.Volume30d, notionalVolume)
	referrer.TotalRebates.Add(referrer.TotalRebates, rebate)
	referrer.PendingRebates.Add(referrer.PendingRebates, rebate)
	referrer.UpdatedAt = now
	e.updateReferrerTier(referrer)

	// Update referee
	referee.TotalVolume.Add(referee.TotalVolume, notionalVolume)
	referee.TotalDiscount.Add(referee.TotalDiscount, discount)
	referee.IsActive = true
	referee.LastActiveAt = now

	// Update stats
	e.stats.TotalRebatesPaid.Add(e.stats.TotalRebatesPaid, rebate)
	e.stats.TotalDiscountsGiven.Add(e.stats.TotalDiscountsGiven, discount)
	e.stats.Volume30d.Add(e.stats.Volume30d, notionalVolume)

	// Calculate actual fee to charge (fee - discount)
	actualFee := new(big.Int).Sub(tradeFee, discount)

	return payment, actualFee, nil
}

// ClaimRebates allows a referrer to claim pending rebates
func (e *ReferralEngine) ClaimRebates(referrerID ids.ID) (*big.Int, error) {
	referrer, exists := e.referrers[referrerID]
	if !exists {
		return nil, errors.New("referrer not found")
	}

	amount := new(big.Int).Set(referrer.PendingRebates)
	referrer.PendingRebates = big.NewInt(0)
	referrer.UpdatedAt = time.Now()

	return amount, nil
}

// GetReferrer returns referrer info
func (e *ReferralEngine) GetReferrer(referrerID ids.ID) (*Referrer, error) {
	referrer, exists := e.referrers[referrerID]
	if !exists {
		return nil, errors.New("referrer not found")
	}
	return referrer, nil
}

// GetReferee returns referee info
func (e *ReferralEngine) GetReferee(refereeID ids.ID) (*Referee, error) {
	referee, exists := e.referees[refereeID]
	if !exists {
		return nil, errors.New("not referred")
	}
	return referee, nil
}

// GetReferralCode returns a referral code
func (e *ReferralEngine) GetReferralCode(code string) (*ReferralCode, error) {
	refCode, exists := e.codes[code]
	if !exists {
		return nil, ErrReferralCodeNotFound
	}
	return refCode, nil
}

// GetStats returns referral program stats
func (e *ReferralEngine) GetStats() *ReferralStats {
	return e.stats
}

// GetFeeDiscount returns the fee discount for a trader
func (e *ReferralEngine) GetFeeDiscount(traderID ids.ID) uint16 {
	referee, exists := e.referees[traderID]
	if !exists {
		return 0
	}

	referrer, exists := e.referrers[referee.ReferrerID]
	if !exists {
		return e.defaultDiscount
	}

	tier := e.getTier(referrer.Tier)
	return tier.RefereeDiscount
}

// GetReferralsByCode returns all referees who used a specific code
func (e *ReferralEngine) GetReferralsByCode(code string) []*Referee {
	var referees []*Referee
	for _, referee := range e.referees {
		if referee.ReferralCode == code {
			referees = append(referees, referee)
		}
	}
	return referees
}

// SetCustomRebateRate sets a custom rebate rate for a code
func (e *ReferralEngine) SetCustomRebateRate(code string, rate uint16) error {
	if rate > 5000 { // Max 50% custom rebate
		return ErrInvalidRebateRate
	}

	refCode, exists := e.codes[code]
	if !exists {
		return ErrReferralCodeNotFound
	}

	refCode.CustomRebate = rate
	refCode.UpdatedAt = time.Now()
	return nil
}

// DeactivateCode deactivates a referral code
func (e *ReferralEngine) DeactivateCode(code string, ownerID ids.ID) error {
	refCode, exists := e.codes[code]
	if !exists {
		return ErrReferralCodeNotFound
	}

	if refCode.Owner != ownerID {
		return errors.New("not authorized")
	}

	refCode.IsActive = false
	refCode.UpdatedAt = time.Now()
	return nil
}

// Helper functions

func (e *ReferralEngine) getTier(tierNum uint8) *ReferralTier {
	for _, tier := range e.tiers {
		if tier.Tier == tierNum {
			return tier
		}
	}
	return e.tiers[0] // Default to tier 1
}

func (e *ReferralEngine) updateReferrerTier(referrer *Referrer) {
	// Check tiers from highest to lowest
	for i := len(e.tiers) - 1; i >= 0; i-- {
		tier := e.tiers[i]
		if referrer.Volume30d.Cmp(tier.MinVolume) >= 0 && referrer.ActiveReferrals >= tier.MinReferrals {
			referrer.Tier = tier.Tier
			return
		}
	}
	referrer.Tier = 1 // Default tier
}

// VIPTier represents a VIP fee tier based on trading volume
type VIPTier struct {
	Tier         uint8    // VIP level (0-9)
	MinVolume30d *big.Int // Minimum 30-day trading volume
	MakerFee     uint16   // Maker fee in basis points
	TakerFee     uint16   // Taker fee in basis points
}

// DefaultVIPTiers returns standard VIP fee tiers
func DefaultVIPTiers() []*VIPTier {
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

	return []*VIPTier{
		{Tier: 0, MinVolume30d: big.NewInt(0), MakerFee: 10, TakerFee: 50},                                  // 0.1% / 0.5%
		{Tier: 1, MinVolume30d: new(big.Int).Mul(scale, big.NewInt(1000000)), MakerFee: 8, TakerFee: 45},    // $1M
		{Tier: 2, MinVolume30d: new(big.Int).Mul(scale, big.NewInt(5000000)), MakerFee: 6, TakerFee: 40},    // $5M
		{Tier: 3, MinVolume30d: new(big.Int).Mul(scale, big.NewInt(10000000)), MakerFee: 4, TakerFee: 35},   // $10M
		{Tier: 4, MinVolume30d: new(big.Int).Mul(scale, big.NewInt(25000000)), MakerFee: 2, TakerFee: 30},   // $25M
		{Tier: 5, MinVolume30d: new(big.Int).Mul(scale, big.NewInt(50000000)), MakerFee: 0, TakerFee: 27},   // $50M (negative maker = rebate)
		{Tier: 6, MinVolume30d: new(big.Int).Mul(scale, big.NewInt(100000000)), MakerFee: 0, TakerFee: 25},  // $100M (maker rebate)
		{Tier: 7, MinVolume30d: new(big.Int).Mul(scale, big.NewInt(250000000)), MakerFee: 0, TakerFee: 22},  // $250M
		{Tier: 8, MinVolume30d: new(big.Int).Mul(scale, big.NewInt(500000000)), MakerFee: 0, TakerFee: 20},  // $500M
		{Tier: 9, MinVolume30d: new(big.Int).Mul(scale, big.NewInt(1000000000)), MakerFee: 0, TakerFee: 15}, // $1B (MM tier)
	}
}

// GetVIPTierFees returns maker/taker fees for a given volume
func GetVIPTierFees(volume30d *big.Int, vipTiers []*VIPTier) (uint16, uint16) {
	currentTier := vipTiers[0]

	for i := len(vipTiers) - 1; i >= 0; i-- {
		if volume30d.Cmp(vipTiers[i].MinVolume30d) >= 0 {
			currentTier = vipTiers[i]
			break
		}
	}

	return currentTier.MakerFee, currentTier.TakerFee
}
