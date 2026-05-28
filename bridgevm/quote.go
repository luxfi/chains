// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// quote.go: authoritative quote engine for the B-Chain.
//
// The bridge is permissionless and non-custodial: validators run this
// VM collectively, so settlement decisions (receive_amount, fee,
// min_receive_amount) MUST come from this engine, not from any single
// daemon's local price feed.
//
// The engine consumes USD-denominated unit prices via the PriceFeed
// interface. The default implementation (StaticPriceFeed) is map-backed
// for first deploys; future iterations can swap in a quorum-signed
// oracle without changing the RPC surface.
//
// Settlement math mirrors the historical TS quote logic in
// app/server/src/domain/quote.ts:
//
//	rawReceive   = amount * sourcePrice / destPrice
//	feeRate      = isLuxExit(src, dst) ? BridgeFeeRate : 0
//	serviceFee   = rawReceive * feeRate
//	netReceive   = rawReceive - serviceFee
//	minReceive   = netReceive * (1 - Slippage)

// =============================================================================
// PriceFeed
// =============================================================================

// PriceFeed returns USD-denominated unit prices.
type PriceFeed interface {
	// Price returns the USD value of one unit of asset. Returns
	// ErrPriceUnknown when the asset is not priced.
	Price(asset string) (float64, error)
}

// ErrPriceUnknown is returned by PriceFeed.Price when the asset is
// not priced. The RPC layer maps this to JSON-RPC code -32004 so
// callers (e.g. the daemon) can distinguish "transient miss" from
// "invalid params".
var ErrPriceUnknown = errors.New("bridgevm: price unknown for asset")

// StaticPriceFeed is a map-backed PriceFeed. Concurrency-safe. Asset
// symbols are matched case-insensitively.
type StaticPriceFeed struct {
	mu     sync.RWMutex
	prices map[string]float64
}

// NewStaticPriceFeed builds a feed from an initial table.
func NewStaticPriceFeed(prices map[string]float64) *StaticPriceFeed {
	out := &StaticPriceFeed{prices: make(map[string]float64, len(prices))}
	for k, v := range prices {
		out.prices[strings.ToUpper(k)] = v
	}
	return out
}

// Set updates / inserts a price.
func (f *StaticPriceFeed) Set(asset string, usd float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prices[strings.ToUpper(asset)] = usd
}

// Price returns the USD value of one unit of asset.
func (f *StaticPriceFeed) Price(asset string) (float64, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if v, ok := f.prices[strings.ToUpper(asset)]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("%w: %s", ErrPriceUnknown, asset)
}

// =============================================================================
// QuoteEngine
// =============================================================================

// Defaults match the historical SDK assumptions so the on-wire shape
// stays stable across the daemon migration.
const (
	DefaultBridgeFeeRate = 0.01  // 1% on Lux-family exits
	DefaultSlippage      = 0.025 // 2.5% min-receive tolerance
	DefaultEstimatedTime = 180   // seconds
	DefaultAvgCompletion = "00:03:00"
)

// QuoteEngine computes settlement quotes for the B-Chain RPC layer.
// Concurrency-safe — PriceFeed is the only mutable dependency.
type QuoteEngine struct {
	Feed     PriceFeed
	FeeRate  float64 // zero ⇒ DefaultBridgeFeeRate
	Slippage float64 // zero ⇒ DefaultSlippage
}

// luxFamilyNetworks lists the Lux-derived L1 names that pay the
// bridge fee on exit. Matches the historical LUX_ZOO_NETWORKS set.
var luxFamilyNetworks = map[string]bool{
	"LUX_MAINNET": true,
	"LUX_TESTNET": true,
	"LUX_DEVNET":  true,
	"ZOO_MAINNET": true,
	"ZOO_TESTNET": true,
	"ZOO_DEVNET":  true,
}

// isLuxExit reports whether the source chain is in the Lux family
// (i.e. funds are leaving the ecosystem and the bridge fee applies).
func isLuxExit(source string) bool {
	return luxFamilyNetworks[source]
}

// QuoteInput is the engine's call payload.
type QuoteInput struct {
	Amount             float64
	SourceNetwork      string
	SourceAsset        string
	DestinationNetwork string
	DestinationAsset   string
	Refuel             bool
}

// QuoteResult is the engine's output. Stringified amounts are
// emitted via the RPC layer (canonical bridge wire encoding).
type QuoteResult struct {
	ReceiveAmount    float64
	MinReceiveAmount float64
	ServiceFee       float64
	TotalFee         float64
	Slippage         float64
	EstimatedTime    int
	AvgCompletion    string
}

// Quote computes settlement economics for one bridge intent.
func (q *QuoteEngine) Quote(in QuoteInput) (*QuoteResult, error) {
	if in.Amount <= 0 {
		return nil, errors.New("bridgevm: amount must be > 0")
	}
	if q.Feed == nil {
		return nil, errors.New("bridgevm: no PriceFeed configured")
	}
	srcUSD, err := q.Feed.Price(in.SourceAsset)
	if err != nil {
		return nil, fmt.Errorf("source price: %w", err)
	}
	dstUSD, err := q.Feed.Price(in.DestinationAsset)
	if err != nil {
		return nil, fmt.Errorf("destination price: %w", err)
	}
	if dstUSD <= 0 {
		return nil, fmt.Errorf("bridgevm: destination price must be > 0 (got %v)", dstUSD)
	}

	gross := in.Amount * srcUSD / dstUSD

	feeRate := 0.0
	if isLuxExit(in.SourceNetwork) {
		if q.FeeRate > 0 {
			feeRate = q.FeeRate
		} else {
			feeRate = DefaultBridgeFeeRate
		}
	}
	fee := gross * feeRate
	net := gross - fee

	slip := q.Slippage
	if slip <= 0 {
		slip = DefaultSlippage
	}

	return &QuoteResult{
		ReceiveAmount:    net,
		MinReceiveAmount: net * (1 - slip),
		ServiceFee:       fee,
		TotalFee:         fee,
		Slippage:         slip,
		EstimatedTime:    DefaultEstimatedTime,
		AvgCompletion:    DefaultAvgCompletion,
	}, nil
}

// formatAmount renders a float as the canonical bridge wire string.
// Matches the daemon's parseAmount round-trip so float→string→float
// is lossless within ParseFloat precision.
func formatAmount(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// defaultPriceFeed seeds the price table the bridge handles at
// genesis. A future PR adds a quorum-signed oracle feed; the engine
// interface stays stable.
func defaultPriceFeed() *StaticPriceFeed {
	return NewStaticPriceFeed(map[string]float64{
		"ETH":  3500.00,
		"LUX":  2.50,
		"ZOO":  0.05,
		"BTC":  65000.00,
		"SOL":  150.00,
		"TON":  6.00,
		"USDC": 1.00,
		"USDT": 1.00,
		"DAI":  1.00,
		"BNB":  600.00,
	})
}
