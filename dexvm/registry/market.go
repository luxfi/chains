// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"errors"
	"fmt"

	"github.com/luxfi/ids"
)

// Market is an admitted trading pair. Both sides are pinned to registered, real,
// enabled assets by construction: a Market cannot be created (CreateMarket) unless
// both BaseAssetID and QuoteAssetID resolve in the registry. The MarketID is DERIVED
// from the two AssetIDs and the venue config, never supplied — so a market's identity
// is structurally bound to its real assets.
type Market struct {
	// NetworkID must match both assets' networks (a market does not span networks).
	NetworkID uint32 `json:"networkID"`
	// BaseAssetID / QuoteAssetID are canonical AssetIDs of registered assets.
	BaseAssetID  ids.ID `json:"baseAssetID"`
	QuoteAssetID ids.ID `json:"quoteAssetID"`
	// VenueConfig is the canonical serialization of the venue parameters (tick, lot,
	// fee tier) that distinguish two venues on the same pair. Hex in JSON.
	VenueConfig Bytes `json:"venueConfig"`
	// Enabled gates whether the market trades. A disabled market is still pinned to
	// real assets; it simply admits no orders.
	Enabled bool `json:"enabled"`
}

// ID returns the canonical MarketID = H(networkID, baseAssetID, quoteAssetID, venueConfig).
func (m Market) ID() ids.ID {
	return MarketID(m.NetworkID, m.BaseAssetID, m.QuoteAssetID, m.VenueConfig)
}

var (
	// ErrSameAsset is returned when a market names the same asset on both sides.
	ErrSameAsset = errors.New("registry: market base and quote assets are identical")
	// ErrNetworkMismatch is returned when a market's network does not match an asset's.
	ErrNetworkMismatch = errors.New("registry: market network does not match asset network")
	// ErrDuplicateMarket is returned when a MarketID already exists.
	ErrDuplicateMarket = errors.New("registry: market already exists")
)

// CreateMarket admits a market ONLY if BOTH sides resolve to a registered, enabled,
// real asset on the SAME network as the market. This is the structural enforcement
// of "no synthetic market": there is no AssetID for a synthetic asset, so a market
// over one cannot resolve, so it cannot be created. The market is stored in the
// registry and its derived MarketID returned.
//
// The check order is deliberate and fail-closed: resolve base, resolve quote, reject
// self-pair, reject network mismatch, reject duplicate. Any failure leaves the
// registry unchanged.
func (r *Registry) CreateMarket(m Market) (ids.ID, error) {
	base, err := r.MustResolveEnabled(m.BaseAssetID)
	if err != nil {
		return ids.Empty, fmt.Errorf("market base side: %w", err)
	}
	quote, err := r.MustResolveEnabled(m.QuoteAssetID)
	if err != nil {
		return ids.Empty, fmt.Errorf("market quote side: %w", err)
	}
	if m.BaseAssetID == m.QuoteAssetID {
		return ids.Empty, ErrSameAsset
	}
	if m.NetworkID != base.NetworkID || m.NetworkID != quote.NetworkID {
		return ids.Empty, fmt.Errorf("%w: market=%d base=%d quote=%d",
			ErrNetworkMismatch, m.NetworkID, base.NetworkID, quote.NetworkID)
	}

	id := m.ID()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.markets[id]; exists {
		return ids.Empty, fmt.Errorf("%w: %s", ErrDuplicateMarket, id)
	}
	if r.markets == nil {
		r.markets = make(map[ids.ID]Market)
	}
	r.markets[id] = m
	return id, nil
}

// ResolveMarket returns the market for a MarketID, ok=false if not registered.
func (r *Registry) ResolveMarket(id ids.ID) (Market, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.markets[id]
	return m, ok
}

// EachMarket iterates registered markets. Used by the startup gate to audit that
// every enabled market references only real, registered assets.
func (r *Registry) EachMarket(fn func(id ids.ID, m Market)) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for id, m := range r.markets {
		fn(id, m)
	}
}
