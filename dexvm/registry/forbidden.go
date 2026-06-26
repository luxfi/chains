// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// This file is the deny-list half of admission: a set of cheap, total predicates
// that recognise the SHAPES of the anti-patterns the DEX must never carry, so the
// startup gate can refuse them by name. Reality (ChainVerifier) is the positive
// gate; these are the negative gate — they catch a reference that is structurally a
// synthetic/phantom/branded artifact even before (or instead of) a chain lookup.

// mockLiquidityTokens mark a synthetic/mock liquidity source — fabricated depth that
// does not correspond to real on-chain reserves. Any asset/market label carrying one
// is refused: the DEX quotes real reserves only.
var mockLiquidityTokens = []string{
	"mock",
	"synthetic",
	"fake",
	"phantom",
	"placeholder",
	"testliquidity",
	"mockliquidity",
	"d-native", // the explicitly-forbidden "D-native asset" class
	"dnative",
}

// forbiddenUniverseLabels name OFF-NETWORK white-label universes a Lux-native DEX must
// never carry assets from. A source chain that labels itself a "Liquidity" / "Liquid"
// (Liquid EVM / Liquid DEX white-label) universe — or the upstream "satschel" lineage —
// is refused at STARTUP, even when the token itself is real on-chain: the DEX serves the
// Lux primary network and its L1s/L2s, never a foreign branded universe. This is the
// negative half of the never-mix-Liquidity boundary (the positive ChainVerifier gate
// proves real on-chain existence; this refuses a forbidden BRAND regardless).
var forbiddenUniverseLabels = []string{
	"liquid",   // catches "Liquid EVM" / "Liquid DEX" / "Liquidity" (all contain "liquid")
	"satschel", // upstream poison-lineage org
}

// IsForbiddenUniverseLabel reports whether a chain's human label names a forbidden
// off-network white-label universe. Case-insensitive substring match — no Lux/Hanzo/Zoo
// chain label contains these tokens, so the match is precise to the forbidden brands.
func IsForbiddenUniverseLabel(label string) bool {
	l := strings.ToLower(label)
	for _, t := range forbiddenUniverseLabels {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

// IsMockLiquidityRef reports whether a label names mock/synthetic/phantom liquidity.
// Case-insensitive.
func IsMockLiquidityRef(label string) bool {
	l := strings.ToLower(label)
	for _, t := range mockLiquidityTokens {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

// looksLikeASCIITickerID reports whether a string is being used as an asset IDENTITY
// rather than a display symbol. An AssetID is a 32-byte hash; a bare ticker like
// "LUX" or "BTC-USD" used where an id is expected is the anti-pattern. We flag a
// short all-uppercase-with-separators token because that is the classic
// ticker-as-id shape. This guards the SYMBOL field (which is display-only) from
// being relied on as identity, and the manifest validator from accepting a ticker in
// place of a real reference.
//
// It deliberately does NOT reject normal symbols outright — a symbol may BE "LUX".
// It rejects the specific case where such a token appears where a canonical id /
// reference is required (see manifest validation), and it is also used by Asset to
// keep the symbol field from masquerading as an id when the symbol literally encodes
// a pair-id like "LUX/USDC" or "LUX-USDC@venue".
func looksLikeASCIITickerID(s string) bool {
	if s == "" {
		return false
	}
	// A pair-shaped symbol (contains a market separator) is an id masquerading as a
	// label — a real per-asset symbol never names two assets.
	for _, sep := range []string{"/", "-", ":", "@", "_"} {
		if strings.Contains(s, sep) {
			// allow a single hyphen inside a normal name token only if the result
			// is not all-caps ticker shaped; pair separators on an ALL-CAPS token
			// are the giveaway.
			if isUpperTickerish(s) {
				return true
			}
		}
	}
	return false
}

// isUpperTickerish reports whether s is composed only of A-Z, 0-9 and market
// separators (the alphabet of a ticker / pair id), with at least one letter. A
// human Name like "USD Coin" has a space and lowercase, so it is not tickerish; a
// pair id like "LUX/USDC" is.
func isUpperTickerish(s string) bool {
	hasLetter := false
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9':
		case r == '/' || r == '-' || r == ':' || r == '@' || r == '_':
		default:
			return false
		}
	}
	return hasLetter
}

// AssertNoForbiddenAssetRefs is the per-asset deny-gate: it refuses an asset whose
// SOURCE CHAIN is labeled a forbidden off-network white-label universe (Liquid/Liquidity/
// satschel), or whose symbol/name names mock/synthetic liquidity, or whose symbol is an
// ASCII-ticker id. The chain-label scan is the negative half of the never-mix-Liquidity
// boundary — a branded universe is refused BY NAME even when the token is real on-chain
// (the positive ChainVerifier gate proves existence; it does not police brand).
func AssertNoForbiddenAssetRefs(a Asset, chainLabel string) error {
	if IsForbiddenUniverseLabel(chainLabel) {
		return fmt.Errorf("registry: asset source chain %q is a forbidden off-network white-label universe", chainLabel)
	}
	if IsMockLiquidityRef(a.Symbol) || IsMockLiquidityRef(a.Name) {
		return fmt.Errorf("registry: asset symbol/name names mock/synthetic/phantom liquidity")
	}
	if looksLikeASCIITickerID(a.Symbol) {
		return fmt.Errorf("registry: asset symbol %q is an ASCII-ticker id; assets are keyed by AssetID", a.Symbol)
	}
	return nil
}

// --- hex helpers (canonicalRef / venueConfig JSON encoding) -----------------

func toHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

func fromHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return []byte{}, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("registry: invalid hex reference %q: %w", s, err)
	}
	return b, nil
}
