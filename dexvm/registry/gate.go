// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"errors"
	"fmt"

	"github.com/luxfi/ids"
)

// NetworkClass distinguishes the value-bearing networks (mainnet, testnet — where
// synthetic anything is forbidden) from dev networks (devnet/local — where a
// developer may opt into synthetic assets for testing, but ONLY there).
type NetworkClass uint8

const (
	NetworkClassDev     NetworkClass = 0 // devnet / localnet — synthetic flags MAY be set
	NetworkClassTestnet NetworkClass = 1 // testnet — synthetic flags FORBIDDEN
	NetworkClassMainnet NetworkClass = 2 // mainnet — synthetic flags FORBIDDEN
)

// String renders the class.
func (c NetworkClass) String() string {
	switch c {
	case NetworkClassMainnet:
		return "mainnet"
	case NetworkClassTestnet:
		return "testnet"
	default:
		return "dev"
	}
}

// valueBearing reports whether this network class forbids any synthetic flag. Both
// mainnet and testnet are value-bearing for the purpose of this gate.
func (c NetworkClass) valueBearing() bool {
	return c == NetworkClassMainnet || c == NetworkClassTestnet
}

// NetworkClassFor maps a Lux networkID to its class using the convention-fixed ids
// (1 mainnet, 2 testnet, 3 local, 1337 localnet) and treats every other id as a
// sovereign/dev network. Mainnet and testnet are the only value-bearing classes.
func NetworkClassFor(networkID uint32) NetworkClass {
	switch networkID {
	case 1:
		return NetworkClassMainnet
	case 2:
		return NetworkClassTestnet
	default:
		// 3 (local), 1337 (localnet), and every sovereign L1 id are dev-class for
		// the purpose of synthetic-flag permission. Value on those is still guarded
		// by the consensus-mode guard; this class only governs the synthetic flags.
		return NetworkClassDev
	}
}

// DexAssetPolicy is the backend-enforced, fail-closed configuration for the DEX's
// real-assets-only posture. Every field's SAFE value is the zero value, so a
// zero-initialised policy is the locked-down policy. These are the exact flags the
// task pins:
//
//	dexAllowSyntheticAssets   = false
//	dexAllowSyntheticMarkets  = false
//	dexAllowMockLiquidity     = false
//	dexAllowedAssetKinds      = [EVM_NATIVE, ERC20, UTXO]
//
// They are NOT front-end toggles: they live in the VM config and are read once at
// Initialize. A front end cannot relax them.
type DexAssetPolicy struct {
	// AllowSyntheticAssets, AllowSyntheticMarkets, AllowMockLiquidity default false.
	// On a value-bearing network (mainnet/testnet) any true value fails startup. On
	// a dev network a true value is permitted (developer opt-in) but is still subject
	// to the forbidden-reference scan (Liquidity is never allowed, anywhere).
	AllowSyntheticAssets  bool `json:"dexAllowSyntheticAssets"`
	AllowSyntheticMarkets bool `json:"dexAllowSyntheticMarkets"`
	AllowMockLiquidity    bool `json:"dexAllowMockLiquidity"`
	// AllowedAssetKinds is the active dexAllowedAssetKinds set. Empty is treated as
	// the canonical default {EVM_NATIVE, ERC20, UTXO}; an explicit set may only ever
	// be a SUBSET of those three — any other token is rejected by ParseAssetKind.
	AllowedAssetKinds []AssetKind `json:"dexAllowedAssetKinds"`
}

// DefaultDexAssetPolicy returns the canonical locked-down policy: no synthetic
// anything, all three real kinds allowed.
func DefaultDexAssetPolicy() DexAssetPolicy {
	return DexAssetPolicy{
		AllowSyntheticAssets:  false,
		AllowSyntheticMarkets: false,
		AllowMockLiquidity:    false,
		AllowedAssetKinds:     []AssetKind{AssetKindEVMNative, AssetKindERC20, AssetKindUTXO},
	}
}

// kinds returns the effective allowed-kind set: the canonical three when unset, else
// exactly the configured subset.
func (p DexAssetPolicy) kinds() []AssetKind {
	if len(p.AllowedAssetKinds) == 0 {
		return []AssetKind{AssetKindEVMNative, AssetKindERC20, AssetKindUTXO}
	}
	return p.AllowedAssetKinds
}

// AllowedKindsOrDefault is the exported effective allowed-kind set (the canonical three
// when unset, else the configured subset), used by the node to seed a Registry. It
// returns a fresh slice the caller may not mutate the policy through.
func (p DexAssetPolicy) AllowedKindsOrDefault() []AssetKind {
	return append([]AssetKind(nil), p.kinds()...)
}

// anySyntheticFlag reports whether any synthetic/mock flag is set.
func (p DexAssetPolicy) anySyntheticFlag() bool {
	return p.AllowSyntheticAssets || p.AllowSyntheticMarkets || p.AllowMockLiquidity
}

// AnySyntheticFlag is the exported predicate: true iff any synthetic/mock flag is set.
// The node uses it to MACHINE-DERIVE the HONEST_VALIDATOR_LAUNCH "real-assets-only"
// assertion rather than trusting an operator-supplied claim.
func (p DexAssetPolicy) AnySyntheticFlag() bool { return p.anySyntheticFlag() }

var (
	// ErrSyntheticOnValueNet is returned when any synthetic flag is true on
	// mainnet or testnet.
	ErrSyntheticOnValueNet = errors.New("startup: synthetic asset/market/liquidity flag set on a value-bearing network (mainnet/testnet)")
	// ErrEnabledMarketUnknownAsset is returned when an enabled market references an
	// asset that is not in the registry (synthetic).
	ErrEnabledMarketUnknownAsset = errors.New("startup: enabled market references an unknown/synthetic asset")
	// ErrBadAllowedKind is returned when dexAllowedAssetKinds contains a token that
	// is not one of the three real kinds.
	ErrBadAllowedKind = errors.New("startup: dexAllowedAssetKinds contains a non-real kind")
)

// RefuseUnderSyntheticConfig is the SINGLE fail-closed startup gate. It is called
// once at VM Initialize, BEFORE the chain accepts work, with the already-populated
// registry and the VM's network + policy. It refuses startup (returns an error,
// which the VM turns into a hard init failure) if ANY of the following hold:
//
//  1. dexAllowedAssetKinds contains a non-real kind (it may only ever be a subset
//     of {EVM_NATIVE, ERC20, UTXO}).
//  2. (mainnet OR testnet) AND any synthetic flag (assets/markets/liquidity) true.
//  3. Any ENABLED market references an asset not in the registry (unknown/synthetic),
//     references a disabled asset, or spans a network mismatch.
//  4. Any registered asset carries a forbidden reference: a Liquidity (white-label)
//     universe chain, mock/synthetic/phantom liquidity, an ASCII-ticker asset id, or
//     a declared-but-unbacked credit shape. (The positive reality check happened at
//     Register; this is the residual deny-scan over whatever is enabled, plus the
//     Liquidity/mock label scan that reality alone would not catch.)
//
// It returns nil ONLY when the registry is fully real and the policy is locked down
// for the network. Anything ambiguous fails closed.
//
// chainLabelFor maps a source chain id to its human label so the off-network-universe
// scan can run; pass a function that yields "" for unknown ids (an unknown id simply
// cannot be a known white-label universe, and its asset already passed the reality
// gate at Register).
func RefuseUnderSyntheticConfig(
	class NetworkClass,
	policy DexAssetPolicy,
	reg *Registry,
	chainLabelFor func(chainID ids.ID) string,
) error {
	// (1) allowed-kinds must be a subset of the three real kinds.
	for _, k := range policy.kinds() {
		if !k.Valid() {
			return fmt.Errorf("%w: %q", ErrBadAllowedKind, k.String())
		}
	}

	// (2) no synthetic flags on a value-bearing network.
	if class.valueBearing() && policy.anySyntheticFlag() {
		return fmt.Errorf("%w (network=%s synthAssets=%t synthMarkets=%t mockLiq=%t)",
			ErrSyntheticOnValueNet, class,
			policy.AllowSyntheticAssets, policy.AllowSyntheticMarkets, policy.AllowMockLiquidity)
	}

	// (4) deny-scan every registered asset for forbidden references. Run before the
	// market scan so a tainted asset is reported at its source.
	var scanErr error
	reg.Each(func(id ids.ID, a Asset) {
		if scanErr != nil {
			return
		}
		label := ""
		if chainLabelFor != nil {
			label = chainLabelFor(a.ChainID)
		}
		if err := AssertNoForbiddenAssetRefs(a, label); err != nil {
			scanErr = fmt.Errorf("registered asset %s: %w", id, err)
		}
	})
	if scanErr != nil {
		return scanErr
	}

	// (3) every ENABLED market must resolve both sides to a registered, enabled asset
	// on the matching network. A market over a synthetic asset has no AssetID to
	// resolve, so this catches it structurally.
	reg.EachMarket(func(id ids.ID, m Market) {
		if scanErr != nil || !m.Enabled {
			return
		}
		base, err := reg.MustResolveEnabled(m.BaseAssetID)
		if err != nil {
			scanErr = fmt.Errorf("%w: market %s base: %v", ErrEnabledMarketUnknownAsset, id, err)
			return
		}
		quote, err := reg.MustResolveEnabled(m.QuoteAssetID)
		if err != nil {
			scanErr = fmt.Errorf("%w: market %s quote: %v", ErrEnabledMarketUnknownAsset, id, err)
			return
		}
		if m.NetworkID != base.NetworkID || m.NetworkID != quote.NetworkID {
			scanErr = fmt.Errorf("%w: market %s network mismatch (market=%d base=%d quote=%d)",
				ErrEnabledMarketUnknownAsset, id, m.NetworkID, base.NetworkID, quote.NetworkID)
		}
	})
	return scanErr
}
