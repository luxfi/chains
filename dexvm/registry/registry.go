// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/luxfi/ids"
)

// RiskTier is an operator-assigned risk classification for an asset. It is metadata
// (it does not gate admissibility — only REALITY gates admissibility), used by the
// venue to set conservative caps on newer/lower-tier assets. Tier0 is the safest
// (the primary-network native coin and blue-chip stables); higher numbers are
// riskier.
type RiskTier uint8

const (
	RiskTier0 RiskTier = 0 // primary-network native + canonical stables
	RiskTier1 RiskTier = 1 // established, audited tokens
	RiskTier2 RiskTier = 2 // newer / lower-liquidity tokens
	RiskTier3 RiskTier = 3 // experimental — tightest caps
)

// Valid bounds the tier to the defined range.
func (t RiskTier) Valid() bool { return t <= RiskTier3 }

// Asset is a single registered, real, on-chain asset. Its AssetID is DERIVED from
// the canonical fields (networkID, chainID, assetKind, canonicalRef) — never
// supplied independently — so the identity and the description can never disagree.
//
// This is the AssetRegistry record the task specifies:
//
//	AssetRegistry{networkID, chainID, assetKind, canonicalRef, decimals, symbol, name, enabled, riskTier}
type Asset struct {
	// NetworkID is the Lux network this asset lives on (1 mainnet, 2 testnet, ...).
	NetworkID uint32 `json:"networkID"`
	// ChainID is the SOURCE chain id: the C-Chain id for EVM_NATIVE/ERC20, the
	// UTXO source-chain id (X-Chain) for UTXO.
	ChainID ids.ID `json:"chainID"`
	// Kind is the asset class (EVM_NATIVE | ERC20 | UTXO).
	Kind AssetKind `json:"assetKind"`
	// CanonicalRef is the on-chain reference bytes: the 20-byte ERC-20 address, the
	// 20-byte native marker, or the 32-byte UTXO assetID. Hex-encoded in JSON.
	CanonicalRef Bytes `json:"canonicalRef"`
	// Decimals is the asset's on-chain decimal precision (ERC-20 decimals(),
	// native/UTXO denomination). Verified against chain state for ERC-20.
	Decimals uint8 `json:"decimals"`
	// Symbol/Name are display metadata. They are NOT identity (the AssetID does not
	// hash them) and they are NOT a ticker-id — an asset is keyed by AssetID, never
	// by Symbol. They exist for the UI only.
	Symbol string `json:"symbol"`
	Name   string `json:"name"`
	// Enabled gates whether this asset (and markets over it) may trade. A disabled
	// asset stays registered (auditable) but admits no markets.
	Enabled bool `json:"enabled"`
	// RiskTier is the operator risk classification (caps input, not admissibility).
	RiskTier RiskTier `json:"riskTier"`
}

// ID returns the canonical AssetID for this record, derived from its real fields.
func (a Asset) ID() (ids.ID, error) {
	return DeriveAssetID(a.NetworkID, a.ChainID, a.Kind, a.CanonicalRef)
}

// validateShape checks the record is internally well-formed BEFORE any chain I/O:
// valid kind, valid ref shape, valid tier, sane decimals. It does NOT check reality
// (that is VerifyOnChain). A record that fails the shape check can never be real, so
// we reject it early and cheaply.
func (a Asset) validateShape() error {
	if !a.Kind.Valid() {
		return ErrInvalidKind
	}
	if !a.RiskTier.Valid() {
		return fmt.Errorf("registry: risk tier %d out of range", uint8(a.RiskTier))
	}
	// canonicalRefFor enforces per-kind ref shape (length, non-zero, native marker).
	if _, err := canonicalRefFor(a.Kind, a.CanonicalRef); err != nil {
		return err
	}
	if a.ChainID == ids.Empty {
		return ErrEmptyChainID
	}
	// A symbol that looks like an asset IDENTITY (rather than a display label) is a
	// red flag for the ASCII-ticker-as-id anti-pattern; we keep symbols as pure
	// display by forbidding the obviously-id-shaped ones.
	if looksLikeASCIITickerID(a.Symbol) {
		return fmt.Errorf("registry: symbol %q looks like an ASCII-ticker asset id; symbols are display-only, assets are keyed by AssetID", a.Symbol)
	}
	return nil
}

// ChainVerifier proves an asset is REAL on its target network by reading live chain
// state. It is injected so the registry's admission logic is identical whether it
// runs offline in CI (a verifier backed by JSON-RPC against the target net) or at
// node startup (a verifier backed by the local chain state). Tests inject a verifier
// backed by an in-memory chain snapshot — the rejection paths are exercised for
// real, never stubbed to always-true.
type ChainVerifier interface {
	// VerifyERC20 confirms a contract exists at addr on the given C-Chain of the
	// given network (code length > 0) and returns its on-chain decimals(). An error
	// means the token is not real there (no code, wrong chain, RPC failure) and the
	// asset MUST be refused.
	VerifyERC20(networkID uint32, cChainID ids.ID, addr []byte) (decimals uint8, err error)
	// VerifyEVMNative confirms the C-Chain itself is the expected native chain for
	// the network (chainID matches) and returns the native decimals.
	VerifyEVMNative(networkID uint32, cChainID ids.ID) (decimals uint8, err error)
	// VerifyUTXOAsset confirms a UTXO assetID exists on the given source chain of
	// the given network and returns its denomination (decimals). An error means the
	// asset does not exist there and MUST be refused.
	VerifyUTXOAsset(networkID uint32, sourceChainID ids.ID, assetID ids.ID) (decimals uint8, err error)
}

// VerifyOnChain proves the asset is real against live chain state via v, and that
// its declared decimals match what the chain reports. This is the gate that makes
// "synthetic asset" unrepresentable: a synthetic asset has nothing for the verifier
// to find, so VerifyOnChain returns an error and the asset is never admitted.
func (a Asset) VerifyOnChain(v ChainVerifier) error {
	if err := a.validateShape(); err != nil {
		return err
	}
	var onChainDecimals uint8
	var err error
	switch a.Kind {
	case AssetKindERC20:
		onChainDecimals, err = v.VerifyERC20(a.NetworkID, a.ChainID, a.CanonicalRef)
	case AssetKindEVMNative:
		onChainDecimals, err = v.VerifyEVMNative(a.NetworkID, a.ChainID)
	case AssetKindUTXO:
		var assetID ids.ID
		copy(assetID[:], a.CanonicalRef)
		onChainDecimals, err = v.VerifyUTXOAsset(a.NetworkID, a.ChainID, assetID)
	default:
		return ErrInvalidKind
	}
	if err != nil {
		return fmt.Errorf("registry: asset %s not real on network %d: %w", a.Kind, a.NetworkID, err)
	}
	if onChainDecimals != a.Decimals {
		return fmt.Errorf("registry: declared decimals %d != on-chain decimals %d for %s asset",
			a.Decimals, onChainDecimals, a.Kind)
	}
	return nil
}

var (
	// ErrUnknownAsset is returned when a market (or any caller) references an
	// AssetID that is not registered — the structural form of "synthetic asset".
	ErrUnknownAsset = errors.New("registry: asset is not registered (unknown/synthetic)")
	// ErrAssetDisabled is returned when a referenced asset is registered but disabled.
	ErrAssetDisabled = errors.New("registry: asset is registered but disabled")
	// ErrKindNotAllowed is returned when an asset's kind is not in the active
	// dexAllowedAssetKinds policy.
	ErrKindNotAllowed = errors.New("registry: asset kind not in allowed-kinds policy")
	// ErrDuplicateAsset is returned when registering an AssetID that already exists.
	ErrDuplicateAsset = errors.New("registry: asset already registered")
)

// Registry is the in-memory set of admitted real assets, keyed by canonical AssetID.
// It is the authority every admission decision consults. It is concurrency-safe; the
// hot path (Resolve) is a read under RLock.
type Registry struct {
	mu sync.RWMutex
	// allowedKinds is the active dexAllowedAssetKinds policy. An asset whose kind is
	// not present is refused at registration even if it is real — the policy is a
	// second, narrower gate on top of reality.
	allowedKinds map[AssetKind]struct{}
	byID         map[ids.ID]Asset
	// markets holds admitted trading pairs, each pinned to two registered assets.
	markets map[ids.ID]Market
}

// New constructs an empty Registry permitting the given asset kinds. With no kinds
// it admits nothing (fail-closed). The canonical production policy is all three:
// {EVM_NATIVE, ERC20, UTXO}.
func New(allowed ...AssetKind) *Registry {
	r := &Registry{
		allowedKinds: make(map[AssetKind]struct{}, len(allowed)),
		byID:         make(map[ids.ID]Asset),
		markets:      make(map[ids.ID]Market),
	}
	for _, k := range allowed {
		if k.Valid() {
			r.allowedKinds[k] = struct{}{}
		}
	}
	return r
}

// AllowsKind reports whether the active policy admits k.
func (r *Registry) AllowsKind(k AssetKind) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.allowedKinds[k]
	return ok
}

// Register admits a single asset after proving it is (a) well-formed, (b) of an
// allowed kind, and (c) REAL on its target network via v. It is the ONLY way an
// asset enters the registry — there is no path that admits an unverified asset. The
// derived AssetID is returned so callers can pin markets to it.
func (r *Registry) Register(a Asset, v ChainVerifier) (ids.ID, error) {
	if v == nil {
		return ids.Empty, errors.New("registry: Register requires a ChainVerifier (refusing to admit an unverified asset)")
	}
	if err := a.validateShape(); err != nil {
		return ids.Empty, err
	}
	if !r.AllowsKind(a.Kind) {
		return ids.Empty, fmt.Errorf("%w: %s", ErrKindNotAllowed, a.Kind)
	}
	if err := a.VerifyOnChain(v); err != nil {
		return ids.Empty, err
	}
	id, err := a.ID()
	if err != nil {
		return ids.Empty, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[id]; exists {
		return ids.Empty, fmt.Errorf("%w: %s", ErrDuplicateAsset, id)
	}
	r.byID[id] = a
	return id, nil
}

// Resolve returns the registered asset for an AssetID. ok is false for any
// unregistered (i.e. synthetic) id — this is the predicate the market gate and the
// startup gate use to refuse synthetic references.
func (r *Registry) Resolve(id ids.ID) (Asset, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byID[id]
	return a, ok
}

// MustResolveEnabled returns the asset for id, erroring if it is unknown
// (synthetic) or disabled. It is the strict resolver the market gate uses.
func (r *Registry) MustResolveEnabled(id ids.ID) (Asset, error) {
	a, ok := r.Resolve(id)
	if !ok {
		return Asset{}, fmt.Errorf("%w: %s", ErrUnknownAsset, id)
	}
	if !a.Enabled {
		return Asset{}, fmt.Errorf("%w: %s", ErrAssetDisabled, id)
	}
	return a, nil
}

// Len reports the number of registered assets.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// Each iterates registered assets (id, asset) in unspecified order. Used by the
// startup gate to audit every registered asset and by the manifest exporter.
func (r *Registry) Each(fn func(id ids.ID, a Asset)) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for id, a := range r.byID {
		fn(id, a)
	}
}

// Bytes is a []byte that marshals to/from hex in JSON, used for canonicalRef so a
// manifest carries token addresses and assetIDs as 0x-hex rather than base64.
type Bytes []byte

func (b Bytes) MarshalText() ([]byte, error) {
	return []byte(toHex(b)), nil
}

func (b *Bytes) UnmarshalText(t []byte) error {
	v, err := fromHex(strings.TrimSpace(string(t)))
	if err != nil {
		return err
	}
	*b = v
	return nil
}
