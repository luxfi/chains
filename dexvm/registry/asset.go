// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package registry is the DEX's real-assets-only enforcement layer: the single,
// orthogonal place that decides which assets and which markets are admissible.
//
// It exists to make ONE property structural rather than incidental: every asset
// the DEX ledger can ever credit or debit corresponds to a REAL object on-chain
// (an ERC-20 contract on the C-Chain, the C-Chain native coin, or a UTXO asset on
// the X-Chain). There is no "D-native asset" class, no synthetic asset, no
// ASCII-ticker identity, and no declared-but-unbacked credit. An asset's identity
// is a canonical hash of WHERE IT REALLY LIVES — so two parties, given the same
// chain, derive the same 32-byte AssetID, and a fabricated asset has no preimage.
//
// This package is deliberately independent of the matcher (which lives in-process
// in the C-Chain settlement precompile) and of the proxy's settle path. It is a
// pure identity + admission primitive: derive an AssetID, register a real asset,
// gate a market on two registered assets. Verification against live chain state is
// injected (ChainVerifier) so the same logic backs both the offline CI manifest
// validator and the node's fail-closed startup gate.
package registry

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/luxfi/ids"
)

// AssetKind is the CLOSED set of asset classes the DEX admits. There are exactly
// three. There is NO synthetic / D-native / declared class — adding one is a
// breaking change to the wire identity and is intentionally hard.
type AssetKind uint8

const (
	// AssetKindInvalid is the zero value and is never admissible. Keeping it at 0
	// means a zero-initialised struct fails closed.
	AssetKindInvalid AssetKind = 0
	// AssetKindEVMNative is the C-Chain native coin (e.g. LUX on the primary
	// network's C-Chain). Its on-chain reference is the fixed native marker.
	AssetKindEVMNative AssetKind = 1
	// AssetKindERC20 is an ERC-20 token deployed on the C-Chain. Its on-chain
	// reference is the 20-byte token contract address.
	AssetKindERC20 AssetKind = 2
	// AssetKindUTXO is a UTXO-model asset native to the X-Chain (or another
	// UTXO source chain). Its on-chain reference is the source-chain assetID.
	AssetKindUTXO AssetKind = 3
)

// String renders the kind as its canonical wire/JSON token. These exact strings
// appear in manifests and in the dexAllowedAssetKinds policy; they are part of the
// contract, not cosmetic.
func (k AssetKind) String() string {
	switch k {
	case AssetKindEVMNative:
		return "EVM_NATIVE"
	case AssetKindERC20:
		return "ERC20"
	case AssetKindUTXO:
		return "UTXO"
	default:
		return "INVALID"
	}
}

// Valid reports whether k is one of the three admissible kinds.
func (k AssetKind) Valid() bool {
	return k == AssetKindEVMNative || k == AssetKindERC20 || k == AssetKindUTXO
}

// MarshalText/UnmarshalText make AssetKind round-trip through JSON as its canonical
// token (EVM_NATIVE / ERC20 / UTXO), never as a bare integer. An unknown token —
// including any ASCII-ticker masquerading as a kind — fails closed.
func (k AssetKind) MarshalText() ([]byte, error) {
	if !k.Valid() {
		return nil, fmt.Errorf("registry: refuse to marshal invalid asset kind %d", uint8(k))
	}
	return []byte(k.String()), nil
}

func (k *AssetKind) UnmarshalText(b []byte) error {
	switch strings.TrimSpace(string(b)) {
	case "EVM_NATIVE":
		*k = AssetKindEVMNative
	case "ERC20":
		*k = AssetKindERC20
	case "UTXO":
		*k = AssetKindUTXO
	default:
		return fmt.Errorf("registry: unknown asset kind %q (only EVM_NATIVE, ERC20, UTXO)", string(b))
	}
	return nil
}

// ParseAssetKind is the imperative form of UnmarshalText for callers that hold a
// plain string (manifest loaders, the allowed-kinds policy parser).
func ParseAssetKind(s string) (AssetKind, error) {
	var k AssetKind
	if err := k.UnmarshalText([]byte(s)); err != nil {
		return AssetKindInvalid, err
	}
	return k, nil
}

// EVMNativeMarker is the fixed on-chain reference for the C-Chain native coin.
// EVM_NATIVE has no contract address, so its canonical reference is this constant
// 20-byte marker (the EVM zero address — the EVM's own sentinel for "the native
// coin"). Folding a fixed, kind-tagged marker means every party derives the same
// EVM_NATIVE AssetID for a given (networkID, C-chainID) and nobody can invent a
// second native asset.
var EVMNativeMarker = make([]byte, 20) // 20 zero bytes == EVM address(0)

var (
	// ErrInvalidKind is returned when an asset's kind is not one of the three.
	ErrInvalidKind = errors.New("registry: asset kind is not EVM_NATIVE, ERC20 or UTXO")
	// ErrBadRef is returned when an asset's canonical reference does not match the
	// shape its kind requires (e.g. a 19-byte ERC-20 address).
	ErrBadRef = errors.New("registry: canonical reference does not match asset kind")
	// ErrEmptyChainID is returned when the source chain of an asset is the empty id.
	ErrEmptyChainID = errors.New("registry: asset source chain id is empty")
)

// Domain-separation tags. Folded as the FIRST field of every AssetID preimage so
// the three kinds occupy disjoint hash spaces: an ERC-20 whose 20-byte address
// numerically equals the low bytes of a UTXO assetID can never collide, because
// the tag byte differs and the length-prefixed fold forbids field-boundary
// aliasing. Versioned so a future migration can re-domain without ambiguity.
var (
	domAssetV1  = []byte("lux:dex:asset:v1")
	domMarketV1 = []byte("lux:dex:market:v1")
)

// canonicalRefFor validates and returns the canonical on-chain reference bytes for
// a (kind, ref) pair. This is the SINGLE place that decides what a well-formed
// reference looks like per kind — the derivation and the registry both call it, so
// the shape rule lives in exactly one spot.
//
//   - EVM_NATIVE: ref must equal EVMNativeMarker (20 zero bytes). The native coin
//     has no address; we pin the marker so no caller can smuggle a non-native ref
//     into the native kind.
//   - ERC20:      ref must be a 20-byte token contract address, and not the zero
//     address (the zero address is the native marker, never a token).
//   - UTXO:       ref must be a 32-byte source-chain assetID.
func canonicalRefFor(kind AssetKind, ref []byte) ([]byte, error) {
	switch kind {
	case AssetKindEVMNative:
		if len(ref) != 20 {
			return nil, fmt.Errorf("%w: EVM_NATIVE marker must be 20 bytes, got %d", ErrBadRef, len(ref))
		}
		if !allZero(ref) {
			return nil, fmt.Errorf("%w: EVM_NATIVE reference must be the native marker (address zero)", ErrBadRef)
		}
		// Normalise to the canonical marker so callers can't pass a distinct
		// all-zero-but-differently-typed slice.
		return append([]byte(nil), EVMNativeMarker...), nil
	case AssetKindERC20:
		if len(ref) != 20 {
			return nil, fmt.Errorf("%w: ERC20 token address must be 20 bytes, got %d", ErrBadRef, len(ref))
		}
		if allZero(ref) {
			return nil, fmt.Errorf("%w: ERC20 token address must not be the zero address", ErrBadRef)
		}
		return append([]byte(nil), ref...), nil
	case AssetKindUTXO:
		if len(ref) != 32 {
			return nil, fmt.Errorf("%w: UTXO assetID must be 32 bytes, got %d", ErrBadRef, len(ref))
		}
		if allZero(ref) {
			return nil, fmt.Errorf("%w: UTXO assetID must not be empty", ErrBadRef)
		}
		return append([]byte(nil), ref...), nil
	default:
		return nil, ErrInvalidKind
	}
}

// DeriveAssetID computes the canonical, consensus-native 32-byte identity of a real
// on-chain asset. The identity is a length-prefixed SHA-256 fold over, in order:
//
//	domAssetV1 | networkID | sourceChainID | kind | canonicalRef
//
// matching the per-kind formulas exactly:
//
//	ERC20:      H(networkID, C-chainID, ERC20,      token-address)
//	EVM_NATIVE: H(networkID, C-chainID, EVM_NATIVE, native-marker)
//	UTXO:       H(networkID, X-chain-id, UTXO,      assetID)
//
// sourceChainID is the C-Chain id for EVM_NATIVE/ERC20 and the UTXO source chain id
// (X-Chain) for UTXO. The fold is length-prefixed (each field's length precedes its
// bytes) so no two distinct field tuples share a preimage, and the kind byte
// domain-separates the three classes. The result is an ids.ID — the SAME identity
// space the on-chain atomic objects already use (AtomicInput.Asset,
// AtomicOutput.Asset, RelayOrderTx.AssetOut) — so a registered AssetID is directly
// comparable to the asset a real cross-chain object carries. It is NEVER a string
// ticker.
func DeriveAssetID(networkID uint32, sourceChainID ids.ID, kind AssetKind, ref []byte) (ids.ID, error) {
	if sourceChainID == ids.Empty {
		return ids.Empty, ErrEmptyChainID
	}
	cref, err := canonicalRefFor(kind, ref)
	if err != nil {
		return ids.Empty, err
	}

	var f folder
	f.tag(domAssetV1)
	f.u32(networkID)
	f.bytes(sourceChainID[:])
	f.u8(uint8(kind))
	f.bytes(cref)
	return f.sum(), nil
}

// MarketID computes the canonical identity of a market from its two asset
// identities and the venue configuration:
//
//	marketID = H(networkID, baseAssetID, quoteAssetID, venueConfig)
//
// baseAssetID and quoteAssetID are themselves canonical AssetIDs (so a market is
// pinned to real assets by construction — you cannot name a market over a synthetic
// asset because there is no AssetID for one). venueConfig is the canonical bytes of
// the venue parameters (tick size, lot size, fee tier, etc.) that distinguish two
// venues on the same pair; callers pass its canonical serialization.
func MarketID(networkID uint32, baseAssetID, quoteAssetID ids.ID, venueConfig []byte) ids.ID {
	var f folder
	f.tag(domMarketV1)
	f.u32(networkID)
	f.bytes(baseAssetID[:])
	f.bytes(quoteAssetID[:])
	f.bytes(venueConfig)
	return f.sum()
}

// folder accumulates a length-prefixed, domain-separated preimage and folds it with
// SHA-256 — the same primitive and the same length-prefixed discipline as the
// existing consensus state hash in dexvm/state/state.go (crypto/sha256, each field
// length-prefixed). The length prefix on every field is what makes the fold
// injective: (networkID=1, ref=0x02) and (networkID=0x0102, ref=) cannot produce the
// same byte stream.
type folder struct {
	buf []byte
}

func (f *folder) raw(b []byte) {
	var lp [8]byte
	binary.BigEndian.PutUint64(lp[:], uint64(len(b)))
	f.buf = append(f.buf, lp[:]...)
	f.buf = append(f.buf, b...)
}

// tag folds a domain-separation constant. Same encoding as a field; named for intent.
func (f *folder) tag(b []byte) { f.raw(b) }

// bytes folds a variable-length field.
func (f *folder) bytes(b []byte) { f.raw(b) }

// u8 folds a single-byte field (the kind tag).
func (f *folder) u8(v uint8) { f.raw([]byte{v}) }

// u32 folds a 32-bit field (networkID) in big-endian.
func (f *folder) u32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	f.raw(b[:])
}

func (f *folder) sum() ids.ID {
	return ids.ID(sha256.Sum256(f.buf))
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
