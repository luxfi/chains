// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"embed"
	"fmt"

	"github.com/luxfi/ids"
)

// embedded.go makes the per-network asset manifests available to a NODE BINARY with
// no filesystem dependency. The manifests are the SINGLE source of truth for which
// real assets the DEX admits on each network; embedding them means a validator carries
// the exact, CI-approved asset set in its binary and never has to locate a file on
// disk at boot. This is the registry's trust-root data: the value-path resolver the EVM
// plugin installs is built from exactly this.
//
// Selection is by the C-Chain's EVM chainID (eth_chainId), the unambiguous per-network
// identity the directive pins:
//
//	96369 -> mainnet  (networkID 1)
//	96368 -> testnet  (networkID 2)
//	96370 -> devnet   (networkID 3)
//	 1337 -> localnet (networkID 1337)  — see LocalnetNativeManifest below
//
// The three value/dev networks ship a committed manifest (mainnet/testnet/devnet);
// localnet's C-Chain id is environment-specific (it differs per genesis), so localnet
// has no committed manifest — its native-only manifest is synthesised at boot from the
// node's LIVE runtime C-Chain id (LocalnetNativeManifest), never from a constant.

//go:embed manifests/assets.mainnet.json manifests/assets.testnet.json manifests/assets.devnet.json
var manifestFS embed.FS

// EVM chainIDs of the three networks that ship a committed manifest. These are the
// eth_chainId values, NOT the consensus networkIDs (1/2/3). Localnet (1337) is handled
// separately because its C-Chain id is not fixed.
const (
	MainnetEVMChainID  uint64 = 96369
	TestnetEVMChainID  uint64 = 96368
	DevnetEVMChainID   uint64 = 96370
	LocalnetEVMChainID uint64 = 1337
)

// embeddedManifestPath maps an EVM chainID to its embedded manifest path. A chainID
// with no committed manifest is absent (ok=false) — the caller then either synthesises
// the localnet native manifest or fails closed (no resolver installed).
func embeddedManifestPath(evmChainID uint64) (string, bool) {
	switch evmChainID {
	case MainnetEVMChainID:
		return "manifests/assets.mainnet.json", true
	case TestnetEVMChainID:
		return "manifests/assets.testnet.json", true
	case DevnetEVMChainID:
		return "manifests/assets.devnet.json", true
	default:
		return "", false
	}
}

// ErrNoEmbeddedManifest is returned when no committed manifest exists for an EVM
// chainID (e.g. localnet 1337, or an unknown sovereign chainID). The caller decides
// whether to synthesise a native-only manifest (localnet) or stay fail-closed.
var ErrNoEmbeddedManifest = fmt.Errorf("registry: no embedded asset manifest for this EVM chainID")

// EmbeddedManifestFor loads, content-hashes, and shape-validates the committed manifest
// for an EVM chainID, returning the parsed manifest and the manifest bytes' SHA-256
// (lowercase hex). It performs the SAME shape validation LoadManifest does. It is the
// node-side entry point that replaces a filesystem LoadManifest: the bytes are the ones
// compiled into the binary, so there is no on-disk file to tamper with.
//
// A chainID with no committed manifest returns ErrNoEmbeddedManifest (the localnet /
// unknown-chain case the caller handles explicitly).
func EmbeddedManifestFor(evmChainID uint64) (*Manifest, string, error) {
	path, ok := embeddedManifestPath(evmChainID)
	if !ok {
		return nil, "", fmt.Errorf("%w (evmChainID=%d)", ErrNoEmbeddedManifest, evmChainID)
	}
	raw, err := manifestFS.ReadFile(path)
	if err != nil {
		// An embed path that does not resolve is a build-time bug, surfaced loudly.
		return nil, "", fmt.Errorf("registry: embedded manifest %s unreadable: %w", path, err)
	}
	return decodeManifestBytes(raw, path)
}

// LocalnetNativeManifest synthesises the localnet (chainID 1337) manifest IN MEMORY,
// containing ONLY the C-Chain native coin, rooted at the node's LIVE runtime ids
// (networkID, cChainID). It exists because localnet's C-Chain consensus id is not fixed
// across genesis runs, so no committed manifest can pin it — but the native coin is
// ALWAYS a real, known asset on any localnet C-Chain (it is the chain's own coin), so
// admitting exactly it (and nothing else) keeps localnet swaps live out-of-the-box while
// every ERC-20 must still be registered explicitly (its address is unknown until it is
// deployed). The cChainID comes from the runtime, NEVER a constant — so the resulting
// resolver is identity-bound exactly like the committed-manifest path.
//
// networkID must be the localnet convention id (1337); cChainID must be the node's live
// C-Chain consensus id (non-empty). The returned manifest passes validateShape.
func LocalnetNativeManifest(networkID uint32, cChainID ids.ID) (*Manifest, error) {
	if cChainID == ids.Empty {
		return nil, fmt.Errorf("registry: localnet native manifest requires a non-empty live C-Chain id")
	}
	m := &Manifest{
		Network:    "localnet",
		NetworkID:  networkID,
		EVMChainID: LocalnetEVMChainID,
		CChainID:   cChainID,
		Assets: []Asset{{
			NetworkID:    networkID,
			ChainID:      cChainID,
			Kind:         AssetKindEVMNative,
			CanonicalRef: append(Bytes(nil), EVMNativeMarker...),
			Decimals:     18,
			Symbol:       "LUX",
			Name:         "Lux",
			Enabled:      true,
			RiskTier:     RiskTier0,
		}},
		Markets: nil,
	}
	if err := m.validateShape(); err != nil {
		return nil, fmt.Errorf("registry: synthesised localnet native manifest invalid: %w", err)
	}
	return m, nil
}
