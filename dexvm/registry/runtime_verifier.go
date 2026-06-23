// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"fmt"

	"github.com/luxfi/ids"
)

// RuntimeVerifier is the node-side ChainVerifier used at VM Initialize. It is a REAL
// check, not a stub: it binds a manifest's DECLARED chain identities to the node's
// ACTUAL running chain ids (the consensus-supplied C-Chain and X-Chain ids), so a
// manifest built for the wrong network — or one that points an "ERC20" at a chain
// the node is not running — is REFUSED at startup. It returns the manifest's
// shape-validated decimals only AFTER that identity binding holds.
//
// Division of proof (deliberate, documented):
//
//   - The NODE (this verifier) proves chain-IDENTITY binding + structure + policy at
//     boot, with NO external RPC dependency (so a validator can start even if a remote
//     RPC is briefly unreachable). It catches a wrong-net / wrong-chain manifest.
//   - CI (the rpcverify.Verifier + the validate-asset-manifests workflow) proves each
//     token EXISTS on the live target net (eth_getCode length > 0, decimals(), UTXO
//     avm.getAssetDescription) BEFORE the manifest artifact ships. It catches a
//     fabricated/typo'd token address.
//
// Both are real, neither is "always true". A manifest that passes CI (reality) and the
// node's RuntimeVerifier (identity + policy) is admissible; either failing refuses it.
type RuntimeVerifier struct {
	// NetworkID is the node's running network id (runtime.Runtime.NetworkID).
	NetworkID uint32
	// CChainID is the node's running C-Chain consensus id (runtime.Runtime.CChainID).
	// EVM_NATIVE / ERC20 assets must be rooted here.
	CChainID ids.ID
	// XChainID is the node's running X-Chain id (runtime.Runtime.XChainID). UTXO assets
	// are accepted only from a UTXO source chain the node actually runs; when XChainID
	// is set, a UTXO asset rooted off it is refused.
	XChainID ids.ID
	// declaredDecimals is populated by the manifest loader from the shape-validated
	// entries so the verifier can return the asset's decimals after the identity bind
	// without re-reading the file. Keyed by canonical AssetID.
	declaredDecimals map[ids.ID]uint8
}

// NewRuntimeVerifier builds a RuntimeVerifier bound to the node's running chain ids and
// pre-loaded with the manifest's shape-validated decimals (so Register's decimals
// cross-check compares the manifest against itself consistently, and the identity bind
// is what gates admission). m must already have passed validateShape.
func NewRuntimeVerifier(networkID uint32, cChainID, xChainID ids.ID, m *Manifest) (*RuntimeVerifier, error) {
	if m == nil {
		return nil, fmt.Errorf("registry: RuntimeVerifier requires a manifest")
	}
	if m.NetworkID != networkID {
		return nil, fmt.Errorf("registry: manifest networkID %d != running network %d (wrong-net manifest)", m.NetworkID, networkID)
	}
	if cChainID == ids.Empty {
		return nil, fmt.Errorf("registry: running C-Chain id is empty (cannot bind manifest)")
	}
	if m.CChainID != cChainID {
		return nil, fmt.Errorf("registry: manifest cChainID %s != running C-Chain %s (wrong-chain manifest)", m.CChainID, cChainID)
	}
	rv := &RuntimeVerifier{
		NetworkID:        networkID,
		CChainID:         cChainID,
		XChainID:         xChainID,
		declaredDecimals: make(map[ids.ID]uint8, len(m.Assets)),
	}
	for _, a := range m.Assets {
		id, err := a.ID()
		if err != nil {
			return nil, fmt.Errorf("registry: manifest asset id: %w", err)
		}
		rv.declaredDecimals[id] = a.Decimals
	}
	return rv, nil
}

// ConfirmCChain implements CChainConfirmer: the manifest's network + C-Chain id must
// equal the node's running ids. (EVMChainID is RPC-checked by CI; at boot we bind the
// consensus C-Chain id, which is the authoritative cross-chain identity.)
func (rv *RuntimeVerifier) ConfirmCChain(networkID uint32, _ uint64, cChainID ids.ID) error {
	if networkID != rv.NetworkID {
		return fmt.Errorf("manifest network %d != running %d", networkID, rv.NetworkID)
	}
	if cChainID != rv.CChainID {
		return fmt.Errorf("manifest C-Chain %s != running %s", cChainID, rv.CChainID)
	}
	return nil
}

func (rv *RuntimeVerifier) decimalsFor(networkID uint32, chainID ids.ID, kind AssetKind, ref []byte) (uint8, error) {
	id, err := DeriveAssetID(networkID, chainID, kind, ref)
	if err != nil {
		return 0, err
	}
	d, ok := rv.declaredDecimals[id]
	if !ok {
		// The asset is not in the manifest the verifier was built from — it cannot be
		// admitted at the node (reality for it was never CI-proven).
		return 0, fmt.Errorf("asset %s not in the runtime manifest", id)
	}
	return d, nil
}

// VerifyERC20 binds the ERC-20 to the node's running C-Chain. Per-token code existence
// is the CI gate; here the asset must be on the chain the node actually runs.
func (rv *RuntimeVerifier) VerifyERC20(networkID uint32, cChainID ids.ID, addr []byte) (uint8, error) {
	if networkID != rv.NetworkID {
		return 0, fmt.Errorf("ERC20 network %d != running %d", networkID, rv.NetworkID)
	}
	if cChainID != rv.CChainID {
		return 0, fmt.Errorf("ERC20 rooted at C-Chain %s but node runs %s", cChainID, rv.CChainID)
	}
	return rv.decimalsFor(networkID, cChainID, AssetKindERC20, addr)
}

// VerifyEVMNative binds the native coin to the node's running C-Chain.
func (rv *RuntimeVerifier) VerifyEVMNative(networkID uint32, cChainID ids.ID) (uint8, error) {
	if networkID != rv.NetworkID {
		return 0, fmt.Errorf("EVM_NATIVE network %d != running %d", networkID, rv.NetworkID)
	}
	if cChainID != rv.CChainID {
		return 0, fmt.Errorf("EVM_NATIVE rooted at C-Chain %s but node runs %s", cChainID, rv.CChainID)
	}
	return rv.decimalsFor(networkID, cChainID, AssetKindEVMNative, EVMNativeMarker)
}

// VerifyUTXOAsset binds the UTXO asset to a UTXO source chain the node runs. When the
// node's XChainID is known, a UTXO asset rooted off it is refused (you cannot import a
// UTXO asset from a chain this node does not run).
func (rv *RuntimeVerifier) VerifyUTXOAsset(networkID uint32, sourceChainID ids.ID, assetID ids.ID) (uint8, error) {
	if networkID != rv.NetworkID {
		return 0, fmt.Errorf("UTXO network %d != running %d", networkID, rv.NetworkID)
	}
	if rv.XChainID != ids.Empty && sourceChainID != rv.XChainID {
		return 0, fmt.Errorf("UTXO rooted at source chain %s but node X-Chain is %s", sourceChainID, rv.XChainID)
	}
	return rv.decimalsFor(networkID, sourceChainID, AssetKindUTXO, assetID[:])
}
