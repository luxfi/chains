// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"strings"
	"testing"

	"github.com/luxfi/ids"
)

// nativeManifest builds a minimal manifest with one EVM_NATIVE + one ERC-20 + one UTXO
// asset for the runtime-verifier tests.
func nativeManifest(networkID uint32, cChain, xChain, utxoAsset ids.ID, erc20 []byte) *Manifest {
	return &Manifest{
		Network:    "testnet",
		NetworkID:  networkID,
		EVMChainID: 96368,
		CChainID:   cChain,
		Assets: []Asset{
			{NetworkID: networkID, ChainID: cChain, Kind: AssetKindEVMNative, CanonicalRef: append([]byte(nil), EVMNativeMarker...), Decimals: 18, Symbol: "LUX", Name: "Lux", Enabled: true},
			{NetworkID: networkID, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: erc20, Decimals: 6, Symbol: "USDC", Name: "USD Coin", Enabled: true},
			{NetworkID: networkID, ChainID: xChain, Kind: AssetKindUTXO, CanonicalRef: utxoAsset[:], Decimals: 9, Symbol: "XAV", Name: "X asset", Enabled: true},
		},
	}
}

func TestRuntimeVerifier_BindsToRunningChainAndAdmitsRealEntries(t *testing.T) {
	cChain := ids.GenerateTestID()
	xChain := ids.GenerateTestID()
	utxoAsset := ids.GenerateTestID()
	erc20 := addr20(0x21)
	const net uint32 = 2

	m := nativeManifest(net, cChain, xChain, utxoAsset, erc20)
	if err := m.validateShape(); err != nil {
		t.Fatalf("manifest shape: %v", err)
	}
	rv, err := NewRuntimeVerifier(net, cChain, xChain, m)
	if err != nil {
		t.Fatalf("build runtime verifier: %v", err)
	}
	// Apply admits all three real entries and the gate passes.
	reg := New(AssetKindEVMNative, AssetKindERC20, AssetKindUTXO)
	if err := m.ApplyTo(reg, rv, DefaultDexAssetPolicy()); err != nil {
		t.Fatalf("manifest must admit through runtime verifier: %v", err)
	}
	if reg.Len() != 3 {
		t.Fatalf("expected 3 admitted assets, got %d", reg.Len())
	}
}

func TestRuntimeVerifier_RefusesWrongCChain(t *testing.T) {
	manifestC := ids.GenerateTestID()
	runningC := ids.GenerateTestID() // node runs a different C-Chain
	m := nativeManifest(2, manifestC, ids.GenerateTestID(), ids.GenerateTestID(), addr20(0x21))
	if _, err := NewRuntimeVerifier(2, runningC, ids.Empty, m); err == nil {
		t.Fatal("runtime verifier must refuse a manifest rooted at a C-Chain the node does not run")
	} else if !strings.Contains(err.Error(), "wrong-chain") {
		t.Fatalf("expected wrong-chain error, got: %v", err)
	}
}

func TestRuntimeVerifier_RefusesWrongNetwork(t *testing.T) {
	cChain := ids.GenerateTestID()
	m := nativeManifest(2, cChain, ids.GenerateTestID(), ids.GenerateTestID(), addr20(0x21))
	if _, err := NewRuntimeVerifier(1 /*running mainnet*/, cChain, ids.Empty, m); err == nil {
		t.Fatal("runtime verifier must refuse a manifest whose networkID != running network")
	}
}

func TestRuntimeVerifier_RefusesUTXOOffRunningXChain(t *testing.T) {
	cChain := ids.GenerateTestID()
	manifestX := ids.GenerateTestID()
	runningX := ids.GenerateTestID() // node runs a different X-Chain
	utxoAsset := ids.GenerateTestID()
	m := nativeManifest(2, cChain, manifestX, utxoAsset, addr20(0x21))
	rv, err := NewRuntimeVerifier(2, cChain, runningX, m)
	if err != nil {
		t.Fatalf("verifier build (C-Chain matches, X differs): %v", err)
	}
	// The C/native/ERC20 entries bind fine; the UTXO entry on the wrong X-Chain is
	// refused at admission.
	reg := New(AssetKindEVMNative, AssetKindERC20, AssetKindUTXO)
	if err := m.ApplyTo(reg, rv, DefaultDexAssetPolicy()); err == nil {
		t.Fatal("UTXO asset rooted off the node's X-Chain must be refused")
	}
}

func TestRuntimeVerifier_RefusesAssetNotInManifest(t *testing.T) {
	cChain := ids.GenerateTestID()
	m := nativeManifest(2, cChain, ids.GenerateTestID(), ids.GenerateTestID(), addr20(0x21))
	rv, err := NewRuntimeVerifier(2, cChain, ids.Empty, m)
	if err != nil {
		t.Fatalf("verifier build: %v", err)
	}
	// An ERC-20 the verifier was NOT built from (a different address) must be refused:
	// its reality was never CI-proven for this manifest.
	other := Asset{NetworkID: 2, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: addr20(0x99), Decimals: 6, Symbol: "OTH", Enabled: true}
	reg := New(AssetKindERC20)
	if _, err := reg.Register(other, rv); err == nil {
		t.Fatal("an asset absent from the runtime manifest must be refused at the node")
	}
}
