// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"encoding/hex"
	"testing"

	"github.com/luxfi/ids"
)

// asset_golden_test.go is the registry side of the CANONICAL cross-home golden KAT
// (MED-1). It asserts that registry.DeriveAssetID reproduces the EXACT 32-byte AssetID
// bytes that dexcore.DeriveAssetID asserts in luxfi/dex pkg/dexcore (assetid_test.go,
// AssetIDGoldenVectors). The two homes derive the SAME id from the SAME fields by sharing
// the byte-identical preimage discipline (domain tag "lux:dex:asset:v1", length-prefixed
// SHA-256 fold, wire-pinned kind bytes). Pinning the IDENTICAL expected bytes in BOTH
// suites locks the resolve<->register equivalence the DEX value path depends on: a
// registered AssetID (here) and a swap-derived AssetID (dexcore, via the 0x9999 resolver)
// name the SAME asset by the SAME id. If either home's discipline drifts, BOTH KATs fail —
// a real consensus-identity divergence caught in CI, never in prod.
//
// These vectors are BYTE-FOR-BYTE the dexcore vectors: networkID=2, source chain id all
// 0x11, the three kinds. Do NOT edit a vector to make a test pass — a changed id is a fork.

// goldenChainAllOnes is the fixed 32-byte source chain id (every byte 0x11) the golden
// vectors are generated against — identical to dexcore's chainAllOnes().
func goldenChainAllOnes() ids.ID {
	var c ids.ID
	for i := range c {
		c[i] = 0x11
	}
	return c
}

func TestAssetID_GoldenKAT_MatchesDexcore(t *testing.T) {
	chain := goldenChainAllOnes()

	erc20 := make([]byte, 20)
	erc20[19] = 0x01
	utxo := make([]byte, 32)
	utxo[31] = 0x07

	vectors := []struct {
		name string
		kind AssetKind
		ref  []byte
		want string // BYTE-IDENTICAL to dexcore.AssetIDGoldenVectors
	}{
		{"ERC20/addr..01", AssetKindERC20, erc20, "dc392784b1b0764f885a2b24786850dae0a221fe7eaa218065ac1497473fa868"},
		{"EVM_NATIVE/marker", AssetKindEVMNative, EVMNativeMarker, "5941ecf871f909bac11b9b3d34fff1d05c7a0182f3a1c5b905ee6059dbb6dc72"},
		{"UTXO/asset..07", AssetKindUTXO, utxo, "5cd895b8a577437bdf39e921902cbf06c29a11ae4f1776b369584c46fc0d647d"},
	}

	for _, v := range vectors {
		got, err := DeriveAssetID(2, chain, v.kind, v.ref)
		if err != nil {
			t.Fatalf("%s: derive: %v", v.name, err)
		}
		if h := hex.EncodeToString(got[:]); h != v.want {
			t.Fatalf("%s: registry AssetID diverged from the dexcore golden KAT:\n got  %s\n want %s", v.name, h, v.want)
		}
	}
}
