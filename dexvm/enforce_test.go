// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// enforce_test.go — Gate A end-to-end: the backend-enforced real-assets-only startup
// gate. These tests drive enforceRealAssetsOnly exactly as VM.Initialize does, proving
// it REFUSES synthetic flags on value nets, value activation without a legal consensus
// mode, a wrong-net / Liquidity manifest, and a value launch with no real assets — and
// ADMITS a clean manifest under a legal value mode.
package dexvm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luxfi/chains/dexvm/config"
	"github.com/luxfi/chains/dexvm/registry"
	"github.com/luxfi/ids"
)

const (
	mainnetNet uint32 = 1
	devNet     uint32 = 1337
)

func addr20(seed byte) []byte {
	b := make([]byte, 20)
	for i := range b {
		b[i] = seed + byte(i) + 1
	}
	return b
}

// writeRealManifest writes a manifest with two real ERC-20 assets and their market on
// the given C-Chain, returning the path. The assets are "real" for the node gate via
// the RuntimeVerifier identity bind (per-token existence is the CI gate, not the node).
func writeRealManifest(t *testing.T, networkID uint32, cChain ids.ID, liquidityLabel bool) string {
	t.Helper()
	wlux := addr20(0x4a)
	lusd := addr20(0x84)
	wluxID, _ := registry.DeriveAssetID(networkID, cChain, registry.AssetKindERC20, wlux)
	lusdID, _ := registry.DeriveAssetID(networkID, cChain, registry.AssetKindERC20, lusd)
	label := "Lux C-Chain"
	if liquidityLabel {
		label = "Liquidity primary network"
	}
	m := registry.Manifest{
		Network:     "mainnet",
		NetworkID:   networkID,
		EVMChainID:  96369,
		CChainID:    cChain,
		ChainLabels: map[string]string{cChain.Hex(): label},
		Assets: []registry.Asset{
			{NetworkID: networkID, ChainID: cChain, Kind: registry.AssetKindERC20, CanonicalRef: wlux, Decimals: 18, Symbol: "WLUX", Name: "Wrapped LUX", Enabled: true, RiskTier: registry.RiskTier0},
			{NetworkID: networkID, ChainID: cChain, Kind: registry.AssetKindERC20, CanonicalRef: lusd, Decimals: 18, Symbol: "LUSD", Name: "Lux Dollar", Enabled: true, RiskTier: registry.RiskTier0},
		},
		Markets: []registry.Market{
			{NetworkID: networkID, BaseAssetID: wluxID, QuoteAssetID: lusdID, VenueConfig: []byte("tick=1;lot=1;fee=30"), Enabled: true},
		},
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	path := filepath.Join(t.TempDir(), "assets.mainnet.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

// TestGateA_CleanManifestUnderQuorumFinality is the happy path: a real manifest on the
// node's running C-Chain, value enabled under QUORUM_FINALITY, admits and surfaces no
// disclaimer.
func TestGateA_CleanManifestUnderQuorumFinality(t *testing.T) {
	cChain := ids.GenerateTestID()
	cfg := config.DefaultConfig()
	cfg.DexAssetManifestPath = writeRealManifest(t, mainnetNet, cChain, false)
	cfg.DexNativeValueEnabled = true
	cfg.DexConsensusMode = "QUORUM_FINALITY"

	st, err := enforceRealAssetsOnly(cfg, mainnetNet, cChain, ids.GenerateTestID())
	if err != nil {
		t.Fatalf("clean manifest under QUORUM_FINALITY must pass: %v", err)
	}
	if st.Mode != registry.ConsensusModeQuorumFinality {
		t.Fatalf("wrong value mode: %s", st.Mode)
	}
	if st.Status != "" {
		t.Fatalf("QUORUM_FINALITY must not surface a disclaimer, got %q", st.Status)
	}
}

// TestGateA_HonestValidatorLabeledSurfacesDisclaimer proves the labeled CFT-parity mode
// activates only with caps-on + halt-ready (real-assets-only is machine-derived) and
// surfaces the exact no-Byzantine-finality string.
func TestGateA_HonestValidatorLabeledSurfacesDisclaimer(t *testing.T) {
	cChain := ids.GenerateTestID()
	base := config.DefaultConfig()
	base.DexAssetManifestPath = writeRealManifest(t, mainnetNet, cChain, false)
	base.DexNativeValueEnabled = true
	base.DexConsensusMode = "HONEST_VALIDATOR_LABELED"

	// Missing caps => refused.
	noCaps := base
	noCaps.DexCapsOn = false
	noCaps.DexHaltReady = true
	if _, err := enforceRealAssetsOnly(noCaps, mainnetNet, cChain, ids.Empty); !errors.Is(err, registry.ErrLaunchAssertionsUnmet) {
		t.Fatalf("HONEST_VALIDATOR_LABELED without caps must refuse, got: %v", err)
	}

	// Full bundle => admitted with the disclaimer.
	full := base
	full.DexCapsOn = true
	full.DexHaltReady = true
	st, err := enforceRealAssetsOnly(full, mainnetNet, cChain, ids.Empty)
	if err != nil {
		t.Fatalf("HONEST_VALIDATOR_LABELED with full bundle must pass: %v", err)
	}
	if st.Status != registry.NoByzantineFinalityClaim {
		t.Fatalf("must surface no-Byzantine-finality disclaimer, got %q", st.Status)
	}
}

// TestGateA_RefusesSyntheticFlagOnMainnet proves a synthetic flag fails startup on a
// value-bearing network, regardless of manifest.
func TestGateA_RefusesSyntheticFlagOnMainnet(t *testing.T) {
	cChain := ids.GenerateTestID()
	cfg := config.DefaultConfig()
	cfg.DexAssetManifestPath = writeRealManifest(t, mainnetNet, cChain, false)
	cfg.DexAllowSyntheticAssets = true // forbidden on mainnet

	if _, err := enforceRealAssetsOnly(cfg, mainnetNet, cChain, ids.Empty); !errors.Is(err, registry.ErrSyntheticOnValueNet) {
		t.Fatalf("synthetic flag on mainnet must refuse startup, got: %v", err)
	}

	// On a DEV network the same flag is permitted (developer opt-in). Use a dev manifest
	// (devNet) so the manifest's networkID matches.
	devCfg := config.DefaultConfig()
	devCfg.DexAssetManifestPath = writeRealManifest(t, devNet, cChain, false)
	devCfg.DexAllowSyntheticAssets = true
	if _, err := enforceRealAssetsOnly(devCfg, devNet, cChain, ids.Empty); err != nil {
		t.Fatalf("dev network must permit synthetic flag: %v", err)
	}
}

// TestGateA_RefusesValueWithoutLegalMode proves native value cannot activate under an
// UNSET or unknown consensus mode.
func TestGateA_RefusesValueWithoutLegalMode(t *testing.T) {
	cChain := ids.GenerateTestID()
	cfg := config.DefaultConfig()
	cfg.DexAssetManifestPath = writeRealManifest(t, mainnetNet, cChain, false)
	cfg.DexNativeValueEnabled = true
	cfg.DexConsensusMode = "" // UNSET

	if _, err := enforceRealAssetsOnly(cfg, mainnetNet, cChain, ids.Empty); !errors.Is(err, registry.ErrValueModeUnset) {
		t.Fatalf("value with UNSET mode must refuse, got: %v", err)
	}

	cfg.DexConsensusMode = "PARTIAL_FINALITY" // unknown token
	if _, err := enforceRealAssetsOnly(cfg, mainnetNet, cChain, ids.Empty); err == nil {
		t.Fatal("value with unknown consensus mode must refuse")
	}
}

// TestGateA_RefusesWrongNetManifest proves the RuntimeVerifier identity bind catches a
// manifest built for a different C-Chain than the node is running.
func TestGateA_RefusesWrongNetManifest(t *testing.T) {
	manifestChain := ids.GenerateTestID()
	runningChain := ids.GenerateTestID() // node runs a DIFFERENT C-Chain
	cfg := config.DefaultConfig()
	cfg.DexAssetManifestPath = writeRealManifest(t, mainnetNet, manifestChain, false)

	if _, err := enforceRealAssetsOnly(cfg, mainnetNet, runningChain, ids.Empty); err == nil {
		t.Fatal("manifest rooted at a C-Chain the node does not run must refuse startup")
	} else if !strings.Contains(err.Error(), "wrong-chain") {
		t.Fatalf("expected wrong-chain identity-bind error, got: %v", err)
	}
}

// TestGateA_RefusesLiquidityManifest proves a Liquidity (white-label) universe label is
// refused even when the token is otherwise structurally real.
func TestGateA_RefusesLiquidityManifest(t *testing.T) {
	cChain := ids.GenerateTestID()
	cfg := config.DefaultConfig()
	cfg.DexAssetManifestPath = writeRealManifest(t, mainnetNet, cChain, true) // Liquidity label

	if _, err := enforceRealAssetsOnly(cfg, mainnetNet, cChain, ids.Empty); err == nil {
		t.Fatal("manifest labeling its chain a Liquidity universe must refuse startup")
	}
}

// TestGateA_RefusesValueWithNoRealAssets proves value cannot activate with an empty
// registry (no manifest).
func TestGateA_RefusesValueWithNoRealAssets(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DexNativeValueEnabled = true
	cfg.DexConsensusMode = "QUORUM_FINALITY"
	cfg.DexAssetManifestPath = "" // no real assets declared

	if _, err := enforceRealAssetsOnly(cfg, mainnetNet, ids.GenerateTestID(), ids.Empty); err == nil {
		t.Fatal("value activation with no real declared assets must refuse startup")
	}
}

// TestGateA_RefusesBadAllowedKind proves a non-real allowed-kind token fails startup.
func TestGateA_RefusesBadAllowedKind(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DexAllowedAssetKinds = []string{"ERC20", "D_NATIVE"} // D_NATIVE is not a real kind

	if _, err := enforceRealAssetsOnly(cfg, mainnetNet, ids.GenerateTestID(), ids.Empty); err == nil {
		t.Fatal("non-real allowed-kind token must refuse startup")
	}
}

// TestGateA_PaperModeNoManifestOK proves the default locked-down config (paper mode, no
// value, no manifest) starts fine on every network class — Gate A does not block a
// non-value deployment.
func TestGateA_PaperModeNoManifestOK(t *testing.T) {
	for _, net := range []uint32{mainnetNet, 2 /*testnet*/, devNet} {
		cfg := config.DefaultConfig()
		st, err := enforceRealAssetsOnly(cfg, net, ids.GenerateTestID(), ids.Empty)
		if err != nil {
			t.Fatalf("paper-mode default config must start on net %d: %v", net, err)
		}
		if st.Status != "" {
			t.Fatalf("paper mode surfaces no value disclaimer, got %q", st.Status)
		}
	}
}
