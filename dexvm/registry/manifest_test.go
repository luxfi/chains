// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luxfi/ids"
)

// fakeChainConfirm is a fakeChain that also implements CChainConfirmer, so the
// manifest-level identity check is exercised. It confirms a single declared
// (networkID, evmChainID, cChainID) triple.
type fakeChainConfirm struct {
	*fakeChain
	networkID  uint32
	evmChainID uint64
	cChainID   ids.ID
}

func (f *fakeChainConfirm) ConfirmCChain(networkID uint32, evmChainID uint64, cChainID ids.ID) error {
	if networkID != f.networkID {
		return errNotOnChain
	}
	if evmChainID != f.evmChainID {
		return errNotOnChain
	}
	if cChainID != f.cChainID {
		return errNotOnChain
	}
	return nil
}

func TestManifest_LoadAndValidateRealEntries(t *testing.T) {
	cChain := ids.GenerateTestID()
	wlux := addr20(0x4a)
	lusd := addr20(0x84)

	fc := newFakeChain()
	fc.seedERC20(mainnetID, cChain, wlux, 18)
	fc.seedERC20(mainnetID, cChain, lusd, 18)
	v := &fakeChainConfirm{fakeChain: fc, networkID: mainnetID, evmChainID: 96369, cChainID: cChain}

	// Build a manifest in memory, write it to a temp file, then load + validate it
	// through the real LoadManifest -> Validate path (the same path CI uses).
	m := Manifest{
		Network:    "mainnet",
		NetworkID:  mainnetID,
		EVMChainID: 96369,
		CChainID:   cChain,
		ChainLabels: map[string]string{
			cChain.Hex(): "Lux C-Chain",
		},
		Assets: []Asset{
			{NetworkID: mainnetID, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: wlux, Decimals: 18, Symbol: "WLUX", Name: "Wrapped LUX", Enabled: true, RiskTier: RiskTier0},
			{NetworkID: mainnetID, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: lusd, Decimals: 18, Symbol: "LUSD", Name: "Lux Dollar", Enabled: true, RiskTier: RiskTier0},
		},
	}
	wluxID, _ := DeriveAssetID(mainnetID, cChain, AssetKindERC20, wlux)
	lusdID, _ := DeriveAssetID(mainnetID, cChain, AssetKindERC20, lusd)
	m.Markets = []Market{
		{NetworkID: mainnetID, BaseAssetID: wluxID, QuoteAssetID: lusdID, VenueConfig: []byte("tick=1;lot=1;fee=30"), Enabled: true},
	}

	path := writeManifest(t, m)
	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	reg, err := loaded.Validate(v)
	if err != nil {
		t.Fatalf("validate manifest against (fake) chain: %v", err)
	}
	if reg.Len() != 2 {
		t.Fatalf("expected 2 admitted assets, got %d", reg.Len())
	}
	if _, ok := reg.Resolve(wluxID); !ok {
		t.Fatal("WLUX not admitted")
	}
	if _, ok := reg.ResolveMarket((Market{NetworkID: mainnetID, BaseAssetID: wluxID, QuoteAssetID: lusdID, VenueConfig: []byte("tick=1;lot=1;fee=30")}).ID()); !ok {
		t.Fatal("WLUX/LUSD market not admitted")
	}
}

func TestManifest_RejectsWrongChainAndUnknownField(t *testing.T) {
	cChain := ids.GenerateTestID()
	wlux := addr20(0x4a)
	fc := newFakeChain()
	fc.seedERC20(mainnetID, cChain, wlux, 18)

	// (a) Verifier bound to a DIFFERENT cChainID => ConfirmCChain fails => validate fails.
	wrong := &fakeChainConfirm{fakeChain: fc, networkID: mainnetID, evmChainID: 96369, cChainID: ids.GenerateTestID()}
	m := Manifest{
		Network: "mainnet", NetworkID: mainnetID, EVMChainID: 96369, CChainID: cChain,
		Assets: []Asset{{NetworkID: mainnetID, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: wlux, Decimals: 18, Symbol: "WLUX", Enabled: true}},
	}
	if _, err := m.Validate(wrong); err == nil {
		t.Fatal("manifest validated against the wrong C-Chain; must be refused")
	}

	// (b) An ERC-20 entry whose chainID is not the manifest C-Chain => shape error.
	bad := Manifest{
		Network: "mainnet", NetworkID: mainnetID, EVMChainID: 96369, CChainID: cChain,
		Assets: []Asset{{NetworkID: mainnetID, ChainID: ids.GenerateTestID(), Kind: AssetKindERC20, CanonicalRef: wlux, Decimals: 18, Symbol: "WLUX", Enabled: true}},
	}
	if err := bad.validateShape(); err == nil {
		t.Fatal("ERC-20 rooted off the C-Chain must be rejected by shape validation")
	}

	// (c) A manifest file with an unknown field fails closed at load.
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"network":"mainnet","networkID":1,"evmChainID":96369,"cChainID":"`+cChain.String()+`","asssets":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("manifest with an unknown field must fail to load (DisallowUnknownFields)")
	}
}

func TestManifest_ForbiddenLiquidityLabelRefusesViaLoadedFile(t *testing.T) {
	cChain := ids.GenerateTestID()
	wlux := addr20(0x4a)
	fc := newFakeChain()
	fc.seedERC20(mainnetID, cChain, wlux, 18)
	v := &fakeChainConfirm{fakeChain: fc, networkID: mainnetID, evmChainID: 96369, cChainID: cChain}

	// A loaded manifest that labels its source chain as a Liquidity (white-label)
	// universe must be refused even though the token itself is real on-chain — the
	// label travels through the file -> chainLabelFor -> deny-scan path.
	m := Manifest{
		Network: "mainnet", NetworkID: mainnetID, EVMChainID: 96369, CChainID: cChain,
		ChainLabels: map[string]string{cChain.Hex(): "Liquidity primary network"},
		Assets:      []Asset{{NetworkID: mainnetID, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: wlux, Decimals: 18, Symbol: "WLUX", Enabled: true, RiskTier: RiskTier0}},
	}
	path := writeManifest(t, m)
	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := loaded.Validate(v); err == nil {
		t.Fatal("manifest with a Liquidity universe label must be refused")
	}
}

func writeManifest(t *testing.T, m Manifest) string {
	t.Helper()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	path := filepath.Join(t.TempDir(), m.Network+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}
