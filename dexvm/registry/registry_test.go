// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"bytes"
	"errors"
	"testing"

	"github.com/luxfi/ids"
)

const mainnetID uint32 = 1

// realERC20 builds a registered+verifiable ERC-20 asset and seeds it on the fake
// chain so Register succeeds. Returns the asset and its derived id.
func realERC20(t *testing.T, fc *fakeChain, cChain ids.ID, addr []byte, sym string) (Asset, ids.ID) {
	t.Helper()
	fc.seedERC20(mainnetID, cChain, addr, 6)
	a := Asset{
		NetworkID:    mainnetID,
		ChainID:      cChain,
		Kind:         AssetKindERC20,
		CanonicalRef: addr,
		Decimals:     6,
		Symbol:       sym,
		Name:         sym + " token",
		Enabled:      true,
		RiskTier:     RiskTier1,
	}
	id, err := a.ID()
	if err != nil {
		t.Fatalf("derive id: %v", err)
	}
	return a, id
}

// --- (T1) TestNoSyntheticAssetCanRegister ----------------------------------
//
// A synthetic asset — one with no real on-chain object behind it — MUST be refused
// at registration. We attempt to register an ERC-20 whose address was never seeded
// on the fake chain (so it does not exist there), plus the structurally-impossible
// "D-native" / synthetic shapes, and assert every one is rejected.
func TestNoSyntheticAssetCanRegister(t *testing.T) {
	fc := newFakeChain()
	cChain := ids.GenerateTestID()
	reg := New(AssetKindEVMNative, AssetKindERC20, AssetKindUTXO)

	// (a) ERC-20 that does not exist on-chain (never seeded) — must be refused.
	ghost := Asset{
		NetworkID:    mainnetID,
		ChainID:      cChain,
		Kind:         AssetKindERC20,
		CanonicalRef: addr20(0x42),
		Decimals:     18,
		Symbol:       "GHOST",
		Name:         "Ghost token",
		Enabled:      true,
		RiskTier:     RiskTier2,
	}
	if _, err := reg.Register(ghost, fc); err == nil {
		t.Fatal("synthetic ERC-20 (no on-chain code) was registered; must be refused")
	}

	// (b) UTXO asset that does not exist on the source chain — must be refused.
	src := ids.GenerateTestID()
	phantomUTXO := Asset{
		NetworkID:    mainnetID,
		ChainID:      src,
		Kind:         AssetKindUTXO,
		CanonicalRef: idBytes(ids.GenerateTestID()),
		Decimals:     9,
		Symbol:       "PUTXO",
		Name:         "Phantom UTXO",
		Enabled:      true,
		RiskTier:     RiskTier2,
	}
	if _, err := reg.Register(phantomUTXO, fc); err == nil {
		t.Fatal("synthetic UTXO (not on source chain) was registered; must be refused")
	}

	// (c) An asset whose declared kind is the invalid/zero kind (the closest a
	//     caller can get to a "D-native" synthetic class) — must be refused as an
	//     invalid kind, never admitted.
	dNative := Asset{
		NetworkID:    mainnetID,
		ChainID:      cChain,
		Kind:         AssetKindInvalid, // there is no synthetic/D-native kind
		CanonicalRef: addr20(0x01),
		Decimals:     18,
		Symbol:       "DNAT",
		Enabled:      true,
	}
	if _, err := reg.Register(dNative, fc); !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("invalid/D-native kind admitted or wrong error: %v", err)
	}

	// (d) A REAL ERC-20 (seeded) registers fine — proves the verifier is not
	//     rejecting everything (the rejections above are genuine, not blanket).
	real, _ := realERC20(t, fc, cChain, addr20(0x99), "USDC")
	if _, err := reg.Register(real, fc); err != nil {
		t.Fatalf("real seeded ERC-20 should register: %v", err)
	}
	if reg.Len() != 1 {
		t.Fatalf("only the real asset should be registered, got %d", reg.Len())
	}
}

// --- (T2) TestNoSyntheticMarketCanStart ------------------------------------
//
// A market MUST fail creation unless BOTH sides resolve to a registered, real,
// enabled asset, and the fail-closed startup gate MUST refuse to start a chain whose
// enabled market references a synthetic asset.
func TestNoSyntheticMarketCanStart(t *testing.T) {
	fc := newFakeChain()
	cChain := ids.GenerateTestID()
	reg := New(AssetKindEVMNative, AssetKindERC20, AssetKindUTXO)

	// Register exactly one real asset (the quote). The base will be synthetic.
	usdc, usdcID := realERC20(t, fc, cChain, addr20(0x10), "USDC")
	if _, err := reg.Register(usdc, fc); err != nil {
		t.Fatalf("register quote: %v", err)
	}

	// Derive an AssetID for a base that was NEVER registered (synthetic).
	syntheticBaseID, err := DeriveAssetID(mainnetID, cChain, AssetKindERC20, addr20(0x7e))
	if err != nil {
		t.Fatalf("derive synthetic base id: %v", err)
	}

	// (a) CreateMarket must refuse because the base side does not resolve.
	_, err = reg.CreateMarket(Market{
		NetworkID:    mainnetID,
		BaseAssetID:  syntheticBaseID,
		QuoteAssetID: usdcID,
		Enabled:      true,
	})
	if !errors.Is(err, ErrUnknownAsset) {
		t.Fatalf("market over synthetic base should be refused with ErrUnknownAsset, got: %v", err)
	}

	// (b) A market over two REAL assets is created fine.
	lux, luxID := realERC20(t, fc, cChain, addr20(0x20), "WLUX")
	if _, err := reg.Register(lux, fc); err != nil {
		t.Fatalf("register base: %v", err)
	}
	mid, err := reg.CreateMarket(Market{
		NetworkID:    mainnetID,
		BaseAssetID:  luxID,
		QuoteAssetID: usdcID,
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("real market should be created: %v", err)
	}

	// (c) The startup gate passes for the all-real registry.
	if err := RefuseUnderSyntheticConfig(NetworkClassMainnet, DefaultDexAssetPolicy(), reg, nil); err != nil {
		t.Fatalf("startup gate should pass for all-real registry: %v", err)
	}

	// (d) Now smuggle a synthetic market straight into the registry's market map
	//     (simulating a corrupted/forced config that bypassed CreateMarket) and
	//     assert the startup gate REFUSES to start. This proves the gate is a real
	//     second line of defense, not just CreateMarket's pre-check.
	reg.mu.Lock()
	reg.markets[ids.GenerateTestID()] = Market{
		NetworkID:    mainnetID,
		BaseAssetID:  syntheticBaseID, // unregistered
		QuoteAssetID: usdcID,
		Enabled:      true,
	}
	reg.mu.Unlock()
	if err := RefuseUnderSyntheticConfig(NetworkClassMainnet, DefaultDexAssetPolicy(), reg, nil); !errors.Is(err, ErrEnabledMarketUnknownAsset) {
		t.Fatalf("startup gate must refuse a synthetic enabled market, got: %v", err)
	}

	_ = mid
}

// --- (T3) TestERC20AssetIDUsesRealTokenAddress -----------------------------
//
// The ERC-20 AssetID MUST derive from the REAL token contract address — change the
// address, the id changes; keep the address, the id is stable regardless of display
// metadata (symbol/name/decimals are NOT in the identity preimage).
func TestERC20AssetIDUsesRealTokenAddress(t *testing.T) {
	cChain := ids.GenerateTestID()
	addrA := addr20(0x11)
	addrB := addr20(0x22)

	idA, err := DeriveAssetID(mainnetID, cChain, AssetKindERC20, addrA)
	if err != nil {
		t.Fatalf("derive A: %v", err)
	}
	idB, err := DeriveAssetID(mainnetID, cChain, AssetKindERC20, addrB)
	if err != nil {
		t.Fatalf("derive B: %v", err)
	}
	if idA == idB {
		t.Fatal("different token addresses produced the same AssetID — id is not bound to the address")
	}

	// Same address, different display metadata => SAME id (identity is the address,
	// not the ticker). This is the anti-ASCII-ticker property.
	aDisplay1 := Asset{NetworkID: mainnetID, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: addrA, Decimals: 6, Symbol: "USDC", Name: "USD Coin", Enabled: true}
	aDisplay2 := Asset{NetworkID: mainnetID, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: addrA, Decimals: 18, Symbol: "ZZZ", Name: "Renamed", Enabled: true}
	id1, _ := aDisplay1.ID()
	id2, _ := aDisplay2.ID()
	if id1 != id2 {
		t.Fatal("AssetID changed when only display metadata changed — id must be bound to the real address, not the ticker")
	}
	if id1 != idA {
		t.Fatal("Asset.ID() disagrees with DeriveAssetID for the same real address")
	}

	// The id is genuinely a function of the address bytes: re-derive directly and
	// confirm the address participates (a hand-rolled preimage with the address
	// reproduces the id, a preimage with a different address does not).
	if got, _ := DeriveAssetID(mainnetID, cChain, AssetKindERC20, append([]byte(nil), addrA...)); got != idA {
		t.Fatal("AssetID not reproducible from the same real address bytes")
	}

	// Different network or different C-Chain also changes the id (the address is
	// scoped to its chain — the same token address on two chains is two assets).
	otherChain := ids.GenerateTestID()
	if got, _ := DeriveAssetID(mainnetID, otherChain, AssetKindERC20, addrA); got == idA {
		t.Fatal("same address on a different C-Chain produced the same id; chain must be in the preimage")
	}
	if got, _ := DeriveAssetID(2, cChain, AssetKindERC20, addrA); got == idA {
		t.Fatal("same address on a different network produced the same id; networkID must be in the preimage")
	}
}

// --- (T4) TestUTXOAssetIDUsesRealUTXOAssetID -------------------------------
//
// The UTXO AssetID MUST derive from the REAL source-chain assetID, and a UTXO asset
// and an ERC-20 that share the same 32/20-byte low bytes MUST NOT collide (the kind
// is domain-separated in the preimage).
func TestUTXOAssetIDUsesRealUTXOAssetID(t *testing.T) {
	src := ids.GenerateTestID()
	realAssetID := ids.GenerateTestID()
	otherAssetID := ids.GenerateTestID()

	idReal, err := DeriveAssetID(mainnetID, src, AssetKindUTXO, idBytes(realAssetID))
	if err != nil {
		t.Fatalf("derive real utxo: %v", err)
	}
	idOther, err := DeriveAssetID(mainnetID, src, AssetKindUTXO, idBytes(otherAssetID))
	if err != nil {
		t.Fatalf("derive other utxo: %v", err)
	}
	if idReal == idOther {
		t.Fatal("different UTXO assetIDs produced the same DEX AssetID")
	}

	// Reproducible from the real assetID bytes.
	if got, _ := DeriveAssetID(mainnetID, src, AssetKindUTXO, idBytes(realAssetID)); got != idReal {
		t.Fatal("UTXO AssetID not reproducible from the real source assetID")
	}

	// Domain separation: an ERC-20 whose 20-byte address is the first 20 bytes of
	// the UTXO assetID must NOT collide with the UTXO asset.
	clashAddr := idBytes(realAssetID)[:20]
	idERC20, err := DeriveAssetID(mainnetID, src, AssetKindERC20, clashAddr)
	if err != nil {
		t.Fatalf("derive clashing erc20: %v", err)
	}
	if idERC20 == idReal {
		t.Fatal("ERC-20 and UTXO with overlapping bytes collided; kind must domain-separate the preimage")
	}

	// Through the registry: a real seeded UTXO registers and its stored id matches
	// the derivation from the real assetID.
	fc := newFakeChain()
	fc.seedUTXO(mainnetID, src, realAssetID, 9)
	reg := New(AssetKindUTXO)
	a := Asset{
		NetworkID:    mainnetID,
		ChainID:      src,
		Kind:         AssetKindUTXO,
		CanonicalRef: idBytes(realAssetID),
		Decimals:     9,
		Symbol:       "XAV",
		Name:         "X-Chain asset",
		Enabled:      true,
		RiskTier:     RiskTier1,
	}
	gotID, err := reg.Register(a, fc)
	if err != nil {
		t.Fatalf("real UTXO should register: %v", err)
	}
	if gotID != idReal {
		t.Fatal("registry stored a UTXO id that is not the derivation from the real source assetID")
	}
	if !bytes.Equal(idBytes(gotID), idBytes(idReal)) {
		t.Fatal("registry UTXO id bytes mismatch")
	}
}
