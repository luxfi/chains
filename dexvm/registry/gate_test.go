// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"errors"
	"testing"

	"github.com/luxfi/ids"
)

// --- consensus-mode value guard -------------------------------------------

func TestConsensusGuard_QuorumFinality_AllowsValue(t *testing.T) {
	st, err := GuardValueActivation(true, ConsensusModeQuorumFinality, LaunchAssertions{})
	if err != nil {
		t.Fatalf("QUORUM_FINALITY must permit value activation: %v", err)
	}
	if st.Mode != ConsensusModeQuorumFinality {
		t.Fatalf("wrong mode: %s", st.Mode)
	}
	if st.Status != "" {
		t.Fatalf("QUORUM_FINALITY must not surface a disclaimer (genuine BFT), got %q", st.Status)
	}
}

func TestConsensusGuard_HonestValidatorLabeled_RequiresBundleAndDisclaimer(t *testing.T) {
	// Missing any leg of the bundle => refuse.
	for _, a := range []LaunchAssertions{
		{CapsOn: false, RealAssetsOnly: true, HaltReady: true},
		{CapsOn: true, RealAssetsOnly: false, HaltReady: true},
		{CapsOn: true, RealAssetsOnly: true, HaltReady: false},
	} {
		if _, err := GuardValueActivation(true, ConsensusModeHonestValidatorLabeled, a); !errors.Is(err, ErrLaunchAssertionsUnmet) {
			t.Fatalf("HONEST_VALIDATOR_LABELED must refuse without full bundle (a=%+v), got: %v", a, err)
		}
	}

	// Full bundle => permitted AND surfaces the exact no-Byzantine-finality string.
	st, err := GuardValueActivation(true, ConsensusModeHonestValidatorLabeled, LaunchAssertions{CapsOn: true, RealAssetsOnly: true, HaltReady: true})
	if err != nil {
		t.Fatalf("HONEST_VALIDATOR_LABELED with full bundle must permit value: %v", err)
	}
	if st.Status != NoByzantineFinalityClaim {
		t.Fatalf("HONEST_VALIDATOR_LABELED must surface the no-Byzantine-finality status, got %q", st.Status)
	}
}

func TestConsensusGuard_RefusesUnsetAndUnknown_NeverSilentThirdState(t *testing.T) {
	// UNSET with value requested => refuse.
	if _, err := GuardValueActivation(true, ConsensusModeUnset, LaunchAssertions{}); !errors.Is(err, ErrValueModeUnset) {
		t.Fatalf("UNSET value activation must be refused, got: %v", err)
	}
	// Any out-of-enum mode value => refuse (the closed-enum default arm). 99 is not
	// a legal mode; it must never silently authorise value.
	if _, err := GuardValueActivation(true, ConsensusMode(99), LaunchAssertions{CapsOn: true, RealAssetsOnly: true, HaltReady: true}); !errors.Is(err, ErrValueModeIllegal) {
		t.Fatalf("out-of-enum consensus mode must be refused, got: %v", err)
	}
	// Value DISABLED => no error regardless of mode (nothing to authorise).
	if _, err := GuardValueActivation(false, ConsensusModeUnset, LaunchAssertions{}); err != nil {
		t.Fatalf("value-disabled must not error: %v", err)
	}
}

func TestParseConsensusMode_RejectsUnknown(t *testing.T) {
	if _, err := ParseConsensusMode("PARTIAL_FINALITY"); err == nil {
		t.Fatal("unknown consensus mode token must be rejected")
	}
	for tok, want := range map[string]ConsensusMode{
		"QUORUM_FINALITY":         ConsensusModeQuorumFinality,
		"HONEST_VALIDATOR_LABELED": ConsensusModeHonestValidatorLabeled,
		"":                        ConsensusModeUnset,
	} {
		got, err := ParseConsensusMode(tok)
		if err != nil || got != want {
			t.Fatalf("ParseConsensusMode(%q) = %s,%v want %s", tok, got, err, want)
		}
	}
}

// --- fail-closed startup gate edge cases -----------------------------------

func TestStartupGate_RefusesSyntheticFlagsOnValueNets(t *testing.T) {
	reg := New(AssetKindEVMNative, AssetKindERC20, AssetKindUTXO)

	synthPolicies := []DexAssetPolicy{
		{AllowSyntheticAssets: true},
		{AllowSyntheticMarkets: true},
		{AllowMockLiquidity: true},
	}
	for _, class := range []NetworkClass{NetworkClassMainnet, NetworkClassTestnet} {
		for _, p := range synthPolicies {
			if err := RefuseUnderSyntheticConfig(class, p, reg, nil); !errors.Is(err, ErrSyntheticOnValueNet) {
				t.Fatalf("class=%s policy=%+v must refuse (synthetic on value net), got: %v", class, p, err)
			}
		}
	}

	// Dev network MAY set synthetic flags (developer opt-in) — gate passes.
	if err := RefuseUnderSyntheticConfig(NetworkClassDev, DexAssetPolicy{AllowSyntheticAssets: true}, reg, nil); err != nil {
		t.Fatalf("dev network should permit synthetic flags: %v", err)
	}
}

func TestStartupGate_RefusesForbiddenLiquidityUniverse(t *testing.T) {
	fc := newFakeChain()
	cChain := ids.GenerateTestID()
	reg := New(AssetKindERC20)

	// Register a real asset, but give its source chain a Liquidity (white-label)
	// label via the chainLabelFor hook. The gate must refuse to start.
	a, _ := realERC20(t, fc, cChain, addr20(0x33), "USDC")
	if _, err := reg.Register(a, fc); err != nil {
		t.Fatalf("register: %v", err)
	}
	labelLiquidity := func(id ids.ID) string {
		if id == cChain {
			return "Liquidity L1 universe"
		}
		return ""
	}
	if err := RefuseUnderSyntheticConfig(NetworkClassMainnet, DefaultDexAssetPolicy(), reg, labelLiquidity); err == nil {
		t.Fatal("startup gate must refuse an asset on a Liquidity (white-label) universe chain")
	}

	// With a clean label, the same registry starts fine.
	if err := RefuseUnderSyntheticConfig(NetworkClassMainnet, DefaultDexAssetPolicy(), reg, func(ids.ID) string { return "Lux C-Chain" }); err != nil {
		t.Fatalf("clean-label registry should start: %v", err)
	}
}

func TestStartupGate_RefusesBadAllowedKind(t *testing.T) {
	reg := New(AssetKindERC20)
	// A policy whose allowed-kinds list smuggles the invalid/zero kind must be
	// refused (the list may only ever be a subset of the three real kinds).
	p := DexAssetPolicy{AllowedAssetKinds: []AssetKind{AssetKindERC20, AssetKindInvalid}}
	if err := RefuseUnderSyntheticConfig(NetworkClassMainnet, p, reg, nil); !errors.Is(err, ErrBadAllowedKind) {
		t.Fatalf("startup gate must refuse a non-real allowed kind, got: %v", err)
	}
}

func TestRegister_RefusesDecimalsMismatchAndForbiddenSymbol(t *testing.T) {
	fc := newFakeChain()
	cChain := ids.GenerateTestID()
	reg := New(AssetKindERC20)

	// Seed the token with 6 decimals on-chain but declare 18 => refused.
	addr := addr20(0x44)
	fc.seedERC20(mainnetID, cChain, addr, 6)
	mismatch := Asset{
		NetworkID: mainnetID, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: addr,
		Decimals: 18, Symbol: "USDC", Enabled: true,
	}
	if _, err := reg.Register(mismatch, fc); err == nil {
		t.Fatal("declared decimals != on-chain decimals must be refused")
	}

	// A forbidden (mock/synthetic) symbol is caught by the deny-scan at the gate
	// even though the token is real on-chain.
	addr2 := addr20(0x55)
	fc.seedERC20(mainnetID, cChain, addr2, 6)
	mock := Asset{
		NetworkID: mainnetID, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: addr2,
		Decimals: 6, Symbol: "MOCKUSD", Name: "mock liquidity token", Enabled: true,
	}
	if _, err := reg.Register(mock, fc); err != nil {
		t.Fatalf("real token registers (symbol scan is at the gate): %v", err)
	}
	if err := RefuseUnderSyntheticConfig(NetworkClassMainnet, DefaultDexAssetPolicy(), reg, nil); err == nil {
		t.Fatal("startup gate must refuse an asset whose name/symbol names mock liquidity")
	}
}

func TestAssetKind_JSONRoundTripAndTickerRejection(t *testing.T) {
	for _, k := range []AssetKind{AssetKindEVMNative, AssetKindERC20, AssetKindUTXO} {
		txt, err := k.MarshalText()
		if err != nil {
			t.Fatalf("marshal %v: %v", k, err)
		}
		var back AssetKind
		if err := back.UnmarshalText(txt); err != nil || back != k {
			t.Fatalf("round-trip %v: got %v err %v", k, back, err)
		}
	}
	// Invalid kind refuses to marshal (fail-closed).
	if _, err := AssetKindInvalid.MarshalText(); err == nil {
		t.Fatal("invalid kind must refuse to marshal")
	}
	// An ASCII ticker is not a kind.
	var k AssetKind
	if err := k.UnmarshalText([]byte("LUX")); err == nil {
		t.Fatal("ASCII ticker must not parse as an asset kind")
	}
}

func TestMarketID_BoundToAssetsAndVenue(t *testing.T) {
	base := ids.GenerateTestID()
	quote := ids.GenerateTestID()
	venueA := []byte("tick=1,lot=1,fee=30")
	venueB := []byte("tick=1,lot=1,fee=5")

	id1 := MarketID(mainnetID, base, quote, venueA)
	id2 := MarketID(mainnetID, base, quote, venueB)
	if id1 == id2 {
		t.Fatal("different venue configs must yield different market ids")
	}
	// Swapping base/quote yields a different market (directionality is part of id).
	if MarketID(mainnetID, base, quote, venueA) == MarketID(mainnetID, quote, base, venueA) {
		t.Fatal("base/quote order must affect the market id")
	}
	// Reproducible.
	if MarketID(mainnetID, base, quote, venueA) != id1 {
		t.Fatal("MarketID not reproducible")
	}
}
