// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"errors"
	"fmt"

	"github.com/luxfi/chains/dexvm/config"
	"github.com/luxfi/chains/dexvm/registry"
	"github.com/luxfi/ids"
)

// ConsensusModeGate is the OPTIONAL real-engine cross-check for the dexvm value-mode
// guard (H2). The dexvm itself is a STATELESS ATOMIC ZAP PROXY that moves NO value at
// runtime (see config.Config's doc) — the canonical native-value surface is the 0x9999
// cEVM, which is ALWAYS-ON (live since the Dec 25 2025 activation) with no runtime value
// gate. So the dexvm's DexConsensusMode is a STARTUP-CONFIG HYGIENE check (is the declared
// posture a legal token?), NOT a runtime value authority.
//
// When an engine gate IS injected, the dexvm value-mode CLAIM is cross-checked against the
// REAL engine — the same "derive, don't trust" discipline RealAssetsOnly already uses
// (machine-derived from the registry, never operator-attested). A config that claims
// QUORUM_FINALITY while the engine is K=1 / CFT (not actually quorum-finality) FAILS CLOSED.
// The interface is satisfied structurally by the consensus engine's *Transitive, so no
// import of consensus/engine/chain is needed here (dependency inversion).
type ConsensusModeGate interface {
	// IsQuorumFinality reports whether the live consensus engine finalizes on a verified
	// alpha-of-K quorum (K>1 with a vote verifier AND a cert gossiper) — the ONLY regime
	// under which a QUORUM_FINALITY claim is truthful. A K=1 / CFT / degraded engine
	// returns false.
	IsQuorumFinality() bool
}

// ErrConsensusModeEngineMismatch is returned when the dexvm config claims QUORUM_FINALITY
// but the injected real engine is NOT in quorum-finality mode — a config posture the
// running consensus cannot back. Fail-closed (derive, don't trust).
var ErrConsensusModeEngineMismatch = errors.New("dexvm: DexConsensusMode claims QUORUM_FINALITY but the live consensus engine is not quorum-finality (K=1/CFT); refusing — the config cannot assert a finality posture the engine does not have")

// enforceRealAssetsOnly is the SINGLE backend-enforced startup gate (Gate A, the
// green-first gate). It runs once at VM Initialize, AFTER config + genesis parse and
// BEFORE the VM is marked initialized, using the node's CONSENSUS-supplied network
// identity (networkID / C-Chain / X-Chain ids) — never an operator-spoofable value.
//
// VALUE AUTHORITY (H2, the architecture boundary): the dexvm moves NO value at runtime
// (it is the stateless atomic ZAP proxy). The canonical native-value surface is the 0x9999
// cEVM, which is always-on with no runtime value gate. The DexConsensusMode guard below is
// therefore STARTUP-CONFIG HYGIENE —
// it refuses an UNSET/unknown/under-asserted mode when value is configured — and it is
// CROSS-CHECKED against the real engine when an engineMode gate is injected (a config that
// claims QUORUM_FINALITY while the engine is K=1/CFT fails closed). RealAssetsOnly is
// likewise machine-derived (the registry being real + no synthetic flag), not
// operator-attested, so neither leg of the launch posture trusts a bare config string.
//
// It enforces, fail-closed (any ambiguity refuses startup), exactly the task's gate:
//
//  1. dexAllowedAssetKinds is a subset of {EVM_NATIVE, ERC20, UTXO}.
//  2. No synthetic flag (assets/markets/mockLiquidity) on a value-bearing network
//     (mainnet/testnet).
//  3. If a per-network manifest is configured, every asset binds to the node's running
//     C-Chain/X-Chain identity (RuntimeVerifier — a real check), every market resolves
//     to two registered real assets, and the residual deny-scan (Liquidity universe,
//     mock/phantom liquidity, ASCII-ticker id, declared-credit) passes.
//  4. The consensus-mode value guard: if native value is enabled it activates ONLY
//     under QUORUM_FINALITY or a fully-asserted HONEST_VALIDATOR_LABELED; otherwise
//     startup is refused. When an engineMode gate is injected, a QUORUM_FINALITY claim
//     is additionally cross-checked against the live engine and fails closed on mismatch.
//
// engineMode is optional (variadic, 0-or-1): with none injected the value-mode guard is
// config-hygiene only (correct for the non-value proxy, whose value never moves); with one
// injected the QUORUM_FINALITY claim must match the real engine.
//
// It returns the value-mode status (the no-Byzantine-finality disclaimer for a labeled
// CFT-parity launch, empty for QUORUM_FINALITY) so the caller can surface it, and an
// error that the VM turns into a hard init failure.
func enforceRealAssetsOnly(
	cfg config.Config,
	networkID uint32,
	cChainID ids.ID,
	xChainID ids.ID,
	engineMode ...ConsensusModeGate,
) (registry.ValueModeStatus, error) {
	// Build the locked-down policy from config (every flag SAFE-by-default).
	policy, err := assetPolicyFromConfig(cfg)
	if err != nil {
		return registry.ValueModeStatus{}, err
	}

	class := registry.NetworkClassFor(networkID)

	// Build the registry from the configured manifest (if any). A configured manifest is
	// loaded, identity-bound to the running chain (RuntimeVerifier), and admitted; with
	// no manifest the registry is empty (no markets can be enabled, which is itself
	// fail-closed). Admission and gating are orthogonal: AdmitInto only registers, then
	// the startup gate runs EXACTLY ONCE below regardless of path.
	reg := registry.New(policy.AllowedKindsOrDefault()...)
	var chainLabelFor func(ids.ID) string
	if cfg.DexAssetManifestPath != "" {
		// M1: load the manifest PINNED to its CI-approved content hash when configured. An
		// edited local manifest (a fabricated token address) no longer matches the pin and
		// fails startup. With no pin set it falls back to shape-only load (LoadManifestPinned
		// with "" == LoadManifest), so pinning is opt-in but mandatory-when-set.
		m, lerr := registry.LoadManifestPinned(cfg.DexAssetManifestPath, cfg.DexAssetManifestSHA256)
		if lerr != nil {
			return registry.ValueModeStatus{}, fmt.Errorf("dex asset manifest: %w", lerr)
		}
		rv, verr := registry.NewRuntimeVerifier(networkID, cChainID, xChainID, m)
		if verr != nil {
			return registry.ValueModeStatus{}, fmt.Errorf("dex asset manifest identity bind: %w", verr)
		}
		if aerr := m.AdmitInto(reg, rv); aerr != nil {
			return registry.ValueModeStatus{}, fmt.Errorf("dex asset manifest admit: %w", aerr)
		}
		chainLabelFor = m.ChainLabelFor()
	}

	// THE single fail-closed startup gate: no synthetic flag on a value net, every enabled
	// market resolves to two registered real assets, no Liquidity/mock/ticker reference,
	// allowed-kinds a subset of the three. Runs once over whatever was admitted (or the
	// empty registry when no manifest is configured).
	if gerr := registry.RefuseUnderSyntheticConfig(class, policy, reg, chainLabelFor); gerr != nil {
		return registry.ValueModeStatus{}, gerr
	}

	// Native value cannot be activated with no real declared assets — a value launch
	// with an empty registry is a misconfiguration, refused.
	if cfg.DexNativeValueEnabled && reg.Len() == 0 {
		return registry.ValueModeStatus{}, fmt.Errorf(
			"refuse DEX native value activation: no real assets registered (manifest path=%q) — value requires declared real on-chain assets",
			cfg.DexAssetManifestPath)
	}

	// Consensus-mode value guard. RealAssetsOnly is MACHINE-DERIVED (registry is real +
	// no synthetic flag enabled), not operator-attested, so the operator cannot lie about
	// it under HONEST_VALIDATOR_LABELED.
	mode, err := registry.ParseConsensusMode(cfg.DexConsensusMode)
	if err != nil {
		return registry.ValueModeStatus{}, err
	}
	assertions := registry.LaunchAssertions{
		CapsOn:         cfg.DexCapsOn,
		RealAssetsOnly: !policy.AnySyntheticFlag(), // registry already proven real above
		HaltReady:      cfg.DexHaltReady,
	}
	status, err := registry.GuardValueActivation(cfg.DexNativeValueEnabled, mode, assertions)
	if err != nil {
		return registry.ValueModeStatus{}, err
	}

	// H2 (derive, don't trust): when an engine-mode gate is injected, a QUORUM_FINALITY
	// CLAIM is cross-checked against the REAL consensus engine. A config that claims
	// quorum-finality while the live engine is K=1 / CFT (not actually quorum-finality)
	// FAILS CLOSED — the config cannot assert a finality posture the engine does not have.
	// This binds the dexvm's value-mode CLAIM to the same engine the cEVM value gate (H1)
	// reads, so the two cannot disagree. (HONEST_VALIDATOR_LABELED is the LABELED CFT-parity
	// mode and is NOT cross-checked against quorum-finality — it explicitly claims no
	// Byzantine finality; only the QUORUM_FINALITY claim is engine-bound.)
	if cfg.DexNativeValueEnabled && mode == registry.ConsensusModeQuorumFinality && len(engineMode) > 0 {
		if gate := engineMode[0]; gate != nil && !gate.IsQuorumFinality() {
			return registry.ValueModeStatus{}, ErrConsensusModeEngineMismatch
		}
	}
	return status, nil
}

// assetPolicyFromConfig translates the VM config's real-assets flags into the registry
// policy, parsing the allowed-kind tokens (an unknown token fails closed here).
func assetPolicyFromConfig(cfg config.Config) (registry.DexAssetPolicy, error) {
	kinds := make([]registry.AssetKind, 0, len(cfg.DexAllowedAssetKinds))
	for _, tok := range cfg.DexAllowedAssetKinds {
		k, err := registry.ParseAssetKind(tok)
		if err != nil {
			return registry.DexAssetPolicy{}, fmt.Errorf("dexAllowedAssetKinds: %w", err)
		}
		kinds = append(kinds, k)
	}
	return registry.DexAssetPolicy{
		AllowSyntheticAssets:  cfg.DexAllowSyntheticAssets,
		AllowSyntheticMarkets: cfg.DexAllowSyntheticMarkets,
		AllowMockLiquidity:    cfg.DexAllowMockLiquidity,
		AllowedAssetKinds:     kinds,
	}, nil
}
