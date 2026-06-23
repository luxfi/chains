// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"errors"
	"testing"

	"github.com/luxfi/chains/dexvm/config"
	"github.com/luxfi/chains/dexvm/registry"
	"github.com/luxfi/ids"
)

// enforce_h2_test.go is the H2 proof: the dexvm value-mode CLAIM is cross-checked against
// the REAL consensus engine, not trusted from the config string. A config that claims
// QUORUM_FINALITY while the live engine is K=1 / CFT (not actually quorum-finality) FAILS
// CLOSED — the same "derive, don't trust" discipline RealAssetsOnly already uses. This binds
// the dexvm's posture to the same engine the cEVM value gate (H1) reads.

// fakeEngineMode is a ConsensusModeGate stand-in for the consensus engine's *Transitive
// (whose Mode()==ModeQuorumFinality is the truthful quorum signal). It reports a chosen
// finality regime so the cross-check's both branches are exercised.
type fakeEngineMode struct{ quorum bool }

func (g fakeEngineMode) IsQuorumFinality() bool { return g.quorum }

// TestH2_QuorumFinalityClaim_K1Engine_FailsClosed is the decisive proof: the config claims
// QUORUM_FINALITY, the manifest + assets are clean, but the injected engine is NOT
// quorum-finality (K=1 / CFT). Startup MUST be refused — the config cannot assert a
// finality posture the engine does not have.
func TestH2_QuorumFinalityClaim_K1Engine_FailsClosed(t *testing.T) {
	cChain := ids.GenerateTestID()
	cfg := config.DefaultConfig()
	cfg.DexAssetManifestPath = writeRealManifest(t, mainnetNet, cChain, false)
	cfg.DexNativeValueEnabled = true
	cfg.DexConsensusMode = "QUORUM_FINALITY"

	// The real engine is K=1 / CFT — NOT quorum-finality. The config claim is a lie.
	k1Engine := fakeEngineMode{quorum: false}
	if _, err := enforceRealAssetsOnly(cfg, mainnetNet, cChain, ids.Empty, k1Engine); !errors.Is(err, ErrConsensusModeEngineMismatch) {
		t.Fatalf("a QUORUM_FINALITY config claim on a K=1/CFT engine must fail closed (ErrConsensusModeEngineMismatch), got: %v", err)
	}
}

// TestH2_QuorumFinalityClaim_QuorumEngine_Passes proves the cross-check does not over-reject:
// a QUORUM_FINALITY config claim on a genuinely quorum-finality engine admits, with no
// disclaimer (the finality is real).
func TestH2_QuorumFinalityClaim_QuorumEngine_Passes(t *testing.T) {
	cChain := ids.GenerateTestID()
	cfg := config.DefaultConfig()
	cfg.DexAssetManifestPath = writeRealManifest(t, mainnetNet, cChain, false)
	cfg.DexNativeValueEnabled = true
	cfg.DexConsensusMode = "QUORUM_FINALITY"

	quorumEngine := fakeEngineMode{quorum: true}
	st, err := enforceRealAssetsOnly(cfg, mainnetNet, cChain, ids.Empty, quorumEngine)
	if err != nil {
		t.Fatalf("a QUORUM_FINALITY claim on a quorum-finality engine must pass: %v", err)
	}
	if st.Mode != registry.ConsensusModeQuorumFinality {
		t.Fatalf("wrong value mode: %s", st.Mode)
	}
	if st.Status != "" {
		t.Fatalf("QUORUM_FINALITY must not surface a disclaimer, got %q", st.Status)
	}
}

// TestH2_HonestValidatorLabeled_NotCrossCheckedAgainstQuorum proves the LABELED CFT-parity
// mode is NOT cross-checked against quorum-finality: it explicitly claims no Byzantine
// finality, so a K=1/CFT engine is consistent with it. The labeled launch posture admits
// (with its disclaimer) even on a non-quorum engine — only the QUORUM_FINALITY claim is
// engine-bound.
func TestH2_HonestValidatorLabeled_NotCrossCheckedAgainstQuorum(t *testing.T) {
	cChain := ids.GenerateTestID()
	cfg := config.DefaultConfig()
	cfg.DexAssetManifestPath = writeRealManifest(t, mainnetNet, cChain, false)
	cfg.DexNativeValueEnabled = true
	cfg.DexConsensusMode = "HONEST_VALIDATOR_LABELED"
	cfg.DexCapsOn = true
	cfg.DexHaltReady = true

	// Even on a K=1/CFT engine, the LABELED CFT-parity launch is consistent (it claims no
	// Byzantine finality). It admits with the no-Byzantine-finality disclaimer.
	k1Engine := fakeEngineMode{quorum: false}
	st, err := enforceRealAssetsOnly(cfg, mainnetNet, cChain, ids.Empty, k1Engine)
	if err != nil {
		t.Fatalf("HONEST_VALIDATOR_LABELED must admit on a CFT engine (it claims no Byzantine finality): %v", err)
	}
	if st.Status != registry.NoByzantineFinalityClaim {
		t.Fatalf("HONEST_VALIDATOR_LABELED must surface the no-Byzantine-finality disclaimer, got %q", st.Status)
	}
}

// TestM1_Enforce_TamperedManifestWithPin_FailsStartup proves M1 end-to-end at the startup
// gate: with a manifest content hash pinned in config, a manifest whose bytes were edited
// (here, simply a different on-disk file than the pin) FAILS enforceRealAssetsOnly. The
// pin is the dexvm's defense (it has no EVM state to eth_getCode the tokens).
func TestM1_Enforce_TamperedManifestWithPin_FailsStartup(t *testing.T) {
	cChain := ids.GenerateTestID()
	cfg := config.DefaultConfig()
	cfg.DexAssetManifestPath = writeRealManifest(t, mainnetNet, cChain, false)
	// Pin a DIFFERENT hash than the file actually has (simulating a file edited away from the
	// CI-approved artifact whose hash was pinned).
	cfg.DexAssetManifestSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

	if _, err := enforceRealAssetsOnly(cfg, mainnetNet, cChain, ids.Empty); err == nil {
		t.Fatal("a manifest whose content does not match the pinned hash must fail startup")
	} else if !errors.Is(err, registry.ErrManifestHashMismatch) {
		t.Fatalf("expected ErrManifestHashMismatch, got: %v", err)
	}
}

// TestH2_NoEngineGate_ConfigHygieneOnly proves backward-compatibility: with NO engine gate
// injected (the variadic absent), the value-mode guard is config-hygiene only — exactly the
// pre-H2 behavior — because the dexvm is the non-value proxy (its value never moves; the
// cEVM/H1 is the runtime value authority). A QUORUM_FINALITY config admits with no engine
// to contradict it.
func TestH2_NoEngineGate_ConfigHygieneOnly(t *testing.T) {
	cChain := ids.GenerateTestID()
	cfg := config.DefaultConfig()
	cfg.DexAssetManifestPath = writeRealManifest(t, mainnetNet, cChain, false)
	cfg.DexNativeValueEnabled = true
	cfg.DexConsensusMode = "QUORUM_FINALITY"

	// No engine gate -> config hygiene only (the proxy moves no value).
	if _, err := enforceRealAssetsOnly(cfg, mainnetNet, cChain, ids.Empty); err != nil {
		t.Fatalf("with no engine gate the value-mode guard is config-hygiene only and must admit a legal mode: %v", err)
	}
}
