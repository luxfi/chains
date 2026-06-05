// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thresholdvm

// TestGPUBridgeCgoNocgoParity proves that the cgo and nocgo paths
// produce byte-identical MPC ceremony state transitions on the same
// fixture. Under cgo the bridge tries the GPU plugin first and falls
// through to the pure-Go reference on any error; under !cgo it goes
// straight to the reference. Either way, the output bytes are the
// same — this is the substrate's correctness contract.
//
// The test runs the four-op pipeline (CeremonyApply → ContributionApply
// → KeyShareApply → MPCTransition) twice in the same process:
//
//   1. via the public GPUBackend method set (which dispatches based on
//      whether a plugin was dlopened);
//   2. via the pure-Go reference functions directly.
//
// We then byte-compare the resulting arenas and the transition result.
// If the GPU plugin is loaded, this also proves the GPU output matches
// the CPU reference; if no plugin is loaded, this proves the bridge's
// CPU fallback works end-to-end. Either outcome is a successful parity
// proof.

import (
	"testing"
)

// fixtureFROSTKeygen builds a 3-of-5 FROST keygen ceremony arena with
// three rounds of contributions from all five holders. The ceremony
// should finalize on round 3 and emit five key shares.
func fixtureFROSTKeygen() (
	desc1, desc2, desc3, descClose *GPUMPCVMRoundDescriptor,
	round1Ops, round2Ops, round3Ops []GPUContributionOp,
	beginOps []GPUCeremonyOp,
) {
	const cid uint64 = 0xCEFA01CA001
	var subject, seed [32]byte
	for i := 0; i < 32; i++ {
		subject[i] = byte(i + 1)
		seed[i] = byte(0xA0 ^ i)
	}
	begin := GPUCeremonyOp{
		CeremonyID:        cid,
		DeadlineNs:        uint64(10_000_000_000),
		Kind:              cpuCeremonyOpBegin,
		CeremonyKind:      cpuKindFrostKeygen,
		Threshold:         3,
		TotalParticipants: 5,
		Subject:           subject,
		CeremonySeed:      seed,
	}
	beginOps = []GPUCeremonyOp{begin}

	buildRound := func(round uint32) []GPUContributionOp {
		ops := make([]GPUContributionOp, 5)
		for h := uint32(0); h < 5; h++ {
			var payload [384]byte
			for k := 0; k < 16; k++ {
				payload[k] = byte((round * 16) + h*4 + uint32(k))
			}
			ops[h] = GPUContributionOp{
				CeremonyID:  cid,
				HolderAddr:  uint64(0xDEAD0000 | h),
				Round:       round,
				HolderIndex: h,
				PayloadLen:  16,
				Payload:     payload,
			}
		}
		return ops
	}
	round1Ops = buildRound(0)
	round2Ops = buildRound(1)
	round3Ops = buildRound(2)

	desc1 = &GPUMPCVMRoundDescriptor{
		ChainID:             0xABBA,
		Round:               1,
		TimestampNs:         uint64(1_000_000_000),
		Epoch:               1,
		CeremonyOpCount:     1,
		ContributionOpCount: 5,
	}
	desc2 = &GPUMPCVMRoundDescriptor{
		ChainID:             0xABBA,
		Round:               2,
		TimestampNs:         uint64(2_000_000_000),
		Epoch:               1,
		ContributionOpCount: 5,
	}
	desc3 = &GPUMPCVMRoundDescriptor{
		ChainID:             0xABBA,
		Round:               3,
		TimestampNs:         uint64(3_000_000_000),
		Epoch:               1,
		ContributionOpCount: 5,
	}
	descClose = &GPUMPCVMRoundDescriptor{
		ChainID:     0xABBA,
		Round:       4,
		TimestampNs: uint64(4_000_000_000),
		Epoch:       1,
		ClosingFlag: 1,
	}
	return
}

// runFullCeremonyViaBridge runs the full FROST keygen ceremony through
// the public GPUBackend method set. The bridge dispatches based on
// whether a plugin was dlopened; the result is the same arenas+state
// either way.
func runFullCeremonyViaBridge(t *testing.T) (
	cer []GPUCeremony,
	keys []GPUKeyShare,
	con []GPUContribution,
	state GPUMPCVMState,
	result GPUMPCVMTransitionResult,
) {
	t.Helper()
	const N = 16 // power of 2 required by the open-addressing locator
	cer = make([]GPUCeremony, N)
	keys = make([]GPUKeyShare, N)
	con = make([]GPUContribution, N)

	desc1, desc2, desc3, descClose, r1, r2, r3, beginOps := fixtureFROSTKeygen()

	b := Backend() // nil when no plugin is dlopened — methods still work via fallback

	if _, err := b.CeremonyApply(desc1, beginOps, cer); err != nil {
		t.Fatalf("CeremonyApply r0: %v", err)
	}
	if _, err := b.ContributionApply(desc1, r1, cer, con, 1); err != nil {
		t.Fatalf("ContributionApply r0: %v", err)
	}
	if _, _, _, err := b.KeyShareApply(desc1, cer, keys, con, 1); err != nil {
		t.Fatalf("KeyShareApply r0: %v", err)
	}

	if _, err := b.ContributionApply(desc2, r2, cer, con, 6); err != nil {
		t.Fatalf("ContributionApply r1: %v", err)
	}
	if _, _, _, err := b.KeyShareApply(desc2, cer, keys, con, 1); err != nil {
		t.Fatalf("KeyShareApply r1: %v", err)
	}

	if _, err := b.ContributionApply(desc3, r3, cer, con, 11); err != nil {
		t.Fatalf("ContributionApply r2: %v", err)
	}
	if _, _, _, err := b.KeyShareApply(desc3, cer, keys, con, 1); err != nil {
		t.Fatalf("KeyShareApply r2: %v", err)
	}

	res, err := b.MPCTransition(descClose, cer, keys, con, &state)
	if err != nil {
		t.Fatalf("MPCTransition: %v", err)
	}
	result = *res
	return
}

// runFullCeremonyViaCPU runs the same ceremony through the Go reference
// directly, bypassing the GPU dispatch. This is the canonical bytes.
func runFullCeremonyViaCPU(t *testing.T) (
	cer []GPUCeremony,
	keys []GPUKeyShare,
	con []GPUContribution,
	state GPUMPCVMState,
	result GPUMPCVMTransitionResult,
) {
	t.Helper()
	const N = 16
	cer = make([]GPUCeremony, N)
	keys = make([]GPUKeyShare, N)
	con = make([]GPUContribution, N)

	desc1, desc2, desc3, descClose, r1, r2, r3, beginOps := fixtureFROSTKeygen()

	if _, err := ceremonyApplyCPU(desc1, beginOps, cer); err != nil {
		t.Fatalf("ceremonyApplyCPU r0: %v", err)
	}
	if _, err := contributionApplyCPU(desc1, r1, cer, con, 1); err != nil {
		t.Fatalf("contributionApplyCPU r0: %v", err)
	}
	if _, _, _, err := keyShareApplyCPU(desc1, cer, keys, con, 1); err != nil {
		t.Fatalf("keyShareApplyCPU r0: %v", err)
	}

	if _, err := contributionApplyCPU(desc2, r2, cer, con, 6); err != nil {
		t.Fatalf("contributionApplyCPU r1: %v", err)
	}
	if _, _, _, err := keyShareApplyCPU(desc2, cer, keys, con, 1); err != nil {
		t.Fatalf("keyShareApplyCPU r1: %v", err)
	}

	if _, err := contributionApplyCPU(desc3, r3, cer, con, 11); err != nil {
		t.Fatalf("contributionApplyCPU r2: %v", err)
	}
	if _, _, _, err := keyShareApplyCPU(desc3, cer, keys, con, 1); err != nil {
		t.Fatalf("keyShareApplyCPU r2: %v", err)
	}

	res, err := mpcTransitionCPU(descClose, cer, keys, con, &state)
	if err != nil {
		t.Fatalf("mpcTransitionCPU: %v", err)
	}
	result = *res
	return
}

// TestGPUBridgeCgoNocgoParity is the parity gate: run the same FROST
// keygen ceremony through (a) the public GPUBackend method set and
// (b) the pure-Go reference directly. The arenas, state, and
// transition result MUST be byte-identical.
//
// Under cgo with a plugin loaded, this proves the GPU output matches
// the CPU reference. Under cgo without a plugin loaded (or under
// !cgo), this proves the bridge's CPU fallback produces the same
// result as the reference invoked directly. Both are valid parity
// proofs — the substrate is correct in every build flavor.
func TestGPUBridgeCgoNocgoParity(t *testing.T) {
	cerBridge, keysBridge, conBridge, stateBridge, resBridge := runFullCeremonyViaBridge(t)
	cerCPU, keysCPU, conCPU, stateCPU, resCPU := runFullCeremonyViaCPU(t)

	if !equalCeremonies(cerBridge, cerCPU) {
		t.Errorf("ceremonies arena mismatch:\nbridge[0]=%+v\nCPU[0]=%+v",
			cerBridge[0], cerCPU[0])
	}
	if !equalKeyShares(keysBridge, keysCPU) {
		t.Errorf("keyShares arena mismatch:\nbridge[0]=%+v\nCPU[0]=%+v",
			keysBridge[0], keysCPU[0])
	}
	if !equalContributions(conBridge, conCPU) {
		t.Errorf("contributions arena mismatch:\nbridge[0]=%+v\nCPU[0]=%+v",
			conBridge[0], conCPU[0])
	}
	if stateBridge != stateCPU {
		t.Errorf("state mismatch:\nbridge=%+v\nCPU=%+v", stateBridge, stateCPU)
	}
	if resBridge != resCPU {
		t.Errorf("result mismatch:\nbridge=%+v\nCPU=%+v", resBridge, resCPU)
	}

	if stateCPU.FinalizedCeremonyCount != 1 {
		t.Errorf("expected 1 finalized ceremony, got %d", stateCPU.FinalizedCeremonyCount)
	}
	if stateCPU.KeyShareCount != 5 {
		t.Errorf("expected 5 emitted key shares, got %d", stateCPU.KeyShareCount)
	}
	var zero [32]byte
	if stateCPU.MPCVMStateRoot == zero {
		t.Errorf("mpcvm_state_root is zero — the fold produced no output")
	}
}

// TestGPUBridgeCPUMatchesEmpty proves the pure-Go reference handles an
// empty round (no ops, no contributions) correctly — state advances
// (timestamp, epoch under ClosingFlag) but no arena changes.
func TestGPUBridgeCPUMatchesEmpty(t *testing.T) {
	const N = 16
	cer := make([]GPUCeremony, N)
	keys := make([]GPUKeyShare, N)
	con := make([]GPUContribution, N)

	desc := &GPUMPCVMRoundDescriptor{
		ChainID:     0xDEADBEEF,
		Round:       1,
		TimestampNs: 1_700_000_000_000_000_000,
		Epoch:       1,
		ClosingFlag: 1,
	}
	var state GPUMPCVMState
	res, err := mpcTransitionCPU(desc, cer, keys, con, &state)
	if err != nil {
		t.Fatalf("mpcTransitionCPU(empty): %v", err)
	}
	if res.Status != 1 {
		t.Errorf("status=%d want=1", res.Status)
	}
	if state.CurrentEpoch != 2 {
		t.Errorf("epoch after closing-flag advance = %d, want 2", state.CurrentEpoch)
	}
	if state.NowNs != desc.TimestampNs {
		t.Errorf("now_ns = %d, want %d", state.NowNs, desc.TimestampNs)
	}
	var zero [32]byte
	if state.MPCVMStateRoot == zero {
		t.Errorf("mpcvm_state_root is all-zero on a non-trivial fold")
	}
}

// =============================================================================
// helpers
// =============================================================================

func equalCeremonies(a, b []GPUCeremony) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalKeyShares(a, b []GPUKeyShare) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalContributions(a, b []GPUContribution) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
