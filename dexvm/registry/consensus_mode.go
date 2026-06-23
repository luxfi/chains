// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"errors"
	"fmt"
)

// ConsensusMode is the CLOSED set of consensus postures under which the DEX may
// activate NATIVE VALUE (real-money trading). There are exactly two legal value
// modes plus the zero value; the guard is exhaustive and any unmodelled value falls
// through to refusal. There is NEVER a silent third state.
type ConsensusMode uint8

const (
	// ConsensusModeUnset is the zero value: no value mode declared. Value activation
	// under it is always refused (fail-closed).
	ConsensusModeUnset ConsensusMode = 0

	// ConsensusModeQuorumFinality is post-quantum BFT with quorum finality (the
	// consensus round-2 work). It provides Byzantine fault tolerance, so a value
	// activation under it may legitimately claim Byzantine-finality safety.
	ConsensusModeQuorumFinality ConsensusMode = 1

	// ConsensusModeHonestValidatorLaunch is a DELIBERATE, LABELED crash-fault-tolerant
	// (CFT) parity mode: the validator set is assumed honest-but-crash-prone, NOT
	// Byzantine. It is a legitimate launch posture, but it MUST NOT be presented as
	// Byzantine-finality. Activating value under it is permitted ONLY when it asserts
	// the launch safety bundle (caps-on + real-assets-only + halt-ready) and surfaces
	// an explicit "no Byzantine-finality claim" status string. It is the only other
	// legal value mode.
	ConsensusModeHonestValidatorLaunch ConsensusMode = 2
)

// String renders the mode as its canonical token.
func (m ConsensusMode) String() string {
	switch m {
	case ConsensusModeQuorumFinality:
		return "QUORUM_FINALITY"
	case ConsensusModeHonestValidatorLaunch:
		return "HONEST_VALIDATOR_LAUNCH"
	default:
		return "UNSET"
	}
}

// ParseConsensusMode parses the canonical token. An unknown token is refused (it
// must not silently become a third state).
func ParseConsensusMode(s string) (ConsensusMode, error) {
	switch s {
	case "QUORUM_FINALITY":
		return ConsensusModeQuorumFinality, nil
	case "HONEST_VALIDATOR_LAUNCH":
		return ConsensusModeHonestValidatorLaunch, nil
	case "", "UNSET":
		return ConsensusModeUnset, nil
	default:
		return ConsensusModeUnset, fmt.Errorf("registry: unknown consensus mode %q (only QUORUM_FINALITY or HONEST_VALIDATOR_LAUNCH)", s)
	}
}

// LaunchAssertions is the safety bundle a HONEST_VALIDATOR_LAUNCH activation MUST
// satisfy. It is the explicit, auditable record that the CFT-parity launch is
// running with the compensating controls that justify it. Every field MUST be true
// for value to activate under that mode; a false field is a refusal.
type LaunchAssertions struct {
	// CapsOn asserts per-asset / per-market notional caps are enforced (bounding the
	// blast radius of a crash-fault or operator error during the CFT launch window).
	CapsOn bool
	// RealAssetsOnly asserts the asset registry admits only EVM_NATIVE|ERC20|UTXO and
	// no synthetic asset/market/liquidity is enabled (the property this whole package
	// enforces).
	RealAssetsOnly bool
	// HaltReady asserts the halt control is wired and reachable, so the chain can be
	// stopped fast if the honest-validator assumption is violated.
	HaltReady bool
}

func (a LaunchAssertions) ok() bool {
	return a.CapsOn && a.RealAssetsOnly && a.HaltReady
}

// NoByzantineFinalityClaim is the EXACT status string a HONEST_VALIDATOR_LAUNCH
// activation surfaces. It is a constant so the UI/status surface and any audit
// tooling can match it byte-for-byte; the launch posture must never be silently
// presented as Byzantine-final.
const NoByzantineFinalityClaim = "DEX value active under HONEST_VALIDATOR_LAUNCH (CFT parity): no Byzantine-finality claim"

var (
	// ErrValueModeUnset is returned when value activation is requested with no legal
	// value mode declared.
	ErrValueModeUnset = errors.New("registry: refuse DEX value activation — consensus mode is UNSET (no Byzantine-finality and no labeled CFT-parity declared)")
	// ErrValueModeIllegal is returned for any consensus mode that is not one of the
	// two legal value modes.
	ErrValueModeIllegal = errors.New("registry: refuse DEX value activation — consensus mode is not QUORUM_FINALITY or HONEST_VALIDATOR_LAUNCH")
	// ErrLaunchAssertionsUnmet is returned when HONEST_VALIDATOR_LAUNCH is requested
	// without the full caps-on + real-assets-only + halt-ready bundle.
	ErrLaunchAssertionsUnmet = errors.New("registry: refuse HONEST_VALIDATOR_LAUNCH value activation — caps-on + real-assets-only + halt-ready not all asserted")
)

// ValueModeStatus is the outcome of a successful value-activation guard check: the
// mode that authorised it and, for the labeled CFT-parity mode, the explicit
// "no Byzantine-finality claim" status string to surface. For QUORUM_FINALITY the
// status is empty (Byzantine finality is genuine, so no disclaimer is required).
type ValueModeStatus struct {
	Mode   ConsensusMode
	Status string // NoByzantineFinalityClaim for HONEST_VALIDATOR_LAUNCH, "" for QUORUM_FINALITY
}

// GuardValueActivation is THE consensus-mode value guard. It decides whether the DEX
// may activate native value under the given consensus mode, and returns the status
// the activation must surface.
//
// Semantics (exactly as required):
//
//	if !dexNativeValueEnabled            -> no value to gate; returns the unset status, nil.
//	if mode == QUORUM_FINALITY           -> permitted (PQ BFT); status "".
//	if mode == HONEST_VALIDATOR_LAUNCH   -> permitted ONLY if assertions.ok();
//	                                        status = NoByzantineFinalityClaim.
//	otherwise (UNSET or any other value) -> REFUSED. Never a silent third state.
//
// The default arm refuses, so an unmodelled or zero mode can never accidentally
// authorise value.
func GuardValueActivation(dexNativeValueEnabled bool, mode ConsensusMode, assertions LaunchAssertions) (ValueModeStatus, error) {
	if !dexNativeValueEnabled {
		// No native value requested — nothing to authorise. This is not an error;
		// the DEX runs in non-value (paper) mode.
		return ValueModeStatus{Mode: mode, Status: ""}, nil
	}
	switch mode {
	case ConsensusModeQuorumFinality:
		return ValueModeStatus{Mode: mode, Status: ""}, nil
	case ConsensusModeHonestValidatorLaunch:
		if !assertions.ok() {
			return ValueModeStatus{}, fmt.Errorf("%w (capsOn=%t realAssetsOnly=%t haltReady=%t)",
				ErrLaunchAssertionsUnmet, assertions.CapsOn, assertions.RealAssetsOnly, assertions.HaltReady)
		}
		return ValueModeStatus{Mode: mode, Status: NoByzantineFinalityClaim}, nil
	case ConsensusModeUnset:
		return ValueModeStatus{}, ErrValueModeUnset
	default:
		// Closed enum: any value outside the two legal modes is refused. There is
		// never a silent third state.
		return ValueModeStatus{}, fmt.Errorf("%w: %d", ErrValueModeIllegal, uint8(mode))
	}
}
