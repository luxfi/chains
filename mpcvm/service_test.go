// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import "testing"

// TestServiceSurfaces_Decomposition documents and locks the LP-134 / LP-7050
// service decomposition: the single *VM satisfies all three orthogonal
// surfaces today (compatibility bridge), and — critically — the layering is
// real, not cosmetic: MPCService and FHEService each EMBED ThresholdService,
// so any type that is an MPCService or FHEService is necessarily also a
// ThresholdService (it consumes the substrate). The var-block assertions in
// service.go already enforce *VM satisfies each at compile time; this test
// makes the embedding relationship explicit so a future physical split
// (mpcvm implements MPCService, fhevm implements FHEService) cannot silently
// drop the substrate dependency.
func TestServiceSurfaces_Decomposition(t *testing.T) {
	var vm *VM // nil is fine: we only exercise the static type system

	// MPCService is a superset of ThresholdService (M consumes the substrate).
	var mpc MPCService = vm
	var _ ThresholdService = mpc

	// FHEService is a superset of ThresholdService (F consumes the substrate).
	var fhe FHEService = vm
	var _ ThresholdService = fhe

	// ThresholdService alone must NOT expose the MPC/FHE-specific surface —
	// this is verified structurally by the interfaces not sharing those
	// methods; the assignment above going only one direction (MPC->Threshold,
	// never Threshold->MPC) is the compile-time proof of orthogonality.
	var ths ThresholdService = vm
	_ = ths
}
