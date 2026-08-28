// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package aivm

import (
	"testing"
	"unsafe"
)

// TestLayoutSizes pins the Go struct sizes against the on-device layout in
// ops/aivm/cuda/aivm_kernels_common.cuh. A failure here means Go would
// write garbage at the cgo boundary — every kernel reads these structs via
// reinterpret_cast.
//
// The init() in aivm_gpu.go already panics on drift, but a Test in test
// mode catches it via `go test` instead of a process-start crash and
// reports which struct drifted.
func TestLayoutSizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Attestation", unsafe.Sizeof(Attestation{}), 144},
		{"ModelRegistryEntry", unsafe.Sizeof(ModelRegistryEntry{}), 160},
		{"AuditAnchor", unsafe.Sizeof(AuditAnchor{}), 128},
		{"AIVMEpochState", unsafe.Sizeof(AIVMEpochState{}), 160},
		{"AIVMRoundDescriptor", unsafe.Sizeof(AIVMRoundDescriptor{}), 96},
		{"AttestationOp", unsafe.Sizeof(AttestationOp{}), 144},
		{"ModelOp", unsafe.Sizeof(ModelOp{}), 160},
		{"AnchorOp", unsafe.Sizeof(AnchorOp{}), 128},
		{"AIVMTransitionResult", unsafe.Sizeof(AIVMTransitionResult{}), 192},
		{"InferenceWeights", unsafe.Sizeof(InferenceWeights{}), 672},
		{"InferenceOp", unsafe.Sizeof(InferenceOp{}), 144},
		{"InferenceResult", unsafe.Sizeof(InferenceResult{}), 112},
		{"ProofVerifyOp", unsafe.Sizeof(ProofVerifyOp{}), 240},
		{"ProofVerifyResult", unsafe.Sizeof(ProofVerifyResult{}), 48},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("sizeof(%s) = %d, want %d (layout drift vs ops/aivm/cuda/aivm_kernels_common.cuh)",
				c.name, c.got, c.want)
		}
	}
}

// The two round-trip tests that used to live here probed the host for a vendor
// plugin DSO and SKIPPED when none was found — which was every machine without
// CUDA, so they never ran and never could have failed. What they were reaching
// for, the dlopen/dlsym/launcher round trip, is now driven in gpu_plugin_test.go
// against a mirror plugin compiled at test time, so it runs everywhere. What
// they additionally asserted — that a real kernel leaves a zero-op table
// untouched — is kernel arithmetic, which no mirror can stand in for and which
// belongs with the kernel.

// TestNoPluginFallback ensures the package degrades cleanly when no plugin
// is reachable. We deliberately probe a path that can't exist and assert
// openGPUBackend returns an error (not a panic, not a zero-handle
// success). The active backend stays whatever init() resolved.
func TestNoPluginFallback(t *testing.T) {
	_, err := openGPUBackend(AvailableMetal, "/nonexistent/aivm-no-such-plugin.dylib")
	if err == nil {
		t.Fatalf("openGPUBackend on missing plugin: expected error, got nil")
	}
}

// TestModeAPI pins the public SetBackend / ActiveMode surface used by the
// chain bootstrap to opt the AIVM transition into GPU mode.
func TestModeAPI(t *testing.T) {
	// Snapshot + restore the package-level mode so we don't leak state to
	// other tests that may run in the same binary.
	prev := ActiveMode()
	defer SetBackend(prev)

	SetBackend(CPUAIVM)
	if got := ActiveMode(); got != CPUAIVM {
		t.Errorf("ActiveMode after SetBackend(CPUAIVM) = %s, want %s", got, CPUAIVM)
	}
	if got := EffectiveBackendKind(); got != AvailableNone {
		t.Errorf("EffectiveBackendKind under CPUAIVM = %s, want none", got)
	}

	SetBackend(AutoAIVM)
	if got := ActiveMode(); got != AutoAIVM {
		t.Errorf("ActiveMode after SetBackend(AutoAIVM) = %s, want %s", got, AutoAIVM)
	}
	// EffectiveBackendKind under AutoAIVM is whatever the dlopen probe
	// resolved at init(). We don't pin a specific value — the test only
	// asserts the API call doesn't panic and returns a valid BackendKind.
	_ = EffectiveBackendKind().String()
}
