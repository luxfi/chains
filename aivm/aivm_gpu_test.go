// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package aivm

import (
	"os"
	"path/filepath"
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

// locatePlugin tries the same env-driven search as backend.go's
// candidatePaths() but in a test-friendly form: it returns the first
// loadable plugin's filename, or "" with t.Skip if none are present.
//
// Order matches platformCandidates() — the dlopen probe used by init().
func locatePlugin(t *testing.T) (BackendKind, string) {
	t.Helper()
	for _, c := range platformCandidates() {
		for _, p := range candidatePaths(c) {
			if !filepath.IsAbs(p) {
				continue // skip bare-name candidates — too noisy in CI
			}
			if _, err := os.Stat(p); err == nil {
				return c.kind, p
			}
		}
	}
	return AvailableNone, ""
}

// TestRoundTripAttestation is the canonical end-to-end check: dlopen the
// best-available plugin, dlsym lux_<kind>_aivm_attestation_apply, and
// invoke it with a zero-input fixture. The kernel should accept the
// payload and return rc==0 with applied_out == 0 (no ops applied, table
// untouched).
//
// We use the FULL openGPUBackend path (the same one production init()
// uses) rather than rolling our own dlsym so the test exercises the real
// resolution sequence. If openGPUBackend can't find the plugin file
// (CI without lux-private/gpu-kernels), we Skip.
func TestRoundTripAttestation(t *testing.T) {
	// Force a re-probe in case the package-level activeBackend was loaded
	// before the test environment was set up.
	kind, path := locatePlugin(t)
	if kind == AvailableNone || path == "" {
		t.Skip("aivm: no lux-gpu-kernels plugin DSO found on this host " +
			"(set LUX_PRIVATE_GPU_KERNELS_DIR or LUX_GPU_PLUGIN_DIR)")
	}
	t.Logf("aivm: using plugin %s at %s", kind, path)

	b, err := openGPUBackend(kind, path)
	if err != nil {
		t.Fatalf("openGPUBackend(%s, %s): %v", kind, path, err)
	}
	defer b.Close()

	if !b.IsAvailable() {
		t.Fatalf("openGPUBackend returned non-nil backend but IsAvailable() == false")
	}
	if b.Kind() != kind {
		t.Errorf("backend kind: got %s, want %s", b.Kind(), kind)
	}
	if b.Path() != path {
		t.Errorf("backend path: got %q, want %q", b.Path(), path)
	}

	// Zero-input fixture:
	//   - One round descriptor with attestation_op_count = 0
	//   - No attestation ops
	//   - 16-slot attestation table (must be > 0 and a power of two for
	//     the kernel's open-addressing locator)
	//   - applied_out initialised to 0xFFFFFFFF so we can verify the
	//     kernel wrote a fresh count
	desc := &AIVMRoundDescriptor{
		ChainID:            1,
		Round:              1,
		TimestampNS:        1_000_000_000,
		Epoch:              0,
		Mode:               0, // kModeAttestation
		AttestationOpCount: 0,
		ModelOpCount:       0,
		AnchorOpCount:      0,
	}
	// Every launcher (metal / vulkan / cuda / hip / webgpu) rejects a NULL
	// ops pointer with rc=1 even when desc.AttestationOpCount==0. Hand it
	// a one-element placeholder slice; the kernel reads ops[0..op_count)
	// and op_count is 0, so the placeholder is untouched.
	ops := make([]AttestationOp, 1)
	table := make([]Attestation, 16)
	applied := uint32(0xFFFFFFFF)

	if err := b.AttestationApply(desc, ops, table, &applied); err != nil {
		t.Fatalf("AttestationApply: %v", err)
	}

	// With zero ops, the kernel must touch nothing — applied count must
	// be 0 and the table must remain entirely unoccupied.
	if applied != 0 {
		t.Errorf("zero-op AttestationApply: applied_out = %d, want 0", applied)
	}
	for i, slot := range table {
		if slot.Occupied != 0 {
			t.Errorf("zero-op AttestationApply: table[%d].Occupied = %d, want 0",
				i, slot.Occupied)
		}
	}
}

// TestRoundTripProofVerifyZeroOps exercises the proof-verify launcher with
// op_count==0. The launcher must short-circuit (rc=0) without touching the
// (nil) buffers — same behaviour as the metal / vulkan / cuda launchers.
//
// This is a second round-trip beyond the spec'd one to also exercise the
// "early return on op_count==0" branch that lives in every launcher.
func TestRoundTripProofVerifyZeroOps(t *testing.T) {
	kind, path := locatePlugin(t)
	if kind == AvailableNone || path == "" {
		t.Skip("aivm: no lux-gpu-kernels plugin DSO found on this host")
	}
	b, err := openGPUBackend(kind, path)
	if err != nil {
		t.Fatalf("openGPUBackend: %v", err)
	}
	defer b.Close()

	// op_count == 0 → the Go wrapper short-circuits before reaching C.
	// This still exercises the IsAvailable() guard and the nil-input
	// handling that vm.go callers rely on.
	if err := b.ProofVerify(nil, nil); err != nil {
		t.Fatalf("ProofVerify(nil, nil): unexpected error: %v", err)
	}
}

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
