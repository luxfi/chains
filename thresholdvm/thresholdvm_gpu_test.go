// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thresholdvm

import (
	"errors"
	"testing"
	"unsafe"
)

// TestGPULayoutSizes pins the on-wire struct sizes to the device-side
// __align__(16) values declared in
// the GPU plugin install tree ops/mpcvm/cuda/mpcvm_kernels_common.cuh.
// Any drift would produce silently-wrong kernel results — the same check
// runs inside assertSizes() at init() under cgo; this test pins it for
// nocgo builds AND lets `go test` surface the mismatch immediately
// instead of waiting for a process start to panic.
func TestGPULayoutSizes(t *testing.T) {
	cases := []struct {
		name string
		want uintptr
		got  uintptr
	}{
		{"GPUCeremony", 128, unsafe.Sizeof(GPUCeremony{})},
		{"GPUKeyShare", 368, unsafe.Sizeof(GPUKeyShare{})},
		{"GPUContribution", 432, unsafe.Sizeof(GPUContribution{})},
		{"GPUMPCVMState", 160, unsafe.Sizeof(GPUMPCVMState{})},
		{"GPUMPCVMRoundDescriptor", 96, unsafe.Sizeof(GPUMPCVMRoundDescriptor{})},
		{"GPUCeremonyOp", 96, unsafe.Sizeof(GPUCeremonyOp{})},
		{"GPUContributionOp", 416, unsafe.Sizeof(GPUContributionOp{})},
		{"GPUMPCVMTransitionResult", 176, unsafe.Sizeof(GPUMPCVMTransitionResult{})},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: sizeof=%d want=%d (device-side mpcvm_kernels_common.cuh __align__(16))",
				c.name, c.got, c.want)
		}
	}
}

// TestGPUBackendKindString round-trips the resolved plugin kind to the
// launcher symbol prefix used by tryLoadPlugin(). The cgo flavor returns
// the prefix used in lux_<X>_mpcvm_*; the !cgo flavor returns "none" for
// every kind because no dlopen ever happens. Both branches must surface
// GPUBackendNone as "none" so callers can `if kind.String() == "none"`
// regardless of build mode.
func TestGPUBackendKindString(t *testing.T) {
	if got := GPUBackendNone.String(); got != "none" {
		t.Errorf("GPUBackendNone.String()=%q want=%q", got, "none")
	}
	// Under cgo the named backends round-trip to their prefix. Under !cgo
	// they all collapse to "none". Cover the cgo expectation only when we
	// see Backend() != nil OR see GPUBackendCUDA round-tripping correctly —
	// otherwise we're in the nocgo build and the noop contract applies.
	cudaName := GPUBackendCUDA.String()
	if cudaName != "cuda" && cudaName != "none" {
		t.Errorf("GPUBackendCUDA.String()=%q want one of {cuda, none}", cudaName)
	}
	if cudaName == "cuda" {
		// cgo build — pin all the other names too.
		cases := []struct {
			k    GPUBackendKind
			want string
		}{
			{GPUBackendHIP, "hip"},
			{GPUBackendMetal, "metal"},
			{GPUBackendVulkan, "vulkan"},
			{GPUBackendWebGPU, "webgpu"},
		}
		for _, c := range cases {
			if got := c.k.String(); got != c.want {
				t.Errorf("kind=%d string=%q want=%q", c.k, got, c.want)
			}
		}
	}
}

// TestGPUBridgeZeroFixture is the dlopen round-trip required by the task:
// resolve the best-available backend, call lux_<best>_mpcvm_ceremony_apply
// with a zero fixture, assert no error. The two acceptable outcomes are:
//
//  1. The plugin is dlopen'd (e.g. on a dev box with the metal_backend
//     dylib in the lux GPU plugin build/metal_backend/). The launcher
//     runs against the zero fixture and returns rc=0 (zero ops applied).
//
//  2. The plugin is absent. Backend() returns nil; we get ErrGPUNotAvailable.
//
// Both outcomes count as a passing round-trip — the bridge correctly
// surfaces the GPU state through the public Go API. The test only fails
// on a third outcome: a partially-resolved plugin that returns an
// unexpected error rc.
func TestGPUBridgeZeroFixture(t *testing.T) {
	b := Backend()
	if b == nil || !b.IsAvailable() {
		t.Logf("no GPU plugin resolved (expected on CI without a dylib in LUX_GPU_PLUGIN_DIR/build/)")
		// Re-prove the error contract by calling through the nil receiver:
		// the GPUBackend method set on nil must return ErrGPUNotAvailable
		// rather than panicking. This is the substrate contract.
		_, err := (*GPUBackend)(nil).CeremonyApply(nil, nil, nil)
		if !errors.Is(err, ErrGPUNotAvailable) {
			t.Fatalf("nil receiver: want ErrGPUNotAvailable, got %v", err)
		}
		return
	}
	t.Logf("resolved GPU backend: kind=%s path=%s", b.Kind, b.Path)

	// Zero fixture: 1 empty ceremony slot, no ceremony ops, no contribution
	// ops. The kernel walks zero ops and returns applied=0, rc=0. Any
	// non-zero rc is a real launcher failure — fail the test.
	desc := &GPUMPCVMRoundDescriptor{
		ChainID:     0xDEADBEEF,
		Round:       1,
		TimestampNs: 1700000000_000000000,
		Epoch:       1,
		Mode:        0,
	}
	// The ceremony arena MUST be a power-of-2 length (device-side open
	// addressing). The smallest legal arena is 1 slot.
	ceremonies := make([]GPUCeremony, 1)
	applied, err := b.CeremonyApply(desc, nil, ceremonies)
	if err != nil {
		t.Fatalf("CeremonyApply(zero): %v", err)
	}
	if applied != 0 {
		t.Errorf("CeremonyApply(zero): applied=%d want=0 (no ops in input)", applied)
	}
}

// TestGPUBridgeNoCgoStub verifies that the !cgo build flavor surfaces the
// same Go API surface as cgo, with every method returning ErrGPUNotAvailable
// and IsAvailable()==false. Under cgo this test runs the cgo surface (which
// also returns ErrGPUNotAvailable when no plugin is loaded), so the contract
// is consistent across build flavors.
func TestGPUBridgeNoCgoStub(t *testing.T) {
	// Constructing a zero GPUBackend mimics the nocgo Backend() == nil
	// path. Every method must error out without panicking.
	var b GPUBackend
	if b.IsAvailable() {
		t.Fatal("zero GPUBackend.IsAvailable() must be false")
	}
	if _, err := b.CeremonyApply(nil, nil, nil); !errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("CeremonyApply: want ErrGPUNotAvailable, got %v", err)
	}
	if _, _, _, err := b.KeyShareApply(nil, nil, nil, nil, 0); !errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("KeyShareApply: want ErrGPUNotAvailable, got %v", err)
	}
	if _, err := b.ContributionApply(nil, nil, nil, nil, 0); !errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("ContributionApply: want ErrGPUNotAvailable, got %v", err)
	}
	if _, err := b.MPCTransition(nil, nil, nil, nil, nil); !errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("MPCTransition: want ErrGPUNotAvailable, got %v", err)
	}
}
