// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package bridgevm

// Round-trip test for the dlopen + dlsym BridgeVM GPU substrate.
//
// We do not require a plugin to be present — the test is structured to SKIP
// cleanly when AutoBackend() == BackendNone (no libluxgpu_backend_*.so on
// the search path), which is the common case in a public chains checkout.
//
// When a plugin IS present (e.g. dev box with ~/work/lux-private/gpu-kernels
// built and $LUX_GPU_PLUGIN_DIR set to the build/backends/<bk>/ dir), the
// test exercises signer_apply with a zero descriptor + zero ops + a sized
// signers arena and asserts:
//
//   1. The launcher returns code 0 (success) — the zero descriptor has
//      signer_op_count=0 so the kernel walks no ops and writes applied=0
//      without touching the signers arena. This is the smallest non-trivial
//      round-trip that exercises dlopen → dlsym → cgo call → kernel dispatch
//      → C ABI return → Go slice readback.
//   2. applied == 0 — the zero ops pile shouldn't apply anything.
//   3. The signers arena is unchanged (sentinel-byte check on a single slot).

import (
	"errors"
	"os"
	"testing"
	"unsafe"
)

// TestActiveBackend just verifies AutoBackend() is callable and returns
// either BackendNone (no plugin) or a known backend tag. Always runs.
func TestActiveBackend(t *testing.T) {
	bk := AutoBackend()
	switch bk {
	case BackendNone, BackendCUDA, BackendHIP, BackendMetal, BackendVulkan, BackendWebGPU:
		t.Logf("AutoBackend() = %s", bk)
	default:
		t.Fatalf("unexpected backend: %v", bk)
	}
}

// TestStubReturnsErrGPUNotAvailable asserts the contract: when the plugin
// isn't loaded, every method returns ErrGPUNotAvailable. Constructed
// directly with tag=BackendNone so the test works regardless of whether a
// plugin happens to be on the search path.
func TestStubReturnsErrGPUNotAvailable(t *testing.T) {
	b := cgoBackend{tag: BackendNone}
	if _, err := b.SignerApply(&BridgeVMRoundDescriptor{}, nil,
		make([]Signer, 1)); !errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("SignerApply: got %v, want ErrGPUNotAvailable", err)
	}
	if _, _, _, err := b.LiquidityApply(&BridgeVMRoundDescriptor{}, nil,
		make([]LiquidityEntry, 1)); !errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("LiquidityApply: got %v, want ErrGPUNotAvailable", err)
	}
	if _, _, _, err := b.MessageInbox(&BridgeVMRoundDescriptor{}, nil,
		make([]Signer, 1), make([]DailyLimit, 1), make([]Message, 1)); !errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("MessageInbox: got %v, want ErrGPUNotAvailable", err)
	}
	if _, _, _, err := b.MessageOutbox(&BridgeVMRoundDescriptor{}, nil,
		make([]DailyLimit, 1), make([]Message, 1),
		&BridgeVMEpochState{}); !errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("MessageOutbox: got %v, want ErrGPUNotAvailable", err)
	}
	if err := b.BridgeTransition(&BridgeVMRoundDescriptor{},
		make([]Signer, 1), make([]LiquidityEntry, 1), make([]DailyLimit, 1),
		make([]Message, 1), make([]Message, 1),
		&BridgeVMEpochState{}, &BridgeVMTransitionResult{}); !errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("BridgeTransition: got %v, want ErrGPUNotAvailable", err)
	}
}

// TestLayoutSizesMatchHeader is the runtime-equivalent of the C++
// static_asserts in ops/bridgevm/cuda/bridgevm_kernels_common.cuh. The init()
// in backend.go already panics on drift; this test makes the assertions
// visible to `go test -v` output for CI dashboards and named per-struct so
// a diff narrows immediately to the offending type.
func TestLayoutSizesMatchHeader(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Signer", sizeOf[Signer](), 208},
		{"LiquidityEntry", sizeOf[LiquidityEntry](), 80},
		{"DailyLimit", sizeOf[DailyLimit](), 64},
		{"Message", sizeOf[Message](), 240},
		{"BridgeVMEpochState", sizeOf[BridgeVMEpochState](), 240},
		{"BridgeVMRoundDescriptor", sizeOf[BridgeVMRoundDescriptor](), 112},
		{"SignerOp", sizeOf[SignerOp](), 224},
		{"LiquidityOp", sizeOf[LiquidityOp](), 64},
		{"OutboundReq", sizeOf[OutboundReq](), 112},
		{"BridgeVMTransitionResult", sizeOf[BridgeVMTransitionResult](), 304},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: sizeof=%d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestSignerApplyZeroFixture is the round-trip we promised: dlopen, dlsym,
// call lux_<best>_bridgevm_signer_apply with a zero-initialised descriptor +
// zero ops + sized signers arena, assert no error. SKIPs when no plugin is
// loaded so the test passes in a public checkout without gpu-kernels built.
func TestSignerApplyZeroFixture(t *testing.T) {
	bk := AutoBackend()
	if bk == BackendNone {
		t.Skip("no GPU plugin loaded; set LUX_GPU_PLUGIN_DIR=" +
			os.Getenv("HOME") + "/work/lux-private/gpu-kernels/build/backends/<bk> to exercise")
	}

	// Zero descriptor → signer_op_count=0, kernel walks no ops. The mode
	// field stays at kModeInbox (0) which is what the kernel checks
	// to early-out from anything other than signer_apply when it's not
	// the requested mode — but signer_apply ignores mode (it's the
	// dispatcher's job, not the kernel's, per bridgevm_signer.cu).
	desc := BridgeVMRoundDescriptor{}
	// Sized arena, byte-zero. Sentinel: set occupied=0 explicitly so we
	// can read it back unchanged.
	signers := make([]Signer, 16)
	for i := range signers {
		signers[i].Occupied = 0
	}
	// Sized but zero-init ops slice. The descriptor says signer_op_count=0
	// so the kernel walks none of them, but launchers (Vulkan in particular)
	// require ops to be non-nil — they pass it through as a storage-buffer
	// binding even when bytes_ops is zero. One element is enough to give
	// the launcher a valid pointer to bind without committing the caller
	// to any non-trivial work.
	ops := make([]SignerOp, 1)

	b := ActiveGPUBackend()
	applied, err := b.SignerApply(&desc, ops, signers)
	if err != nil {
		t.Fatalf("SignerApply(zero fixture) on %s: %v", bk, err)
	}
	if applied != 0 {
		t.Errorf("SignerApply(zero fixture): applied=%d, want 0", applied)
	}
	// Arena should be unchanged.
	for i, s := range signers {
		if s.Occupied != 0 {
			t.Errorf("signers[%d].Occupied = %d, want 0 (kernel touched the arena on no-op input)",
				i, s.Occupied)
		}
	}
}

// sizeOf is a tiny generic helper to make the layout-asserts read naturally
// in TestLayoutSizesMatchHeader. Keeping unsafe.Sizeof out of the test
// callsites makes each line a one-liner; the unsafe is centralised here.
func sizeOf[T any]() uintptr {
	var z T
	return unsafe.Sizeof(z)
}
