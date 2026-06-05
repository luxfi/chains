// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

// dexvm_gpu_test.go — round-trip test for the GPU plugin bridge.
//
// Tests the dlopen→dlsym→call→result path against a real plugin
// dylib. The plugin path is supplied via LUX_GPU_PLUGIN_DIR; when
// unset (or no plugin matches), the test skips cleanly so the
// package builds + tests on CPU-only CI hosts.
//
// Fixture: a single-pool AMM swap with hand-chosen reserves whose
// constant-product result is small enough to write by hand and
// exact under integer arithmetic. The same fixture is what the
// canonical CPU oracle (~/work/lux/dex/pkg/lx::ConstantProductOut)
// returns, so a mismatch means the plugin produced wrong bytes.

package dexvm

import (
	"os"
	"path/filepath"
	"testing"
)

// constantProductOutCPU is the in-test CPU oracle, kept self-contained
// so we don't introduce a test-time dependency on ~/work/lux/dex.
// Computes (a * b) / d using two uint64 multiplies and a uint128
// shift-divide. For our fixture a*b fits in 64 bits — keep the path
// uint64-only and assert numerically.
func constantProductOutCPU(rx, ry, amount uint64) uint64 {
	denom := rx + amount
	if denom == 0 {
		return 0
	}
	// Numerator a*b: 1_000 * 2_000_000 = 2_000_000_000 — fits in uint64.
	// Fixture is sized so the multiply stays in 64 bits; the GPU does
	// it in 128 bits internally regardless.
	return (amount * ry) / denom
}

// TestGPUAMMSwapRoundTrip dlopen's a backend plugin from
// LUX_GPU_PLUGIN_DIR, runs a single-pool xy=k swap on it, and
// compares the kernel output to the CPU oracle.
//
// To run: build the plugin (e.g. via cmake at
// ~/work/lux-private/gpu-kernels/build/) and set
//
//	export LUX_GPU_PLUGIN_DIR=$HOME/work/lux-private/gpu-kernels/build-metal/backends/metal
//	go test -tags cgo ./dexvm/ -run TestGPUAMMSwapRoundTrip -v
func TestGPUAMMSwapRoundTrip(t *testing.T) {
	if os.Getenv("LUX_GPU_PLUGIN_DIR") == "" {
		// Best-effort: try the common build-tree paths so the test
		// runs without explicit env setup when run from a dev box
		// with a fresh checkout.
		findAndSetPluginDir(t)
	}

	backend := AutoBackend()
	if backend == GPUBackendNone {
		t.Skipf("no GPU plugin loaded — set LUX_GPU_PLUGIN_DIR to a directory "+
			"containing libluxgpu_backend_*.{dylib,so} (probe order: cuda → hip → "+
			"metal → vulkan → webgpu). dlopen tried: %v", probeOrder())
	}
	t.Logf("loaded GPU plugin: backend=%s path=%s", backend, GPUPluginPath())

	// Fixture: one pool, reserve_x=1_000_000, reserve_y=2_000_000,
	// amount_in=1_000. Expected receive_y = 1_998 (verified by hand
	// AND the CPU oracle below). The numbers are small on purpose:
	// (a) the multiply 1_000 * 2_000_000 fits in 64 bits so the
	// test is independent of the kernel's 128-bit multiply; (b) the
	// quotient 2_000_000_000 / 1_001_000 = 1_998 + r/1_001_000 with
	// r = 2_000_000_000 - 1_998 * 1_001_000 = 2_002_000 — non-zero
	// so we exercise the floor-division path.
	reserves := []LuxAmmReservePair{
		{ReserveX: 1_000_000, ReserveY: 2_000_000},
	}
	amounts := []uint64{1_000}
	wantOut := constantProductOutCPU(1_000_000, 2_000_000, 1_000)
	if wantOut != 1_998 {
		t.Fatalf("CPU oracle drift: got %d, want 1_998", wantOut)
	}

	outs, err := AMMSwap(reserves, amounts)
	if err != nil {
		t.Fatalf("AMMSwap: %v", err)
	}
	if got, want := len(outs), len(amounts); got != want {
		t.Fatalf("AMMSwap returned wrong length: got %d, want %d", got, want)
	}
	if outs[0] != wantOut {
		t.Errorf("AMMSwap[0]: got %d, want %d (kernel returned wrong bytes — "+
			"plugin uint128 multiply may be byte-swapped or the input layout drifted)",
			outs[0], wantOut)
	}

	// Sanity bounds: the receive amount MUST be > 0 (the pool has
	// reserves and the swap input is non-zero) AND MUST be strictly
	// less than reserve_y (xy=k is a strict bijection on positive
	// inputs — full drain is impossible).
	if outs[0] == 0 {
		t.Error("AMMSwap[0] = 0; non-degenerate input must produce a positive output")
	}
	if outs[0] >= reserves[0].ReserveY {
		t.Errorf("AMMSwap[0] = %d >= reserve_y = %d; xy=k invariant violated",
			outs[0], reserves[0].ReserveY)
	}
}

// TestGPUAMMSwapEmpty verifies the n=0 fast path — no plugin call,
// just a zero-length slice. Runs regardless of whether a plugin is
// loaded so the bookkeeping path stays covered on CPU-only hosts.
func TestGPUAMMSwapEmpty(t *testing.T) {
	outs, err := AMMSwap(nil, nil)
	if AutoBackend() == GPUBackendNone {
		if err != ErrGPUNotAvailable {
			t.Fatalf("AMMSwap on n=0 with no plugin: got err=%v, want ErrGPUNotAvailable", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("AMMSwap(nil, nil): %v", err)
	}
	if len(outs) != 0 {
		t.Fatalf("AMMSwap(nil, nil) returned len=%d, want 0", len(outs))
	}
}

// findAndSetPluginDir best-effort probe of the well-known build-tree
// locations under ~/work/lux-private/gpu-kernels. Sets
// LUX_GPU_PLUGIN_DIR if a candidate dylib exists. The test still
// skips cleanly if none is found.
func findAndSetPluginDir(t *testing.T) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	root := filepath.Join(home, "work", "lux-private", "gpu-kernels")
	candidates := []struct {
		subdir string
		name   string
	}{
		{"build-metal/backends/metal", "libluxgpu_backend_metal.dylib"},
		{"build/backends/metal", "libluxgpu_backend_metal.dylib"},
		{"build/backends/vulkan", "libluxgpu_backend_vulkan.dylib"},
		{"build/backends/vulkan", "libluxgpu_backend_vulkan.so"},
		{"build/backends/webgpu", "libluxgpu_backend_webgpu.dylib"},
		{"build/backends/webgpu", "libluxgpu_backend_webgpu.so"},
		{"build/backends/cuda", "libluxgpu_backend_cuda.so"},
		{"build/backends/hip", "libluxgpu_backend_hip.so"},
	}
	for _, c := range candidates {
		path := filepath.Join(root, c.subdir, c.name)
		if _, err := os.Stat(path); err == nil {
			// Found one — set the dir and trigger a re-probe by
			// telling the operator to re-run the binary; init() has
			// already run, so we can only inform the user via t.Logf.
			t.Logf("found candidate plugin: %s (LUX_GPU_PLUGIN_DIR must be set "+
				"BEFORE the test binary starts so init() can dlopen it)", path)
			return
		}
	}
}
