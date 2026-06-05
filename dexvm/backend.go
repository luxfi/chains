// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// GPU plugin bridge — shared types between cgo and nocgo builds.
//
// The dexvm GPU backend is loaded via dlopen at process start: the
// init() in dexvm_gpu.go probes a fixed candidate list of plugin
// dylibs in order (cuda → hip → metal → vulkan → webgpu) and binds
// the host launcher symbols exported by the gpu-kernels plugin:
//
//   lux_<backend>_amm_xyk_batch              (AMM xyk swap)
//   lux_<backend>_dex_clob_match             (CLOB matcher, EVM 0x100)
//   lux_<backend>_dex_clob_arena_create      (BookArena lifecycle)
//   lux_<backend>_dex_clob_arena_destroy
//
// The plugin sources live at:
//   ~/work/lux-private/gpu-kernels/backends/<X>/src/dex_launchers.{mm,cpp}
//   ~/work/lux-private/gpu-kernels/ops/dex/<X>/...
//
// Public ABI header (single source of truth for byte layouts):
//   ~/work/lux-private/gpu-kernels/include/lux/gpu/dex.h
//
// The cgo file (dexvm_gpu.go) does the dlopen + dlsym. The nocgo file
// (dexvm_gpu_nocgo.go) is a thin stub returning ErrGPUNotAvailable.
// This file holds the cross-build types every consumer can reference
// without taking a cgo dependency.
//
// IMPORTANT: this is opt-in. The existing dexvm vm.go and orderbook
// path do NOT call into this backend. Helpers here are exposed so
// consumers can adopt the GPU path explicitly when ready.

package dexvm

import "errors"

// GPUBackend names the GPU backend the plugin loader bound. The
// numeric values match the dlopen probe order used by init() —
// callers can rely on (GPUBackendCUDA < GPUBackendHIP < GPUBackendMetal
// < GPUBackendVulkan < GPUBackendWebGPU) as a stable ordering of
// preference.
type GPUBackend uint8

const (
	// GPUBackendNone means no plugin was loaded (or build was !cgo).
	GPUBackendNone GPUBackend = iota
	// GPUBackendCUDA is the NVIDIA CUDA plugin (libluxgpu_backend_cuda.so).
	GPUBackendCUDA
	// GPUBackendHIP is the AMD ROCm/HIP plugin (libluxgpu_backend_hip.so).
	GPUBackendHIP
	// GPUBackendMetal is the Apple Metal plugin (libluxgpu_backend_metal.dylib).
	GPUBackendMetal
	// GPUBackendVulkan is the Vulkan plugin (libluxgpu_backend_vulkan.{so,dylib,dll}).
	GPUBackendVulkan
	// GPUBackendWebGPU is the wgpu/Dawn plugin (libluxgpu_backend_webgpu.{so,dylib,dll}).
	GPUBackendWebGPU
)

// String returns the human-readable lowercase backend name used in the
// host launcher symbol prefix (e.g. "metal" → "lux_metal_amm_xyk_batch").
func (b GPUBackend) String() string {
	switch b {
	case GPUBackendCUDA:
		return "cuda"
	case GPUBackendHIP:
		return "hip"
	case GPUBackendMetal:
		return "metal"
	case GPUBackendVulkan:
		return "vulkan"
	case GPUBackendWebGPU:
		return "webgpu"
	default:
		return "none"
	}
}

// ErrGPUNotAvailable is returned by every GPU method on the nocgo
// build, and by the cgo build when init() failed to bind any plugin.
// Consumers treat this as "fall back to the CPU path" rather than as
// a hard failure.
var ErrGPUNotAvailable = errors.New("dexvm: GPU plugin not available")

// LuxAmmReservePair mirrors include/lux/gpu/dex.h::LuxAmmReservePair.
// 16 bytes, packed (no padding), little-endian uint64 fields.
// MUST match:
//   ~/work/lux-private/gpu-kernels/include/lux/gpu/dex.h::LuxAmmReservePair
//   ~/work/lux/dex/pkg/lx/amm.go::ReservePair
//   ~/work/lux-private/gpu-kernels/ops/dex/{cuda,metal,wgsl}/amm_xyk*
type LuxAmmReservePair struct {
	ReserveX uint64
	ReserveY uint64
}

// CLOB ABI byte sizes from include/lux/gpu/dex.h.
const (
	// LuxCLOBCalldataLen is the on-wire calldata for EVM precompile 0x100:
	// side(1) | price(32 BE) | qty(32 BE) | user(20) | book_id(32) = 117.
	LuxCLOBCalldataLen = 117
	// LuxCLOBOutLen is the output: filled(32 BE) | avg_price(32 BE) | num_fills(4 BE) = 68.
	LuxCLOBOutLen = 68
	// LuxCLOBMaxLevels caps the per-side resting-level depth (bid_*/ask_* arrays).
	LuxCLOBMaxLevels = 1024
	// LuxCLOBBookIDOffset is where book_id starts inside calldata.
	LuxCLOBBookIDOffset = 85
	// LuxCLOBBookIDLen is the book_id width.
	LuxCLOBBookIDLen = 32
)
