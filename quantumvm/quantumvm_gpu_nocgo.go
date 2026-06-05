//go:build !cgo

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// quantumvm_gpu_nocgo.go — !cgo build of the GPU plugin bridge.
//
// CGO_ENABLED=0 means dlopen is unreachable, so no plugin can ever
// load here. Instead of the prior all-stub policy (every GPUBackend
// method returned ErrGPUNotAvailable, forcing callers to maintain a
// parallel CPU verify path), the bridge now routes every call straight
// into the pure-Go reference in quantumvm_gpu_cpu.go (circl-backed
// FIPS 204/205). Output is byte-identical to the cgo build's CPU
// fallback path on every fixture, so a node with CGO_ENABLED=0 still
// produces consensus-safe quantum-signature results — just without
// GPU acceleration.
//
// AutoBackend() still reports BackendNone here. Callers that branch on
// AutoBackend() for telemetry ("which backend is hot?") keep working;
// callers that branch on it for *correctness* were already wrong,
// because the cgo build's CPU fallback path lives under the same tag.

package quantumvm

func init() {
	setActiveBackend(BackendNone)
}

// ActiveGPUBackend returns the package-level GPUBackend handle. Under
// !cgo this is the shared CPU implementation defined in
// quantumvm_gpu_cpu.go — the same FIPS 204/205 circl-backed code path
// the cgo build falls through to when no plugin satisfies the dlopen
// probe (or when a loaded plugin returns NOT_SUPPORTED at the vtbl).
func ActiveGPUBackend() GPUBackend {
	return cpuBackend{}
}
