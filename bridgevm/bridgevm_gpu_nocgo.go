// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package bridgevm

// Non-cgo build of the BridgeVM GPU substrate. With CGO_ENABLED=0 we can't
// dlopen the plugin, so every operation routes to the pure-Go CPU oracle
// in bridgevm_gpu_cpu.go (cpuBackend). The oracle is byte-equal to the C++
// reference at ~/work/luxcpp/bridgevm/src/bridgevm_cpu_reference.cpp and to
// every shipping GPU plugin (cuda / hip / metal / vulkan / wgsl) in non-
// strict (legacy) BLS mode, so callers see the same state transition
// regardless of build mode.
//
// init() sets activeBackend to BackendNone — the dlopen probe doesn't run.
// AutoBackend() still reports BackendNone so consumers can branch on
// hardware availability for metrics / profiling purposes, but functional
// correctness no longer depends on it: a BackendNone backend now executes
// the same transition as a real GPU plugin.

func init() {
	setActiveBackend(BackendNone)
}

// ActiveGPUBackend returns the pure-Go CPU oracle. Always non-nil, never
// returns ErrGPUNotAvailable — the contract under !cgo is "transition runs,
// just on the CPU".
func ActiveGPUBackend() GPUBackend { return cpuBackend{} }
