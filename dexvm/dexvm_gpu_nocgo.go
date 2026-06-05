// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

// dexvm_gpu_nocgo.go — nocgo stub for the GPU plugin bridge.
//
// When CGO_ENABLED=0 the dlopen path in dexvm_gpu.go is unreachable,
// so every public method returns ErrGPUNotAvailable and AutoBackend()
// reports GPUBackendNone. The package surface is identical to the
// cgo build — consumers compile unconditionally and branch on
// AutoBackend() at runtime.

package dexvm

// AutoBackend reports GPUBackendNone under !cgo — dlopen is unreachable.
func AutoBackend() GPUBackend { return GPUBackendNone }

// GPUPluginPath returns "" under !cgo — no plugin was loaded.
func GPUPluginPath() string { return "" }

// CLOBArena is a zero-sized opaque type so the package surface
// compiles uniformly under both build tags. The nocgo build never
// returns a non-nil arena from ArenaCreate.
type CLOBArena struct{}

// AMMSwap returns ErrGPUNotAvailable under !cgo.
func AMMSwap(reserves []LuxAmmReservePair, amounts []uint64) ([]uint64, error) {
	_ = reserves
	_ = amounts
	return nil, ErrGPUNotAvailable
}

// ArenaCreate returns ErrGPUNotAvailable under !cgo.
func ArenaCreate() (*CLOBArena, error) {
	return nil, ErrGPUNotAvailable
}

// ArenaDestroy returns ErrGPUNotAvailable under !cgo. A nil arena is
// still a no-op for symmetry with the cgo build.
func ArenaDestroy(a *CLOBArena) error {
	if a == nil {
		return nil
	}
	return ErrGPUNotAvailable
}

// CLOBMatch returns ErrGPUNotAvailable under !cgo.
func CLOBMatch(a *CLOBArena, calldata []byte) (out [LuxCLOBOutLen]byte, numFills uint32, err error) {
	_ = a
	_ = calldata
	return out, 0, ErrGPUNotAvailable
}
