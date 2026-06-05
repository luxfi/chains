// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

// dexvm_gpu_nocgo.go — !cgo build of the GPU plugin bridge.
//
// CGO_ENABLED=0 means dlopen is unreachable, so no plugin can ever
// load here. Every public function routes straight into the pure-Go
// reference implementation in dexvm_gpu_cpu.go. Output is byte-
// identical to the kernel's CPU oracle, so a node built with
// CGO_ENABLED=0 still produces consensus-safe AMM/CLOB results — it
// just doesn't get GPU acceleration.
//
// AutoBackend() still reports GPUBackendNone here. Callers that
// branch on AutoBackend() for telemetry ("which backend is hot?")
// keep working; callers that branch on it for *correctness* were
// already wrong, because the cgo build's CPU fallback path lives
// under the same backend tag.

package dexvm

import "fmt"

// AutoBackend reports GPUBackendNone under !cgo — no plugin is
// loaded, the Go CPU path serves the same surface.
func AutoBackend() GPUBackend { return GPUBackendNone }

// GPUPluginPath returns "" under !cgo — no plugin was loaded.
func GPUPluginPath() string { return "" }

// CLOBArena is the public handle; the !cgo build holds the Go-side
// arena directly. Symmetric with the cgo build's CLOBArena (which
// holds the device pointer + a Go-side mirror for fallback).
type CLOBArena struct {
	cpu *clobArenaCPU
}

// AMMSwap evaluates the xy=k swap formula per pool. Routes straight
// into the pure-Go reference — see ammSwapCPU. Byte-equal to the
// canonical Go reference at lx.BatchEvalConstantProductCPU and to
// every GPU backend's kernel.
func AMMSwap(reserves []LuxAmmReservePair, amounts []uint64) ([]uint64, error) {
	return ammSwapCPU(reserves, amounts)
}

// ArenaCreate allocates a fresh CPU-side BookArena. Returns a handle
// the caller passes to CLOBMatch / ArenaDestroy. Concurrent calls are
// safe — each arena is independent.
func ArenaCreate() (*CLOBArena, error) {
	return &CLOBArena{cpu: &clobArenaCPU{}}, nil
}

// ArenaDestroy releases the arena. A nil arena is a no-op (matches
// the cgo build's C-side symmetry). A double-destroy is also safe
// — the second call sees the nil inner pointer and returns cleanly.
func ArenaDestroy(a *CLOBArena) error {
	if a == nil {
		return nil
	}
	a.cpu = nil
	return nil
}

// CLOBMatch runs one matcher step on the arena. Routes straight into
// the pure-Go reference — see clobMatchCPU. A nil arena (or an arena
// already passed through ArenaDestroy) returns the same "arena is nil"
// error string as the cgo bridge's nil-arena guard, so callers can
// build a single err == nil branch that works under both build modes.
func CLOBMatch(a *CLOBArena, calldata []byte) (out [LuxCLOBOutLen]byte, numFills uint32, err error) {
	if a == nil || a.cpu == nil {
		return out, 0, fmt.Errorf("dexvm.CLOBMatch: arena is nil")
	}
	return clobMatchCPU(a.cpu, calldata)
}
