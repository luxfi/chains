// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

// dexvm_gpu.go — direct dlopen + dlsym to the gpu-kernels DEX plugin.
//
// Why dlopen, not pkg-config: the AMM/CLOB host launchers live in a
// per-backend plugin (libluxgpu_backend_{cuda,hip,metal,vulkan,webgpu})
// whose presence is platform-dependent — Apple has only Metal+Vulkan
// (via MoltenVK), Linux has CUDA+Vulkan+WebGPU, ROCm only on a small
// set of AMD hosts. pkg-config would force a build-time decision; we
// want a runtime probe so the same go binary picks up whichever
// plugin is on disk. This mirrors the dlopen pattern luxcpp/gpu uses
// for its own backend loader (luxcpp/gpu/test/test_plugin_loader.cpp).
//
// Host launcher ABI — exposed by every plugin under the per-backend
// symbol prefix `lux_<backend>_*`. The C signatures come straight from
// the GPU plugin install tree backends/{metal/src/dex_launchers.mm,
// vulkan/src/dex_launchers.cpp}:
//
//   int amm_xyk_batch(const void* reserves, const void* amounts,
//                     void* outs, uint32_t n, void* stream);
//   int dex_clob_match(void* arena, const uint8_t* calldata,
//                      uint8_t* out, uint32_t* num_fills);
//   int dex_clob_arena_create(void** out_arena);
//   int dex_clob_arena_destroy(void* arena);
//
// All inputs are HOST pointers (no separate device address space is
// exposed across the ABI — the launcher does H2D/D2H copies
// internally). The `stream` argument on AMM is ignored by every
// backend except CUDA/HIP (where it would be a cudaStream_t / hipStream_t).
// `arena` for CLOB is opaque — created/destroyed via the symmetric
// pair, persisted across calls so the BookArena lives device-resident
// for the lifetime of the book.

package dexvm

/*
#cgo LDFLAGS: -ldl

#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Typed function-pointer typedefs for the four launcher symbols. cgo
// can't cast `unsafe.Pointer` directly into a typed C function pointer,
// so we route every call through a tiny trampoline that takes the
// dlsym'd pointer and the typed arguments.

typedef int (*lux_amm_xyk_batch_fn)(
    const void* reserves,
    const void* amounts,
    void*       outs,
    uint32_t    n,
    void*       stream);

typedef int (*lux_dex_clob_match_fn)(
    void*          arena,
    const uint8_t* calldata,
    uint8_t*       out,
    uint32_t*      num_fills);

typedef int (*lux_dex_clob_arena_create_fn)(void** out_arena);
typedef int (*lux_dex_clob_arena_destroy_fn)(void* arena);

static int call_amm_xyk_batch(
    void* fn,
    const void* reserves,
    const void* amounts,
    void* outs,
    uint32_t n)
{
    return ((lux_amm_xyk_batch_fn)fn)(reserves, amounts, outs, n, NULL);
}

static int call_dex_clob_match(
    void* fn,
    void* arena,
    const uint8_t* calldata,
    uint8_t* out,
    uint32_t* num_fills)
{
    return ((lux_dex_clob_match_fn)fn)(arena, calldata, out, num_fills);
}

static int call_dex_clob_arena_create(void* fn, void** out_arena) {
    return ((lux_dex_clob_arena_create_fn)fn)(out_arena);
}

static int call_dex_clob_arena_destroy(void* fn, void* arena) {
    return ((lux_dex_clob_arena_destroy_fn)fn)(arena);
}

// dlopen / dlsym wrappers. dlerror() returns thread-local NULL when
// the last call succeeded; we call it after every failed lookup to
// produce a meaningful error string back in Go.
static void* lux_dlopen(const char* path) {
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}

static void lux_dlclose(void* handle) {
    if (handle) dlclose(handle);
}

static void* lux_dlsym(void* handle, const char* name) {
    return dlsym(handle, name);
}

static const char* lux_dlerror(void) {
    return dlerror();
}
*/
import "C"

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"
)

// gpuHandle bundles the dlopen handle and the four resolved symbol
// pointers for one backend. Created by init() exactly once per
// process; safe for concurrent use from multiple goroutines because
// the underlying plugin uses thread-safe per-backend launchers (Metal
// caches an MTLPipelineState behind a once-flag; Vulkan keeps a
// process-global VkDevice + pool; CUDA/HIP launchers are reentrant).
type gpuHandle struct {
	backend GPUBackend
	libPath string

	hLib unsafe.Pointer // dlopen handle

	fnAMMSwap      unsafe.Pointer // lux_<backend>_amm_xyk_batch
	fnCLOBMatch    unsafe.Pointer // lux_<backend>_dex_clob_match
	fnArenaCreate  unsafe.Pointer // lux_<backend>_dex_clob_arena_create
	fnArenaDestroy unsafe.Pointer // lux_<backend>_dex_clob_arena_destroy
}

// globalGPU holds the result of the init() probe. nil after a clean
// init when no plugin was found on disk — every method returns
// ErrGPUNotAvailable in that case.
var (
	globalGPU   *gpuHandle
	globalGPUMu sync.RWMutex
)

// init runs the dlopen probe at package load time. Order is
// cuda → hip → metal → vulkan → webgpu, matching the GPUBackend
// numeric ordering. The first plugin whose dylib loads AND exposes
// all four required symbols wins; later candidates are skipped.
//
// Search path order, per candidate:
//  1. ${LUX_GPU_PLUGIN_DIR}/lib<name>.<ext>  (operator-set override)
//  2. lib<name>.<ext>                        (system dlopen lookup —
//     LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, rpath, default loader paths)
//
// A struct-size assertion runs ahead of the dlopen probes so a
// build-side mismatch between Go's LuxAmmReservePair and the C ABI's
// LuxAmmReservePair (the kind of bug pkg-config would catch at link
// time but dlopen can't) fails fast instead of producing silent
// byte-shifted output.
func init() {
	// Layout assertion: LuxAmmReservePair MUST be 16 bytes packed.
	// Bigger means Go added padding and the ABI byte layout diverges.
	const wantAmmReserveBytes = 16
	if unsafe.Sizeof(LuxAmmReservePair{}) != wantAmmReserveBytes {
		panic(fmt.Sprintf(
			"dexvm: LuxAmmReservePair layout drift — got %d bytes, want %d. "+
				"Sync include/lux/gpu/dex.h::LuxAmmReservePair with backend.go.",
			unsafe.Sizeof(LuxAmmReservePair{}), wantAmmReserveBytes))
	}

	for _, b := range probeOrder() {
		if h := tryLoadBackend(b); h != nil {
			globalGPUMu.Lock()
			globalGPU = h
			globalGPUMu.Unlock()
			return
		}
	}
	// No plugin available — every method returns ErrGPUNotAvailable.
	// Intentionally NOT a panic: a node on a CPU-only host is fine,
	// it just falls back to the in-Go orderbook path.
}

// probeOrder returns the canonical dlopen probe order. CUDA first so
// NVIDIA hosts pick up the native ICD; HIP next for AMD ROCm; Metal
// is the Apple Silicon native path; Vulkan covers the rest (cross-
// vendor portable, MoltenVK on Apple, native ICDs on Linux/Windows);
// WebGPU (wgpu / Dawn) is the universal last-resort.
func probeOrder() []GPUBackend {
	return []GPUBackend{
		GPUBackendCUDA,
		GPUBackendHIP,
		GPUBackendMetal,
		GPUBackendVulkan,
		GPUBackendWebGPU,
	}
}

// dylibExt returns the platform-specific shared-library extension. We
// search both the platform-native form (.dylib on darwin, .so on
// linux, .dll on windows-via-cgo) and the unix-style .so as a
// fallback — the Vulkan loader, for example, sometimes lives under
// libluxgpu_backend_vulkan.so even on darwin (when built by CMake's
// MODULE_LIBRARY default).
func dylibExt() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{".dylib", ".so"}
	case "windows":
		return []string{".dll"}
	default:
		return []string{".so"}
	}
}

// pluginCandidatePaths returns the dlopen candidates for one backend,
// in lookup order: the operator override directory first (when set),
// then the bare library name so the system loader's standard search
// path takes over (LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, rpath, default
// loader paths).
func pluginCandidatePaths(b GPUBackend) []string {
	base := "libluxgpu_backend_" + b.String()
	exts := dylibExt()

	var out []string
	if dir := os.Getenv("LUX_GPU_PLUGIN_DIR"); dir != "" {
		for _, ext := range exts {
			out = append(out, dir+"/"+base+ext)
		}
	}
	for _, ext := range exts {
		out = append(out, base+ext)
	}
	return out
}

// tryLoadBackend dlopen's the candidate paths for one backend, and
// resolves the four required symbols. Returns nil if either the
// dylib won't load OR any required symbol is missing. Symbol misses
// are treated as fatal-for-this-backend (we don't accept a partial
// plugin — that would mask a build skew and produce a "GPU loaded
// but CLOB returns garbage" failure mode that's worse than CPU).
func tryLoadBackend(b GPUBackend) *gpuHandle {
	candidates := pluginCandidatePaths(b)
	for _, path := range candidates {
		// Clear dlerror() before dlopen so a previous miss doesn't
		// confuse the post-failure diagnostic.
		C.lux_dlerror()
		cpath := C.CString(path)
		hLib := C.lux_dlopen(cpath)
		C.free(unsafe.Pointer(cpath))
		if hLib == nil {
			continue
		}

		prefix := "lux_" + b.String() + "_"
		var (
			fnAMM    = dlsymOrNil(hLib, prefix+"amm_xyk_batch")
			fnCLOB   = dlsymOrNil(hLib, prefix+"dex_clob_match")
			fnCreate = dlsymOrNil(hLib, prefix+"dex_clob_arena_create")
			fnDestr  = dlsymOrNil(hLib, prefix+"dex_clob_arena_destroy")
		)
		if fnAMM == nil || fnCLOB == nil || fnCreate == nil || fnDestr == nil {
			// Partial export set — plausible cause is a stale plugin
			// build that pre-dates the DEX launcher landing. Close
			// the handle so we don't keep a dangling mapping, and
			// keep probing.
			C.lux_dlclose(hLib)
			continue
		}
		return &gpuHandle{
			backend:        b,
			libPath:        path,
			hLib:           hLib,
			fnAMMSwap:      fnAMM,
			fnCLOBMatch:    fnCLOB,
			fnArenaCreate:  fnCreate,
			fnArenaDestroy: fnDestr,
		}
	}
	return nil
}

// dlsymOrNil wraps dlsym() — returns nil on lookup failure so the
// caller can fail uniformly without parsing dlerror() strings.
func dlsymOrNil(h unsafe.Pointer, name string) unsafe.Pointer {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	C.lux_dlerror()
	p := C.lux_dlsym(h, cname)
	if p == nil {
		return nil
	}
	return p
}

// AutoBackend returns the GPU backend bound at init(), or
// GPUBackendNone if no plugin loaded. Callers branch on this to
// decide between the GPU path and the CPU fallback.
func AutoBackend() GPUBackend {
	globalGPUMu.RLock()
	defer globalGPUMu.RUnlock()
	if globalGPU == nil {
		return GPUBackendNone
	}
	return globalGPU.backend
}

// GPUPluginPath returns the dylib path the active backend was loaded
// from, useful for diagnostic logging at node startup. Empty string
// when no plugin loaded.
func GPUPluginPath() string {
	globalGPUMu.RLock()
	defer globalGPUMu.RUnlock()
	if globalGPU == nil {
		return ""
	}
	return globalGPU.libPath
}

// activeGPU returns the loaded handle or ErrGPUNotAvailable. Every
// public method funnels through this so the nil-check is in one place.
func activeGPU() (*gpuHandle, error) {
	globalGPUMu.RLock()
	defer globalGPUMu.RUnlock()
	if globalGPU == nil {
		return nil, ErrGPUNotAvailable
	}
	return globalGPU, nil
}

// AMMSwap runs the constant-product (xy=k) swap kernel over `n` pools
// in one batched dispatch. `reserves[i]` is the (ReserveX, ReserveY)
// pair for pool i and `amounts[i]` is the input amount. The output
// `outs[i]` is the receive-side amount:
//
//	outs[i] = (amounts[i] * reserves[i].ReserveY)
//	       / (reserves[i].ReserveX + amounts[i])
//
// Byte-equal across all five GPU backends and to the CPU oracle at
// ~/work/lux/dex/pkg/lx::ConstantProductOut. Slices must be the same
// length; a length mismatch is a caller bug (returns an error rather
// than panicking).
//
// Memory safety: every passed Go slice is pinned with runtime.Pinner
// for the duration of the C call. The pinner is unpinned via defer
// on every return path including the error path. runtime.KeepAlive
// keeps the slices reachable until C returns even if the compiler
// sees no further Go-side reference.
func AMMSwap(reserves []LuxAmmReservePair, amounts []uint64) ([]uint64, error) {
	h, err := activeGPU()
	if err != nil {
		return nil, err
	}
	if len(reserves) != len(amounts) {
		return nil, fmt.Errorf("dexvm.AMMSwap: reserves (n=%d) != amounts (n=%d)",
			len(reserves), len(amounts))
	}
	n := len(reserves)
	outs := make([]uint64, n)
	if n == 0 {
		return outs, nil
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(&reserves[0])
	pinner.Pin(&amounts[0])
	pinner.Pin(&outs[0])

	rc := C.call_amm_xyk_batch(
		h.fnAMMSwap,
		unsafe.Pointer(&reserves[0]),
		unsafe.Pointer(&amounts[0]),
		unsafe.Pointer(&outs[0]),
		C.uint32_t(n),
	)
	runtime.KeepAlive(reserves)
	runtime.KeepAlive(amounts)
	runtime.KeepAlive(outs)
	if rc != 0 {
		return nil, fmt.Errorf("dexvm.AMMSwap: %s plugin returned rc=%d",
			h.backend, int(rc))
	}
	return outs, nil
}

// CLOBArena is the opaque handle to a device-resident BookArena. The
// pointer crosses the cgo boundary as void* — Go never dereferences
// it, only passes it to ArenaDestroy or CLOBMatch.
//
// ArenaCreate hands ownership to the Go caller; ArenaDestroy releases
// it. The arena lives across many CLOBMatch calls — that's the
// entire reason it's device-resident: the BookArena holds the
// resting bids/asks for a single book, and successive CLOBMatch
// calls on the same book MUST share state.
type CLOBArena struct {
	ptr unsafe.Pointer
}

// ArenaCreate allocates a fresh device-resident BookArena (zero
// initialized). The returned handle is owned by the caller; call
// ArenaDestroy to free it. Concurrent ArenaCreate is safe.
func ArenaCreate() (*CLOBArena, error) {
	h, err := activeGPU()
	if err != nil {
		return nil, err
	}
	var raw unsafe.Pointer
	rc := C.call_dex_clob_arena_create(h.fnArenaCreate, &raw)
	if rc != 0 {
		return nil, fmt.Errorf("dexvm.ArenaCreate: %s plugin returned rc=%d",
			h.backend, int(rc))
	}
	if raw == nil {
		return nil, fmt.Errorf("dexvm.ArenaCreate: %s plugin returned NULL arena",
			h.backend)
	}
	return &CLOBArena{ptr: raw}, nil
}

// ArenaDestroy releases the device-resident BookArena. Calling it on
// a nil arena is a no-op (matches the C-side symmetry). Calling it
// twice on the same arena is UB at the plugin level — don't.
func ArenaDestroy(a *CLOBArena) error {
	if a == nil || a.ptr == nil {
		return nil
	}
	h, err := activeGPU()
	if err != nil {
		return err
	}
	rc := C.call_dex_clob_arena_destroy(h.fnArenaDestroy, a.ptr)
	a.ptr = nil
	if rc != 0 {
		return fmt.Errorf("dexvm.ArenaDestroy: %s plugin returned rc=%d",
			h.backend, int(rc))
	}
	return nil
}

// CLOBMatch runs one matcher step against the arena. calldata is the
// 117-byte EVM precompile 0x100 input — see backend.go for the byte
// layout. Output is a fixed-size 68-byte buffer (filled + avg_price +
// num_fills) plus a num_fills uint32 mirror for callers that want it
// without re-parsing the 68 bytes.
//
// Single matcher pass per call; concurrency is across book_ids — each
// book gets its own arena, and independent arenas can be matched in
// parallel on different goroutines without serialization.
func CLOBMatch(a *CLOBArena, calldata []byte) (out [LuxCLOBOutLen]byte, numFills uint32, err error) {
	h, gerr := activeGPU()
	if gerr != nil {
		return out, 0, gerr
	}
	if a == nil || a.ptr == nil {
		return out, 0, fmt.Errorf("dexvm.CLOBMatch: arena is nil")
	}
	if len(calldata) != LuxCLOBCalldataLen {
		return out, 0, fmt.Errorf("dexvm.CLOBMatch: calldata len=%d, want %d",
			len(calldata), LuxCLOBCalldataLen)
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(&calldata[0])
	pinner.Pin(&out[0])

	var nf C.uint32_t
	rc := C.call_dex_clob_match(
		h.fnCLOBMatch,
		a.ptr,
		(*C.uint8_t)(unsafe.Pointer(&calldata[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		&nf,
	)
	runtime.KeepAlive(calldata)
	runtime.KeepAlive(out)
	if rc != 0 {
		return out, 0, fmt.Errorf("dexvm.CLOBMatch: %s plugin returned rc=%d",
			h.backend, int(rc))
	}
	return out, uint32(nf), nil
}
