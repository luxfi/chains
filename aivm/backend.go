// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package aivm

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// =============================================================================
// Backend registry — the one and only entry point for resolving the active
// AIVM GPU plugin at process start.
//
// init() walks a priority list of plugin filenames, dlopen+dlsyms the first
// one that loads successfully, and stores the result in `activeBackend`.
// Callers read it via ActiveGPUBackend().
//
// Search rules:
//
//  1. LUX_GPU_PLUGIN_DIR (env) — direct directory.
//  2. LUX_GPU_PLUGIN_DIR (env) — root of the lux GPU plugin.
//     Probes `<dir>/build/backends/<kind>/<filename>` and
//     `<dir>/build/metal-only/backends/<kind>/<filename>`.
//  3. Default install: $LUXCPP_PREFIX/lib (when LUXCPP_PREFIX is set).
//  4. Bare filename — DT_RUNPATH / DT_RPATH / system loader cache.
//
// The first plugin whose all six AIVM launchers resolve via dlsym wins.
// =============================================================================

var (
	activeBackendOnce sync.Once
	activeBackend     *GPUBackend
)

// backendCandidate captures one entry in the priority probe list.
type backendCandidate struct {
	kind     BackendKind
	filename string // platform-appropriate DSO filename
	subdir   string // backends/<subdir>/
}

// platformCandidates returns the dlopen priority list for the current
// runtime. CUDA + HIP first (typically Linux + discrete GPU = highest
// throughput), then Metal on darwin, then Vulkan / WebGPU as portable
// fallbacks. The exact order intentionally matches the documented
// priority in the task spec.
func platformCandidates() []backendCandidate {
	out := []backendCandidate{
		{kind: AvailableCUDA, filename: "libluxgpu_backend_cuda.so", subdir: "cuda"},
		{kind: AvailableHIP, filename: "libluxgpu_backend_hip.so", subdir: "hip"},
	}
	if runtime.GOOS == "darwin" {
		out = append(out,
			backendCandidate{kind: AvailableMetal, filename: "libluxgpu_backend_metal.dylib", subdir: "metal"},
			backendCandidate{kind: AvailableVulkan, filename: "libluxgpu_backend_vulkan.dylib", subdir: "vulkan"},
			backendCandidate{kind: AvailableWebGPU, filename: "libluxgpu_backend_webgpu.dylib", subdir: "webgpu"},
		)
	} else {
		// linux / freebsd / windows fall through here. On windows we'd want
		// .dll suffixes, but the current build matrix has Linux as the only
		// non-darwin platform actually producing the plugin DSOs.
		out = append(out,
			backendCandidate{kind: AvailableMetal, filename: "libluxgpu_backend_metal.dylib", subdir: "metal"},
			backendCandidate{kind: AvailableVulkan, filename: "libluxgpu_backend_vulkan.so", subdir: "vulkan"},
			backendCandidate{kind: AvailableWebGPU, filename: "libluxgpu_backend_webgpu.so", subdir: "webgpu"},
		)
	}
	return out
}

// candidatePaths expands a (kind, filename, subdir) candidate into the set
// of absolute paths to probe in priority order. Includes:
//
//   - LUX_GPU_PLUGIN_DIR/<filename>
//   - LUX_GPU_PLUGIN_DIR/backends/<subdir>/<filename>
//   - LUX_GPU_PLUGIN_DIR/build/backends/<subdir>/<filename>
//   - LUX_GPU_PLUGIN_DIR/build/metal-only/backends/<subdir>/<filename>
//   - LUX_GPU_PLUGIN_DIR/build/vulkan-m1/backends/<subdir>/<filename>
//   - LUXCPP_PREFIX/lib/<filename>
//   - bare filename (DT_RUNPATH / DT_RPATH / system search)
//
// Bare last so an explicit env override always wins.
func candidatePaths(c backendCandidate) []string {
	var paths []string
	if dir := os.Getenv("LUX_GPU_PLUGIN_DIR"); dir != "" {
		paths = append(paths,
			filepath.Join(dir, c.filename),
			filepath.Join(dir, "backends", c.subdir, c.filename),
		)
	}
	if dir := os.Getenv("LUX_GPU_PLUGIN_DIR"); dir != "" {
		// Match the on-disk layout shipped by the GPU plugin install tree:
		// `build/backends/<kind>/<filename>` from the default CMake build,
		// plus the per-flavor subdirs the kernel team uses for matrix
		// builds (metal-only, vulkan-m1, …).
		paths = append(paths,
			filepath.Join(dir, "build", "backends", c.subdir, c.filename),
			filepath.Join(dir, "build", "metal-only", "backends", c.subdir, c.filename),
			filepath.Join(dir, "build", "vulkan-m1", "backends", c.subdir, c.filename),
		)
	}
	if dir := os.Getenv("LUXCPP_PREFIX"); dir != "" {
		paths = append(paths, filepath.Join(dir, "lib", c.filename))
	}
	// Bare name — fall back to the loader's default search (DT_RPATH on Linux,
	// @rpath on darwin, LD_LIBRARY_PATH / DYLD_LIBRARY_PATH set by user).
	paths = append(paths, c.filename)
	return paths
}

// init runs the dlopen probe at process start. The first plugin whose all
// six AIVM launchers resolve via dlsym becomes the active backend. If none
// load, activeBackend remains nil and gpuAvailable() reports false; vm.go
// continues on the pure-Go path with no observable degradation.
//
// init() is intentionally silent on failure — the absence of a plugin is a
// supported configuration (the chain runs without GPU acceleration). The
// kind / path of the resolved backend is available via ActiveGPUBackend()
// for diagnostics.
func init() {
	autoLoadBackend()
}

// autoLoadBackend resolves the active backend lazily-but-once. It walks
// platformCandidates(), tries each plugin file in candidatePaths(), and
// stops at the first complete success. Exposed for tests so they can
// re-trigger the probe under a different env without restarting the
// process; production callers go through init() once.
func autoLoadBackend() *GPUBackend {
	activeBackendOnce.Do(func() {
		for _, c := range platformCandidates() {
			for _, path := range candidatePaths(c) {
				b, err := openGPUBackend(c.kind, path)
				if err != nil {
					continue // try the next candidate path
				}
				if !b.IsAvailable() {
					b.Close()
					continue
				}
				activeBackend = b
				return
			}
		}
	})
	return activeBackend
}

// ActiveGPUBackend returns the backend resolved at init time. Always
// non-nil — when no plugin loaded it returns a zero-value *GPUBackend
// whose IsAvailable() reports false. Callers test IsAvailable() / Kind()
// to decide whether to opt into the GPU path.
func ActiveGPUBackend() *GPUBackend {
	if activeBackend == nil {
		// Defensive: if init() ran before LUX_GPU_PLUGIN_DIR was
		// set (rare, mostly tests), re-probe via the once-guarded loader.
		// Once activeBackend is set the once-guard keeps subsequent calls
		// cheap.
		if b := autoLoadBackend(); b != nil {
			return b
		}
		return &GPUBackend{} // zero value, IsAvailable() == false
	}
	return activeBackend
}

// =============================================================================
// Public API — parallel.SetBackend(parallel.AutoAIVM) analogue.
//
// Mirrors the cevm side at chains/evm/cevm/parallel: a tiny package-level
// switch that lets callers opt into the GPU-accelerated AIVM transition
// path. AutoAIVM = pick whatever ActiveGPUBackend() resolved. CPUAIVM =
// force the Go fallback. Set per-process at startup; no per-call dispatch.
//
// `Mode` and the AutoAIVM / CPUAIVM / GPUAIVM constants live in the
// build-tag-free aivm_gpu_types.go (so the nocgo build sees the same
// surface). This file owns the cgo-side package-level state.
// =============================================================================

var (
	modeMu     sync.RWMutex
	activeMode = AutoAIVM
)

// SetBackend selects the active AIVM transition mode for the process.
// Use AutoAIVM (the default) to let init()'s dlopen probe pick the best
// available backend.
func SetBackend(m Mode) {
	modeMu.Lock()
	defer modeMu.Unlock()
	activeMode = m
}

// ActiveMode returns the current transition mode set by SetBackend().
func ActiveMode() Mode {
	modeMu.RLock()
	defer modeMu.RUnlock()
	return activeMode
}

// EffectiveBackendKind returns which backend the next transition will
// actually use given (ActiveMode, ActiveGPUBackend). Useful for logging
// at boot.
func EffectiveBackendKind() BackendKind {
	switch ActiveMode() {
	case CPUAIVM:
		return AvailableNone
	case GPUAIVM:
		return ActiveGPUBackend().Kind()
	default:
		if b := ActiveGPUBackend(); b.IsAvailable() {
			return b.Kind()
		}
		return AvailableNone
	}
}
