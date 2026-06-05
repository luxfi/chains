// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package thresholdvm

// dlopen probe for the MPCVM GPU plugin. Runs once at package init() and
// pins the resolved GPUBackend into the gpuBackend singleton. Probe order
// matches the LP-186 substrate priority: native (CUDA, HIP, Metal) over
// portable (Vulkan, WebGPU), discrete over UMA.
//
//   cuda → hip → metal → vulkan → webgpu
//
// Each backend has a small set of candidate dylib names. We try the
// LUXCPP_PREFIX install path first, then the lux-gpu-kernels build-tree
// path, then the bare leaf-name (relying on the dynamic linker's default
// search path: $DYLD_LIBRARY_PATH, $LD_LIBRARY_PATH, system dirs).
//
// LUX_THRESHOLDVM_GPU_BACKEND overrides the probe — when set to a backend
// name we try ONLY that one. When set to "none" we skip the probe entirely.
//
// The probe is intentionally silent on failure: a host with no GPU still
// boots; thresholdvm just runs on the CPU reference (the existing
// protocol/, factory.go, executor.go state machine, unchanged by this
// bridge). Failure paths log to stderr at most once at init() under
// LUX_THRESHOLDVM_GPU_DEBUG=1 for diagnostics.

import (
	"fmt"
	"os"
	"path/filepath"
)

// init runs the dlopen probe exactly once at package load. The size
// assertions run first so any wire-struct drift fails fast at process
// start instead of producing silently-wrong kernel results.
func init() {
	gpuBackendOnce.Do(func() {
		assertSizes()
		gpuBackend = probeGPUBackend()
		if debugProbe() {
			if gpuBackend == nil || !gpuBackend.IsAvailable() {
				fmt.Fprintln(os.Stderr,
					"[lux-thresholdvm-gpu] no plugin resolved, falling back to CPU")
			} else {
				fmt.Fprintf(os.Stderr,
					"[lux-thresholdvm-gpu] resolved backend=%s path=%s\n",
					gpuBackend.Kind, gpuBackend.Path)
			}
		}
	})
}

func debugProbe() bool {
	v := os.Getenv("LUX_THRESHOLDVM_GPU_DEBUG")
	return v == "1" || v == "true"
}

// probeGPUBackend walks the canonical backend priority list and returns the
// first one that dlopens AND resolves the required symbol pair. Returns
// nil when nothing matches (CPU-only mode).
func probeGPUBackend() *GPUBackend {
	if kind, set := envBackendOverride(); set {
		if kind == GPUBackendNone {
			return nil
		}
		return tryLoadPlugin(kind, candidatesFor(kind)...)
	}

	order := []GPUBackendKind{
		GPUBackendCUDA,
		GPUBackendHIP,
		GPUBackendMetal,
		GPUBackendVulkan,
		GPUBackendWebGPU,
	}
	for _, kind := range order {
		if b := tryLoadPlugin(kind, candidatesFor(kind)...); b != nil {
			return b
		}
	}
	return nil
}

// candidatesFor returns up to three dylib filename candidates for the given
// backend, ordered: LUXCPP_PREFIX/lib install path, lux-gpu-kernels build-tree
// path under LUX_PRIVATE_GPU_KERNELS_DIR, then bare leaf-name for the
// dynamic-linker default search path.
//
// On darwin the convention is libluxgpu_backend_<X>.dylib; on linux it's
// .so. WebGPU has both .dylib (when built locally on macOS) and .so
// (linux), so we include both extensions in its candidate list to maximize
// dlopen hit rate without per-platform compile-time branching.
func candidatesFor(kind GPUBackendKind) []string {
	leaves := backendDylibLeaves(kind)
	out := make([]string, 0, len(leaves)*3)

	prefix := os.Getenv("LUXCPP_PREFIX")
	if prefix == "" {
		if home := os.Getenv("HOME"); home != "" {
			prefix = filepath.Join(home, "work", "luxcpp", "install")
		}
	}
	for _, leaf := range leaves {
		if prefix != "" {
			out = append(out, filepath.Join(prefix, "lib", leaf))
		}
	}

	if kernels := os.Getenv("LUX_PRIVATE_GPU_KERNELS_DIR"); kernels != "" {
		for _, leaf := range leaves {
			// build/<backend>_backend/<leaf> is the cmake output convention
			// for both metal_backend/ and webgpu_backend/.
			sub := backendBuildDirname(kind)
			if sub != "" {
				out = append(out, filepath.Join(kernels, "build", sub, leaf))
			}
		}
	} else if home := os.Getenv("HOME"); home != "" {
		// Default lux-private path per the project memory note (2026-05-28):
		// "luxcpp/metal + luxcpp/webgpu ARCHIVED. Plugin source + shaders
		// now at lux-private/gpu-kernels/{metal,webgpu,kernels/...}".
		root := filepath.Join(home, "work", "lux-private", "gpu-kernels")
		for _, leaf := range leaves {
			sub := backendBuildDirname(kind)
			if sub != "" {
				out = append(out, filepath.Join(root, "build", sub, leaf))
			}
		}
	}

	// Bare leaf names — dynamic-linker default search picks them up if
	// LD_LIBRARY_PATH / DYLD_LIBRARY_PATH or /usr/local/lib has them.
	out = append(out, leaves...)
	return out
}

// backendDylibLeaves returns the OS-appropriate leaf filenames for one
// backend. WebGPU has two valid extensions across platforms — we include
// both so the same probe works on macOS and linux.
func backendDylibLeaves(kind GPUBackendKind) []string {
	switch kind {
	case GPUBackendCUDA:
		return []string{"libluxgpu_backend_cuda.so"}
	case GPUBackendHIP:
		return []string{"libluxgpu_backend_hip.so"}
	case GPUBackendMetal:
		return []string{"libluxgpu_backend_metal.dylib"}
	case GPUBackendVulkan:
		return []string{
			"libluxgpu_backend_vulkan.so",
			"libluxgpu_backend_vulkan.dylib",
		}
	case GPUBackendWebGPU:
		return []string{
			"libluxgpu_backend_webgpu.dylib",
			"libluxgpu_backend_webgpu.so",
		}
	default:
		return nil
	}
}

// backendBuildDirname maps each backend to its cmake build subdirectory
// under lux-private/gpu-kernels/build/.
func backendBuildDirname(kind GPUBackendKind) string {
	switch kind {
	case GPUBackendCUDA:
		return "cuda_backend"
	case GPUBackendHIP:
		return "hip_backend"
	case GPUBackendMetal:
		return "metal_backend"
	case GPUBackendVulkan:
		return "vulkan_backend"
	case GPUBackendWebGPU:
		return "webgpu_backend"
	default:
		return ""
	}
}
