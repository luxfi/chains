//go:build cgo

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package quantumvm GPU backend — runtime-loaded plugin bridge via the
// ABI v14 vtbl entry point.
//
// Unlike cevm/cevm_cgo.go (which links libevm + libevm-gpu via pkg-config
// and reaches the C ABI through extern "C" gpu_* helpers), Q-Chain
// resolves its GPU substrate at PROCESS START via dlopen / dlsym against
// the lux-gpu-kernels plugin DSO and reaches the per-op kernel through
// function pointers inside a vtbl populated by the plugin's
// `lux_gpu_backend_init` entry point. This keeps the chains module
// compilable without lux-private/gpu-kernels present in the build tree —
// the plugin is fully optional. When no libluxgpu_backend_*.{so,dylib}
// is findable on the dlopen search path, AutoBackend() returns
// BackendNone, every GPUBackend method returns ErrGPUNotAvailable, and
// the existing CPU verify path stays unchanged.
//
// Probe order (init()): cuda → hip → metal → vulkan → webgpu. First
// plugin that resolves the entry point AND reports a v14 ABI matching
// the header we compiled against AND exposes the three Q-Chain slots
// (op_mldsa_verify_batch, op_mldsa_sign_batch,
// op_slhdsa_verify_batch[_shake192f]) wins; remaining probes are
// skipped. The cookie checks (abi_version + vtbl_size) defend against
// a plugin that lies about its ABI version while shipping a truncated
// vtable (see backend_plugin.h §"Backend Descriptor" comment).
//
// Search path: the dlopen library name is the bare basename
// (libluxgpu_backend_<x>.{so,dylib}); the loader's standard
// LD_LIBRARY_PATH / DYLD_LIBRARY_PATH / rpath resolution finds it.
// LUX_GPU_PLUGIN_DIR overrides — if set, every probe joins it to the
// basename before calling dlopen.
package quantumvm

/*
#cgo darwin LDFLAGS: -ldl
#cgo linux  LDFLAGS: -ldl

// Workspace-relative path to the ABI v14 plugin header. From
// ${SRCDIR} = ~/work/lux/chains/quantumvm we walk three levels up
// (chains → lux → work) and one down (lux-private/gpu-kernels/include)
// to reach the canonical header. External consumers building from
// $GOMODCACHE need lux-private/gpu-kernels checked out at the standard
// sibling location; this matches the convention LLM.md establishes
// for every other workspace-coupled component (LUXCPP_DIR etc.).
//
// Header-only inclusion: we DO NOT link against any luxcpp / lux-gpu
// library. The plugin DSO is dlopen'd at runtime; the only compile-
// time dependency is the C struct layout in backend_plugin.h.
#cgo CFLAGS: -I${SRCDIR}/../../../lux-private/gpu-kernels/include

#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lux/gpu/backend_plugin.h"

// ABI v14 vtbl entry-point thunk. dlsym returns void*; this struct lets
// Go pass the function pointer back through the bridge without losing
// type information at the cgo boundary.
typedef bool (*qvm_backend_init_fn)(lux_gpu_backend_desc* out);

// qvm_backend_init invokes the plugin's `lux_gpu_backend_init` symbol
// and returns 0 on success, non-zero (1..5) on a specific cookie /
// slot failure. The cookies (abi_version + vtbl_size) detect plugins
// built against a different header — fail fast at process start
// instead of UB at the first vtbl slot call (a stale plugin's
// op_mldsa_verify_batch at the wrong offset would be a junk function
// pointer dispatch otherwise).
//
//   ret == 0 — desc populated AND all three Q-Chain slots non-NULL.
//   ret == 1 — init function returned false (no runtime available on
//              this host: missing driver, ICD, etc.). Caller treats
//              as SKIP, not FAIL.
//   ret == 2 — abi_version mismatch (plugin is from a different ABI
//              than the Go bindings were compiled against).
//   ret == 3 — vtbl_size mismatch (plugin shipped a truncated vtbl).
//   ret == 4 — vtbl pointer is NULL (malformed descriptor).
//   ret == 5 — vtbl is missing one of the three Q-Chain slots.
static int qvm_backend_init(void* sym, lux_gpu_backend_desc* desc) {
    if (!sym || !desc) return 4;
    memset(desc, 0, sizeof(*desc));
    qvm_backend_init_fn fn = (qvm_backend_init_fn)sym;
    if (!fn(desc)) return 1;
    if (desc->abi_version != LUX_GPU_BACKEND_ABI_VERSION) return 2;
    if (desc->vtbl_size != sizeof(lux_gpu_backend_vtbl)) return 3;
    if (!desc->vtbl) return 4;
    if (!desc->vtbl->create_context || !desc->vtbl->destroy_context) return 5;
    // ML-DSA verify is the canonical Q-Chain slot. ML-DSA sign and
    // SLH-DSA verify may be nullptr on backends that haven't wired
    // their orchestrator yet — those methods then return
    // LUX_BACKEND_ERROR_NOT_SUPPORTED at call time, which the Go
    // wrapper translates to ErrGPUNotAvailable. The plugin is still
    // viable if at least op_mldsa_verify_batch is wired (ML-DSA
    // verify is the load-bearing Q-Chain op).
    if (!desc->vtbl->op_mldsa_verify_batch) return 5;
    return 0;
}

// Lifecycle helpers — exported so the Go side can open / close a
// LuxBackendContext per probe-result backend exactly once. device_index
// = 0 is the canonical "first available device" sentinel — backends
// like Metal that don't expose multi-GPU selection assume 0 and would
// throw on -1 (NSRangeException on Apple Silicon, observed).
static LuxBackendContext* qvm_create_context(const lux_gpu_backend_vtbl* vtbl) {
    return vtbl->create_context(0);
}
static void qvm_destroy_context(const lux_gpu_backend_vtbl* vtbl, LuxBackendContext* ctx) {
    if (ctx) vtbl->destroy_context(ctx);
}

// Per-slot wrappers. The trampolines unpack Go's flat parameter slices
// and dispatch through the vtbl function pointer. Each returns the raw
// LuxBackendError code — the Go side maps NOT_SUPPORTED (3) →
// ErrGPUNotAvailable and other non-zero codes → fmt.Errorf("rc=%d").

// op_mldsa_verify_batch — see backend_plugin.h v14 block. msg_lens is
// optional (NULL → use msg_width_hint for every element).
static int qvm_op_mldsa_verify(
    const lux_gpu_backend_vtbl* vtbl,
    LuxBackendContext*          ctx,
    const uint8_t* const*       pubkeys,
    const uint8_t* const*       messages,
    const size_t*               msg_lens,
    uint32_t                    msg_width_hint,
    const uint8_t* const*       signatures,
    bool*                       results,
    size_t                      count) {
    if (!vtbl->op_mldsa_verify_batch) return LUX_BACKEND_ERROR_NOT_SUPPORTED;
    return (int)vtbl->op_mldsa_verify_batch(
        ctx, pubkeys, messages, msg_lens,
        msg_width_hint, signatures, results, count);
}

// op_mldsa_sign_batch — see backend_plugin.h v14 block. sig_lens_out is
// optional (NULL is fine — caller falls back to per-element verify if
// it needs accept / reject feedback).
static int qvm_op_mldsa_sign(
    const lux_gpu_backend_vtbl* vtbl,
    LuxBackendContext*          ctx,
    const uint8_t*              skeys,
    size_t                      sk_stride,
    const uint8_t*              msgs,
    const size_t*               msg_lens,
    uint32_t                    msg_width_hint,
    size_t                      count,
    uint8_t*                    sigs_out,
    uint32_t*                   sig_lens_out) {
    if (!vtbl->op_mldsa_sign_batch) return LUX_BACKEND_ERROR_NOT_SUPPORTED;
    return (int)vtbl->op_mldsa_sign_batch(
        ctx, skeys, sk_stride, msgs, msg_lens,
        msg_width_hint, count, sigs_out, sig_lens_out);
}

// op_slhdsa_verify_batch — SHAKE-128f. See backend_plugin.h ABI v13.
static int qvm_op_slhdsa_verify_128f(
    const lux_gpu_backend_vtbl* vtbl,
    LuxBackendContext*          ctx,
    const uint8_t* const*       pubkeys,
    const uint8_t* const*       messages,
    const size_t*               msg_lens,
    const uint8_t* const*       signatures,
    bool*                       results,
    size_t                      count) {
    if (!vtbl->op_slhdsa_verify_batch) return LUX_BACKEND_ERROR_NOT_SUPPORTED;
    return (int)vtbl->op_slhdsa_verify_batch(
        ctx, pubkeys, messages, msg_lens, signatures, results, count);
}

// op_slhdsa_verify_batch_shake192f — SHAKE-192f. See backend_plugin.h
// ABI v13.
static int qvm_op_slhdsa_verify_192f(
    const lux_gpu_backend_vtbl* vtbl,
    LuxBackendContext*          ctx,
    const uint8_t* const*       pubkeys,
    const uint8_t* const*       messages,
    const size_t*               msg_lens,
    const uint8_t* const*       signatures,
    bool*                       results,
    size_t                      count) {
    if (!vtbl->op_slhdsa_verify_batch_shake192f) return LUX_BACKEND_ERROR_NOT_SUPPORTED;
    return (int)vtbl->op_slhdsa_verify_batch_shake192f(
        ctx, pubkeys, messages, msg_lens, signatures, results, count);
}

// dlopen / dlsym wrappers — kept here so backend.go stays pure Go.
static void* qvm_dlopen(const char* path) {
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}
static void* qvm_dlsym(void* handle, const char* sym) {
    return dlsym(handle, sym);
}
static const char* qvm_dlerror(void) {
    return dlerror();
}
static void qvm_dlclose(void* handle) {
    if (handle) dlclose(handle);
}

// Allocates a lux_gpu_backend_desc the Go side keeps for the lifetime
// of the GPUBackend. Heap-allocated so the Go object's address can be
// shared across cgo calls without escape-analysis surprises.
static lux_gpu_backend_desc* qvm_alloc_desc(void) {
    lux_gpu_backend_desc* d = (lux_gpu_backend_desc*)calloc(1, sizeof(*d));
    return d;
}
static void qvm_free_desc(lux_gpu_backend_desc* d) {
    free(d);
}
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"
)

// pluginEntrySymbol is the canonical ABI v14 entry point exported by every
// libluxgpu_backend_<x>.{so,dylib} plugin. Resolving this symbol yields a
// function pointer that populates a lux_gpu_backend_desc with abi_version,
// vtbl_size cookies, and the vtbl pointer the rest of this file walks.
const pluginEntrySymbol = "lux_gpu_backend_init"

// pluginEnv overrides the dlopen search path. When set, every probe joins
// the env value to the bare basename before calling dlopen — useful for
// in-tree development against a freshly-built plugin under
// ~/work/lux-private/gpu-kernels/build/ without installing it.
const pluginEnv = "LUX_GPU_PLUGIN_DIR"

// probeOrder is the dlopen probe sequence fixed by the spec:
// cuda → hip → metal → vulkan → webgpu. First plugin that satisfies the
// cookie checks AND exposes the load-bearing op_mldsa_verify_batch slot
// wins; the remaining probes are skipped. Order is preserved at struct
// definition (not encoded as a map) so the iteration order is the same
// on every platform.
var probeOrder = []struct {
	kind Backend
	name string // basename without lib prefix or .so/.dylib suffix
}{
	{BackendCUDA, "luxgpu_backend_cuda"},
	{BackendHIP, "luxgpu_backend_hip"},
	{BackendMetal, "luxgpu_backend_metal"},
	{BackendVulkan, "luxgpu_backend_vulkan"},
	{BackendWebGPU, "luxgpu_backend_webgpu"},
}

// pluginBasenames returns the platform-specific DSO basenames to attempt
// for a given backend. On darwin we try both .dylib (native) and .so
// (cross-tooling fallback). On linux / other we try .so first. The
// order within each entry's slice matches the lookup order used by
// dlopen — first hit wins.
func pluginBasenames(name string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"lib" + name + ".dylib",
			"lib" + name + ".so",
		}
	case "windows":
		return []string{
			name + ".dll",
		}
	default:
		return []string{
			"lib" + name + ".so",
		}
	}
}

// =============================================================================
// gpuBackend — the cgo implementation of the GPUBackend interface.
//
// One struct per loaded plugin; pinned at package level by init()'s probe.
// All vtbl invocations route through C trampolines (qvm_op_*) defined in
// the cgo preamble above. mu serialises Close() against concurrent op
// dispatch — every vtbl call increments / decrements an in-flight counter
// so Close() can wait for outstanding calls before destroying the context.
// =============================================================================

type gpuBackend struct {
	mu     sync.Mutex
	kind   Backend
	handle unsafe.Pointer       // dlopen result (void*)
	desc   *C.lux_gpu_backend_desc // heap-allocated descriptor
	ctx    *C.LuxBackendContext // backend-managed opaque context
	path   string
}

// init runs the dlopen probe exactly once at process start. The probe
// walks probeOrder, attempts each candidate basename, and stops at the
// first plugin that:
//
//   1. Successfully dlopens.
//   2. Exposes the lux_gpu_backend_init symbol.
//   3. Reports abi_version == LUX_GPU_BACKEND_ABI_VERSION (14).
//   4. Reports vtbl_size == sizeof(lux_gpu_backend_vtbl) on our header.
//   5. Has op_mldsa_verify_batch wired (the load-bearing Q-Chain slot).
//   6. Successfully opens a LuxBackendContext via vtbl->create_context.
//
// On success the package-level activeBackend atomic is set to the
// matching Backend enum value. Failure at any stage is silent — we move
// to the next candidate. If no candidate succeeds, activeBackend stays
// BackendNone and ActiveGPUBackend() returns a noGPUBackend stub.
func init() {
	if b, ok := tryProbe(); ok {
		setActiveBackend(b.kind)
		setActiveGPU(b)
		return
	}
	setActiveBackend(BackendNone)
	setActiveGPU(nil)
}

// tryProbe runs the probeOrder dlopen loop. Returns the loaded gpuBackend
// on success, or (nil, false) if no candidate satisfied all six checks.
// Errors are deliberately not surfaced — this is a probe, not a hard
// requirement. Callers see BackendNone and route to the CPU path.
func tryProbe() (*gpuBackend, bool) {
	dir := os.Getenv(pluginEnv)
	for _, p := range probeOrder {
		for _, bn := range pluginBasenames(p.name) {
			path := bn
			if dir != "" {
				path = filepath.Join(dir, bn)
			}
			b, err := openPlugin(p.kind, path)
			if err == nil {
				return b, true
			}
		}
	}
	return nil, false
}

// openPlugin attempts to dlopen `path`, resolve lux_gpu_backend_init,
// run the cookie checks, and create a backend context. Returns the
// loaded gpuBackend on success, or (nil, err) with the offending stage
// documented in the error. The dlopen handle is closed on any failure
// past the dlopen point — we never leak a half-bound plugin.
func openPlugin(kind Backend, path string) (*gpuBackend, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	// Clear pending dlerror so a stale message from a prior failed call
	// doesn't get mis-attributed to this dlopen.
	C.qvm_dlerror()

	handle := C.qvm_dlopen(cpath)
	if handle == nil {
		return nil, fmt.Errorf("quantumvm: dlopen(%s): %s",
			path, C.GoString(C.qvm_dlerror()))
	}

	csym := C.CString(pluginEntrySymbol)
	defer C.free(unsafe.Pointer(csym))
	C.qvm_dlerror()
	sym := C.qvm_dlsym(handle, csym)
	if sym == nil {
		C.qvm_dlclose(handle)
		return nil, fmt.Errorf("quantumvm: dlsym(%s, %s): %s",
			path, pluginEntrySymbol, C.GoString(C.qvm_dlerror()))
	}

	desc := C.qvm_alloc_desc()
	if desc == nil {
		C.qvm_dlclose(handle)
		return nil, fmt.Errorf("quantumvm: calloc(lux_gpu_backend_desc) failed")
	}
	if rc := C.qvm_backend_init(sym, desc); rc != 0 {
		C.qvm_free_desc(desc)
		C.qvm_dlclose(handle)
		return nil, fmt.Errorf(
			"quantumvm: %s plugin init failed (rc=%d, path=%s)",
			kind, int(rc), path)
	}

	ctx := C.qvm_create_context(desc.vtbl)
	if ctx == nil {
		C.qvm_free_desc(desc)
		C.qvm_dlclose(handle)
		return nil, fmt.Errorf(
			"quantumvm: %s create_context returned NULL (no runtime on this host?)",
			kind)
	}

	return &gpuBackend{
		kind:   kind,
		handle: handle,
		desc:   desc,
		ctx:    ctx,
		path:   path,
	}, nil
}

// =============================================================================
// Active-backend handle plumbing.
//
// activeGPU stores the *gpuBackend resolved by init()'s probe (or nil
// when no plugin loaded). Read via ActiveGPUBackend() — which returns
// the GPUBackend interface (gpuBackend implements it). The pointer is
// pinned at init time and never mutated thereafter; we still serialise
// access through a Mutex for safety against a future caller that might
// add an explicit re-probe path.
// =============================================================================

var (
	activeGPUMu sync.RWMutex
	activeGPU   *gpuBackend
)

func setActiveGPU(b *gpuBackend) {
	activeGPUMu.Lock()
	activeGPU = b
	activeGPUMu.Unlock()
}

// ActiveGPUBackend returns the package-level GPUBackend handle. Under
// cgo this is the *gpuBackend chosen by init()'s probe, or a sentinel
// noGPUBackend stub when no plugin loaded. The returned handle's
// methods are safe to call from any goroutine — every vtbl call
// holds the backend mutex.
func ActiveGPUBackend() GPUBackend {
	activeGPUMu.RLock()
	b := activeGPU
	activeGPUMu.RUnlock()
	if b == nil {
		return noGPUBackend{}
	}
	return b
}

// noGPUBackend is the cgo build's stub for the "no plugin loaded" case.
// Distinct from the !cgo noGPUBackend so the !cgo file can ship without
// any cgo machinery; same method semantics.
type noGPUBackend struct{}

func (noGPUBackend) Backend() Backend { return BackendNone }

func (noGPUBackend) Close() error { return nil }

func (noGPUBackend) MLDSAVerifyBatch(
	mode MLDSAMode,
	pubkeys [][]byte,
	messages [][]byte,
	msgLens []int,
	msgWidthHint uint32,
	signatures [][]byte,
	results []bool,
) error {
	_ = mode
	_ = messages
	_ = msgLens
	_ = msgWidthHint
	_ = signatures
	_ = results
	if len(pubkeys) == 0 {
		return nil
	}
	return ErrGPUNotAvailable
}

func (noGPUBackend) MLDSASignBatch(
	mode MLDSAMode,
	skeys []byte,
	msgs []byte,
	msgLens []int,
	msgWidthHint uint32,
	count int,
	sigsOut []byte,
	sigLensOut []uint32,
) error {
	_ = mode
	_ = skeys
	_ = msgs
	_ = msgLens
	_ = msgWidthHint
	_ = sigsOut
	_ = sigLensOut
	if count == 0 {
		return nil
	}
	return ErrGPUNotAvailable
}

func (noGPUBackend) SLHDSAVerifyBatch(
	variant SLHDSAVariant,
	pubkeys [][]byte,
	messages [][]byte,
	msgLens []int,
	signatures [][]byte,
	results []bool,
) error {
	_ = variant
	_ = messages
	_ = msgLens
	_ = signatures
	_ = results
	if len(pubkeys) == 0 {
		return nil
	}
	return ErrGPUNotAvailable
}

// =============================================================================
// gpuBackend method implementations.
// =============================================================================

func (b *gpuBackend) Backend() Backend {
	if b == nil {
		return BackendNone
	}
	return b.kind
}

// Close destroys the LuxBackendContext, dlcloses the plugin, and frees
// the descriptor. Safe on a nil receiver and idempotent — a second call
// is a no-op once the handle has been cleared.
func (b *gpuBackend) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handle == nil {
		return nil
	}
	if b.ctx != nil {
		C.qvm_destroy_context(b.desc.vtbl, b.ctx)
		b.ctx = nil
	}
	if b.desc != nil {
		C.qvm_free_desc(b.desc)
		b.desc = nil
	}
	C.qvm_dlclose(b.handle)
	b.handle = nil
	return nil
}

// MLDSAVerifyBatch dispatches op_mldsa_verify_batch from the loaded
// vtbl. See the GPUBackend interface doc + backend_plugin.h v14 block
// for the contract.
func (b *gpuBackend) MLDSAVerifyBatch(
	mode MLDSAMode,
	pubkeys [][]byte,
	messages [][]byte,
	msgLens []int,
	msgWidthHint uint32,
	signatures [][]byte,
	results []bool,
) error {
	if mode != MLDSAMode65 {
		// v14 vtbl only exposes ML-DSA-65 at op_mldsa_verify_batch.
		// Modes 44 / 87 will land at sibling slots in a future ABI
		// bump (see backend_plugin.h v14 block).
		return ErrGPUNotAvailable
	}
	n := len(pubkeys)
	if n == 0 {
		return nil
	}
	if len(messages) != n || len(signatures) != n || len(results) != n {
		return fmt.Errorf(
			"quantumvm: MLDSAVerifyBatch: length mismatch (pubkeys=%d messages=%d signatures=%d results=%d)",
			n, len(messages), len(signatures), len(results))
	}
	if msgLens != nil && len(msgLens) != n {
		return fmt.Errorf(
			"quantumvm: MLDSAVerifyBatch: msgLens length %d != batch %d",
			len(msgLens), n)
	}
	if b == nil || b.ctx == nil || b.desc == nil {
		return ErrGPUNotAvailable
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Pin every Go-side byte slice for the duration of the C call.
	// runtime.Pinner guarantees the GC won't move (or collect) the
	// backing arrays while the kernel reads them.
	var pinner runtime.Pinner
	defer pinner.Unpin()

	pkPtrs := make([]*C.uint8_t, n)
	msgPtrs := make([]*C.uint8_t, n)
	sigPtrs := make([]*C.uint8_t, n)
	var lensBuf []C.size_t
	for i := 0; i < n; i++ {
		if len(pubkeys[i]) != MLDSA65PublicKeySize {
			return fmt.Errorf(
				"quantumvm: MLDSAVerifyBatch[%d]: pubkey len %d != %d",
				i, len(pubkeys[i]), MLDSA65PublicKeySize)
		}
		if len(signatures[i]) > MLDSA65SignatureSize {
			return fmt.Errorf(
				"quantumvm: MLDSAVerifyBatch[%d]: signature len %d > max %d",
				i, len(signatures[i]), MLDSA65SignatureSize)
		}
		pinner.Pin(&pubkeys[i][0])
		pkPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&pubkeys[i][0]))
		// Allow zero-length message (legal — empty-message verify is
		// a defined SHAKE256 absorb-zero operation per FIPS 204).
		if len(messages[i]) > 0 {
			pinner.Pin(&messages[i][0])
			msgPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&messages[i][0]))
		}
		pinner.Pin(&signatures[i][0])
		sigPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&signatures[i][0]))
	}
	if msgLens != nil {
		lensBuf = make([]C.size_t, n)
		for i := 0; i < n; i++ {
			if msgLens[i] < 0 {
				return fmt.Errorf(
					"quantumvm: MLDSAVerifyBatch[%d]: negative msgLen %d",
					i, msgLens[i])
			}
			lensBuf[i] = C.size_t(msgLens[i])
		}
	}

	// bool layout in cgo: C.bool is one byte. Stage results in a
	// scratch buffer; copy back to the caller's []bool after the call.
	cresults := make([]C.bool, n)
	pkPtrsPtr := (**C.uint8_t)(unsafe.Pointer(&pkPtrs[0]))
	msgPtrsPtr := (**C.uint8_t)(unsafe.Pointer(&msgPtrs[0]))
	sigPtrsPtr := (**C.uint8_t)(unsafe.Pointer(&sigPtrs[0]))
	var lensPtr *C.size_t
	if lensBuf != nil {
		lensPtr = (*C.size_t)(unsafe.Pointer(&lensBuf[0]))
	}

	rc := C.qvm_op_mldsa_verify(
		b.desc.vtbl,
		b.ctx,
		pkPtrsPtr,
		msgPtrsPtr,
		lensPtr,
		C.uint32_t(msgWidthHint),
		sigPtrsPtr,
		(*C.bool)(unsafe.Pointer(&cresults[0])),
		C.size_t(n),
	)
	runtime.KeepAlive(pkPtrs)
	runtime.KeepAlive(msgPtrs)
	runtime.KeepAlive(sigPtrs)
	runtime.KeepAlive(lensBuf)
	runtime.KeepAlive(cresults)

	if rc != 0 {
		return mapBackendError(int(rc), "op_mldsa_verify_batch")
	}
	for i := 0; i < n; i++ {
		results[i] = bool(cresults[i])
	}
	return nil
}

// MLDSASignBatch dispatches op_mldsa_sign_batch from the loaded vtbl.
// See the GPUBackend interface doc + backend_plugin.h v14 block.
func (b *gpuBackend) MLDSASignBatch(
	mode MLDSAMode,
	skeys []byte,
	msgs []byte,
	msgLens []int,
	msgWidthHint uint32,
	count int,
	sigsOut []byte,
	sigLensOut []uint32,
) error {
	if mode != MLDSAMode65 {
		return ErrGPUNotAvailable
	}
	if count == 0 {
		return nil
	}
	const skStride = MLDSA65SecretKeySize
	const sigStride = MLDSA65SignatureSize
	if len(skeys) != count*skStride {
		return fmt.Errorf(
			"quantumvm: MLDSASignBatch: skeys len %d != count*%d (%d)",
			len(skeys), skStride, count*skStride)
	}
	if len(sigsOut) != count*sigStride {
		return fmt.Errorf(
			"quantumvm: MLDSASignBatch: sigsOut len %d != count*%d (%d)",
			len(sigsOut), sigStride, count*sigStride)
	}
	if msgLens != nil && len(msgLens) != count {
		return fmt.Errorf(
			"quantumvm: MLDSASignBatch: msgLens length %d != count %d",
			len(msgLens), count)
	}
	if sigLensOut != nil && len(sigLensOut) != count {
		return fmt.Errorf(
			"quantumvm: MLDSASignBatch: sigLensOut length %d != count %d",
			len(sigLensOut), count)
	}
	if b == nil || b.ctx == nil || b.desc == nil {
		return ErrGPUNotAvailable
	}

	// Validate the msgs pool is large enough to cover the per-element
	// lengths. NULL msgLens uses msgWidthHint uniformly — same check
	// against count * msgWidthHint.
	var total int
	if msgLens != nil {
		for i := 0; i < count; i++ {
			if msgLens[i] < 0 {
				return fmt.Errorf(
					"quantumvm: MLDSASignBatch[%d]: negative msgLen %d",
					i, msgLens[i])
			}
			total += msgLens[i]
		}
	} else {
		total = int(msgWidthHint) * count
	}
	if len(msgs) < total {
		return fmt.Errorf(
			"quantumvm: MLDSASignBatch: msgs pool len %d < total %d",
			len(msgs), total)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(&skeys[0])
	if total > 0 {
		pinner.Pin(&msgs[0])
	}
	pinner.Pin(&sigsOut[0])
	var lensBuf []C.size_t
	var lensPtr *C.size_t
	if msgLens != nil {
		lensBuf = make([]C.size_t, count)
		for i := 0; i < count; i++ {
			lensBuf[i] = C.size_t(msgLens[i])
		}
		lensPtr = (*C.size_t)(unsafe.Pointer(&lensBuf[0]))
	}
	var sigLensPtr *C.uint32_t
	if sigLensOut != nil {
		sigLensPtr = (*C.uint32_t)(unsafe.Pointer(&sigLensOut[0]))
	}
	var msgsPtr *C.uint8_t
	if total > 0 {
		msgsPtr = (*C.uint8_t)(unsafe.Pointer(&msgs[0]))
	}

	rc := C.qvm_op_mldsa_sign(
		b.desc.vtbl,
		b.ctx,
		(*C.uint8_t)(unsafe.Pointer(&skeys[0])),
		C.size_t(skStride),
		msgsPtr,
		lensPtr,
		C.uint32_t(msgWidthHint),
		C.size_t(count),
		(*C.uint8_t)(unsafe.Pointer(&sigsOut[0])),
		sigLensPtr,
	)
	runtime.KeepAlive(lensBuf)

	if rc != 0 {
		return mapBackendError(int(rc), "op_mldsa_sign_batch")
	}
	return nil
}

// SLHDSAVerifyBatch dispatches the SHAKE-128f or SHAKE-192f variant of
// op_slhdsa_verify_batch from the loaded vtbl. The 10 other FIPS 205
// variants are not exposed at v14 — they return ErrGPUNotAvailable.
func (b *gpuBackend) SLHDSAVerifyBatch(
	variant SLHDSAVariant,
	pubkeys [][]byte,
	messages [][]byte,
	msgLens []int,
	signatures [][]byte,
	results []bool,
) error {
	is128f := variant == SLHDSAShake128f
	is192f := variant == SLHDSAShake192f
	if !is128f && !is192f {
		return ErrGPUNotAvailable
	}
	n := len(pubkeys)
	if n == 0 {
		return nil
	}
	if len(messages) != n || len(signatures) != n || len(results) != n {
		return fmt.Errorf(
			"quantumvm: SLHDSAVerifyBatch: length mismatch (pubkeys=%d messages=%d signatures=%d results=%d)",
			n, len(messages), len(signatures), len(results))
	}
	if msgLens != nil && len(msgLens) != n {
		return fmt.Errorf(
			"quantumvm: SLHDSAVerifyBatch: msgLens length %d != batch %d",
			len(msgLens), n)
	}
	pkSize := variant.PublicKeySize()
	sigSize := variant.SignatureSize()
	if b == nil || b.ctx == nil || b.desc == nil {
		return ErrGPUNotAvailable
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	var pinner runtime.Pinner
	defer pinner.Unpin()
	pkPtrs := make([]*C.uint8_t, n)
	msgPtrs := make([]*C.uint8_t, n)
	sigPtrs := make([]*C.uint8_t, n)
	lensBuf := make([]C.size_t, n)
	for i := 0; i < n; i++ {
		if len(pubkeys[i]) != pkSize {
			return fmt.Errorf(
				"quantumvm: SLHDSAVerifyBatch[%d]: pubkey len %d != %d",
				i, len(pubkeys[i]), pkSize)
		}
		if len(signatures[i]) != sigSize {
			return fmt.Errorf(
				"quantumvm: SLHDSAVerifyBatch[%d]: signature len %d != %d",
				i, len(signatures[i]), sigSize)
		}
		pinner.Pin(&pubkeys[i][0])
		pkPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&pubkeys[i][0]))
		if len(messages[i]) > 0 {
			pinner.Pin(&messages[i][0])
			msgPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&messages[i][0]))
		}
		pinner.Pin(&signatures[i][0])
		sigPtrs[i] = (*C.uint8_t)(unsafe.Pointer(&signatures[i][0]))
		// SLH-DSA has no msg_width_hint surface — msg_lens is
		// mandatory at the vtbl boundary. Fill lensBuf from either
		// msgLens or the message slice length.
		if msgLens != nil {
			if msgLens[i] < 0 {
				return fmt.Errorf(
					"quantumvm: SLHDSAVerifyBatch[%d]: negative msgLen %d",
					i, msgLens[i])
			}
			lensBuf[i] = C.size_t(msgLens[i])
		} else {
			lensBuf[i] = C.size_t(len(messages[i]))
		}
	}
	cresults := make([]C.bool, n)
	pkPtrsPtr := (**C.uint8_t)(unsafe.Pointer(&pkPtrs[0]))
	msgPtrsPtr := (**C.uint8_t)(unsafe.Pointer(&msgPtrs[0]))
	sigPtrsPtr := (**C.uint8_t)(unsafe.Pointer(&sigPtrs[0]))
	lensPtr := (*C.size_t)(unsafe.Pointer(&lensBuf[0]))

	var rc C.int
	if is128f {
		rc = C.qvm_op_slhdsa_verify_128f(
			b.desc.vtbl,
			b.ctx,
			pkPtrsPtr,
			msgPtrsPtr,
			lensPtr,
			sigPtrsPtr,
			(*C.bool)(unsafe.Pointer(&cresults[0])),
			C.size_t(n),
		)
	} else {
		rc = C.qvm_op_slhdsa_verify_192f(
			b.desc.vtbl,
			b.ctx,
			pkPtrsPtr,
			msgPtrsPtr,
			lensPtr,
			sigPtrsPtr,
			(*C.bool)(unsafe.Pointer(&cresults[0])),
			C.size_t(n),
		)
	}
	runtime.KeepAlive(pkPtrs)
	runtime.KeepAlive(msgPtrs)
	runtime.KeepAlive(sigPtrs)
	runtime.KeepAlive(lensBuf)
	runtime.KeepAlive(cresults)

	if rc != 0 {
		return mapBackendError(int(rc), "op_slhdsa_verify_batch")
	}
	for i := 0; i < n; i++ {
		results[i] = bool(cresults[i])
	}
	return nil
}

// mapBackendError translates a LuxBackendError code to a Go error.
// NOT_SUPPORTED (3) maps to the package sentinel so callers can route
// to the CPU oracle via errors.Is. Other non-zero codes return a
// formatted error including the numeric code for diagnostics.
func mapBackendError(rc int, op string) error {
	switch rc {
	case 0:
		return nil
	case int(C.LUX_BACKEND_ERROR_NOT_SUPPORTED):
		return ErrGPUNotAvailable
	case int(C.LUX_BACKEND_ERROR_INVALID_ARGUMENT):
		return fmt.Errorf("quantumvm: %s: invalid argument (rc=1)", op)
	case int(C.LUX_BACKEND_ERROR_OUT_OF_MEMORY):
		return fmt.Errorf("quantumvm: %s: out of memory (rc=2)", op)
	case int(C.LUX_BACKEND_ERROR_DEVICE_LOST):
		return fmt.Errorf("quantumvm: %s: device lost (rc=4)", op)
	case int(C.LUX_BACKEND_ERROR_INTERNAL):
		return fmt.Errorf("quantumvm: %s: internal error (rc=5)", op)
	default:
		return fmt.Errorf("quantumvm: %s: rc=%d", op, rc)
	}
}
