//go:build cgo

// Package aivm GPU backend — runtime-loaded plugin bridge with CPU
// fall-through.
//
// Two pieces:
//
//  1. dlopen/dlsym against a lux-gpu-kernels plugin DSO at process start
//     (backend.go handles the probe). Resolves six host launchers per
//     backend (cuda / hip / metal / vulkan / webgpu).
//
//  2. Each public method tries the GPU plugin first; on
//     ErrGPUNotAvailable (no plugin loaded) OR any plugin-side error
//     (rc != 0) it falls through to the canonical pure-Go reference
//     defined in aivm_gpu_cpu.go. GPU is a strict positive overlay —
//     the CPU answer is the canonical truth. Both build modes produce
//     byte-identical output on every fixture.
//
// Layout structs (Attestation, ModelRegistryEntry, …), BackendKind /
// Mode enums, ErrGPUNotAvailable, and the init() layout-drift guard
// all live in the build-tag-free aivm_gpu_types.go so both cgo and
// !cgo share ONE copy. The pure-Go reference implementations of the
// six kernels live in aivm_gpu_cpu.go (also no build tag).
//
// Lookup order (handled by backend.go):
//
//	libluxgpu_backend_cuda.so       (Linux x86_64 + NVIDIA)
//	libluxgpu_backend_hip.so        (Linux x86_64 + AMD ROCm)
//	libluxgpu_backend_metal.dylib   (macOS Apple Silicon / Intel)
//	libluxgpu_backend_vulkan.so/.dylib   (any Vulkan ICD)
//	libluxgpu_backend_webgpu.so/.dylib   (Dawn / wgpu-native)
//
// Each plugin exports six extern "C" host launchers per backend:
//
//	lux_<backend>_aivm_attestation_apply
//	lux_<backend>_aivm_provenance_apply
//	lux_<backend>_aivm_anchor_apply
//	lux_<backend>_aivm_epoch_transition
//	lux_<backend>_aivm_inference_step
//	lux_<backend>_aivm_proof_verify
//
// Struct layout matches ops/aivm/cuda/aivm_kernels_common.cuh byte-for-byte
// (asserted by init()). Pointer ABI is HOST pointers — the launcher does
// H2D-upload / dispatch / D2H-download internally.
package aivm

/*
#cgo darwin LDFLAGS: -ldl
#cgo linux  LDFLAGS: -ldl

#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>

// Six host-launcher trampolines — invoked by Go via cgo. The function
// pointer is opaque (void*); the cgo bridge casts it to the expected
// C signature and forwards arguments.
//
// All six launcher prototypes are identical across backends (cuda / hip /
// metal / vulkan / webgpu). Argument pointers are HOST pointers; the
// last `void*` is a "stream" handle that is always nullptr on the GPU
// kernels that don't expose CUDA streams (i.e., all of them on the
// AIVM path today).

typedef int (*aivm_attestation_fn)(
    const void* desc,
    const void* ops,
    void*       attestations,
    void*       applied_out,
    uint32_t    att_count,
    void*       stream);

typedef int (*aivm_provenance_fn)(
    const void* desc,
    const void* ops,
    void*       models,
    void*       applied_out,
    uint32_t    model_count,
    void*       stream);

typedef int (*aivm_anchor_fn)(
    const void* desc,
    const void* ops,
    void*       anchors,
    void*       applied_out,
    uint32_t    anchor_count,
    void*       stream);

typedef int (*aivm_epoch_fn)(
    const void* desc,
    void*       attestations,
    void*       models,
    void*       anchors,
    void*       epoch,
    void*       result,
    uint32_t    att_count,
    uint32_t    model_count,
    uint32_t    anchor_count,
    void*       stream);

typedef int (*aivm_inference_fn)(
    const void* weights,
    const void* ops,
    const void* batch_inputs,
    void*       batch_outputs,
    void*       results,
    uint32_t    op_count,
    void*       stream);

typedef int (*aivm_proof_verify_fn)(
    const void* ops,
    void*       results,
    uint32_t    op_count,
    void*       stream);

static int call_aivm_attestation(void* fn, const void* desc, const void* ops,
                                 void* attestations, void* applied_out,
                                 uint32_t att_count) {
    return ((aivm_attestation_fn)fn)(desc, ops, attestations, applied_out,
                                      att_count, NULL);
}
static int call_aivm_provenance(void* fn, const void* desc, const void* ops,
                                void* models, void* applied_out,
                                uint32_t model_count) {
    return ((aivm_provenance_fn)fn)(desc, ops, models, applied_out,
                                     model_count, NULL);
}
static int call_aivm_anchor(void* fn, const void* desc, const void* ops,
                            void* anchors, void* applied_out,
                            uint32_t anchor_count) {
    return ((aivm_anchor_fn)fn)(desc, ops, anchors, applied_out,
                                 anchor_count, NULL);
}
static int call_aivm_epoch(void* fn, const void* desc, void* attestations,
                           void* models, void* anchors, void* epoch,
                           void* result, uint32_t att_count,
                           uint32_t model_count, uint32_t anchor_count) {
    return ((aivm_epoch_fn)fn)(desc, attestations, models, anchors, epoch,
                                result, att_count, model_count, anchor_count,
                                NULL);
}
static int call_aivm_inference(void* fn, const void* weights, const void* ops,
                                const void* batch_inputs, void* batch_outputs,
                                void* results, uint32_t op_count) {
    return ((aivm_inference_fn)fn)(weights, ops, batch_inputs, batch_outputs,
                                    results, op_count, NULL);
}
static int call_aivm_proof_verify(void* fn, const void* ops, void* results,
                                   uint32_t op_count) {
    return ((aivm_proof_verify_fn)fn)(ops, results, op_count, NULL);
}

// dlopen / dlsym wrappers — kept here so backend.go can stay pure Go.
static void* lux_dlopen(const char* path) {
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}
static void* lux_dlsym(void* handle, const char* sym) {
    return dlsym(handle, sym);
}
static const char* lux_dlerror() {
    return dlerror();
}
static void lux_dlclose(void* handle) {
    dlclose(handle);
}
*/
import "C"

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// =============================================================================
// GPUBackend — handle to an open plugin DSO + its six resolved launchers.
// =============================================================================

// GPUBackend is a handle to an open lux-gpu-kernels plugin. Zero value is
// usable (every method falls through to the canonical CPU reference in
// aivm_gpu_cpu.go). The active backend is stored at package level by
// backend.go's init(); call ActiveGPUBackend() to retrieve it.
type GPUBackend struct {
	mu        sync.Mutex
	kind      BackendKind
	handle    unsafe.Pointer // dlopen result
	path      string
	fnAttest  unsafe.Pointer
	fnProv    unsafe.Pointer
	fnAnchor  unsafe.Pointer
	fnEpoch   unsafe.Pointer
	fnInfer   unsafe.Pointer
	fnProof   unsafe.Pointer
}

// Kind returns which backend satisfied the dlopen probe.
func (b *GPUBackend) Kind() BackendKind {
	if b == nil {
		return AvailableNone
	}
	return b.kind
}

// Path returns the absolute path of the loaded plugin DSO.
func (b *GPUBackend) Path() string {
	if b == nil {
		return ""
	}
	return b.path
}

// IsAvailable reports whether the backend is loaded AND all six host
// launchers were successfully resolved. Used by vm.go's gpuAvailable().
func (b *GPUBackend) IsAvailable() bool {
	if b == nil || b.handle == nil {
		return false
	}
	return b.fnAttest != nil && b.fnProv != nil && b.fnAnchor != nil &&
		b.fnEpoch != nil && b.fnInfer != nil && b.fnProof != nil
}

// openGPUBackend attempts to dlopen `path` and dlsym the six host launchers
// for `kind`. Returns a fully-initialised *GPUBackend on success, or
// (nil, error) when either the dlopen or any dlsym fails.
//
// On dlsym failure the dlopened handle IS dlclose'd before returning so
// we never leak a half-bound plugin.
func openGPUBackend(kind BackendKind, path string) (*GPUBackend, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	// Clear any pending error so a stale dlerror() from a previous failed
	// dlsym doesn't get mis-attributed to this dlopen call.
	C.lux_dlerror()

	handle := C.lux_dlopen(cpath)
	if handle == nil {
		return nil, fmt.Errorf("aivm: dlopen(%s): %s", path, C.GoString(C.lux_dlerror()))
	}

	backendName := kind.String() // cuda / hip / metal / vulkan / webgpu

	resolve := func(suffix string) (unsafe.Pointer, error) {
		sym := fmt.Sprintf("lux_%s_aivm_%s", backendName, suffix)
		csym := C.CString(sym)
		defer C.free(unsafe.Pointer(csym))
		C.lux_dlerror()
		ptr := C.lux_dlsym(handle, csym)
		if ptr == nil {
			return nil, fmt.Errorf("aivm: dlsym(%s, %s): %s",
				path, sym, C.GoString(C.lux_dlerror()))
		}
		return ptr, nil
	}

	b := &GPUBackend{kind: kind, handle: handle, path: path}
	var err error
	if b.fnAttest, err = resolve("attestation_apply"); err != nil {
		C.lux_dlclose(handle)
		return nil, err
	}
	if b.fnProv, err = resolve("provenance_apply"); err != nil {
		C.lux_dlclose(handle)
		return nil, err
	}
	if b.fnAnchor, err = resolve("anchor_apply"); err != nil {
		C.lux_dlclose(handle)
		return nil, err
	}
	if b.fnEpoch, err = resolve("epoch_transition"); err != nil {
		C.lux_dlclose(handle)
		return nil, err
	}
	if b.fnInfer, err = resolve("inference_step"); err != nil {
		C.lux_dlclose(handle)
		return nil, err
	}
	if b.fnProof, err = resolve("proof_verify"); err != nil {
		C.lux_dlclose(handle)
		return nil, err
	}
	return b, nil
}

// Close releases the dlopen handle. Idempotent — safe to call on a nil
// receiver or an already-closed backend.
func (b *GPUBackend) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handle == nil {
		return nil
	}
	C.lux_dlclose(b.handle)
	b.handle = nil
	b.fnAttest = nil
	b.fnProv = nil
	b.fnAnchor = nil
	b.fnEpoch = nil
	b.fnInfer = nil
	b.fnProof = nil
	return nil
}

// =============================================================================
// Six host launcher wrappers. Each is a thin cgo trampoline that pins the
// Go-side slice memory (via runtime.KeepAlive) for the duration of the C
// call. The launchers ALWAYS take HOST pointers — no D2H/H2D contract on
// the Go side beyond a defer'd KeepAlive on every input/output buffer.
// =============================================================================

// AttestationApply runs the attestation kernel. Tries the GPU plugin
// first; falls through to attestationApplyCPU on missing plugin or any
// plugin-side error. Byte-equal to the C++ CPU oracle by construction.
func (b *GPUBackend) AttestationApply(
	desc *AIVMRoundDescriptor,
	ops []AttestationOp,
	attestations []Attestation,
	appliedOut *uint32,
) error {
	if desc == nil || appliedOut == nil {
		return errAttestationNilInput
	}
	if len(attestations) == 0 {
		return errAttestationEmptyTable
	}

	if b.IsAvailable() {
		var opsPtr unsafe.Pointer
		if len(ops) > 0 {
			opsPtr = unsafe.Pointer(&ops[0])
		}
		rc := C.call_aivm_attestation(
			b.fnAttest,
			unsafe.Pointer(desc),
			opsPtr,
			unsafe.Pointer(&attestations[0]),
			unsafe.Pointer(appliedOut),
			C.uint32_t(len(attestations)),
		)
		runtime.KeepAlive(desc)
		runtime.KeepAlive(ops)
		runtime.KeepAlive(attestations)
		runtime.KeepAlive(appliedOut)
		if rc == 0 {
			return nil
		}
		// Plugin-side error — fall through to the CPU reference. GPU is
		// a strict positive overlay; the CPU answer is canonical.
	}
	attestationApplyCPU(desc, ops, attestations, appliedOut)
	return nil
}

// ProvenanceApply runs the provenance (model-registry) kernel. Tries
// the GPU plugin first; falls through to provenanceApplyCPU on missing
// plugin or any plugin-side error.
func (b *GPUBackend) ProvenanceApply(
	desc *AIVMRoundDescriptor,
	ops []ModelOp,
	models []ModelRegistryEntry,
	appliedOut *uint32,
) error {
	if desc == nil || appliedOut == nil {
		return errProvenanceNilInput
	}
	if len(models) == 0 {
		return errProvenanceEmptyTable
	}

	if b.IsAvailable() {
		var opsPtr unsafe.Pointer
		if len(ops) > 0 {
			opsPtr = unsafe.Pointer(&ops[0])
		}
		rc := C.call_aivm_provenance(
			b.fnProv,
			unsafe.Pointer(desc),
			opsPtr,
			unsafe.Pointer(&models[0]),
			unsafe.Pointer(appliedOut),
			C.uint32_t(len(models)),
		)
		runtime.KeepAlive(desc)
		runtime.KeepAlive(ops)
		runtime.KeepAlive(models)
		runtime.KeepAlive(appliedOut)
		if rc == 0 {
			return nil
		}
	}
	provenanceApplyCPU(desc, ops, models, appliedOut)
	return nil
}

// AnchorApply runs the audit-anchor kernel. Tries the GPU plugin
// first; falls through to anchorApplyCPU on missing plugin or any
// plugin-side error.
func (b *GPUBackend) AnchorApply(
	desc *AIVMRoundDescriptor,
	ops []AnchorOp,
	anchors []AuditAnchor,
	appliedOut *uint32,
) error {
	if desc == nil || appliedOut == nil {
		return errAnchorNilInput
	}
	if len(anchors) == 0 {
		return errAnchorEmptyTable
	}

	if b.IsAvailable() {
		var opsPtr unsafe.Pointer
		if len(ops) > 0 {
			opsPtr = unsafe.Pointer(&ops[0])
		}
		rc := C.call_aivm_anchor(
			b.fnAnchor,
			unsafe.Pointer(desc),
			opsPtr,
			unsafe.Pointer(&anchors[0]),
			unsafe.Pointer(appliedOut),
			C.uint32_t(len(anchors)),
		)
		runtime.KeepAlive(desc)
		runtime.KeepAlive(ops)
		runtime.KeepAlive(anchors)
		runtime.KeepAlive(appliedOut)
		if rc == 0 {
			return nil
		}
	}
	anchorApplyCPU(desc, ops, anchors, appliedOut)
	return nil
}

// EpochTransition runs the GPU epoch-finalisation kernel. Composes per-epoch
// attestation_root / model_registry_root / audit_root / aivm_state_root.
func (b *GPUBackend) EpochTransition(
	desc *AIVMRoundDescriptor,
	attestations []Attestation,
	models []ModelRegistryEntry,
	anchors []AuditAnchor,
	epoch *AIVMEpochState,
	result *AIVMTransitionResult,
) error {
	if desc == nil || epoch == nil || result == nil {
		return errEpochNilInput
	}
	if len(attestations) == 0 {
		return errEpochEmptyTable
	}

	if b.IsAvailable() {
		var modelsPtr, anchorsPtr unsafe.Pointer
		if len(models) > 0 {
			modelsPtr = unsafe.Pointer(&models[0])
		}
		if len(anchors) > 0 {
			anchorsPtr = unsafe.Pointer(&anchors[0])
		}
		rc := C.call_aivm_epoch(
			b.fnEpoch,
			unsafe.Pointer(desc),
			unsafe.Pointer(&attestations[0]),
			modelsPtr,
			anchorsPtr,
			unsafe.Pointer(epoch),
			unsafe.Pointer(result),
			C.uint32_t(len(attestations)),
			C.uint32_t(len(models)),
			C.uint32_t(len(anchors)),
		)
		runtime.KeepAlive(desc)
		runtime.KeepAlive(attestations)
		runtime.KeepAlive(models)
		runtime.KeepAlive(anchors)
		runtime.KeepAlive(epoch)
		runtime.KeepAlive(result)
		if rc == 0 {
			return nil
		}
	}
	epochTransitionCPU(desc, attestations, models, anchors, epoch, result)
	return nil
}

// InferenceStep runs the deterministic int8 32→16→1 inference kernel.
// `batchInputs` is op_count × 32 bytes of input rows; `batchOutputs`
// receives op_count × 1 byte of output values. Tries the GPU plugin
// first; falls through to inferenceStepCPU on missing plugin or any
// plugin-side error. Byte-equal across CPU + every GPU backend.
func (b *GPUBackend) InferenceStep(
	weights *InferenceWeights,
	ops []InferenceOp,
	batchInputs []int8,
	batchOutputs []int8,
	results []InferenceResult,
) error {
	if weights == nil {
		return errInferenceNilWeights
	}
	if len(ops) == 0 {
		return nil // no-op
	}
	if len(results) != len(ops) {
		return errInferenceLenMismatchResults
	}
	if len(batchInputs) != len(ops)*InferenceInDim {
		return errInferenceLenMismatchInputs
	}
	if len(batchOutputs) != len(ops)*InferenceOutDim {
		return errInferenceLenMismatchOutputs
	}

	if b.IsAvailable() {
		rc := C.call_aivm_inference(
			b.fnInfer,
			unsafe.Pointer(weights),
			unsafe.Pointer(&ops[0]),
			unsafe.Pointer(&batchInputs[0]),
			unsafe.Pointer(&batchOutputs[0]),
			unsafe.Pointer(&results[0]),
			C.uint32_t(len(ops)),
		)
		runtime.KeepAlive(weights)
		runtime.KeepAlive(ops)
		runtime.KeepAlive(batchInputs)
		runtime.KeepAlive(batchOutputs)
		runtime.KeepAlive(results)
		if rc == 0 {
			return nil
		}
	}
	inferenceStepCPU(weights, ops, batchInputs, batchOutputs, results)
	return nil
}

// ProofVerify runs the TEE-attestation envelope check kernel. Tries
// the GPU plugin first; falls through to proofVerifyCPU on missing
// plugin or any plugin-side error.
func (b *GPUBackend) ProofVerify(
	ops []ProofVerifyOp,
	results []ProofVerifyResult,
) error {
	if len(ops) == 0 {
		return nil // no-op
	}
	if len(results) != len(ops) {
		return errProofVerifyLenMismatch
	}

	if b.IsAvailable() {
		rc := C.call_aivm_proof_verify(
			b.fnProof,
			unsafe.Pointer(&ops[0]),
			unsafe.Pointer(&results[0]),
			C.uint32_t(len(ops)),
		)
		runtime.KeepAlive(ops)
		runtime.KeepAlive(results)
		if rc == 0 {
			return nil
		}
	}
	proofVerifyCPU(ops, results)
	return nil
}

// =============================================================================
// vm.go opt-in hooks. Decomplected: vm.go calls these instead of reaching
// into the GPU machinery; the GPU implementation lives behind these two
// thin shims.
// =============================================================================

// gpuAvailable reports whether the package-level backend is loaded and
// ready. vm.go's Build/Verify/Accept paths can check this before opting
// into a GPU transition.
func gpuAvailable() bool {
	return ActiveGPUBackend().IsAvailable()
}

// gpuTransitionApply is a one-call wrapper around EpochTransition that
// vm.go's Accept() can opt into. Now that EpochTransition itself falls
// through to the CPU reference on plugin error, this never returns
// ErrGPUNotAvailable; the caller always gets a correct answer.
func gpuTransitionApply(
	desc *AIVMRoundDescriptor,
	attestations []Attestation,
	models []ModelRegistryEntry,
	anchors []AuditAnchor,
	epoch *AIVMEpochState,
	result *AIVMTransitionResult,
) error {
	return ActiveGPUBackend().EpochTransition(desc, attestations, models, anchors, epoch, result)
}
