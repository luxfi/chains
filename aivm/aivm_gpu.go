//go:build cgo

// Package aivm GPU backend — runtime-loaded plugin bridge.
//
// Unlike cevm/cevm_cgo.go (which links libevm + libevm-gpu via pkg-config),
// AIVM resolves its GPU backend at PROCESS START via dlopen/dlsym against
// the lux-gpu-kernels plugin DSOs. This keeps the chains module compilable
// without the lux GPU plugin present in the build tree — the plugin
// is fully optional.
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
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// ErrGPUNotAvailable is returned by every GPUBackend method when no plugin
// was loadable at init time. Callers fall through to the existing Go path.
var ErrGPUNotAvailable = errors.New("aivm: no GPU plugin available")

// BackendKind identifies which lux-gpu-kernels plugin satisfied the
// runtime dlopen probe. AvailableNone is the sentinel "fall through to Go".
type BackendKind uint8

const (
	AvailableNone   BackendKind = 0
	AvailableCUDA   BackendKind = 1
	AvailableHIP    BackendKind = 2
	AvailableMetal  BackendKind = 3
	AvailableVulkan BackendKind = 4
	AvailableWebGPU BackendKind = 5
)

// String returns the human-readable name for the backend kind.
func (k BackendKind) String() string {
	switch k {
	case AvailableNone:
		return "none"
	case AvailableCUDA:
		return "cuda"
	case AvailableHIP:
		return "hip"
	case AvailableMetal:
		return "metal"
	case AvailableVulkan:
		return "vulkan"
	case AvailableWebGPU:
		return "webgpu"
	default:
		return fmt.Sprintf("backend(%d)", uint8(k))
	}
}

// =============================================================================
// Layout-drift guards — match ops/aivm/cuda/aivm_kernels_common.cuh exactly.
//
// The struct bytes Go hands to C MUST match the on-disk layout file at
// the GPU plugin ops/aivm/op.yaml — every kernel reads them
// via reinterpret_cast. A silent layout shift produces consensus-divergent
// state roots. init() refuses to load if any size drifts.
// =============================================================================

// Attestation mirrors aivm::cuda::Attestation (144 bytes).
type Attestation struct {
	TEEQuoteDigest [32]byte
	Measurement    [32]byte
	AttestingKey   [48]byte
	ExpiryNS       uint64
	Kind           uint32
	EvidenceOffset uint32
	EvidenceLen    uint32
	Status         uint32
	Occupied       uint32
	_pad0          uint32
}

// ModelRegistryEntry mirrors aivm::cuda::ModelRegistryEntry (160 bytes).
type ModelRegistryEntry struct {
	ModelRoot      [32]byte
	WeightHash     [32]byte
	LicenseRoot    [32]byte
	OwnerAddr      [20]byte
	_pad0          uint32
	Version        uint64
	ParameterCount uint64
	Modality       uint32
	Occupied       uint32
	_pad1          uint64
	_pad2          uint64
}

// AuditAnchor mirrors aivm::cuda::AuditAnchor (128 bytes).
type AuditAnchor struct {
	CommitRoot                [32]byte
	ParentRoot                [32]byte
	ValidatorSetRootAtCommit  [32]byte
	Height                    uint64
	TimestampNS               uint64
	Occupied                  uint32
	_pad0                     uint32
	_pad1                     uint64
}

// AIVMEpochState mirrors aivm::cuda::AIVMEpochState (160 bytes).
type AIVMEpochState struct {
	CurrentEpoch             uint64
	NextEpochHeight          uint64
	TotalActiveAttestations  uint64
	ActiveModelCount         uint32
	ExpiredAttestationCount  uint32
	AttestationRoot          [32]byte
	ModelRegistryRoot        [32]byte
	AuditRoot                [32]byte
	AIVMStateRoot            [32]byte
}

// AIVMRoundDescriptor mirrors aivm::cuda::AIVMRoundDescriptor (96 bytes).
type AIVMRoundDescriptor struct {
	ChainID            uint64
	Round              uint64
	TimestampNS        uint64
	Epoch              uint64
	Mode               uint32
	AttestationOpCount uint32
	ModelOpCount       uint32
	AnchorOpCount      uint32
	ClosingFlag        uint32
	_pad0              uint32
	_pad1              uint64
	ParentAIVMRoot     [32]byte
}

// AttestationOp mirrors aivm::cuda::AttestationOp (144 bytes).
type AttestationOp struct {
	TEEQuoteDigest [32]byte
	Measurement    [32]byte
	AttestingKey   [48]byte
	ExpiryNS       uint64
	Kind           uint32
	EvidenceOffset uint32
	EvidenceLen    uint32
	Epoch          uint32
	_pad0          uint32
	_pad1          uint32
}

// ModelOp mirrors aivm::cuda::ModelOp (160 bytes).
type ModelOp struct {
	ModelRoot      [32]byte
	WeightHash     [32]byte
	LicenseRoot    [32]byte
	OwnerAddr      [20]byte
	_pad0          uint32
	ParameterCount uint64
	Modality       uint32
	Kind           uint32
	Epoch          uint32
	_pad1          uint32
	_pad2          uint64
	_pad3          uint64
}

// AnchorOp mirrors aivm::cuda::AnchorOp (128 bytes).
type AnchorOp struct {
	CommitRoot                [32]byte
	ParentRoot                [32]byte
	ValidatorSetRootAtCommit  [32]byte
	Height                    uint64
	TimestampNS               uint64
	Epoch                     uint32
	_pad0                     uint32
	_pad1                     uint64
}

// AIVMTransitionResult mirrors aivm::cuda::AIVMTransitionResult (192 bytes).
type AIVMTransitionResult struct {
	Status                uint32
	AttestationApplyCount uint32
	ModelApplyCount       uint32
	AnchorApplyCount      uint32
	ActiveAttestations    uint32
	ExpiredAttestations   uint32
	ModelCount            uint32
	AnchorCount           uint32
	Epoch                 uint64
	TotalModels           uint64
	TotalAnchors          uint64
	_pad0                 uint64
	AttestationRoot       [32]byte
	ModelRegistryRoot     [32]byte
	AuditRoot             [32]byte
	AIVMStateRoot         [32]byte
}

// InferenceWeights mirrors aivm::cuda::InferenceWeights (672 bytes).
// 32→16→1 quantized classifier weights.
const (
	InferenceInDim  = 32
	InferenceHidden = 16
	InferenceOutDim = 1
)

type InferenceWeights struct {
	W1              [InferenceInDim * InferenceHidden]int8
	B1              [InferenceHidden]int32
	W2              [InferenceHidden * InferenceOutDim]int8
	B2              [InferenceOutDim]int32
	Shift1          int8
	Shift2          int8
	_pad0           [2]uint8
	ModelHash       [32]byte
	ModelConfigHash [32]byte
	_pad1           [8]uint8
}

// InferenceOp mirrors aivm::cuda::InferenceOp (144 bytes).
type InferenceOp struct {
	ModelHash      [32]byte
	PolicyHash     [32]byte
	Salt           [32]byte
	Mode           uint32
	InputOffset    uint32
	InputLen       uint32
	OutputOffset   uint32
	OutputCapacity uint32
	_pad0          uint32
	RoundID        uint64
	TimestampNS    uint64
	_pad1          [8]uint8
}

// InferenceResult mirrors aivm::cuda::InferenceResult (112 bytes).
type InferenceResult struct {
	Status            uint32
	OutputLen         uint32
	InputCommitment   [32]byte
	OutputCommitment  [32]byte
	AttestationRoot   [32]byte
	_pad0             [8]uint8
}

// ProofVerifyOp mirrors aivm::cuda::ProofVerifyOp (240 bytes).
type ProofVerifyOp struct {
	Measurement  [32]byte
	AttestingKey [48]byte
	Signature    [96]byte
	MessageHash  [32]byte
	ExpiryNS     uint64
	TimestampNS  uint64
	Kind         uint32
	Nonce        uint32
	_pad0        [8]uint8
}

// ProofVerifyResult mirrors aivm::cuda::ProofVerifyResult (48 bytes).
type ProofVerifyResult struct {
	Status      uint32
	Kind        uint32
	BindingHash [32]byte
	_pad0       [8]uint8
}

// Layout-drift guard — refuse to load if any struct size disagrees with
// the on-device layout in aivm_kernels_common.cuh / aivm_gpu_layout.hpp.
// Any disagreement here means Go would write garbage at the C boundary.
func init() {
	type sz struct {
		name string
		got  uintptr
		want uintptr
	}
	checks := []sz{
		{"Attestation", unsafe.Sizeof(Attestation{}), 144},
		{"ModelRegistryEntry", unsafe.Sizeof(ModelRegistryEntry{}), 160},
		{"AuditAnchor", unsafe.Sizeof(AuditAnchor{}), 128},
		{"AIVMEpochState", unsafe.Sizeof(AIVMEpochState{}), 160},
		{"AIVMRoundDescriptor", unsafe.Sizeof(AIVMRoundDescriptor{}), 96},
		{"AttestationOp", unsafe.Sizeof(AttestationOp{}), 144},
		{"ModelOp", unsafe.Sizeof(ModelOp{}), 160},
		{"AnchorOp", unsafe.Sizeof(AnchorOp{}), 128},
		{"AIVMTransitionResult", unsafe.Sizeof(AIVMTransitionResult{}), 192},
		{"InferenceWeights", unsafe.Sizeof(InferenceWeights{}), 672},
		{"InferenceOp", unsafe.Sizeof(InferenceOp{}), 144},
		{"InferenceResult", unsafe.Sizeof(InferenceResult{}), 112},
		{"ProofVerifyOp", unsafe.Sizeof(ProofVerifyOp{}), 240},
		{"ProofVerifyResult", unsafe.Sizeof(ProofVerifyResult{}), 48},
	}
	for _, c := range checks {
		if c.got != c.want {
			panic(fmt.Sprintf(
				"aivm: layout drift — Go sizeof(%s)=%d but on-device layout=%d. "+
					"Re-sync chains/aivm/aivm_gpu.go against "+
					"the GPU plugin ops/aivm/cuda/aivm_kernels_common.cuh.",
				c.name, c.got, c.want))
		}
	}
}

// =============================================================================
// GPUBackend — handle to an open plugin DSO + its six resolved launchers.
// =============================================================================

// GPUBackend is a handle to an open lux-gpu-kernels plugin. Zero value is
// usable (every method returns ErrGPUNotAvailable). The active backend is
// stored at package level by backend.go's init(); call ActiveGPUBackend()
// to retrieve it.
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

// AttestationApply runs the GPU attestation kernel. `attestations` is read+
// written in place; `appliedOut` is the count of successfully applied ops.
func (b *GPUBackend) AttestationApply(
	desc *AIVMRoundDescriptor,
	ops []AttestationOp,
	attestations []Attestation,
	appliedOut *uint32,
) error {
	if !b.IsAvailable() {
		return ErrGPUNotAvailable
	}
	if desc == nil || appliedOut == nil {
		return errors.New("aivm: AttestationApply: nil desc or appliedOut")
	}
	if len(attestations) == 0 {
		return errors.New("aivm: AttestationApply: empty attestations table")
	}

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
	if rc != 0 {
		return fmt.Errorf("aivm: %s_aivm_attestation_apply returned %d", b.kind, int(rc))
	}
	return nil
}

// ProvenanceApply runs the GPU provenance (model-registry) kernel.
func (b *GPUBackend) ProvenanceApply(
	desc *AIVMRoundDescriptor,
	ops []ModelOp,
	models []ModelRegistryEntry,
	appliedOut *uint32,
) error {
	if !b.IsAvailable() {
		return ErrGPUNotAvailable
	}
	if desc == nil || appliedOut == nil {
		return errors.New("aivm: ProvenanceApply: nil desc or appliedOut")
	}
	if len(models) == 0 {
		return errors.New("aivm: ProvenanceApply: empty models table")
	}

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
	if rc != 0 {
		return fmt.Errorf("aivm: %s_aivm_provenance_apply returned %d", b.kind, int(rc))
	}
	return nil
}

// AnchorApply runs the GPU audit-anchor kernel.
func (b *GPUBackend) AnchorApply(
	desc *AIVMRoundDescriptor,
	ops []AnchorOp,
	anchors []AuditAnchor,
	appliedOut *uint32,
) error {
	if !b.IsAvailable() {
		return ErrGPUNotAvailable
	}
	if desc == nil || appliedOut == nil {
		return errors.New("aivm: AnchorApply: nil desc or appliedOut")
	}
	if len(anchors) == 0 {
		return errors.New("aivm: AnchorApply: empty anchors table")
	}

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
	if rc != 0 {
		return fmt.Errorf("aivm: %s_aivm_anchor_apply returned %d", b.kind, int(rc))
	}
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
	if !b.IsAvailable() {
		return ErrGPUNotAvailable
	}
	if desc == nil || epoch == nil || result == nil {
		return errors.New("aivm: EpochTransition: nil desc, epoch, or result")
	}
	if len(attestations) == 0 {
		return errors.New("aivm: EpochTransition: empty attestations table")
	}

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
	if rc != 0 {
		return fmt.Errorf("aivm: %s_aivm_epoch_transition returned %d", b.kind, int(rc))
	}
	return nil
}

// InferenceStep runs the deterministic int8 32→16→1 inference kernel.
// `batchInputs` is op_count × 32 bytes of input rows; `batchOutputs` receives
// op_count × 1 byte of output values. Determinism contract: byte-equal to
// the CPU reference + every other backend.
func (b *GPUBackend) InferenceStep(
	weights *InferenceWeights,
	ops []InferenceOp,
	batchInputs []int8,
	batchOutputs []int8,
	results []InferenceResult,
) error {
	if !b.IsAvailable() {
		return ErrGPUNotAvailable
	}
	if weights == nil {
		return errors.New("aivm: InferenceStep: nil weights")
	}
	if len(ops) == 0 {
		return nil // no-op
	}
	if len(results) != len(ops) {
		return fmt.Errorf("aivm: InferenceStep: results length %d != ops length %d",
			len(results), len(ops))
	}
	if len(batchInputs) != len(ops)*InferenceInDim {
		return fmt.Errorf("aivm: InferenceStep: batchInputs length %d != ops*%d (=%d)",
			len(batchInputs), InferenceInDim, len(ops)*InferenceInDim)
	}
	if len(batchOutputs) != len(ops)*InferenceOutDim {
		return fmt.Errorf("aivm: InferenceStep: batchOutputs length %d != ops*%d (=%d)",
			len(batchOutputs), InferenceOutDim, len(ops)*InferenceOutDim)
	}

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
	if rc != 0 {
		return fmt.Errorf("aivm: %s_aivm_inference_step returned %d", b.kind, int(rc))
	}
	return nil
}

// ProofVerify runs the TEE-attestation envelope check kernel.
func (b *GPUBackend) ProofVerify(
	ops []ProofVerifyOp,
	results []ProofVerifyResult,
) error {
	if !b.IsAvailable() {
		return ErrGPUNotAvailable
	}
	if len(ops) == 0 {
		return nil // no-op
	}
	if len(results) != len(ops) {
		return fmt.Errorf("aivm: ProofVerify: results length %d != ops length %d",
			len(results), len(ops))
	}

	rc := C.call_aivm_proof_verify(
		b.fnProof,
		unsafe.Pointer(&ops[0]),
		unsafe.Pointer(&results[0]),
		C.uint32_t(len(ops)),
	)
	runtime.KeepAlive(ops)
	runtime.KeepAlive(results)
	if rc != 0 {
		return fmt.Errorf("aivm: %s_aivm_proof_verify returned %d", b.kind, int(rc))
	}
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
// vm.go's Accept() can opt into when ready. Returns ErrGPUNotAvailable
// if no backend is loaded — caller falls through to the CPU Go path.
func gpuTransitionApply(
	desc *AIVMRoundDescriptor,
	attestations []Attestation,
	models []ModelRegistryEntry,
	anchors []AuditAnchor,
	epoch *AIVMEpochState,
	result *AIVMTransitionResult,
) error {
	b := ActiveGPUBackend()
	if !b.IsAvailable() {
		return ErrGPUNotAvailable
	}
	return b.EpochTransition(desc, attestations, models, anchors, epoch, result)
}
