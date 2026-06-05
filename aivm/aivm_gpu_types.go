// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// aivm_gpu_types.go — shared declarations for the AIVM GPU bridge.
//
// Built unconditionally under both `cgo` and `!cgo`. Every type and
// constant here is the ONE-and-ONLY copy used by:
//
//   - aivm_gpu.go         (cgo plugin bridge with fall-through to CPU)
//   - aivm_gpu_nocgo.go   (CPU-only bridge: no plugin to call)
//   - aivm_gpu_cpu.go     (pure-Go reference, the canonical CPU oracle)
//
// Layout structs MUST match the on-device layouts in
// ~/work/lux-private/gpu-kernels/ops/aivm/cuda/aivm_kernels_common.cuh
// byte-for-byte. A drift would make the same input produce different
// state roots on Go-CPU vs the GPU plugin — consensus-divergent.
// init() refuses to load on any size mismatch (the runtime guard).

package aivm

import (
	"errors"
	"fmt"
	"unsafe"
)

// ErrGPUNotAvailable signals "no GPU plugin loaded". Under cgo it surfaces
// when the dlopen probe at init() found nothing; under nocgo it is never
// returned from the public bridge methods (they always run the CPU path
// instead). Kept exported so external callers can compare against it
// without caring which build mode is active.
var ErrGPUNotAvailable = errors.New("aivm: no GPU plugin available")

// =============================================================================
// Argument-validation errors — surfaced by the bridge methods on BOTH
// build modes when the caller passes a nil pointer, empty arena, or a
// length-mismatched slice. Kept as package-level vars so the same error
// instance is returned regardless of which path runs.
// =============================================================================

var (
	errAttestationNilInput   = errors.New("aivm: AttestationApply: nil desc or appliedOut")
	errAttestationEmptyTable = errors.New("aivm: AttestationApply: empty attestations table")

	errProvenanceNilInput   = errors.New("aivm: ProvenanceApply: nil desc or appliedOut")
	errProvenanceEmptyTable = errors.New("aivm: ProvenanceApply: empty models table")

	errAnchorNilInput   = errors.New("aivm: AnchorApply: nil desc or appliedOut")
	errAnchorEmptyTable = errors.New("aivm: AnchorApply: empty anchors table")

	errEpochNilInput   = errors.New("aivm: EpochTransition: nil desc, epoch, or result")
	errEpochEmptyTable = errors.New("aivm: EpochTransition: empty attestations table")

	errInferenceNilWeights         = errors.New("aivm: InferenceStep: nil weights")
	errInferenceLenMismatchResults = errors.New("aivm: InferenceStep: results length != ops length")
	errInferenceLenMismatchInputs  = errors.New("aivm: InferenceStep: batchInputs length != ops*InferenceInDim")
	errInferenceLenMismatchOutputs = errors.New("aivm: InferenceStep: batchOutputs length != ops*InferenceOutDim")

	errProofVerifyLenMismatch = errors.New("aivm: ProofVerify: results length != ops length")
)

// BackendKind identifies which lux-gpu-kernels plugin satisfied the
// runtime dlopen probe. AvailableNone is the sentinel "no plugin — the
// CPU reference is canonical".
type BackendKind uint8

const (
	AvailableNone   BackendKind = 0
	AvailableCUDA   BackendKind = 1
	AvailableHIP    BackendKind = 2
	AvailableMetal  BackendKind = 3
	AvailableVulkan BackendKind = 4
	AvailableWebGPU BackendKind = 5
)

// String returns the human-readable name for the backend kind. The
// strings double as the per-backend symbol-prefix in the plugin DSO:
// lux_<kind>_aivm_<op>. Keep them lowercase.
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

// Mode selects the AIVM transition execution mode at the bridge layer.
// AutoAIVM picks the GPU plugin when available, else CPUAIVM. GPUAIVM
// forces the plugin path (no fall-through). CPUAIVM forces the Go path.
type Mode uint8

const (
	// AutoAIVM picks the GPU plugin when available, else CPUAIVM.
	AutoAIVM Mode = 0
	// CPUAIVM forces the pure-Go transition path.
	CPUAIVM Mode = 1
	// GPUAIVM forces the GPU path. Under nocgo this is downgraded to
	// CPUAIVM (there is no plugin to call); under cgo a plugin-side
	// failure is surfaced as an error rather than silently falling
	// through to the CPU path.
	GPUAIVM Mode = 2
)

// String returns the human-readable mode name.
func (m Mode) String() string {
	switch m {
	case AutoAIVM:
		return "auto"
	case CPUAIVM:
		return "cpu"
	case GPUAIVM:
		return "gpu"
	default:
		return "unknown"
	}
}

// =============================================================================
// Layout-drift guards — match ops/aivm/cuda/aivm_kernels_common.cuh exactly.
//
// The struct bytes Go hands to C MUST match the on-disk layout file at
// the GPU plugin install tree ops/aivm/op.yaml — every kernel reads them
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
	CommitRoot               [32]byte
	ParentRoot               [32]byte
	ValidatorSetRootAtCommit [32]byte
	Height                   uint64
	TimestampNS              uint64
	Occupied                 uint32
	_pad0                    uint32
	_pad1                    uint64
}

// AIVMEpochState mirrors aivm::cuda::AIVMEpochState (160 bytes).
type AIVMEpochState struct {
	CurrentEpoch            uint64
	NextEpochHeight         uint64
	TotalActiveAttestations uint64
	ActiveModelCount        uint32
	ExpiredAttestationCount uint32
	AttestationRoot         [32]byte
	ModelRegistryRoot       [32]byte
	AuditRoot               [32]byte
	AIVMStateRoot           [32]byte
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
	CommitRoot               [32]byte
	ParentRoot               [32]byte
	ValidatorSetRootAtCommit [32]byte
	Height                   uint64
	TimestampNS              uint64
	Epoch                    uint32
	_pad0                    uint32
	_pad1                    uint64
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

// Inference dimensions — 32 input features → 16 hidden → 1 output. Same
// shape as the GPU kernel and the C++ CPU reference; the bytes are
// quantized int8 throughout, accumulators are int32.
const (
	InferenceInDim  = 32
	InferenceHidden = 16
	InferenceOutDim = 1
)

// InferenceWeights mirrors aivm::cuda::InferenceWeights (672 bytes).
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
	Status           uint32
	OutputLen        uint32
	InputCommitment  [32]byte
	OutputCommitment [32]byte
	AttestationRoot  [32]byte
	_pad0            [8]uint8
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

// =============================================================================
// Per-kernel constants — must match aivm_kernels_common.cuh exactly.
// =============================================================================

// Attestation status bits (mirror kAttStatusVerified / kAttStatusExpired
// in the on-device header). Lower bits 0x1 (occupied) and unused bits
// are managed by the locator.
const (
	attStatusVerified uint32 = 0x2
	attStatusExpired  uint32 = 0x4
)

// Model op kinds (mirror kModelOpRegister / kModelOpUpdateWeights /
// kModelOpUpdateLicense / kModelOpTransfer).
const (
	modelOpRegister      uint32 = 0
	modelOpUpdateWeights uint32 = 1
	modelOpUpdateLicense uint32 = 2
	modelOpTransfer      uint32 = 3
)

// Transition modes (mirror kModeAttestation / kModeProvenance /
// kModeAnchor / kModeEpoch / kModeFullRound). vm.go and the kernel
// share these values.
const (
	modeAttestation uint32 = 0
	modeProvenance  uint32 = 1
	modeAnchor      uint32 = 2
	modeEpoch       uint32 = 3
	modeFullRound   uint32 = 4
)

// ProofVerify status bits (mirror kProofStatusOk / kProofStatusSigCheck /
// kProofStatusMeasureCheck / kProofStatusExpired / kProofStatusKeyZero).
const (
	proofStatusOk           uint32 = 0x01
	proofStatusSigCheck     uint32 = 0x02
	proofStatusMeasureCheck uint32 = 0x04
	proofStatusExpired      uint32 = 0x08
	proofStatusKeyZero      uint32 = 0x10
)

// =============================================================================
// Layout-drift guard — refuse to load if any struct size disagrees with
// the on-device layout in aivm_kernels_common.cuh / aivm_gpu_layout.hpp.
// Any disagreement here means Go would write garbage at the C boundary
// (cgo) or compute against a different binary contract (nocgo).
// =============================================================================

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
					"Re-sync chains/aivm/aivm_gpu_types.go against "+
					"the GPU plugin install tree ops/aivm/cuda/aivm_kernels_common.cuh.",
				c.name, c.got, c.want))
		}
	}
}
