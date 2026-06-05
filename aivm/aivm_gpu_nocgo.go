//go:build !cgo

// Package aivm GPU backend — stub used when CGO is disabled.
//
// The cgo build (aivm_gpu.go + backend.go) uses dlopen/dlsym to find a
// lux-gpu-kernels plugin at process start. Without cgo there's no way to
// reach a C function pointer, so every GPUBackend method returns
// ErrGPUNotAvailable. vm.go callers see gpuAvailable() == false and
// fall through to the existing Go path.
//
// This file keeps the public API surface identical between build modes:
// the same struct names, the same method signatures, the same package
// constants. Only the implementation differs.
package aivm

import "errors"

// ErrGPUNotAvailable mirrors the cgo build's sentinel. vm.go can compare
// against it without caring which build mode is active.
var ErrGPUNotAvailable = errors.New("aivm: GPU plugin unavailable (built without CGo)")

// BackendKind identifies which lux-gpu-kernels plugin satisfied the
// runtime probe. AvailableNone is the only value reachable without cgo.
type BackendKind uint8

const (
	AvailableNone   BackendKind = 0
	AvailableCUDA   BackendKind = 1
	AvailableHIP    BackendKind = 2
	AvailableMetal  BackendKind = 3
	AvailableVulkan BackendKind = 4
	AvailableWebGPU BackendKind = 5
)

// String returns "none" under the nocgo stub. The other kinds are
// unreachable on this build but kept declared so callers can compare
// against the same constants either way.
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
		return "unknown"
	}
}

// =============================================================================
// Layout structs — kept fully declared so package-internal helpers compile
// identically in both modes. Field tags and sizes are NOT enforced under
// nocgo (no cgo boundary to validate against).
// =============================================================================

// Attestation mirrors the cgo build's layout (no-op container under nocgo).
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

// ModelRegistryEntry mirrors the cgo build's layout.
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

// AuditAnchor mirrors the cgo build's layout.
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

// AIVMEpochState mirrors the cgo build's layout.
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

// AIVMRoundDescriptor mirrors the cgo build's layout.
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

// AttestationOp mirrors the cgo build's layout.
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

// ModelOp mirrors the cgo build's layout.
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

// AnchorOp mirrors the cgo build's layout.
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

// AIVMTransitionResult mirrors the cgo build's layout.
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

// Inference dimensions mirror the cgo build's constants.
const (
	InferenceInDim  = 32
	InferenceHidden = 16
	InferenceOutDim = 1
)

// InferenceWeights mirrors the cgo build's layout.
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

// InferenceOp mirrors the cgo build's layout.
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

// InferenceResult mirrors the cgo build's layout.
type InferenceResult struct {
	Status            uint32
	OutputLen         uint32
	InputCommitment   [32]byte
	OutputCommitment  [32]byte
	AttestationRoot   [32]byte
	_pad0             [8]uint8
}

// ProofVerifyOp mirrors the cgo build's layout.
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

// ProofVerifyResult mirrors the cgo build's layout.
type ProofVerifyResult struct {
	Status      uint32
	Kind        uint32
	BindingHash [32]byte
	_pad0       [8]uint8
}

// =============================================================================
// GPUBackend stub — every method returns ErrGPUNotAvailable.
// =============================================================================

// GPUBackend is the nocgo stub. All methods return ErrGPUNotAvailable so
// vm.go's gpu paths fall through cleanly to the Go implementation.
type GPUBackend struct{}

// Kind returns AvailableNone under nocgo.
func (b *GPUBackend) Kind() BackendKind { return AvailableNone }

// Path returns "" under nocgo.
func (b *GPUBackend) Path() string { return "" }

// IsAvailable always returns false under nocgo.
func (b *GPUBackend) IsAvailable() bool { return false }

// Close is a no-op under nocgo.
func (b *GPUBackend) Close() error { return nil }

// AttestationApply returns ErrGPUNotAvailable under nocgo.
func (b *GPUBackend) AttestationApply(
	_ *AIVMRoundDescriptor,
	_ []AttestationOp,
	_ []Attestation,
	_ *uint32,
) error {
	return ErrGPUNotAvailable
}

// ProvenanceApply returns ErrGPUNotAvailable under nocgo.
func (b *GPUBackend) ProvenanceApply(
	_ *AIVMRoundDescriptor,
	_ []ModelOp,
	_ []ModelRegistryEntry,
	_ *uint32,
) error {
	return ErrGPUNotAvailable
}

// AnchorApply returns ErrGPUNotAvailable under nocgo.
func (b *GPUBackend) AnchorApply(
	_ *AIVMRoundDescriptor,
	_ []AnchorOp,
	_ []AuditAnchor,
	_ *uint32,
) error {
	return ErrGPUNotAvailable
}

// EpochTransition returns ErrGPUNotAvailable under nocgo.
func (b *GPUBackend) EpochTransition(
	_ *AIVMRoundDescriptor,
	_ []Attestation,
	_ []ModelRegistryEntry,
	_ []AuditAnchor,
	_ *AIVMEpochState,
	_ *AIVMTransitionResult,
) error {
	return ErrGPUNotAvailable
}

// InferenceStep returns ErrGPUNotAvailable under nocgo.
func (b *GPUBackend) InferenceStep(
	_ *InferenceWeights,
	_ []InferenceOp,
	_ []int8,
	_ []int8,
	_ []InferenceResult,
) error {
	return ErrGPUNotAvailable
}

// ProofVerify returns ErrGPUNotAvailable under nocgo.
func (b *GPUBackend) ProofVerify(
	_ []ProofVerifyOp,
	_ []ProofVerifyResult,
) error {
	return ErrGPUNotAvailable
}

// gpuAvailable always returns false under nocgo. vm.go callers see this
// and fall through to the existing Go path.
func gpuAvailable() bool { return false }

// gpuTransitionApply returns ErrGPUNotAvailable under nocgo. vm.go's
// Accept() can opt into this and fall through cleanly when the plugin
// isn't available.
func gpuTransitionApply(
	_ *AIVMRoundDescriptor,
	_ []Attestation,
	_ []ModelRegistryEntry,
	_ []AuditAnchor,
	_ *AIVMEpochState,
	_ *AIVMTransitionResult,
) error {
	return ErrGPUNotAvailable
}

// =============================================================================
// Public Mode API — kept declared under nocgo so callers don't need a
// build-tag fence. AutoAIVM / SetBackend are no-ops under nocgo (the only
// reachable mode is CPUAIVM).
// =============================================================================

// Mode mirrors the cgo build's transition-mode enum.
type Mode uint8

const (
	// AutoAIVM picks the GPU plugin when available, else CPUAIVM. Under
	// nocgo this is always equivalent to CPUAIVM.
	AutoAIVM Mode = 0
	// CPUAIVM forces the pure-Go transition path.
	CPUAIVM Mode = 1
	// GPUAIVM forces the GPU path. Unreachable under nocgo — SetBackend
	// silently downgrades it to CPUAIVM.
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

// ActiveGPUBackend returns a zero-value *GPUBackend under nocgo. Callers
// test IsAvailable() (always false here) to decide whether to opt in.
func ActiveGPUBackend() *GPUBackend { return &GPUBackend{} }

// SetBackend is a no-op under nocgo — there's no GPU path to switch to.
func SetBackend(_ Mode) {}

// ActiveMode always returns CPUAIVM under nocgo.
func ActiveMode() Mode { return CPUAIVM }

// EffectiveBackendKind always returns AvailableNone under nocgo.
func EffectiveBackendKind() BackendKind { return AvailableNone }
