//go:build !cgo

// Package aivm GPU backend — pure-CPU bridge used when CGO is disabled.
//
// Two ways to think about this file:
//
//  1. The nocgo build has no way to reach a C function pointer, so the
//     dlopen-based plugin path (aivm_gpu.go + backend.go) is absent.
//     Every public bridge method here delegates to the canonical Go
//     reference in aivm_gpu_cpu.go. The CPU answer is the source of
//     truth on every backend.
//
//  2. The public API surface is IDENTICAL between cgo and nocgo —
//     same struct names, same method signatures, same exported
//     constants — so vm.go does NOT need build-tag fences. The only
//     observable difference is `gpuAvailable()` (always false here)
//     and `Kind()` / `Path()` on `GPUBackend` (always AvailableNone
//     / "" here).
//
// Layout structs, BackendKind, Mode, ErrGPUNotAvailable, and the
// init() layout-drift guard all live in aivm_gpu_types.go (no build
// tag) so both build modes share ONE copy. The pure-Go reference
// implementations of the six kernels live in aivm_gpu_cpu.go (also
// no build tag).

package aivm

import "sync"

// =============================================================================
// GPUBackend stub — every method routes to the Go CPU reference.
// =============================================================================

// GPUBackend is the nocgo stub. It carries no GPU plugin handle (there
// is no plugin), so every method calls into the canonical Go reference
// in aivm_gpu_cpu.go. Both build modes therefore produce byte-identical
// output on every fixture.
type GPUBackend struct{}

// Kind returns AvailableNone under nocgo.
func (b *GPUBackend) Kind() BackendKind { return AvailableNone }

// Path returns "" under nocgo.
func (b *GPUBackend) Path() string { return "" }

// IsAvailable always returns false under nocgo. There is no GPU plugin
// to call; the bridge methods always run the Go CPU reference.
func (b *GPUBackend) IsAvailable() bool { return false }

// Close is a no-op under nocgo.
func (b *GPUBackend) Close() error { return nil }

// AttestationApply runs the attestation kernel via the Go CPU
// reference. Byte-equal to the cgo path's plugin output (and to
// the C++ CPU oracle).
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
	attestationApplyCPU(desc, ops, attestations, appliedOut)
	return nil
}

// ProvenanceApply runs the provenance (model-registry) kernel via the
// Go CPU reference.
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
	provenanceApplyCPU(desc, ops, models, appliedOut)
	return nil
}

// AnchorApply runs the audit-anchor kernel via the Go CPU reference.
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
	anchorApplyCPU(desc, ops, anchors, appliedOut)
	return nil
}

// EpochTransition runs the epoch-finalisation kernel via the Go CPU
// reference. Composes per-epoch attestation_root / model_registry_root /
// audit_root / aivm_state_root.
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
	epochTransitionCPU(desc, attestations, models, anchors, epoch, result)
	return nil
}

// InferenceStep runs the deterministic int8 32→16→1 inference kernel
// via the Go CPU reference.
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
	inferenceStepCPU(weights, ops, batchInputs, batchOutputs, results)
	return nil
}

// ProofVerify runs the TEE-attestation envelope check kernel via the
// Go CPU reference.
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
	proofVerifyCPU(ops, results)
	return nil
}

// =============================================================================
// vm.go opt-in hooks under nocgo. No plugin can ever load — gpuAvailable()
// reports false; gpuTransitionApply() runs the Go CPU reference and
// returns success.
// =============================================================================

// gpuAvailable always returns false under nocgo. vm.go callers see this
// and decide on the Go-only path; they do NOT skip work — the bridge
// methods always return the correct CPU answer regardless.
func gpuAvailable() bool { return false }

// gpuTransitionApply runs the epoch-finalisation kernel via the Go CPU
// reference. Never returns ErrGPUNotAvailable; the caller always gets a
// correct result.
func gpuTransitionApply(
	desc *AIVMRoundDescriptor,
	attestations []Attestation,
	models []ModelRegistryEntry,
	anchors []AuditAnchor,
	epoch *AIVMEpochState,
	result *AIVMTransitionResult,
) error {
	return (*GPUBackend)(nil).EpochTransition(desc, attestations, models, anchors, epoch, result)
}

// =============================================================================
// Public Mode API — kept declared under nocgo so callers don't need a
// build-tag fence. AutoAIVM / SetBackend are no-ops under nocgo (the only
// reachable mode is CPUAIVM).
// =============================================================================

var (
	modeMu     sync.RWMutex
	activeMode = AutoAIVM
)

// ActiveGPUBackend returns a zero-value *GPUBackend under nocgo. Callers
// test IsAvailable() (always false here) to decide whether the GPU
// plugin specifically is in play; bridge methods always return the
// CPU answer.
func ActiveGPUBackend() *GPUBackend { return &GPUBackend{} }

// SetBackend updates the package-level Mode. Under nocgo every value
// other than CPUAIVM behaves identically to CPUAIVM — there is no GPU
// plugin to dispatch to. Kept settable so production code that bootstraps
// the chain doesn't need a build-tag fence around the SetBackend call.
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

// EffectiveBackendKind always returns AvailableNone under nocgo.
func EffectiveBackendKind() BackendKind { return AvailableNone }
