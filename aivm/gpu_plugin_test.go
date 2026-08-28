// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package aivm

// gpu_plugin_test.go — the dlopen bridge, driven against a real plugin.
//
// The GPU bridge is a runtime overlay: it dlopens a backend plugin, dlsyms six
// launchers, and hands them host pointers to the wire structs. What can be wrong
// here is not the arithmetic inside a kernel — that is the kernel's business —
// but the BRIDGE: whether a missing symbol is noticed, whether the counts the
// launcher receives are the ones the caller passed, and whether a launcher's
// non-zero return reaches the caller as an error rather than as a zero count the
// caller reads as success.
//
// So the plugin under test is a real shared object, compiled here, whose
// launchers ECHO what they were handed back through the output slots the ABI
// already provides. That exercises the same dlopen, the same dlsym and the same
// call shims a CUDA plugin would, with the kernel replaced by a mirror. No GPU
// is required and none is simulated: the arithmetic is not what this file is
// about, and pretending otherwise would be a test that passes when the bridge
// and the mirror are wrong in the same way.
//
// The mirror's contract, which the tests read back:
//
//	rc            — every launcher returns a field of its first argument:
//	                desc->Mode (offset 32) for the four that take a descriptor,
//	                ops[0].Mode (offset 96) for inference_step,
//	                ops[0].Kind (offset 224) for proof_verify.
//	*applied_out  — the table count the bridge passed
//	result        — Status=7, counts echoed; epoch->CurrentEpoch += 1
//	outputs       — inference writes op_count bytes; proof writes Status=1

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// The six launchers, in the order openGPUBackend resolves them. Building a
// plugin that exports only a PREFIX of this list is how each dlsym-failure
// branch is reached — one source, seven shared objects.
var launchers = []string{`
static int rc_desc(const void* p) { return (int)*(const uint32_t*)((const char*)p + 32); }

int lux_cuda_aivm_attestation_apply(const void* desc, const void* ops, void* att,
                                    void* applied, uint32_t n, void* stream) {
    (void)ops; (void)att; (void)stream;
    *(uint32_t*)applied = n;
    return rc_desc(desc);
}
`, `
int lux_cuda_aivm_provenance_apply(const void* desc, const void* ops, void* models,
                                   void* applied, uint32_t n, void* stream) {
    (void)ops; (void)models; (void)stream;
    *(uint32_t*)applied = n + 100;
    return rc_desc(desc);
}
`, `
int lux_cuda_aivm_anchor_apply(const void* desc, const void* ops, void* anchors,
                               void* applied, uint32_t n, void* stream) {
    (void)ops; (void)anchors; (void)stream;
    *(uint32_t*)applied = n + 200;
    return rc_desc(desc);
}
`, `
int lux_cuda_aivm_epoch_transition(const void* desc, void* att, void* models, void* anchors,
                                   void* epoch, void* result, uint32_t na, uint32_t nm,
                                   uint32_t nk, void* stream) {
    (void)att; (void)models; (void)anchors; (void)stream;
    uint32_t* out = (uint32_t*)result;
    out[0] = 7;    // Status
    out[1] = na;   // AttestationApplyCount
    out[2] = nm;   // ModelApplyCount
    out[3] = nk;   // AnchorApplyCount
    ((uint64_t*)epoch)[0] += 1;  // CurrentEpoch advances in place
    return rc_desc(desc);
}
`, `
int lux_cuda_aivm_inference_step(const void* w, const void* ops, const void* in,
                                 void* out, void* results, uint32_t n, void* stream) {
    (void)w; (void)in; (void)stream;
    for (uint32_t i = 0; i < n; i++) ((signed char*)out)[i] = (signed char)(i + 1);
    ((uint32_t*)results)[0] = n;   // InferenceResult.Status
    // No descriptor reaches this launcher; ops[0].Mode carries the code.
    return (int)*(const uint32_t*)((const char*)ops + 96);
}
`, `
int lux_cuda_aivm_proof_verify(const void* ops, void* results, uint32_t n, void* stream) {
    (void)stream;
    for (uint32_t i = 0; i < n; i++) ((uint32_t*)results)[i * 12] = 1;  // Status
    // ops[0].Kind carries the code.
    return (int)*(const uint32_t*)((const char*)ops + 224);
}
`}

const stubPreamble = `
#include <stdint.h>
`

var (
	stubOnce sync.Once
	stubDir  string
	stubErr  error
)

// stubPlugins compiles the seven mirror plugins once: one exporting the first k
// launchers for each k in 0..6. plugin[6] is complete; plugin[k<6] is how the
// loader's k-th dlsym failure is reached.
func stubPlugins(t *testing.T) string {
	t.Helper()
	stubOnce.Do(func() {
		dir, err := os.MkdirTemp("", "aivm-gpu-stub")
		if err != nil {
			stubErr = err
			return
		}
		for k := 0; k <= len(launchers); k++ {
			body := stubPreamble + strings.Join(launchers[:k], "\n")
			// rc_desc is only referenced by the first four launchers; keep the
			// compiler quiet when it is defined and unused.
			if k > 0 {
				body = strings.Replace(body, "static int rc_desc", "static int __attribute__((unused)) rc_desc", 1)
			}
			src := filepath.Join(dir, fmt.Sprintf("stub%d.c", k))
			if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
				stubErr = err
				return
			}
			out := filepath.Join(dir, fmt.Sprintf("k%d", k), "libluxgpu_backend_cuda.so")
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				stubErr = err
				return
			}
			if msg, err := exec.Command(compiler(), "-shared", "-fPIC", "-o", out, src).CombinedOutput(); err != nil {
				stubErr = fmt.Errorf("%s: %w: %s", compiler(), err, msg)
				return
			}
		}
		stubDir = dir
	})
	require.NoError(t, stubErr)
	return stubDir
}

// stubAt is the plugin exporting the first k launchers.
func stubAt(t *testing.T, k int) string {
	t.Helper()
	return filepath.Join(stubPlugins(t), fmt.Sprintf("k%d", k), "libluxgpu_backend_cuda.so")
}

func compiler() string {
	if cc := os.Getenv("CC"); cc != "" {
		return cc
	}
	return "cc"
}

// mirror opens the complete stub through the production loader.
func mirror(t *testing.T) *GPUBackend {
	t.Helper()
	b, err := openGPUBackend(AvailableCUDA, stubAt(t, len(launchers)))
	require.NoError(t, err)
	require.True(t, b.IsAvailable())
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// round is a descriptor whose Mode carries the code the mirror echoes.
func round(rc uint32) *AIVMRoundDescriptor {
	return &AIVMRoundDescriptor{ChainID: 1, Round: 2, Mode: rc}
}

// -----------------------------------------------------------------------------
// Naming.
// -----------------------------------------------------------------------------

func TestBackendKindNames(t *testing.T) {
	require := require.New(t)
	for kind, want := range map[BackendKind]string{
		AvailableNone: "none", AvailableCUDA: "cuda", AvailableHIP: "hip",
		AvailableMetal: "metal", AvailableVulkan: "vulkan", AvailableWebGPU: "webgpu",
	} {
		require.Equal(want, kind.String())
	}
	// The name is what the symbol is built from, so an unknown kind must not
	// silently collapse onto a known one's symbols.
	require.Equal("backend(200)", BackendKind(200).String())
}

func TestModeNames(t *testing.T) {
	require := require.New(t)
	require.Equal("auto", AutoAIVM.String())
	require.Equal("cpu", CPUAIVM.String())
	require.Equal("gpu", GPUAIVM.String())
	require.Equal("unknown", Mode(9).String())
}

// -----------------------------------------------------------------------------
// Where the loader looks.
// -----------------------------------------------------------------------------

func TestTheProbeListCoversEveryBackend(t *testing.T) {
	require := require.New(t)
	got := platformCandidates()
	require.Len(got, 5)
	require.Equal(AvailableCUDA, got[0].kind, "CUDA is probed first")
	require.Equal(AvailableHIP, got[1].kind)
	kinds := map[BackendKind]bool{}
	for _, c := range got {
		require.NotEmpty(c.filename)
		require.NotEmpty(c.subdir)
		kinds[c.kind] = true
	}
	require.Len(kinds, 5, "each candidate names a distinct backend")
}

func TestAnExplicitPluginDirWinsOverTheLoaderSearch(t *testing.T) {
	require := require.New(t)
	c := backendCandidate{kind: AvailableCUDA, filename: "libluxgpu_backend_cuda.so", subdir: "cuda"}

	// With nothing set, the bare filename is all there is: the loader's own
	// search, and nothing that could override it.
	t.Setenv("LUX_GPU_PLUGIN_DIR", "")
	t.Setenv("LUXCPP_PREFIX", "")
	require.Equal([]string{c.filename}, candidatePaths(c))

	t.Setenv("LUX_GPU_PLUGIN_DIR", "/plugins")
	t.Setenv("LUXCPP_PREFIX", "/opt/luxcpp")
	paths := candidatePaths(c)
	require.Equal([]string{
		"/plugins/libluxgpu_backend_cuda.so",
		"/plugins/backends/cuda/libluxgpu_backend_cuda.so",
		"/plugins/build/backends/cuda/libluxgpu_backend_cuda.so",
		"/plugins/build/metal-only/backends/cuda/libluxgpu_backend_cuda.so",
		"/plugins/build/vulkan-m1/backends/cuda/libluxgpu_backend_cuda.so",
		"/opt/luxcpp/lib/libluxgpu_backend_cuda.so",
		"libluxgpu_backend_cuda.so",
	}, paths)
	require.Equal(c.filename, paths[len(paths)-1], "the bare name is probed last, so an override always wins")
}

// -----------------------------------------------------------------------------
// Resolution.
// -----------------------------------------------------------------------------

// A plugin that will not open, and one that opens but is missing a launcher,
// are both refused — and the second must not leave the handle open.
func TestAPluginMissingALauncherIsRefused(t *testing.T) {
	require := require.New(t)

	_, err := openGPUBackend(AvailableCUDA, filepath.Join(t.TempDir(), "absent.so"))
	require.ErrorContains(err, "dlopen")

	for k := 0; k < len(launchers); k++ {
		_, err := openGPUBackend(AvailableCUDA, stubAt(t, k))
		require.ErrorContains(err, "dlsym", "a plugin exporting %d of %d launchers loaded", k, len(launchers))
	}

	b := mirror(t)
	require.Equal(AvailableCUDA, b.Kind())
	require.Equal(stubAt(t, len(launchers)), b.Path())
}

// Closing is idempotent and nil-safe: the loader closes a half-bound plugin on
// its way out, and a caller may close what it opened.
func TestClosingIsIdempotent(t *testing.T) {
	require := require.New(t)
	require.NoError((*GPUBackend)(nil).Close())
	require.NoError((&GPUBackend{}).Close())

	b, err := openGPUBackend(AvailableCUDA, stubAt(t, len(launchers)))
	require.NoError(err)
	require.NoError(b.Close())
	require.False(b.IsAvailable(), "a closed backend must stop reporting itself as available")
	require.NoError(b.Close())
}

// -----------------------------------------------------------------------------
// The guard. No plugin means an error, never a call through a null pointer.
// -----------------------------------------------------------------------------

func TestEveryLauncherRefusesWithoutAPlugin(t *testing.T) {
	require := require.New(t)
	var applied uint32

	for _, b := range []*GPUBackend{nil, {}, {handle: unsafe.Pointer(new(byte))}} {
		require.False(b.IsAvailable())
		require.Equal(AvailableNone, b.Kind())
		require.Equal("", b.Path())
		require.ErrorIs(b.AttestationApply(round(0), nil, make([]Attestation, 1), &applied), ErrGPUNotAvailable)
		require.ErrorIs(b.ProvenanceApply(round(0), nil, make([]ModelRegistryEntry, 1), &applied), ErrGPUNotAvailable)
		require.ErrorIs(b.AnchorApply(round(0), nil, make([]AuditAnchor, 1), &applied), ErrGPUNotAvailable)
		require.ErrorIs(b.EpochTransition(round(0), make([]Attestation, 1), nil, nil,
			&AIVMEpochState{}, &AIVMTransitionResult{}), ErrGPUNotAvailable)
		require.ErrorIs(b.InferenceStep(&InferenceWeights{}, make([]InferenceOp, 1),
			make([]int8, InferenceInDim), make([]int8, 1), make([]InferenceResult, 1)), ErrGPUNotAvailable)
		require.ErrorIs(b.ProofVerify(make([]ProofVerifyOp, 1), make([]ProofVerifyResult, 1)), ErrGPUNotAvailable)
	}
}

// The bridge refuses a call it cannot describe BEFORE it reaches C: a nil
// output slot or an empty table would otherwise be dereferenced by the kernel.
func TestTheBridgeRefusesArgumentsItCannotPass(t *testing.T) {
	require := require.New(t)
	b := mirror(t)
	var applied uint32

	require.ErrorContains(b.AttestationApply(nil, nil, make([]Attestation, 1), &applied), "nil desc")
	require.ErrorContains(b.AttestationApply(round(0), nil, make([]Attestation, 1), nil), "nil desc")
	require.ErrorContains(b.AttestationApply(round(0), nil, nil, &applied), "empty attestations")

	require.ErrorContains(b.ProvenanceApply(nil, nil, make([]ModelRegistryEntry, 1), &applied), "nil desc")
	require.ErrorContains(b.ProvenanceApply(round(0), nil, nil, &applied), "empty models")

	require.ErrorContains(b.AnchorApply(nil, nil, make([]AuditAnchor, 1), &applied), "nil desc")
	require.ErrorContains(b.AnchorApply(round(0), nil, nil, &applied), "empty anchors")

	require.ErrorContains(b.EpochTransition(nil, make([]Attestation, 1), nil, nil, &AIVMEpochState{}, &AIVMTransitionResult{}), "nil desc")
	require.ErrorContains(b.EpochTransition(round(0), make([]Attestation, 1), nil, nil, nil, &AIVMTransitionResult{}), "nil desc")
	require.ErrorContains(b.EpochTransition(round(0), make([]Attestation, 1), nil, nil, &AIVMEpochState{}, nil), "nil desc")
	require.ErrorContains(b.EpochTransition(round(0), nil, nil, nil, &AIVMEpochState{}, &AIVMTransitionResult{}), "empty attestations")

	require.ErrorContains(b.InferenceStep(nil, nil, nil, nil, nil), "nil weights")
	require.NoError(b.InferenceStep(&InferenceWeights{}, nil, nil, nil, nil), "no ops is a no-op, not an error")
	require.ErrorContains(b.InferenceStep(&InferenceWeights{}, make([]InferenceOp, 2),
		make([]int8, 2*InferenceInDim), make([]int8, 2), make([]InferenceResult, 1)), "results length")
	require.ErrorContains(b.InferenceStep(&InferenceWeights{}, make([]InferenceOp, 2),
		make([]int8, 3), make([]int8, 2), make([]InferenceResult, 2)), "batchInputs length")
	require.ErrorContains(b.InferenceStep(&InferenceWeights{}, make([]InferenceOp, 2),
		make([]int8, 2*InferenceInDim), make([]int8, 3), make([]InferenceResult, 2)), "batchOutputs length")

	require.NoError(b.ProofVerify(nil, nil), "no ops is a no-op, not an error")
	require.ErrorContains(b.ProofVerify(make([]ProofVerifyOp, 2), make([]ProofVerifyResult, 1)), "results length")
}

// -----------------------------------------------------------------------------
// The bridge, end to end against the mirror.
// -----------------------------------------------------------------------------

// Each launcher receives the count the caller passed and writes back through the
// output slot it was given, and a non-zero return arrives as an error rather
// than as a zero count a caller would read as success.
func TestTheBridgeCarriesCountsAndFailures(t *testing.T) {
	require := require.New(t)
	b := mirror(t)
	var applied uint32

	require.NoError(b.AttestationApply(round(0), make([]AttestationOp, 2), make([]Attestation, 3), &applied))
	require.Equal(uint32(3), applied)
	require.ErrorContains(b.AttestationApply(round(9), nil, make([]Attestation, 3), &applied),
		"cuda_aivm_attestation_apply returned 9")

	require.NoError(b.ProvenanceApply(round(0), make([]ModelOp, 1), make([]ModelRegistryEntry, 4), &applied))
	require.Equal(uint32(104), applied)
	require.ErrorContains(b.ProvenanceApply(round(8), nil, make([]ModelRegistryEntry, 1), &applied),
		"provenance_apply returned 8")

	require.NoError(b.AnchorApply(round(0), make([]AnchorOp, 1), make([]AuditAnchor, 5), &applied))
	require.Equal(uint32(205), applied)
	require.ErrorContains(b.AnchorApply(round(7), nil, make([]AuditAnchor, 1), &applied),
		"anchor_apply returned 7")

	epoch := &AIVMEpochState{CurrentEpoch: 41}
	var result AIVMTransitionResult
	require.NoError(b.EpochTransition(round(0), make([]Attestation, 2),
		make([]ModelRegistryEntry, 3), make([]AuditAnchor, 4), epoch, &result))
	require.Equal(uint64(42), epoch.CurrentEpoch, "the kernel advanced the epoch in place")
	require.Equal(uint32(7), result.Status)
	require.Equal(uint32(2), result.AttestationApplyCount)
	require.Equal(uint32(3), result.ModelApplyCount)
	require.Equal(uint32(4), result.AnchorApplyCount)
	require.ErrorContains(b.EpochTransition(round(6), make([]Attestation, 1), nil, nil,
		epoch, &result), "epoch_transition returned 6")

	ops := make([]InferenceOp, 3)
	outs := make([]int8, 3)
	results := make([]InferenceResult, 3)
	require.NoError(b.InferenceStep(&InferenceWeights{}, ops, make([]int8, 3*InferenceInDim), outs, results))
	require.Equal([]int8{1, 2, 3}, outs)
	require.Equal(uint32(3), results[0].Status)
	ops[0].Mode = 5
	require.ErrorContains(b.InferenceStep(&InferenceWeights{}, ops,
		make([]int8, 3*InferenceInDim), outs, results), "inference_step returned 5")

	pops := make([]ProofVerifyOp, 2)
	pres := make([]ProofVerifyResult, 2)
	require.NoError(b.ProofVerify(pops, pres))
	require.Equal(uint32(1), pres[0].Status)
	require.Equal(uint32(1), pres[1].Status)
	pops[0].Kind = 4
	require.ErrorContains(b.ProofVerify(pops, pres), "proof_verify returned 4")
}

// -----------------------------------------------------------------------------
// The process-wide backend.
// -----------------------------------------------------------------------------

// holdBackend saves and restores the package globals the probe writes, so one
// test's plugin does not become another's. These tests are therefore serial.
func holdBackend(t *testing.T) {
	t.Helper()
	b, mode := activeBackend, ActiveMode()
	t.Cleanup(func() {
		// The once-guard is reset rather than restored: a sync.Once cannot be
		// copied, and a fresh one is the honest state anyway — the next probe
		// re-reads an environment this test has just put back.
		activeBackend, activeBackendOnce = b, sync.Once{}
		SetBackend(mode)
	})
}

// With no plugin anywhere, the process-wide backend is a value that reports
// itself unavailable — never nil, so a caller cannot dereference one.
func TestWithNoPluginTheBackendIsUnavailable(t *testing.T) {
	require := require.New(t)
	holdBackend(t)

	activeBackend, activeBackendOnce = nil, sync.Once{}
	t.Setenv("LUX_GPU_PLUGIN_DIR", filepath.Join(t.TempDir(), "empty"))
	t.Setenv("LUXCPP_PREFIX", "")

	require.Nil(autoLoadBackend())
	b := ActiveGPUBackend()
	require.NotNil(b)
	require.False(b.IsAvailable())
	require.False(gpuAvailable())

	SetBackend(AutoAIVM)
	require.Equal(AvailableNone, EffectiveBackendKind(), "auto falls back to the Go path")
	SetBackend(CPUAIVM)
	require.Equal(AvailableNone, EffectiveBackendKind())
	SetBackend(GPUAIVM)
	require.Equal(AvailableNone, EffectiveBackendKind(), "forcing GPU with no plugin still names none")

	// And the transition shim declines rather than calling through nothing.
	require.ErrorIs(gpuTransitionApply(round(0), make([]Attestation, 1), nil, nil,
		&AIVMEpochState{}, &AIVMTransitionResult{}), ErrGPUNotAvailable)
}

// Pointed at a plugin directory, the probe finds it and every process-wide
// answer follows from that one resolution.
func TestThePluginDirectoryDrivesTheProbe(t *testing.T) {
	require := require.New(t)
	holdBackend(t)

	activeBackend, activeBackendOnce = nil, sync.Once{}
	t.Setenv("LUX_GPU_PLUGIN_DIR", filepath.Dir(stubAt(t, len(launchers))))
	t.Setenv("LUXCPP_PREFIX", "")

	b := autoLoadBackend()
	require.NotNil(b, "the probe did not find the plugin in LUX_GPU_PLUGIN_DIR")
	require.True(b.IsAvailable())
	require.Equal(AvailableCUDA, b.Kind())
	require.Same(b, ActiveGPUBackend())
	require.True(gpuAvailable())

	SetBackend(AutoAIVM)
	require.Equal(AvailableCUDA, EffectiveBackendKind())
	SetBackend(GPUAIVM)
	require.Equal(AvailableCUDA, EffectiveBackendKind())
	SetBackend(CPUAIVM)
	require.Equal(AvailableNone, EffectiveBackendKind(), "CPU mode ignores a loaded plugin")

	// The transition shim now reaches the mirror.
	epoch := &AIVMEpochState{CurrentEpoch: 1}
	var result AIVMTransitionResult
	require.NoError(gpuTransitionApply(round(0), make([]Attestation, 1), nil, nil, epoch, &result))
	require.Equal(uint64(2), epoch.CurrentEpoch)

	// The probe runs once: a second call does not re-open the plugin.
	require.Same(b, autoLoadBackend())

	// ActiveGPUBackend probes for itself when the global was never set — the
	// path a process takes when init() ran before the environment did.
	activeBackend, activeBackendOnce = nil, sync.Once{}
	found := ActiveGPUBackend()
	require.True(found.IsAvailable(), "ActiveGPUBackend did not probe for a plugin it had not resolved yet")
	require.Equal(AvailableCUDA, found.Kind())
	require.Same(found, activeBackend, "the probe must publish what it found")
}
