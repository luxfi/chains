// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package thresholdvm

// GPU bridge — dlopen + dlsym substrate for the MPCVM state-machine kernels.
//
// This file binds Go to the host launchers exported by the per-backend GPU
// plugins in the lux GPU plugin backends/<X>/. Unlike the cevm bridge
// which links statically through pkg-config (libevm + libevm-gpu), the
// thresholdvm bridge is a runtime overlay: zero compile-time dependency on
// the plugin, no pkg-config, no link-time resolution. Either the dlopen
// succeeds at init() and GPUBackend is populated, or it doesn't and
// callers fall back to the CPU reference (the Go state machine in
// protocol/, factory.go, executor.go — unchanged).
//
// Symbols expected per backend (host launchers in
// the lux GPU plugin backends/<X>/src/mpcvm_launchers.{cpp,mm} and
// the kernel TUs in the lux GPU plugin ops/mpcvm/<X>/):
//
//   lux_<X>_mpcvm_ceremony_apply       (begin/cancel + contribution dedup)
//   lux_<X>_mpcvm_ceremony_sweep       (DKG finalize -> key share assignment)
//   lux_<X>_mpcvm_compute_leaves       (parallel keccak per slot)
//   lux_<X>_mpcvm_compose_root         (serial fold + epoch advance)
//
// where <X> ∈ {cuda, hip, metal, vulkan, webgpu}. The Go bridge exposes
// the four MPC state-machine ops requested by the substrate contract:
//
//   GPUBackend.CeremonyApply       → ceremony_apply (ceremony ops only)
//   GPUBackend.KeyShareApply       → ceremony_sweep (DKG finalize path)
//   GPUBackend.ContributionApply   → ceremony_apply (contribution ops only)
//   GPUBackend.MPCTransition       → compute_leaves + compose_root pair
//
// The same ceremony_apply launcher is used twice with disjoint ops because
// the MPC state machine separates "ceremony admin" (begin/cancel) from
// "round contribution" (per-party payload) — both flow through the same
// dedup-and-write GPU kernel by design (see ops/mpcvm/cuda/mpcvm_ceremony.cu).
//
// Corona = R-LWE threshold (the PQ variant per project memory). Pulsar =
// threshold ML-DSA. Magnetar = threshold SLH-DSA (not built yet). When the
// caller invokes CeremonyApply with a CeremonyOp whose kind is kKindCoronaDkg
// or kKindCoronaSign, the GPU dispatches the Corona path; the kernel
// dispatch table is in ops/mpcvm/<X>/mpcvm_corona.cu (or .metal, etc.).

/*
#cgo CFLAGS: -Wno-unused-parameter
#cgo darwin LDFLAGS: -ldl
#cgo linux  LDFLAGS: -ldl

#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// =============================================================================
// Function-pointer typedefs — match the extern "C" launcher signatures in
// the lux GPU plugin backends/<X>/src/mpcvm_launchers.{cpp,mm}.
//
// All pointers are HOST pointers. The launcher wraps them into the backend's
// native buffer type (MTLBuffer, VkBuffer, cudaMalloc, etc.) and uploads /
// downloads via memcpy on UMA backends or H2D/D2H on discrete backends.
//
// Return code: 0 = OK; non-zero = launcher-defined error (1 invalid arg,
// 2 no device, 3 pipeline build, 4 dispatch, 5 readback, 6 submit).
// =============================================================================

typedef int (*lux_mpcvm_ceremony_apply_fn)(
    const void* desc,
    const void* ceremony_ops,
    const void* contribution_ops,
    void*       ceremonies,
    void*       contributions,
    void*       ceremony_applied_out,
    void*       contribution_applied_out,
    uint32_t    ceremony_count,
    uint32_t    contribution_count,
    uint64_t    next_contribution_id_in,
    void*       stream);

typedef int (*lux_mpcvm_ceremony_sweep_fn)(
    const void* desc,
    void*       ceremonies,
    void*       key_shares,
    void*       contributions,
    void*       round_advance_out,
    void*       finalized_out,
    void*       failed_out,
    uint32_t    ceremony_count,
    uint32_t    key_share_count,
    uint32_t    contribution_count,
    uint64_t    next_share_id_in,
    void*       stream);

typedef int (*lux_mpcvm_compute_leaves_fn)(
    const void* ceremonies,
    const void* shares,
    const void* contributions,
    void*       ceremony_leaf_hashes,
    void*       share_leaf_hashes,
    void*       contribution_leaf_hashes,
    void*       active_count_out,
    void*       finalized_count_out,
    void*       failed_count_out,
    void*       share_count_out,
    void*       ceremony_used_mask,
    void*       share_used_mask,
    void*       contribution_used_mask,
    uint32_t    ceremony_count,
    uint32_t    share_count,
    uint32_t    contribution_count,
    void*       stream);

typedef int (*lux_mpcvm_compose_root_fn)(
    const void* desc,
    const void* ceremony_leaf_hashes,
    const void* share_leaf_hashes,
    const void* contribution_leaf_hashes,
    const void* ceremony_used_mask,
    const void* share_used_mask,
    const void* contribution_used_mask,
    const void* active_count_in,
    const void* finalized_count_in,
    const void* failed_count_in,
    const void* share_count_in,
    void*       state,
    void*       result,
    uint32_t    ceremony_count,
    uint32_t    share_count,
    uint32_t    contribution_count,
    void*       stream);

// Thin call shims — Go can't call a C function pointer directly.

static int call_ceremony_apply(
    void* fn, const void* desc, const void* cops, const void* nops,
    void* cer, void* con, void* capp, void* napp,
    uint32_t cc, uint32_t nc, uint64_t next_cont, void* stream)
{
    return ((lux_mpcvm_ceremony_apply_fn)fn)(
        desc, cops, nops, cer, con, capp, napp, cc, nc, next_cont, stream);
}

static int call_ceremony_sweep(
    void* fn, const void* desc,
    void* cer, void* ks, void* con,
    void* ra, void* fin, void* fai,
    uint32_t cc, uint32_t kc, uint32_t nc, uint64_t next_share, void* stream)
{
    return ((lux_mpcvm_ceremony_sweep_fn)fn)(
        desc, cer, ks, con, ra, fin, fai, cc, kc, nc, next_share, stream);
}

static int call_compute_leaves(
    void* fn,
    const void* cer, const void* ks, const void* con,
    void* cl, void* sl, void* nl,
    void* ac, void* fc, void* fac, void* sc,
    void* cm, void* sm, void* nm,
    uint32_t cc, uint32_t kc, uint32_t nc, void* stream)
{
    return ((lux_mpcvm_compute_leaves_fn)fn)(
        cer, ks, con, cl, sl, nl, ac, fc, fac, sc, cm, sm, nm,
        cc, kc, nc, stream);
}

static int call_compose_root(
    void* fn,
    const void* desc,
    const void* cl, const void* sl, const void* nl,
    const void* cm, const void* sm, const void* nm,
    const void* ac, const void* fc, const void* fac, const void* sc,
    void* state, void* result,
    uint32_t cc, uint32_t kc, uint32_t nc, void* stream)
{
    return ((lux_mpcvm_compose_root_fn)fn)(
        desc, cl, sl, nl, cm, sm, nm, ac, fc, fac, sc, state, result,
        cc, kc, nc, stream);
}

// dlsym helper — returns NULL when symbol is missing. Callers check.
static void* lux_dlsym(void* handle, const char* name) {
    if (handle == NULL) return NULL;
    dlerror();
    return dlsym(handle, name);
}

// dlopen wrapper — try multiple candidate filenames in order. Returns NULL
// if every candidate fails. The dlopen mode is RTLD_NOW|RTLD_LOCAL: NOW so
// any missing symbol fails fast at load time, LOCAL so the plugin's
// internal symbols don't pollute the global namespace.
static void* lux_dlopen_first(const char* a, const char* b, const char* c) {
    void* h = NULL;
    if (a && *a) { h = dlopen(a, RTLD_NOW|RTLD_LOCAL); if (h) return h; }
    if (b && *b) { h = dlopen(b, RTLD_NOW|RTLD_LOCAL); if (h) return h; }
    if (c && *c) { h = dlopen(c, RTLD_NOW|RTLD_LOCAL); if (h) return h; }
    return NULL;
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

// ErrGPUNotAvailable is the historical "no plugin loaded" sentinel.
// Retained for ABI compatibility with callers that branch on
// `errors.Is(err, ErrGPUNotAvailable)`. The bridge no longer surfaces
// it on the main happy path: when the GPU plugin isn't dlopen'd OR a
// launcher returns a non-zero rc, the bridge falls through to the
// pure-Go reference in thresholdvm_gpu_cpu.go. The substrate ALWAYS
// produces a result — the GPU is a positive-performance overlay, never
// a correctness gate. Returned only on input-validation failures (nil
// desc, empty arena) where neither path can run.
var ErrGPUNotAvailable = errors.New("thresholdvm: GPU backend not available (no plugin dlopened)")

// GPUBackendKind is the resolved plugin family. Matches the dlopen probe
// order in backend.go: cuda → hip → metal → vulkan → webgpu.
type GPUBackendKind uint8

const (
	GPUBackendNone   GPUBackendKind = 0
	GPUBackendCUDA   GPUBackendKind = 1
	GPUBackendHIP    GPUBackendKind = 2
	GPUBackendMetal  GPUBackendKind = 3
	GPUBackendVulkan GPUBackendKind = 4
	GPUBackendWebGPU GPUBackendKind = 5
)

// String returns the launcher prefix used in symbol resolution.
func (k GPUBackendKind) String() string {
	switch k {
	case GPUBackendCUDA:
		return "cuda"
	case GPUBackendHIP:
		return "hip"
	case GPUBackendMetal:
		return "metal"
	case GPUBackendVulkan:
		return "vulkan"
	case GPUBackendWebGPU:
		return "webgpu"
	default:
		return "none"
	}
}

// =============================================================================
// Wire structs — byte-equivalent to ops/mpcvm/cuda/mpcvm_kernels_common.cuh.
//
// The struct layout MUST match the device-side __align__(16) declarations.
// Go's natural field alignment delivers the exact same packing on amd64 and
// arm64 (verified by the unsafe.Sizeof asserts in init()).
//
// Sizes (post __align__(16) tail padding):
//
//   Ceremony                = 128
//   KeyShare                = 368
//   Contribution            = 432
//   MPCVMState              = 160
//   MPCVMRoundDescriptor    = 96
//   CeremonyOp              = 96
//   ContributionOp          = 416
//   MPCVMTransitionResult   = 176
// =============================================================================

// GPUCeremony is the on-GPU ceremony state. 128 bytes, __align__(16). The
// GPU prefix distinguishes the wire mirror from the domain-level Ceremony
// types in protocols.go / runtime/. ONLY the GPU bridge ever touches these.
type GPUCeremony struct {
	CeremonyID          uint64
	StartedAtNs         uint64
	DeadlineNs          uint64
	ParticipantsBitmap  uint64
	Kind                uint32
	Round               uint32
	Threshold           uint32
	TotalParticipants   uint32
	Status              uint32
	ContributionCount   uint32
	Subject             [32]byte
	CeremonySeed        [32]byte
	_                   [8]byte // tail pad to 128
}

// GPUKeyShare is the on-GPU key share record. 368 bytes, __align__(16).
type GPUKeyShare struct {
	ShareID      uint64
	CeremonyID   uint64
	HolderAddr   uint64
	Scheme       uint32
	HolderIndex  uint32
	ShareDataLen uint32
	Occupied     uint32
	ShareData    [320]byte
	Pad0         uint64
}

// GPUContribution is the on-GPU contribution record. 432 bytes, __align__(16).
type GPUContribution struct {
	ContributionID uint64
	CeremonyID     uint64
	HolderAddr     uint64
	Round          uint32
	HolderIndex    uint32
	PayloadLen     uint32
	Status         uint32
	Payload        [384]byte
	Pad0           uint64
}

// GPUMPCVMState is the on-GPU substrate state. 160 bytes, __align__(16).
type GPUMPCVMState struct {
	CurrentEpoch           uint64
	NowNs                  uint64
	ActiveCeremonyCount    uint32
	FinalizedCeremonyCount uint32
	FailedCeremonyCount    uint32
	KeyShareCount          uint32
	CeremonyRoot           [32]byte
	KeyShareRoot           [32]byte
	ContributionRoot       [32]byte
	MPCVMStateRoot         [32]byte
}

// GPUMPCVMRoundDescriptor describes one round's input envelope. 96 bytes.
type GPUMPCVMRoundDescriptor struct {
	ChainID             uint64
	Round               uint64
	TimestampNs         uint64
	Epoch               uint64
	Mode                uint32
	CeremonyOpCount     uint32
	ContributionOpCount uint32
	ClosingFlag         uint32
	Pad0                uint32
	Pad1                uint32
	Pad2                uint64
	ParentStateRoot     [32]byte
}

// GPUCeremonyOp is one inbound ceremony op (begin/cancel). 96 bytes.
type GPUCeremonyOp struct {
	CeremonyID        uint64
	DeadlineNs        uint64
	Kind              uint32
	CeremonyKind      uint32
	Threshold         uint32
	TotalParticipants uint32
	Subject           [32]byte
	CeremonySeed      [32]byte
}

// GPUContributionOp is one inbound contribution payload. 416 bytes.
type GPUContributionOp struct {
	CeremonyID  uint64
	HolderAddr  uint64
	Round       uint32
	HolderIndex uint32
	PayloadLen  uint32
	Pad0        uint32
	Payload     [384]byte
}

// GPUMPCVMTransitionResult is the transition envelope written by
// compose_root. 176 bytes.
type GPUMPCVMTransitionResult struct {
	Status                 uint32
	CeremonyApplyCount     uint32
	ContributionApplyCount uint32
	FinalizedThisRound     uint32
	FailedThisRound        uint32
	ActiveCeremonyCount    uint32
	KeyShareCount          uint32
	RoundAdvanceCount      uint32
	Epoch                  uint64
	NowNs                  uint64
	CeremonyRoot           [32]byte
	KeyShareRoot           [32]byte
	ContributionRoot       [32]byte
	MPCVMStateRoot         [32]byte
}

// =============================================================================
// Layout asserts — pin Go-side sizeof() to the device-side __align__(16)
// values. Any drift between the host structs and the device structs would
// produce silently-wrong results (the kernel reads bytes at fixed offsets),
// so any mismatch must fail at init() time. These are documented again in
// the .cuh peer file ops/mpcvm/cuda/mpcvm_kernels_common.cuh.
// =============================================================================

const (
	sizeCeremony              = 128
	sizeKeyShare              = 368
	sizeContribution          = 432
	sizeMPCVMState            = 160
	sizeMPCVMRoundDescriptor  = 96
	sizeCeremonyOp            = 96
	sizeContributionOp        = 416
	sizeMPCVMTransitionResult = 176
)

func assertSizes() {
	type pair struct {
		name string
		want int
		got  uintptr
	}
	checks := []pair{
		{"GPUCeremony", sizeCeremony, unsafe.Sizeof(GPUCeremony{})},
		{"GPUKeyShare", sizeKeyShare, unsafe.Sizeof(GPUKeyShare{})},
		{"GPUContribution", sizeContribution, unsafe.Sizeof(GPUContribution{})},
		{"GPUMPCVMState", sizeMPCVMState, unsafe.Sizeof(GPUMPCVMState{})},
		{"GPUMPCVMRoundDescriptor", sizeMPCVMRoundDescriptor, unsafe.Sizeof(GPUMPCVMRoundDescriptor{})},
		{"GPUCeremonyOp", sizeCeremonyOp, unsafe.Sizeof(GPUCeremonyOp{})},
		{"GPUContributionOp", sizeContributionOp, unsafe.Sizeof(GPUContributionOp{})},
		{"GPUMPCVMTransitionResult", sizeMPCVMTransitionResult, unsafe.Sizeof(GPUMPCVMTransitionResult{})},
	}
	for _, c := range checks {
		if int(c.got) != c.want {
			panic(fmt.Sprintf(
				"thresholdvm: GPU layout mismatch — %s sizeof=%d want=%d. "+
					"Rebuild gpu-kernels (ops/mpcvm/cuda/mpcvm_kernels_common.cuh) "+
					"or update the Go struct.", c.name, c.got, c.want))
		}
	}
}

// =============================================================================
// GPUBackend — dlopen'd plugin handle + resolved function pointers.
//
// Constructed exactly once at init() (backend.go). Concurrent reads are safe
// (the symbol table is immutable after init). Concurrent calls into the same
// launcher are safe because the launchers themselves are stateless modulo
// the singleton MTL/cuda/vulkan context which holds its own mutex.
// =============================================================================

// GPUBackend is the resolved plugin substrate. Zero value = not available.
type GPUBackend struct {
	Kind GPUBackendKind
	Path string // dlopen'd library path, for diagnostics

	handle unsafe.Pointer // dlopen handle; nil = no plugin

	// Resolved symbols. Nil = symbol missing in plugin (launcher disabled).
	fnCeremonyApply  unsafe.Pointer
	fnCeremonySweep  unsafe.Pointer
	fnComputeLeaves  unsafe.Pointer
	fnComposeRoot    unsafe.Pointer
}

var (
	gpuBackend     *GPUBackend
	gpuBackendOnce sync.Once
)

// Backend returns the resolved GPU plugin. nil means no plugin was loaded.
func Backend() *GPUBackend {
	return gpuBackend
}

// IsAvailable reports whether the bridge has a usable plugin with at least
// the ceremony_apply and ceremony_sweep launchers resolved. compute_leaves
// and compose_root are required for MPCTransition but are checked
// per-method to allow partial GPU coverage when a plugin ships fewer
// symbols (e.g. an early Vulkan port).
func (g *GPUBackend) IsAvailable() bool {
	if g == nil {
		return false
	}
	return g.handle != nil &&
		g.fnCeremonyApply != nil &&
		g.fnCeremonySweep != nil
}

// =============================================================================
// MPC state-machine surface — four methods covering the substrate's apply /
// transition contract. Each one is a thin shim over the corresponding
// host launcher symbol; the device-side semantics live in
// ops/mpcvm/<X>/mpcvm_*.{cu,metal,wgsl,comp}.
//
// The same ceremony_apply launcher is used twice — CeremonyApply runs it
// with contribution_ops empty, ContributionApply runs it with ceremony_ops
// empty. This mirrors the orthogonal state-machine view (one kernel, two
// op streams) while keeping the C ABI surface tight.
// =============================================================================

// CeremonyApply applies ceremony begin/cancel ops to the ceremony table.
// Contribution slots are not touched (callers passing nil contribution_ops
// get the lean ceremony-admin dispatch).
//
// ceremonies is the open-addressed ceremony hash table (must be a power-of-2
// length on the device-side; the Go caller owns the buffer). The kernel
// mutates it in place; the round descriptor's CeremonyOpCount tells the
// kernel how many ops to consume from ceremonyOps.
//
// next_contribution_id_in is the substrate's monotonically increasing
// contribution-id counter at the start of the round; the kernel doesn't
// advance it on the ceremony-only path but the parameter is part of the
// shared launcher signature.
func (g *GPUBackend) CeremonyApply(
	desc *GPUMPCVMRoundDescriptor,
	ceremonyOps []GPUCeremonyOp,
	ceremonies []GPUCeremony,
) (applied uint32, err error) {
	// Input validation is shared across cgo / nocgo / GPU / CPU. nil
	// desc or empty arena returns ErrGPUNotAvailable so caller
	// `errors.Is(err, ErrGPUNotAvailable)` fires consistently.
	if desc == nil || len(ceremonies) == 0 {
		return 0, ErrGPUNotAvailable
	}
	// Fall through to the pure-Go reference whenever the GPU plugin
	// isn't usable: nil receiver, no dlopen handle, missing launcher
	// symbol. thresholdvm_gpu_cpu.go is byte-equivalent to the CUDA
	// kernel; the bridge ALWAYS produces a result.
	if g == nil || g.handle == nil || g.fnCeremonyApply == nil {
		return ceremonyApplyCPU(desc, ceremonyOps, ceremonies)
	}
	var (
		ceremonyApplied     uint32
		contributionApplied uint32
		emptyContribOps     [1]GPUContributionOp
		emptyContributions  [1]GPUContribution
	)
	descPtr := unsafe.Pointer(desc)
	cerOpsPtr := unsafe.Pointer(&emptyContribOps[0])
	if len(ceremonyOps) > 0 {
		cerOpsPtr = unsafe.Pointer(&ceremonyOps[0])
	}
	cerPtr := unsafe.Pointer(&ceremonies[0])
	conPtr := unsafe.Pointer(&emptyContributions[0])

	rc := C.call_ceremony_apply(
		g.fnCeremonyApply,
		descPtr,
		cerOpsPtr,
		unsafe.Pointer(&emptyContribOps[0]), // contribution_ops: empty stream
		cerPtr,
		conPtr, // contributions: 1-slot placeholder (count=1)
		unsafe.Pointer(&ceremonyApplied),
		unsafe.Pointer(&contributionApplied),
		C.uint32_t(len(ceremonies)),
		C.uint32_t(1),
		C.uint64_t(0),
		nil,
	)
	runtime.KeepAlive(desc)
	runtime.KeepAlive(ceremonyOps)
	runtime.KeepAlive(ceremonies)
	runtime.KeepAlive(emptyContribOps)
	runtime.KeepAlive(emptyContributions)
	if rc != 0 {
		// Launcher failed — fall back to the Go reference so the
		// caller still gets a correct, byte-equivalent result.
		return ceremonyApplyCPU(desc, ceremonyOps, ceremonies)
	}
	return ceremonyApplied, nil
}

// KeyShareApply runs the per-slot fan-out sweep that advances ceremonies,
// finalizes keygens (assigning canonical share_ids), and times out expired
// ceremonies. Backed by lux_<X>_mpcvm_ceremony_sweep.
//
// On DKG finalize, fresh KeyShare slots are written into keyShares with the
// share_data_len matching the scheme (Frost=65, CGGMP21=65, Corona=256).
// next_share_id_in seeds the prefix-sum scheme that gives every finalized
// share a deterministic share_id.
func (g *GPUBackend) KeyShareApply(
	desc *GPUMPCVMRoundDescriptor,
	ceremonies []GPUCeremony,
	keyShares []GPUKeyShare,
	contributions []GPUContribution,
	nextShareID uint64,
) (roundAdvance, finalized, failed uint32, err error) {
	if desc == nil || len(ceremonies) == 0 ||
		len(keyShares) == 0 || len(contributions) == 0 {
		return 0, 0, 0, ErrGPUNotAvailable
	}
	if g == nil || g.handle == nil || g.fnCeremonySweep == nil {
		return keyShareApplyCPU(desc, ceremonies, keyShares, contributions, nextShareID)
	}
	rc := C.call_ceremony_sweep(
		g.fnCeremonySweep,
		unsafe.Pointer(desc),
		unsafe.Pointer(&ceremonies[0]),
		unsafe.Pointer(&keyShares[0]),
		unsafe.Pointer(&contributions[0]),
		unsafe.Pointer(&roundAdvance),
		unsafe.Pointer(&finalized),
		unsafe.Pointer(&failed),
		C.uint32_t(len(ceremonies)),
		C.uint32_t(len(keyShares)),
		C.uint32_t(len(contributions)),
		C.uint64_t(nextShareID),
		nil,
	)
	runtime.KeepAlive(desc)
	runtime.KeepAlive(ceremonies)
	runtime.KeepAlive(keyShares)
	runtime.KeepAlive(contributions)
	if rc != 0 {
		return keyShareApplyCPU(desc, ceremonies, keyShares, contributions, nextShareID)
	}
	return roundAdvance, finalized, failed, nil
}

// ContributionApply applies contribution payloads to the contribution table.
// Ceremony slots are not touched (callers passing nil ceremonyOps get the
// lean contribution-only dispatch). Uses the same ceremony_apply kernel
// because the dedup-and-write path is the same on the device side; only
// the op stream differs.
func (g *GPUBackend) ContributionApply(
	desc *GPUMPCVMRoundDescriptor,
	contributionOps []GPUContributionOp,
	ceremonies []GPUCeremony,
	contributions []GPUContribution,
	nextContributionID uint64,
) (applied uint32, err error) {
	if desc == nil || len(ceremonies) == 0 || len(contributions) == 0 {
		return 0, ErrGPUNotAvailable
	}
	if g == nil || g.handle == nil || g.fnCeremonyApply == nil {
		return contributionApplyCPU(desc, contributionOps, ceremonies, contributions, nextContributionID)
	}
	var (
		ceremonyApplied     uint32
		contributionApplied uint32
		emptyCeremonyOps    [1]GPUCeremonyOp
	)
	conOpsPtr := unsafe.Pointer(&emptyCeremonyOps[0]) // bound buffer placeholder
	conActualOpsPtr := unsafe.Pointer(&emptyCeremonyOps[0])
	if len(contributionOps) > 0 {
		conActualOpsPtr = unsafe.Pointer(&contributionOps[0])
	}

	rc := C.call_ceremony_apply(
		g.fnCeremonyApply,
		unsafe.Pointer(desc),
		conOpsPtr, // ceremony_ops: empty stream
		conActualOpsPtr,
		unsafe.Pointer(&ceremonies[0]),
		unsafe.Pointer(&contributions[0]),
		unsafe.Pointer(&ceremonyApplied),
		unsafe.Pointer(&contributionApplied),
		C.uint32_t(len(ceremonies)),
		C.uint32_t(len(contributions)),
		C.uint64_t(nextContributionID),
		nil,
	)
	runtime.KeepAlive(desc)
	runtime.KeepAlive(emptyCeremonyOps)
	runtime.KeepAlive(contributionOps)
	runtime.KeepAlive(ceremonies)
	runtime.KeepAlive(contributions)
	if rc != 0 {
		// Launcher failed — fall back to the Go reference.
		return contributionApplyCPU(desc, contributionOps, ceremonies, contributions, nextContributionID)
	}
	return contributionApplied, nil
}

// MPCTransition runs the per-leaf keccak pass and the canonical-order fold
// pass, producing the round's MPCVMTransitionResult and advancing the
// substrate state. This is the composition of compute_leaves and
// compose_root — one substrate state transition per call.
//
// Returns the result envelope written by compose_root. The substrate state
// in `state` is also updated in place (cur_epoch, now_ns, counts, all four
// roots).
func (g *GPUBackend) MPCTransition(
	desc *GPUMPCVMRoundDescriptor,
	ceremonies []GPUCeremony,
	keyShares []GPUKeyShare,
	contributions []GPUContribution,
	state *GPUMPCVMState,
) (*GPUMPCVMTransitionResult, error) {
	if desc == nil || state == nil ||
		len(ceremonies) == 0 || len(keyShares) == 0 || len(contributions) == 0 {
		return nil, ErrGPUNotAvailable
	}
	if g == nil || g.handle == nil ||
		g.fnComputeLeaves == nil || g.fnComposeRoot == nil {
		return mpcTransitionCPU(desc, ceremonies, keyShares, contributions, state)
	}

	// Scratch buffers consumed by compute_leaves and feeding compose_root.
	// All Go-allocated, all live for the duration of both calls — pinned by
	// being on the local stack (escape-analysis-promoted to heap if needed).
	ceremonyLeaves := make([]byte, len(ceremonies)*32)
	shareLeaves := make([]byte, len(keyShares)*32)
	contributionLeaves := make([]byte, len(contributions)*32)
	ceremonyMask := make([]byte, len(ceremonies))
	shareMask := make([]byte, len(keyShares))
	contributionMask := make([]byte, len(contributions))
	var activeCount, finalizedCount, failedCount, shareCount uint32
	var result GPUMPCVMTransitionResult

	rc := C.call_compute_leaves(
		g.fnComputeLeaves,
		unsafe.Pointer(&ceremonies[0]),
		unsafe.Pointer(&keyShares[0]),
		unsafe.Pointer(&contributions[0]),
		unsafe.Pointer(&ceremonyLeaves[0]),
		unsafe.Pointer(&shareLeaves[0]),
		unsafe.Pointer(&contributionLeaves[0]),
		unsafe.Pointer(&activeCount),
		unsafe.Pointer(&finalizedCount),
		unsafe.Pointer(&failedCount),
		unsafe.Pointer(&shareCount),
		unsafe.Pointer(&ceremonyMask[0]),
		unsafe.Pointer(&shareMask[0]),
		unsafe.Pointer(&contributionMask[0]),
		C.uint32_t(len(ceremonies)),
		C.uint32_t(len(keyShares)),
		C.uint32_t(len(contributions)),
		nil,
	)
	if rc != 0 {
		// Launcher failed — fall back to the Go reference.
		return mpcTransitionCPU(desc, ceremonies, keyShares, contributions, state)
	}

	rc = C.call_compose_root(
		g.fnComposeRoot,
		unsafe.Pointer(desc),
		unsafe.Pointer(&ceremonyLeaves[0]),
		unsafe.Pointer(&shareLeaves[0]),
		unsafe.Pointer(&contributionLeaves[0]),
		unsafe.Pointer(&ceremonyMask[0]),
		unsafe.Pointer(&shareMask[0]),
		unsafe.Pointer(&contributionMask[0]),
		unsafe.Pointer(&activeCount),
		unsafe.Pointer(&finalizedCount),
		unsafe.Pointer(&failedCount),
		unsafe.Pointer(&shareCount),
		unsafe.Pointer(state),
		unsafe.Pointer(&result),
		C.uint32_t(len(ceremonies)),
		C.uint32_t(len(keyShares)),
		C.uint32_t(len(contributions)),
		nil,
	)
	runtime.KeepAlive(desc)
	runtime.KeepAlive(ceremonies)
	runtime.KeepAlive(keyShares)
	runtime.KeepAlive(contributions)
	runtime.KeepAlive(state)
	runtime.KeepAlive(ceremonyLeaves)
	runtime.KeepAlive(shareLeaves)
	runtime.KeepAlive(contributionLeaves)
	runtime.KeepAlive(ceremonyMask)
	runtime.KeepAlive(shareMask)
	runtime.KeepAlive(contributionMask)
	if rc != 0 {
		// Launcher failed — fall back to the Go reference.
		return mpcTransitionCPU(desc, ceremonies, keyShares, contributions, state)
	}
	return &result, nil
}

// =============================================================================
// Plugin loader — dlopen one candidate path, dlsym the four symbol pairs,
// fail soft if the plugin is missing or any required symbol is absent.
// Soft-fail returns nil; callers then see Backend() == nil and route to CPU.
// =============================================================================

// tryLoadPlugin attempts to dlopen the candidate filenames in order and
// resolve the four expected symbols using the given backend prefix. Returns
// non-nil only when dlopen succeeded AND ceremony_apply + ceremony_sweep
// both resolved (the minimum useful surface). compute_leaves and
// compose_root are optional at this stage — MPCTransition will surface
// ErrGPUNotAvailable when either is missing.
func tryLoadPlugin(kind GPUBackendKind, candidates ...string) *GPUBackend {
	prefix := kind.String()
	if prefix == "none" {
		return nil
	}

	var (
		ca *C.char
		cb *C.char
		cc *C.char
	)
	if len(candidates) > 0 && candidates[0] != "" {
		ca = C.CString(candidates[0])
		defer C.free(unsafe.Pointer(ca))
	}
	if len(candidates) > 1 && candidates[1] != "" {
		cb = C.CString(candidates[1])
		defer C.free(unsafe.Pointer(cb))
	}
	if len(candidates) > 2 && candidates[2] != "" {
		cc = C.CString(candidates[2])
		defer C.free(unsafe.Pointer(cc))
	}

	h := C.lux_dlopen_first(ca, cb, cc)
	if h == nil {
		return nil
	}

	resolve := func(name string) unsafe.Pointer {
		cname := C.CString(name)
		defer C.free(unsafe.Pointer(cname))
		return unsafe.Pointer(C.lux_dlsym(h, cname))
	}

	b := &GPUBackend{
		Kind:            kind,
		handle:          unsafe.Pointer(h),
		fnCeremonyApply: resolve(fmt.Sprintf("lux_%s_mpcvm_ceremony_apply", prefix)),
		fnCeremonySweep: resolve(fmt.Sprintf("lux_%s_mpcvm_ceremony_sweep", prefix)),
		fnComputeLeaves: resolve(fmt.Sprintf("lux_%s_mpcvm_compute_leaves", prefix)),
		fnComposeRoot:   resolve(fmt.Sprintf("lux_%s_mpcvm_compose_root", prefix)),
	}

	if b.fnCeremonyApply == nil || b.fnCeremonySweep == nil {
		// Required symbols missing — close the handle and return nil so the
		// probe falls through to the next backend.
		_ = C.dlclose(h)
		return nil
	}

	// Pick a resolved path string from the first non-empty candidate that
	// dlopen could have used. We don't get the resolved name back from
	// dlopen on every platform, so this is best-effort diagnostic.
	for _, c := range candidates {
		if c != "" {
			b.Path = c
			break
		}
	}
	return b
}

