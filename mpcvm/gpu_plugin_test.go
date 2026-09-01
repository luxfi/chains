// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package mpcvm

// gpu_plugin_test.go — the dlopen bridge, driven against a real plugin.
//
// The GPU bridge is a runtime overlay: it dlopens a backend plugin, dlsyms four
// launchers, and hands them host pointers to the wire structs. What can be
// wrong here is not the arithmetic inside a kernel — that is the kernel's
// business — but the BRIDGE: whether a missing symbol is noticed, whether the
// counts the launcher receives are the ones the caller passed, and whether a
// launcher's non-zero return reaches the caller as an error instead of as a
// zero count the caller reads as success.
//
// So the plugin under test is a real shared object, compiled here, whose
// launchers ECHO what they were handed back through the output buffers the ABI
// already gives them. That exercises the same dlopen, the same dlsym and the
// same call shims a CUDA plugin would, with the kernel replaced by a mirror. No
// GPU is required and none is simulated: the arithmetic is not what this file
// is about, and pretending otherwise would be a test that passes when the
// bridge and the mirror are wrong in the same way.
//
// The mirror's contract, which the tests below read back:
//
//	rc          — every launcher returns desc->Mode (compute_leaves, which gets
//	              no descriptor, returns the low half of ceremonies[0].CeremonyID)
//	*capp       — ceremony_count       *napp  — next_contribution_id (truncated)
//	*ra         — ceremony_count       *fin   — key_share_count
//	*fai        — next_share_id (truncated)
//	result      — Status=7, ActiveCeremonyCount=ceremony_count,
//	              KeyShareCount=key_share_count; state.CurrentEpoch += 1

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

const stubSource = `
#include <stdint.h>
#include <string.h>

// The descriptor's Mode field, at offset 32, carries the return code the
// caller wants back — so one plugin covers the success and the failure path
// without a second build.
static int rc_of(const void* desc) { return (int)*(const uint32_t*)((const char*)desc + 32); }

int lux_cuda_mpcvm_ceremony_apply(
    const void* desc, const void* cops, const void* nops,
    void* cer, void* con, void* capp, void* napp,
    uint32_t cc, uint32_t nc, uint64_t next_cont, void* stream)
{
    (void)cops; (void)nops; (void)cer; (void)con; (void)stream;
    *(uint32_t*)capp = cc;
    *(uint32_t*)napp = (uint32_t)next_cont;
    return rc_of(desc);
}

int lux_cuda_mpcvm_ceremony_sweep(
    const void* desc, void* cer, void* ks, void* con,
    void* ra, void* fin, void* fai,
    uint32_t cc, uint32_t kc, uint32_t nc, uint64_t next_share, void* stream)
{
    (void)cer; (void)ks; (void)con; (void)nc; (void)stream;
    *(uint32_t*)ra = cc;
    *(uint32_t*)fin = kc;
    *(uint32_t*)fai = (uint32_t)next_share;
    return rc_of(desc);
}

int lux_cuda_mpcvm_compute_leaves(
    const void* cer, const void* ks, const void* con,
    void* cl, void* sl, void* nl,
    void* ac, void* fc, void* fac, void* sc,
    void* cm, void* sm, void* nm,
    uint32_t cc, uint32_t kc, uint32_t nc, void* stream)
{
    (void)ks; (void)con; (void)stream;
    memset(cl, 0xAA, (size_t)cc * 32);
    memset(sl, 0xBB, (size_t)kc * 32);
    memset(nl, 0xCC, (size_t)nc * 32);
    memset(cm, 1, cc); memset(sm, 1, kc); memset(nm, 1, nc);
    *(uint32_t*)ac = cc; *(uint32_t*)fc = kc; *(uint32_t*)fac = nc; *(uint32_t*)sc = kc;
    // No descriptor reaches this launcher; the first ceremony slot carries the
    // return code instead.
    return (int)*(const uint32_t*)cer;
}

int lux_cuda_mpcvm_compose_root(
    const void* desc,
    const void* cl, const void* sl, const void* nl,
    const void* cm, const void* sm, const void* nm,
    const void* ac, const void* fc, const void* fac, const void* sc,
    void* state, void* result,
    uint32_t cc, uint32_t kc, uint32_t nc, void* stream)
{
    (void)cl; (void)sl; (void)nl; (void)cm; (void)sm; (void)nm;
    (void)fc; (void)fac; (void)cc; (void)kc; (void)nc; (void)stream;
    uint32_t* out = (uint32_t*)result;
    out[0] = 7;                     // Status
    out[5] = *(const uint32_t*)ac;  // ActiveCeremonyCount
    out[6] = *(const uint32_t*)sc;  // KeyShareCount
    ((uint64_t*)state)[0] += 1;     // CurrentEpoch advances in place
    return rc_of(desc);
}
`

// stubIdentity is what makes a compiled stub a plugin tryLoadPlugin will
// trust: the init symbol the header requires, answering with the ABI version
// and vtable size this build was compiled against. A stub built without it
// exports the four launcher names and nothing else, which is precisely the
// library the loader must refuse — see TestALibraryThatOnlyExportsTheNames.
const stubIdentity = `
#include <stdbool.h>
#include "lux/gpu/backend_plugin.h"

bool lux_gpu_backend_init(lux_gpu_backend_desc* out) {
    out->abi_version     = LUX_GPU_BACKEND_ABI_VERSION;
    out->vtbl_size       = (uint32_t)sizeof(lux_gpu_backend_vtbl);
    out->backend_name    = "cuda";
    out->backend_version = "0.0.0-mirror";
    out->capabilities    = 0;
    out->vtbl            = 0;
    return true;
}
`

// pluginInclude is where the plugin header lives, relative to this package.
const pluginInclude = "-I../internal/luxgpu/include"

var (
	stubOnce sync.Once
	stubPath string
	stubAnon string
	stubErr  error
)

// stubPlugin compiles the mirror plugin once. A C compiler is present by
// construction: this file only builds under cgo, and cgo needed one.
func stubPlugin(t *testing.T) string {
	t.Helper()
	stubOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mpcvm-gpu-stub")
		if err != nil {
			stubErr = err
			return
		}
		// Two builds from one mirror: one that identifies itself, and one that
		// exports the launcher names and nothing else.
		for name, identity := range map[string]string{
			"named": stubIdentity,
			"anon":  "",
		} {
			src := filepath.Join(dir, "stub_"+name+".c")
			if err := os.WriteFile(src, []byte(stubSource+identity), 0o600); err != nil {
				stubErr = err
				return
			}
			out := filepath.Join(dir, name, "libluxgpu_backend_cuda.so")
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				stubErr = err
				return
			}
			if combined, err := exec.Command(compiler(), pluginInclude, "-shared", "-fPIC", "-o", out, src).CombinedOutput(); err != nil {
				stubErr = fmt.Errorf("%s: %w: %s", compiler(), err, combined)
				return
			}
			if name == "anon" {
				stubAnon = out
			} else {
				stubPath = out
			}
		}
	})
	require.NoError(t, stubErr)
	return stubPath
}

// stubUnidentified is the same mirror without the init symbol.
func stubUnidentified(t *testing.T) string {
	t.Helper()
	stubPlugin(t)
	return stubAnon
}

// A library exporting the four launcher names and nothing else is what an
// attacker plants. It is refused before a single launcher is resolved: the
// name was the only thing being matched, and a name is not a contract.
func TestALibraryThatOnlyExportsTheNames(t *testing.T) {
	anon := stubUnidentified(t)
	require.FileExists(t, anon, "the stub is built; it just does not identify itself")
	require.Nil(t, tryLoadPlugin(GPUBackendCUDA, anon),
		"an unidentified library is not a backend")

	// The identified build opens, so the refusal above is the identity check
	// and not a broken stub.
	b := tryLoadPlugin(GPUBackendCUDA, stubPlugin(t))
	require.NotNil(t, b)
	require.True(t, b.IsAvailable())
}

func compiler() string {
	if cc := os.Getenv("CC"); cc != "" {
		return cc
	}
	return "cc"
}

// loadStub resolves the mirror plugin through the production loader.
func loadStub(t *testing.T) *GPUBackend {
	t.Helper()
	b := tryLoadPlugin(GPUBackendCUDA, stubPlugin(t))
	require.NotNil(t, b, "the loader did not resolve a plugin exporting all four launchers")
	require.Equal(t, GPUBackendCUDA, b.Kind)
	require.Equal(t, stubPlugin(t), b.Path)
	require.True(t, b.IsAvailable())
	return b
}

// round is a descriptor whose Mode carries the return code the mirror echoes.
func round(rc uint32) *GPUMPCVMRoundDescriptor {
	return &GPUMPCVMRoundDescriptor{ChainID: 1, Round: 2, Mode: rc}
}

// -----------------------------------------------------------------------------
// Resolution
// -----------------------------------------------------------------------------

// A plugin is used only when the launchers it must export actually resolve. A
// library that dlopens but exports nothing is not a backend, and adopting one
// would call a null pointer on the first round.
func TestALibraryWithoutTheLaunchersIsNotABackend(t *testing.T) {
	require.Nil(t, tryLoadPlugin(GPUBackendCUDA, "libc.so.6", "libSystem.B.dylib"),
		"a library missing ceremony_apply/ceremony_sweep must not be adopted as a backend")
}

func TestAPluginThatIsNotThereIsNotABackend(t *testing.T) {
	require.Nil(t, tryLoadPlugin(GPUBackendCUDA, "/nonexistent/a.so", "/nonexistent/b.so", "/nonexistent/c.so"))
	require.Nil(t, tryLoadPlugin(GPUBackendCUDA))
	require.Nil(t, tryLoadPlugin(GPUBackendCUDA, "", "", ""))
	require.Nil(t, tryLoadPlugin(GPUBackendNone, "anything"),
		"a backend with no launcher prefix names no symbols to resolve")
}

// The probe walks the substrate priority order and adopts the first backend
// that resolves. A host with no plugin adopts none and runs on the CPU
// reference, rather than adopting a broken one.
func TestTheProbeAdoptsTheFirstBackendThatResolves(t *testing.T) {
	t.Setenv("LUX_GPU_PLUGIN_DIR", filepath.Dir(stubPlugin(t)))
	t.Setenv("LUXCPP_PREFIX", "/nonexistent")

	got := probeGPUBackend()
	require.NotNil(t, got)
	require.Equal(t, GPUBackendCUDA, got.Kind, "cuda is first in the substrate priority order")

	t.Setenv("LUX_GPU_PLUGIN_DIR", "/nonexistent")
	require.Nil(t, probeGPUBackend(), "a host with no plugin runs on the CPU reference")
}

// Every backend has candidate filenames, ordered: install path, then build
// tree, then the bare leaf for the dynamic linker's own search.
func TestEveryBackendHasCandidateFilenames(t *testing.T) {
	t.Setenv("LUXCPP_PREFIX", "/opt/luxcpp")
	t.Setenv("LUX_GPU_PLUGIN_DIR", "/build/plugins")

	for _, kind := range []GPUBackendKind{
		GPUBackendCUDA, GPUBackendHIP, GPUBackendMetal, GPUBackendVulkan, GPUBackendWebGPU,
	} {
		got := candidatesFor(kind)
		require.NotEmptyf(t, got, "%s has no candidate filenames", kind)
		require.Containsf(t, got[0], "/opt/luxcpp/lib/", "%s must try the install path first", kind)
		require.Truef(t, hasPrefixDir(got, "/build/plugins"), "%s must try the build tree", kind)
		require.NotContainsf(t, got, filepath.Base(got[0]),
			"%s must not offer a bare leaf: the loader would search its own path, "+
				"and a GPU plugin mints threshold-signing custody", kind)
		require.NotEmptyf(t, kind.String(), "%s has no launcher prefix", kind)
	}
	require.Empty(t, candidatesFor(GPUBackendNone))
	require.Empty(t, backendDylibLeaves(GPUBackendNone))

	// With no explicit prefix, the home-relative install tree stands in.
	t.Setenv("LUXCPP_PREFIX", "")
	t.Setenv("LUX_GPU_PLUGIN_DIR", "")
	t.Setenv("HOME", "/home/somebody")
	require.Contains(t, candidatesFor(GPUBackendCUDA)[0], "/home/somebody/work/luxcpp/install/lib/")

	// With neither, nothing remains. Every candidate came from somewhere an
	// operator named, so when nobody named anywhere there is nowhere to look.
	t.Setenv("HOME", "")
	require.Empty(t, candidatesFor(GPUBackendCUDA))
}

// -----------------------------------------------------------------------------
// The four launchers
// -----------------------------------------------------------------------------

// Each method hands the launcher the counts and buffers the caller passed, and
// returns what the launcher wrote back into them.
func TestTheBridgePassesTheCallersCountsAndReadsBackTheResult(t *testing.T) {
	b := loadStub(t)
	desc := round(0)
	ceremonies := make([]GPUCeremony, 4)
	contributions := make([]GPUContribution, 3)
	shares := make([]GPUKeyShare, 2)

	applied, err := b.CeremonyApply(desc, []GPUCeremonyOp{{CeremonyID: 9}}, ceremonies)
	require.NoError(t, err)
	require.Equal(t, uint32(len(ceremonies)), applied, "the ceremony table's length reaches the launcher")

	applied, err = b.ContributionApply(desc, []GPUContributionOp{{CeremonyID: 9}}, ceremonies, contributions, 41)
	require.NoError(t, err)
	require.Equal(t, uint32(41), applied, "the contribution-id counter reaches the launcher")

	advance, finalized, failed, err := b.KeyShareApply(desc, ceremonies, shares, contributions, 77)
	require.NoError(t, err)
	require.Equal(t, uint32(len(ceremonies)), advance)
	require.Equal(t, uint32(len(shares)), finalized)
	require.Equal(t, uint32(77), failed, "the share-id counter reaches the launcher")

	state := &GPUMPCVMState{CurrentEpoch: 5}
	result, err := b.MPCTransition(desc, ceremonies, shares, contributions, state)
	require.NoError(t, err)
	require.Equal(t, uint32(7), result.Status)
	require.Equal(t, uint32(len(ceremonies)), result.ActiveCeremonyCount,
		"the leaf pass's counts reach the fold pass")
	require.Equal(t, uint32(len(shares)), result.KeyShareCount)
	require.Equal(t, uint64(6), state.CurrentEpoch, "the substrate state advances in place")
}

// An empty op stream is a legal call: the ceremony-admin and contribution
// dispatches share one launcher and differ only in which stream is populated.
func TestAnEmptyOpStreamStillDispatches(t *testing.T) {
	b := loadStub(t)
	desc := round(0)
	ceremonies := make([]GPUCeremony, 2)
	contributions := make([]GPUContribution, 2)

	_, err := b.CeremonyApply(desc, nil, ceremonies)
	require.NoError(t, err)
	_, err = b.ContributionApply(desc, nil, ceremonies, contributions, 0)
	require.NoError(t, err)
}

// A launcher that fails is an error, not a zero count. A caller that read the
// count without the error would apply nothing and believe it applied
// everything.
func TestALauncherFailureIsAnErrorNotAZeroCount(t *testing.T) {
	b := loadStub(t)
	desc := round(4) // 4 = dispatch, in the launcher's own vocabulary
	ceremonies := make([]GPUCeremony, 1)
	contributions := make([]GPUContribution, 1)
	shares := make([]GPUKeyShare, 1)

	_, err := b.CeremonyApply(desc, []GPUCeremonyOp{{}}, ceremonies)
	require.ErrorContains(t, err, "rc=4")
	_, err = b.ContributionApply(desc, []GPUContributionOp{{}}, ceremonies, contributions, 0)
	require.ErrorContains(t, err, "rc=4")
	_, _, _, err = b.KeyShareApply(desc, ceremonies, shares, contributions, 0)
	require.ErrorContains(t, err, "rc=4")

	// Both halves of the transition report separately, so an operator knows
	// which pass failed.
	_, err = b.MPCTransition(desc, ceremonies, shares, contributions, &GPUMPCVMState{})
	require.ErrorContains(t, err, "compose_root: launcher rc=4")

	ceremonies[0].CeremonyID = 5 // the leaf pass's return code
	_, err = b.MPCTransition(round(0), ceremonies, shares, contributions, &GPUMPCVMState{})
	require.ErrorContains(t, err, "compute_leaves: launcher rc=5")
}

// An empty arena is refused before any pointer is taken. Taking &slice[0] of an
// empty slice panics, so this is what stands between an empty round and a
// crash.
func TestAnEmptyArenaIsRefusedBeforeAPointerIsTaken(t *testing.T) {
	b := loadStub(t)
	desc := round(0)
	ceremonies := make([]GPUCeremony, 1)
	contributions := make([]GPUContribution, 1)
	shares := make([]GPUKeyShare, 1)

	_, err := b.CeremonyApply(nil, nil, ceremonies)
	require.ErrorContains(t, err, "nil desc")
	_, err = b.CeremonyApply(desc, nil, nil)
	require.ErrorContains(t, err, "empty ceremonies")

	_, err = b.ContributionApply(nil, nil, ceremonies, contributions, 0)
	require.ErrorContains(t, err, "empty arena")
	_, err = b.ContributionApply(desc, nil, nil, contributions, 0)
	require.ErrorContains(t, err, "empty arena")
	_, err = b.ContributionApply(desc, nil, ceremonies, nil, 0)
	require.ErrorContains(t, err, "empty arena")

	_, _, _, err = b.KeyShareApply(nil, ceremonies, shares, contributions, 0)
	require.ErrorContains(t, err, "empty arena")
	_, _, _, err = b.KeyShareApply(desc, nil, shares, contributions, 0)
	require.ErrorContains(t, err, "empty arena")
	_, _, _, err = b.KeyShareApply(desc, ceremonies, nil, contributions, 0)
	require.ErrorContains(t, err, "empty arena")
	_, _, _, err = b.KeyShareApply(desc, ceremonies, shares, nil, 0)
	require.ErrorContains(t, err, "empty arena")

	_, err = b.MPCTransition(nil, ceremonies, shares, contributions, &GPUMPCVMState{})
	require.ErrorContains(t, err, "empty arena")
	_, err = b.MPCTransition(desc, ceremonies, shares, contributions, nil)
	require.ErrorContains(t, err, "empty arena")
	_, err = b.MPCTransition(desc, nil, shares, contributions, &GPUMPCVMState{})
	require.ErrorContains(t, err, "empty arena")
	_, err = b.MPCTransition(desc, ceremonies, nil, contributions, &GPUMPCVMState{})
	require.ErrorContains(t, err, "empty arena")
	_, err = b.MPCTransition(desc, ceremonies, shares, nil, &GPUMPCVMState{})
	require.ErrorContains(t, err, "empty arena")
}

// A plugin exporting the two required launchers but not the two the whole
// transition needs is adopted for what it can do and refuses the rest by name,
// so an early port is usable rather than silently wrong.
func TestAPartialPluginIsUsedForWhatItExports(t *testing.T) {
	b := loadStub(t)

	partial := *b
	partial.fnComputeLeaves = nil
	require.True(t, partial.IsAvailable())
	_, err := partial.MPCTransition(round(0),
		make([]GPUCeremony, 1), make([]GPUKeyShare, 1), make([]GPUContribution, 1), &GPUMPCVMState{})
	require.ErrorIs(t, err, ErrGPUNotAvailable)
	require.ErrorContains(t, err, "compute_leaves or compose_root missing")

	partial = *b
	partial.fnComposeRoot = nil
	_, err = partial.MPCTransition(round(0),
		make([]GPUCeremony, 1), make([]GPUKeyShare, 1), make([]GPUContribution, 1), &GPUMPCVMState{})
	require.ErrorIs(t, err, ErrGPUNotAvailable)
}

// hasPrefixDir reports whether any candidate lives under dir.
func hasPrefixDir(candidates []string, dir string) bool {
	for _, c := range candidates {
		if strings.HasPrefix(c, dir+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// A caller holding no backend at all asks the same question and gets the same
// answer, rather than dereferencing nothing.
func TestNoBackendIsNotAnAvailableOne(t *testing.T) {
	require.False(t, (*GPUBackend)(nil).IsAvailable())
	require.False(t, (&GPUBackend{}).IsAvailable(), "a zero backend has dlopened nothing")
}
