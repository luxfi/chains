// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package bridgevm

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The plugin loader, driven against a real shared object.
//
// The GPU kernels this ABI calls live in another repository, so nothing here
// can test what they compute. What it CAN test — and what nothing tested
// before — is the boundary: that the loader finds a plugin, that it refuses
// one missing a launcher, that a call crosses into C and back, and that the
// Go structs land at the byte offsets the C side reads. The comment on those
// structs says drift would "silently corrupt every round's state root", and a
// stub that reads a field at a fixed offset and hands the value back is what
// turns that from a claim into a measurement.
//
// The stub answers the five launcher signatures and nothing else:
//   - it reads Height out of the descriptor and reports it as the applied
//     count, so a Go/C disagreement about where Height sits shows up as a
//     wrong number rather than as nothing;
//   - it writes into each output arena at a fixed offset, so the same holds
//     in the other direction;
//   - it returns the descriptor's Mode as its status code, so the error path
//     is a real launcher refusal.
const stubLauncherSource = `
#include <stdint.h>
#include <string.h>

/* Offsets into BridgeVMRoundDescriptor (112 bytes, see backend.go). */
#define DESC_HEIGHT_U64 4   /* byte 32 */
#define DESC_MODE_U32  10   /* byte 40 */

static uint64_t desc_height(const void* d) { return ((const uint64_t*)d)[DESC_HEIGHT_U64]; }
static int      desc_status(const void* d) { return (int)((const uint32_t*)d)[DESC_MODE_U32]; }

int lux_cuda_bridgevm_signer_apply(
    const void* desc, const void* ops, void* signers, void* applied_out,
    uint32_t signer_count, void* stream) {
  (void)ops; (void)stream;
  *(uint32_t*)applied_out = (uint32_t)desc_height(desc);
  if (signer_count) ((uint32_t*)signers)[49] = 1;  /* Signer.Occupied, byte 196 */
  return desc_status(desc);
}

int lux_cuda_bridgevm_liquidity_apply(
    const void* desc, const void* ops, void* liquidity, void* applied_out,
    void* total_fees_lo_out, void* total_fees_hi_out,
    uint32_t liquidity_count, void* stream) {
  (void)ops; (void)liquidity; (void)liquidity_count; (void)stream;
  *(uint32_t*)applied_out = (uint32_t)desc_height(desc);
  *(uint64_t*)total_fees_lo_out = 11;
  *(uint64_t*)total_fees_hi_out = 22;
  return desc_status(desc);
}

int lux_cuda_bridgevm_message_inbox(
    const void* desc, const void* in_msgs, void* signers, void* daily,
    void* inbox, void* applied_out, void* total_in_lo_out, void* total_in_hi_out,
    uint32_t signer_count, uint32_t daily_count, uint32_t inbox_count,
    void* stream) {
  (void)in_msgs; (void)signers; (void)daily; (void)inbox;
  (void)signer_count; (void)daily_count; (void)inbox_count; (void)stream;
  *(uint32_t*)applied_out = (uint32_t)desc_height(desc);
  *(uint64_t*)total_in_lo_out = 33;
  *(uint64_t*)total_in_hi_out = 44;
  return desc_status(desc);
}

int lux_cuda_bridgevm_message_outbox(
    const void* desc, const void* reqs, void* daily, void* outbox, void* epoch,
    void* applied_out, void* total_out_lo_out, void* total_out_hi_out,
    uint32_t daily_count, uint32_t outbox_count, void* stream) {
  (void)reqs; (void)daily; (void)outbox; (void)daily_count;
  (void)outbox_count; (void)stream;
  *(uint32_t*)applied_out = (uint32_t)desc_height(desc);
  *(uint64_t*)total_out_lo_out = 55;
  *(uint64_t*)total_out_hi_out = 66;
  *(uint64_t*)epoch = 99;  /* BridgeVMEpochState.CurrentEpoch, byte 0 */
  return desc_status(desc);
}

int lux_cuda_bridgevm_transition(
    const void* desc, void* signers, void* liquidity, void* daily,
    void* inbox, void* outbox, void* epoch, void* result,
    uint32_t signer_count, uint32_t liquidity_count, uint32_t daily_count,
    uint32_t inbox_count, uint32_t outbox_count, void* stream) {
  (void)signers; (void)liquidity; (void)daily; (void)inbox; (void)outbox;
  (void)epoch; (void)signer_count; (void)liquidity_count; (void)daily_count;
  (void)inbox_count; (void)outbox_count; (void)stream;
  ((uint64_t*)result)[12] = desc_height(desc);        /* Result.Epoch, byte 96 */
  memset((char*)result + 272, 0xAB, 32);              /* Result.BridgeVMStateRoot */
  return desc_status(desc);
}
`

// buildStub compiles src into dir/name and returns its path.
func buildStub(t *testing.T, dir, name, src string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	csrc := filepath.Join(t.TempDir(), name+".c")
	require.NoError(t, os.WriteFile(csrc, []byte(src), 0o644))

	out := filepath.Join(dir, name)
	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	cmd := exec.Command(cc, "-shared", "-fPIC", "-o", out, csrc)
	combined, err := cmd.CombinedOutput()
	require.NoError(t, err, "compiling the stub launcher: %s", combined)
	return out
}

// loadStub points the loader at a plugin tree and re-runs the probe, putting
// the package back the way it found it afterwards.
func loadStub(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("LUX_GPU_PLUGIN_DIR", dir)
	t.Setenv("LUXCPP_PREFIX", filepath.Join(t.TempDir(), "no-such-prefix"))
	t.Cleanup(func() {
		setActiveBackend(BackendNone)
		pluginHandle = nil
		fnSignerApply, fnLiquidityApply = nil, nil
		fnMessageInbox, fnMessageOutbox, fnBridgeTransit = nil, nil, nil
	})
	probePlugin()
}

// TestThePluginLoaderFindsAPluginAndRefusesAPartialOne. The search list is
// walked in order; a shared object that opens but does not carry all five
// launchers is not a backend, and the walk goes on rather than committing to
// half an ABI.
func TestThePluginLoaderFindsAPluginAndRefusesAPartialOne(t *testing.T) {
	root := t.TempDir()
	name := dsoBareName(BackendCUDA)

	// First candidate: opens, carries none of the launchers.
	buildStub(t, root, name, "int lux_unrelated_symbol(void) { return 0; }\n")
	// Second candidate: the real thing.
	buildStub(t, filepath.Join(root, BackendCUDA.String()), name, stubLauncherSource)

	loadStub(t, root)

	require.Equal(t, BackendCUDA, AutoBackend(),
		"the loader passed over a complete plugin, or committed to an incomplete one")
	require.Equal(t, BackendCUDA, ActiveGPUBackend().Backend())
	require.NotNil(t, pluginHandle)
}

// TestTheLauncherABICarriesValuesBothWays is the measurement the layout
// comments promise. The stub reads Height out of the descriptor at the byte
// offset the C header puts it at and hands it back; a Go struct that disagreed
// would return a different number, which is the drift that would otherwise
// show up as a wrong state root.
func TestTheLauncherABICarriesValuesBothWays(t *testing.T) {
	root := t.TempDir()
	buildStub(t, root, dsoBareName(BackendCUDA), stubLauncherSource)
	loadStub(t, root)
	require.Equal(t, BackendCUDA, AutoBackend())

	b := ActiveGPUBackend()
	desc := &BridgeVMRoundDescriptor{Height: 7}

	signers := make([]Signer, 4)
	applied, err := b.SignerApply(desc, make([]SignerOp, 1), signers)
	require.NoError(t, err)
	require.Equal(t, uint32(7), applied, "the descriptor's Height is not where C reads it")
	require.Equal(t, uint32(1), signers[0].Occupied, "Signer.Occupied is not where C writes it")

	applied, feesLo, feesHi, err := b.LiquidityApply(desc, make([]LiquidityOp, 1), make([]LiquidityEntry, 2))
	require.NoError(t, err)
	require.Equal(t, uint32(7), applied)
	require.Equal(t, uint64(11), feesLo)
	require.Equal(t, uint64(22), feesHi)

	applied, inLo, inHi, err := b.MessageInbox(desc, make([]Message, 1),
		make([]Signer, 1), make([]DailyLimit, 1), make([]Message, 1))
	require.NoError(t, err)
	require.Equal(t, uint32(7), applied)
	require.Equal(t, uint64(33), inLo)
	require.Equal(t, uint64(44), inHi)

	epoch := &BridgeVMEpochState{}
	applied, outLo, outHi, err := b.MessageOutbox(desc, make([]OutboundReq, 1),
		make([]DailyLimit, 1), make([]Message, 1), epoch)
	require.NoError(t, err)
	require.Equal(t, uint32(7), applied)
	require.Equal(t, uint64(55), outLo)
	require.Equal(t, uint64(66), outHi)
	require.Equal(t, uint64(99), epoch.CurrentEpoch, "EpochState.CurrentEpoch is not where C writes it")

	result := &BridgeVMTransitionResult{}
	require.NoError(t, b.BridgeTransition(desc, make([]Signer, 1), make([]LiquidityEntry, 1),
		make([]DailyLimit, 1), make([]Message, 1), make([]Message, 1), epoch, result))
	require.Equal(t, uint64(7), result.Epoch, "TransitionResult.Epoch is not where C writes it")
	require.Equal(t, byte(0xAB), result.BridgeVMStateRoot[0],
		"TransitionResult.BridgeVMStateRoot is not where C writes it")
	require.Equal(t, byte(0xAB), result.BridgeVMStateRoot[31])
}

// A launcher that refuses reports why, with the code it returned.
func TestALauncherRefusalIsAnError(t *testing.T) {
	root := t.TempDir()
	buildStub(t, root, dsoBareName(BackendCUDA), stubLauncherSource)
	loadStub(t, root)

	b := ActiveGPUBackend()
	refuse := &BridgeVMRoundDescriptor{Height: 1, Mode: 3}

	_, err := b.SignerApply(refuse, make([]SignerOp, 1), make([]Signer, 1))
	require.ErrorContains(t, err, "signer_apply launcher returned code 3")

	_, _, _, err = b.LiquidityApply(refuse, nil, make([]LiquidityEntry, 1))
	require.ErrorContains(t, err, "liquidity_apply launcher returned code 3")

	_, _, _, err = b.MessageInbox(refuse, nil, make([]Signer, 1), make([]DailyLimit, 1), make([]Message, 1))
	require.ErrorContains(t, err, "message_inbox launcher returned code 3")

	_, _, _, err = b.MessageOutbox(refuse, nil, make([]DailyLimit, 1), make([]Message, 1), &BridgeVMEpochState{})
	require.ErrorContains(t, err, "message_outbox launcher returned code 3")

	err = b.BridgeTransition(refuse, make([]Signer, 1), make([]LiquidityEntry, 1),
		make([]DailyLimit, 1), make([]Message, 1), make([]Message, 1),
		&BridgeVMEpochState{}, &BridgeVMTransitionResult{})
	require.ErrorContains(t, err, "transition launcher returned code 3")
}

// A launcher call with nothing to work on is refused here rather than handed
// to C as a null pointer.
func TestALauncherIsNotCalledWithNothing(t *testing.T) {
	root := t.TempDir()
	buildStub(t, root, dsoBareName(BackendCUDA), stubLauncherSource)
	loadStub(t, root)

	b := ActiveGPUBackend()
	_, err := b.SignerApply(nil, nil, make([]Signer, 1))
	require.ErrorContains(t, err, "requires non-nil desc")
	_, err = b.SignerApply(&BridgeVMRoundDescriptor{}, nil, nil)
	require.ErrorContains(t, err, "non-empty signers")

	_, _, _, err = b.LiquidityApply(&BridgeVMRoundDescriptor{}, nil, nil)
	require.ErrorContains(t, err, "non-empty liquidity")

	_, _, _, err = b.MessageInbox(&BridgeVMRoundDescriptor{}, nil, nil, nil, nil)
	require.ErrorContains(t, err, "non-empty signers/daily/inbox")

	_, _, _, err = b.MessageOutbox(&BridgeVMRoundDescriptor{}, nil, nil, nil, nil)
	require.ErrorContains(t, err, "non-empty daily/outbox")

	err = b.BridgeTransition(&BridgeVMRoundDescriptor{}, nil, nil, nil, nil, nil, nil, nil)
	require.ErrorContains(t, err, "non-empty arrays")
}

// With nothing on the search path the loader commits to nothing, and every
// call says so rather than dispatching into a plugin that is not there.
func TestNoPluginMeansNoBackend(t *testing.T) {
	loadStub(t, filepath.Join(t.TempDir(), "empty"))
	require.Equal(t, BackendNone, AutoBackend())
	require.Nil(t, pluginHandle)

	_, err := ActiveGPUBackend().SignerApply(&BridgeVMRoundDescriptor{}, nil, make([]Signer, 1))
	require.ErrorIs(t, err, ErrGPUNotAvailable)
}

// The search list is what the documented one says it is, in order.
func TestThePluginSearchList(t *testing.T) {
	t.Setenv("LUX_GPU_PLUGIN_DIR", "/plugins")
	t.Setenv("LUXCPP_PREFIX", "/opt/lux")
	cwd, err := os.Getwd()
	require.NoError(t, err)

	name := dsoBareName(BackendCUDA)
	require.Equal(t, []string{
		filepath.Join("/plugins", name),
		filepath.Join("/plugins", "cuda", name),
		filepath.Join("/opt/lux", "lib", "lux-gpu", name),
		filepath.Join("/opt/lux", "lib", name),
		filepath.Join(cwd, name),
	}, candidatePluginPaths(BackendCUDA))

	t.Setenv("LUX_GPU_PLUGIN_DIR", "")
	t.Setenv("LUXCPP_PREFIX", "")
	require.Equal(t, []string{filepath.Join(cwd, name)}, candidatePluginPaths(BackendCUDA))

	// An absolute path that is not there is skipped without a dlopen; a bare
	// name is left to the loader's own search.
	require.False(t, plausiblePath("/no/such/plugin.so"))
	require.True(t, plausiblePath(name))
	require.True(t, plausiblePath(cwd))
}

// Every backend names one shared object, and the names do not collide.
func TestEveryBackendNamesOneObject(t *testing.T) {
	seen := map[string]Backend{}
	for _, bk := range []Backend{BackendCUDA, BackendHIP, BackendMetal, BackendVulkan, BackendWebGPU} {
		name := dsoBareName(bk)
		require.Contains(t, name, bk.String())
		prior, dup := seen[name]
		require.False(t, dup, "%s and %s name the same object", bk, prior)
		seen[name] = bk
	}
	require.Len(t, seen, 5)
}
