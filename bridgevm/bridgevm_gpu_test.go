// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package bridgevm

// The GPU substrate's contract, without a plugin present. The other half —
// a real shared object, loaded, called, and read back — is in
// gpu_plugin_test.go, which builds one.

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// A backend tag names itself, including one that names nothing.
func TestABackendNamesItself(t *testing.T) {
	require.Equal(t, "none", BackendNone.String())
	require.Equal(t, "cuda", BackendCUDA.String())
	require.Equal(t, "hip", BackendHIP.String())
	require.Equal(t, "metal", BackendMetal.String())
	require.Equal(t, "vulkan", BackendVulkan.String())
	require.Equal(t, "webgpu", BackendWebGPU.String())
	require.Equal(t, "unknown(42)", Backend(42).String())
}

// TestActiveBackend verifies AutoBackend() is callable and returns either
// BackendNone (no plugin) or a known backend tag.
func TestActiveBackend(t *testing.T) {
	require.Contains(t,
		[]Backend{BackendNone, BackendCUDA, BackendHIP, BackendMetal, BackendVulkan, BackendWebGPU},
		AutoBackend())

	// The probe records exactly one result, and it is the one read back.
	t.Cleanup(func() { setActiveBackend(BackendNone) })
	setActiveBackend(BackendVulkan)
	require.Equal(t, BackendVulkan, AutoBackend())
	setActiveBackend(BackendNone)
	require.Equal(t, BackendNone, AutoBackend())
}

// TestStubReturnsErrGPUNotAvailable asserts the contract: when the plugin
// isn't loaded, every method returns ErrGPUNotAvailable. Constructed
// directly with tag=BackendNone so the test works regardless of whether a
// plugin happens to be on the search path.
func TestStubReturnsErrGPUNotAvailable(t *testing.T) {
	b := cgoBackend{tag: BackendNone}
	require.Equal(t, BackendNone, b.Backend())

	_, err := b.SignerApply(&BridgeVMRoundDescriptor{}, nil, make([]Signer, 1))
	require.ErrorIs(t, err, ErrGPUNotAvailable)

	_, _, _, err = b.LiquidityApply(&BridgeVMRoundDescriptor{}, nil, make([]LiquidityEntry, 1))
	require.ErrorIs(t, err, ErrGPUNotAvailable)

	_, _, _, err = b.MessageInbox(&BridgeVMRoundDescriptor{}, nil,
		make([]Signer, 1), make([]DailyLimit, 1), make([]Message, 1))
	require.ErrorIs(t, err, ErrGPUNotAvailable)

	_, _, _, err = b.MessageOutbox(&BridgeVMRoundDescriptor{}, nil,
		make([]DailyLimit, 1), make([]Message, 1), &BridgeVMEpochState{})
	require.ErrorIs(t, err, ErrGPUNotAvailable)

	err = b.BridgeTransition(&BridgeVMRoundDescriptor{},
		make([]Signer, 1), make([]LiquidityEntry, 1), make([]DailyLimit, 1),
		make([]Message, 1), make([]Message, 1),
		&BridgeVMEpochState{}, &BridgeVMTransitionResult{})
	require.ErrorIs(t, err, ErrGPUNotAvailable)

	require.True(t, errors.Is(ErrGPUNotAvailable, ErrGPUNotAvailable))
}

// TestLayoutSizesMatchHeader is the runtime-equivalent of the C++
// static_asserts in ops/bridgevm/cuda/bridgevm_kernels_common.cuh. The init()
// in backend.go already panics on drift; this test makes the assertions
// visible to `go test -v` output for CI dashboards and named per-struct so
// a diff narrows immediately to the offending type.
func TestLayoutSizesMatchHeader(t *testing.T) {
	for name, sizes := range map[string][2]uintptr{
		"Signer":                   {sizeOf[Signer](), 208},
		"LiquidityEntry":           {sizeOf[LiquidityEntry](), 80},
		"DailyLimit":               {sizeOf[DailyLimit](), 64},
		"Message":                  {sizeOf[Message](), 240},
		"BridgeVMEpochState":       {sizeOf[BridgeVMEpochState](), 240},
		"BridgeVMRoundDescriptor":  {sizeOf[BridgeVMRoundDescriptor](), 112},
		"SignerOp":                 {sizeOf[SignerOp](), 224},
		"LiquidityOp":              {sizeOf[LiquidityOp](), 64},
		"OutboundReq":              {sizeOf[OutboundReq](), 112},
		"BridgeVMTransitionResult": {sizeOf[BridgeVMTransitionResult](), 304},
	} {
		require.Equal(t, sizes[1], sizes[0], "%s size", name)
	}
}

// The offsets the C side reads, asserted here rather than only implied by the
// sizes. A struct can keep its total width while a field moves inside it,
// which is the drift a size check cannot see.
func TestLayoutOffsetsMatchHeader(t *testing.T) {
	var desc BridgeVMRoundDescriptor
	require.Equal(t, uintptr(32), unsafe.Offsetof(desc.Height))
	require.Equal(t, uintptr(40), unsafe.Offsetof(desc.Mode))
	require.Equal(t, uintptr(80), unsafe.Offsetof(desc.ParentStateRoot))

	var signer Signer
	require.Equal(t, uintptr(196), unsafe.Offsetof(signer.Occupied))
	require.Equal(t, uintptr(72), unsafe.Offsetof(signer.BLSPubKey))

	var epoch BridgeVMEpochState
	require.Zero(t, unsafe.Offsetof(epoch.CurrentEpoch))
	require.Equal(t, uintptr(208), unsafe.Offsetof(epoch.BridgeVMStateRoot))

	var result BridgeVMTransitionResult
	require.Equal(t, uintptr(96), unsafe.Offsetof(result.Epoch))
	require.Equal(t, uintptr(272), unsafe.Offsetof(result.BridgeVMStateRoot))

	var msg Message
	require.Equal(t, uintptr(64), unsafe.Offsetof(msg.AggSignature))
}

// sizeOf is a tiny generic helper to make the layout-asserts read naturally.
func sizeOf[T any]() uintptr {
	var z T
	return unsafe.Sizeof(z)
}
