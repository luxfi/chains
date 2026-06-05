// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package bridgevm

// Non-cgo build of the BridgeVM GPU substrate. With CGO_ENABLED=0 we can't
// dlopen the plugin, so every GPUBackend method returns ErrGPUNotAvailable.
// The package-level AutoBackend() therefore reports BackendNone, and
// consumers (vm.go's round applier) should route to the CPU oracle.
//
// init() sets activeBackend to BackendNone explicitly — this mirrors the
// behaviour of the cgo build when the probe finds no plugin, so a caller's
// `if AutoBackend() == BackendNone { ... cpu fallback ... }` works
// identically under both build modes.

func init() {
	setActiveBackend(BackendNone)
}

// ActiveGPUBackend returns a stub GPUBackend whose methods all return
// ErrGPUNotAvailable. Always non-nil so callers can dispatch without a nil
// check — they only need to handle the ErrGPUNotAvailable sentinel from
// the call sites.
func ActiveGPUBackend() GPUBackend { return nocgoBackend{} }

type nocgoBackend struct{}

func (nocgoBackend) Backend() Backend { return BackendNone }

func (nocgoBackend) SignerApply(
	_ *BridgeVMRoundDescriptor,
	_ []SignerOp,
	_ []Signer,
) (uint32, error) {
	return 0, ErrGPUNotAvailable
}

func (nocgoBackend) LiquidityApply(
	_ *BridgeVMRoundDescriptor,
	_ []LiquidityOp,
	_ []LiquidityEntry,
) (uint32, uint64, uint64, error) {
	return 0, 0, 0, ErrGPUNotAvailable
}

func (nocgoBackend) MessageInbox(
	_ *BridgeVMRoundDescriptor,
	_ []Message,
	_ []Signer,
	_ []DailyLimit,
	_ []Message,
) (uint32, uint64, uint64, error) {
	return 0, 0, 0, ErrGPUNotAvailable
}

func (nocgoBackend) MessageOutbox(
	_ *BridgeVMRoundDescriptor,
	_ []OutboundReq,
	_ []DailyLimit,
	_ []Message,
	_ *BridgeVMEpochState,
) (uint32, uint64, uint64, error) {
	return 0, 0, 0, ErrGPUNotAvailable
}

func (nocgoBackend) BridgeTransition(
	_ *BridgeVMRoundDescriptor,
	_ []Signer,
	_ []LiquidityEntry,
	_ []DailyLimit,
	_ []Message,
	_ []Message,
	_ *BridgeVMEpochState,
	_ *BridgeVMTransitionResult,
) error {
	return ErrGPUNotAvailable
}
