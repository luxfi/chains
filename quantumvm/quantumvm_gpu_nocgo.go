//go:build !cgo

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

// !cgo build: no plugin DSO is loadable without cgo (we cannot call
// dlopen / dlsym from pure Go), so every GPUBackend method returns
// ErrGPUNotAvailable and AutoBackend() reports BackendNone. The cgo
// build's quantumvm_gpu.go does the runtime probe; this file keeps the
// package surface identical regardless of CGO_ENABLED.

func init() {
	setActiveBackend(BackendNone)
}

// noGPUBackend is the !cgo implementation of the GPUBackend interface —
// every method returns ErrGPUNotAvailable so callers route to the CPU
// verify path cleanly.
type noGPUBackend struct{}

// ActiveGPUBackend returns the package-level GPUBackend handle. Under
// !cgo this is always a stub returning ErrGPUNotAvailable on every
// method call.
func ActiveGPUBackend() GPUBackend {
	return noGPUBackend{}
}

func (noGPUBackend) Backend() Backend { return BackendNone }

func (noGPUBackend) Close() error { return nil }

func (noGPUBackend) MLDSAVerifyBatch(
	mode MLDSAMode,
	pubkeys [][]byte,
	messages [][]byte,
	msgLens []int,
	msgWidthHint uint32,
	signatures [][]byte,
	results []bool,
) error {
	_ = mode
	_ = messages
	_ = msgLens
	_ = msgWidthHint
	_ = signatures
	_ = results
	// Empty batch is a legal no-op — match the cgo implementation's
	// short-circuit so callers don't have to special-case "no plugin
	// loaded AND empty batch" at the call site.
	if len(pubkeys) == 0 {
		return nil
	}
	return ErrGPUNotAvailable
}

func (noGPUBackend) MLDSASignBatch(
	mode MLDSAMode,
	skeys []byte,
	msgs []byte,
	msgLens []int,
	msgWidthHint uint32,
	count int,
	sigsOut []byte,
	sigLensOut []uint32,
) error {
	_ = mode
	_ = skeys
	_ = msgs
	_ = msgLens
	_ = msgWidthHint
	_ = sigsOut
	_ = sigLensOut
	if count == 0 {
		return nil
	}
	return ErrGPUNotAvailable
}

func (noGPUBackend) SLHDSAVerifyBatch(
	variant SLHDSAVariant,
	pubkeys [][]byte,
	messages [][]byte,
	msgLens []int,
	signatures [][]byte,
	results []bool,
) error {
	_ = variant
	_ = messages
	_ = msgLens
	_ = signatures
	_ = results
	if len(pubkeys) == 0 {
		return nil
	}
	return ErrGPUNotAvailable
}
