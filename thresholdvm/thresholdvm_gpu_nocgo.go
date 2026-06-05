// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package thresholdvm

import "errors"

// ErrGPUNotAvailable is returned by GPUBackend methods when the build was
// produced without CGo. The thresholdvm GPU substrate is a runtime overlay
// that requires dlopen()/dlsym() — under !cgo there is no way to reach the
// host launchers, so every method on GPUBackend short-circuits to this
// error and callers fall back to the CPU reference (the Go state machine
// in protocol/, factory.go, executor.go — unchanged).
var ErrGPUNotAvailable = errors.New("thresholdvm: GPU backend not available (built without CGo)")

// GPUBackendKind mirrors the cgo variant so the package surface is
// identical regardless of build mode. Under nocgo every value is None.
type GPUBackendKind uint8

const (
	GPUBackendNone   GPUBackendKind = 0
	GPUBackendCUDA   GPUBackendKind = 1
	GPUBackendHIP    GPUBackendKind = 2
	GPUBackendMetal  GPUBackendKind = 3
	GPUBackendVulkan GPUBackendKind = 4
	GPUBackendWebGPU GPUBackendKind = 5
)

func (k GPUBackendKind) String() string { return "none" }

// =============================================================================
// Wire structs — same fields as the cgo variant so external callers that
// build with -tags '!cgo' still see the same package API. The sizes are
// not asserted here because no kernel ever runs against them.
// =============================================================================

type GPUCeremony struct {
	CeremonyID         uint64
	StartedAtNs        uint64
	DeadlineNs         uint64
	ParticipantsBitmap uint64
	Kind               uint32
	Round              uint32
	Threshold          uint32
	TotalParticipants  uint32
	Status             uint32
	ContributionCount  uint32
	Subject            [32]byte
	CeremonySeed       [32]byte
	_                  [8]byte
}

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

type GPUContributionOp struct {
	CeremonyID  uint64
	HolderAddr  uint64
	Round       uint32
	HolderIndex uint32
	PayloadLen  uint32
	Pad0        uint32
	Payload     [384]byte
}

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

// GPUBackend is the no-op nocgo placeholder. Every method returns
// ErrGPUNotAvailable; IsAvailable() returns false.
type GPUBackend struct {
	Kind GPUBackendKind
	Path string
}

// Backend always returns nil under !cgo — the bridge has no plugin to load.
func Backend() *GPUBackend { return nil }

// IsAvailable reports false for every GPUBackend under !cgo.
func (g *GPUBackend) IsAvailable() bool { return false }

func (g *GPUBackend) CeremonyApply(
	_ *GPUMPCVMRoundDescriptor,
	_ []GPUCeremonyOp,
	_ []GPUCeremony,
) (uint32, error) {
	return 0, ErrGPUNotAvailable
}

func (g *GPUBackend) KeyShareApply(
	_ *GPUMPCVMRoundDescriptor,
	_ []GPUCeremony,
	_ []GPUKeyShare,
	_ []GPUContribution,
	_ uint64,
) (uint32, uint32, uint32, error) {
	return 0, 0, 0, ErrGPUNotAvailable
}

func (g *GPUBackend) ContributionApply(
	_ *GPUMPCVMRoundDescriptor,
	_ []GPUContributionOp,
	_ []GPUCeremony,
	_ []GPUContribution,
	_ uint64,
) (uint32, error) {
	return 0, ErrGPUNotAvailable
}

func (g *GPUBackend) MPCTransition(
	_ *GPUMPCVMRoundDescriptor,
	_ []GPUCeremony,
	_ []GPUKeyShare,
	_ []GPUContribution,
	_ *GPUMPCVMState,
) (*GPUMPCVMTransitionResult, error) {
	return nil, ErrGPUNotAvailable
}
