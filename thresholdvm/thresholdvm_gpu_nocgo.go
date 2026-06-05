// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package thresholdvm

import "errors"

// ErrGPUNotAvailable is retained for ABI compatibility with callers
// that branch on `errors.Is(err, ErrGPUNotAvailable)`. Under !cgo the
// GPU plugin is unreachable (dlopen requires CGo), but the four
// substrate methods on GPUBackend still produce correct results by
// delegating to the pure-Go reference in thresholdvm_gpu_cpu.go. The
// sentinel is now only returned on input-validation failures (nil
// desc, empty arena) — never on a missing GPU plugin, which is no
// longer a fatal condition.
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
// Wire structs — byte-equivalent to the cgo variant and to the
// device-side __align__(16) layouts in mpcvm_kernels_common.cuh. Sizes
// are pinned by TestGPULayoutSizes (thresholdvm_gpu_test.go), which
// runs in BOTH build flavors and surfaces any drift immediately.
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

// GPUBackend is the nocgo no-op handle. Carries no resolved symbols —
// every state-machine method routes straight to the pure-Go reference
// in thresholdvm_gpu_cpu.go. IsAvailable() returns false so diagnostic
// code can still surface "thresholdvm-gpu: no plugin resolved
// (CPU-only)".
type GPUBackend struct {
	Kind GPUBackendKind
	Path string
}

// Backend always returns nil under !cgo. The bridge methods are still
// useful through a nil receiver — they delegate to the CPU reference.
func Backend() *GPUBackend { return nil }

// IsAvailable reports false for every GPUBackend under !cgo. The
// substrate methods STILL produce correct results — IsAvailable()
// only answers "is there an accelerated path?", not "can the
// substrate transition?".
func (g *GPUBackend) IsAvailable() bool { return false }

// CeremonyApply delegates to the pure-Go reference. Under !cgo there
// is no plugin to call, but the same canonical algorithm runs in Go.
func (g *GPUBackend) CeremonyApply(
	desc *GPUMPCVMRoundDescriptor,
	ceremonyOps []GPUCeremonyOp,
	ceremonies []GPUCeremony,
) (uint32, error) {
	if desc == nil || len(ceremonies) == 0 {
		return 0, ErrGPUNotAvailable
	}
	return ceremonyApplyCPU(desc, ceremonyOps, ceremonies)
}

// KeyShareApply delegates to the pure-Go reference.
func (g *GPUBackend) KeyShareApply(
	desc *GPUMPCVMRoundDescriptor,
	ceremonies []GPUCeremony,
	keyShares []GPUKeyShare,
	contributions []GPUContribution,
	nextShareID uint64,
) (uint32, uint32, uint32, error) {
	if desc == nil || len(ceremonies) == 0 || len(keyShares) == 0 || len(contributions) == 0 {
		return 0, 0, 0, ErrGPUNotAvailable
	}
	return keyShareApplyCPU(desc, ceremonies, keyShares, contributions, nextShareID)
}

// ContributionApply delegates to the pure-Go reference.
func (g *GPUBackend) ContributionApply(
	desc *GPUMPCVMRoundDescriptor,
	contributionOps []GPUContributionOp,
	ceremonies []GPUCeremony,
	contributions []GPUContribution,
	nextContributionID uint64,
) (uint32, error) {
	if desc == nil || len(ceremonies) == 0 || len(contributions) == 0 {
		return 0, ErrGPUNotAvailable
	}
	return contributionApplyCPU(desc, contributionOps, ceremonies, contributions, nextContributionID)
}

// MPCTransition delegates to the pure-Go reference.
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
	return mpcTransitionCPU(desc, ceremonies, keyShares, contributions, state)
}
