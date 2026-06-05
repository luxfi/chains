// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thresholdvm

// Pure-Go MPCVM reference implementation. Byte-equivalent to
// luxcpp/mpcvm/src/mpcvm_cpu_reference.cpp and to the per-backend GPU
// kernels at lux-private/gpu-kernels/ops/mpcvm/<X>/. There is ONE Go
// state machine for the GPU-ABI struct layout; the cgo bridge wraps it
// in a try-GPU-first-then-CPU fallback, the nocgo bridge invokes it
// directly. No build tags here — both flavors compile this file.
//
// Algorithm provenance:
//
//   1. CeremonyApply        ← apply_ceremony_ops + apply_contribution_ops
//                              (begin/cancel + contribution dedup) from
//                              mpcvm_cpu_reference.cpp::run_reference.
//                            This file's ceremonyApplyCPU runs the
//                            ceremony_ops side; contributionApplyCPU runs
//                            the contribution_ops side. Identical Go
//                            implementation, dispatched via empty op
//                            streams in the bridge wrappers.
//
//   2. KeyShareApply        ← run_ceremony_step (sweep that advances
//                              ceremonies, emits keygen shares on
//                              finalize, fails ceremonies past deadline).
//
//   3. ContributionApply    ← see #1.
//
//   4. MPCTransition        ← compute_ceremony_root + compute_key_share_root
//                              + compute_contribution_root + close_round
//                              (parallel-then-serial fold in the GPU
//                              version; serial-only in pure Go, same
//                              byte output).
//
// keccak256 is the same Keccak-f[1600] / 0x01 padding / 0x80 final used
// by every backend kernel. The Go implementation uses
// golang.org/x/crypto/sha3.NewLegacyKeccak256 — the canonical Lux Go
// Keccak256 wrapper (see geth/eth/protocols/snap/sync_test.go, bridge,
// consensus). All struct field ordering and offsets MUST match the
// __align__(16) layouts in mpcvm_kernels_common.cuh — the layout
// assertions at the top of thresholdvm_gpu.go pin this at init().

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/sha3"
)

// =============================================================================
// On-wire constants — must match
// lux-private/gpu-kernels/ops/mpcvm/cuda/mpcvm_kernels_common.cuh.
// "Corona" naming reflects the LP-077 sweep that renamed R-LWE threshold
// from "Ringtail" → "Corona" (memory note 2026-06).
// =============================================================================

const (
	cpuCeremonyStatusFree       uint32 = 0
	cpuCeremonyStatusInProgress uint32 = 1
	cpuCeremonyStatusFinalized  uint32 = 2
	cpuCeremonyStatusFailed     uint32 = 3

	cpuCeremonyOpBegin  uint32 = 0
	cpuCeremonyOpCancel uint32 = 1

	cpuKindFrostKeygen   uint32 = 0
	cpuKindFrostSign     uint32 = 1
	cpuKindCggmp21Keygen uint32 = 2
	cpuKindCggmp21Sign   uint32 = 3
	cpuKindCoronaDkg     uint32 = 4
	cpuKindCoronaSign    uint32 = 5

	cpuFrostKeygenRounds   uint32 = 3
	cpuFrostSignRounds     uint32 = 2
	cpuCggmp21KeygenRounds uint32 = 3
	cpuCggmp21SignRounds   uint32 = 5
	cpuCoronaDkgRounds     uint32 = 2
	cpuCoronaSignRounds    uint32 = 2

	cpuSchemeFrost   uint32 = 0
	cpuSchemeCggmp21 uint32 = 1
	cpuSchemeCorona  uint32 = 2

	cpuContributionStatusFree     uint32 = 0
	cpuContributionStatusAccepted uint32 = 1

	cpuContributionPayloadMax uint32 = 384

	cpuFNVOffset uint64 = 0xcbf29ce484222325
	cpuFNVPrime  uint64 = 0x100000001b3

	cpuGoldenRatio uint64 = 0x9E3779B97F4A7C15
)

// errCPUNoSlot is the substrate's internal "table full" sentinel. Not
// surfaced on the bridge happy path — open-addressing dead-ends are
// at-capacity events the host chain must avoid.
var errCPUNoSlot = errors.New("thresholdvm: open-addressing table full")

// =============================================================================
// keccak256 — same Keccak-f[1600] / 0x01 padding / 0x80 final used by
// the device kernels.
// =============================================================================

func keccak256CPU(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// =============================================================================
// Open-addressing locators — mirror the GPU recipes.
// =============================================================================

func ceremonyIndexHashCPU(ceremonyID uint64, mask uint32) uint32 {
	h := cpuFNVOffset
	h = (h ^ ceremonyID) * cpuFNVPrime
	return uint32(h) & mask
}

func ceremonyLocateCPU(tab []GPUCeremony, cid uint64, insertIfMissing bool) (uint32, bool) {
	n := uint32(len(tab))
	if n == 0 || n&(n-1) != 0 {
		return 0, false
	}
	mask := n - 1
	idx := ceremonyIndexHashCPU(cid, mask)
	for probe := uint32(0); probe < n; probe++ {
		s := &tab[idx]
		if s.Status == cpuCeremonyStatusFree {
			if insertIfMissing {
				*s = GPUCeremony{}
				s.CeremonyID = cid
				s.Status = cpuCeremonyStatusInProgress
				return idx, true
			}
			return 0, false
		}
		if s.CeremonyID == cid {
			return idx, true
		}
		idx = (idx + 1) & mask
	}
	return 0, false
}

func contributionLocateCPU(tab []GPUContribution, cid uint64, round, holder uint32, insertIfMissing bool) (uint32, bool) {
	n := uint32(len(tab))
	if n == 0 || n&(n-1) != 0 {
		return 0, false
	}
	mask := n - 1
	composite := cid ^ ((uint64(round) << 32) | uint64(holder))
	composite ^= cpuGoldenRatio + (cid << 6) + (cid >> 2)
	idx := uint32(composite) & mask
	for probe := uint32(0); probe < n; probe++ {
		s := &tab[idx]
		if s.Status == cpuContributionStatusFree {
			if insertIfMissing {
				*s = GPUContribution{}
				s.CeremonyID = cid
				s.Round = round
				s.HolderIndex = holder
				s.Status = cpuContributionStatusAccepted
				return idx, true
			}
			return 0, false
		}
		if s.CeremonyID == cid && s.Round == round && s.HolderIndex == holder {
			return idx, true
		}
		idx = (idx + 1) & mask
	}
	return 0, false
}

func keyShareLocateFreeCPU(tab []GPUKeyShare, cid uint64, holder uint32) (uint32, bool) {
	n := uint32(len(tab))
	if n == 0 || n&(n-1) != 0 {
		return 0, false
	}
	mask := n - 1
	composite := cid ^ ((uint64(holder) + cpuGoldenRatio) + (cid << 6) + (cid >> 2))
	idx := uint32(composite) & mask
	for probe := uint32(0); probe < n; probe++ {
		s := &tab[idx]
		if s.Occupied == 0 {
			return idx, true
		}
		if s.CeremonyID == cid && s.HolderIndex == holder {
			return idx, true
		}
		idx = (idx + 1) & mask
	}
	return 0, false
}

// =============================================================================
// Per-kind round counts and share metadata.
// =============================================================================

func totalRoundsForCPU(kind uint32) uint32 {
	switch kind {
	case cpuKindFrostKeygen:
		return cpuFrostKeygenRounds
	case cpuKindFrostSign:
		return cpuFrostSignRounds
	case cpuKindCggmp21Keygen:
		return cpuCggmp21KeygenRounds
	case cpuKindCggmp21Sign:
		return cpuCggmp21SignRounds
	case cpuKindCoronaDkg:
		return cpuCoronaDkgRounds
	case cpuKindCoronaSign:
		return cpuCoronaSignRounds
	default:
		return 1
	}
}

func isKeygenKindCPU(kind uint32) bool {
	return kind == cpuKindFrostKeygen ||
		kind == cpuKindCggmp21Keygen ||
		kind == cpuKindCoronaDkg
}

func schemeForKindCPU(kind uint32) uint32 {
	switch kind {
	case cpuKindFrostKeygen, cpuKindFrostSign:
		return cpuSchemeFrost
	case cpuKindCggmp21Keygen, cpuKindCggmp21Sign:
		return cpuSchemeCggmp21
	default:
		return cpuSchemeCorona
	}
}

func shareDataLenForSchemeCPU(scheme uint32) uint32 {
	switch scheme {
	case cpuSchemeFrost, cpuSchemeCggmp21:
		return 65
	default:
		return 256
	}
}

func countContributionsCPU(tab []GPUContribution, cid uint64, round uint32) uint32 {
	var n uint32
	for i := range tab {
		c := &tab[i]
		if c.Status != cpuContributionStatusAccepted {
			continue
		}
		if c.CeremonyID == cid && c.Round == round {
			n++
		}
	}
	return n
}

// =============================================================================
// ceremonyApplyOpsCPU — begin / cancel ops.
// =============================================================================

func ceremonyApplyOpsCPU(
	desc *GPUMPCVMRoundDescriptor,
	ops []GPUCeremonyOp,
	ceremonies []GPUCeremony,
) uint32 {
	if desc == nil {
		return 0
	}
	count := desc.CeremonyOpCount
	if int(count) > len(ops) {
		count = uint32(len(ops))
	}
	var applied uint32
	for i := uint32(0); i < count; i++ {
		op := &ops[i]
		switch op.Kind {
		case cpuCeremonyOpBegin:
			if op.Threshold == 0 || op.Threshold > op.TotalParticipants {
				continue
			}
			if op.TotalParticipants > 64 {
				continue
			}
			idx, ok := ceremonyLocateCPU(ceremonies, op.CeremonyID, true)
			if !ok {
				continue
			}
			c := &ceremonies[idx]
			c.Kind = op.CeremonyKind
			c.Threshold = op.Threshold
			c.TotalParticipants = op.TotalParticipants
			c.DeadlineNs = op.DeadlineNs
			c.Round = 0
			c.ContributionCount = 0
			c.ParticipantsBitmap = 0
			c.Status = cpuCeremonyStatusInProgress
			copy(c.Subject[:], op.Subject[:])
			copy(c.CeremonySeed[:], op.CeremonySeed[:])
			applied++
		case cpuCeremonyOpCancel:
			idx, ok := ceremonyLocateCPU(ceremonies, op.CeremonyID, false)
			if !ok {
				continue
			}
			c := &ceremonies[idx]
			if c.Status != cpuCeremonyStatusInProgress {
				continue
			}
			c.Status = cpuCeremonyStatusFailed
			applied++
		}
	}
	return applied
}

// =============================================================================
// contributionApplyOpsCPU — contribution dedup + insert.
// =============================================================================

func contributionApplyOpsCPU(
	desc *GPUMPCVMRoundDescriptor,
	ops []GPUContributionOp,
	ceremonies []GPUCeremony,
	contributions []GPUContribution,
	nextContributionIDIn uint64,
) (applied uint32, nextContributionIDOut uint64) {
	if desc == nil {
		return 0, nextContributionIDIn
	}
	count := desc.ContributionOpCount
	if int(count) > len(ops) {
		count = uint32(len(ops))
	}
	nextID := nextContributionIDIn
	for i := uint32(0); i < count; i++ {
		op := &ops[i]
		if op.PayloadLen > cpuContributionPayloadMax {
			continue
		}
		cidx, ok := ceremonyLocateCPU(ceremonies, op.CeremonyID, false)
		if !ok {
			continue
		}
		c := &ceremonies[cidx]
		if c.Status != cpuCeremonyStatusInProgress {
			continue
		}
		if op.Round != c.Round {
			continue
		}
		if op.HolderIndex >= c.TotalParticipants {
			continue
		}
		if _, found := contributionLocateCPU(contributions, op.CeremonyID, op.Round, op.HolderIndex, false); found {
			continue
		}
		nidx, ok := contributionLocateCPU(contributions, op.CeremonyID, op.Round, op.HolderIndex, true)
		if !ok {
			continue
		}
		cn := &contributions[nidx]
		cn.ContributionID = nextID
		nextID++
		cn.HolderAddr = op.HolderAddr
		cn.PayloadLen = op.PayloadLen
		copy(cn.Payload[:op.PayloadLen], op.Payload[:op.PayloadLen])

		bit := uint64(1) << op.HolderIndex
		if c.ParticipantsBitmap&bit == 0 {
			c.ParticipantsBitmap |= bit
			c.ContributionCount = countContributionsCPU(contributions, op.CeremonyID, op.Round)
		}
		applied++
	}
	return applied, nextID
}

// =============================================================================
// emitKeygenSharesCPU — emit keccak-derived shares for a finalized
// keygen ceremony.
// =============================================================================

func emitKeygenSharesCPU(c *GPUCeremony, contributions []GPUContribution, shares []GPUKeyShare, nextShareIDIn uint64) uint64 {
	scheme := schemeForKindCPU(c.Kind)
	outLen := shareDataLenForSchemeCPU(scheme)
	totalRounds := totalRoundsForCPU(c.Kind)
	nextID := nextShareIDIn

	for holder := uint32(0); holder < c.TotalParticipants; holder++ {
		bit := uint64(1) << holder
		if c.ParticipantsBitmap&bit == 0 {
			continue
		}

		buf := make([]byte, 0, 32+8+4+14+int(totalRounds)*64)
		buf = append(buf, c.CeremonySeed[:]...)
		var u64 [8]byte
		binary.LittleEndian.PutUint64(u64[:], c.CeremonyID)
		buf = append(buf, u64[:]...)
		var u32 [4]byte
		binary.LittleEndian.PutUint32(u32[:], holder)
		buf = append(buf, u32[:]...)
		buf = append(buf, []byte("MPCVM-SHARE-V1")...)

		for r := uint32(0); r < totalRounds; r++ {
			cidx, ok := contributionLocateCPU(contributions, c.CeremonyID, r, holder, false)
			if !ok {
				continue
			}
			cn := &contributions[cidx]
			buf = append(buf, cn.Payload[:cn.PayloadLen]...)
		}

		kidx, ok := keyShareLocateFreeCPU(shares, c.CeremonyID, holder)
		if !ok {
			continue
		}
		ks := &shares[kidx]
		if ks.Occupied == 0 {
			ks.ShareID = nextID
			nextID++
			ks.CeremonyID = c.CeremonyID
			ks.HolderIndex = holder
			ks.Scheme = scheme
			ks.Occupied = 1
		}
		ks.ShareDataLen = outLen

		prev := keccak256CPU(buf)
		var written uint32
		for written < outLen {
			take := outLen - written
			if take > 32 {
				take = 32
			}
			copy(ks.ShareData[written:written+take], prev[:take])
			written += take
			if written < outLen {
				ext := make([]byte, 33)
				copy(ext[:32], prev[:])
				ext[32] = byte(written / 32)
				prev = keccak256CPU(ext)
			}
		}
	}
	return nextID
}

// =============================================================================
// keyShareApplySweepCPU — Phase 3 sweep.
// =============================================================================

func keyShareApplySweepCPU(
	desc *GPUMPCVMRoundDescriptor,
	ceremonies []GPUCeremony,
	keyShares []GPUKeyShare,
	contributions []GPUContribution,
	nextShareIDIn uint64,
) (roundAdvance, finalized, failed uint32, nextShareIDOut uint64) {
	nextID := nextShareIDIn
	for i := range ceremonies {
		c := &ceremonies[i]
		if c.Status != cpuCeremonyStatusInProgress {
			continue
		}
		inRound := countContributionsCPU(contributions, c.CeremonyID, c.Round)
		c.ContributionCount = inRound
		if inRound >= c.Threshold {
			totalRounds := totalRoundsForCPU(c.Kind)
			c.Round++
			roundAdvance++
			if c.Round >= totalRounds {
				c.Status = cpuCeremonyStatusFinalized
				finalized++
				if isKeygenKindCPU(c.Kind) {
					nextID = emitKeygenSharesCPU(c, contributions, keyShares, nextID)
				}
			} else {
				c.ParticipantsBitmap = 0
				c.ContributionCount = 0
			}
			continue
		}
		if desc != nil && desc.TimestampNs > c.DeadlineNs {
			c.Status = cpuCeremonyStatusFailed
			failed++
		}
	}
	return roundAdvance, finalized, failed, nextID
}

// =============================================================================
// Leaf encoding + root composition.
// =============================================================================

func computeCeremonyRootCPU(ceremonies []GPUCeremony) (root [32]byte, active, finalized, failed uint32) {
	var acc [32]byte
	for i := range ceremonies {
		c := &ceremonies[i]
		if c.Status == cpuCeremonyStatusFree {
			continue
		}
		switch c.Status {
		case cpuCeremonyStatusInProgress:
			active++
		case cpuCeremonyStatusFinalized:
			finalized++
		case cpuCeremonyStatusFailed:
			failed++
		}

		const leafLen = 8 + 8 + 8 + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 32 + 32 + 4
		var leaf [leafLen]byte
		o := 0
		binary.LittleEndian.PutUint64(leaf[o:], c.CeremonyID)
		o += 8
		binary.LittleEndian.PutUint64(leaf[o:], c.StartedAtNs)
		o += 8
		binary.LittleEndian.PutUint64(leaf[o:], c.DeadlineNs)
		o += 8
		binary.LittleEndian.PutUint64(leaf[o:], c.ParticipantsBitmap)
		o += 8
		binary.LittleEndian.PutUint32(leaf[o:], c.Kind)
		o += 4
		binary.LittleEndian.PutUint32(leaf[o:], c.Round)
		o += 4
		binary.LittleEndian.PutUint32(leaf[o:], c.Threshold)
		o += 4
		binary.LittleEndian.PutUint32(leaf[o:], c.TotalParticipants)
		o += 4
		binary.LittleEndian.PutUint32(leaf[o:], c.Status)
		o += 4
		binary.LittleEndian.PutUint32(leaf[o:], c.ContributionCount)
		o += 4
		copy(leaf[o:o+32], c.Subject[:])
		o += 32
		copy(leaf[o:o+32], c.CeremonySeed[:])
		o += 32
		binary.LittleEndian.PutUint32(leaf[o:], uint32(i))

		leafHash := keccak256CPU(leaf[:])
		var buf [64]byte
		copy(buf[:32], acc[:])
		copy(buf[32:], leafHash[:])
		acc = keccak256CPU(buf[:])
	}
	return acc, active, finalized, failed
}

func computeKeyShareRootCPU(shares []GPUKeyShare) (root [32]byte, shareCount uint32) {
	var acc [32]byte
	for i := range shares {
		s := &shares[i]
		if s.Occupied == 0 {
			continue
		}
		shareCount++

		leafLen := 8 + 8 + 8 + 4 + 4 + 4 + int(s.ShareDataLen) + 4
		leaf := make([]byte, leafLen)
		o := 0
		binary.LittleEndian.PutUint64(leaf[o:], s.ShareID)
		o += 8
		binary.LittleEndian.PutUint64(leaf[o:], s.CeremonyID)
		o += 8
		binary.LittleEndian.PutUint64(leaf[o:], s.HolderAddr)
		o += 8
		binary.LittleEndian.PutUint32(leaf[o:], s.Scheme)
		o += 4
		binary.LittleEndian.PutUint32(leaf[o:], s.HolderIndex)
		o += 4
		binary.LittleEndian.PutUint32(leaf[o:], s.ShareDataLen)
		o += 4
		copy(leaf[o:o+int(s.ShareDataLen)], s.ShareData[:s.ShareDataLen])
		o += int(s.ShareDataLen)
		binary.LittleEndian.PutUint32(leaf[o:], uint32(i))

		leafHash := keccak256CPU(leaf)
		var buf [64]byte
		copy(buf[:32], acc[:])
		copy(buf[32:], leafHash[:])
		acc = keccak256CPU(buf[:])
	}
	return acc, shareCount
}

func computeContributionRootCPU(contributions []GPUContribution) [32]byte {
	var acc [32]byte
	for i := range contributions {
		c := &contributions[i]
		if c.Status != cpuContributionStatusAccepted {
			continue
		}

		leafLen := 8 + 8 + 8 + 4 + 4 + 4 + int(c.PayloadLen) + 4
		leaf := make([]byte, leafLen)
		o := 0
		binary.LittleEndian.PutUint64(leaf[o:], c.ContributionID)
		o += 8
		binary.LittleEndian.PutUint64(leaf[o:], c.CeremonyID)
		o += 8
		binary.LittleEndian.PutUint64(leaf[o:], c.HolderAddr)
		o += 8
		binary.LittleEndian.PutUint32(leaf[o:], c.Round)
		o += 4
		binary.LittleEndian.PutUint32(leaf[o:], c.HolderIndex)
		o += 4
		binary.LittleEndian.PutUint32(leaf[o:], c.PayloadLen)
		o += 4
		copy(leaf[o:o+int(c.PayloadLen)], c.Payload[:c.PayloadLen])
		o += int(c.PayloadLen)
		binary.LittleEndian.PutUint32(leaf[o:], uint32(i))

		leafHash := keccak256CPU(leaf)
		var buf [64]byte
		copy(buf[:32], acc[:])
		copy(buf[32:], leafHash[:])
		acc = keccak256CPU(buf[:])
	}
	return acc
}

func closeRoundCPU(
	desc *GPUMPCVMRoundDescriptor,
	state *GPUMPCVMState,
	ceremonies []GPUCeremony,
	keyShares []GPUKeyShare,
	contributions []GPUContribution,
) GPUMPCVMTransitionResult {
	var r GPUMPCVMTransitionResult

	cerRoot, active, finalized, failed := computeCeremonyRootCPU(ceremonies)
	state.CeremonyRoot = cerRoot
	state.ActiveCeremonyCount = active
	state.FinalizedCeremonyCount = finalized
	state.FailedCeremonyCount = failed

	shareRoot, shareCount := computeKeyShareRootCPU(keyShares)
	state.KeyShareRoot = shareRoot
	state.KeyShareCount = shareCount

	state.ContributionRoot = computeContributionRootCPU(contributions)

	state.NowNs = desc.TimestampNs
	if desc.ClosingFlag != 0 {
		state.CurrentEpoch = desc.Epoch + 1
	}

	const composedLen = 32 + 32 + 32 + 32 + 8 + 8 + 4 + 4 + 4 + 4
	var composed [composedLen]byte
	o := 0
	copy(composed[o:o+32], desc.ParentStateRoot[:])
	o += 32
	copy(composed[o:o+32], state.CeremonyRoot[:])
	o += 32
	copy(composed[o:o+32], state.KeyShareRoot[:])
	o += 32
	copy(composed[o:o+32], state.ContributionRoot[:])
	o += 32
	binary.LittleEndian.PutUint64(composed[o:], state.CurrentEpoch)
	o += 8
	binary.LittleEndian.PutUint64(composed[o:], state.NowNs)
	o += 8
	binary.LittleEndian.PutUint32(composed[o:], state.ActiveCeremonyCount)
	o += 4
	binary.LittleEndian.PutUint32(composed[o:], state.FinalizedCeremonyCount)
	o += 4
	binary.LittleEndian.PutUint32(composed[o:], state.FailedCeremonyCount)
	o += 4
	binary.LittleEndian.PutUint32(composed[o:], state.KeyShareCount)
	state.MPCVMStateRoot = keccak256CPU(composed[:])

	r.CeremonyRoot = state.CeremonyRoot
	r.KeyShareRoot = state.KeyShareRoot
	r.ContributionRoot = state.ContributionRoot
	r.MPCVMStateRoot = state.MPCVMStateRoot
	r.ActiveCeremonyCount = active
	r.KeyShareCount = shareCount
	r.Epoch = state.CurrentEpoch
	r.NowNs = state.NowNs
	r.Status = 1
	return r
}

// =============================================================================
// Public Go-side reference methods.
// =============================================================================

// ceremonyApplyCPU runs the begin/cancel-only path.
func ceremonyApplyCPU(
	desc *GPUMPCVMRoundDescriptor,
	ceremonyOps []GPUCeremonyOp,
	ceremonies []GPUCeremony,
) (uint32, error) {
	if desc == nil || len(ceremonies) == 0 {
		return 0, errCPUNoSlot
	}
	return ceremonyApplyOpsCPU(desc, ceremonyOps, ceremonies), nil
}

// contributionApplyCPU runs the round-contribution-only path.
func contributionApplyCPU(
	desc *GPUMPCVMRoundDescriptor,
	contributionOps []GPUContributionOp,
	ceremonies []GPUCeremony,
	contributions []GPUContribution,
	nextContributionID uint64,
) (uint32, error) {
	if desc == nil || len(ceremonies) == 0 || len(contributions) == 0 {
		return 0, errCPUNoSlot
	}
	applied, _ := contributionApplyOpsCPU(desc, contributionOps, ceremonies, contributions, nextContributionID)
	return applied, nil
}

// keyShareApplyCPU runs the per-slot sweep.
func keyShareApplyCPU(
	desc *GPUMPCVMRoundDescriptor,
	ceremonies []GPUCeremony,
	keyShares []GPUKeyShare,
	contributions []GPUContribution,
	nextShareID uint64,
) (roundAdvance, finalized, failed uint32, err error) {
	if desc == nil || len(ceremonies) == 0 || len(keyShares) == 0 || len(contributions) == 0 {
		return 0, 0, 0, errCPUNoSlot
	}
	ra, fin, fa, _ := keyShareApplySweepCPU(desc, ceremonies, keyShares, contributions, nextShareID)
	return ra, fin, fa, nil
}

// mpcTransitionCPU runs the compute_leaves + compose_root composition.
func mpcTransitionCPU(
	desc *GPUMPCVMRoundDescriptor,
	ceremonies []GPUCeremony,
	keyShares []GPUKeyShare,
	contributions []GPUContribution,
	state *GPUMPCVMState,
) (*GPUMPCVMTransitionResult, error) {
	if desc == nil || state == nil ||
		len(ceremonies) == 0 || len(keyShares) == 0 || len(contributions) == 0 {
		return nil, errCPUNoSlot
	}
	r := closeRoundCPU(desc, state, ceremonies, keyShares, contributions)
	return &r, nil
}
