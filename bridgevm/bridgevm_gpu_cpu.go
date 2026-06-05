// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

// Pure-Go CPU oracle for the BridgeVM GPU substrate — byte-equal to the C++
// reference at ~/work/luxcpp/bridgevm/src/bridgevm_cpu_reference.cpp and to
// every shipping GPU plugin (cuda / hip / metal / vulkan / wgsl) in non-
// strict (legacy) BLS mode.
//
// One transition implementation, two callers:
//
//   * bridgevm_gpu.go       (cgo)  — tries the dlopen'd GPU plugin first;
//                                    on ErrGPUNotAvailable falls through to
//                                    this oracle. Same result either way.
//   * bridgevm_gpu_nocgo.go (!cgo) — wraps this oracle directly. Same result
//                                    either way.
//
// Algorithm: this file is a line-by-line port of bridgevm_cpu_reference.cpp.
// Names follow the Go style (CamelCase exports, lowerCase locals) but the
// arithmetic — keccak256 round constants, 128-bit saturating add, FNV-1a
// hash-table probes, leaf-encoding offsets — is bit-identical to the C++.
//
// Why a Go port instead of pkg-config'ing the C++ oracle? Because the chains
// module must build with CGO_ENABLED=0 (the `!cgo` build tag this file is
// usable under). Adding a non-cgo dependency for a 1k-line CPU oracle is
// out of bounds — we ship the bits in Go, validated against the C++ via
// the determinism KAT in the gpu-kernels repo + the parity test in
// bridgevm_gpu_parity_test.go.
//
// Strict BLS mode (mode bit 31, kModeStrictBLS): this oracle ignores the
// bit and runs the non-strict path. Strict mode requires per-message blst
// pairing, which would re-introduce a CGO dep. Callers needing strict
// verification must use the cgo path with a real GPU plugin loaded.

import (
	"encoding/binary"
)

// =============================================================================
// keccak256 — byte-equal to bridgevm_cpu_reference.cpp's keccak_f1600 +
// keccak256. Same round constants, same rotation offsets, same 0x01 / 0x80
// padding (Ethereum keccak, NOT FIPS 202 SHA-3).
// =============================================================================

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008,
}

var keccakRot = [25]uint32{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

// rotl64 mirrors the C++ rotl64 — the n=0 case is identity (kKeccakRot[0]==0)
// and the C++ explicitly masks `n & 63` to avoid undefined behaviour at the
// shift-by-width edge. Go's shift operator is well-defined for n in [0,63]
// since uint64 has 64 bits, but we keep the mask for byte-equivalence with
// the C++ source — any optimisation that re-shapes the expression would have
// to preserve the same mathematical result, which is the contract.
func rotl64(x uint64, n uint32) uint64 {
	return (x << (n & 63)) | (x >> ((64 - n) & 63))
}

// keccakF1600 — 24-round permutation. Matches the C++ exactly: theta,
// rho-pi, chi, iota.
func keccakF1600(s *[25]uint64) {
	for round := 0; round < 24; round++ {
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = s[x] ^ s[x+5] ^ s[x+10] ^ s[x+15] ^ s[x+20]
		}
		var d [5]uint64
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ rotl64(c[(x+1)%5], 1)
		}
		for y := 0; y < 25; y += 5 {
			for x := 0; x < 5; x++ {
				s[y+x] ^= d[x]
			}
		}
		var b [25]uint64
		for y := uint32(0); y < 5; y++ {
			for x := uint32(0); x < 5; x++ {
				i := x + 5*y
				j := y + 5*((2*x+3*y)%5)
				b[j] = rotl64(s[i], keccakRot[i])
			}
		}
		for y := 0; y < 25; y += 5 {
			t0, t1, t2, t3, t4 := b[y+0], b[y+1], b[y+2], b[y+3], b[y+4]
			s[y+0] = t0 ^ ((^t1) & t2)
			s[y+1] = t1 ^ ((^t2) & t3)
			s[y+2] = t2 ^ ((^t3) & t4)
			s[y+3] = t3 ^ ((^t4) & t0)
			s[y+4] = t4 ^ ((^t0) & t1)
		}
		s[0] ^= keccakRC[round]
	}
}

// keccak256 — sponge absorb + pad + squeeze 32 bytes. rate=136 bytes (1088
// bits) for keccak256. Padding is 0x01 (start) + 0x80 (end), Ethereum
// flavour — NOT FIPS 202's 0x06.
func keccak256(data []byte, out []byte) {
	const rate = 136
	var s [25]uint64

	off := 0
	for len(data)-off >= rate {
		for i := 0; i < rate; i++ {
			lane := i / 8
			sh := uint32((i % 8) * 8)
			s[lane] ^= uint64(data[off+i]) << sh
		}
		keccakF1600(&s)
		off += rate
	}
	var block [rate]byte
	rem := len(data) - off
	for i := 0; i < rem; i++ {
		block[i] = data[off+i]
	}
	block[rem] ^= 0x01
	block[rate-1] ^= 0x80
	for i := 0; i < rate; i++ {
		lane := i / 8
		sh := uint32((i % 8) * 8)
		s[lane] ^= uint64(block[i]) << sh
	}
	keccakF1600(&s)
	for i := 0; i < 32; i++ {
		lane := i / 8
		sh := uint32((i % 8) * 8)
		out[i] = byte((s[lane] >> sh) & 0xFF)
	}
}

// absorbU32 / absorbU64 — little-endian 32/64-bit absorb into a byte slice
// at the given offset. Mirrors the C++ helpers byte-for-byte.
func absorbU32(dst []byte, off int, v uint32) {
	binary.LittleEndian.PutUint32(dst[off:off+4], v)
}

func absorbU64(dst []byte, off int, v uint64) {
	binary.LittleEndian.PutUint64(dst[off:off+8], v)
}

// =============================================================================
// 128-bit saturating arithmetic — mirrors the C++ U128 helpers.
// =============================================================================

type u128 struct {
	lo uint64
	hi uint64
}

// u128Add — saturates to (UINT64_MAX, UINT64_MAX) on overflow. The C++
// branch sequence is preserved exactly so the saturating boundary is the
// same value.
func u128Add(a, b u128) u128 {
	var r u128
	r.lo = a.lo + b.lo
	var carry uint64
	if r.lo < a.lo {
		carry = 1
	}
	hiSum := a.hi + b.hi
	hiOverflow := hiSum < a.hi
	r.hi = hiSum + carry
	if r.hi < hiSum {
		hiOverflow = true
	}
	if hiOverflow {
		r.lo = ^uint64(0)
		r.hi = ^uint64(0)
	}
	return r
}

// u128Sub — saturates to zero on negative result. Matches the C++ ordering
// (compare hi first, then lo).
func u128Sub(a, b u128) u128 {
	if a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo) {
		return u128{0, 0}
	}
	var r u128
	r.lo = a.lo - b.lo
	var borrow uint64
	if a.lo < b.lo {
		borrow = 1
	}
	r.hi = a.hi - b.hi - borrow
	return r
}

func u128Lt(a, b u128) bool {
	return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo)
}

// =============================================================================
// Status constants — match bridgevm_cpu_reference.cpp's anonymous-namespace
// constexpr values byte-for-byte. Names mirror the C++.
// =============================================================================

const (
	signerStatusActive      uint32 = 0x1
	signerStatusJailed      uint32 = 0x2
	signerStatusTombstoned  uint32 = 0x4
	signerStatusPendingAdd  uint32 = 0x8
	signerStatusPendingDrop uint32 = 0x10
	signerStatusExiting     uint32 = 0x20
)

const (
	liqStatusActive      uint32 = 1
	liqStatusWithdrawing uint32 = 2
	liqStatusClosed      uint32 = 3
)

const dailyStatusActive uint32 = 1

const (
	msgStatusFree       uint32 = 0
	msgStatusVerified   uint32 = 1
	msgStatusAccepted   uint32 = 2
	msgStatusRejected   uint32 = 3
	msgStatusOutboxEmit uint32 = 4
)

const (
	msgKindMint    uint32 = 0
	msgKindBurn    uint32 = 1
	msgKindGeneric uint32 = 2
)

// SignerOpKind values — match bridgevm_gpu_layout.hpp's enum class. Exposed
// here as un-typed constants (rather than a defined type) so the CPU oracle
// can read the kind field straight off the layout struct without a cast.
const (
	signerOpKindOptIn      uint32 = 0
	signerOpKindOptOut     uint32 = 1
	signerOpKindSlash      uint32 = 2
	signerOpKindUnjail     uint32 = 3
	signerOpKindRotateKeys uint32 = 4
)

const (
	liquidityOpKindDeposit   uint32 = 0
	liquidityOpKindWithdraw  uint32 = 1
	liquidityOpKindAccrueFee uint32 = 2
)

// Transition-mode values from BridgeVMTransitionMode in
// bridgevm_gpu_layout.hpp + the strict-BLS bit from bridgevm_bls.hpp.
const (
	transitionModeMessageInbox       uint32 = 0
	transitionModeSignerSetApply     uint32 = 1
	transitionModeLiquidityApply     uint32 = 2
	transitionModeMessageOutbox      uint32 = 3
	transitionModeBridgeVMTransition uint32 = 4
	transitionModeFullRound          uint32 = 5

	modeStrictBLS uint32 = 1 << 31
)

func baseMode(mode uint32) uint32 { return mode &^ modeStrictBLS }

// Minimum bond constants — 100M LUX in nLUX (1e9 base units). 1e17 in
// (lo, hi) split form. Numerically equal to the C++ kMinSignerBondLo /
// kMinSignerBondHi.
const (
	minSignerBondLo uint64 = 0x6BC75E2D63100000 // 1e17 lo
	minSignerBondHi uint64 = 0x00000000         // 1e17 hi
)

const maxSigners uint32 = 128

// meetsBFTThreshold — ceil(2N/3) signers required (BFT). Matches C++ formula
// exactly (avoids floating-point so the threshold is identical on every
// platform).
func meetsBFTThreshold(signerCount, activeCount uint32) bool {
	if activeCount == 0 {
		return false
	}
	needed := (2*activeCount + 2) / 3
	return signerCount >= needed
}

// computeMsgSubject — subject hash = keccak(dst_chain || nonce || payload_root).
// Field order + sizes match the C++ byte-for-byte (4-byte dst_chain LE,
// 8-byte nonce LE, 32-byte payload_root raw).
func computeMsgSubject(dstChain uint32, nonce uint64, payloadRoot []byte, out []byte) {
	var buf [4 + 8 + 32]byte
	absorbU32(buf[:], 0, dstChain)
	absorbU64(buf[:], 4, nonce)
	copy(buf[12:44], payloadRoot[:32])
	keccak256(buf[:], out)
}

// =============================================================================
// Hash-table locators — open addressing with FNV-1a starting from the same
// seed (0xcbf29ce484222325) and prime (0x100000001b3) the C++ uses.
// =============================================================================

func signerIndex(signerID uint64, mask uint32) uint32 {
	h := uint64(0xcbf29ce484222325)
	h = (h ^ signerID) * 0x100000001b3
	return uint32(h) & mask
}

// signerLocate finds the slot for a given signer_id, optionally inserting an
// empty one. Returns 0xFFFFFFFF on miss when not inserting, or when the table
// is full.
func signerLocate(tab []Signer, signerID uint64, insertIfMissing bool) uint32 {
	if len(tab) == 0 {
		return 0xFFFFFFFF
	}
	mask := uint32(len(tab)) - 1
	idx := signerIndex(signerID, mask)
	for probe := 0; probe < len(tab); probe++ {
		s := &tab[idx]
		if s.Occupied == 0 {
			if insertIfMissing {
				*s = Signer{}
				s.SignerID = signerID
				s.Occupied = 1
				return idx
			}
			return 0xFFFFFFFF
		}
		if s.SignerID == signerID {
			return idx
		}
		idx = (idx + 1) & mask
	}
	return 0xFFFFFFFF
}

func addrAssetHash(addr []byte, assetID uint32, mask uint32) uint32 {
	h := uint64(0xcbf29ce484222325)
	for k := 0; k < 20; k++ {
		h = (h ^ uint64(addr[k])) * 0x100000001b3
	}
	h = (h ^ uint64(assetID)) * 0x100000001b3
	return uint32(h) & mask
}

func addrEq(a, b []byte) bool {
	for k := 0; k < 20; k++ {
		if a[k] != b[k] {
			return false
		}
	}
	return true
}

func liquidityLocate(tab []LiquidityEntry, addr []byte, assetID uint32, insertIfMissing bool) uint32 {
	if len(tab) == 0 {
		return 0xFFFFFFFF
	}
	mask := uint32(len(tab)) - 1
	idx := addrAssetHash(addr, assetID, mask)
	for probe := 0; probe < len(tab); probe++ {
		s := &tab[idx]
		if s.Status == 0 {
			if insertIfMissing {
				*s = LiquidityEntry{}
				copy(s.ProviderAddr[:], addr[:20])
				s.AssetID = assetID
				s.Status = liqStatusActive
				return idx
			}
			return 0xFFFFFFFF
		}
		if s.AssetID == assetID && addrEq(s.ProviderAddr[:], addr) {
			return idx
		}
		idx = (idx + 1) & mask
	}
	return 0xFFFFFFFF
}

func dailyLimitLocate(tab []DailyLimit, assetID uint32) uint32 {
	if len(tab) == 0 {
		return 0xFFFFFFFF
	}
	mask := uint32(len(tab)) - 1
	h := uint64(0xcbf29ce484222325)
	h = (h ^ uint64(assetID)) * 0x100000001b3
	idx := uint32(h) & mask
	for probe := 0; probe < len(tab); probe++ {
		s := &tab[idx]
		if s.Status == 0 {
			return 0xFFFFFFFF
		}
		if s.AssetID == assetID {
			return idx
		}
		idx = (idx + 1) & mask
	}
	return 0xFFFFFFFF
}

func msgIDEq(a, b []byte) bool {
	for k := 0; k < 32; k++ {
		if a[k] != b[k] {
			return false
		}
	}
	return true
}

func msgIDZero(a []byte) bool {
	for k := 0; k < 32; k++ {
		if a[k] != 0 {
			return false
		}
	}
	return true
}

func msgIDHash(id []byte, mask uint32) uint32 {
	h := uint64(0xcbf29ce484222325)
	for k := 0; k < 32; k++ {
		h = (h ^ uint64(id[k])) * 0x100000001b3
	}
	return uint32(h) & mask
}

func inboxLocate(tab []Message, msgID []byte, insertIfMissing bool) uint32 {
	if len(tab) == 0 {
		return 0xFFFFFFFF
	}
	mask := uint32(len(tab)) - 1
	idx := msgIDHash(msgID, mask)
	for probe := 0; probe < len(tab); probe++ {
		s := &tab[idx]
		if s.Status == 0 && msgIDZero(s.MsgID[:]) {
			if insertIfMissing {
				return idx
			}
			return 0xFFFFFFFF
		}
		if msgIDEq(s.MsgID[:], msgID) {
			return idx
		}
		idx = (idx + 1) & mask
	}
	return 0xFFFFFFFF
}

func popcountU128(lo, hi uint64) uint32 {
	var c uint32
	for k := 0; k < 64; k++ {
		if (lo>>k)&1 == 1 {
			c++
		}
	}
	for k := 0; k < 64; k++ {
		if (hi>>k)&1 == 1 {
			c++
		}
	}
	return c
}

func countActiveSigners(signers []Signer) uint32 {
	var n uint32
	for i := range signers {
		s := &signers[i]
		if s.Occupied == 0 {
			continue
		}
		if (s.Status&signerStatusActive) != 0 &&
			(s.Status&signerStatusTombstoned) == 0 &&
			(s.Status&signerStatusJailed) == 0 {
			n++
		}
	}
	return n
}

// =============================================================================
// Kernel 1: MessageInbox
// =============================================================================

// cpuMessageInbox applies inbound BLS-verified messages to the inbox arena,
// respecting daily limits and the 2/3 BFT threshold. Mirrors apply_inbox()
// in bridgevm_cpu_reference.cpp byte-for-byte.
//
// Strict-BLS mode (mode bit 31) is treated as non-strict here — see file
// header for rationale.
//
// Returns: applied count, total inbound (lo, hi).
func cpuMessageInbox(
	desc *BridgeVMRoundDescriptor,
	inMsgs []Message,
	signers []Signer,
	daily []DailyLimit,
	inbox []Message,
) (uint32, uint64, uint64) {
	var applied uint32
	total := u128{0, 0}
	active := countActiveSigners(signers)

	for mi := 0; mi < len(inMsgs); mi++ {
		m := &inMsgs[mi]

		// 1. Recompute msg_id from subject and require it matches.
		var expectedID [32]byte
		computeMsgSubject(m.DstChain, m.Nonce, m.PayloadRoot[:], expectedID[:])
		if !msgIDEq(expectedID[:], m.MsgID[:]) {
			continue
		}

		// 2. Replay check: msg_id must not already be in the inbox.
		if inboxLocate(inbox, m.MsgID[:], false) != 0xFFFFFFFF {
			continue
		}

		// 3. Threshold: signer_count must meet 2/3 BFT against active set.
		if m.SignerCount == 0 {
			continue
		}
		if popcountU128(m.SignersBitmapLo, m.SignersBitmapHi) != m.SignerCount {
			continue
		}
		if !meetsBFTThreshold(m.SignerCount, active) {
			continue
		}

		// 4. Insert into inbox.
		idx := inboxLocate(inbox, m.MsgID[:], true)
		if idx == 0xFFFFFFFF {
			continue
		}
		slot := &inbox[idx]
		*slot = *m
		slot.Status = msgStatusAccepted
		slot.ArrivalHeight = desc.Height

		// 5. For mint: queue under daily limit.
		if m.Kind == msgKindMint {
			dlIdx := dailyLimitLocate(daily, m.AssetID)
			if dlIdx != 0xFFFFFFFF {
				dl := &daily[dlIdx]
				cap := u128{dl.DailyCapLo, dl.DailyCapHi}
				used := u128{dl.UsedTodayLo, dl.UsedTodayHi}
				amt := u128{m.AmountLo, m.AmountHi}
				newUsed := u128Add(used, amt)
				if u128Lt(cap, newUsed) {
					// Exhausted — leave as verified, not accepted.
					slot.Status = msgStatusVerified
					continue
				}
				dl.UsedTodayLo = newUsed.lo
				dl.UsedTodayHi = newUsed.hi
			}
			total = u128Add(total, u128{m.AmountLo, m.AmountHi})
		}
		applied++
	}
	return applied, total.lo, total.hi
}

// =============================================================================
// Kernel 2: SignerSetApply
// =============================================================================

// cpuSignerApply applies a list of signer ops (opt-in, opt-out, slash, unjail,
// rotate-keys) to the signer arena. Mirrors apply_signer_ops().
func cpuSignerApply(
	desc *BridgeVMRoundDescriptor,
	ops []SignerOp,
	signers []Signer,
) uint32 {
	_ = desc
	var applied uint32
	for i := range ops {
		op := &ops[i]
		switch op.Kind {
		case signerOpKindOptIn:
			bond := u128{op.BondAmountLo, op.BondAmountHi}
			minBond := u128{minSignerBondLo, minSignerBondHi}
			if u128Lt(bond, minBond) {
				break
			}
			active := countActiveSigners(signers)
			if active >= maxSigners {
				break
			}
			idx := signerLocate(signers, op.SignerID, true)
			if idx == 0xFFFFFFFF {
				break
			}
			s := &signers[idx]
			copy(s.LuxAddress[:], op.LuxAddress[:])
			s.BondAmountLo = op.BondAmountLo
			s.BondAmountHi = op.BondAmountHi
			s.OptInHeight = op.OptInHeight
			copy(s.BLSPubKey[:], op.BLSPubKey[:])
			copy(s.RingtailPubKey[:], op.RingtailPubKey[:])
			copy(s.MLDSAPubKey[:], op.MLDSAPubKey[:])
			s.Status = signerStatusActive | signerStatusPendingAdd
			s.JailUntilEpoch = 0
			applied++
		case signerOpKindOptOut:
			idx := signerLocate(signers, op.SignerID, false)
			if idx == 0xFFFFFFFF {
				break
			}
			s := &signers[idx]
			if (s.Status & signerStatusTombstoned) != 0 {
				break
			}
			s.Status |= signerStatusExiting
			s.Status &^= signerStatusActive
			s.ExitEpoch = uint64(op.Epoch) + 14
			applied++
		case signerOpKindSlash:
			idx := signerLocate(signers, op.SignerID, false)
			if idx == 0xFFFFFFFF {
				break
			}
			s := &signers[idx]
			if (s.Status & signerStatusTombstoned) != 0 {
				break
			}
			bond := u128{s.BondAmountLo, s.BondAmountHi}
			// op.SlashAmount{Lo,Hi} are u32 per the layout — widen for arithmetic.
			amt := u128{uint64(op.SlashAmountLo), uint64(op.SlashAmountHi)}
			newBond := u128Sub(bond, amt)
			s.BondAmountLo = newBond.lo
			s.BondAmountHi = newBond.hi
			s.SlashCount++
			isEquivocation := false
			for k := 0; k < 32; k++ {
				if op.EvidenceDigest[k] != 0 {
					isEquivocation = true
					break
				}
			}
			if isEquivocation {
				s.Status |= signerStatusTombstoned
				s.Status &^= signerStatusActive
			} else {
				s.Status |= signerStatusJailed
				s.Status &^= signerStatusActive
				jailFor := op.JailUntilEpoch
				if jailFor == 0 {
					jailFor = 100
				}
				newJail := op.Epoch + jailFor
				if newJail > s.JailUntilEpoch {
					s.JailUntilEpoch = newJail
				}
			}
			minBond := u128{minSignerBondLo, minSignerBondHi}
			if u128Lt(newBond, minBond) {
				s.Status |= signerStatusExiting
				s.Status &^= signerStatusActive
			}
			applied++
		case signerOpKindUnjail:
			idx := signerLocate(signers, op.SignerID, false)
			if idx == 0xFFFFFFFF {
				break
			}
			s := &signers[idx]
			if (s.Status & signerStatusTombstoned) != 0 {
				break
			}
			if op.Epoch < s.JailUntilEpoch {
				break
			}
			s.Status &^= signerStatusJailed
			s.Status |= signerStatusActive
			s.JailUntilEpoch = 0
			applied++
		case signerOpKindRotateKeys:
			idx := signerLocate(signers, op.SignerID, false)
			if idx == 0xFFFFFFFF {
				break
			}
			s := &signers[idx]
			if (s.Status & signerStatusTombstoned) != 0 {
				break
			}
			copy(s.BLSPubKey[:], op.BLSPubKey[:])
			copy(s.RingtailPubKey[:], op.RingtailPubKey[:])
			copy(s.MLDSAPubKey[:], op.MLDSAPubKey[:])
			applied++
		}
	}
	return applied
}

// =============================================================================
// Kernel 3: LiquidityApply
// =============================================================================

// cpuLiquidityApply applies deposit / withdraw / accrue-fee ops to the
// liquidity arena. Fee accrual is pro-rata by provider amount.
func cpuLiquidityApply(
	desc *BridgeVMRoundDescriptor,
	ops []LiquidityOp,
	liquidity []LiquidityEntry,
) (uint32, uint64, uint64) {
	_ = desc
	var applied uint32
	total := u128{0, 0}
	for i := range ops {
		op := &ops[i]
		switch op.Kind {
		case liquidityOpKindDeposit:
			idx := liquidityLocate(liquidity, op.ProviderAddr[:], op.AssetID, true)
			if idx == 0xFFFFFFFF {
				break
			}
			s := &liquidity[idx]
			amt := u128{op.AmountLo, op.AmountHi}
			cur := u128{s.AmountLo, s.AmountHi}
			nu := u128Add(cur, amt)
			s.AmountLo = nu.lo
			s.AmountHi = nu.hi
			if s.DepositHeight == 0 {
				s.DepositHeight = op.Height
			}
			s.Status = liqStatusActive
			applied++
		case liquidityOpKindWithdraw:
			idx := liquidityLocate(liquidity, op.ProviderAddr[:], op.AssetID, false)
			if idx == 0xFFFFFFFF {
				break
			}
			s := &liquidity[idx]
			if s.Status != liqStatusActive {
				break
			}
			cur := u128{s.AmountLo, s.AmountHi}
			amt := u128{op.AmountLo, op.AmountHi}
			if u128Lt(cur, amt) {
				break
			}
			nu := u128Sub(cur, amt)
			s.AmountLo = nu.lo
			s.AmountHi = nu.hi
			if nu.lo == 0 && nu.hi == 0 {
				s.Status = liqStatusClosed
			}
			applied++
		case liquidityOpKindAccrueFee:
			feeTotal := u128{op.AmountLo, op.AmountHi}
			poolTotal := u128{0, 0}
			for j := range liquidity {
				s := &liquidity[j]
				if s.Status != liqStatusActive {
					continue
				}
				if s.AssetID != op.AssetID {
					continue
				}
				poolTotal = u128Add(poolTotal, u128{s.AmountLo, s.AmountHi})
			}
			if poolTotal.lo == 0 && poolTotal.hi == 0 {
				break
			}
			// C++ short-circuit conditions — preserve byte-for-byte.
			if poolTotal.hi != 0 {
				break
			}
			if feeTotal.hi != 0 {
				break
			}
			poolLo := poolTotal.lo
			feeLo := feeTotal.lo
			if poolLo == 0 {
				break
			}
			for j := range liquidity {
				s := &liquidity[j]
				if s.Status != liqStatusActive {
					continue
				}
				if s.AssetID != op.AssetID {
					continue
				}
				if s.AmountHi != 0 {
					continue
				}
				// delta = floor(fee_lo * s.AmountLo / pool_lo). The C++ uses
				// __uint128_t; we do the same in Go via the long multiplication
				// + 128/64 divide helper below.
				_, deltaLo := mulDiv64(feeLo, s.AmountLo, poolLo)
				curFee := u128{s.FeeAccrualLo, s.FeeAccrualHi}
				nu := u128Add(curFee, u128{deltaLo, 0})
				s.FeeAccrualLo = nu.lo
				s.FeeAccrualHi = nu.hi
			}
			total = u128Add(total, feeTotal)
			applied++
		}
	}
	return applied, total.lo, total.hi
}

// mulDiv64 computes floor(a * b / d) where the product a*b fits in 128 bits.
// Mirrors the C++ `__uint128_t prod = (__uint128_t)fee_lo * s.amount_lo;
// delta = prod / pool_lo`. The hi limb of the quotient is dropped because
// the C++ truncates by casting to uint64_t — same end result.
//
// Returns (hi, lo) of the quotient.
func mulDiv64(a, b, d uint64) (uint64, uint64) {
	// 128-bit product via 64x64 = 128.
	aLo, aHi := a&0xFFFFFFFF, a>>32
	bLo, bHi := b&0xFFFFFFFF, b>>32
	p0 := aLo * bLo
	p1 := aLo * bHi
	p2 := aHi * bLo
	p3 := aHi * bHi
	mid := p1 + (p0 >> 32) + (p2 & 0xFFFFFFFF)
	lo := (p0 & 0xFFFFFFFF) | (mid << 32)
	hi := p3 + (mid >> 32) + (p2 >> 32)
	// Long division 128/64. When hi == 0 we can use Go's native uint64 div.
	if hi == 0 {
		if d == 0 {
			return 0, 0
		}
		return 0, lo / d
	}
	if d == 0 {
		return 0, 0
	}
	var quoLo uint64
	var rem uint64
	for i := 127; i >= 0; i-- {
		rem <<= 1
		var bit uint64
		if i >= 64 {
			bit = (hi >> uint(i-64)) & 1
		} else {
			bit = (lo >> uint(i)) & 1
		}
		rem |= bit
		if rem >= d {
			rem -= d
			if i < 64 {
				quoLo |= uint64(1) << uint(i)
			}
			// quotient bits ≥ 64 land in the high limb; we drop them to
			// match the C++ `uint64_t delta = uint64_t(prod / pool_lo)`.
		}
	}
	return 0, quoLo
}

// =============================================================================
// Kernel 4: MessageOutbox
// =============================================================================

// cpuMessageOutbox emits outbound messages, debiting daily limits and
// stamping msg_id = keccak(dst_chain || nonce || payload_root). Mirrors
// apply_outbox().
func cpuMessageOutbox(
	desc *BridgeVMRoundDescriptor,
	reqs []OutboundReq,
	daily []DailyLimit,
	outbox []Message,
	epoch *BridgeVMEpochState,
) (uint32, uint64, uint64) {
	_ = desc
	var applied uint32
	total := u128{0, 0}
	cursor := epoch.OutboxCount
	for i := range reqs {
		req := &reqs[i]
		// For mint/burn: enforce daily cap if the asset has one.
		if req.Kind == msgKindMint || req.Kind == msgKindBurn {
			dlIdx := dailyLimitLocate(daily, req.AssetID)
			if dlIdx != 0xFFFFFFFF {
				dl := &daily[dlIdx]
				cap := u128{dl.DailyCapLo, dl.DailyCapHi}
				used := u128{dl.UsedTodayLo, dl.UsedTodayHi}
				amt := u128{req.AmountLo, req.AmountHi}
				nu := u128Add(used, amt)
				if u128Lt(cap, nu) {
					continue
				}
				dl.UsedTodayLo = nu.lo
				dl.UsedTodayHi = nu.hi
			}
		}
		if cursor >= uint32(len(outbox)) {
			break
		}
		slot := &outbox[cursor]
		*slot = Message{}
		computeMsgSubject(req.DstChain, req.Nonce, req.PayloadRoot[:], slot.MsgID[:])
		copy(slot.PayloadRoot[:], req.PayloadRoot[:])
		slot.SignersBitmapLo = 0
		slot.SignersBitmapHi = 0
		slot.SignerCount = 0
		slot.Nonce = req.Nonce
		slot.SrcChain = req.SrcChain
		slot.DstChain = req.DstChain
		slot.Kind = req.Kind
		slot.AssetID = req.AssetID
		slot.AmountLo = req.AmountLo
		slot.AmountHi = req.AmountHi
		slot.ArrivalHeight = req.Height
		slot.Status = msgStatusOutboxEmit
		cursor++
		total = u128Add(total, u128{req.AmountLo, req.AmountHi})
		applied++
	}
	epoch.OutboxCount = cursor
	return applied, total.lo, total.hi
}

// =============================================================================
// Kernel 5: BridgeVMTransition (root computation)
// =============================================================================

// computeSignerSetRoot — folds the signer arena into a single 32-byte root
// via a left-to-right Merkle accumulator: acc = keccak(acc || leaf_hash) for
// each occupied slot. Side-output: active / jailed / tombstoned counts and
// the total active bond (saturating). Mirrors compute_signer_set_root().
func computeSignerSetRoot(signers []Signer, out []byte) (uint32, uint32, uint32, u128) {
	var acc [32]byte
	var activeCount, jailedCount, tombstonedCount uint32
	totalActiveBond := u128{0, 0}

	for i := range signers {
		s := &signers[i]
		if s.Occupied == 0 {
			continue
		}
		if (s.Status & signerStatusTombstoned) != 0 {
			tombstonedCount++
		}
		if (s.Status & signerStatusJailed) != 0 {
			jailedCount++
		}
		if (s.Status&signerStatusActive) != 0 &&
			(s.Status&signerStatusJailed) == 0 &&
			(s.Status&signerStatusTombstoned) == 0 {
			activeCount++
			totalActiveBond = u128Add(totalActiveBond, u128{s.BondAmountLo, s.BondAmountHi})
		}

		// Leaf layout — byte-for-byte from compute_signer_set_root in C++:
		//   signer_id u64 | lux_address [20] | pad u32 | bond_lo u64 |
		//   bond_hi u64 | opt_in_height u64 | exit_epoch u64 | sign_count u64 |
		//   bls_pubkey [48] | corona_pubkey [32] | mldsa_pubkey [32] |
		//   status u32 | jail_until_epoch u32 | slash_count u32 | index u32
		var leaf [8 + 20 + 4 + 8 + 8 + 8 + 8 + 8 + 48 + 32 + 32 + 4 + 4 + 4 + 4]byte
		o := 0
		absorbU64(leaf[:], o, s.SignerID)
		o += 8
		copy(leaf[o:o+20], s.LuxAddress[:])
		o += 20
		absorbU32(leaf[:], o, 0)
		o += 4
		absorbU64(leaf[:], o, s.BondAmountLo)
		o += 8
		absorbU64(leaf[:], o, s.BondAmountHi)
		o += 8
		absorbU64(leaf[:], o, s.OptInHeight)
		o += 8
		absorbU64(leaf[:], o, s.ExitEpoch)
		o += 8
		absorbU64(leaf[:], o, s.SignCount)
		o += 8
		copy(leaf[o:o+48], s.BLSPubKey[:])
		o += 48
		copy(leaf[o:o+32], s.RingtailPubKey[:])
		o += 32
		copy(leaf[o:o+32], s.MLDSAPubKey[:])
		o += 32
		absorbU32(leaf[:], o, s.Status)
		o += 4
		absorbU32(leaf[:], o, s.JailUntilEpoch)
		o += 4
		absorbU32(leaf[:], o, s.SlashCount)
		o += 4
		absorbU32(leaf[:], o, uint32(i))
		o += 4

		var leafHash [32]byte
		keccak256(leaf[:o], leafHash[:])

		var buf [64]byte
		copy(buf[:32], acc[:])
		copy(buf[32:], leafHash[:])
		keccak256(buf[:], acc[:])
	}
	copy(out[:32], acc[:])
	return activeCount, jailedCount, tombstonedCount, totalActiveBond
}

// computeLiquidityRoot mirrors compute_liquidity_root() — same leaf layout.
func computeLiquidityRoot(liq []LiquidityEntry, out []byte) {
	var acc [32]byte
	for i := range liq {
		s := &liq[i]
		if s.Status == 0 {
			continue
		}
		var leaf [20 + 4 + 4 + 4 + 8*4 + 4]byte
		o := 0
		copy(leaf[o:o+20], s.ProviderAddr[:])
		o += 20
		absorbU32(leaf[:], o, 0)
		o += 4
		absorbU32(leaf[:], o, s.AssetID)
		o += 4
		absorbU32(leaf[:], o, s.Status)
		o += 4
		absorbU64(leaf[:], o, s.AmountLo)
		o += 8
		absorbU64(leaf[:], o, s.AmountHi)
		o += 8
		absorbU64(leaf[:], o, s.FeeAccrualLo)
		o += 8
		absorbU64(leaf[:], o, s.FeeAccrualHi)
		o += 8
		absorbU32(leaf[:], o, uint32(i))
		o += 4

		var leafHash [32]byte
		keccak256(leaf[:o], leafHash[:])
		var buf [64]byte
		copy(buf[:32], acc[:])
		copy(buf[32:], leafHash[:])
		keccak256(buf[:], acc[:])
	}
	copy(out[:32], acc[:])
}

// computeMessageRoot mirrors compute_message_root().
func computeMessageRoot(tab []Message, out []byte) {
	var acc [32]byte
	for i := range tab {
		m := &tab[i]
		if m.Status == 0 && msgIDZero(m.MsgID[:]) {
			continue
		}
		var leaf [32 + 32 + 8 + 4 + 4 + 4 + 4 + 8 + 8 + 4]byte
		o := 0
		copy(leaf[o:o+32], m.MsgID[:])
		o += 32
		copy(leaf[o:o+32], m.PayloadRoot[:])
		o += 32
		absorbU64(leaf[:], o, m.Nonce)
		o += 8
		absorbU32(leaf[:], o, m.SrcChain)
		o += 4
		absorbU32(leaf[:], o, m.DstChain)
		o += 4
		absorbU32(leaf[:], o, m.Kind)
		o += 4
		absorbU32(leaf[:], o, m.Status)
		o += 4
		absorbU64(leaf[:], o, m.AmountLo)
		o += 8
		absorbU64(leaf[:], o, m.AmountHi)
		o += 8
		absorbU32(leaf[:], o, uint32(i))
		o += 4

		var leafHash [32]byte
		keccak256(leaf[:o], leafHash[:])
		var buf [64]byte
		copy(buf[:32], acc[:])
		copy(buf[32:], leafHash[:])
		keccak256(buf[:], acc[:])
	}
	copy(out[:32], acc[:])
}

// computeDailyLimitRoot mirrors compute_daily_limit_root().
func computeDailyLimitRoot(tab []DailyLimit, out []byte) {
	var acc [32]byte
	for i := range tab {
		s := &tab[i]
		if s.Status == 0 {
			continue
		}
		var leaf [4 + 4 + 8*4 + 4]byte
		o := 0
		absorbU32(leaf[:], o, s.AssetID)
		o += 4
		absorbU32(leaf[:], o, s.Status)
		o += 4
		absorbU64(leaf[:], o, s.DailyCapLo)
		o += 8
		absorbU64(leaf[:], o, s.DailyCapHi)
		o += 8
		absorbU64(leaf[:], o, s.UsedTodayLo)
		o += 8
		absorbU64(leaf[:], o, s.UsedTodayHi)
		o += 8
		absorbU32(leaf[:], o, uint32(i))
		o += 4

		var leafHash [32]byte
		keccak256(leaf[:o], leafHash[:])
		var buf [64]byte
		copy(buf[:32], acc[:])
		copy(buf[32:], leafHash[:])
		keccak256(buf[:], acc[:])
	}
	copy(out[:32], acc[:])
}

// cpuBridgeTransition closes the epoch: promotes pending_add → active, drops
// pending_drop → tombstoned, exits expired exiting signers, auto-unjails
// expired jails, resets daily limits whose reset_epoch has passed, then
// computes all five component roots + the composed bridgevm_state_root.
//
// Mirrors close_epoch() — same field order, same composed-root byte layout.
func cpuBridgeTransition(
	desc *BridgeVMRoundDescriptor,
	signers []Signer,
	liquidity []LiquidityEntry,
	daily []DailyLimit,
	inbox []Message,
	outbox []Message,
	epoch *BridgeVMEpochState,
	result *BridgeVMTransitionResult,
) {
	var pendingDropCount uint32
	targetEpoch := desc.Epoch
	if desc.ClosingFlag != 0 {
		targetEpoch = desc.Epoch + 1
	}
	for i := range signers {
		s := &signers[i]
		if s.Occupied == 0 {
			continue
		}
		if (s.Status & signerStatusPendingAdd) != 0 {
			s.Status &^= signerStatusPendingAdd
		}
		if (s.Status & signerStatusPendingDrop) != 0 {
			s.Status &^= signerStatusPendingDrop
			s.Status |= signerStatusTombstoned
			pendingDropCount++
		}
		if (s.Status&signerStatusExiting) != 0 &&
			s.ExitEpoch != 0 &&
			targetEpoch >= s.ExitEpoch &&
			(s.Status&signerStatusTombstoned) == 0 {
			s.Status &^= signerStatusExiting
			s.Status |= signerStatusTombstoned
			pendingDropCount++
		}
		if (s.Status&signerStatusJailed) != 0 &&
			s.JailUntilEpoch != 0 &&
			uint32(targetEpoch) >= s.JailUntilEpoch &&
			(s.Status&signerStatusTombstoned) == 0 {
			s.Status &^= signerStatusJailed
			s.Status |= signerStatusActive
			s.JailUntilEpoch = 0
		}
	}
	epoch.PendingDropCount = pendingDropCount

	// Reset daily limits whose reset_epoch has passed.
	for i := range daily {
		dl := &daily[i]
		if dl.Status == 0 {
			continue
		}
		if targetEpoch >= dl.ResetEpoch {
			dl.UsedTodayLo = 0
			dl.UsedTodayHi = 0
			dl.ResetEpoch = targetEpoch + 1
		}
	}

	activeCount, jailedCount, tombstonedCount, totalActiveBond :=
		computeSignerSetRoot(signers, epoch.SignerSetRoot[:])
	computeLiquidityRoot(liquidity, epoch.LiquidityRoot[:])
	computeMessageRoot(inbox, epoch.InboxRoot[:])
	computeMessageRoot(outbox, epoch.OutboxRoot[:])
	computeDailyLimitRoot(daily, epoch.DailyLimitRoot[:])

	epoch.ActiveSignerCount = activeCount
	epoch.TotalActiveBondLo = totalActiveBond.lo
	epoch.TotalActiveBondHi = totalActiveBond.hi
	if desc.ClosingFlag != 0 {
		epoch.CurrentEpoch = targetEpoch
	}

	// Composed bridgevm_state_root = keccak(parent || signer || liq || inbox
	//                                      || outbox || daily || epoch_u64
	//                                      || total_bond_lo || total_bond_hi
	//                                      || active_count_u32)
	var composed [32 + 32 + 32 + 32 + 32 + 32 + 8 + 8 + 8 + 4]byte
	o := 0
	copy(composed[o:o+32], desc.ParentStateRoot[:])
	o += 32
	copy(composed[o:o+32], epoch.SignerSetRoot[:])
	o += 32
	copy(composed[o:o+32], epoch.LiquidityRoot[:])
	o += 32
	copy(composed[o:o+32], epoch.InboxRoot[:])
	o += 32
	copy(composed[o:o+32], epoch.OutboxRoot[:])
	o += 32
	copy(composed[o:o+32], epoch.DailyLimitRoot[:])
	o += 32
	absorbU64(composed[:], o, epoch.CurrentEpoch)
	o += 8
	absorbU64(composed[:], o, epoch.TotalActiveBondLo)
	o += 8
	absorbU64(composed[:], o, epoch.TotalActiveBondHi)
	o += 8
	absorbU32(composed[:], o, epoch.ActiveSignerCount)
	o += 4
	keccak256(composed[:o], epoch.BridgeVMStateRoot[:])

	copy(result.SignerSetRoot[:], epoch.SignerSetRoot[:])
	copy(result.LiquidityRoot[:], epoch.LiquidityRoot[:])
	copy(result.InboxRoot[:], epoch.InboxRoot[:])
	copy(result.OutboxRoot[:], epoch.OutboxRoot[:])
	copy(result.DailyLimitRoot[:], epoch.DailyLimitRoot[:])
	copy(result.BridgeVMStateRoot[:], epoch.BridgeVMStateRoot[:])
	result.ActiveSignerCount = activeCount
	result.JailedCount = jailedCount
	result.TombstonedCount = tombstonedCount
	result.TotalActiveBondLo = totalActiveBond.lo
	result.TotalActiveBondHi = totalActiveBond.hi
	result.Epoch = epoch.CurrentEpoch
}

// =============================================================================
// cpuBackend — the GPUBackend implementation that uses the pure-Go oracle.
// Both bridgevm_gpu.go (cgo, as the fallback path) and bridgevm_gpu_nocgo.go
// (!cgo, as the only path) hand a *cpuBackend to ActiveGPUBackend().
// =============================================================================

type cpuBackend struct{}

func (cpuBackend) Backend() Backend { return BackendNone }

func (cpuBackend) SignerApply(
	desc *BridgeVMRoundDescriptor,
	ops []SignerOp,
	signers []Signer,
) (uint32, error) {
	if desc == nil || len(signers) == 0 {
		return 0, errInvalidArgs("SignerApply", "non-nil desc + non-empty signers")
	}
	return cpuSignerApply(desc, ops, signers), nil
}

func (cpuBackend) LiquidityApply(
	desc *BridgeVMRoundDescriptor,
	ops []LiquidityOp,
	liquidity []LiquidityEntry,
) (uint32, uint64, uint64, error) {
	if desc == nil || len(liquidity) == 0 {
		return 0, 0, 0, errInvalidArgs("LiquidityApply",
			"non-nil desc + non-empty liquidity")
	}
	applied, lo, hi := cpuLiquidityApply(desc, ops, liquidity)
	return applied, lo, hi, nil
}

func (cpuBackend) MessageInbox(
	desc *BridgeVMRoundDescriptor,
	inMsgs []Message,
	signers []Signer,
	daily []DailyLimit,
	inbox []Message,
) (uint32, uint64, uint64, error) {
	if desc == nil || len(signers) == 0 || len(daily) == 0 || len(inbox) == 0 {
		return 0, 0, 0, errInvalidArgs("MessageInbox",
			"non-nil desc + non-empty signers/daily/inbox")
	}
	applied, lo, hi := cpuMessageInbox(desc, inMsgs, signers, daily, inbox)
	return applied, lo, hi, nil
}

func (cpuBackend) MessageOutbox(
	desc *BridgeVMRoundDescriptor,
	reqs []OutboundReq,
	daily []DailyLimit,
	outbox []Message,
	epoch *BridgeVMEpochState,
) (uint32, uint64, uint64, error) {
	if desc == nil || epoch == nil || len(daily) == 0 || len(outbox) == 0 {
		return 0, 0, 0, errInvalidArgs("MessageOutbox",
			"non-nil desc/epoch + non-empty daily/outbox")
	}
	applied, lo, hi := cpuMessageOutbox(desc, reqs, daily, outbox, epoch)
	return applied, lo, hi, nil
}

func (cpuBackend) BridgeTransition(
	desc *BridgeVMRoundDescriptor,
	signers []Signer,
	liquidity []LiquidityEntry,
	daily []DailyLimit,
	inbox []Message,
	outbox []Message,
	epoch *BridgeVMEpochState,
	result *BridgeVMTransitionResult,
) error {
	if desc == nil || epoch == nil || result == nil ||
		len(signers) == 0 || len(liquidity) == 0 || len(daily) == 0 ||
		len(inbox) == 0 || len(outbox) == 0 {
		return errInvalidArgs("BridgeTransition",
			"non-nil desc/epoch/result + non-empty arrays")
	}
	cpuBridgeTransition(desc, signers, liquidity, daily, inbox, outbox, epoch, result)
	return nil
}

// errInvalidArgs returns a uniform "bridgevm: <op> requires <constraint>"
// error matching the cgo bridge's wording (so tests that check error strings
// see the same surface under both build modes).
func errInvalidArgs(op, constraint string) error {
	return &argsError{op: op, constraint: constraint}
}

type argsError struct {
	op         string
	constraint string
}

func (e *argsError) Error() string {
	return "bridgevm: " + e.op + " requires " + e.constraint
}
