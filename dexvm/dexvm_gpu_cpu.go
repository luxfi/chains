// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// dexvm_gpu_cpu.go — pure-Go reference implementation of the four
// GPU plugin entry points (AMMSwap, ArenaCreate, ArenaDestroy,
// CLOBMatch).
//
// One implementation, used unconditionally by both build modes:
//
//   - The nocgo bridge (dexvm_gpu_nocgo.go) calls these directly:
//     no plugin can ever load there, so the Go path IS the path.
//
//   - The cgo bridge (dexvm_gpu.go) tries the GPU plugin first; on
//     a missing plugin (init() found no dylib) or a plugin-side
//     rc != 0 it falls through to the same Go path. Both build modes
//     therefore produce byte-identical output on every fixture.
//
// Byte-equality references:
//
//   - AMM: ~/work/lux/dex/pkg/lx/amm.go::ConstantProductOut — the OSS
//     canonical Go reference for the xy=k curve. Mirrored here (the
//     math is small enough that vendoring it in-package avoids a
//     cross-repo Go-module dependency while staying pinned to the
//     canonical recipe).
//
//   - CLOB: the GPU plugin's CPU oracle at
//     ~/work/lux-private/gpu-kernels/tools/kat/dex_cpu_oracle.hpp
//     ::clob_match_step_cpu — uint256 BE byte arithmetic, 4×4
//     schoolbook multiply, 512/256 shift-subtract VWAP. Translated
//     1:1 to Go.
//
// Any divergence between these helpers and the kernel CPU oracle is
// a bug — see ops/dex/{amm_xyk,clob_match}/op.yaml for the canonical
// recipe in each backend's shader.

package dexvm

import (
	"fmt"
	"sync"
)

// =============================================================================
// AMM — constant-product (xy=k), batched.
// =============================================================================

// ammSwapCPU is the per-pool xy=k swap, batched. Mirrors
// ~/work/lux/dex/pkg/lx::BatchEvalConstantProductCPU. Same recipe as
// the kernel: out = (amount * reserve_y) / (reserve_x + amount), with
// the numerator computed in 128 bits (split-32 multiply) and the
// quotient produced by a 128/64 shift-subtract division so the floor
// behaviour matches the kernel byte-for-byte.
//
// Length mismatch is a caller bug — return an error rather than panic.
// n=0 is a legal no-op (returns an empty slice, no error).
func ammSwapCPU(reserves []LuxAmmReservePair, amounts []uint64) ([]uint64, error) {
	if len(reserves) != len(amounts) {
		return nil, fmt.Errorf("dexvm.AMMSwap: reserves (n=%d) != amounts (n=%d)",
			len(reserves), len(amounts))
	}
	out := make([]uint64, len(reserves))
	for i := range reserves {
		out[i] = constantProductOut(
			reserves[i].ReserveX,
			reserves[i].ReserveY,
			amounts[i],
		)
	}
	return out, nil
}

// constantProductOut: same recipe as lx.ConstantProductOut. Kept in
// this package so dexvm doesn't pick up a Go-module dependency on
// luxfi/dex just for 20 lines of math.
func constantProductOut(rx, ry, amount uint64) uint64 {
	denom := rx + amount
	if denom == 0 {
		return 0
	}
	return mulDiv64(amount, ry, denom)
}

// mulDiv64 = (a * b) / d using 128-bit intermediates. Splits the
// 64×64 multiply into four 32×32 partial products (same split as the
// kernel's split-32 path on backends without a 64-bit hardware
// multiply); the divide is a 128/64 shift-subtract loop.
func mulDiv64(a, b, d uint64) uint64 {
	aLo, aHi := a&0xFFFFFFFF, a>>32
	bLo, bHi := b&0xFFFFFFFF, b>>32

	ll := aLo * bLo
	lh := aLo * bHi
	hl := aHi * bLo
	hh := aHi * bHi

	mid := (ll >> 32) + (lh & 0xFFFFFFFF) + (hl & 0xFFFFFFFF)
	lo := (ll & 0xFFFFFFFF) | (mid << 32)
	hi := hh + (lh >> 32) + (hl >> 32) + (mid >> 32)

	return divU128byU64(hi, lo, d)
}

// divU128byU64: shift-subtract long division. Same algorithm as the
// kernel so a per-bit divergence between paths is impossible. The
// caller is responsible for asserting the quotient fits in uint64.
func divU128byU64(hi, lo, d uint64) uint64 {
	if hi == 0 {
		return lo / d
	}
	var quotient, remainder uint64
	for i := 127; i >= 0; i-- {
		remainder <<= 1
		var bit uint64
		if i >= 64 {
			bit = (hi >> uint(i-64)) & 1
		} else {
			bit = (lo >> uint(i)) & 1
		}
		remainder |= bit
		if remainder >= d {
			remainder -= d
			if i < 64 {
				quotient |= uint64(1) << uint(i)
			}
		}
	}
	return quotient
}

// =============================================================================
// CLOB — uint256 BE byte arithmetic mirroring dex_cpu_oracle.hpp.
// =============================================================================

// u256 is the 32-byte big-endian uint256 representation used by the
// GPU plugin's CLOB ABI. Same layout as the kernel-side BookArena
// (luxgpu host arena is a fixed-cap array of these). Index 0 is the
// most significant byte; index 31 is the least.
type u256 = [32]byte

// u256Cmp returns -1, 0, +1 for a < b, a == b, a > b. Byte-wise from
// MSB so the comparison is just a memcmp under the hood.
func u256Cmp(a, b *u256) int {
	for i := 0; i < 32; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// u256IsZero reports whether every byte is 0.
func u256IsZero(a *u256) bool {
	for i := 0; i < 32; i++ {
		if a[i] != 0 {
			return false
		}
	}
	return true
}

// u256Sub returns a - b (mod 2^256). The caller asserts a >= b; the
// final borrow is dropped, matching the kernel's wrap-around behaviour.
func u256Sub(a, b *u256) u256 {
	var r u256
	borrow := 0
	for i := 31; i >= 0; i-- {
		diff := int(a[i]) - int(b[i]) - borrow
		if diff < 0 {
			diff += 256
			borrow = 1
		} else {
			borrow = 0
		}
		r[i] = uint8(diff)
	}
	return r
}

// u256AddInplace: dst += a (mod 2^256). Final carry dropped.
func u256AddInplace(dst, a *u256) {
	carry := 0
	for i := 31; i >= 0; i-- {
		sum := int(dst[i]) + int(a[i]) + carry
		dst[i] = uint8(sum & 0xff)
		carry = sum >> 8
	}
}

// u256Mul: (hi:lo) = a * b. 256×256 → 512 schoolbook multiply over
// four 64-bit limbs (same shape as dex_cpu_oracle.hpp::u256_mul). Go
// has no 128-bit type, so each i,j product is split via mul64Wide
// (same split-32 partial-product chain as mulDiv64 above and the AMM
// kernel's split-32 path); the partial sum + carry chain is identical
// to the reference's `unsigned __int128` path.
func u256Mul(hi, lo, a, b *u256) {
	// Pack each operand as 4 little-endian uint64 limbs.
	var aL, bL [4]uint64
	for i := 0; i < 4; i++ {
		var va, vb uint64
		for j := 0; j < 8; j++ {
			va |= uint64(a[31-i*8-j]) << uint(j*8)
			vb |= uint64(b[31-i*8-j]) << uint(j*8)
		}
		aL[i] = va
		bL[i] = vb
	}
	// 4×4 partial products with explicit (lo, hi) carry chain. Each
	// (lo, hi) pair is the 128-bit result of one 64×64 multiply +
	// accumulator; the next iteration's carry consumes hi.
	var r [8]uint64
	for i := 0; i < 4; i++ {
		var carryLo, carryHi uint64
		for j := 0; j < 4; j++ {
			pLo, pHi := mul64Wide(aL[i], bL[j])
			// cur128 = r[i+j] + pLo + carry (low 128 bits)
			sumLo, sumHi := add128(r[i+j], 0, pLo, pHi)
			sumLo, sumHi = add128(sumLo, sumHi, carryLo, carryHi)
			r[i+j] = sumLo
			carryLo, carryHi = sumHi, 0
		}
		r[i+4] += carryLo
	}
	// Unpack 8 limbs back into BE bytes — limbs 0..3 → lo, 4..7 → hi.
	for x := range lo {
		lo[x] = 0
	}
	for x := range hi {
		hi[x] = 0
	}
	for i := 0; i < 4; i++ {
		vl := r[i]
		vh := r[i+4]
		for j := 0; j < 8; j++ {
			lo[31-i*8-j] = uint8(vl >> uint(j*8))
			hi[31-i*8-j] = uint8(vh >> uint(j*8))
		}
	}
}

// mul64Wide returns the 128-bit product of a*b as (lo, hi). Same
// split-32 partial-product chain as mulDiv64 above (and the AMM
// kernel's split-32 path).
func mul64Wide(a, b uint64) (lo, hi uint64) {
	aLo, aHi := a&0xFFFFFFFF, a>>32
	bLo, bHi := b&0xFFFFFFFF, b>>32

	ll := aLo * bLo
	lh := aLo * bHi
	hl := aHi * bLo
	hh := aHi * bHi

	mid := (ll >> 32) + (lh & 0xFFFFFFFF) + (hl & 0xFFFFFFFF)
	lo = (ll & 0xFFFFFFFF) | (mid << 32)
	hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32)
	return lo, hi
}

// add128 returns (aLo:aHi) + (bLo:bHi) as (lo, hi). 128-bit add with
// carry-out folded into hi.
func add128(aLo, aHi, bLo, bHi uint64) (lo, hi uint64) {
	lo = aLo + bLo
	carry := uint64(0)
	if lo < aLo {
		carry = 1
	}
	hi = aHi + bHi + carry
	return lo, hi
}

// u512AddInplace: (outHi:outLo) += (aHi:aLo). The low 256 bits add
// first with their own carry chain, then the high 256 bits absorb
// the cross-half carry. Matches dex_cpu_oracle.hpp::u512_add_inplace.
func u512AddInplace(outHi, outLo, aHi, aLo *u256) {
	carry := 0
	for i := 31; i >= 0; i-- {
		sum := int(outLo[i]) + int(aLo[i]) + carry
		outLo[i] = uint8(sum & 0xff)
		carry = sum >> 8
	}
	for i := 31; i >= 0; i-- {
		sum := int(outHi[i]) + int(aHi[i]) + carry
		outHi[i] = uint8(sum & 0xff)
		carry = sum >> 8
	}
}

// u256VWAP = (notionalHi:notionalLo) / total. 512/256 shift-subtract
// long division — same per-bit recipe as dex_cpu_oracle.hpp::u256_vwap
// (and the kernel's BookArena average-price computation). Returns the
// quotient as a 32-byte BE blob; remainder is dropped (matches kernel).
//
// total == 0 returns the zero vector — same short-circuit as the
// kernel so a fill-empty match step (num_fills == 0) produces an
// avg_price of all-zeroes rather than a divide-by-zero trap.
func u256VWAP(notionalHi, notionalLo, total *u256) u256 {
	if u256IsZero(total) {
		return u256{}
	}
	var rem, quot u256
	for bit := 511; bit >= 0; bit-- {
		// Pick the source limb (hi for top 256 bits, lo for bottom 256).
		var src *u256
		if bit >= 256 {
			src = notionalHi
		} else {
			src = notionalLo
		}
		b := bit % 256
		byteIdx := 31 - (b / 8)
		shift := b % 8
		incBit := (src[byteIdx] >> uint(shift)) & 1

		// rem = (rem << 1) | incBit
		carry := int(incBit)
		for i := 31; i >= 0; i-- {
			v := (int(rem[i]) << 1) | carry
			rem[i] = uint8(v & 0xff)
			carry = (v >> 8) & 1
		}

		// if rem >= total: rem -= total; qbit = 1 else qbit = 0
		ge := u256Cmp(&rem, total) >= 0
		qbit := 0
		if ge {
			qbit = 1
			rem = u256Sub(&rem, total)
		}

		// quot = (quot << 1) | qbit
		carry = qbit
		for i := 31; i >= 0; i-- {
			v := (int(quot[i]) << 1) | carry
			quot[i] = uint8(v & 0xff)
			carry = (v >> 8) & 1
		}
	}
	return quot
}

// =============================================================================
// CLOB — host BookArena + match step.
// =============================================================================

// clobArenaCPU mirrors the GPU plugin's device-resident BookArena.
// Fixed-cap LuxCLOBMaxLevels (=1024) per side. Each level is a
// (price, qty) pair in uint256 BE byte form.
//
// The mutex serialises CLOBMatch calls on the same arena. Two callers
// on the same book MUST observe a consistent rest-or-match sequence;
// the GPU plugin enforces this via a per-arena stream serialisation,
// the CPU path mirrors it with a sync.Mutex. Different arenas (i.e.
// different book_ids) can be matched concurrently with no contention.
type clobArenaCPU struct {
	mu       sync.Mutex
	nBids    uint32
	nAsks    uint32
	bidPrice [LuxCLOBMaxLevels]u256
	bidQty   [LuxCLOBMaxLevels]u256
	askPrice [LuxCLOBMaxLevels]u256
	askQty   [LuxCLOBMaxLevels]u256
}

// clobMatchCPU runs one matcher step against the arena. The semantics
// are bit-for-bit identical to dex_cpu_oracle.hpp::clob_match_step_cpu:
//
//  1. Decode the 117-byte calldata.
//  2. Walk the opposite-side resting levels best-first. While the
//     incoming order crosses (bid >= top ask, or ask <= top bid),
//     consume min(remaining, top_qty) at the top level's price,
//     weight it into the VWAP accumulator, and either decrement
//     the top level's qty (partial) or pop it (full fill).
//  3. If the incoming order has unfilled remainder, sorted-insert it
//     as a new resting level at its own price (bid: descending price;
//     ask: ascending price). Drop the insert silently when the side
//     is already at LuxCLOBMaxLevels — same overflow behaviour as the
//     kernel.
//  4. Output 68 bytes: filled(32) | avg_price(32) | num_fills(4 BE).
//
// Concurrent calls on the same arena are serialised by arena.mu;
// different arenas can be matched in parallel without contention.
func clobMatchCPU(arena *clobArenaCPU, calldata []byte) (out [LuxCLOBOutLen]byte, numFills uint32, err error) {
	if arena == nil {
		return out, 0, fmt.Errorf("dexvm.CLOBMatch: arena is nil")
	}
	if len(calldata) != LuxCLOBCalldataLen {
		return out, 0, fmt.Errorf("dexvm.CLOBMatch: calldata len=%d, want %d",
			len(calldata), LuxCLOBCalldataLen)
	}

	// Decode calldata: side(1) | price(32 BE) | qty(32 BE) | user(20) | book_id(32).
	// We don't need the user or book_id fields in the match step — the
	// arena IS the per-book state, and the user is only consumed by the
	// host driver for fill emission (which the dexvm bridge ABI doesn't
	// expose). The kernel itself ignores both fields too.
	side := calldata[0]
	var price, qty u256
	copy(price[:], calldata[1:33])
	copy(qty[:], calldata[33:65])

	arena.mu.Lock()
	defer arena.mu.Unlock()

	remaining := qty
	var filled u256
	var notionalHi, notionalLo u256
	var nFills uint32

	matchLoop := func(
		oppPrice, oppQty *[LuxCLOBMaxLevels]u256,
		nOpp *uint32,
		incomingIsBid bool,
	) {
		for *nOpp > 0 && !u256IsZero(&remaining) {
			topPrice := oppPrice[0]
			topQty := oppQty[0]
			var crosses bool
			if incomingIsBid {
				// bid-side incoming: cross if topAsk <= price.
				crosses = u256Cmp(&topPrice, &price) <= 0
			} else {
				// ask-side incoming: cross if price <= topBid.
				crosses = u256Cmp(&price, &topPrice) <= 0
			}
			if !crosses {
				break
			}

			var fillQty u256
			if u256Cmp(&remaining, &topQty) < 0 {
				fillQty = remaining
			} else {
				fillQty = topQty
			}

			// notional += fill_qty * top_price (256×256 → 512, then
			// 512-add into the running accumulator).
			var addHi, addLo u256
			u256Mul(&addHi, &addLo, &fillQty, &topPrice)
			u512AddInplace(&notionalHi, &notionalLo, &addHi, &addLo)

			u256AddInplace(&filled, &fillQty)
			remaining = u256Sub(&remaining, &fillQty)

			if u256Cmp(&fillQty, &topQty) < 0 {
				// Partial top: decrement remaining qty in place.
				oppQty[0] = u256Sub(&topQty, &fillQty)
			} else {
				// Full top: pop level 0 via shift-down. Same compaction
				// the kernel applies — O(n) per pop, bounded by depth.
				for i := uint32(1); i < *nOpp; i++ {
					oppPrice[i-1] = oppPrice[i]
					oppQty[i-1] = oppQty[i]
				}
				*nOpp--
			}
			nFills++
		}
	}

	if side == 0 {
		// Incoming bid: match against asks; insert residual as a bid.
		matchLoop(&arena.askPrice, &arena.askQty, &arena.nAsks, true)
		if !u256IsZero(&remaining) && arena.nBids < LuxCLOBMaxLevels {
			// Bid book is sorted descending — find the first existing
			// level whose price is strictly less than ours, shift the
			// tail right, and drop in.
			pos := arena.nBids
			for i := uint32(0); i < arena.nBids; i++ {
				if u256Cmp(&arena.bidPrice[i], &price) < 0 {
					pos = i
					break
				}
			}
			for i := arena.nBids; i > pos; i-- {
				arena.bidPrice[i] = arena.bidPrice[i-1]
				arena.bidQty[i] = arena.bidQty[i-1]
			}
			arena.bidPrice[pos] = price
			arena.bidQty[pos] = remaining
			arena.nBids++
		}
	} else {
		// Incoming ask: match against bids; insert residual as an ask.
		matchLoop(&arena.bidPrice, &arena.bidQty, &arena.nBids, false)
		if !u256IsZero(&remaining) && arena.nAsks < LuxCLOBMaxLevels {
			// Ask book is sorted ascending — find the first existing
			// level whose price is strictly greater than ours.
			pos := arena.nAsks
			for i := uint32(0); i < arena.nAsks; i++ {
				if u256Cmp(&price, &arena.askPrice[i]) < 0 {
					pos = i
					break
				}
			}
			for i := arena.nAsks; i > pos; i-- {
				arena.askPrice[i] = arena.askPrice[i-1]
				arena.askQty[i] = arena.askQty[i-1]
			}
			arena.askPrice[pos] = price
			arena.askQty[pos] = remaining
			arena.nAsks++
		}
	}

	avgPrice := u256VWAP(&notionalHi, &notionalLo, &filled)

	// Pack output: filled(32) | avg_price(32) | num_fills(4 BE).
	copy(out[0:32], filled[:])
	copy(out[32:64], avgPrice[:])
	out[64] = uint8(nFills >> 24)
	out[65] = uint8(nFills >> 16)
	out[66] = uint8(nFills >> 8)
	out[67] = uint8(nFills)
	return out, nFills, nil
}
