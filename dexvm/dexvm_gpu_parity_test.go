// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// dexvm_gpu_parity_test.go — proves the cgo and nocgo bridges produce
// byte-identical output for the public AMMSwap / CLOBMatch surface.
//
// The cgo build's pure-Go fallback (dexvm_gpu_cpu.go) IS the nocgo
// build's only path — that's the "one and only one way" the task
// brief calls out. The test therefore runs the same fixture under
// whatever backend the build was wired with and asserts the same
// answers under both. Since dexvm_gpu_cpu.go has no build tag, the
// kernel-oracle code path is identical on disk; the parity test is
// essentially a regression net against any future refactor that
// would let the two bridges drift.
//
// Fixture choice:
//
//   - AMM: the same (rx, ry, amount) = (1_000_000, 2_000_000, 1_000)
//     fixture as TestGPUAMMSwapRoundTrip — expected output is 1_998,
//     same value the GPU kernel produces. Reusing the fixture means
//     a regression in the Go fallback also fails the GPU path test
//     when a plugin IS loaded.
//
//   - CLOB: a four-step sequence (rest two asks, sweep them with a
//     crossing bid, rest a bid below market) that exercises EVERY
//     code path in clob_match_step_cpu: partial fill, full level
//     pop, multi-level walk, residual insert. The expected output
//     bytes are derived from the kernel oracle's recipe so a drift
//     in the Go side surfaces here.

package dexvm

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestGPUBridgeCgoNocgoParity proves the AMMSwap surface produces the
// same output regardless of which backend (cgo plugin, cgo CPU
// fallback, !cgo CPU) the bridge picks. The fixture is the canonical
// xy=k case from TestGPUAMMSwapRoundTrip — 1_998 is the kernel-side
// expected result and the CPU oracle target.
func TestGPUBridgeCgoNocgoParity(t *testing.T) {
	// AMM parity — the canonical kernel fixture. ammSwapCPU is the
	// pure-Go reference that both bridges fall through to (and the
	// nocgo bridge always uses); the public AMMSwap entry point goes
	// through the bridge dispatch logic. Both MUST produce the
	// expected kernel output of 1_998.
	t.Run("amm/round_trip", func(t *testing.T) {
		reserves := []LuxAmmReservePair{
			{ReserveX: 1_000_000, ReserveY: 2_000_000},
		}
		amounts := []uint64{1_000}

		got, err := AMMSwap(reserves, amounts)
		if err != nil {
			t.Fatalf("AMMSwap: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("AMMSwap: got len=%d, want 1", len(got))
		}
		const want = uint64(1_998)
		if got[0] != want {
			t.Errorf("AMMSwap: got %d, want %d (kernel byte-equality contract)",
				got[0], want)
		}

		// Cross-check against the in-package CPU reference. Under the
		// nocgo build this is the same code path AMMSwap took — but
		// running it explicitly confirms no dispatch indirection
		// silently dropped the result.
		ref, err := ammSwapCPU(reserves, amounts)
		if err != nil {
			t.Fatalf("ammSwapCPU: %v", err)
		}
		if got[0] != ref[0] {
			t.Errorf("AMMSwap=%d diverges from ammSwapCPU=%d", got[0], ref[0])
		}
	})

	// AMM parity — batched. Stress the per-pool loop and the floor-
	// division edge cases (large reserves, small amount, denom that
	// produces a non-trivial remainder). Same recipe as the kernel
	// across every backend.
	t.Run("amm/batched", func(t *testing.T) {
		reserves := []LuxAmmReservePair{
			{ReserveX: 1_000_000, ReserveY: 2_000_000},
			{ReserveX: 5_000_000_000, ReserveY: 3_000_000_000},
			{ReserveX: 1, ReserveY: 1},
		}
		amounts := []uint64{1_000, 10_000_000, 1}
		// Hand-computed expected values:
		//   pool 0: (1_000   * 2_000_000)         / (1_000_000 + 1_000)     = 1_998
		//   pool 1: (10_000_000 * 3_000_000_000)  / (5_000_000_000 + 10_000_000)
		//                                          = 30_000_000_000_000_000 / 5_010_000_000 = 5_988_023
		//   pool 2: (1 * 1)                       / (1 + 1)                = 0
		want := []uint64{1_998, 5_988_023, 0}

		got, err := AMMSwap(reserves, amounts)
		if err != nil {
			t.Fatalf("AMMSwap: %v", err)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("AMMSwap[%d]: got %d, want %d", i, got[i], want[i])
			}
		}

		// Equivalent CPU reference call. Same result MUST come back.
		ref, err := ammSwapCPU(reserves, amounts)
		if err != nil {
			t.Fatalf("ammSwapCPU: %v", err)
		}
		for i := range want {
			if got[i] != ref[i] {
				t.Errorf("AMMSwap[%d]=%d diverges from ammSwapCPU=%d",
					i, got[i], ref[i])
			}
		}
	})

	// CLOB parity — a four-step sequence that exercises every code
	// path in clob_match_step_cpu and asserts the final filled / num
	// values are what the kernel oracle would emit. The output bytes
	// are the GPU plugin's 68-byte format
	// (filled(32) | avg_price(32) | num_fills(4 BE)).
	t.Run("clob/sequence", func(t *testing.T) {
		arena, err := ArenaCreate()
		if err != nil {
			t.Fatalf("ArenaCreate: %v", err)
		}
		t.Cleanup(func() {
			if err := ArenaDestroy(arena); err != nil {
				t.Errorf("ArenaDestroy: %v", err)
			}
		})

		// Step 1: rest an ask at price=100, qty=10 → 0 fills.
		// Side=1 (ask), residual rests at price 100.
		ask100 := encodeCLOBCalldata(t, 1, 100, 10)
		out1, n1, err := CLOBMatch(arena, ask100)
		if err != nil {
			t.Fatalf("CLOBMatch ask@100: %v", err)
		}
		if n1 != 0 {
			t.Errorf("ask@100 first-rest: num_fills=%d, want 0", n1)
		}
		assertCLOBFilled(t, out1, 0, "ask@100 first-rest")

		// Step 2: rest an ask at price=110, qty=5 → 0 fills.
		// Sorted insert: now book is [{100,10}, {110,5}] ascending.
		ask110 := encodeCLOBCalldata(t, 1, 110, 5)
		out2, n2, err := CLOBMatch(arena, ask110)
		if err != nil {
			t.Fatalf("CLOBMatch ask@110: %v", err)
		}
		if n2 != 0 {
			t.Errorf("ask@110 rest: num_fills=%d, want 0", n2)
		}
		assertCLOBFilled(t, out2, 0, "ask@110 rest")

		// Step 3: incoming bid price=120, qty=12 — crosses both
		// resting asks. Fills 10 @ 100 (full top, pop), 2 @ 110
		// (partial second level). Expected:
		//   - filled = 12
		//   - num_fills = 2
		//   - avg_price = (10*100 + 2*110) / 12 = 1220 / 12 = 101 (floor)
		// Residual after match = 0, so no insert; book becomes
		// [{110, 3}] on the ask side.
		bid120 := encodeCLOBCalldata(t, 0, 120, 12)
		out3, n3, err := CLOBMatch(arena, bid120)
		if err != nil {
			t.Fatalf("CLOBMatch bid@120: %v", err)
		}
		if n3 != 2 {
			t.Errorf("bid@120 sweep: num_fills=%d, want 2", n3)
		}
		assertCLOBFilled(t, out3, 12, "bid@120 sweep")
		assertCLOBAvgPrice(t, out3, 101, "bid@120 sweep")

		// Step 4: rest a bid at price=90, qty=4 (doesn't cross the
		// remaining ask at 110). Expected: 0 fills, residual rests
		// as bid level. Book: bids=[{90,4}], asks=[{110,3}].
		bid90 := encodeCLOBCalldata(t, 0, 90, 4)
		out4, n4, err := CLOBMatch(arena, bid90)
		if err != nil {
			t.Fatalf("CLOBMatch bid@90: %v", err)
		}
		if n4 != 0 {
			t.Errorf("bid@90 rest: num_fills=%d, want 0", n4)
		}
		assertCLOBFilled(t, out4, 0, "bid@90 rest")

		// Step 5: incoming ask price=85, qty=2 — crosses the resting
		// bid at 90. Partial fill of the bid level (qty=4 - 2 = 2 left).
		// Expected:
		//   - filled = 2, num_fills = 1, avg_price = 90.
		ask85 := encodeCLOBCalldata(t, 1, 85, 2)
		out5, n5, err := CLOBMatch(arena, ask85)
		if err != nil {
			t.Fatalf("CLOBMatch ask@85: %v", err)
		}
		if n5 != 1 {
			t.Errorf("ask@85 partial: num_fills=%d, want 1", n5)
		}
		assertCLOBFilled(t, out5, 2, "ask@85 partial")
		assertCLOBAvgPrice(t, out5, 90, "ask@85 partial")
	})
}

// encodeCLOBCalldata builds the 117-byte EVM precompile input from
// uint64-sized price/qty fixtures. uint256 BE wire format — same
// encoding the kernel parses.
func encodeCLOBCalldata(t *testing.T, side uint8, price, qty uint64) []byte {
	t.Helper()
	buf := make([]byte, LuxCLOBCalldataLen)
	buf[0] = side
	// uint64 → 32-byte BE: zero high 24 bytes, big-endian low 8.
	binary.BigEndian.PutUint64(buf[1+24:1+32], price)
	binary.BigEndian.PutUint64(buf[33+24:33+32], qty)
	// user (20 bytes) + book_id (32 bytes) are not parsed by the
	// matcher; leave at zero. Same as the kernel.
	return buf
}

// assertCLOBFilled checks that the 32-byte BE filled field equals the
// expected uint64 value (zero-extended into 32 bytes).
func assertCLOBFilled(t *testing.T, out [LuxCLOBOutLen]byte, want uint64, label string) {
	t.Helper()
	var expected [32]byte
	binary.BigEndian.PutUint64(expected[24:], want)
	if !bytes.Equal(out[0:32], expected[:]) {
		t.Errorf("%s: filled bytes = %x, want %x", label, out[0:32], expected)
	}
}

// assertCLOBAvgPrice checks that the 32-byte BE avg_price field equals
// the expected uint64 (zero-extended). The kernel computes VWAP as a
// full uint256 then writes it BE; our fixtures keep the value small
// enough to fit in uint64 so we can compare in plain numbers.
func assertCLOBAvgPrice(t *testing.T, out [LuxCLOBOutLen]byte, want uint64, label string) {
	t.Helper()
	var expected [32]byte
	binary.BigEndian.PutUint64(expected[24:], want)
	if !bytes.Equal(out[32:64], expected[:]) {
		t.Errorf("%s: avg_price bytes = %x, want %x",
			label, out[32:64], expected)
	}
}
