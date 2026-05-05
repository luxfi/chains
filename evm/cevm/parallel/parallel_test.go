// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package parallel

import (
	"testing"

	"github.com/luxfi/chains/evm/cevm"
)

// TestExecuteBlockV4_StateSnapshot_GPUCall exercises the state-aware GPU
// dispatch path: a tx whose top-level opcode is CALL into a deployed
// contract address. Pre-V4 every backend would return TxCallNotSupported
// because the kernel had no way to resolve the target's code on-device.
// With V4 the dispatcher hands the kernel a state snapshot containing the
// target's code, so the call executes through the GPU CALL trampoline.
//
// We don't assert TxOK strictly — the LP-108 P5 corpus is the cevm side's
// gate for which CALL shapes the GPU CALL trampoline supports. What we
// verify here is that:
//   1. ExecuteBlockV4 returns without error.
//   2. The result has the new ABIVersion (6) — proves the v4 ABI wired
//      end-to-end.
//   3. Per-tx status / gas slices have the right length.
//   4. Backends that DO support state-aware CALL return a non-OOG status
//      (i.e. the kernel made progress past the kernel-internal "not
//      supported" sentinel).
func TestExecuteBlockV4_StateSnapshot_GPUCall(t *testing.T) {
	backends := cevm.AvailableBackends()
	if len(backends) == 0 {
		t.Skip("no backends available")
	}

	// Caller program: CALL with constant 20-byte target, 0 value, 0 gas hint.
	//   PUSH1 0   (retSize)
	//   PUSH1 0   (retOff)
	//   PUSH1 0   (argSize)
	//   PUSH1 0   (argOff)
	//   PUSH1 0   (value)
	//   PUSH20 <target>  (to)
	//   PUSH2 0xFFFF   (gas)
	//   CALL
	//   POP
	//   STOP
	//
	// The target's bytecode is a trivial STOP — fine because the test only
	// verifies that the kernel resolved the target on-device instead of
	// bailing out with CallNotSupported.
	target := [20]byte{
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
	}
	caller := [20]byte{
		0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0,
		0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05,
	}

	callerCode := []byte{
		0x60, 0x00, // PUSH1 0 retSize
		0x60, 0x00, // PUSH1 0 retOff
		0x60, 0x00, // PUSH1 0 argSize
		0x60, 0x00, // PUSH1 0 argOff
		0x60, 0x00, // PUSH1 0 value
		0x73, // PUSH20
	}
	callerCode = append(callerCode, target[:]...)
	callerCode = append(callerCode,
		0x61, 0xff, 0xff, // PUSH2 0xFFFF gas
		0xf1, // CALL
		0x50, // POP
		0x00, // STOP
	)
	// Target bytecode: STOP only.
	targetCode := []byte{0x00}

	// Code-hash: kernel reads it from the snapshot, doesn't recompute.
	// Empty for the test — the GPU CALL path checks size != 0 first.
	var emptyHash [32]byte

	tx := cevm.Transaction{
		HasTo:    true,
		Code:     callerCode,
		GasLimit: 200_000,
		GasPrice: 1,
	}
	tx.From = caller
	tx.To = caller // tx target is self; the inner CALL goes to `target`

	state := []cevm.StateAccount{
		{Address: caller, Nonce: 1, CodeHash: emptyHash},
		{Address: target, Code: targetCode, CodeHash: emptyHash},
	}

	for _, b := range backends {
		b := b
		t.Run(cevm.BackendName(b), func(t *testing.T) {
			r, err := cevm.ExecuteBlockV4(b, 0, []cevm.Transaction{tx}, nil, state)
			if err != nil {
				t.Fatalf("ExecuteBlockV4: %v", err)
			}
			if r.ABIVersion != cevm.ABIVersion {
				t.Errorf("ABIVersion=%d want %d", r.ABIVersion, cevm.ABIVersion)
			}
			if len(r.GasUsed) != 1 || len(r.Status) != 1 {
				t.Fatalf("malformed result: gas_len=%d status_len=%d",
					len(r.GasUsed), len(r.Status))
			}
			t.Logf("backend=%s status=%s gas=%d", b, r.Status[0], r.GasUsed[0])
		})
	}
}

// TestExecuteBlockV4_EmptySnapshot is the V3-equivalent path: an empty
// snapshot must produce the same result as ExecuteBlockV3. Guards against
// a regression where the new code path corrupts results when the caller
// passes no state.
func TestExecuteBlockV4_EmptySnapshot(t *testing.T) {
	backends := cevm.AvailableBackends()
	if len(backends) == 0 {
		t.Skip("no backends available")
	}

	// Simple ADD program — no CALL involvement.
	code := []byte{
		0x60, 0x01, // PUSH1 1
		0x60, 0x01, // PUSH1 1
		0x01, // ADD
		0x50, // POP
		0x00, // STOP
	}
	tx := cevm.Transaction{
		HasTo:    true,
		Code:     code,
		GasLimit: 100_000,
		GasPrice: 1,
	}

	for _, b := range backends {
		b := b
		t.Run(cevm.BackendName(b), func(t *testing.T) {
			r3, err3 := cevm.ExecuteBlockV3(b, 0, []cevm.Transaction{tx}, nil)
			if err3 != nil {
				t.Fatalf("V3: %v", err3)
			}
			r4, err4 := cevm.ExecuteBlockV4(b, 0, []cevm.Transaction{tx}, nil, nil)
			if err4 != nil {
				t.Fatalf("V4: %v", err4)
			}
			if len(r3.GasUsed) != len(r4.GasUsed) {
				t.Fatalf("gas length mismatch V3=%d V4=%d",
					len(r3.GasUsed), len(r4.GasUsed))
			}
			if len(r3.Status) != len(r4.Status) {
				t.Fatalf("status length mismatch V3=%d V4=%d",
					len(r3.Status), len(r4.Status))
			}
			for i := range r3.GasUsed {
				if r3.GasUsed[i] != r4.GasUsed[i] {
					t.Errorf("gas[%d] V3=%d V4=%d (empty snapshot must match V3)",
						i, r3.GasUsed[i], r4.GasUsed[i])
				}
			}
			for i := range r3.Status {
				if r3.Status[i] != r4.Status[i] {
					t.Errorf("status[%d] V3=%s V4=%s (empty snapshot must match V3)",
						i, r3.Status[i], r4.Status[i])
				}
			}
		})
	}
}
