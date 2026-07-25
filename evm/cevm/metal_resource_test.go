//go:build cgo

package cevm

import (
	"slices"
	"testing"
)

// TestMetalSustainedExecution guards the fix in luxcpp/cevm's
// EvmKernelHost::create(): it used to compile evm_kernel.metal and allocate a
// command queue and pipeline states on every call, so a process doing
// sustained work piled up Metal objects until the driver faulted. The crash
// needed volume to show up — any single execution was fine, which is why it
// survived as long as it did.
//
// Executing the same trivial block many times reproduces that in seconds. It
// is a resource test, so it asserts only that every run completes; opcode
// semantics are covered by TestOpcodeCoverage_GPU_vs_CPU.
func TestMetalSustainedExecution(t *testing.T) {
	if !slices.Contains(AvailableBackends(), GPUMetal) {
		t.Skip("no Metal backend on this host")
	}
	var from [20]byte
	from[19] = 0x42
	tx := Transaction{
		From:     from,
		GasLimit: 100_000,
		GasPrice: 1,
		Code:     []byte{0x60, 0x01, 0x00}, // PUSH1 1; STOP
	}
	const runs = 250
	for i := range runs {
		if _, err := ExecuteBlock(GPUMetal, 1, []Transaction{tx}, nil, nil); err != nil {
			t.Fatalf("run %d of %d failed: %v", i+1, runs, err)
		}
	}
}
