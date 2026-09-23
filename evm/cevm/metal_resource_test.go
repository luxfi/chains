//go:build cgo && lux_cevm_native

package cevm

import "testing"

// TestMetalSustainedExecution guards against a device path that builds its
// pipelines and queues on every call: a process doing sustained work piles
// them up until the driver faults, which no single execution shows. Running
// the same block of transfers many times reproduces that in seconds, and
// every run must still be the block's answer.
func TestMetalSustainedExecution(t *testing.T) {
	if !contains(deviceLanes(t), GPUMetal) {
		t.Skip("Metal runs no block on this host")
	}
	txs, ctx, state := transfers(1)
	const runs = 250
	for i := range runs {
		r, err := ExecuteBlock(GPUMetal, 1, txs, &ctx, state)
		if err != nil || !allTransfers(r, 1) {
			t.Fatalf("run %d of %d: err=%v result=%+v", i+1, runs, err, r)
		}
	}
}
