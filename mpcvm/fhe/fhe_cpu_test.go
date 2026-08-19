//go:build !cgo

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// The pure-Go accelerator had no test of any kind: every other file in this
// package is //go:build cgo, so a CGO_ENABLED=0 build compiled fhe.go and then
// ran nothing against it. That is the build a CPU-only node runs, and it is the
// only build that cross-compiles cleanly to a cluster node, so it is the one
// worth measuring.
//
// Parameters mirror the cgo benchmarks (N=16384, one NTT-friendly prime) so the
// two paths can be compared directly rather than approximately.
package fhe

import (
	"testing"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/log"
)

const (
	benchN = 16384
	benchQ = uint64(0x7fffffffe0001)
)

func cpuRing(tb testing.TB) (*FHEAccelerator, *ring.Ring) {
	tb.Helper()
	accel, err := NewFHEAccelerator(log.Noop())
	if err != nil {
		tb.Fatalf("NewFHEAccelerator: %v", err)
	}
	r, err := ring.NewRing(benchN, []uint64{benchQ})
	if err != nil {
		tb.Fatalf("NewRing: %v", err)
	}
	return accel, r
}

func polys(r *ring.Ring, n int) []ring.Poly {
	out := make([]ring.Poly, n)
	for i := range out {
		out[i] = r.NewPoly()
		for j := 0; j < benchN; j++ {
			out[i].Coeffs[0][j] = uint64(i*benchN+j) % benchQ
		}
	}
	return out
}

// TestCPUBackendRoundTrip is the correctness floor the benchmarks stand on: a
// number that comes from an operation computing the wrong thing is not a
// measurement. Forward then inverse NTT must return the original coefficients.
func TestCPUBackendRoundTrip(t *testing.T) {
	accel, r := cpuRing(t)
	defer accel.Close()

	// IsEnabled reports that the accelerator is usable, not that a GPU exists —
	// the pure-Go build is enabled and CPU-backed. The backend string is what
	// separates the two, so that is what this pins.
	if got := accel.Backend(); got != "CPU (Pure Go lattice)" {
		t.Fatalf("the !cgo build must run the pure-Go CPU backend, got %q", got)
	}

	in := polys(r, 16)
	want := make([][]uint64, len(in))
	for i := range in {
		want[i] = append([]uint64(nil), in[i].Coeffs[0]...)
	}

	if err := accel.BatchNTTForward(r, in); err != nil {
		t.Fatalf("BatchNTTForward: %v", err)
	}
	if err := accel.BatchNTTInverse(r, in); err != nil {
		t.Fatalf("BatchNTTInverse: %v", err)
	}

	for i := range in {
		for j := 0; j < benchN; j++ {
			if in[i].Coeffs[0][j] != want[i][j] {
				t.Fatalf("round-trip mismatch at poly %d coeff %d: got %d want %d",
					i, j, in[i].Coeffs[0][j], want[i][j])
			}
		}
	}
}

func benchBatch(b *testing.B, n int) {
	accel, r := cpuRing(b)
	defer accel.Close()
	p := polys(r, n)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := accel.BatchNTTForward(r, p); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	// polys/sec is the number that matters for sizing: op latency alone hides
	// whether a bigger batch buys anything.
	b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds(), "polys/sec")
}

func BenchmarkCPUNTTForward(b *testing.B) {
	accel, r := cpuRing(b)
	defer accel.Close()
	p := polys(r, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := accel.BatchNTTForward(r, p); err != nil {
			b.Fatal(err)
		}
	}
}

// 4 and 8 straddle the sequential/parallel split in BatchNTTForward: below 8 it
// runs inline, at 8 and above it fans out to a FIXED four workers. The pair says
// whether that boundary is where the speedup actually starts.
func BenchmarkCPUBatchNTT4(b *testing.B)   { benchBatch(b, 4) }
func BenchmarkCPUBatchNTT8(b *testing.B)   { benchBatch(b, 8) }
func BenchmarkCPUBatchNTT16(b *testing.B)  { benchBatch(b, 16) }
func BenchmarkCPUBatchNTT64(b *testing.B)  { benchBatch(b, 64) }
func BenchmarkCPUBatchNTT256(b *testing.B) { benchBatch(b, 256) }

func BenchmarkCPUPolyMul(b *testing.B) {
	accel, r := cpuRing(b)
	defer accel.Close()
	x, y := polys(r, 1), polys(r, 1)
	out := []ring.Poly{r.NewPoly()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := accel.BatchPolyMul(r, x, y, out); err != nil {
			b.Fatal(err)
		}
	}
}
