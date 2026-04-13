//go:build cgo

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"testing"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

func TestFHEAccelerator(t *testing.T) {
	accel, err := NewFHEAccelerator(log.Noop())
	require.NoError(t, err)
	require.NotNil(t, accel)

	t.Logf("GPU enabled: %v", accel.IsEnabled())
	t.Logf("Backend: %s", accel.Backend())
}

func TestBatchNTT(t *testing.T) {
	accel, err := NewFHEAccelerator(log.Noop())
	require.NoError(t, err)

	// Test that batch operations work via CPU path
	// (GPU threshold requires 64+ polys at N>=8192)
	N := 1024
	Q := uint64(0x7fffffffe0001) // NTT-friendly prime

	r, err := ring.NewRing(N, []uint64{Q})
	require.NoError(t, err)

	// Create test polynomials with known values
	numPolys := 8
	polys := make([]ring.Poly, numPolys)
	original := make([][]uint64, numPolys)
	for i := range polys {
		polys[i] = r.NewPoly()
		original[i] = make([]uint64, N)
		for j := 0; j < N; j++ {
			val := uint64((i*N + j) % int(Q))
			polys[i].Coeffs[0][j] = val
			original[i][j] = val
		}
	}

	// Verify the CPU-based ring NTT works for round-trip
	for i := range polys {
		r.NTT(polys[i], polys[i])
	}
	for i := range polys {
		r.INTT(polys[i], polys[i])
	}

	// Should return to original values (NTT is invertible)
	for i := range polys {
		for j := 0; j < N; j++ {
			require.Equal(t, original[i][j], polys[i].Coeffs[0][j],
				"CPU NTT round-trip mismatch at poly %d, coeff %d", i, j)
		}
	}

	t.Logf("GPU enabled: %v, backend: %s", accel.IsEnabled(), accel.Backend())
	t.Logf("Stats: %+v", accel.Stats())
}

func BenchmarkNTTForwardCPU(b *testing.B) {
	N := 16384
	Q := uint64(0x7fffffffe0001)

	r, _ := ring.NewRing(N, []uint64{Q})
	poly := r.NewPoly()

	for i := 0; i < N; i++ {
		poly.Coeffs[0][i] = uint64(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.NTT(poly, poly)
	}
}

func BenchmarkNTTForwardAccel(b *testing.B) {
	accel, err := NewFHEAccelerator(log.Noop())
	if err != nil || !accel.IsEnabled() {
		b.Skip("GPU not available")
	}

	N := 16384
	Q := uint64(0x7fffffffe0001)

	r, _ := ring.NewRing(N, []uint64{Q})

	polys := make([]ring.Poly, 16)
	for i := range polys {
		polys[i] = r.NewPoly()
		for j := 0; j < N; j++ {
			polys[i].Coeffs[0][j] = uint64(j)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = accel.BatchNTTForward(r, polys)
	}
}

func BenchmarkBatchNTT16(b *testing.B) {
	benchmarkBatchNTT(b, 16)
}

func BenchmarkBatchNTT64(b *testing.B) {
	benchmarkBatchNTT(b, 64)
}

func BenchmarkBatchNTT256(b *testing.B) {
	benchmarkBatchNTT(b, 256)
}

func benchmarkBatchNTT(b *testing.B, batchSize int) {
	accel, err := NewFHEAccelerator(log.Noop())
	if err != nil {
		b.Skip("GPU not available")
	}

	N := 8192
	Q := uint64(0x7fffffffe0001)

	r, _ := ring.NewRing(N, []uint64{Q})

	polys := make([]ring.Poly, batchSize)
	for i := range polys {
		polys[i] = r.NewPoly()
		for j := 0; j < N; j++ {
			polys[i].Coeffs[0][j] = uint64(j)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = accel.BatchNTTForward(r, polys)
	}

	b.ReportMetric(float64(batchSize*b.N)/b.Elapsed().Seconds(), "polys/sec")
}

func BenchmarkPolyMulCPU(b *testing.B) {
	N := 8192
	Q := uint64(0x7fffffffe0001)

	r, _ := ring.NewRing(N, []uint64{Q})

	a := r.NewPoly()
	bb := r.NewPoly()
	out := r.NewPoly()

	for i := 0; i < N; i++ {
		a.Coeffs[0][i] = uint64(i)
		bb.Coeffs[0][i] = uint64(N - i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.MulCoeffsBarrett(a, bb, out)
	}
}

func BenchmarkBatchPolyMulAccel(b *testing.B) {
	accel, err := NewFHEAccelerator(log.Noop())
	if err != nil || !accel.IsEnabled() {
		b.Skip("GPU not available")
	}

	batchSize := 32
	N := 8192
	Q := uint64(0x7fffffffe0001)

	r, _ := ring.NewRing(N, []uint64{Q})

	a := make([]ring.Poly, batchSize)
	bb := make([]ring.Poly, batchSize)
	out := make([]ring.Poly, batchSize)

	for i := range a {
		a[i] = r.NewPoly()
		bb[i] = r.NewPoly()
		out[i] = r.NewPoly()
		for j := 0; j < N; j++ {
			a[i].Coeffs[0][j] = uint64(j)
			bb[i].Coeffs[0][j] = uint64(N - j)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = accel.BatchPolyMul(r, a, bb, out)
	}

	b.ReportMetric(float64(batchSize*b.N)/b.Elapsed().Seconds(), "muls/sec")
}
