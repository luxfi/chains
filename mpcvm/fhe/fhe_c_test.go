//go:build cgo

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"io"
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

// ---------------------------------------------------------------------------
// What the accelerator does without a GPU behind it
// ---------------------------------------------------------------------------

// discardLogger is a real logger over a writer that keeps nothing. It matters
// that it is real: the accelerator skips its whole reporting block when the
// logger IsZero, which log.Noop is, so a Noop logger leaves that path unrun.
func discardLogger() log.Logger { return log.NewWriter(io.Discard) }

// ring8192 is the smallest ring that clears the accelerator's own GPU
// thresholds (N >= 8192), so a batch large enough to be offered to a GPU can be
// built.
func ring8192(t testing.TB) *ring.Ring {
	t.Helper()
	r, err := ring.NewRing(8192, []uint64{0x7fffffffe0001})
	require.NoError(t, err)
	return r
}

func filled(t testing.TB, r *ring.Ring, n int) []ring.Poly {
	t.Helper()
	out := make([]ring.Poly, n)
	for i := range out {
		out[i] = r.NewPoly()
		for j := range out[i].Coeffs[0] {
			out[i].Coeffs[0][j] = uint64(i*7 + j)
		}
	}
	return out
}

// TestAcceleratorReportsCPUWithoutAGPU holds what the accelerator says about
// itself on a host with no GPU backend: not enabled, and a backend name that
// says so rather than naming a device that is not there. Callers pick batch
// sizes off this.
func TestAcceleratorReportsCPUWithoutAGPU(t *testing.T) {
	accel, err := NewFHEAccelerator(discardLogger())
	require.NoError(t, err)
	require.False(t, accel.IsEnabled())
	require.Equal(t, "CPU (GPU not available)", accel.Backend())
	require.Equal(t, FHEStats{}, accel.Stats())

	// Asking for the CPU backend explicitly reaches the same place.
	cpu, err := NewFHEAcceleratorWithOptions(discardLogger(), FHEOptions{Backend: "cpu"})
	require.NoError(t, err)
	require.False(t, cpu.IsEnabled())
	require.Equal(t, "CPU (GPU not available)", cpu.Backend())
}

// TestAcceleratorMatchesTheCPUReference holds the property the whole
// accelerator exists to preserve: whichever path a batch takes, the
// coefficients that come out are the ones the ring's own NTT produces. A
// wrong-but-fast transform is worse than no acceleration at all.
func TestAcceleratorMatchesTheCPUReference(t *testing.T) {
	accel, err := NewFHEAccelerator(discardLogger())
	require.NoError(t, err)
	r := ring8192(t)

	// Batch sizes straddling every threshold in the three batch paths: 0, the
	// polymul/inverse cutoff at 4, and the forward cutoff at 64.
	for _, n := range []int{0, 1, 4, 8, 64} {
		batch := filled(t, r, n)
		reference := filled(t, r, n)
		for i := range reference {
			r.NTT(reference[i], reference[i])
		}

		require.NoError(t, accel.BatchNTTForward(r, batch))
		for i := range batch {
			require.Equal(t, reference[i].Coeffs[0], batch[i].Coeffs[0], "n=%d poly %d", n, i)
		}

		require.NoError(t, accel.BatchNTTInverse(r, batch))
		original := filled(t, r, n)
		for i := range batch {
			require.Equal(t, original[i].Coeffs[0], batch[i].Coeffs[0], "n=%d poly %d round trip", n, i)
		}

		out := filled(t, r, n)
		require.NoError(t, accel.BatchPolyMul(r, batch, original, out))
		for i := range out {
			want := r.NewPoly()
			r.MulCoeffsBarrett(batch[i], original[i], want)
			require.Equal(t, want.Coeffs[0], out[i].Coeffs[0], "n=%d poly %d", n, i)
		}
	}
}

// TestBatchPolyMulRefusesMismatchedBatches holds that three slices of different
// lengths are refused rather than multiplied up to the shortest. Silently
// truncating would leave the tail of the output holding whatever it held
// before, which downstream reads as a valid product.
func TestBatchPolyMulRefusesMismatchedBatches(t *testing.T) {
	accel, err := NewFHEAccelerator(discardLogger())
	require.NoError(t, err)
	r := ring8192(t)

	a, b, out := filled(t, r, 4), filled(t, r, 3), filled(t, r, 4)
	require.ErrorContains(t, accel.BatchPolyMul(r, a, b, out), "batch size mismatch")
	require.ErrorContains(t, accel.BatchPolyMul(r, a, out, b), "batch size mismatch")
}

// TestEnabledAcceleratorWithoutASessionFallsBackToCPU holds the guard that
// stands between "GPU acceleration is on" and "there is a session to run it
// on". Close() leaves exactly that state -- enabled cleared, session cleared --
// and the batch paths check the session again after taking the lock, because
// Close can land between the enabled check and the dispatch. Without the guard
// a batch on a closed accelerator dereferences nil in the middle of a block.
func TestEnabledAcceleratorWithoutASessionFallsBackToCPU(t *testing.T) {
	accel, err := NewFHEAccelerator(discardLogger())
	require.NoError(t, err)
	r := ring8192(t)

	// The state a host with a GPU has, minus the session.
	accel.enabled = true

	for _, n := range []int{4, 64} {
		batch := filled(t, r, n)
		reference := filled(t, r, n)
		for i := range reference {
			r.NTT(reference[i], reference[i])
		}

		require.NoError(t, accel.BatchNTTForward(r, batch))
		for i := range batch {
			require.Equal(t, reference[i].Coeffs[0], batch[i].Coeffs[0], "n=%d poly %d", n, i)
		}

		require.NoError(t, accel.BatchNTTInverse(r, batch))
		require.NoError(t, accel.BatchPolyMul(r, batch, batch, filled(t, r, n)))
	}

	// It still says it is enabled, and names its backend from the session it
	// does not have.
	require.True(t, accel.IsEnabled())
	require.Equal(t, "CPU (GPU not available)", accel.Backend())
}

// TestCloseDisablesTheAccelerator holds that Close leaves the accelerator
// usable and CPU-backed rather than half-torn-down: the session it borrowed
// belongs to the accel package, so Close drops the reference instead of
// releasing a session other holders are still using.
func TestCloseDisablesTheAccelerator(t *testing.T) {
	accel, err := NewFHEAccelerator(discardLogger())
	require.NoError(t, err)

	accel.enabled = true
	accel.Close()
	require.False(t, accel.IsEnabled())
	require.Nil(t, accel.session)
	require.Equal(t, "CPU (GPU not available)", accel.Backend())

	// Close is idempotent, and ClearCache has nothing to clear.
	accel.Close()
	accel.ClearCache()

	r := ring8192(t)
	require.NoError(t, accel.BatchNTTForward(r, filled(t, r, 8)))
}

// TestGlobalAcceleratorIsOne holds that the process-wide accelerator is built
// once and shared. Two accelerators would keep two sets of statistics and, on a
// GPU host, two claims on the same device.
func TestGlobalAcceleratorIsOne(t *testing.T) {
	first, err := GetFHEAccelerator()
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := GetFHEAccelerator()
	require.NoError(t, err)
	require.Same(t, first, second)
}
