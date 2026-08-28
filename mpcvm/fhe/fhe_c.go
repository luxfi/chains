//go:build cgo

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package fhe provides GPU-accelerated FHE operations for ThresholdVM.
//
// This file provides GPU acceleration for:
//   - NTT forward/inverse transforms (40x speedup on Apple Silicon)
//   - Polynomial multiplication in CKKS scheme
//   - Batch FHE operations for throughput
//
// Architecture:
//
//	lux/accel (unified GPU) → ThresholdVM FHE
package fhe

import (
	"fmt"
	"sync"

	"github.com/luxfi/accel"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/log"
	"github.com/luxfi/node/config"
)

// FHEAccelerator provides GPU-accelerated FHE operations for ThresholdVM.
// It uses the unified accel package to accelerate CKKS operations.
type FHEAccelerator struct {
	mu      sync.RWMutex
	session *accel.Session
	enabled bool
	logger  log.Logger
	stats   *FHEStats
}

// FHEStats tracks GPU acceleration statistics
type FHEStats struct {
	NTTForwardCalls  uint64
	NTTInverseCalls  uint64
	PolyMulCalls     uint64
	BatchCalls       uint64
	GPUFallbackCalls uint64
	TotalGPUTimeNs   uint64
}

// FHEOptions holds options for creating a GPU FHE accelerator.
type FHEOptions struct {
	// Enabled controls whether GPU acceleration is used
	Enabled bool
	// Backend specifies which GPU backend to use: "auto", "metal", "cuda", "cpu"
	Backend string
}

// NewFHEAccelerator creates a new GPU FHE accelerator for ThresholdVM.
func NewFHEAccelerator(logger log.Logger) (*FHEAccelerator, error) {
	return NewFHEAcceleratorWithOptions(logger, FHEOptions{})
}

// NewFHEAcceleratorWithOptions creates a new GPU FHE accelerator with custom options.
// If options are zero-valued, it uses the global GPU config.
func NewFHEAcceleratorWithOptions(logger log.Logger, opts FHEOptions) (*FHEAccelerator, error) {
	// Get global config if options not specified
	gpuCfg := config.GetGlobalGPUConfig()

	// Determine if GPU should be enabled
	enabled := gpuCfg.Enabled
	if opts.Backend == "cpu" {
		enabled = false
	}

	// Check if accel is available
	available := accel.Available() && enabled

	var session *accel.Session
	if available {
		var err error
		session, err = accel.DefaultSession()
		if err != nil {
			available = false
			if !logger.IsZero() {
				logger.Warn("Failed to create accel session, using CPU fallback",
					"error", err)
			}
		}
	}

	if !logger.IsZero() {
		if available && session != nil {
			logger.Info("GPU FHE acceleration enabled via accel",
				"backend", session.Backend().String(),
				"device", session.DeviceInfo().Name)
		} else {
			logger.Warn("GPU FHE acceleration not available, using CPU fallback",
				"gpuConfigEnabled", gpuCfg.Enabled,
				"accelAvailable", accel.Available())
		}
	}

	return &FHEAccelerator{
		session: session,
		enabled: available && session != nil,
		logger:  logger,
		stats:   &FHEStats{},
	}, nil
}

// IsEnabled returns whether GPU acceleration is available.
func (g *FHEAccelerator) IsEnabled() bool {
	return g.enabled
}

// Backend returns the active GPU backend name.
func (g *FHEAccelerator) Backend() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.enabled || g.session == nil {
		return "CPU (GPU not available)"
	}
	return g.session.Backend().String()
}

// Stats returns current GPU statistics.
func (g *FHEAccelerator) Stats() FHEStats {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return *g.stats
}

// =============================================================================
// One device round trip, three kernels
// =============================================================================
//
// The three batch entry points below differ in exactly three things: how many
// polynomials one element reads, which lattice kernel runs, and what the CPU
// does instead. Everything else — the size floor, the session snapshot, the
// tensor lifecycle, and the rule that ANY device failure falls back to the CPU
// rather than failing the batch — used to be written out three times, ~45
// statements each. Three copies of a resource lifecycle are three places to
// forget a Close, and a kernel added later is a fourth.
//
// The floors are NOT unified, deliberately. Forward NTT goes to the device only
// at 64 polynomials and ring degree 8192; inverse NTT and multiply go at 4, at
// any degree. The reasoning written on the forward path — that below some size
// the host/device transfer costs more than the kernel saves — applies to all
// three, so the other two look like drift rather than a decision. Changing a
// performance threshold needs a device to measure on, and this host has none,
// so the numbers are carried through as parameters and the disagreement is
// stated rather than guessed at.

// kernel is one lattice operation on operands already resident on the device.
type kernel func(ops accel.LatticeOps, in []*accel.UntypedTensor, out *accel.UntypedTensor, q uint32) error

// element moves one batch element's operands onto the device, runs k, and
// brings the result back. Every tensor it opens it closes, on every path,
// including the ones it never got to use.
func element(s *accel.Session, n int, q uint32, operands [][]uint64, k kernel) ([]uint64, error) {
	var open []*accel.Tensor[uint64]
	defer func() {
		for _, t := range open {
			t.Close()
		}
	}()

	in := make([]*accel.UntypedTensor, 0, len(operands))
	for _, src := range operands {
		t, err := accel.NewTensorWithData[uint64](s, []int{n}, src[:n])
		if err != nil {
			return nil, err
		}
		open = append(open, t)
		in = append(in, t.Untyped())
	}

	out, err := accel.NewTensor[uint64](s, []int{n})
	if err != nil {
		return nil, err
	}
	open = append(open, out)

	if err := k(s.Lattice(), in, out.Untyped(), q); err != nil {
		return nil, err
	}
	if err := s.Sync(); err != nil {
		return nil, err
	}
	return out.ToSlice()
}

// offload runs k over a batch of count elements, writing each result into the
// slice dst names, and does cpu(i) instead for any element the device will not
// take — a short coefficient slice, a failed allocation, a kernel error, a
// failed readback. A device that cannot do the work is a slower batch, never a
// failed one.
func (g *FHEAccelerator) offload(
	r *ring.Ring,
	count, minBatch, minDegree int,
	cpu func(i int),
	operands func(i int) [][]uint64,
	dst func(i int) []uint64,
	k kernel,
) error {
	// An empty batch needs no special case: count < minBatch is already true of
	// it for every floor, so it takes the same path as a batch too small to be
	// worth a device, and loops zero times.
	n := r.N()
	if !g.enabled || count < minBatch || n < minDegree {
		for i := 0; i < count; i++ {
			cpu(i)
		}
		return nil
	}

	g.mu.RLock()
	session := g.session
	g.mu.RUnlock()
	if session == nil {
		for i := 0; i < count; i++ {
			cpu(i)
		}
		return nil
	}

	if len(r.ModuliChain()) == 0 {
		return fmt.Errorf("ring has no moduli")
	}
	q := uint32(r.ModuliChain()[0])

	for i := 0; i < count; i++ {
		src := operands(i)
		if src == nil {
			cpu(i)
			continue
		}
		result, err := element(session, n, q, src, k)
		if err != nil {
			cpu(i)
			continue
		}
		copy(dst(i), result)
	}

	g.mu.Lock()
	g.stats.BatchCalls++
	g.mu.Unlock()
	return nil
}

// wide returns the coefficient rows of polys[i] if the element is wide enough
// to move, and nil if it is not — which offload reads as "do this one on the
// CPU".
func wide(n int, polys ...ring.Poly) [][]uint64 {
	out := make([][]uint64, 0, len(polys))
	for _, p := range polys {
		if len(p.Coeffs) == 0 || len(p.Coeffs[0]) < n {
			return nil
		}
		out = append(out, p.Coeffs[0])
	}
	return out
}

// BatchNTTForward performs forward NTT on multiple polynomials.
// This is the primary use case for GPU acceleration - batch operations.
func (g *FHEAccelerator) BatchNTTForward(r *ring.Ring, polys []ring.Poly) error {
	return g.offload(r, len(polys), 64, 8192,
		func(i int) { r.NTT(polys[i], polys[i]) },
		func(i int) [][]uint64 { return wide(r.N(), polys[i]) },
		func(i int) []uint64 { return polys[i].Coeffs[0] },
		func(ops accel.LatticeOps, in []*accel.UntypedTensor, out *accel.UntypedTensor, q uint32) error {
			return ops.PolynomialNTT(in[0], out, q)
		})
}

// BatchNTTInverse performs inverse NTT on multiple polynomials.
func (g *FHEAccelerator) BatchNTTInverse(r *ring.Ring, polys []ring.Poly) error {
	return g.offload(r, len(polys), 4, 0,
		func(i int) { r.INTT(polys[i], polys[i]) },
		func(i int) [][]uint64 { return wide(r.N(), polys[i]) },
		func(i int) []uint64 { return polys[i].Coeffs[0] },
		func(ops accel.LatticeOps, in []*accel.UntypedTensor, out *accel.UntypedTensor, q uint32) error {
			return ops.PolynomialINTT(in[0], out, q)
		})
}

// BatchPolyMul performs polynomial multiplication on batches using GPU.
func (g *FHEAccelerator) BatchPolyMul(r *ring.Ring, a, b, out []ring.Poly) error {
	if len(a) != len(b) || len(a) != len(out) {
		return fmt.Errorf("batch size mismatch")
	}
	return g.offload(r, len(a), 4, 0,
		func(i int) { r.MulCoeffsBarrett(a[i], b[i], out[i]) },
		func(i int) [][]uint64 { return wide(r.N(), a[i], b[i], out[i]) },
		func(i int) []uint64 { return out[i].Coeffs[0] },
		func(ops accel.LatticeOps, in []*accel.UntypedTensor, o *accel.UntypedTensor, q uint32) error {
			return ops.PolynomialMul(in[0], in[1], o, q)
		})
}

// ClearCache clears any cached state.
func (g *FHEAccelerator) ClearCache() {
	// No cache to clear with accel - session manages resources
}

// Close releases all GPU resources.
func (g *FHEAccelerator) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Session is managed by accel.DefaultSession, don't close it here
	g.session = nil
	g.enabled = false
}

// Global GPU accelerator instance (lazily initialized)
var (
	globalFHEAccelerator     *FHEAccelerator
	globalFHEAcceleratorOnce sync.Once
	globalFHEAcceleratorErr  error
)

// GetFHEAccelerator returns the global GPU FHE accelerator instance.
func GetFHEAccelerator() (*FHEAccelerator, error) {
	globalFHEAcceleratorOnce.Do(func() {
		globalFHEAccelerator, globalFHEAcceleratorErr = NewFHEAccelerator(log.Noop())
	})
	return globalFHEAccelerator, globalFHEAcceleratorErr
}
