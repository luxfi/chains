// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

// Package fhe provides FHE operations for the zkvm.
// This file provides pure Go CPU implementation when CGO is not available.
// All operations use the luxfi/lattice library which provides optimized
// NTT implementations in pure Go.
package fhe

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/log"
)

// FHEAccelerator provides FHE operations for CKKS.
// When CGO is disabled, this uses the pure Go lattice library
// which provides optimized CPU-based NTT transforms.
type FHEAccelerator struct {
	logger  log.Logger
	stats   *FHEStats
	statsmu sync.RWMutex
}

// FHEStats tracks FHE accelerator statistics.
type FHEStats struct {
	NTTOps       uint64
	INTTOps      uint64
	PolyMulOps   uint64
	GPUHits      uint64
	CPUFallbacks uint64
}

// FHEAccelOptions holds options for creating an FHE accelerator.
type FHEAccelOptions struct {
	// Enabled controls whether GPU acceleration is used (ignored in pure Go build)
	Enabled bool
	// Backend specifies which GPU backend to use (ignored in pure Go build)
	Backend string
	// DeviceIndex specifies which GPU device to use (ignored in pure Go build)
	DeviceIndex int
}

// NewFHEAccelerator creates a new FHE processor using pure Go lattice library.
func NewFHEAccelerator(logger log.Logger) (*FHEAccelerator, error) {
	return NewFHEAcceleratorWithOptions(logger, FHEAccelOptions{})
}

// NewFHEAcceleratorWithOptions creates a new FHE accelerator with custom options.
// In pure Go builds, GPU options are ignored and CPU is always used.
func NewFHEAcceleratorWithOptions(logger log.Logger, _ FHEAccelOptions) (*FHEAccelerator, error) {
	accel := &FHEAccelerator{
		logger: logger,
		stats:  &FHEStats{},
	}

	if logger != nil {
		logger.Info("FHE using CPU (Pure Go lattice library, CGO disabled)")
	}

	return accel, nil
}

// IsEnabled returns false - GPU is never available in pure Go builds.
func (g *FHEAccelerator) IsEnabled() bool {
	return false
}

// Backend returns the backend name.
func (g *FHEAccelerator) Backend() string {
	return "CPU (Pure Go lattice)"
}

// Stats returns current FHE accelerator statistics.
func (g *FHEAccelerator) Stats() FHEStats {
	g.statsmu.RLock()
	defer g.statsmu.RUnlock()
	return FHEStats{
		NTTOps:       atomic.LoadUint64(&g.stats.NTTOps),
		INTTOps:      atomic.LoadUint64(&g.stats.INTTOps),
		PolyMulOps:   atomic.LoadUint64(&g.stats.PolyMulOps),
		GPUHits:      0, // Always 0 in CPU-only build
		CPUFallbacks: atomic.LoadUint64(&g.stats.CPUFallbacks),
	}
}

// ClearCache is a no-op for CPU implementation (no GPU cache).
func (g *FHEAccelerator) ClearCache() {}

// NumberTheoreticTransformer implements NTT operations
// using pure Go lattice library.
type NumberTheoreticTransformer struct {
	accel *FHEAccelerator
	ring  *ring.Ring
	N     int
	Q     uint64
}

// NewNumberTheoreticTransformer creates a new NTT transformer.
func NewNumberTheoreticTransformer(accel *FHEAccelerator, r *ring.Ring) *NumberTheoreticTransformer {
	N := r.N()
	Q := r.ModuliChain()[0]

	return &NumberTheoreticTransformer{
		accel: accel,
		ring:  r,
		N:     N,
		Q:     Q,
	}
}

// Forward performs forward NTT using lattice library.
func (t *NumberTheoreticTransformer) Forward(p ring.Poly, pOut ring.Poly) {
	t.ring.NTT(p, pOut)
	atomic.AddUint64(&t.accel.stats.NTTOps, 1)
	atomic.AddUint64(&t.accel.stats.CPUFallbacks, 1)
}

// ForwardLazy performs forward NTT without final reduction.
func (t *NumberTheoreticTransformer) ForwardLazy(p ring.Poly, pOut ring.Poly) {
	t.ring.NTT(p, pOut)
	atomic.AddUint64(&t.accel.stats.NTTOps, 1)
	atomic.AddUint64(&t.accel.stats.CPUFallbacks, 1)
}

// Backward performs inverse NTT using lattice library.
func (t *NumberTheoreticTransformer) Backward(p ring.Poly, pOut ring.Poly) {
	t.ring.INTT(p, pOut)
	atomic.AddUint64(&t.accel.stats.INTTOps, 1)
	atomic.AddUint64(&t.accel.stats.CPUFallbacks, 1)
}

// BackwardLazy performs inverse NTT without final reduction.
func (t *NumberTheoreticTransformer) BackwardLazy(p ring.Poly, pOut ring.Poly) {
	t.ring.INTT(p, pOut)
	atomic.AddUint64(&t.accel.stats.INTTOps, 1)
	atomic.AddUint64(&t.accel.stats.CPUFallbacks, 1)
}

// BatchNTTForward performs forward NTT on multiple polynomials.
// Uses parallel processing for better performance on multi-core CPUs.
func (g *FHEAccelerator) BatchNTTForward(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	// For small batches, process sequentially
	if len(polys) < 8 {
		for i := range polys {
			r.NTT(polys[i], polys[i])
		}
		atomic.AddUint64(&g.stats.NTTOps, uint64(len(polys)))
		atomic.AddUint64(&g.stats.CPUFallbacks, uint64(len(polys)))
		return nil
	}

	// For larger batches, use parallel processing
	var wg sync.WaitGroup
	numWorkers := 4
	chunkSize := (len(polys) + numWorkers - 1) / numWorkers

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(polys) {
			end = len(polys)
		}
		if start >= end {
			break
		}

		wg.Add(1)
		go func(batch []ring.Poly) {
			defer wg.Done()
			for j := range batch {
				r.NTT(batch[j], batch[j])
			}
		}(polys[start:end])
	}
	wg.Wait()

	atomic.AddUint64(&g.stats.NTTOps, uint64(len(polys)))
	atomic.AddUint64(&g.stats.CPUFallbacks, uint64(len(polys)))
	return nil
}

// BatchNTTInverse performs inverse NTT on multiple polynomials.
// Uses parallel processing for better performance on multi-core CPUs.
func (g *FHEAccelerator) BatchNTTInverse(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	// For small batches, process sequentially
	if len(polys) < 8 {
		for i := range polys {
			r.INTT(polys[i], polys[i])
		}
		atomic.AddUint64(&g.stats.INTTOps, uint64(len(polys)))
		atomic.AddUint64(&g.stats.CPUFallbacks, uint64(len(polys)))
		return nil
	}

	// For larger batches, use parallel processing
	var wg sync.WaitGroup
	numWorkers := 4
	chunkSize := (len(polys) + numWorkers - 1) / numWorkers

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(polys) {
			end = len(polys)
		}
		if start >= end {
			break
		}

		wg.Add(1)
		go func(batch []ring.Poly) {
			defer wg.Done()
			for j := range batch {
				r.INTT(batch[j], batch[j])
			}
		}(polys[start:end])
	}
	wg.Wait()

	atomic.AddUint64(&g.stats.INTTOps, uint64(len(polys)))
	atomic.AddUint64(&g.stats.CPUFallbacks, uint64(len(polys)))
	return nil
}

// BatchPolyMul performs batch polynomial multiplications.
// Uses parallel processing for better performance on multi-core CPUs.
func (g *FHEAccelerator) BatchPolyMul(r *ring.Ring, a, b, out []ring.Poly) error {
	if len(a) == 0 || len(a) != len(b) || len(a) != len(out) {
		return fmt.Errorf("mismatched polynomial slice lengths")
	}

	// For small batches, process sequentially
	if len(a) < 8 {
		for i := range a {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
		}
		atomic.AddUint64(&g.stats.PolyMulOps, uint64(len(a)))
		atomic.AddUint64(&g.stats.CPUFallbacks, uint64(len(a)))
		return nil
	}

	// For larger batches, use parallel processing
	var wg sync.WaitGroup
	numWorkers := 4
	chunkSize := (len(a) + numWorkers - 1) / numWorkers

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(a) {
			end = len(a)
		}
		if start >= end {
			break
		}

		wg.Add(1)
		go func(startIdx, endIdx int) {
			defer wg.Done()
			for j := startIdx; j < endIdx; j++ {
				r.MulCoeffsBarrett(a[j], b[j], out[j])
			}
		}(start, end)
	}
	wg.Wait()

	atomic.AddUint64(&g.stats.PolyMulOps, uint64(len(a)))
	atomic.AddUint64(&g.stats.CPUFallbacks, uint64(len(a)))
	return nil
}

// Global FHE accelerator instance (lazily initialized)
var (
	globalFHEAccelerator     *FHEAccelerator
	globalFHEAcceleratorOnce sync.Once
)

// GetFHEAccelerator returns the global FHE accelerator instance.
// The accelerator is lazily initialized on first call.
func GetFHEAccelerator() (*FHEAccelerator, error) {
	globalFHEAcceleratorOnce.Do(func() {
		globalFHEAccelerator, _ = NewFHEAccelerator(nil)
	})
	return globalFHEAccelerator, nil
}
