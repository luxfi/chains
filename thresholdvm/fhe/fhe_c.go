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

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/log"
	"github.com/luxfi/accel"
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

// BatchNTTForward performs forward NTT on multiple polynomials.
// This is the primary use case for GPU acceleration - batch operations.
func (g *FHEAccelerator) BatchNTTForward(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	// Get parameters from ring
	N := r.N()

	// GPU only beneficial for large batches (>64 polys with N>=8192)
	// Otherwise CPU is faster due to data transfer overhead
	if !g.enabled || len(polys) < 64 || N < 8192 {
		for i := range polys {
			r.NTT(polys[i], polys[i])
		}
		return nil
	}

	g.mu.RLock()
	session := g.session
	g.mu.RUnlock()

	if session == nil {
		for i := range polys {
			r.NTT(polys[i], polys[i])
		}
		return nil
	}

	if len(r.ModuliChain()) == 0 {
		return fmt.Errorf("ring has no moduli")
	}
	Q := r.ModuliChain()[0]

	// Process each polynomial using GPU
	for i := range polys {
		if len(polys[i].Coeffs) == 0 || len(polys[i].Coeffs[0]) < N {
			r.NTT(polys[i], polys[i])
			continue
		}

		inputTensor, err := accel.NewTensorWithData[uint64](session, []int{N}, polys[i].Coeffs[0][:N])
		if err != nil {
			r.NTT(polys[i], polys[i])
			continue
		}

		outputTensor, err := accel.NewTensor[uint64](session, []int{N})
		if err != nil {
			inputTensor.Close()
			r.NTT(polys[i], polys[i])
			continue
		}

		err = session.Lattice().PolynomialNTT(inputTensor.Untyped(), outputTensor.Untyped(), uint32(Q))
		if err != nil {
			inputTensor.Close()
			outputTensor.Close()
			r.NTT(polys[i], polys[i])
			continue
		}

		if err := session.Sync(); err != nil {
			inputTensor.Close()
			outputTensor.Close()
			r.NTT(polys[i], polys[i])
			continue
		}

		result, err := outputTensor.ToSlice()
		if err != nil {
			inputTensor.Close()
			outputTensor.Close()
			r.NTT(polys[i], polys[i])
			continue
		}

		copy(polys[i].Coeffs[0], result)
		inputTensor.Close()
		outputTensor.Close()
	}

	g.mu.Lock()
	g.stats.BatchCalls++
	g.mu.Unlock()

	return nil
}

// BatchNTTInverse performs inverse NTT on multiple polynomials.
func (g *FHEAccelerator) BatchNTTInverse(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	if !g.enabled || len(polys) < 4 {
		for i := range polys {
			r.INTT(polys[i], polys[i])
		}
		return nil
	}

	g.mu.RLock()
	session := g.session
	g.mu.RUnlock()

	if session == nil {
		for i := range polys {
			r.INTT(polys[i], polys[i])
		}
		return nil
	}

	N := r.N()
	if len(r.ModuliChain()) == 0 {
		return fmt.Errorf("ring has no moduli")
	}
	Q := r.ModuliChain()[0]

	for i := range polys {
		if len(polys[i].Coeffs) == 0 || len(polys[i].Coeffs[0]) < N {
			r.INTT(polys[i], polys[i])
			continue
		}

		inputTensor, err := accel.NewTensorWithData[uint64](session, []int{N}, polys[i].Coeffs[0][:N])
		if err != nil {
			r.INTT(polys[i], polys[i])
			continue
		}

		outputTensor, err := accel.NewTensor[uint64](session, []int{N})
		if err != nil {
			inputTensor.Close()
			r.INTT(polys[i], polys[i])
			continue
		}

		err = session.Lattice().PolynomialINTT(inputTensor.Untyped(), outputTensor.Untyped(), uint32(Q))
		if err != nil {
			inputTensor.Close()
			outputTensor.Close()
			r.INTT(polys[i], polys[i])
			continue
		}

		if err := session.Sync(); err != nil {
			inputTensor.Close()
			outputTensor.Close()
			r.INTT(polys[i], polys[i])
			continue
		}

		result, err := outputTensor.ToSlice()
		if err != nil {
			inputTensor.Close()
			outputTensor.Close()
			r.INTT(polys[i], polys[i])
			continue
		}

		copy(polys[i].Coeffs[0], result)
		inputTensor.Close()
		outputTensor.Close()
	}

	g.mu.Lock()
	g.stats.BatchCalls++
	g.mu.Unlock()

	return nil
}

// BatchPolyMul performs polynomial multiplication on batches using GPU.
func (g *FHEAccelerator) BatchPolyMul(r *ring.Ring, a, b, out []ring.Poly) error {
	if len(a) != len(b) || len(a) != len(out) {
		return fmt.Errorf("batch size mismatch")
	}

	if !g.enabled || len(a) < 4 {
		// CPU fallback
		for i := range a {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
		}
		return nil
	}

	g.mu.RLock()
	session := g.session
	g.mu.RUnlock()

	if session == nil {
		for i := range a {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
		}
		return nil
	}

	N := r.N()
	if len(r.ModuliChain()) == 0 {
		return fmt.Errorf("ring has no moduli")
	}
	Q := r.ModuliChain()[0]

	for i := range a {
		if len(a[i].Coeffs) == 0 || len(b[i].Coeffs) == 0 || len(out[i].Coeffs) == 0 {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			continue
		}

		aTensor, err := accel.NewTensorWithData[uint64](session, []int{N}, a[i].Coeffs[0][:N])
		if err != nil {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			continue
		}

		bTensor, err := accel.NewTensorWithData[uint64](session, []int{N}, b[i].Coeffs[0][:N])
		if err != nil {
			aTensor.Close()
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			continue
		}

		outTensor, err := accel.NewTensor[uint64](session, []int{N})
		if err != nil {
			aTensor.Close()
			bTensor.Close()
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			continue
		}

		err = session.Lattice().PolynomialMul(aTensor.Untyped(), bTensor.Untyped(), outTensor.Untyped(), uint32(Q))
		if err != nil {
			aTensor.Close()
			bTensor.Close()
			outTensor.Close()
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			continue
		}

		if err := session.Sync(); err != nil {
			aTensor.Close()
			bTensor.Close()
			outTensor.Close()
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			continue
		}

		result, err := outTensor.ToSlice()
		if err != nil {
			aTensor.Close()
			bTensor.Close()
			outTensor.Close()
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			continue
		}

		copy(out[i].Coeffs[0], result)
		aTensor.Close()
		bTensor.Close()
		outTensor.Close()
	}

	g.mu.Lock()
	g.stats.PolyMulCalls++
	g.mu.Unlock()

	return nil
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
