// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

// Package fhe provides GPU-accelerated FHE operations for the zkvm.
// This uses the unified lux/accel package for GPU acceleration of CKKS
// homomorphic encryption operations.
//
// GPU acceleration provides 40x+ speedup for NTT operations on Apple Silicon
// and NVIDIA GPUs via the accel library (Metal/CUDA/CPU backends).
//
// Architecture:
//
//	luxcpp/accel (C++ GPU)  →  lux/accel (Go CGO)  →  zkvm FHE operations
package fhe

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/luxfi/accel"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/log"
	"github.com/luxfi/node/config"
)

// FHEAccelerator provides GPU-accelerated operations for CKKS FHE.
// It uses the unified lux/accel package for Metal/CUDA/CPU backends.
type FHEAccelerator struct {
	mu      sync.RWMutex
	session *accel.Session
	enabled bool
	logger  log.Logger
	stats   *FHEStats
}

// FHEStats tracks FHE accelerator statistics.
type FHEStats struct {
	NTTOps       uint64
	INTTOps      uint64
	PolyMulOps   uint64
	GPUHits      uint64
	CPUFallbacks uint64
}

// NewFHEAccelerator creates a new GPU-accelerated FHE processor.
// It auto-detects available GPU backends (Metal on macOS, CUDA on Linux).
func NewFHEAccelerator(logger log.Logger) (*FHEAccelerator, error) {
	return NewFHEAcceleratorWithOptions(logger, FHEAccelOptions{})
}

// FHEAccelOptions holds options for creating an FHE accelerator.
type FHEAccelOptions struct {
	// Enabled controls whether GPU acceleration is used
	Enabled bool
	// Backend specifies which GPU backend to use: "auto", "metal", "cuda", "cpu"
	Backend string
	// DeviceIndex specifies which GPU device to use
	DeviceIndex int
}

// NewFHEAcceleratorWithOptions creates a new FHE accelerator with custom options.
func NewFHEAcceleratorWithOptions(logger log.Logger, opts FHEAccelOptions) (*FHEAccelerator, error) {
	// Get global config if options not specified
	gpuCfg := config.GetGlobalGPUConfig()

	// Determine if GPU should be enabled
	enabled := gpuCfg.Enabled
	if opts.Backend == "cpu" {
		enabled = false
	}

	// Check if GPU is available via accel library
	available := accel.Available() && enabled

	var session *accel.Session
	if available {
		var err error
		session, err = accel.DefaultSession()
		if err != nil {
			// Fall back to CPU mode
			available = false
			if logger != nil {
				logger.Warn("GPU acceleration unavailable, falling back to CPU",
					"error", err)
			}
		}
	}

	accel := &FHEAccelerator{
		session: session,
		enabled: available,
		logger:  logger,
		stats:   &FHEStats{},
	}

	if logger != nil {
		if available {
			logger.Info("FHE GPU accelerator initialized",
				"backend", accel.Backend())
		} else {
			logger.Info("FHE using CPU (GPU not available)")
		}
	}

	return accel, nil
}

// IsEnabled returns whether GPU acceleration is available.
func (g *FHEAccelerator) IsEnabled() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.enabled
}

// Backend returns the name of the active GPU backend.
func (g *FHEAccelerator) Backend() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.enabled || g.session == nil {
		return "CPU (GPU not available)"
	}
	return g.session.Backend().String()
}

// Stats returns current FHE accelerator statistics.
func (g *FHEAccelerator) Stats() FHEStats {
	return FHEStats{
		NTTOps:       atomic.LoadUint64(&g.stats.NTTOps),
		INTTOps:      atomic.LoadUint64(&g.stats.INTTOps),
		PolyMulOps:   atomic.LoadUint64(&g.stats.PolyMulOps),
		GPUHits:      atomic.LoadUint64(&g.stats.GPUHits),
		CPUFallbacks: atomic.LoadUint64(&g.stats.CPUFallbacks),
	}
}

// NumberTheoreticTransformer provides GPU-accelerated NTT operations
// for CKKS polynomial operations.
type NumberTheoreticTransformer struct {
	accel *FHEAccelerator
	ring  *ring.Ring
	N     int
	Q     uint64
}

// NewNumberTheoreticTransformer creates a new GPU-accelerated NTT transformer.
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

// Forward performs forward NTT using GPU acceleration when beneficial.
func (t *NumberTheoreticTransformer) Forward(p ring.Poly, pOut ring.Poly) {
	// For single polynomials, CPU is often faster due to GPU kernel launch overhead
	// Use GPU only for large enough polynomials
	if t.accel.enabled && t.N >= 8192 {
		if err := t.forwardGPU(p, pOut); err == nil {
			atomic.AddUint64(&t.accel.stats.GPUHits, 1)
			return
		}
		atomic.AddUint64(&t.accel.stats.CPUFallbacks, 1)
	}

	// CPU fallback using ring directly
	t.ring.NTT(p, pOut)
	atomic.AddUint64(&t.accel.stats.NTTOps, 1)
}

// ForwardLazy performs forward NTT without final reduction.
func (t *NumberTheoreticTransformer) ForwardLazy(p ring.Poly, pOut ring.Poly) {
	// Lazy variant: ring.NTT handles this; lattice/v7 doesn't have separate lazy method
	t.ring.NTT(p, pOut)
	atomic.AddUint64(&t.accel.stats.NTTOps, 1)
}

// Backward performs inverse NTT using GPU acceleration when beneficial.
func (t *NumberTheoreticTransformer) Backward(p ring.Poly, pOut ring.Poly) {
	if t.accel.enabled && t.N >= 8192 {
		if err := t.backwardGPU(p, pOut); err == nil {
			atomic.AddUint64(&t.accel.stats.GPUHits, 1)
			return
		}
		atomic.AddUint64(&t.accel.stats.CPUFallbacks, 1)
	}

	// CPU fallback using ring directly
	t.ring.INTT(p, pOut)
	atomic.AddUint64(&t.accel.stats.INTTOps, 1)
}

// BackwardLazy performs inverse NTT without final reduction.
func (t *NumberTheoreticTransformer) BackwardLazy(p ring.Poly, pOut ring.Poly) {
	// Lazy variant: ring.INTT handles this; lattice/v7 doesn't have separate lazy method
	t.ring.INTT(p, pOut)
	atomic.AddUint64(&t.accel.stats.INTTOps, 1)
}

// forwardGPU performs GPU-accelerated forward NTT.
func (t *NumberTheoreticTransformer) forwardGPU(p ring.Poly, pOut ring.Poly) error {
	if t.accel.session == nil {
		return fmt.Errorf("no GPU session")
	}

	coeffs := p.Coeffs
	if len(coeffs) == 0 || len(coeffs[0]) < t.N {
		return fmt.Errorf("invalid polynomial size")
	}

	// Create input tensor
	inputTensor, err := accel.NewTensorWithData[uint64](t.accel.session, []int{t.N}, coeffs[0][:t.N])
	if err != nil {
		return err
	}
	defer inputTensor.Close()

	// Create output tensor
	outputTensor, err := accel.NewTensor[uint64](t.accel.session, []int{t.N})
	if err != nil {
		return err
	}
	defer outputTensor.Close()

	// GPU NTT
	if err := t.accel.session.Lattice().PolynomialNTT(
		inputTensor.Untyped(),
		outputTensor.Untyped(),
		uint32(t.Q),
	); err != nil {
		return err
	}

	// Synchronize and copy result
	t.accel.session.Sync()
	result, err := outputTensor.ToSlice()
	if err != nil {
		return err
	}
	copy(pOut.Coeffs[0], result)

	return nil
}

// backwardGPU performs GPU-accelerated inverse NTT.
func (t *NumberTheoreticTransformer) backwardGPU(p ring.Poly, pOut ring.Poly) error {
	if t.accel.session == nil {
		return fmt.Errorf("no GPU session")
	}

	coeffs := p.Coeffs
	if len(coeffs) == 0 || len(coeffs[0]) < t.N {
		return fmt.Errorf("invalid polynomial size")
	}

	// Create input tensor
	inputTensor, err := accel.NewTensorWithData[uint64](t.accel.session, []int{t.N}, coeffs[0][:t.N])
	if err != nil {
		return err
	}
	defer inputTensor.Close()

	// Create output tensor
	outputTensor, err := accel.NewTensor[uint64](t.accel.session, []int{t.N})
	if err != nil {
		return err
	}
	defer outputTensor.Close()

	// GPU INTT
	if err := t.accel.session.Lattice().PolynomialINTT(
		inputTensor.Untyped(),
		outputTensor.Untyped(),
		uint32(t.Q),
	); err != nil {
		return err
	}

	// Synchronize and copy result
	t.accel.session.Sync()
	result, err := outputTensor.ToSlice()
	if err != nil {
		return err
	}
	copy(pOut.Coeffs[0], result)

	return nil
}

// BatchNTTForward performs forward NTT on multiple polynomials.
// GPU acceleration is used for batches of 64+ polynomials with N >= 8192.
func (g *FHEAccelerator) BatchNTTForward(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	N := r.N()

	// GPU acceleration threshold: 64+ polys and N >= 8192
	// Below this, CPU is often faster due to kernel launch overhead
	if !g.enabled || g.session == nil || len(polys) < 64 || N < 8192 {
		// CPU fallback with parallel processing
		return g.batchNTTForwardCPU(r, polys)
	}

	Q, err := g.getModulus(r)
	if err != nil {
		return g.batchNTTForwardCPU(r, polys)
	}

	// Process through GPU
	for i := range polys {
		coeffs := polys[i].Coeffs
		if len(coeffs) == 0 || len(coeffs[0]) < N {
			r.NTT(polys[i], polys[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		inputTensor, err := accel.NewTensorWithData[uint64](g.session, []int{N}, coeffs[0][:N])
		if err != nil {
			r.NTT(polys[i], polys[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		outputTensor, err := accel.NewTensor[uint64](g.session, []int{N})
		if err != nil {
			inputTensor.Close()
			r.NTT(polys[i], polys[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		if err := g.session.Lattice().PolynomialNTT(inputTensor.Untyped(), outputTensor.Untyped(), Q); err != nil {
			inputTensor.Close()
			outputTensor.Close()
			r.NTT(polys[i], polys[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		g.session.Sync()
		result, err := outputTensor.ToSlice()
		if err != nil {
			inputTensor.Close()
			outputTensor.Close()
			r.NTT(polys[i], polys[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}
		copy(coeffs[0], result)

		inputTensor.Close()
		outputTensor.Close()
		atomic.AddUint64(&g.stats.GPUHits, 1)
	}

	atomic.AddUint64(&g.stats.NTTOps, uint64(len(polys)))
	return nil
}

// BatchNTTInverse performs inverse NTT on multiple polynomials.
func (g *FHEAccelerator) BatchNTTInverse(r *ring.Ring, polys []ring.Poly) error {
	if len(polys) == 0 {
		return nil
	}

	N := r.N()

	// GPU acceleration threshold
	if !g.enabled || g.session == nil || len(polys) < 64 || N < 8192 {
		return g.batchNTTInverseCPU(r, polys)
	}

	Q, err := g.getModulus(r)
	if err != nil {
		return g.batchNTTInverseCPU(r, polys)
	}

	// Process through GPU
	for i := range polys {
		coeffs := polys[i].Coeffs
		if len(coeffs) == 0 || len(coeffs[0]) < N {
			r.INTT(polys[i], polys[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		inputTensor, err := accel.NewTensorWithData[uint64](g.session, []int{N}, coeffs[0][:N])
		if err != nil {
			r.INTT(polys[i], polys[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		outputTensor, err := accel.NewTensor[uint64](g.session, []int{N})
		if err != nil {
			inputTensor.Close()
			r.INTT(polys[i], polys[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		if err := g.session.Lattice().PolynomialINTT(inputTensor.Untyped(), outputTensor.Untyped(), Q); err != nil {
			inputTensor.Close()
			outputTensor.Close()
			r.INTT(polys[i], polys[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		g.session.Sync()
		result, err := outputTensor.ToSlice()
		if err != nil {
			inputTensor.Close()
			outputTensor.Close()
			r.INTT(polys[i], polys[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}
		copy(coeffs[0], result)

		inputTensor.Close()
		outputTensor.Close()
		atomic.AddUint64(&g.stats.GPUHits, 1)
	}

	atomic.AddUint64(&g.stats.INTTOps, uint64(len(polys)))
	return nil
}

// BatchPolyMul performs batch polynomial multiplications.
func (g *FHEAccelerator) BatchPolyMul(r *ring.Ring, a, b, out []ring.Poly) error {
	if len(a) == 0 || len(a) != len(b) || len(a) != len(out) {
		return fmt.Errorf("mismatched polynomial slice lengths")
	}

	N := r.N()

	// GPU threshold for polynomial multiplication
	if !g.enabled || g.session == nil || len(a) < 32 || N < 4096 {
		return g.batchPolyMulCPU(r, a, b, out)
	}

	Q, err := g.getModulus(r)
	if err != nil {
		return g.batchPolyMulCPU(r, a, b, out)
	}

	// Process through GPU
	for i := range a {
		aCoeffs := a[i].Coeffs
		bCoeffs := b[i].Coeffs
		outCoeffs := out[i].Coeffs

		if len(aCoeffs) == 0 || len(aCoeffs[0]) < N ||
			len(bCoeffs) == 0 || len(bCoeffs[0]) < N ||
			len(outCoeffs) == 0 || len(outCoeffs[0]) < N {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		aTensor, err := accel.NewTensorWithData[uint64](g.session, []int{N}, aCoeffs[0][:N])
		if err != nil {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		bTensor, err := accel.NewTensorWithData[uint64](g.session, []int{N}, bCoeffs[0][:N])
		if err != nil {
			aTensor.Close()
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		outTensor, err := accel.NewTensor[uint64](g.session, []int{N})
		if err != nil {
			aTensor.Close()
			bTensor.Close()
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		if err := g.session.Lattice().PolynomialMul(aTensor.Untyped(), bTensor.Untyped(), outTensor.Untyped(), Q); err != nil {
			aTensor.Close()
			bTensor.Close()
			outTensor.Close()
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}

		g.session.Sync()
		result, err := outTensor.ToSlice()
		if err != nil {
			aTensor.Close()
			bTensor.Close()
			outTensor.Close()
			r.MulCoeffsBarrett(a[i], b[i], out[i])
			atomic.AddUint64(&g.stats.CPUFallbacks, 1)
			continue
		}
		copy(outCoeffs[0], result)

		aTensor.Close()
		bTensor.Close()
		outTensor.Close()
		atomic.AddUint64(&g.stats.GPUHits, 1)
	}

	atomic.AddUint64(&g.stats.PolyMulOps, uint64(len(a)))
	return nil
}

// CPU fallback methods with parallel processing

func (g *FHEAccelerator) batchNTTForwardCPU(r *ring.Ring, polys []ring.Poly) error {
	// For small batches, process sequentially
	if len(polys) < 8 {
		for i := range polys {
			r.NTT(polys[i], polys[i])
		}
		atomic.AddUint64(&g.stats.NTTOps, uint64(len(polys)))
		atomic.AddUint64(&g.stats.CPUFallbacks, uint64(len(polys)))
		return nil
	}

	// Parallel processing for larger batches
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

func (g *FHEAccelerator) batchNTTInverseCPU(r *ring.Ring, polys []ring.Poly) error {
	// For small batches, process sequentially
	if len(polys) < 8 {
		for i := range polys {
			r.INTT(polys[i], polys[i])
		}
		atomic.AddUint64(&g.stats.INTTOps, uint64(len(polys)))
		atomic.AddUint64(&g.stats.CPUFallbacks, uint64(len(polys)))
		return nil
	}

	// Parallel processing for larger batches
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

func (g *FHEAccelerator) batchPolyMulCPU(r *ring.Ring, a, b, out []ring.Poly) error {
	// For small batches, process sequentially
	if len(a) < 8 {
		for i := range a {
			r.MulCoeffsBarrett(a[i], b[i], out[i])
		}
		atomic.AddUint64(&g.stats.PolyMulOps, uint64(len(a)))
		atomic.AddUint64(&g.stats.CPUFallbacks, uint64(len(a)))
		return nil
	}

	// Parallel processing for larger batches
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

// getModulus extracts the first modulus from the ring.
func (g *FHEAccelerator) getModulus(r *ring.Ring) (uint32, error) {
	if len(r.ModuliChain()) == 0 {
		return 0, fmt.Errorf("ring has no moduli")
	}
	return uint32(r.ModuliChain()[0]), nil
}

// ClearCache is a no-op in the accel-based implementation.
// The accel library manages its own caching internally.
func (g *FHEAccelerator) ClearCache() {
	// No-op: accel library manages caching internally
}

// Global FHE accelerator instance (lazily initialized)
var (
	globalFHEAccelerator     *FHEAccelerator
	globalFHEAcceleratorOnce sync.Once
	globalFHEAcceleratorErr  error
)

// GetFHEAccelerator returns the global FHE accelerator instance.
// The accelerator is lazily initialized on first call.
func GetFHEAccelerator() (*FHEAccelerator, error) {
	globalFHEAcceleratorOnce.Do(func() {
		globalFHEAccelerator, globalFHEAcceleratorErr = NewFHEAccelerator(nil)
	})
	return globalFHEAccelerator, globalFHEAcceleratorErr
}
