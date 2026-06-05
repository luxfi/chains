// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

// Q-Chain GPU substrate — host-side ABI v14 plugin bridge for batched
// post-quantum signature verification + signing.
//
// The kernels live in the GPU plugin under
// ops/crypto/{mldsa,slhdsa}/<backend>/ and are shipped inside the
// libluxgpu_backend_<x>.{so,dylib} plugin shared libraries. The Go side
// dlopens whichever plugin is on disk at process start, populates the
// ABI v14 backend descriptor via the `lux_gpu_backend_init` entry point
// (see the lux GPU plugin include/lux/gpu/backend_plugin.h), and
// invokes the op_mldsa_verify_batch / op_mldsa_sign_batch /
// op_slhdsa_verify_batch slots from the resulting vtbl.
//
// Decomplecting from cevm/cevm_cgo.go: cevm links its kernel bundle via
// pkg-config (lux-cevm.pc → -levm -levm-gpu …) and reaches the C ABI
// through extern "C" gpu_* helpers. Q-Chain takes the opposite tack —
// no pkg-config, no static link, no header-bound C ABI helpers. The
// plugin is OPTIONAL by design: when no libluxgpu_backend_*.{so,dylib}
// is on the dlopen search path, AutoBackend() returns BackendNone and
// every GPUBackend method returns ErrGPUNotAvailable so the existing
// CPU verify path stays unchanged.
//
// Pattern (mirrors evm/cevm + evm/backend_cgo.go split):
//
//   backend.go                — shared types: Backend enum, GPUBackend
//                                interface, ErrGPUNotAvailable, active
//                                backend atomic + AutoBackend(). Build-
//                                tag-free; the runtime probe lives in
//                                the cgo/nocgo files below.
//   quantumvm_gpu.go      cgo — dlopen + dlsym of lux_gpu_backend_init,
//                                vtbl slot invocations.
//   quantumvm_gpu_nocgo.go !cgo — stub returning ErrGPUNotAvailable.
//
// This file is build-tag-free so vm.go can reference Backend, GPUBackend,
// AutoBackend(), and ErrGPUNotAvailable regardless of CGO_ENABLED. The
// implementation behind ActiveGPUBackend() switches based on the build
// tag (real plugin handle vs. stub returning ErrGPUNotAvailable).

import (
	"errors"
	"fmt"
	"sync/atomic"
)

// Backend identifies which GPU plugin satisfied the runtime dlopen probe.
//
// Probe order is fixed by the spec: cuda → hip → metal → vulkan → webgpu.
// The first plugin that resolves the `lux_gpu_backend_init` entry point and
// reports a v14 vtbl with the three Q-Chain slots (op_mldsa_verify_batch,
// op_mldsa_sign_batch, op_slhdsa_verify_batch) wins; remaining probes are
// skipped. Each plugin is fully self-contained — there is no fallback chain
// once one is chosen (this keeps backend selection deterministic across
// reboots, matching consensus-safety expectations).
type Backend uint8

const (
	// BackendNone means no GPU plugin is loaded — every GPUBackend method
	// returns ErrGPUNotAvailable. This is the value reported by
	// AutoBackend() under !cgo, and under cgo when no
	// libluxgpu_backend_*.{so,dylib} was findable.
	BackendNone Backend = 0
	// BackendCUDA selects libluxgpu_backend_cuda.so (NVIDIA, Linux/Windows).
	BackendCUDA Backend = 1
	// BackendHIP selects libluxgpu_backend_hip.so (AMD ROCm, Linux/Windows).
	BackendHIP Backend = 2
	// BackendMetal selects libluxgpu_backend_metal.dylib (Apple, darwin).
	BackendMetal Backend = 3
	// BackendVulkan selects libluxgpu_backend_vulkan.{so,dylib} (portable).
	BackendVulkan Backend = 4
	// BackendWebGPU selects libluxgpu_backend_webgpu.{so,dylib} (portable).
	BackendWebGPU Backend = 5
)

// String returns the canonical lowercase name of the backend. The same
// name appears in the plugin DSO filename (libluxgpu_backend_<name>.*)
// and in the lux_gpu_backend_desc.backend_name field reported by the
// loaded plugin.
func (b Backend) String() string {
	switch b {
	case BackendNone:
		return "none"
	case BackendCUDA:
		return "cuda"
	case BackendHIP:
		return "hip"
	case BackendMetal:
		return "metal"
	case BackendVulkan:
		return "vulkan"
	case BackendWebGPU:
		return "webgpu"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(b))
	}
}

// ErrGPUNotAvailable is returned by every GPUBackend method when no plugin
// is loaded — either because the binary was built without CGo, no
// libluxgpu_backend_*.{so,dylib} was findable on the dlopen search path,
// the loaded plugin reported a non-v14 ABI version, or its vtbl was
// missing one of the three Q-Chain slots.
//
// The error is sentinel-comparable via errors.Is so callers can route
// the CPU verify path cleanly:
//
//	if errors.Is(err, quantumvm.ErrGPUNotAvailable) {
//	    return cpuVerify(pk, msg, sig)
//	}
var ErrGPUNotAvailable = errors.New("quantumvm: GPU backend not available")

// MLDSAMode selects which ML-DSA security parameter set the batch
// targets. The ABI v14 vtbl currently exposes only ML-DSA-65 (mode 3,
// FIPS 204 Dilithium3) — modes 44 and 87 will land at their own vtbl
// slots in a future ABI bump (see backend_plugin.h v14 block). Callers
// pass the mode through so the wrapper can validate batch byte widths
// at the boundary, even though only MLDSA65 round-trips through the
// plugin today.
type MLDSAMode uint8

const (
	// MLDSAMode44 is FIPS 204 Dilithium2. Not yet wired through the v14
	// vtbl — passing this to a batch method returns ErrGPUNotAvailable
	// (caller falls through to the CPU path).
	MLDSAMode44 MLDSAMode = 1
	// MLDSAMode65 is FIPS 204 Dilithium3 — the canonical Q-Chain mode.
	// pk=1952 B, sig=3309 B (max), sk=4032 B.
	MLDSAMode65 MLDSAMode = 2
	// MLDSAMode87 is FIPS 204 Dilithium5. Not yet wired through the v14
	// vtbl — passing this returns ErrGPUNotAvailable.
	MLDSAMode87 MLDSAMode = 3
)

// ML-DSA-65 byte sizes per FIPS 204 §4. Pinned constants — the plugin
// rejects mismatched sk_stride at the boundary, so we surface them up
// front to keep the call sites unambiguous.
const (
	MLDSA65PublicKeySize  = 1952
	MLDSA65SecretKeySize  = 4032
	MLDSA65SignatureSize  = 3309
)

// SLHDSAVariant enumerates the 12 FIPS 205 SLH-DSA parameter sets. Each
// variant has its own (pk, sig) byte width — surfaced via PublicKeySize()
// and SignatureSize() so callers can build the batch arrays correctly.
//
// At ABI v14 only the SHAKE-128f and SHAKE-192f verify slots are wired
// (op_slhdsa_verify_batch and op_slhdsa_verify_batch_shake192f). The
// remaining 10 variants land at their own vtbl slots in future ABI
// bumps; passing them today returns ErrGPUNotAvailable.
type SLHDSAVariant uint8

const (
	SLHDSAShake128f SLHDSAVariant = iota
	SLHDSAShake128s
	SLHDSAShake192f
	SLHDSAShake192s
	SLHDSAShake256f
	SLHDSAShake256s
	SLHDSASha2128f
	SLHDSASha2128s
	SLHDSASha2192f
	SLHDSASha2192s
	SLHDSASha2256f
	SLHDSASha2256s
)

// String returns the FIPS 205 canonical name of the variant.
func (v SLHDSAVariant) String() string {
	switch v {
	case SLHDSAShake128f:
		return "shake-128f"
	case SLHDSAShake128s:
		return "shake-128s"
	case SLHDSAShake192f:
		return "shake-192f"
	case SLHDSAShake192s:
		return "shake-192s"
	case SLHDSAShake256f:
		return "shake-256f"
	case SLHDSAShake256s:
		return "shake-256s"
	case SLHDSASha2128f:
		return "sha2-128f"
	case SLHDSASha2128s:
		return "sha2-128s"
	case SLHDSASha2192f:
		return "sha2-192f"
	case SLHDSASha2192s:
		return "sha2-192s"
	case SLHDSASha2256f:
		return "sha2-256f"
	case SLHDSASha2256s:
		return "sha2-256s"
	default:
		return fmt.Sprintf("slhdsa(%d)", uint8(v))
	}
}

// PublicKeySize returns the FIPS 205 byte width of an SLH-DSA public key
// for this variant. {128,192,256}{f,s} all share the same width per
// security level (32 / 48 / 64 bytes).
func (v SLHDSAVariant) PublicKeySize() int {
	switch v {
	case SLHDSAShake128f, SLHDSAShake128s, SLHDSASha2128f, SLHDSASha2128s:
		return 32
	case SLHDSAShake192f, SLHDSAShake192s, SLHDSASha2192f, SLHDSASha2192s:
		return 48
	case SLHDSAShake256f, SLHDSAShake256s, SLHDSASha2256f, SLHDSASha2256s:
		return 64
	default:
		return 0
	}
}

// SignatureSize returns the FIPS 205 byte width of an SLH-DSA signature
// for this variant. The 12 widths are fixed by parameter set; see the
// FIPS 205 standard §11 width table.
func (v SLHDSAVariant) SignatureSize() int {
	switch v {
	case SLHDSAShake128f, SLHDSASha2128f:
		return 17088
	case SLHDSAShake128s, SLHDSASha2128s:
		return 7856
	case SLHDSAShake192f, SLHDSASha2192f:
		return 35664
	case SLHDSAShake192s, SLHDSASha2192s:
		return 16224
	case SLHDSAShake256f, SLHDSASha2256f:
		return 49856
	case SLHDSAShake256s, SLHDSASha2256s:
		return 29792
	default:
		return 0
	}
}

// GPUBackend is the narrow Q-Chain surface that vm.go's batch verify /
// sign paths can opt into. Three 1:1 mappings to the ABI v14 vtbl slots,
// plus Backend() / Close() lifecycle.
//
// Buffer ownership: callers own every slice / struct passed in. The vtbl
// slot does H2D / D2H internally. On return every output slice has been
// overwritten with the kernel's result; the caller can read immediately,
// no further sync needed.
//
// Composition: the three batch methods are orthogonal — a "round" that
// verifies a mixed batch of ML-DSA + SLH-DSA stamps composes them in
// the round applier. We do NOT try to express a "verify all PQ sigs"
// supercall here; that would couple the round-level policy to the
// substrate, and the substrate intentionally only exposes primitives.
type GPUBackend interface {
	// MLDSAVerifyBatch verifies a batch of ML-DSA signatures. mode pins
	// the FIPS 204 parameter set; only MLDSAMode65 is wired through the
	// v14 vtbl (modes 44/87 return ErrGPUNotAvailable). pubkeys[i],
	// messages[i], and signatures[i] supply the per-element inputs;
	// msgLens[i] is the byte length of messages[i] (NULL slice means
	// every message is exactly msgWidthHint bytes — see the
	// op_mldsa_verify_batch comment in backend_plugin.h for the
	// uniform-batch convenience contract). results[i] is set to true
	// iff verification succeeds.
	//
	// The slices must all have the same length; mismatched lengths are
	// caught at the boundary and returned as an error (no UB into C).
	MLDSAVerifyBatch(
		mode MLDSAMode,
		pubkeys [][]byte,
		messages [][]byte,
		msgLens []int,
		msgWidthHint uint32,
		signatures [][]byte,
		results []bool,
	) error

	// MLDSASignBatch signs a batch of messages with packed ML-DSA secret
	// keys. mode pins the FIPS 204 parameter set; only MLDSAMode65 is
	// wired through the v14 vtbl. skeys is the contiguous pool of
	// per-element packed secret keys (each MLDSA65SecretKeySize = 4032
	// bytes); the wrapper feeds the pool through cudaMemcpy2D directly
	// in one shot. msgs is the contiguous pool of per-element message
	// payloads (msgLens[i] bytes from offset sum(msgLens[0..i-1])).
	// sigsOut receives count × MLDSA65SignatureSize bytes; sigLensOut
	// returns the per-element actual signature length (3309 on accept,
	// 0 on kappa-cap reject — see backend_plugin.h v14 block).
	MLDSASignBatch(
		mode MLDSAMode,
		skeys []byte,
		msgs []byte,
		msgLens []int,
		msgWidthHint uint32,
		count int,
		sigsOut []byte,
		sigLensOut []uint32,
	) error

	// SLHDSAVerifyBatch verifies a batch of SLH-DSA signatures. variant
	// pins the FIPS 205 parameter set; only SHAKE-128f and SHAKE-192f
	// are wired through the v14 vtbl (the other 10 variants return
	// ErrGPUNotAvailable). pubkeys[i], messages[i], and signatures[i]
	// supply the per-element inputs at the FIPS 205 widths reported by
	// variant.PublicKeySize() / variant.SignatureSize(); msgLens[i] is
	// the byte length of messages[i] (any value in [0, INT32_MAX-2]).
	// results[i] is set to true iff verification succeeds.
	SLHDSAVerifyBatch(
		variant SLHDSAVariant,
		pubkeys [][]byte,
		messages [][]byte,
		msgLens []int,
		signatures [][]byte,
		results []bool,
	) error

	// Backend reports which plugin is currently loaded.
	Backend() Backend

	// Close releases the dlopen handle and the LuxBackendContext. Safe
	// on a nil receiver and idempotent.
	Close() error
}

// activeBackend is set by the init() in quantumvm_gpu.go (cgo) or
// quantumvm_gpu_nocgo.go (!cgo). Read via AutoBackend(). Stored as an
// atomic uint32 so concurrent reads from vm.go's batch paths don't race
// with the init() store.
var activeBackend atomic.Uint32

// AutoBackend returns the GPU plugin chosen by the dlopen probe at process
// start. BackendNone means no plugin is loaded — callers should route to
// the CPU verify path. The probe runs exactly once at init time; this
// getter is one atomic load and safe to call from any goroutine.
func AutoBackend() Backend {
	return Backend(uint8(activeBackend.Load()))
}

// setActiveBackend records the probe result. Called by init() in the
// cgo / nocgo files. Not exported — there is one and only one way to
// load the plugin (the init probe at process start).
func setActiveBackend(b Backend) {
	activeBackend.Store(uint32(uint8(b)))
}
