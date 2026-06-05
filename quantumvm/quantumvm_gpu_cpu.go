// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// quantumvm_gpu_cpu.go — pure-Go reference implementation of the three
// GPUBackend entry points (MLDSAVerifyBatch, MLDSASignBatch,
// SLHDSAVerifyBatch).
//
// One implementation, used unconditionally by both build modes:
//
//   - The !cgo bridge (quantumvm_gpu_nocgo.go) calls these directly: no
//     plugin can ever load there, so the Go path IS the path.
//
//   - The cgo bridge (quantumvm_gpu.go) tries the GPU plugin first; on
//     ErrGPUNotAvailable (no plugin loaded, plugin slot returned
//     NOT_SUPPORTED, or any other plugin-side rc != 0) it falls through
//     to the same Go path. Both build modes therefore produce byte-
//     identical output on every fixture.
//
// Byte-equality reference:
//
//   - ML-DSA verify: FIPS 204 §5.3 (Algorithm 8). circl's
//     mldsa65.Verify(pk, msg, ctx=nil, sig) is the canonical pure-Go
//     port. The GPU kernel at ~/work/lux-private/gpu-kernels/ops/crypto/
//     mldsa/cpu/mldsa_verify.hpp is byte-equal to PQClean ML-DSA-65
//     verify (also FIPS 204), so circl and the GPU kernel produce the
//     same boolean for the same (pk, msg, sig).
//
//   - ML-DSA sign: FIPS 204 §5.2 (Algorithm 7). circl's
//     mldsa65.SignTo(sk, msg, ctx=nil, randomized=false, sig) selects the
//     deterministic mode (rnd = 0^32). The GPU kernel at
//     ~/work/lux-private/gpu-kernels/ops/crypto/mldsa/cpu/mldsa_sign.hpp
//     comment block makes the same choice ("Deterministic mode: rnd =
//     0^RNDBYTES (= 32 bytes of zero). FIPS 204 permits both
//     deterministic and randomised sign; our oracle is deterministic
//     for byte-equal cross-check with PQClean"). Both write the same
//     3309-byte FIPS 204 signature for the same (sk, msg).
//
//   - SLH-DSA verify: FIPS 205 §10.3 (Algorithm 24). circl's
//     slhdsa.Verify(&pk, NewMessage(msg), sig, ctx=nil) is the
//     canonical pure-Go port for both SHAKE-128f and SHAKE-192f. The
//     GPU kernel is byte-equal to FIPS 205, so circl and the GPU
//     kernel produce the same boolean for the same (pk, msg, sig).
//
// Any divergence between these helpers and the GPU kernel is a bug in
// the kernel — both implementations are constrained to FIPS 204/205
// bit-exactness and that constraint is what makes this a strict
// positive overlay.

package quantumvm

import (
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// mldsaVerifyBatchCPU is the pure-Go reference implementation of
// MLDSAVerifyBatch. It walks the batch in-order and writes the verify
// result of each element into results[i]. Returns an error iff the
// caller passed inconsistent inputs (length mismatch, oversized
// signature, etc.) — those errors mirror the boundary checks the cgo
// path performs.
//
// FIPS 204 contract: the message bytes the verifier consumes are
// exactly messages[i][0 : msgLens[i]] when msgLens is non-nil, or
// messages[i][0 : msgWidthHint] when msgLens is nil. A nil msgLens
// slice + zero msgWidthHint is the "use len(messages[i]) directly"
// fall-through that the cgo path also accepts (the plugin's vtbl
// dispatches the same fall-through inside the kernel).
//
// Wire format: pubkeys[i] is FIPS 204 §5.6 pack-pk format (1952 B);
// signatures[i] is FIPS 204 §5.6 pack-sig format (3309 B). circl's
// Verify requires exactly SignatureSize bytes (calling Verify with a
// shorter slice would panic on index in sigDecode). We reject any
// length != 3309 as a caller bug, matching the upper-bound check the
// cgo path performs and tightening it on the lower bound.
func mldsaVerifyBatchCPU(
	mode MLDSAMode,
	pubkeys [][]byte,
	messages [][]byte,
	msgLens []int,
	msgWidthHint uint32,
	signatures [][]byte,
	results []bool,
) error {
	if mode != MLDSAMode65 {
		return ErrGPUNotAvailable
	}
	n := len(pubkeys)
	if n == 0 {
		return nil
	}
	if len(messages) != n || len(signatures) != n || len(results) != n {
		return fmt.Errorf(
			"quantumvm: MLDSAVerifyBatch: length mismatch (pubkeys=%d messages=%d signatures=%d results=%d)",
			n, len(messages), len(signatures), len(results))
	}
	if msgLens != nil && len(msgLens) != n {
		return fmt.Errorf(
			"quantumvm: MLDSAVerifyBatch: msgLens length %d != batch %d",
			len(msgLens), n)
	}

	for i := 0; i < n; i++ {
		if len(pubkeys[i]) != MLDSA65PublicKeySize {
			return fmt.Errorf(
				"quantumvm: MLDSAVerifyBatch[%d]: pubkey len %d != %d",
				i, len(pubkeys[i]), MLDSA65PublicKeySize)
		}
		if len(signatures[i]) != MLDSA65SignatureSize {
			return fmt.Errorf(
				"quantumvm: MLDSAVerifyBatch[%d]: signature len %d != %d",
				i, len(signatures[i]), MLDSA65SignatureSize)
		}

		msg := mldsaResolveMessage(messages[i], msgLens, msgWidthHint, i)

		var pk mldsa65.PublicKey
		var pkBuf [mldsa65.PublicKeySize]byte
		copy(pkBuf[:], pubkeys[i])
		pk.Unpack(&pkBuf)

		// FIPS 204 §5.3 Verify with empty context. The cgo plugin's
		// orchestrator passes ctx_len=0 at the wire boundary; circl
		// treats nil ctx as the empty-context wrap (prefix [0x00,
		// 0x00] before the message bytes, see internal Verify), so
		// the two are byte-equivalent.
		results[i] = mldsa65.Verify(&pk, msg, nil, signatures[i])
	}
	return nil
}

// mldsaResolveMessage returns the byte slice the verifier should consume
// for batch element i. msgLens[i] (when non-nil) is the authoritative
// length; msgWidthHint > 0 is the uniform-batch fall-through; otherwise
// the natural len(messages[i]) wins. Mirrors the kernel-side resolution
// at the vtbl boundary (see backend_plugin.h v14 block).
func mldsaResolveMessage(msgI []byte, msgLens []int, msgWidthHint uint32, i int) []byte {
	if msgLens != nil {
		n := msgLens[i]
		if n < 0 {
			// Caller-side validation already rejects this in the cgo
			// path; mirror by clamping to zero so the downstream
			// circl.Verify call doesn't panic on negative slice index.
			n = 0
		}
		if n > len(msgI) {
			n = len(msgI)
		}
		return msgI[:n]
	}
	if msgWidthHint > 0 {
		n := int(msgWidthHint)
		if n > len(msgI) {
			n = len(msgI)
		}
		return msgI[:n]
	}
	return msgI
}

// mldsaSignBatchCPU is the pure-Go reference implementation of
// MLDSASignBatch. Mirrors the cgo path's flat-pool layout:
//
//   - skeys is the contiguous pool of per-element packed secret keys
//     (each MLDSA65SecretKeySize = 4032 bytes).
//   - msgs is the contiguous pool of per-element message payloads
//     (msgLens[i] bytes from offset sum(msgLens[0..i-1])).
//   - sigsOut receives count × MLDSA65SignatureSize bytes; each
//     element gets exactly SignatureSize bytes (FIPS 204 sigs are
//     fixed-width at the pack-sig boundary — the optional sigLensOut
//     reports the same constant per element on success, 0 on
//     kappa-cap reject).
//
// **Determinism**: every element signs with randomized=false (rnd =
// 0^32), matching the GPU kernel's deterministic mode (see
// ~/work/lux-private/gpu-kernels/ops/crypto/mldsa/cpu/mldsa_sign.hpp).
// Both implementations therefore produce byte-identical signatures for
// the same (sk, msg) inputs — the byte-equality contract that the
// parity test exercises.
func mldsaSignBatchCPU(
	mode MLDSAMode,
	skeys []byte,
	msgs []byte,
	msgLens []int,
	msgWidthHint uint32,
	count int,
	sigsOut []byte,
	sigLensOut []uint32,
) error {
	if mode != MLDSAMode65 {
		return ErrGPUNotAvailable
	}
	if count == 0 {
		return nil
	}
	const skStride = MLDSA65SecretKeySize
	const sigStride = MLDSA65SignatureSize
	if len(skeys) != count*skStride {
		return fmt.Errorf(
			"quantumvm: MLDSASignBatch: skeys len %d != count*%d (%d)",
			len(skeys), skStride, count*skStride)
	}
	if len(sigsOut) != count*sigStride {
		return fmt.Errorf(
			"quantumvm: MLDSASignBatch: sigsOut len %d != count*%d (%d)",
			len(sigsOut), sigStride, count*sigStride)
	}
	if msgLens != nil && len(msgLens) != count {
		return fmt.Errorf(
			"quantumvm: MLDSASignBatch: msgLens length %d != count %d",
			len(msgLens), count)
	}
	if sigLensOut != nil && len(sigLensOut) != count {
		return fmt.Errorf(
			"quantumvm: MLDSASignBatch: sigLensOut length %d != count %d",
			len(sigLensOut), count)
	}

	// Validate the msgs pool is large enough to cover the per-element
	// lengths (same boundary check the cgo path performs). Sum first
	// so we get one error rather than failing in the middle of a
	// partial batch.
	var total int
	if msgLens != nil {
		for i := 0; i < count; i++ {
			if msgLens[i] < 0 {
				return fmt.Errorf(
					"quantumvm: MLDSASignBatch[%d]: negative msgLen %d",
					i, msgLens[i])
			}
			total += msgLens[i]
		}
	} else {
		total = int(msgWidthHint) * count
	}
	if len(msgs) < total {
		return fmt.Errorf(
			"quantumvm: MLDSASignBatch: msgs pool len %d < total %d",
			len(msgs), total)
	}

	msgOffset := 0
	for i := 0; i < count; i++ {
		// Slice the per-element SK out of the contiguous pool. circl's
		// Unpack reads exactly skStride bytes via a [skStride]byte
		// pointer — copy through a stack array so the Go runtime
		// doesn't need to escape skBuf.
		var skBuf [mldsa65.PrivateKeySize]byte
		copy(skBuf[:], skeys[i*skStride:(i+1)*skStride])
		var sk mldsa65.PrivateKey
		sk.Unpack(&skBuf)

		// Slice the per-element message out of the flat pool.
		var msgLen int
		if msgLens != nil {
			msgLen = msgLens[i]
		} else {
			msgLen = int(msgWidthHint)
		}
		var msg []byte
		if msgLen > 0 {
			msg = msgs[msgOffset : msgOffset+msgLen]
		}
		msgOffset += msgLen

		// FIPS 204 §5.2 deterministic sign — randomized=false sets the
		// rnd buffer to 0^32 inside circl, byte-matching the GPU
		// kernel's deterministic recipe.
		sigSlot := sigsOut[i*sigStride : (i+1)*sigStride]
		if err := mldsa65.SignTo(&sk, msg, nil, false, sigSlot); err != nil {
			// circl returns ErrContextTooLong if ctx > 255; we always
			// pass nil so the only way to reach this is a wrapped
			// crypto/rand failure (unreachable with randomized=false).
			// Surface it for completeness.
			return fmt.Errorf("quantumvm: MLDSASignBatch[%d]: %w", i, err)
		}
		// FIPS 204 sigs are fixed-width (3309 B). Both modes return the
		// same constant — surface it so callers that opt in to the
		// length-out slice see the same number the cgo path writes.
		if sigLensOut != nil {
			sigLensOut[i] = MLDSA65SignatureSize
		}
	}
	return nil
}

// slhdsaVerifyBatchCPU is the pure-Go reference implementation of
// SLHDSAVerifyBatch. Walks the batch in-order, decodes each pubkey
// against the variant's parameter set, and writes the verify result
// into results[i]. circl's slhdsa.Verify(&pk, NewMessage(msg), sig,
// ctx=nil) is the canonical FIPS 205 port; the GPU kernel is
// byte-equal to FIPS 205, so both produce the same boolean for the
// same (pk, msg, sig).
//
// Only SHAKE-128f and SHAKE-192f are wired through the GPUBackend
// surface (mirroring the v14 vtbl gate) — every other variant returns
// ErrGPUNotAvailable so the CPU path's gate matches the cgo path's
// gate byte-for-byte. Callers that want the other 10 variants can
// reach circl directly.
func slhdsaVerifyBatchCPU(
	variant SLHDSAVariant,
	pubkeys [][]byte,
	messages [][]byte,
	msgLens []int,
	signatures [][]byte,
	results []bool,
) error {
	var id slhdsa.ID
	switch variant {
	case SLHDSAShake128f:
		id = slhdsa.SHAKE_128f
	case SLHDSAShake192f:
		id = slhdsa.SHAKE_192f
	default:
		return ErrGPUNotAvailable
	}
	n := len(pubkeys)
	if n == 0 {
		return nil
	}
	if len(messages) != n || len(signatures) != n || len(results) != n {
		return fmt.Errorf(
			"quantumvm: SLHDSAVerifyBatch: length mismatch (pubkeys=%d messages=%d signatures=%d results=%d)",
			n, len(messages), len(signatures), len(results))
	}
	if msgLens != nil && len(msgLens) != n {
		return fmt.Errorf(
			"quantumvm: SLHDSAVerifyBatch: msgLens length %d != batch %d",
			len(msgLens), n)
	}
	pkSize := variant.PublicKeySize()
	sigSize := variant.SignatureSize()

	for i := 0; i < n; i++ {
		if len(pubkeys[i]) != pkSize {
			return fmt.Errorf(
				"quantumvm: SLHDSAVerifyBatch[%d]: pubkey len %d != %d",
				i, len(pubkeys[i]), pkSize)
		}
		if len(signatures[i]) != sigSize {
			return fmt.Errorf(
				"quantumvm: SLHDSAVerifyBatch[%d]: signature len %d != %d",
				i, len(signatures[i]), sigSize)
		}
		if msgLens != nil && msgLens[i] < 0 {
			return fmt.Errorf(
				"quantumvm: SLHDSAVerifyBatch[%d]: negative msgLen %d",
				i, msgLens[i])
		}

		// circl unmarshals a PublicKey by setting the ID first, then
		// calling UnmarshalBinary on the packed bytes (FIPS 205
		// §10.1: pk = seed || root, 2n bytes total). The byte order
		// matches the GPU kernel's pack-pk encoding (also FIPS 205).
		pk := slhdsa.PublicKey{ID: id}
		if err := pk.UnmarshalBinary(pubkeys[i]); err != nil {
			return fmt.Errorf(
				"quantumvm: SLHDSAVerifyBatch[%d]: pubkey decode: %w",
				i, err)
		}

		var msg []byte
		if msgLens != nil {
			n := msgLens[i]
			if n > len(messages[i]) {
				n = len(messages[i])
			}
			msg = messages[i][:n]
		} else {
			msg = messages[i]
		}

		// FIPS 205 §10.3 Verify with empty context (mirroring the cgo
		// plugin's ctx_len=0). slhdsa.NewMessage wraps the raw bytes
		// in a "pure" Message (isPreHash=0), which circl then prefixes
		// with [0x00, 0x00] inside the verifier — byte-equivalent to
		// the kernel's `context=nullptr, context_len=0` path.
		results[i] = slhdsa.Verify(&pk, slhdsa.NewMessage(msg), signatures[i], nil)
	}
	return nil
}

// =============================================================================
// cpuBackend — the GPUBackend interface satisfied by the pure-Go path.
//
// Used by:
//   - quantumvm_gpu_nocgo.go: ActiveGPUBackend() returns cpuBackend{}
//     directly. There is no plugin probe at !cgo.
//   - quantumvm_gpu.go: when the dlopen probe finds no plugin OR every
//     plugin slot returns ErrGPUNotAvailable, the cgo bridge falls
//     through to these CPU helpers via the same path the nocgo build
//     uses. One implementation, one surface.
//
// Backend() reports BackendNone — the package-level AutoBackend()
// signal stays "no GPU plugin loaded" for telemetry purposes. Callers
// that branch on AutoBackend() for *correctness* were already wrong
// (the cgo path's fallback path runs under the same tag); callers
// that branch on it for telemetry get the truth.
// =============================================================================

type cpuBackend struct{}

func (cpuBackend) Backend() Backend { return BackendNone }

func (cpuBackend) Close() error { return nil }

func (cpuBackend) MLDSAVerifyBatch(
	mode MLDSAMode,
	pubkeys [][]byte,
	messages [][]byte,
	msgLens []int,
	msgWidthHint uint32,
	signatures [][]byte,
	results []bool,
) error {
	return mldsaVerifyBatchCPU(mode, pubkeys, messages, msgLens, msgWidthHint, signatures, results)
}

func (cpuBackend) MLDSASignBatch(
	mode MLDSAMode,
	skeys []byte,
	msgs []byte,
	msgLens []int,
	msgWidthHint uint32,
	count int,
	sigsOut []byte,
	sigLensOut []uint32,
) error {
	return mldsaSignBatchCPU(mode, skeys, msgs, msgLens, msgWidthHint, count, sigsOut, sigLensOut)
}

func (cpuBackend) SLHDSAVerifyBatch(
	variant SLHDSAVariant,
	pubkeys [][]byte,
	messages [][]byte,
	msgLens []int,
	signatures [][]byte,
	results []bool,
) error {
	return slhdsaVerifyBatchCPU(variant, pubkeys, messages, msgLens, signatures, results)
}
