// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// quantumvm_gpu_cpu_test.go — build-tag-free tests for the GPUBackend
// surface. Runs under BOTH cgo and !cgo build modes against the same
// fixtures; the property under test is that ActiveGPUBackend() produces
// output identical to a direct call into circl, regardless of which
// backend (real GPU plugin, cgo fall-through CPU, or pure !cgo CPU)
// served the call.
//
// This is the parity contract that decomplecting the bridge buys us:
// callers no longer need a "did I just get GPU or CPU?" branch — they
// just call ActiveGPUBackend().MLDSAVerifyBatch / MLDSASignBatch /
// SLHDSAVerifyBatch and read the results. Same bytes everywhere.

package quantumvm

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// TestGPUBridgeCgoNocgoParity is the cross-build-mode parity guarantee:
// ActiveGPUBackend() produces output byte-identical to a direct circl
// call for the same (pk, msg, sig) and (sk, msg) inputs. Under cgo
// with no plugin loaded, the bridge falls through to the CPU helpers;
// under cgo with a plugin loaded, the plugin's FIPS 204/205 conformance
// guarantees the same output; under !cgo, the CPU helpers are the only
// path. All three modes must agree.
//
// The test exercises every leg of the GPUBackend surface:
//   - MLDSAVerifyBatch on a valid (pk, msg, sig) triple → true.
//   - MLDSAVerifyBatch on a tampered (pk, msg, sig) triple → false.
//   - MLDSASignBatch with the same (sk, msg) twice → byte-identical
//     signatures (deterministic mode, rnd = 0^32).
//   - MLDSASignBatch + MLDSAVerifyBatch round-trip → true.
//   - SLHDSAVerifyBatch on SHAKE-128f and SHAKE-192f (the two variants
//     wired through the v14 vtbl) → both verify true on the honest
//     triple.
func TestGPUBridgeCgoNocgoParity(t *testing.T) {
	g := ActiveGPUBackend()
	t.Logf("ActiveGPUBackend() = %s (Backend()=%d)", AutoBackend(), g.Backend())

	// --- ML-DSA-65 verify: honest triple via circl, then through the
	// GPUBackend surface, expect results[0]=true.
	pkObj, skObj, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("mldsa65.GenerateKey: %v", err)
	}
	pkBytes := pkObj.Bytes()
	skBytes := skObj.Bytes()
	if len(pkBytes) != MLDSA65PublicKeySize {
		t.Fatalf("pkBytes len = %d, want %d", len(pkBytes), MLDSA65PublicKeySize)
	}
	if len(skBytes) != MLDSA65SecretKeySize {
		t.Fatalf("skBytes len = %d, want %d", len(skBytes), MLDSA65SecretKeySize)
	}
	msg := make([]byte, 64)
	// Deterministic byte pattern keeps the fixture stable across reruns
	// — same shape as the Q-Chain quantum stamp's sha512 digest input.
	for i := range msg {
		msg[i] = byte(i)
	}

	// Deterministic signature via circl (randomized=false → rnd=0^32).
	// This is the canonical FIPS 204 §5.2 deterministic mode — the GPU
	// kernel's CPU oracle in lux-private/gpu-kernels takes the same
	// choice, so the byte stream is the cross-backend ground truth.
	circlSig := make([]byte, MLDSA65SignatureSize)
	if err := mldsa65.SignTo(skObj, msg, nil, false, circlSig); err != nil {
		t.Fatalf("mldsa65.SignTo (deterministic): %v", err)
	}
	if got := mldsa65.Verify(pkObj, msg, nil, circlSig); !got {
		t.Fatalf("circl self-verify failed — fixture corrupt")
	}

	// Through the GPUBackend surface.
	results := make([]bool, 1)
	if err := g.MLDSAVerifyBatch(
		MLDSAMode65,
		[][]byte{pkBytes},
		[][]byte{msg},
		[]int{len(msg)},
		0,
		[][]byte{circlSig},
		results,
	); err != nil {
		t.Fatalf("GPUBackend.MLDSAVerifyBatch (honest): %v", err)
	}
	if !results[0] {
		t.Fatalf("GPUBackend.MLDSAVerifyBatch(honest) = false, want true")
	}

	// Tampered: flip a sig byte. Both backends MUST agree it's
	// invalid. Pick a byte inside the c̃ block (offset 0..47) so the
	// failure surfaces in challenge-recomputation, not in the
	// structural decode.
	badSig := append([]byte(nil), circlSig...)
	badSig[7] ^= 0xFF
	results[0] = true // poison the slot to detect "didn't write"
	if err := g.MLDSAVerifyBatch(
		MLDSAMode65,
		[][]byte{pkBytes},
		[][]byte{msg},
		[]int{len(msg)},
		0,
		[][]byte{badSig},
		results,
	); err != nil {
		t.Fatalf("GPUBackend.MLDSAVerifyBatch (tampered): %v", err)
	}
	if results[0] {
		t.Fatalf("GPUBackend.MLDSAVerifyBatch(tampered) = true, want false")
	}

	// --- ML-DSA-65 sign batch: byte-equality of signatures for the
	// same (sk, msg) input across two invocations of MLDSASignBatch.
	// FIPS 204 deterministic mode → same input gives same bytes.
	skPool := make([]byte, MLDSA65SecretKeySize)
	copy(skPool, skBytes)
	msgPool := append([]byte(nil), msg...)
	msgLens := []int{len(msg)}
	sigsA := make([]byte, MLDSA65SignatureSize)
	sigsB := make([]byte, MLDSA65SignatureSize)
	sigLensA := make([]uint32, 1)
	sigLensB := make([]uint32, 1)
	if err := g.MLDSASignBatch(
		MLDSAMode65,
		skPool,
		msgPool,
		msgLens,
		0,
		1,
		sigsA,
		sigLensA,
	); err != nil {
		t.Fatalf("GPUBackend.MLDSASignBatch (run A): %v", err)
	}
	if err := g.MLDSASignBatch(
		MLDSAMode65,
		skPool,
		msgPool,
		msgLens,
		0,
		1,
		sigsB,
		sigLensB,
	); err != nil {
		t.Fatalf("GPUBackend.MLDSASignBatch (run B): %v", err)
	}
	if !bytesEqual(sigsA, sigsB) {
		t.Fatalf("MLDSASignBatch is not deterministic — sigsA != sigsB")
	}
	if sigLensA[0] != MLDSA65SignatureSize || sigLensB[0] != MLDSA65SignatureSize {
		t.Fatalf("sigLens[0] = (A=%d B=%d), want %d", sigLensA[0], sigLensB[0], MLDSA65SignatureSize)
	}
	// Byte-equal to the circl-direct deterministic signature.
	if !bytesEqual(sigsA, circlSig) {
		t.Fatalf("MLDSASignBatch output != circl-direct deterministic signature\n  GPU:   %x...\n  circl: %x...",
			sigsA[:16], circlSig[:16])
	}

	// And the signed output verifies through the same surface.
	results[0] = false
	if err := g.MLDSAVerifyBatch(
		MLDSAMode65,
		[][]byte{pkBytes},
		[][]byte{msg},
		[]int{len(msg)},
		0,
		[][]byte{sigsA},
		results,
	); err != nil {
		t.Fatalf("GPUBackend.MLDSAVerifyBatch (sign-then-verify): %v", err)
	}
	if !results[0] {
		t.Fatalf("sign-then-verify failed — sigsA didn't verify against pkBytes")
	}

	// --- SLH-DSA verify: SHAKE-128f.
	testSLHDSAParityRoundTrip(t, g, SLHDSAShake128f, slhdsa.SHAKE_128f)
	// --- SLH-DSA verify: SHAKE-192f.
	testSLHDSAParityRoundTrip(t, g, SLHDSAShake192f, slhdsa.SHAKE_192f)
}

// testSLHDSAParityRoundTrip generates an (sk, pk) pair via circl for
// the requested SLH-DSA variant, signs a fixture deterministically,
// and asserts the GPUBackend surface verifies it as true. SLH-DSA
// keygen is comparatively slow (especially for higher security
// levels), so we keep the batch size at 1.
func testSLHDSAParityRoundTrip(
	t *testing.T,
	g GPUBackend,
	variant SLHDSAVariant,
	id slhdsa.ID,
) {
	t.Helper()
	pk, sk, err := slhdsa.GenerateKey(rand.Reader, id)
	if err != nil {
		t.Fatalf("slhdsa.GenerateKey(%s): %v", id, err)
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		t.Fatalf("slhdsa.PublicKey.MarshalBinary(%s): %v", id, err)
	}
	if got, want := len(pkBytes), variant.PublicKeySize(); got != want {
		t.Fatalf("%s pubkey size = %d, want %d", id, got, want)
	}
	msg := []byte("slh-dsa parity fixture")
	sig, err := slhdsa.SignDeterministic(&sk, slhdsa.NewMessage(msg), nil)
	if err != nil {
		t.Fatalf("slhdsa.SignDeterministic(%s): %v", id, err)
	}
	if got, want := len(sig), variant.SignatureSize(); got != want {
		t.Fatalf("%s signature size = %d, want %d", id, got, want)
	}
	results := make([]bool, 1)
	if err := g.SLHDSAVerifyBatch(
		variant,
		[][]byte{pkBytes},
		[][]byte{msg},
		[]int{len(msg)},
		[][]byte{sig},
		results,
	); err != nil {
		t.Fatalf("GPUBackend.SLHDSAVerifyBatch(%s): %v", id, err)
	}
	if !results[0] {
		t.Fatalf("GPUBackend.SLHDSAVerifyBatch(%s) honest = false, want true", id)
	}
	// Tamper and re-verify — must come back false.
	sig[0] ^= 0xFF
	results[0] = true
	if err := g.SLHDSAVerifyBatch(
		variant,
		[][]byte{pkBytes},
		[][]byte{msg},
		[]int{len(msg)},
		[][]byte{sig},
		results,
	); err != nil {
		t.Fatalf("GPUBackend.SLHDSAVerifyBatch(%s, tampered): %v", id, err)
	}
	if results[0] {
		t.Fatalf("GPUBackend.SLHDSAVerifyBatch(%s, tampered) = true, want false", id)
	}
}

// bytesEqual is a local byte-comparison helper. Defined locally rather
// than pulled from bytes.Equal so this file has zero imports outside
// the parity test's actual surface (circl + the quantumvm package
// itself).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
