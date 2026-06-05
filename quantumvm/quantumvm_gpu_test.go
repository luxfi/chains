//go:build cgo

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/luxfi/crypto/mldsa"
)

// TestAutoBackend_Probes documents what the init() probe found at process
// start. Skipped when no plugin loaded — this is the on-CI / clean-build
// signal that the binary stays portable. When a plugin IS loaded, we log
// its name so flakes can be tied back to a specific backend.
func TestAutoBackend_Probes(t *testing.T) {
	b := AutoBackend()
	if b == BackendNone {
		t.Skip("no libluxgpu_backend_*.{so,dylib} loadable on the dlopen path — Q-Chain CPU path remains the only option")
	}
	t.Logf("AutoBackend() = %s", b)
}

// TestActiveGPUBackend_NoBackendReturnsErr exercises the noGPUBackend
// stub returned when no plugin was loaded. Every method must return
// ErrGPUNotAvailable so callers can route to the CPU verify path via
// errors.Is.
func TestActiveGPUBackend_NoBackendReturnsErr(t *testing.T) {
	if AutoBackend() != BackendNone {
		t.Skip("plugin loaded — noGPUBackend stub not exercised on this host")
	}
	g := ActiveGPUBackend()
	if g.Backend() != BackendNone {
		t.Fatalf("Backend() = %s, want none", g.Backend())
	}
	err := g.MLDSAVerifyBatch(MLDSAMode65, nil, nil, nil, 0, nil, nil)
	if err != nil {
		// Empty batch is a legal no-op even when no plugin loaded;
		// length 0 short-circuits before the noGPUBackend stub runs.
		t.Fatalf("MLDSAVerifyBatch(empty) = %v, want nil", err)
	}
	err = g.MLDSAVerifyBatch(MLDSAMode65,
		[][]byte{make([]byte, MLDSA65PublicKeySize)},
		[][]byte{nil},
		nil, 0,
		[][]byte{make([]byte, MLDSA65SignatureSize)},
		make([]bool, 1))
	if !errors.Is(err, ErrGPUNotAvailable) {
		t.Fatalf("MLDSAVerifyBatch on noGPUBackend = %v, want ErrGPUNotAvailable", err)
	}
}

// TestMLDSAVerifyBatch_RoundTrip — open a backend context, sign one
// message via the in-process circl ML-DSA-65 implementation, then run
// op_mldsa_verify_batch on the (pk, msg, sig) triple and assert
// results[0] == true.
//
// The plugin's wrapper consumes FIPS 204 wire-format (pk=1952 B,
// sig=3309 B max) which is exactly what circl's MarshalBinary() /
// SignTo() emit, so the round-trip is byte-compatible — no PQClean
// detour needed in the test.
//
// Skip conditions:
//   * No plugin loaded                              -> AutoBackend() == BackendNone
//   * Plugin loaded but op_mldsa_verify_batch is a   -> rc=NOT_SUPPORTED
//     CPU oracle returning NOT_SUPPORTED (e.g. some
//     WebGPU phase-2 builds) — surfaces as ErrGPUNotAvailable.
//
// Either skip is a CLEAN exit, not a FAIL. The property under test is
// "ABI v14 wire-format round-trips through the loaded plugin", which
// is only meaningful when the plugin actually runs the verify path.
func TestMLDSAVerifyBatch_RoundTrip(t *testing.T) {
	if AutoBackend() == BackendNone {
		t.Skip("no GPU plugin loaded — round-trip test requires the dlopen probe to have succeeded at init()")
	}
	g := ActiveGPUBackend()
	t.Logf("backend = %s", g.Backend())

	// Generate one ML-DSA-65 keypair + signature via circl. The test
	// is single-shot so we don't bother batching beyond N=1; the v14
	// vtbl wrapper has the same shape for every batch size.
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		t.Fatalf("mldsa.GenerateKey: %v", err)
	}
	pkBytes := priv.PublicKey.Bytes()
	if len(pkBytes) != MLDSA65PublicKeySize {
		t.Fatalf("pubkey size = %d, want %d", len(pkBytes), MLDSA65PublicKeySize)
	}

	// 64-byte message — matches what the Q-Chain quantum stamp path
	// hands the verifier (sha512 digest of the round digest + nonce +
	// timestamp). Using a deterministic byte pattern keeps the test
	// reproducible across reruns.
	msg := make([]byte, 64)
	for i := range msg {
		msg[i] = byte(i)
	}
	// Sign with ctx=nil to match the orchestrator's ctx_len=0 wrap.
	sig, err := priv.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatalf("priv.Sign: %v", err)
	}
	if got, max := len(sig), MLDSA65SignatureSize; got > max {
		t.Fatalf("sig size = %d > max %d", got, max)
	}
	// Pad the signature out to the fixed 3309-byte width the orchestrator
	// reads. Padding bytes after the real sig length are ignored by the
	// FIPS 204 verify path (sig parsing terminates at the c̃ + z + h
	// structural decode).
	sigPadded := make([]byte, MLDSA65SignatureSize)
	copy(sigPadded, sig)

	results := make([]bool, 1)
	err = g.MLDSAVerifyBatch(
		MLDSAMode65,
		[][]byte{pkBytes},
		[][]byte{msg},
		[]int{len(msg)},
		/*msgWidthHint=*/ 0,
		[][]byte{sigPadded},
		results,
	)
	if errors.Is(err, ErrGPUNotAvailable) {
		t.Skipf("plugin op_mldsa_verify_batch returned NOT_SUPPORTED (backend=%s) — surface contract honoured, round-trip not testable", g.Backend())
	}
	if err != nil {
		t.Fatalf("MLDSAVerifyBatch: %v", err)
	}
	if !results[0] {
		t.Fatalf("honest verify returned false (backend=%s) — wire-format incompatibility", g.Backend())
	}
	t.Logf("backend=%s op_mldsa_verify_batch honest verify -> true", g.Backend())
}

// TestMLDSAVerifyBatch_LengthMismatch covers the length-validation
// branch at the boundary. The wrapper must reject batches where the
// per-element slices disagree on cardinality before any C call.
func TestMLDSAVerifyBatch_LengthMismatch(t *testing.T) {
	if AutoBackend() == BackendNone {
		t.Skip("no GPU plugin loaded")
	}
	g := ActiveGPUBackend()
	err := g.MLDSAVerifyBatch(
		MLDSAMode65,
		make([][]byte, 2),
		make([][]byte, 1),
		nil, 0,
		make([][]byte, 2),
		make([]bool, 2),
	)
	if err == nil {
		t.Fatal("expected length-mismatch error, got nil")
	}
}

// TestMLDSAVerifyBatch_NonMLDSA65Skips exercises the mode gate. Modes
// 44 / 87 aren't wired at v14 — passing them must surface as
// ErrGPUNotAvailable so callers fall through cleanly.
func TestMLDSAVerifyBatch_NonMLDSA65Skips(t *testing.T) {
	g := ActiveGPUBackend()
	for _, mode := range []MLDSAMode{MLDSAMode44, MLDSAMode87} {
		err := g.MLDSAVerifyBatch(mode,
			[][]byte{make([]byte, 1)},
			[][]byte{nil}, nil, 0,
			[][]byte{make([]byte, 1)},
			make([]bool, 1))
		if !errors.Is(err, ErrGPUNotAvailable) {
			t.Fatalf("mode %d: got %v, want ErrGPUNotAvailable", mode, err)
		}
	}
}
