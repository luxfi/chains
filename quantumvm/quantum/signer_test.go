// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantum

import (
	"bytes"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/luxfi/accel"
	"github.com/luxfi/log"
)

// runtimeCollect gives the collector a chance to run any finalizer that a
// discarded key armed.
func runtimeCollect() {
	runtime.GC()
	time.Sleep(5 * time.Millisecond)
	runtime.GC()
}

func signer(t *testing.T) *QuantumSigner {
	t.Helper()
	return newSigner(t, AlgorithmMLDSA65, time.Minute)
}

func newSigner(t *testing.T, version uint32, window time.Duration) *QuantumSigner {
	t.Helper()
	qs, err := NewQuantumSigner(log.NewNoOpLogger(), version, window)
	if err != nil {
		t.Fatalf("NewQuantumSigner(%d): %v", version, err)
	}
	return qs
}

// stored is a validator key in the shape it takes coming back from storage or
// the wire: the exported fields only, with nothing parsed yet.
func stored(t *testing.T, qs *QuantumSigner) *MLDSAValidatorKey {
	t.Helper()
	gen, err := qs.GenerateCoronaKey()
	if err != nil {
		t.Fatalf("GenerateCoronaKey: %v", err)
	}
	return &MLDSAValidatorKey{
		Version:    gen.Version,
		PublicKey:  gen.PublicKey,
		PrivateKey: gen.PrivateKey,
		Nonce:      gen.Nonce,
	}
}

// TestSignParsesStoredSecretOnce pins that repeated signing reuses one parsed
// key rather than building a new one per signature.
func TestSignParsesStoredSecretOnce(t *testing.T) {
	qs := signer(t)
	key := stored(t, qs)
	msg := []byte("round digest")

	sig, err := qs.Sign(msg, key)
	if err != nil {
		t.Fatalf("first Sign: %v", err)
	}
	if err := qs.Verify(msg, sig); err != nil {
		t.Fatalf("first signature did not verify: %v", err)
	}
	first := key.mldsaPriv
	if first == nil {
		t.Fatal("Sign left the parsed key unset, so the next Sign parses again")
	}

	sig, err = qs.Sign(msg, key)
	if err != nil {
		t.Fatalf("second Sign: %v", err)
	}
	if key.mldsaPriv != first {
		t.Fatal("Sign parsed the stored secret a second time")
	}
	if err := qs.Verify(msg, sig); err != nil {
		t.Fatalf("second signature did not verify: %v", err)
	}
}

// TestSignHoldsUpUnderCollection signs repeatedly across collection cycles: a
// key whose secret outlives every signature keeps producing valid signatures.
func TestSignHoldsUpUnderCollection(t *testing.T) {
	qs := signer(t)
	key := stored(t, qs)
	msg := []byte("round digest")

	for i := 0; i < 8; i++ {
		sig, err := qs.Sign(msg, key)
		if err != nil {
			t.Fatalf("Sign %d: %v", i, err)
		}
		if err := qs.Verify(msg, sig); err != nil {
			t.Fatalf("signature %d did not verify: %v", i, err)
		}
		runtimeCollect()
	}
}

// TestGeneratedKeyOwnsItsSecret pins that the bytes a caller persists out of a
// generated key stay readable for as long as the caller holds them, whatever
// becomes of the key they came from.
func TestGeneratedKeyOwnsItsSecret(t *testing.T) {
	qs := signer(t)
	gen, err := qs.GenerateCoronaKey()
	if err != nil {
		t.Fatalf("GenerateCoronaKey: %v", err)
	}
	persisted := gen.PrivateKey
	want := bytes.Clone(persisted)

	gen = nil
	runtimeCollect()
	runtimeCollect()

	if !bytes.Equal(persisted, want) {
		t.Fatal("collecting the generated key changed the secret already read out of it")
	}
}

// TestSignRejectsUnparseableSecret pins that a key that cannot be parsed fails
// closed, every time, rather than signing with whatever is in the buffer.
func TestSignRejectsUnparseableSecret(t *testing.T) {
	qs := signer(t)
	key := &MLDSAValidatorKey{PrivateKey: []byte("too short to be a key")}

	for i := 0; i < 2; i++ {
		if _, err := qs.Sign([]byte("round digest"), key); err == nil {
			t.Fatalf("Sign %d accepted an unparseable secret", i)
		}
	}
}

// TestVerifyRefusesAnExpiredStamp: a stamp is only good inside its window. The
// window is the whole reason a stamp exists — without the check, a signature
// captured once is replayable for as long as the chain runs.
func TestVerifyRefusesAnExpiredStamp(t *testing.T) {
	qs := newSigner(t, AlgorithmMLDSA65, 50*time.Millisecond)
	key := stored(t, qs)
	msg := []byte("round digest")

	sig, err := qs.Sign(msg, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := qs.Verify(msg, sig); err != nil {
		t.Fatalf("a fresh signature did not verify: %v", err)
	}

	time.Sleep(120 * time.Millisecond)
	if err := qs.Verify(msg, sig); err != ErrQuantumStampExpired {
		t.Fatalf("Verify past the window = %v, want ErrQuantumStampExpired", err)
	}
}

// TestVerifyRefusesAnotherAlgorithm: a signature made under one ML-DSA
// parameter set must not be accepted by a signer running another. The key and
// signature widths differ, so accepting one would mean verifying against a
// truncated key.
func TestVerifyRefusesAnotherAlgorithm(t *testing.T) {
	weak := newSigner(t, AlgorithmMLDSA44, time.Minute)
	strong := newSigner(t, AlgorithmMLDSA87, time.Minute)

	sig, err := weak.Sign([]byte("digest"), stored(t, weak))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := strong.Verify([]byte("digest"), sig); err != ErrUnsupportedAlgorithm {
		t.Fatalf("Verify across parameter sets = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// TestVerifyRefusesAlteredMessageAndNilSignature covers the two ways a caller
// arrives with nothing valid: a signature over other bytes, and none at all.
func TestVerifyRefusesAlteredMessageAndNilSignature(t *testing.T) {
	qs := signer(t)
	sig, err := qs.Sign([]byte("the real message"), stored(t, qs))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := qs.Verify([]byte("a different message"), sig); err != ErrQuantumVerificationFailed {
		t.Fatalf("Verify over other bytes = %v, want ErrQuantumVerificationFailed", err)
	}
	if err := qs.Verify([]byte("the real message"), nil); err != ErrInvalidQuantumSignature {
		t.Fatalf("Verify(nil) = %v, want ErrInvalidQuantumSignature", err)
	}
	if _, err := qs.Sign([]byte("x"), nil); err != ErrInvalidCoronaKey {
		t.Fatalf("Sign(nil key) = %v, want ErrInvalidCoronaKey", err)
	}
}

// TestVerifyRefusesAnUnparseablePublicKey: the key travels with the signature,
// so it is attacker-controlled and must fail closed rather than panic.
func TestVerifyRefusesAnUnparseablePublicKey(t *testing.T) {
	qs := signer(t)
	sig, err := qs.Sign([]byte("digest"), stored(t, qs))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig.PublicKey = []byte("not a key")
	if err := qs.Verify([]byte("digest"), sig); err == nil {
		t.Fatal("Verify accepted a signature carrying an unparseable public key")
	}
}

// TestParallelVerifyFailsOnOneBadSignature: the batch verdict is the AND of its
// members. A batch that passed while holding one bad signature would let a
// forged transaction into a block on the strength of the honest ones beside it.
func TestParallelVerifyFailsOnOneBadSignature(t *testing.T) {
	qs := signer(t)
	const n = 12
	msgs := make([][]byte, n)
	sigs := make([]*QuantumSignature, n)
	for i := range msgs {
		msgs[i] = []byte{byte(i), 'm', 's', 'g'}
		sig, err := qs.Sign(msgs[i], stored(t, qs))
		if err != nil {
			t.Fatalf("Sign %d: %v", i, err)
		}
		sigs[i] = sig
	}

	if err := qs.ParallelVerify(msgs, sigs); err != nil {
		t.Fatalf("a batch of good signatures did not verify: %v", err)
	}

	sigs[n/2].Signature[0] ^= 0xFF
	if err := qs.ParallelVerify(msgs, sigs); err == nil {
		t.Fatal("a batch holding one forged signature verified")
	}

	// The same holds on the batch path the VM actually calls, at a threshold
	// low enough to take it.
	if err := qs.ParallelVerifyWithThreshold(msgs, sigs, 4); err == nil {
		t.Fatal("the thresholded batch path accepted one forged signature")
	}
}

// TestParallelVerifyRefusesMismatchedInputs: a message with no signature beside
// it is not a thing to verify, and pairing them off by index would verify the
// wrong pair.
func TestParallelVerifyRefusesMismatchedInputs(t *testing.T) {
	qs := signer(t)
	if err := qs.ParallelVerify([][]byte{{1}, {2}}, []*QuantumSignature{nil}); err == nil {
		t.Fatal("two messages and one signature were accepted as a batch")
	}
	if err := qs.ParallelVerify(nil, nil); err != nil {
		t.Fatalf("an empty batch is a no-op, got %v", err)
	}
}

// TestSignerReportsItsWidths: the caller sizes buffers from these, so they must
// come from the mode rather than a configured guess.
func TestSignerReportsItsWidths(t *testing.T) {
	for _, tc := range []struct{ version uint32 }{
		{AlgorithmMLDSA44}, {AlgorithmMLDSA65}, {AlgorithmMLDSA87},
	} {
		qs := newSigner(t, tc.version, time.Minute)
		key, err := qs.GenerateCoronaKey()
		if err != nil {
			t.Fatalf("GenerateCoronaKey: %v", err)
		}
		if got := len(key.PublicKey); got != qs.GetPublicKeySize() {
			t.Fatalf("version %d: key is %d bytes, GetPublicKeySize says %d", tc.version, got, qs.GetPublicKeySize())
		}
		sig, err := qs.Sign([]byte("digest"), key)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if got := len(sig.Signature); got > qs.GetSignatureSize() {
			t.Fatalf("version %d: signature is %d bytes, over the %d the mode allows", tc.version, got, qs.GetSignatureSize())
		}
		// A second signer named the same way agrees on the mode, so it can
		// verify what the first produced.
		peer := newSigner(t, tc.version, time.Minute)
		if peer.GetMode() != qs.GetMode() {
			t.Fatalf("version %d resolved to two different modes", tc.version)
		}
		if err := peer.Verify([]byte("digest"), sig); err != nil {
			t.Fatalf("version %d: a peer on the same version could not verify: %v", tc.version, err)
		}
	}
}

// TestGPUVerifyFailsClosedWhenThereIsNoGPU.
//
// The batch path asks the accelerator first and falls back to CPU on any error.
// That fallback is only safe if a missing accelerator is an ERROR — a GPU path
// that returned nil when it had verified nothing would report every signature
// in the batch as good, and the CPU check that should have caught them would
// never run.
func TestGPUVerifyFailsClosedWhenThereIsNoGPU(t *testing.T) {
	if accel.Available() {
		t.Fatalf("this host has an accelerator, so the no-GPU contract cannot be observed here; " +
			"run the GPU batch tests instead")
	}

	qs := signer(t)
	msgs := [][]byte{[]byte("one"), []byte("two")}
	sigs := make([]*QuantumSignature, len(msgs))
	for i := range msgs {
		sig, err := qs.Sign(msgs[i], stored(t, qs))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		sigs[i] = sig
	}

	if err := qs.gpuBatchVerify(msgs, sigs); err == nil {
		t.Fatal("the GPU path reported success with no accelerator to verify on")
	}

	// And the caller routes around it: the same batch verifies on the CPU.
	if err := qs.ParallelVerifyWithThreshold(msgs, sigs, 1); err != nil {
		t.Fatalf("the CPU fallback did not run: %v", err)
	}

	// A forged one is still caught after the fallback.
	sigs[1].Signature[0] ^= 0xFF
	if err := qs.ParallelVerifyWithThreshold(msgs, sigs, 1); err == nil {
		t.Fatal("the fallback accepted a forged signature")
	}
}

// TestTheStampTimeIsSigned.
//
// Freshness was decided by a plain field on the signature — Sign covered
// message || stamp and NOT the Timestamp — so the holder of an expired stamp
// revived it by writing the current time into it, and the same edit forward
// produced one that never expired at all. The window is the only thing standing
// between a captured signature and unlimited replay, so the value it reads has
// to be one the signature covers.
func TestTheStampTimeIsSigned(t *testing.T) {
	qs := newSigner(t, AlgorithmMLDSA65, 50*time.Millisecond)
	key := stored(t, qs)
	msg := []byte("round digest")

	sig, err := qs.Sign(msg, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := qs.Verify(msg, sig); err != nil {
		t.Fatalf("a fresh signature did not verify: %v", err)
	}

	time.Sleep(120 * time.Millisecond)
	if err := qs.Verify(msg, sig); err != ErrQuantumStampExpired {
		t.Fatalf("precondition: the stamp should have expired, got %v", err)
	}

	// Rewrite the field to now. The window is satisfied — and the signature is
	// not, because the field is part of what was signed.
	sig.Timestamp = time.Now()
	if err := qs.Verify(msg, sig); err != ErrQuantumVerificationFailed {
		t.Fatalf("an expired stamp was revived by rewriting its timestamp: %v", err)
	}
}

// TestVerifyRefusesAFutureStamp. time.Since goes NEGATIVE for a date ahead of
// now, so a stamp dated forward compared as arbitrarily fresh and never expired
// — one write to an unsigned field bought a signature that is valid forever.
func TestVerifyRefusesAFutureStamp(t *testing.T) {
	qs := newSigner(t, AlgorithmMLDSA65, time.Minute)
	key := stored(t, qs)
	msg := []byte("round digest")

	sig, err := qs.Sign(msg, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for _, ahead := range []time.Duration{2 * time.Minute, time.Hour, 24 * 365 * time.Hour} {
		sig.Timestamp = time.Now().Add(ahead)
		if err := qs.Verify(msg, sig); err != ErrQuantumStampExpired {
			t.Fatalf("a stamp dated %s ahead was accepted: %v", ahead, err)
		}
	}
}

// TestNewQuantumSignerRefusesAnAlgorithmThatDoesNotExist.
//
// It fell through to ML-DSA-65 for anything unrecognised, so a caller that
// asked for something else got a signer running a parameter set nobody chose
// and never heard about it — and the config and the signer disagreed about what
// an unset version means.
func TestNewQuantumSignerRefusesAnAlgorithmThatDoesNotExist(t *testing.T) {
	for _, version := range []uint32{0, 4, 7, 42, 99, ^uint32(0)} {
		qs, err := NewQuantumSigner(log.NewNoOpLogger(), version, time.Minute)
		if err == nil {
			t.Fatalf("version %d was accepted and resolved to %v", version, qs.GetMode())
		}
		if !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("version %d: %v, want ErrUnsupportedAlgorithm", version, err)
		}
		if qs != nil {
			t.Fatalf("version %d returned a signer alongside its refusal", version)
		}
	}
}

// TestBatchPackingKeepsEveryEntryInItsOwnRow.
//
// The rows are fixed-width and were copied with the low end bounded only, so an
// over-long signature or public key at index i ran off its row and overwrote
// index i+1's. A caller supplying a matching over-long pair chose the key that
// entry i+1 would be verified under. ML-DSA widths are fixed by the parameter
// set, so an off-width input is refused rather than trusted to fit.
func TestBatchPackingKeepsEveryEntryInItsOwnRow(t *testing.T) {
	qs := signer(t)
	sigSize, pkSize := qs.GetSignatureSize(), qs.GetPublicKeySize()

	msgs := [][]byte{[]byte("one"), []byte("two")}
	sigs := make([]*QuantumSignature, len(msgs))
	for i := range msgs {
		sig, err := qs.Sign(msgs[i], stored(t, qs))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		sigs[i] = sig
	}

	_, sigBuf, pkBuf, _, err := qs.packBatch(msgs, sigs)
	if err != nil {
		t.Fatalf("a well-formed batch was refused: %v", err)
	}
	if len(sigBuf) != len(msgs)*sigSize || len(pkBuf) != len(msgs)*pkSize {
		t.Fatalf("rows are %d/%d bytes, want %d/%d", len(sigBuf), len(pkBuf), len(msgs)*sigSize, len(msgs)*pkSize)
	}
	if !bytes.Equal(pkBuf[pkSize:], sigs[1].PublicKey) {
		t.Fatal("entry 1's key is not in entry 1's row")
	}

	// An over-long signature at index 0 would reach into index 1's row.
	oversized := *sigs[0]
	oversized.Signature = bytes.Repeat([]byte{0xAA}, sigSize+64)
	if _, _, _, _, err := qs.packBatch(msgs, []*QuantumSignature{&oversized, sigs[1]}); err == nil {
		t.Fatal("an over-long signature was packed, overwriting the next entry's row")
	}

	// So would an over-long public key — which is the half that decides what
	// the next entry is verified against.
	forged := *sigs[0]
	forged.PublicKey = bytes.Repeat([]byte{0xBB}, pkSize+pkSize)
	if _, _, _, _, err := qs.packBatch(msgs, []*QuantumSignature{&forged, sigs[1]}); err == nil {
		t.Fatal("an over-long public key was packed, choosing the key the next entry verifies under")
	}

	// Short is refused too: padding it would verify against a key nobody sent.
	short := *sigs[0]
	short.Signature = sigs[0].Signature[:sigSize-1]
	if _, _, _, _, err := qs.packBatch(msgs, []*QuantumSignature{&short, sigs[1]}); err == nil {
		t.Fatal("a short signature was padded into a row")
	}

	if _, _, _, _, err := qs.packBatch(msgs, []*QuantumSignature{nil, sigs[1]}); err == nil {
		t.Fatal("a nil signature was packed")
	}
}
