// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantum

import (
	"bytes"
	"runtime"
	"testing"
	"time"

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
	return NewQuantumSigner(log.NewNoOpLogger(), AlgorithmMLDSA65, 0, time.Minute, 8)
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
