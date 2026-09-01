// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/luxfi/log"
)

// Groth16 and PLONK verification are the only things standing between a peer's
// bytes and shielded value. What follows pins the three ways that guard has
// been walked past: arithmetic that dies on a nil scalar, a public-input count
// the key cannot cover, and a curve point at infinity that deletes its own
// term from the pairing.

// groth16Key serializes a Groth16 verifying key of numK generator points:
// Alpha(G1) | Beta(G2) | Gamma(G2) | Delta(G2) | numK(4) | K[numK](G1).
func groth16Key(numK uint32) []byte {
	_, _, g1, g2 := bn254.Generators()
	out := make([]byte, 0, 452+int(numK)*64)
	out = append(out, g1.Marshal()...)
	out = append(out, g2.Marshal()...)
	out = append(out, g2.Marshal()...)
	out = append(out, g2.Marshal()...)
	n := make([]byte, 4)
	binary.BigEndian.PutUint32(n, numK)
	out = append(out, n...)
	for i := uint32(0); i < numK; i++ {
		out = append(out, g1.Marshal()...)
	}
	return out
}

// groth16Frame is Ar‖Bs‖Krs of curve generators: 256 bytes that decode and
// pass every point check, so verification reaches the pairing.
func groth16Frame() []byte {
	_, _, g1, g2 := bn254.Generators()
	out := make([]byte, 0, 256)
	out = append(out, g1.Marshal()...)
	out = append(out, g2.Marshal()...)
	out = append(out, g1.Marshal()...)
	return out
}

func keyedVerifier(t *testing.T, keys map[string][]byte) *ProofVerifier {
	t.Helper()
	pv, err := NewProofVerifier(ZConfig{
		ProofCacheSize: 16,
		VerifyingKeys:  keys,
	}, testBind, log.NoLog{})
	if err != nil {
		t.Fatalf("NewProofVerifier: %v", err)
	}
	return pv
}

// TestWitnessMustFitTheVerifyingKey. A peer chooses how many public inputs its
// transaction carries; the key fixes how many the circuit has. K holds one
// point per input plus the constant term, so a witness of len(K) inputs reads
// K[len(K)] — one past the end. That must be an error, never a panic.
func TestWitnessMustFitTheVerifyingKey(t *testing.T) {
	_, _, g1, _ := bn254.Generators()

	key := func(n int) *Groth16VerifyingKey {
		vk := &Groth16VerifyingKey{K: make([]bn254.G1Affine, n)}
		for i := range vk.K {
			vk.K[i].Set(&g1)
		}
		return vk
	}

	for _, n := range []int{0, 1, 2, 4} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("a peer-chosen public-input count must be an error, not a panic: %v", r)
				}
			}()
			if err := verifyGroth16Pairing(&Groth16Proof{}, key(n), make([]fr.Element, n)); err == nil {
				t.Fatalf("%d public inputs against %d K points must be refused", n, n)
			}
		}()
	}

	// A witness the key does cover reaches the pairing and is judged there.
	// Without this the refusals above could be a verifier that refuses
	// everything.
	proof, err := deserializeGroth16Proof(groth16Frame())
	if err != nil {
		t.Fatalf("deserializeGroth16Proof: %v", err)
	}
	vk, err := deserializeVerifyingKey(groth16Key(3))
	if err != nil {
		t.Fatalf("deserializeVerifyingKey: %v", err)
	}
	err = verifyGroth16Pairing(proof, vk, make([]fr.Element, 2))
	if err == nil || !strings.Contains(err.Error(), "pairing check failed") {
		t.Fatalf("a covered witness must be judged by the pairing, got: %v", err)
	}
}

// TestGroth16ReachesItsPairing. A non-strict chain holding real keys is a
// supported deployment and its whole point is that a groth16 proof is accepted
// or rejected on the arithmetic. Any proof that decodes must produce a verdict.
func TestGroth16ReachesItsPairing(t *testing.T) {
	// Four K points is a circuit taking three public inputs — the chain
	// binding, one nullifier and one commitment — which is what this
	// transaction supplies. A key that spoke about a different number would be
	// refused before the pairing, and this test is about the pairing.
	pv := keyedVerifier(t, map[string][]byte{
		string(TransactionTypeTransfer): groth16Key(4),
	})
	if !pv.VerifyingKeysLoaded() {
		t.Fatal("precondition: the chain holds a real verifying key")
	}

	nullifier := make([]byte, 32)
	nullifier[0] = 0xA1
	commitment := make([]byte, 32)
	commitment[0] = 0xC1

	tx := &Transaction{
		Type:       TransactionTypeTransfer,
		Version:    1,
		Nullifiers: [][]byte{nullifier},
		Outputs:    []*ShieldedOutput{{Commitment: commitment}},
		Proof: &ZKProof{
			ProofType:    "groth16",
			ProofData:    groth16Frame(),
			PublicInputs: [][]byte{testBind[:], nullifier, commitment},
		},
	}
	tx.ID = tx.ComputeID()

	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("verifying a well-formed groth16 proof must not panic: %v", r)
			}
		}()
		err = pv.VerifyTransactionProof(tx)
	}()

	// The proof satisfies no statement, so the verdict is "rejected" — but a
	// verdict from the arithmetic is what has to come back, not a refusal from
	// the checks in front of it.
	if err == nil || !strings.Contains(err.Error(), "pairing check failed") {
		t.Fatalf("expected a pairing verdict, got: %v", err)
	}
}

// TestInfinityIsNotAUsablePoint. gnark decodes all-zero bytes to the point at
// infinity and reports it in-subgroup, and a pairing skips every term whose
// argument is infinity. A proof or key element at infinity therefore deletes
// itself from the equation, so no decoder may hand one on.
func TestInfinityIsNotAUsablePoint(t *testing.T) {
	if _, err := deserializeGroth16Proof(make([]byte, 256)); err == nil {
		t.Fatal("a Groth16 proof of infinity points must not decode")
	}

	zeroKey, err := deserializeVerifyingKey(make([]byte, 1024))
	if err == nil {
		if err := validateVerifyingKey(zeroKey); err == nil {
			t.Fatal("a Groth16 key of infinity points must not validate")
		}
	}

}

// TestCircuitWithoutAKeyIsRefused. A chain is keyed per circuit; the circuits
// the operator did not key have no key at all. A proof judged against a key
// that is not there must be refused, not accepted on the zeros standing in for
// one — zeros decode to points at infinity, and a pairing drops any term whose
// argument is infinity, which empties both sides and makes every proof valid.
func TestCircuitWithoutAKeyIsRefused(t *testing.T) {
	pv := keyedVerifier(t, map[string][]byte{
		string(TransactionTypeTransfer): groth16Key(2), // shield and unshield unkeyed
	})

	commitment := make([]byte, 32)
	commitment[0] = 0xC1

	tx := &Transaction{
		Type:    TransactionTypeShield,
		Version: 1,
		Outputs: []*ShieldedOutput{{Commitment: commitment}},
		Proof: &ZKProof{
			ProofType:    "groth16",
			ProofData:    groth16Frame(),
			PublicInputs: [][]byte{testBind[:], commitment},
		},
	}
	tx.ID = tx.ComputeID()

	if err := pv.VerifyTransactionProof(tx); err == nil {
		t.Fatal("a shield proof judged against an unkeyed circuit must be refused, not accepted")
	}
}

// TestKeyingOneCircuitDoesNotEnableTheOthers pins that each circuit is judged on
// its own key. Keying one circuit says nothing about any other, and a circuit
// the operator did not key is refused by name rather than judged against
// whatever stands in for a key.
func TestKeyingOneCircuitDoesNotEnableTheOthers(t *testing.T) {
	pv := keyedVerifier(t, map[string][]byte{
		string(TransactionTypeTransfer): groth16Key(4),
	})

	if _, keyed := pv.verifyingKeys[string(TransactionTypeShield)]; keyed {
		t.Fatal("a circuit the operator did not key was given one anyway")
	}
	if !pv.VerifyingKeysLoaded() {
		t.Fatal("a verifier holding a real key reports none loaded")
	}

	commitment := make([]byte, 32)
	commitment[0] = 0xC1
	tx := &Transaction{
		Type:    TransactionTypeShield,
		Version: 1,
		Outputs: []*ShieldedOutput{{Commitment: commitment}},
		Proof: &ZKProof{
			ProofType:    "groth16",
			ProofData:    groth16Frame(),
			PublicInputs: [][]byte{commitment},
		},
	}
	tx.ID = tx.ComputeID()

	err := pv.VerifyTransactionProof(tx)
	if err == nil {
		t.Fatal("a shield proof was judged against a circuit nobody keyed, and accepted")
	}
	if !strings.Contains(err.Error(), "no verifying key for circuit") {
		t.Fatalf("the refusal does not name the unkeyed circuit: %v", err)
	}
}

// TestWitnessMustMatchWhatTheKeysCircuitTakes. A verifying key holds one K point
// per public input plus a constant term, so it states exactly how many inputs
// the circuit it was made for takes, and a peer picks the length it sends.
// Either side of that count judges the proof against a statement the key does
// not describe.
func TestWitnessMustMatchWhatTheKeysCircuitTakes(t *testing.T) {
	// Four K points is a circuit taking three public inputs.
	vk, err := deserializeVerifyingKey(groth16Key(4))
	if err != nil {
		t.Fatalf("deserialize key: %v", err)
	}
	proof, err := deserializeGroth16Proof(groth16Frame())
	if err != nil {
		t.Fatalf("deserialize proof: %v", err)
	}

	witness := func(n int) []fr.Element {
		out := make([]fr.Element, n)
		for i := range out {
			out[i].SetUint64(uint64(i + 1))
		}
		return out
	}

	for _, n := range []int{0, 1, 2, 4, 9} {
		err := verifyGroth16Pairing(proof, vk, witness(n))
		if err == nil {
			t.Fatalf("%d public inputs judged against a circuit taking 3", n)
		}
		if !strings.Contains(err.Error(), "public inputs") {
			t.Fatalf("%d inputs: refused for the wrong reason: %v", n, err)
		}
	}

	// The count the key states reaches the arithmetic, which is the control:
	// without it the refusals above would prove only that this rejects
	// everything.
	err = verifyGroth16Pairing(proof, vk, witness(3))
	if err == nil || !strings.Contains(err.Error(), "pairing check failed") {
		t.Fatalf("the count the key states must reach the pairing, got: %v", err)
	}
}

// testBind is the chain binding every test verifier is built with. It is not
// the zero value, so "the chain this proof was made for" is distinguishable
// from "no chain at all" — a zero bind would make every wrong-chain case look
// right. Every proof's public inputs lead with it.
var testBind = [32]byte{
	0x5A, 0xC1, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x11,
	0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02,
	0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
}
