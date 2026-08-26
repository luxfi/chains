// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"encoding/binary"
	"errors"
	"math/big"
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

// plonkKey is G1 | G2 | [alpha]_2 | 5 selectors | 3 permutations, all
// generators, padded to the 1024 bytes the decoder requires.
func plonkKey() []byte {
	_, _, g1, g2 := bn254.Generators()
	out := make([]byte, 0, 1024)
	out = append(out, g1.Marshal()...)
	out = append(out, g2.Marshal()...)
	out = append(out, g2.Marshal()...)
	for i := 0; i < 8; i++ {
		out = append(out, g1.Marshal()...)
	}
	return append(out, make([]byte, 1024-len(out))...)
}

// plonkFrame is 9 G1 generators followed by 5 zero evaluations: 736 bytes.
func plonkFrame() []byte {
	_, _, g1, _ := bn254.Generators()
	out := make([]byte, 0, 736)
	for i := 0; i < 9; i++ {
		out = append(out, g1.Marshal()...)
	}
	return append(out, make([]byte, 160)...)
}

func keyedVerifier(t *testing.T, system string, keys map[string][]byte) *ProofVerifier {
	t.Helper()
	pv, err := NewProofVerifier(ZConfig{
		ProofSystem:    system,
		ProofCacheSize: 16,
		VerifyingKeys:  keys,
	}, log.NoLog{})
	if err != nil {
		t.Fatalf("NewProofVerifier: %v", err)
	}
	return pv
}

// TestMSMAgreesWithRepeatedAddition. The multi-scalar multiplication carries
// the public-input linear combination, so everything a classical proof is
// judged on rests on it equalling the sum it stands for.
func TestMSMAgreesWithRepeatedAddition(t *testing.T) {
	_, _, g1, _ := bn254.Generators()

	scalars := make([]fr.Element, 4)
	bases := make([]bn254.G1Affine, 4)
	for i := range scalars {
		scalars[i].SetUint64(uint64(i + 3))
		bases[i].Set(&g1)
	}

	var want bn254.G1Affine
	for i := range scalars {
		var term bn254.G1Affine
		term.ScalarMultiplication(&bases[i], scalars[i].BigInt(new(big.Int)))
		want.Add(&want, &term)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("computing an MSM must not panic: %v", r)
		}
	}()

	if got := msmCPU(scalars, bases); !got.Equal(&want) {
		t.Fatalf("msmCPU = %v, want %v", got, want)
	}

	got, err := msmGPU(scalars, bases, log.NoLog{})
	if err != nil {
		t.Fatalf("msmGPU: %v", err)
	}
	if !got.Equal(&want) {
		t.Fatalf("msmGPU = %v, want %v — the accelerated path disagrees with the plain one", got, want)
	}
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
	// Three K points is a circuit taking two public inputs, which is what this
	// transaction supplies. A key that spoke about a different number would be
	// refused before the pairing, and this test is about the pairing.
	pv := keyedVerifier(t, "groth16", map[string][]byte{
		string(TransactionTypeTransfer): groth16Key(3),
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
			PublicInputs: [][]byte{nullifier, commitment},
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

// TestPLONKReachesItsPairing is the same property for the other classical
// system a non-strict chain may be configured with.
func TestPLONKIsRefusedForTheStatedReason(t *testing.T) {
	pv := keyedVerifier(t, "plonk", map[string][]byte{
		string(TransactionTypeTransfer): plonkKey(),
	})

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
			ProofType:    "plonk",
			ProofData:    plonkFrame(),
			PublicInputs: [][]byte{nullifier, commitment},
		},
	}
	tx.ID = tx.ComputeID()

	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("verifying a well-formed PLONK proof must not panic: %v", r)
			}
		}()
		err = pv.VerifyTransactionProof(tx)
	}()

	// The verification equation is not implemented, so every PLONK proof is
	// refused rather than bound to nothing. Pin the refusal to that reason: a
	// decode failure, a panic, or any other error would also be non-nil, and
	// none of them would mean what this test is named for.
	if !errors.Is(err, errPLONKIncomplete) {
		t.Fatalf("a PLONK proof must be refused because the equation is not implemented, got: %v", err)
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

	if _, err := deserializePLONKProof(make([]byte, 736)); err == nil {
		t.Fatal("a PLONK proof of infinity points must not decode")
	}

	if _, err := deserializePLONKVerifyingKey(make([]byte, 1024)); err == nil {
		t.Fatal("a PLONK key of infinity points must not decode")
	}
}

// TestCircuitWithoutAKeyIsRefused. A chain is keyed per circuit; the circuits
// the operator did not key get an all-zero placeholder. Those zeros decode to
// infinity, and a PLONK key of infinity points makes both sides of the pairing
// empty — every proof valid, value minted from nothing. A circuit with no key
// must be refused instead.
func TestCircuitWithoutAKeyIsRefused(t *testing.T) {
	pv := keyedVerifier(t, "plonk", map[string][]byte{
		string(TransactionTypeTransfer): plonkKey(), // shield and unshield keyed with zeros
	})

	commitment := make([]byte, 32)
	commitment[0] = 0xC1

	tx := &Transaction{
		Type:    TransactionTypeShield,
		Version: 1,
		Outputs: []*ShieldedOutput{{Commitment: commitment}},
		Proof: &ZKProof{
			ProofType:    "plonk",
			ProofData:    plonkFrame(),
			PublicInputs: [][]byte{commitment},
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
	pv := keyedVerifier(t, "groth16", map[string][]byte{
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

// TestPLONKProofMustBeWholeAndNoMore pins the proof's size exactly. Every
// evaluation is part of the proof, so a frame short of one is not a proof; and
// bytes the format does not describe are bytes two proofs can differ in while
// decoding alike.
func TestPLONKProofMustBeWholeAndNoMore(t *testing.T) {
	whole := plonkFrame()
	if len(whole) != plonkProofSize {
		t.Fatalf("the test frame is %d bytes, want %d", len(whole), plonkProofSize)
	}
	if _, err := deserializePLONKProof(whole); err != nil {
		t.Fatalf("a whole proof was refused: %v", err)
	}

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"missing every evaluation", whole[:9*64]},
		{"missing the last evaluation", whole[:plonkProofSize-32]},
		{"one byte short", whole[:plonkProofSize-1]},
		{"one byte over", append(append([]byte(nil), whole...), 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := deserializePLONKProof(tc.data); err == nil {
				t.Fatalf("%d bytes decoded as a whole proof", len(tc.data))
			}
		})
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
