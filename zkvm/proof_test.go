// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/log"
)

// satisfying builds a verifying key and a proof that SATISFY the pairing
// equation, so the arithmetic reaches a "verified" verdict rather than only a
// refusal. It is honest about how: with Beta = Gamma = Delta = B = g2, the
// equation
//
//	e(A, B) = e(alpha, beta) · e(LC, gamma) · e(C, delta)
//
// collapses by bilinearity to A = alpha + LC + C, which is solvable because the
// test chooses the key. A real key is chosen by a ceremony and this shape is
// exactly what the ceremony rules out — but the verifier does not know that,
// and this drives the same four pairings a real one does.
func satisfying(t *testing.T, witness []fr.Element) (vk []byte, proof []byte) {
	t.Helper()
	_, _, g1, g2 := bn254.Generators()

	// alpha and C are arbitrary points on the curve; K is one point per public
	// input plus the constant term.
	var alpha, c bn254.G1Affine
	alpha.ScalarMultiplication(&g1, big.NewInt(7))
	c.ScalarMultiplication(&g1, big.NewInt(11))

	k := make([]bn254.G1Affine, len(witness)+1)
	for i := range k {
		k[i].ScalarMultiplication(&g1, big.NewInt(int64(i)+2))
	}

	// LC = K[0] + Σ witness_i·K[i+1], the same sum the verifier computes.
	var lc bn254.G1Affine
	lc.Set(&k[0])
	var scalar big.Int
	for i := range witness {
		var term bn254.G1Affine
		term.ScalarMultiplication(&k[i+1], witness[i].BigInt(&scalar))
		lc.Add(&lc, &term)
	}

	var a bn254.G1Affine
	a.Set(&alpha)
	a.Add(&a, &lc)
	a.Add(&a, &c)

	key := make([]byte, 0, 64+128*3+4+64*len(k))
	key = append(key, alpha.Marshal()...)
	key = append(key, g2.Marshal()...) // Beta
	key = append(key, g2.Marshal()...) // Gamma
	key = append(key, g2.Marshal()...) // Delta
	n := make([]byte, 4)
	binary.BigEndian.PutUint32(n, uint32(len(k)))
	key = append(key, n...)
	for i := range k {
		key = append(key, k[i].Marshal()...)
	}

	frame := make([]byte, 0, 256)
	frame = append(frame, a.Marshal()...)  // Ar
	frame = append(frame, g2.Marshal()...) // Bs
	frame = append(frame, c.Marshal()...)  // Krs

	return key, frame
}

// field turns 32 bytes into the field element the verifier reads them as, so a
// test's public inputs and its witness are the same values.
func field(b []byte) fr.Element {
	var e fr.Element
	e.SetBytes(b)
	return e
}

// A proof that satisfies the equation is accepted, and the second look at it
// comes from the cache — keyed on the transaction's CONTENT, so the answer
// belongs to this transaction and no other.
func TestASatisfyingProofIsAcceptedAndRemembered(t *testing.T) {
	nullifier := make([]byte, 32)
	nullifier[0] = 0xA1
	commitment := make([]byte, 32)
	commitment[0] = 0xC1

	witness := []fr.Element{field(testBind[:]), field(nullifier), field(commitment)}
	key, frame := satisfying(t, witness)

	pv := keyedVerifier(t, map[string][]byte{string(TransactionTypeTransfer): key})
	tx := &Transaction{
		Type:       TransactionTypeTransfer,
		Version:    1,
		Nullifiers: [][]byte{nullifier},
		Outputs:    []*ShieldedOutput{{Commitment: commitment}},
		Proof: &ZKProof{
			ProofType:    "groth16",
			ProofData:    frame,
			PublicInputs: [][]byte{testBind[:], nullifier, commitment},
		},
	}
	tx.ID = tx.ComputeID()

	require.NoError(t, pv.VerifyTransactionProof(tx))

	_, hits, misses := pv.GetStats()
	require.EqualValues(t, 0, hits)
	require.EqualValues(t, 1, misses)

	require.NoError(t, pv.VerifyTransactionProof(tx), "the same transaction, from the cache")
	_, hits, _ = pv.GetStats()
	require.EqualValues(t, 1, hits)

	// A transaction spending DIFFERENT notes with the same proof bytes and the
	// same public inputs is a different transaction, so it does not reach this
	// answer. Before the key was the content, its id was the sender's to copy
	// and this returned nil.
	forged := *tx
	forged.Nullifiers = [][]byte{make([]byte, 32)}
	forged.ID = tx.ID // the sender's claim, and it buys nothing
	require.Error(t, pv.VerifyTransactionProof(&forged))

	// A refusal is remembered too, and reported as a refusal.
	_, hits, _ = pv.GetStats()
	before := hits
	require.ErrorContains(t, pv.VerifyTransactionProof(&forged), "(cached)")
	_, hits, _ = pv.GetStats()
	require.Greater(t, hits, before)
}

func TestProofRefusals(t *testing.T) {
	pv := keyedVerifier(t, map[string][]byte{string(TransactionTypeTransfer): groth16Key(4)})

	require.ErrorContains(t, pv.VerifyTransactionProof(&Transaction{}), "missing proof")

	tx := func(kind string, data []byte) *Transaction {
		return &Transaction{
			Type:  TransactionTypeTransfer,
			Proof: &ZKProof{ProofType: kind, ProofData: data, PublicInputs: [][]byte{testBind[:]}},
		}
	}
	require.ErrorContains(t, pv.VerifyTransactionProof(tx("bulletproofs", nil)), "not yet implemented")

	// PLONK's verification equation was never written. Decoding a proof
	// carefully in order to refuse it is not a verifier, so the refusal is all
	// this path does and all it says.
	require.ErrorIs(t, pv.VerifyTransactionProof(tx("plonk", make([]byte, 736))), errPLONKIncomplete)
	require.ErrorIs(t, pv.VerifyTransactionProof(tx("plonk", nil)), errPLONKIncomplete)
	require.ErrorContains(t, pv.VerifyTransactionProof(tx("nonsense", nil)), "unsupported proof type")
	require.ErrorContains(t, pv.VerifyTransactionProof(tx("groth16", make([]byte, 10))), "invalid proof data length")

	// A chain holding no real key verifies nothing, and says so.
	dummy, err := NewProofVerifier(ZConfig{ProofCacheSize: 4}, testBind, log.NoLog{})
	require.NoError(t, err)
	require.False(t, dummy.VerifyingKeysLoaded())
	require.ErrorContains(t, dummy.VerifyTransactionProof(tx("groth16", make([]byte, 256))),
		"proof verification disabled")

	// A cache too small to hold anything is not a verifier.
	_, err = NewProofVerifier(ZConfig{ProofCacheSize: 0}, testBind, log.NoLog{})
	require.Error(t, err)
}

// The public inputs are what tie a proof to the transaction it is offered for.
// Each is compared by VALUE: a mismatch anywhere is a proof about some other
// spend.
func TestPublicInputsBindTheTransaction(t *testing.T) {
	pv := keyedVerifier(t, map[string][]byte{string(TransactionTypeTransfer): groth16Key(4)})

	nullifier := make([]byte, 32)
	nullifier[0] = 0xA1
	commitment := make([]byte, 32)
	commitment[0] = 0xC1

	tx := func(inputs [][]byte) *Transaction {
		return &Transaction{
			Type:       TransactionTypeTransfer,
			Nullifiers: [][]byte{nullifier},
			Outputs:    []*ShieldedOutput{{Commitment: commitment}},
			Proof:      &ZKProof{ProofType: "groth16", ProofData: groth16Frame(), PublicInputs: inputs},
		}
	}

	for _, tt := range []struct {
		name   string
		inputs [][]byte
		want   string
	}{
		{"none at all", nil, "no public inputs"},
		{"the wrong chain", [][]byte{make([]byte, 32), nullifier, commitment}, "chain binding"},
		{"no room for the nullifier", [][]byte{testBind[:]}, "missing public input for nullifier"},
		{"a different nullifier", [][]byte{testBind[:], commitment, commitment}, "mismatch for nullifier"},
		{"no room for the commitment", [][]byte{testBind[:], nullifier}, "missing public input for output commitment"},
		{"a different commitment", [][]byte{testBind[:], nullifier, nullifier}, "mismatch for output commitment"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorContains(t, pv.VerifyTransactionProof(tx(tt.inputs)), tt.want)
		})
	}
}

// A verifying key that does not decode is not a key, and the failure names
// which part of it did not.
func TestVerifyingKeyMustDecode(t *testing.T) {
	full := groth16Key(2)

	_, err := deserializeVerifyingKey(full[:100])
	require.ErrorContains(t, err, "too short")

	for _, tt := range []struct {
		name, want string
		at         int
	}{
		{name: "Alpha", want: "Alpha", at: 0},
		{name: "Beta", want: "Beta", at: 64},
		{name: "Gamma", want: "Gamma", at: 64 + 128},
		{name: "Delta", want: "Delta", at: 64 + 256},
		{name: "K", want: "K[0]", at: 64 + 384 + 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			broken := append([]byte(nil), full...)
			for i := 0; i < 8; i++ {
				broken[tt.at+i] = 0xFF
			}
			_, err := deserializeVerifyingKey(broken)
			require.ErrorContains(t, err, tt.want)
		})
	}

	// A K count the bytes cannot back.
	short := append([]byte(nil), full...)
	binary.BigEndian.PutUint32(short[64+384:], 1<<20)
	_, err = deserializeVerifyingKey(short)
	require.ErrorContains(t, err, "insufficient data for K points")
}

func TestGroth16ProofMustDecode(t *testing.T) {
	full := groth16Frame()

	_, err := deserializeGroth16Proof(full[:100])
	require.ErrorContains(t, err, "too short")

	for _, tt := range []struct {
		name string
		at   int
	}{
		{name: "Ar", at: 0},
		{name: "Bs", at: 64},
		{name: "Krs", at: 192},
	} {
		t.Run(tt.name, func(t *testing.T) {
			broken := append([]byte(nil), full...)
			for i := 0; i < 8; i++ {
				broken[tt.at+i] = 0xFF
			}
			_, err := deserializeGroth16Proof(broken)
			require.ErrorContains(t, err, tt.name)
		})
	}
}
