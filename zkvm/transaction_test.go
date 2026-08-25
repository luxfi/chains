// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"testing"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func shieldTx() *Transaction {
	return &Transaction{
		Type:               TransactionTypeShield,
		Version:            1,
		TransparentInputs:  []*TransparentInput{{TxID: ids.ID{1}, OutputIdx: 0, Amount: 100, Address: []byte("payer")}},
		TransparentOutputs: []*TransparentOutput{{Amount: 90, AssetID: ids.ID{2}, Address: []byte("payee")}},
		Nullifiers:         [][]byte{[]byte("n")},
		Outputs:            []*ShieldedOutput{{Commitment: []byte("c")}},
		Proof:              &ZKProof{ProofType: "groth16", ProofData: []byte("p")},
		Fee:                7,
	}
}

// TestIDCommitsToEverythingTheTransactionMeans. Consensus decides between blocks
// by ID and the mempool keys on it, so any field a transaction can be changed in
// without changing its ID is a field an attacker can change for free. The
// transparent inputs and outputs — who is paid, and how much — were not
// committed to at all.
func TestIDCommitsToEverythingTheTransactionMeans(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*Transaction)
	}{
		{"type", func(tx *Transaction) { tx.Type = TransactionTypeUnshield }},
		{"version", func(tx *Transaction) { tx.Version = 2 }},
		{"fee", func(tx *Transaction) { tx.Fee = 8 }},
		{"expiry", func(tx *Transaction) { tx.Expiry = 1 }},
		{"memo", func(tx *Transaction) { tx.Memo = []byte("m") }},
		{"nullifier", func(tx *Transaction) { tx.Nullifiers = [][]byte{[]byte("m")} }},
		{"commitment", func(tx *Transaction) { tx.Outputs[0].Commitment = []byte("d") }},
		{"encrypted note", func(tx *Transaction) { tx.Outputs[0].EncryptedNote = []byte("e") }},
		{"ephemeral key", func(tx *Transaction) { tx.Outputs[0].EphemeralPubKey = []byte("k") }},
		{"output proof", func(tx *Transaction) { tx.Outputs[0].OutputProof = []byte("r") }},
		{"proof type", func(tx *Transaction) { tx.Proof.ProofType = "plonk" }},
		{"proof bytes", func(tx *Transaction) { tx.Proof.ProofData = []byte("q") }},
		{"public inputs", func(tx *Transaction) { tx.Proof.PublicInputs = [][]byte{[]byte("i")} }},
		{"payer", func(tx *Transaction) { tx.TransparentInputs[0].Address = []byte("other") }},
		{"input amount", func(tx *Transaction) { tx.TransparentInputs[0].Amount = 999 }},
		{"input source", func(tx *Transaction) { tx.TransparentInputs[0].TxID = ids.ID{0xAB} }},
		{"input index", func(tx *Transaction) { tx.TransparentInputs[0].OutputIdx = 1 }},
		{"payee", func(tx *Transaction) { tx.TransparentOutputs[0].Address = []byte("thief") }},
		{"output amount", func(tx *Transaction) { tx.TransparentOutputs[0].Amount = 999 }},
		{"asset", func(tx *Transaction) { tx.TransparentOutputs[0].AssetID = ids.ID{0xCD} }},
		{"dropped input", func(tx *Transaction) { tx.TransparentInputs = nil }},
		{"dropped proof", func(tx *Transaction) { tx.Proof = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			altered := shieldTx()
			tc.alter(altered)
			require.NotEqual(t, shieldTx().ComputeID(), altered.ComputeID(),
				"changing the %s left the transaction ID alone, so it can be changed for free", tc.name)
		})
	}
}

// TestIDCannotBeForgedByMovingAByteBetweenFields. Variable-length fields written
// one after another with no length between them let a byte move from the end of
// one to the start of the next: ["ab","c"] and ["a","bc"] are the same bytes. An
// attacker who can produce two transactions with one ID chooses which one the
// network keeps after the other has been accepted.
func TestIDCannotBeForgedByMovingAByteBetweenFields(t *testing.T) {
	split := shieldTx()
	split.Nullifiers = [][]byte{[]byte("ab"), []byte("c")}

	moved := shieldTx()
	moved.Nullifiers = [][]byte{[]byte("a"), []byte("bc")}

	require.NotEqual(t, split.ComputeID(), moved.ComputeID(),
		"two different nullifier sets hash the same, so their transactions share an ID")

	// The same across a field boundary rather than within one list.
	long := shieldTx()
	long.Outputs = []*ShieldedOutput{{Commitment: []byte("cd"), EncryptedNote: nil}}

	short := shieldTx()
	short.Outputs = []*ShieldedOutput{{Commitment: []byte("c"), EncryptedNote: []byte("d")}}

	require.NotEqual(t, long.ComputeID(), short.ComputeID(),
		"a byte moved from the commitment into the note left the ID unchanged")
}

// The identity has to be stable, or a transaction changes ID by being asked for
// it twice.
func TestIDIsStable(t *testing.T) {
	require.Equal(t, shieldTx().ComputeID(), shieldTx().ComputeID())
}
