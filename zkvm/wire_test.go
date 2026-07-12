// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

func TestWireRoundTrip_UTXO(t *testing.T) {
	require := require.New(t)
	u := &UTXO{
		TxID:        ids.ID{1, 2, 3},
		OutputIndex: 7,
		Height:      42,
		Commitment:  []byte("commit"),
		Ciphertext:  []byte("cipher"),
		EphemeralPK: []byte("epk"),
	}
	b, err := u.Marshal()
	require.NoError(err)
	var got UTXO
	require.NoError(parseUTXO(b, &got))
	require.Equal(*u, got)
	// canonical: trailing byte rejected
	require.Error(parseUTXO(append(b, 0), &got))
}

func TestWireRoundTrip_Transaction(t *testing.T) {
	require := require.New(t)
	tx := &Transaction{
		ID:      ids.ID{9},
		Type:    TransactionTypeShield,
		Version: 1,
		Fee:     100,
		Expiry:  999,
		TransparentInputs: []*TransparentInput{
			{TxID: ids.ID{4}, OutputIdx: 2, Amount: 50, Address: []byte("addr-in")},
		},
		TransparentOutputs: []*TransparentOutput{
			{Amount: 30, AssetID: ids.ID{5}, Address: []byte("addr-out")},
		},
		Nullifiers: [][]byte{[]byte("null1"), []byte("null2")},
		Outputs: []*ShieldedOutput{
			{Commitment: []byte("c"), EncryptedNote: []byte("n"), EphemeralPubKey: []byte("e"), OutputProof: []byte("p")},
		},
		Proof:     &ZKProof{ProofType: "groth16", ProofData: []byte("pd"), PublicInputs: [][]byte{[]byte("pi1"), []byte("pi2")}},
		FHEData:   &FHEData{EncryptedInputs: [][]byte{[]byte("ei")}, CircuitID: "circ", EncryptedResult: []byte("er"), ComputationProof: []byte("cp")},
		Memo:      []byte("memo"),
		Signature: []byte("sig"),
	}
	b, err := tx.Marshal()
	require.NoError(err)
	got, err := parseTransaction(b)
	require.NoError(err)
	require.Equal(tx, got)
}

func TestWireRoundTrip_Block(t *testing.T) {
	require := require.New(t)
	tx := &Transaction{ID: ids.ID{7}, Type: TransactionTypeTransfer, Fee: 1, Nullifiers: [][]byte{[]byte("x")}}
	blk := &Block{
		ParentID_:      ids.ID{2},
		BlockHeight:    5,
		BlockTimestamp: 1_700_000_000,
		Txs:            []*Transaction{tx},
		StateRoot:      []byte("root"),
		BlockProof:     &ZKProof{ProofType: "plonk", ProofData: []byte("bp")},
	}
	b, err := blk.Marshal()
	require.NoError(err)
	var got Block
	require.NoError(parseBlockBytes(b, &got))
	require.Equal(blk.ParentID_, got.ParentID_)
	require.Equal(blk.BlockHeight, got.BlockHeight)
	require.Equal(blk.BlockTimestamp, got.BlockTimestamp)
	require.Equal(blk.StateRoot, got.StateRoot)
	require.Len(got.Txs, 1)
	require.Equal(tx.ID, got.Txs[0].ID)
	require.Equal(blk.BlockProof, got.BlockProof)
}
