// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
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
		Proof: &ZKProof{ProofType: "groth16", ProofData: []byte("pd"), PublicInputs: [][]byte{[]byte("pi1"), []byte("pi2")}},
		Memo:  []byte("memo"),
	}
	b, err := tx.Marshal()
	require.NoError(err)
	got, err := parseTransaction(b)
	require.NoError(err)

	// The id is DERIVED on the way in, not carried. A peer that chooses it
	// chooses the proof-cache key, and the cache answers before anything binds
	// the proof to what the transaction spends.
	require.Equal(tx.ComputeID(), got.ID)
	tx.ID = got.ID
	require.Equal(tx, got)

	// Whatever id the sender puts on the value, the wire carries none, so the
	// bytes and the parsed identity are the same either way.
	tx.ID = ids.ID{0xFF}
	forged, err := tx.Marshal()
	require.NoError(err)
	require.Equal(b, forged, "the id must not reach the wire")

	// Canonical: one transaction has one byte string, so bytes appended to a
	// valid frame are refused rather than ignored. Ignoring them would give a
	// peer unlimited fresh encodings of a transaction the node already holds.
	for _, tail := range [][]byte{{0}, {0xFF}, make([]byte, 32)} {
		_, err := parseTransaction(append(append([]byte(nil), b...), tail...))
		require.ErrorIs(err, errTrailingBytes)
	}
}

// txFrame hand-builds a transaction frame so the nullifier length vector and the
// blob it indexes can be made to disagree — what a hostile peer writes and an
// honest encoder never does.
func txFrame(nullLens []uint32, nullBlob []byte) []byte {
	b := zap.NewBuilder(zap.HeaderSize + txSize + len(nullBlob) + 4*len(nullLens) + 512)
	empty := writeU32List(b, nil)
	nullOff := writeU32List(b, nullLens)

	ob := b.StartObject(txSize)
	ob.SetUint8(0, uint8(TransactionTypeTransfer))
	ob.SetUint8(1, 1)
	ob.SetUint64(2, 1)
	ob.SetUint64(10, 0)
	ob.SetList(18, empty, 0)
	ob.SetBytes(26, nil)
	ob.SetList(34, empty, 0)
	ob.SetBytes(42, nil)
	ob.SetList(50, nullOff, len(nullLens))
	ob.SetBytes(58, nullBlob)
	ob.SetList(66, empty, 0)
	ob.SetBytes(74, nil)
	ob.SetBytes(82, nil)
	ob.SetBytes(90, nil)
	ob.FinishAsRoot()
	return b.Finish()
}

// TestNullifierLengthsMustCoverTheirBlob: the nullifier field is a length vector
// plus a concatenated blob, both peer-written. A length the blob cannot back, or
// a blob byte no length claims, means the transaction the node would act on is
// not the transaction that was sent — a nullifier declared spent would never be
// marked spent. Refuse the frame instead of decoding part of it.
func TestNullifierLengthsMustCoverTheirBlob(t *testing.T) {
	require := require.New(t)

	tx, err := parseTransaction(txFrame([]uint32{4, 4}, []byte("aaaabbbb")))
	require.NoError(err)
	require.Len(tx.Nullifiers, 2)

	for _, tc := range []struct {
		lens []uint32
		blob []byte
	}{
		{[]uint32{4, 4}, []byte("aaaa")},    // second entry absent
		{[]uint32{4, 4}, []byte("aaaabbb")}, // blob one byte short
		{[]uint32{1 << 20}, []byte("aaaa")}, // length beyond any blob
		{[]uint32{4}, nil},                  // declared against nothing
		{[]uint32{4}, []byte("aaaabbbb")},   // blob bytes no length claims
		{nil, []byte("aaaa")},               // blob with no lengths at all
	} {
		_, err := parseTransaction(txFrame(tc.lens, tc.blob))
		require.ErrorIs(err, errLength)
	}
}

// TestDeclaredLengthNeverSizesAnAllocation: whatever the decoder does with a
// dishonest length vector, it must not turn a peer's number into memory.
func TestDeclaredLengthNeverSizesAnAllocation(t *testing.T) {
	_, err := parseTransaction(txFrame([]uint32{0xFFFFFFFF, 0xFFFFFFFF}, []byte("aaaa")))
	require.ErrorIs(t, err, errLength)
}

func TestWireRoundTrip_Block(t *testing.T) {
	require := require.New(t)
	tx := &Transaction{Type: TransactionTypeTransfer, Fee: 1, Nullifiers: [][]byte{[]byte("x")}}
	tx.ID = tx.ComputeID()
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
	require.Equal(tx.ComputeID(), got.Txs[0].ID, "a nested transaction's id is derived from its content too")
	require.Equal(blk.BlockProof, got.BlockProof)
}
