// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// blockTx is a transaction with something in every list, so a block built
// around it exercises the packed sub-frames rather than a trivial one.
func blockTx(fee uint64) *Transaction {
	tx := &Transaction{
		Type:               TransactionTypeShield,
		Version:            1,
		Fee:                fee,
		TransparentInputs:  []*TransparentInput{{TxID: ids.ID{1}, OutputIdx: 2, Amount: 100, Address: []byte("payer")}},
		TransparentOutputs: []*TransparentOutput{{Amount: 90, AssetID: ids.ID{2}, Address: []byte("payee")}},
		Nullifiers:         [][]byte{[]byte("n1"), []byte("n2")},
		Outputs:            []*ShieldedOutput{{Commitment: []byte("c"), EncryptedNote: []byte("n"), EphemeralPubKey: []byte("e"), OutputProof: []byte("p")}},
		Proof:              &ZKProof{ProofType: "groth16", ProofData: []byte("pd"), PublicInputs: [][]byte{[]byte("a"), []byte("bb")}},
		Expiry:             1 << 20,
		Memo:               []byte("memo"),
	}
	tx.ID = tx.ComputeID()
	return tx
}

// blockAround hand-assembles a block frame holding one transaction blob, so the
// blob can carry padding an honest encoder never writes.
func blockAround(txBlob []byte) []byte {
	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(txBlob) + 256)
	txOff := writeU32List(bld, []uint32{uint32(len(txBlob))})
	ob := bld.StartObject(blkSize)
	var parent ids.ID
	ob.SetBytesFixed(0, parent[:])
	ob.SetUint64(32, 1)
	ob.SetInt64(40, 1_600_000_000)
	ob.SetList(48, txOff, 1)
	ob.SetBytes(56, txBlob)
	ob.SetBytes(64, []byte("root"))
	ob.SetBytes(72, nil)
	ob.FinishAsRoot()
	return bld.Finish()
}

// TestBlockRefusesPaddedTransaction: the block frame's own trailing-byte check
// cannot see padding inside a transaction blob, because that blob carries its
// own length and the outer size stays honest. Only the inner frame can refuse
// it. If it does not, the block parses and re-encodes to bytes that are not the
// bytes that arrived, so the block a node stores under an ID is not the block
// its peers gossiped under that ID.
func TestBlockRefusesPaddedTransaction(t *testing.T) {
	require := require.New(t)

	tx := blockTx(3)
	txRaw, err := tx.Marshal()
	require.NoError(err)

	// Positive control: the same hand-assembled shape without padding parses,
	// so the refusal below is caused by the padding and nothing else.
	var honest Block
	require.NoError(parseBlockBytes(blockAround(txRaw), &honest))
	require.Equal([]*Transaction{tx}, honest.Txs)

	padded := append(append([]byte(nil), txRaw...), 0xAA, 0xBB, 0xCC, 0xDD)
	var blk Block
	require.ErrorIs(parseBlockBytes(blockAround(padded), &blk), errTrailingBytes)
}

// TestBlockReencodesToTheBytesItParsed is the property the padding attacks: a
// block that parses must produce the bytes it came from, or one block has many
// encodings and consensus names them all the same thing.
func TestBlockReencodesToTheBytesItParsed(t *testing.T) {
	require := require.New(t)

	blk := &Block{
		ParentID_:      ids.ID{0xEE},
		BlockHeight:    7,
		BlockTimestamp: 1_600_000_000,
		Txs:            []*Transaction{blockTx(1), blockTx(2)},
		StateRoot:      []byte("state-root"),
		BlockProof:     &ZKProof{ProofType: "plonk", ProofData: []byte("agg")},
	}
	raw, err := blk.Marshal()
	require.NoError(err)

	var got Block
	require.NoError(parseBlockBytes(raw, &got))
	require.Equal(blk.Txs, got.Txs)
	require.Equal(raw, got.Bytes())

	for _, tail := range [][]byte{{0}, {0xFF}, make([]byte, 64)} {
		var trailing Block
		require.ErrorIs(parseBlockBytes(append(append([]byte(nil), raw...), tail...), &trailing), errTrailingBytes)
	}
}
