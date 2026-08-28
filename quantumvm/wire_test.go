// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
	"github.com/stretchr/testify/require"
)

func sampleBlock() *Block {
	blk := &Block{
		timestamp: time.Unix(1_700_000_500, 0),
		height:    9,
		parentID:  ids.GenerateTestID(),
		chainID:   testChain,
		networkID: testNetwork,
		transactions: []Transaction{
			stampedTx(1, "op-a"),
			stampedTx(2, "op-bb"),
		},
	}
	blk.id = blk.computeID()
	return blk
}

// TestBlockWireRoundTrip: everything the block committed to comes back, the
// transaction set above all. Leaving it out was what made a received block hold
// zero transactions — and a signature check over zero transactions checks
// nothing.
func TestBlockWireRoundTrip(t *testing.T) {
	require := require.New(t)

	blk := sampleBlock()
	wire := blk.Bytes()
	require.NotEmpty(wire)

	got, err := parseBlockBytes(nil, wire)
	require.NoError(err)
	require.Equal(blk.id, got.id)
	require.Equal(blk.timestamp.Unix(), got.timestamp.Unix())
	require.Equal(blk.height, got.height)
	require.Equal(blk.parentID, got.parentID)
	require.Equal(blk.chainID, got.chainID)
	require.Equal(blk.networkID, got.networkID)

	require.Len(got.transactions, len(blk.transactions), "the parser dropped the transaction set")
	for i, want := range blk.transactions {
		require.Equal(want.ID(), got.transactions[i].ID(), "transaction %d changed identity", i)
		require.Equal(want.Bytes(), got.transactions[i].Bytes(), "transaction %d changed its signed bytes", i)
		require.Equal(want.GetQuantumSignature().Signature,
			got.transactions[i].GetQuantumSignature().Signature,
			"transaction %d lost its signature", i)
	}

	// re-serialization of a parsed block is byte-identical, which is what makes
	// the id a function of the block rather than of its encoder.
	require.Equal(wire, got.Bytes())
}

// TestBlockIDIsContentHash: the block id is the content hash sha256(Bytes())
// and is NOT stored in the wire — so it is never ids.Empty (the prior
// ids.ToID(parent‖height) over 40 bytes silently yielded Empty for every block,
// collapsing the block store to one slot).
func TestBlockIDIsContentHash(t *testing.T) {
	require := require.New(t)

	blk := sampleBlock()
	require.NotEqual(ids.Empty, blk.id, "block id must never be ids.Empty")
	require.Equal(ids.ID(sha256.Sum256(blk.Bytes())), blk.id, "id == sha256(Bytes())")

	// A round-tripped block recovers the same content id from the bytes alone.
	got, err := parseBlockBytes(nil, blk.Bytes())
	require.NoError(err)
	require.Equal(blk.id, got.id)

	// Distinct content ⇒ distinct ids: every field moves the id.
	vary := func(f func(*Block)) *Block {
		c := &Block{timestamp: blk.timestamp, height: blk.height, parentID: blk.parentID,
			chainID: blk.chainID, networkID: blk.networkID, transactions: blk.transactions}
		f(c)
		return c
	}
	variants := []*Block{
		vary(func(c *Block) { c.height++ }),
		vary(func(c *Block) { c.parentID = ids.GenerateTestID() }),
		vary(func(c *Block) { c.chainID = otherChain }),
		vary(func(c *Block) { c.networkID++ }),
		vary(func(c *Block) { c.timestamp = blk.timestamp.Add(time.Second) }),
		vary(func(c *Block) { c.transactions = []Transaction{stampedTx(99, "different")} }),
	}
	seen := map[ids.ID]string{blk.id: "base"}
	for _, c := range variants {
		id := c.computeID()
		require.NotEqual(ids.Empty, id)
		require.NotContains(seen, id, "distinct block content produced a colliding id")
		seen[id] = "variant"
	}
}

// TestOneBlockHasOneEncoding.
//
// A zap message declares its own SIZE and its own ROOT OFFSET, and both are the
// sender's to choose — so the container has degrees of freedom the content does
// not. Rejecting bytes past the DECLARED size rejected nothing: append a byte,
// bump the size field, and one logical block has a second id. Two hundred and
// fifty-six of them, from one byte of padding. Relocating the root struct is the
// same trick on the other field.
//
// Parse re-serializes what it decoded and compares. That covers every degree of
// freedom the container has, rather than the ones anyone thought to enumerate.
func TestOneBlockHasOneEncoding(t *testing.T) {
	blk := sampleBlock()
	wire := blk.Bytes()

	// One byte of padding, with the declared size moved to cover it.
	for pad := 0; pad < 256; pad++ {
		padded := append(append([]byte(nil), wire...), byte(pad))
		binary.LittleEndian.PutUint32(padded[12:16], uint32(len(padded)))

		msg, err := zap.Parse(padded)
		require.NoError(t, err, "precondition: padding 0x%02x still parses as zap", pad)
		require.Equal(t, len(padded), msg.Size(), "precondition: the declared size covers the padding")
		require.NotEqual(t, blk.id, ids.ID(sha256.Sum256(padded)),
			"precondition: padding changes the content hash")

		_, err = parseBlockBytes(nil, padded)
		require.ErrorIs(t, err, errNonCanonical, "padding 0x%02x produced a second id for one block", pad)
	}

	// The root struct, relocated. Every pointer in the object is relative to its
	// own field, so shifting the whole body leaves the content identical and the
	// bytes different.
	shifted := make([]byte, 0, len(wire)+8)
	shifted = append(shifted, wire[:zap.HeaderSize]...)
	shifted = append(shifted, make([]byte, 8)...)
	shifted = append(shifted, wire[zap.HeaderSize:]...)
	binary.LittleEndian.PutUint32(shifted[8:12], binary.LittleEndian.Uint32(wire[8:12])+8)
	binary.LittleEndian.PutUint32(shifted[12:16], uint32(len(shifted)))

	relocated, err := parseBlockBytes(nil, shifted)
	if err == nil {
		t.Fatalf("a relocated root parsed as the same block under a different id: %s vs %s",
			relocated.id, blk.id)
	}
	require.ErrorIs(t, err, errNonCanonical)

	// A root offset pointing into the wire header, where the fields are read out
	// of the magic and the size.
	intoHeader := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint32(intoHeader[8:12], 0)
	_, err = parseBlockBytes(nil, intoHeader)
	require.Error(t, err, "the block's fields were read out of the zap header")
}

// TestBlockWireRejectsTrailing bytes past the declared size.
func TestBlockWireRejectsTrailing(t *testing.T) {
	wire := sampleBlock().Bytes()
	_, err := parseBlockBytes(nil, append(append([]byte(nil), wire...), 0x00))
	require.Error(t, err, "trailing bytes must be rejected")
}

// TestTheTransactionListMustPartitionTheBlob. The lengths say where each
// transaction ends; bytes no length names are bytes the block commits to and
// nothing reads, and a count larger than the blob can hold is an allocation a
// peer chose.
func TestTheTransactionListMustPartitionTheBlob(t *testing.T) {
	blk := sampleBlock()
	wire := blk.Bytes()

	msg, err := zap.Parse(wire)
	require.NoError(t, err)
	root := msg.Root()
	lens := root.List(blkTxLens)
	require.Equal(t, 2, lens.Len(), "precondition: two transactions on the wire")

	// The list lives at a known offset; rewrite the first entry's length.
	first := int(lens.Uint32(0))
	lensAt := findU32(t, wire, uint32(first))

	for _, bad := range []uint32{0, 1, uint32(first - 1), uint32(first + 1), 1 << 30} {
		tampered := append([]byte(nil), wire...)
		binary.LittleEndian.PutUint32(tampered[lensAt:], bad)
		_, err := parseBlockBytes(nil, tampered)
		require.Error(t, err, "a transaction length of %d partitioned the blob", bad)
	}

	// And an absurd count is refused before it is allocated for.
	countAt := root.Offset() + blkTxLens + 4
	tampered := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint32(tampered[countAt:], uint32(len(wire)))
	_, err = parseBlockBytes(nil, tampered)
	require.ErrorIs(t, err, errTxCountAbsurd)
}

// findU32 locates the first little-endian occurrence of v in b.
func findU32(t *testing.T, b []byte, v uint32) int {
	t.Helper()
	var want [4]byte
	binary.LittleEndian.PutUint32(want[:], v)
	for i := 0; i+4 <= len(b); i += 4 {
		if [4]byte(b[i:i+4]) == want {
			return i
		}
	}
	t.Fatalf("could not locate %d in the wire", v)
	return 0
}

func TestBaseTransactionWireDeterministic(t *testing.T) {
	require := require.New(t)

	mk := func() *BaseTransaction {
		return &BaseTransaction{timestamp: time.Unix(1_700_000_000, 0), nonce: 42, data: []byte("payload")}
	}
	a := mk().Bytes()
	b := mk().Bytes()
	require.Equal(a, b, "tx wire is deterministic (stable id + signature preimage)")
	require.NotEmpty(a)

	// The signature is NOT part of the signed bytes.
	signed := mk()
	signed.quantumSignature = stampedTx(42, "payload").quantumSignature
	require.Equal(a, signed.Bytes(), "quantum signature is excluded from the signature preimage")
}

// TestTheEnvelopeCarriesTheSignatureAndTheBodyCarriesNone. Two wires because a
// transaction is two things: what was signed, and what was signed plus the
// signature. Folding them into one would put the signature inside its own
// preimage.
func TestTheEnvelopeCarriesTheSignatureAndTheBodyCarriesNone(t *testing.T) {
	tx := stampedTx(7, "payload")
	env := marshalTx(tx)

	got, err := unmarshalTx(env)
	require.NoError(t, err)
	require.Equal(t, tx.Bytes(), got.Bytes(), "the signature preimage changed in flight")
	require.Equal(t, tx.ID(), got.ID())
	require.Equal(t, tx.quantumSignature.Signature, got.quantumSignature.Signature)
	require.Equal(t, tx.quantumSignature.QuantumStamp, got.quantumSignature.QuantumStamp)
	require.Equal(t, tx.quantumSignature.Timestamp.UnixNano(), got.quantumSignature.Timestamp.UnixNano())
	require.Equal(t, got.quantumSignature.PublicKey, got.quantumSignature.CoronaKey)
	require.Equal(t, env, marshalTx(got), "the envelope is not canonical")

	// A transaction with no signature still rides, and comes back with none.
	bare := &BaseTransaction{timestamp: chainTime, nonce: 3, data: []byte("bare")}
	back, err := unmarshalTx(marshalTx(bare))
	require.NoError(t, err)
	require.Equal(t, bare.Bytes(), back.Bytes())
	require.Empty(t, back.quantumSignature.Signature)

	// Bytes that are not an envelope are refused rather than decoded to zeros.
	for _, bad := range [][]byte{nil, {}, []byte("garbage"), env[:len(env)-1], append(append([]byte(nil), env...), 0)} {
		_, err := unmarshalTx(bad)
		require.Error(t, err, "a %d-byte non-envelope decoded", len(bad))
	}
}

// TestBaseTransactionIDNonEmpty is the regression guard for the tx pool: the
// tx id is sha256(Bytes()) and never ids.Empty, so distinct txs occupy distinct
// pool slots (the prior ids.ToID over the always-≥32-byte wire yielded Empty for
// every tx, collapsing the pool to a single entry).
func TestBaseTransactionIDNonEmpty(t *testing.T) {
	require := require.New(t)

	tx := &BaseTransaction{timestamp: time.Unix(1_700_000_000, 0), nonce: 42, data: []byte("payload")}
	id := tx.ID()
	require.NotEqual(ids.Empty, id, "tx id must never be ids.Empty")
	require.Equal(ids.ID(sha256.Sum256(tx.Bytes())), id, "id == sha256(Bytes())")

	other := &BaseTransaction{timestamp: time.Unix(1_700_000_000, 0), nonce: 43, data: []byte("payload")}
	require.NotEqual(id, other.ID(), "distinct txs must have distinct ids")
}
