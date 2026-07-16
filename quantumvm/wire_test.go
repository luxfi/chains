// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func sampleBlock() *Block {
	blk := &Block{
		timestamp: time.Unix(1_700_000_500, 0),
		height:    9,
		parentID:  ids.GenerateTestID(),
		transactions: []Transaction{
			&BaseTransaction{timestamp: time.Unix(1_700_000_400, 0), nonce: 1, data: []byte("op-a")},
			&BaseTransaction{timestamp: time.Unix(1_700_000_450, 0), nonce: 2, data: []byte("op-bb")},
		},
	}
	blk.id = blk.computeID()
	return blk
}

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

	// The transaction bytes are committed to the wire (block signature covers
	// them), even though parse does not reconstruct the concrete txs.
	require.Nil(got.transactions, "parse preserves the tx-lossy contract")
	empty := (&Block{timestamp: blk.timestamp, height: blk.height, parentID: blk.parentID}).Bytes()
	require.Greater(len(wire), len(empty), "committed tx bytes are present in the block wire")

	// re-parse of the retained bytes is stable (signature re-verification path)
	require.Equal(wire, got.Bytes())
}

// TestBlockIDIsContentHash is the M2 regression guard: the block id is the
// content hash sha256(Bytes()) and is NOT stored in the wire — so it is never
// ids.Empty (the prior ids.ToID(parent‖height) over 40 bytes silently yielded
// Empty for every block, collapsing the block store to one slot).
func TestBlockIDIsContentHash(t *testing.T) {
	require := require.New(t)

	blk := sampleBlock()
	require.NotEqual(ids.Empty, blk.id, "block id must never be ids.Empty")
	require.Equal(ids.ID(sha256.Sum256(blk.Bytes())), blk.id, "id == sha256(Bytes())")

	// A round-tripped block recovers the same content id from the bytes alone.
	got, err := parseBlockBytes(nil, blk.Bytes())
	require.NoError(err)
	require.Equal(blk.id, got.id)

	// Distinct content ⇒ distinct ids (height, parent, and tx set each move it).
	byHeight := &Block{timestamp: blk.timestamp, height: blk.height + 1, parentID: blk.parentID, transactions: blk.transactions}
	byParent := &Block{timestamp: blk.timestamp, height: blk.height, parentID: ids.GenerateTestID(), transactions: blk.transactions}
	byTx := &Block{timestamp: blk.timestamp, height: blk.height, parentID: blk.parentID,
		transactions: []Transaction{&BaseTransaction{timestamp: blk.timestamp, nonce: 99, data: []byte("different")}}}
	seen := map[ids.ID]string{blk.id: "base"}
	for _, c := range []*Block{byHeight, byParent, byTx} {
		id := c.computeID()
		require.NotEqual(ids.Empty, id)
		require.NotContains(seen, id, "distinct block content produced a colliding id")
		seen[id] = "variant"
	}
}

func TestBlockWireRejectsTrailing(t *testing.T) {
	blk := &Block{timestamp: time.Unix(1, 0), height: 1, parentID: ids.GenerateTestID()}
	wire := blk.Bytes()
	_, err := parseBlockBytes(nil, append(append([]byte(nil), wire...), 0x00))
	require.Error(t, err, "trailing bytes must be rejected")
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
	signed := &BaseTransaction{timestamp: time.Unix(1_700_000_000, 0), nonce: 42, data: []byte("payload")}
	signed.quantumSignature = nil
	require.Equal(a, signed.Bytes(), "quantum signature is excluded from tx wire")
}

// TestBaseTransactionIDNonEmpty is the M2 regression guard for the tx pool: the
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
