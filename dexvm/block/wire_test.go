// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package block

import (
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/dexvm/txs"
)

// TestBlockWireRoundTrip proves the native-ZAP block envelope round-trips every
// header field, preserves the nanosecond timestamp (no seconds floor), and keeps
// transactions in proposer order — the DEX determinism invariant.
func TestBlockWireRoundTrip(t *testing.T) {
	require := require.New(t)

	from := ids.GenerateTestShortID()
	var poolID [32]byte
	copy(poolID[:], []byte("pool-1"))
	tx1 := txs.NewPlaceOrderTx(from, 1, poolID, 0, 100, 5)
	tx2 := txs.NewCancelOrderTx(from, 2, poolID, 7)

	orig := &Block{
		parentID:     ids.GenerateTestID(),
		height:       11,
		timestamp:    time.Unix(1_700_000_000, 123_456_789).UnixNano(), // sub-second component
		transactions: []txs.Tx{tx1, tx2},
		txRoot:       ids.GenerateTestID(),
		stateRoot:    ids.GenerateTestID(),
		producer:     ids.GenerateTestNodeID(),
		signature:    []byte("producer-signature"),
	}

	wire := orig.serialize()
	parsed, err := NewBlockParser().Parse(wire)
	require.NoError(err)

	require.Equal(orig.parentID, parsed.parentID)
	require.Equal(orig.height, parsed.height)
	require.Equal(orig.timestamp, parsed.timestamp, "nanosecond timestamp preserved (no floor)")
	require.Equal(orig.txRoot, parsed.txRoot)
	require.Equal(orig.stateRoot, parsed.stateRoot)
	require.Equal(orig.producer, parsed.producer)
	require.Equal(orig.signature, parsed.signature)

	require.Len(parsed.transactions, 2)
	require.Equal(tx1.Bytes(), parsed.transactions[0].Bytes(), "tx order preserved (DEX fairness)")
	require.Equal(tx2.Bytes(), parsed.transactions[1].Bytes())

	// canonical: trailing bytes rejected
	_, err = NewBlockParser().Parse(append(append([]byte(nil), wire...), 0x00))
	require.Error(err)
}
