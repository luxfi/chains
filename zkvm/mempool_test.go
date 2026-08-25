// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

// shieldedTransfer is the smallest transaction the mempool will accept.
func shieldedTransfer(fee uint64, n byte) *Transaction {
	tx := &Transaction{
		Type:       TransactionTypeTransfer,
		Version:    1,
		Fee:        fee,
		Nullifiers: [][]byte{{n}},
		Outputs:    []*ShieldedOutput{{Commitment: []byte{n}}},
		Proof:      &ZKProof{ProofType: "groth16", ProofData: []byte("p")},
	}
	tx.ID = tx.ComputeID()
	return tx
}

// TestMempoolTellsConsensusThereIsWork: a transaction the mempool accepted is
// worth nothing until consensus is told about it. WaitForEvent used to wait only
// on the context, so it never returned, BuildBlock was never called, and the
// chain could not leave genesis however many transactions arrived.
func TestMempoolTellsConsensusThereIsWork(t *testing.T) {
	mp := NewMempool(10, log.NoLog{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Nothing has arrived, so nothing should be claimed.
	idle, cancelIdle := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelIdle()
	if _, err := mp.WaitForEvent(idle); err == nil {
		t.Fatal("an empty mempool reported work to build")
	}

	woke := make(chan error, 1)
	go func() {
		_, err := mp.WaitForEvent(ctx)
		woke <- err
	}()

	require.NoError(t, mp.AddTransaction(shieldedTransfer(1000, 1)))

	select {
	case err := <-woke:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("a transaction was accepted and consensus was never told; this chain cannot produce a block")
	}
}
