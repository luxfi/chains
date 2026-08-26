// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"sync"
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
// worth nothing until consensus is told about it. Consensus builds only when
// WaitForEvent returns, so accepting work and reporting it are one step.
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

// TestFullPoolGivesUpTheCheapest pins which transaction a full pool releases.
// Fees are divided by a fixed 256-byte estimate, so they must differ by more
// than that to differ in priority at all.
func TestFullPoolGivesUpTheCheapest(t *testing.T) {
	const unit = 256
	mp := NewMempool(2, log.NoLog{})

	best := shieldedTransfer(1000*unit, 1)
	dust := shieldedTransfer(1*unit, 2)
	middle := shieldedTransfer(100*unit, 3)

	require.NoError(t, mp.AddTransaction(best))
	require.NoError(t, mp.AddTransaction(dust))
	require.NoError(t, mp.AddTransaction(middle), "the pool is full but the arrival outbids the dust")

	require.True(t, mp.HasTransaction(best.ID), "the best payer must survive a full pool")
	require.True(t, mp.HasTransaction(middle.ID))
	require.False(t, mp.HasTransaction(dust.ID), "the cheapest is the one to give up")
}

// A full pool already holding better has nothing to gain by swapping, and
// accepting the arrival would mean dropping a better transaction for a worse one.
func TestFullPoolRefusesAnArrivalWorseThanItHolds(t *testing.T) {
	const unit = 256
	mp := NewMempool(2, log.NoLog{})
	require.NoError(t, mp.AddTransaction(shieldedTransfer(1000*unit, 1)))
	require.NoError(t, mp.AddTransaction(shieldedTransfer(900*unit, 2)))

	pauper := shieldedTransfer(1*unit, 3)
	require.Error(t, mp.AddTransaction(pauper))
	require.False(t, mp.HasTransaction(pauper.ID))
	require.Equal(t, 2, mp.Size(), "a refused arrival must not change what the pool holds")
}

// Two callers asking what to build at once must not write to each other's
// transactions. GetPendingTransactions sorts a copy of the heap and that copy
// holds the same pointers, so the sort must leave them untouched. Run with
// -race.
func TestReadingThePoolDoesNotWriteToIt(t *testing.T) {
	mp := NewMempool(64, log.NoLog{})
	for i := 0; i < 16; i++ {
		require.NoError(t, mp.AddTransaction(shieldedTransfer(uint64(i+1)*256, byte(i))))
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := mp.GetPendingTransactions(8); len(got) != 8 {
				t.Errorf("asked for 8 transactions, got %d", len(got))
			}
		}()
	}
	wg.Wait()
}
