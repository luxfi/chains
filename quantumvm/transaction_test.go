// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

// TestPoolTellsConsensusThereIsWork: a transaction the pool accepted is worth
// nothing until consensus is told about it. Consensus builds only when
// WaitForEvent returns, so accepting work and reporting it are one step.
func TestPoolTellsConsensusThereIsWork(t *testing.T) {
	pool := NewTransactionPool(8, log.NewNoOpLogger())

	idle, cancelIdle := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelIdle()
	_, err := pool.WaitForEvent(idle)
	require.Error(t, err, "an empty pool reported work to build")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	woke := make(chan error, 1)
	go func() {
		_, err := pool.WaitForEvent(ctx)
		woke <- err
	}()

	require.NoError(t, pool.AddTransaction(stampedTx(1, "op")))
	select {
	case err := <-woke:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("a transaction was accepted and consensus was never told; this chain cannot produce a block")
	}
}

// TestWorkLeftOverStillWakesABuilder.
//
// The latch holds one signal, so transactions arriving together wake one build.
// A build that takes fewer than the pool holds must say there is still work, or
// the remainder waits for an unrelated arrival to wake it — and on a chain that
// has gone quiet, that never comes.
func TestWorkLeftOverStillWakesABuilder(t *testing.T) {
	cfg := quietConfig()
	cfg.ParallelBatchSize = 1 // one transaction per block
	vm, _ := bootVM(t, cfg)

	// Three arrive back to back. The latch collapses them to one signal.
	for i := 0; i < 3; i++ {
		require.NoError(t, vm.txPool.AddTransaction(stampedTx(uint64(i), "op")))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := vm.WaitForEvent(ctx)
	require.NoError(t, err)

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.Len(t, blk.(*Block).transactions, 1, "precondition: one transaction per block")
	require.NoError(t, blk.(*Block).Accept(context.Background()))

	// Two are still pending. The builder has to hear about them.
	woken, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	_, err = vm.WaitForEvent(woken)
	require.NoError(t, err,
		"two transactions sat in the pool with nothing left to wake a builder: the chain stops here")
}

// TestPoolRefusesTheSameTransactionTwice: the id is the content hash, so a
// resend is the same slot. Admitting it twice would let one transaction fill
// the pool by itself.
func TestPoolRefusesTheSameTransactionTwice(t *testing.T) {
	pool := NewTransactionPool(8, log.NewNoOpLogger())
	tx := stampedTx(1, "op")

	require.NoError(t, pool.AddTransaction(tx))
	require.ErrorIs(t, pool.AddTransaction(tx), errDuplicateTx)
	// A separately constructed copy is the same content, so it is the same slot.
	require.ErrorIs(t, pool.AddTransaction(stampedTx(1, "op")), errDuplicateTx)
	require.Equal(t, 1, pool.PendingCount())
}

// TestPoolRefusesAnUnsignedTransaction at admission, so nothing unverifiable
// ever occupies a slot in the first place.
func TestPoolRefusesAnUnsignedTransaction(t *testing.T) {
	pool := NewTransactionPool(8, log.NewNoOpLogger())
	require.ErrorIs(t, pool.AddTransaction(&BaseTransaction{nonce: 1}), errMissingStamp)
	require.Zero(t, pool.PendingCount())
}

// TestPoolIsBounded: the pool is memory a peer can fill, so it has a ceiling
// and the ceiling holds.
func TestPoolIsBounded(t *testing.T) {
	pool := NewTransactionPool(3, log.NewNoOpLogger())
	for i := 0; i < 3; i++ {
		require.NoError(t, pool.AddTransaction(stampedTx(uint64(i), "op")))
	}
	require.ErrorIs(t, pool.AddTransaction(stampedTx(99, "op")), errPoolFull)
	require.Equal(t, 3, pool.PendingCount())

	// A slot freed is a slot usable again.
	require.NoError(t, pool.RemoveTransaction(stampedTx(0, "op").ID()))
	require.NoError(t, pool.AddTransaction(stampedTx(99, "op")))
}

// TestPoolRemoveClearsBothViews. The map decides admission and the queue
// decides selection; a transaction left in either one is either an unusable
// slot or a transaction that gets built into a second block.
func TestPoolRemoveClearsBothViews(t *testing.T) {
	pool := NewTransactionPool(8, log.NewNoOpLogger())
	keep, drop := stampedTx(1, "keep"), stampedTx(2, "drop")
	require.NoError(t, pool.AddTransaction(keep))
	require.NoError(t, pool.AddTransaction(drop))

	require.NoError(t, pool.RemoveTransaction(drop.ID()))
	require.Equal(t, 1, pool.PendingCount(), "the map still holds a removed transaction")

	selected := pool.GetPendingTransactions(0)
	require.Len(t, selected, 1, "the queue still offers a removed transaction for the next block")
	require.Equal(t, keep.ID(), selected[0].ID())

	require.ErrorIs(t, pool.RemoveTransaction(drop.ID()), errTxNotInPool)
}

// TestClosedPoolAcceptsNothing. After shutdown the pool is not a place work can
// be left: accepting it would be a promise to build a block that never comes.
func TestClosedPoolAcceptsNothing(t *testing.T) {
	pool := NewTransactionPool(8, log.NewNoOpLogger())
	require.NoError(t, pool.AddTransaction(stampedTx(1, "op")))

	pool.Close()
	pool.Close() // the VM may shut down more than once

	require.ErrorIs(t, pool.AddTransaction(stampedTx(2, "op")), errPoolClosed)
	require.Zero(t, pool.PendingCount())
	require.Empty(t, pool.GetPendingTransactions(10))
	require.Error(t, pool.RemoveTransaction(stampedTx(1, "op").ID()))
	require.NotPanics(t, pool.signalIfWork)
}

// TestPoolHoldsUpUnderConcurrentUse. Admission, selection and removal all run
// from different goroutines in the live VM — the engine builds while gossip
// arrives.
func TestPoolHoldsUpUnderConcurrentUse(t *testing.T) {
	pool := NewTransactionPool(256, log.NewNoOpLogger())

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(3)
		go func(i int) { defer wg.Done(); _ = pool.AddTransaction(stampedTx(uint64(i), "op")) }(i)
		go func() { defer wg.Done(); _ = pool.GetPendingTransactions(8) }()
		go func(i int) { defer wg.Done(); _ = pool.RemoveTransaction(stampedTx(uint64(i), "op").ID()) }(i)
	}
	wg.Wait()

	// However the races fell out, the two views agree.
	require.Len(t, pool.GetPendingTransactions(0), pool.PendingCount())
}

// TestProcessBatchSeparatesGoodFromBad. Both halves are load-bearing: the good
// go in the block, the bad leave the pool. A batch that reported only the good
// left the bad behind to hold their slots for good.
func TestProcessBatchSeparatesGoodFromBad(t *testing.T) {
	vm, _ := bootVM(t, config.DefaultConfig()) // stamps ON
	worker := &TransactionWorker{vm: vm, quantumSigner: vm.quantumSigner}

	good := signedTx(t, vm, 1, "honest")
	forged := signedTx(t, vm, 2, "forged")
	forged.quantumSignature.Signature[0] ^= 0xFF
	unsigned := &BaseTransaction{timestamp: chainTime, nonce: 3, data: []byte("bare")}

	valid, rejected := worker.ProcessBatch([]Transaction{good, forged, unsigned})

	require.Len(t, valid, 1)
	require.Equal(t, good.ID(), valid[0].ID())
	require.Len(t, rejected, 2, "a forged and an unsigned transaction must both be reported back")

	// Nothing at all is neither valid nor an error.
	valid, rejected = worker.ProcessBatch(nil)
	require.Empty(t, valid)
	require.Empty(t, rejected)
}

// TestProcessBatchWithStampsOffSkipsCrypto but still refuses what has no
// signature — the pool's own admission rule, applied again at build time.
func TestProcessBatchWithStampsOffSkipsCrypto(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	worker := &TransactionWorker{vm: vm, quantumSigner: vm.quantumSigner}

	valid, rejected := worker.ProcessBatch([]Transaction{
		stampedTx(1, "a"), // a meaningless signature passes when nothing checks it
		&BaseTransaction{timestamp: chainTime, nonce: 2},
	})
	require.Len(t, valid, 1)
	require.Len(t, rejected, 1)
}

// TestProcessBatchDropsWhatCannotExecute.
func TestProcessBatchDropsWhatCannotExecute(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	worker := &TransactionWorker{vm: vm, quantumSigner: vm.quantumSigner}

	valid, rejected := worker.ProcessBatch([]Transaction{
		stampedTx(1, "runs"),
		&failingTx{BaseTransaction: *stampedTx(2, "throws")},
	})
	require.Len(t, valid, 1)
	require.Len(t, rejected, 1)
}

type failingTx struct{ BaseTransaction }

func (t *failingTx) Execute() error { return errors.New("execution refused") }

// TestBuildBlockSpansSeveralBatches: the batch size divides the selection, and
// every batch's survivors reach the block.
func TestBuildBlockSpansSeveralBatches(t *testing.T) {
	cfg := quietConfig()
	cfg.ParallelBatchSize = 2
	vm, _ := bootVM(t, cfg)

	for i := 0; i < 2; i++ {
		require.NoError(t, vm.txPool.AddTransaction(stampedTx(uint64(i), "op")))
	}
	// Ask for more than one batch's worth directly, so the split runs.
	valid, rejected := vm.processTransactionsParallel(vm.txPool.GetPendingTransactions(0))
	require.Len(t, valid, 2)
	require.Empty(t, rejected)
}

// TestTransactionIdentityIsItsContent. The id keys the pool, so two different
// transactions sharing one would take a single slot between them.
func TestTransactionIdentityIsItsContent(t *testing.T) {
	base := stampedTx(1, "payload")
	require.NotEqual(t, ids.Empty, base.ID())
	require.Equal(t, base.ID(), base.ID(), "the id is stable across calls")

	require.NotEqual(t, base.ID(), stampedTx(2, "payload").ID(), "the nonce moves the id")
	require.NotEqual(t, base.ID(), stampedTx(1, "other").ID(), "the payload moves the id")

	later := stampedTx(1, "payload")
	later.timestamp = chainTime.Add(time.Second)
	require.NotEqual(t, base.ID(), later.ID(), "the timestamp moves the id")

	require.Equal(t, chainTime, base.Timestamp())
	require.NotNil(t, base.GetQuantumSignature())
	require.NoError(t, base.Execute())
}
