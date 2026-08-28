// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"testing"

	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	luxvm "github.com/luxfi/vm"
	"github.com/luxfi/zap"
	"github.com/stretchr/testify/require"
)

// TestTheVMDoesNotClaimASignatureItCouldNotMake.
//
// Signing needs a Corona share, and shares come from a dealerless DKG that has
// not landed — AddValidator issues BLS keys only. So the post-quantum leg
// cannot sign, and what matters is what the node does about it: it builds the
// block, records no signature for it, and keeps nothing pending. Reporting the
// block as signed would be a node claiming post-quantum finality it never had.
func TestTheVMDoesNotClaimASignatureItCouldNotMake(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	bridge := vm.GetQuasarBridge()

	blk := buildOn(t, vm)
	require.NotContains(t, bridge.pendingBlocks, blk.ID(),
		"the node tracked a block as signed when neither leg produced a signature")

	// The block itself is unaffected: signing is a consensus-layer statement
	// about a block, not a field on it.
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))

	// The finality bridge's stamp falls back to ML-DSA for the same reason.
	stamp, err := vm.StampBlock(blk.ID(), 42, blk.Bytes())
	require.NoError(t, err)
	require.IsType(t, &quantum.QuantumSignature{}, stamp)
	require.NoError(t, vm.VerifyStamp(stamp))
}

// TestBuildBlockWithNoBridgeStillBuilds: signing is best-effort, so a VM with
// no bridge produces blocks rather than stopping.
func TestBuildBlockWithNoBridgeStillBuilds(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	vm.quasarBridge = nil

	blk := buildOn(t, vm)
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))
}

// TestAcceptSurvivesATransactionAlreadyGone. A block's transactions are settled
// by its commit; one that is no longer in the pool is not a reason to fail a
// block that is already durable.
func TestAcceptSurvivesATransactionAlreadyGone(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	tip, err := vm.blockAt(vm.getLastAcceptedID())
	require.NoError(t, err)

	blk := &Block{
		timestamp:    tip.timestamp,
		height:       tip.height + 1,
		parentID:     tip.id,
		transactions: []Transaction{stampedTx(7, "never in this pool")},
		vm:           vm,
	}
	blk.id = blk.computeID()

	require.NoError(t, blk.Accept(context.Background()))
	require.Equal(t, blk.id, vm.getLastAcceptedID())
}

// TestBuildBlockRefusesWhenTheTipIsUnreadable. The builder reads its parent to
// set height and time; a tip pointer naming bytes it cannot read is a refusal,
// never a block built on a guess.
func TestBuildBlockRefusesWhenTheTipIsUnreadable(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	tip := vm.getLastAcceptedID()
	require.NoError(t, vm.state.Put(tip[:], []byte("no longer a block")))

	require.NoError(t, vm.txPool.AddTransaction(stampedTx(1, "op")))
	_, err := vm.BuildBlock(context.Background())
	require.Error(t, err)
}

// TestInitializeRefusesAStoreItCannotCommitTo. Genesis is written at boot; a VM
// that could not write it would come up naming no block, which is the one state
// bootstrap cannot recover from.
func TestInitializeRefusesAStoreItCannotCommitTo(t *testing.T) {
	vm := &VM{Config: config.DefaultConfig()}
	err := vm.Initialize(context.Background(), luxvm.Init{
		DB:      refusing{memdb.New()},
		Log:     log.NewNoOpLogger(),
		Runtime: &runtime.Runtime{NetworkID: 96369, NodeID: ids.GenerateTestNodeID()},
	})
	require.ErrorIs(t, err, errDiskFull)
	require.Equal(t, ids.Empty, vm.getLastAcceptedID())
}

// TestShutdownCompletesWhenTheStoreIsAlreadyGone. Shutdown runs on the way out
// of a node that may already be tearing down, so it has to finish rather than
// fail and leave the process hanging.
func TestShutdownCompletesWhenTheStoreIsAlreadyGone(t *testing.T) {
	db := memdb.New()
	vm := bootVMOn(t, quietConfig(), db)
	require.NoError(t, db.Close())

	// Shutdown logs the failure and still completes, so the node can exit.
	require.NoError(t, vm.Shutdown(context.Background()))
}

// TestHeightReadsZeroFromAMalformedEntry rather than a number made of whatever
// bytes are there — the tip height decides what the next block's height is.
func TestHeightReadsZeroFromAMalformedEntry(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	advance(t, vm, 1)
	require.Equal(t, uint64(1), vm.getHeight())

	require.NoError(t, vm.state.Put(tipHeightKey, []byte{1, 2, 3}))
	require.Zero(t, vm.getHeight(), "three bytes were read as a height")
}

// TestStoreKeysCannotCollide. Block ids, the height index and the two tip
// pointers all live in one namespace, so a height whose key happened to equal
// the tip pointer's would overwrite the chain's head.
func TestStoreKeysCannotCollide(t *testing.T) {
	seen := map[string]string{
		string(lastAcceptedKey): "lastAccepted",
		string(tipHeightKey):    "tipHeight",
	}
	for _, h := range []uint64{0, 1, 255, 1 << 32, ^uint64(0)} {
		k := string(heightKey(h))
		require.NotContains(t, seen, k, "height %d collides with %s", h, seen[k])
		seen[k] = "height"
		require.NotEqual(t, len(k), 32, "a height key is indistinguishable from a block id")
	}
}

// TestCreateHandlersMountsTheRPCWhereTheEngineLooks.
func TestCreateHandlersMountsTheRPCWhereTheEngineLooks(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	handlers, err := vm.CreateHandlers(context.Background())
	require.NoError(t, err)
	require.Contains(t, handlers, rpcPath)
	require.Same(t, vm.rpcServer, handlers[rpcPath])
}

// TestProcessBatchTakesTheWholeBatchWhenEverySignatureIsGood — the fast path,
// where the batch verifier answers once for all of them.
func TestProcessBatchTakesTheWholeBatchWhenEverySignatureIsGood(t *testing.T) {
	vm, _ := bootVM(t, config.DefaultConfig()) // stamps ON
	worker := &TransactionWorker{vm: vm, quantumSigner: vm.quantumSigner}

	txs := make([]Transaction, 6)
	for i := range txs {
		txs[i] = signedTx(t, vm, uint64(i), "honest")
	}

	valid, rejected := worker.ProcessBatch(txs)
	require.Len(t, valid, len(txs))
	require.Empty(t, rejected)
}

// TestWireRefusesAHeaderThatIsNotThere.
//
// A field read past the end of the buffer answers zero rather than failing, so
// a truncated wire did not decode to nothing — it decoded to height 0, time 0
// and the empty parent. Every possible truncation named that one value, each
// under a different id, which is two byte strings for one block and as many
// more as an attacker cares to send.
func TestWireRefusesAHeaderThatIsNotThere(t *testing.T) {
	b := zap.NewBuilder(zap.HeaderSize + 64)
	ob := b.StartObject(8) // eight bytes where the header needs sixty-four
	ob.SetInt64(blkTime, 0)
	ob.FinishAsRoot()
	short := b.Finish()

	// It is a well-formed ZAP message: the refusal has to come from us.
	_, err := zap.Parse(short)
	require.NoError(t, err, "precondition: the bytes parse as ZAP")

	_, err = parseBlockBytes(nil, short)
	require.ErrorContains(t, err, "header")
}
