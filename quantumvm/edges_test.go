// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	luxvm "github.com/luxfi/vm"
	"github.com/luxfi/zap"
	"github.com/stretchr/testify/require"
)

// TestTheVMSignsEveryBlockItBuilds.
//
// The node signs with its own key and tracks the block, so a peer's signature
// has somewhere to land. That is the whole bridge: with the node unregistered
// it signed nothing, tracked nothing, and every peer signature was answered
// "pending block not found" — a finality engine that could never finalize, one
// warning line per block.
func TestTheVMSignsEveryBlockItBuilds(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	bridge := vm.GetQuasarBridge()

	blk := buildOn(t, vm)
	require.Contains(t, bridge.pendingBlocks, blk.ID(),
		"the node built a block and recorded no signature for it")
	pending := bridge.pendingBlocks[blk.ID()]
	require.Len(t, pending.Signatures, 1)
	require.True(t, bridge.VerifySignature(blk.Bytes(), pending.Signatures[0]),
		"the recorded signature does not check out over the block it signs")

	// The block itself is unaffected: signing is a consensus-layer statement
	// about a block, not a field on it.
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))

	// The finality bridge's stamp is that same signature.
	stamp, err := vm.StampBlock(blk.ID(), 42, blk.Bytes())
	require.NoError(t, err)
	require.IsType(t, &quasar.QuasarSig{}, stamp)
	require.NoError(t, vm.VerifyStamp(blk.Bytes(), stamp))
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
	tip, err := vm.blockAt(tipOf(t, vm))
	require.NoError(t, err)

	blk := blockOn(vm, tip, stampedTx(7, "never in this pool"))

	require.NoError(t, blk.Accept(context.Background()))
	require.Equal(t, blk.id, tipOf(t, vm))
}

// TestBuildBlockRefusesWhenTheTipIsUnreadable. The builder reads its parent to
// set height and time; a tip pointer naming bytes it cannot read is a refusal,
// never a block built on a guess.
func TestBuildBlockRefusesWhenTheTipIsUnreadable(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	tip := tipOf(t, vm)
	require.NoError(t, vm.state.Put(tip[:], []byte("no longer a block")))

	require.NoError(t, vm.txPool.AddTransaction(stampedTx(1, "op")))
	_, err := vm.BuildBlock(context.Background())
	require.Error(t, err)
}

// TestInitializeRefusesAStoreItCannotCommitTo. Genesis is written at boot; a VM
// that could not write it would come up naming no block, which is the one state
// bootstrap cannot recover from.
func TestInitializeRefusesAStoreItCannotCommitTo(t *testing.T) {
	always := true
	vm := &VM{Config: config.DefaultConfig()}
	err := vm.Initialize(context.Background(), luxvm.Init{
		DB:      refusing{memdb.New(), &always},
		Log:     log.NewNoOpLogger(),
		Runtime: testRuntime(),
	})
	require.ErrorIs(t, err, errDiskFull)
	require.Equal(t, ids.Empty, tipOf(t, vm))
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

// unreadable is a store that holds everything and answers nothing: the shape of
// a disk that is failing rather than empty.
type unreadable struct{ database.Database }

var errUnreadable = errors.New("store could not answer the read")

func (d unreadable) Get([]byte) ([]byte, error) { return nil, errUnreadable }

// TestAReadThatFailedIsNotAChainThatIsEmpty.
//
// The tip was read as "ids.Empty on any error, and on any value that is not
// 32 bytes" — and seedGenesis reads ids.Empty as "a fresh chain". So ONE
// transient read failure at boot committed genesis over a live tip, and
// Initialize returned success: a node holding five blocks came back holding one
// and told its peers so. A short read did exactly the same. Not-found is the
// only reason for an empty answer; every other reason is a refusal to run.
func TestAReadThatFailedIsNotAChainThatIsEmpty(t *testing.T) {
	vm, db := bootVM(t, quietConfig())
	tip := advance(t, vm, 5)
	require.Equal(t, uint64(5), heightOf(t, vm))

	// A store that cannot answer.
	blind := &VM{log: log.NewNoOpLogger(), blockchainID: testChain, NetworkID: testNetwork}
	blind.state = versiondb.New(unreadable{db})

	_, err := blind.tip()
	require.ErrorIs(t, err, errTipUnreadable, "a failed read answered 'this chain is empty'")
	_, err = blind.tipHeight()
	require.ErrorIs(t, err, errTipUnreadable)
	require.Error(t, blind.seedGenesis(), "genesis was written over a chain that could not be read")
	_, err = blind.LastAccepted(context.Background())
	require.Error(t, err)

	// A short read is the same fact: an answer that is not an id.
	short := &VM{log: log.NewNoOpLogger(), blockchainID: testChain, NetworkID: testNetwork}
	short.state = versiondb.New(memdb.New())
	require.NoError(t, short.state.Put(lastAcceptedKey, []byte("not an id")))
	_, err = short.tip()
	require.ErrorIs(t, err, errTipUnreadable)
	require.Error(t, short.seedGenesis(), "genesis was written over a chain whose tip read short")

	// The chain underneath is untouched: nothing rewound it.
	reopened := bootVMOn(t, quietConfig(), db)
	require.Equal(t, tip.id, tipOf(t, reopened))
	require.Equal(t, uint64(5), heightOf(t, reopened))
}

// TestAMalformedHeightIsNotAHeightOfZero: the tip height decides what the next
// block's height is, so bytes that are not a height must refuse rather than
// read as the start of the chain.
func TestAMalformedHeightIsNotAHeightOfZero(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	advance(t, vm, 1)
	require.Equal(t, uint64(1), heightOf(t, vm))

	require.NoError(t, vm.state.Put(tipHeightKey, []byte{1, 2, 3}))
	_, err := vm.tipHeight()
	require.ErrorIs(t, err, errTipUnreadable, "three bytes were read as a height")

	require.NoError(t, vm.txPool.AddTransaction(stampedTx(9, "op")))
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.ErrorIs(t, blk.(*Block).Accept(context.Background()), errTipUnreadable)
}

// TestInitializeRefusesToBootOnAStoreItCannotRead is the same fact one level up:
// a node that cannot read its own tip does not start, because the alternative is
// starting on a chain it has just destroyed.
func TestInitializeRefusesToBootOnAStoreItCannotRead(t *testing.T) {
	vm, db := bootVM(t, quietConfig())
	advance(t, vm, 3)

	fresh := &VM{Config: quietConfig()}
	err := fresh.Initialize(context.Background(), luxvm.Init{
		DB:      unreadable{db},
		Log:     log.NewNoOpLogger(),
		Runtime: testRuntime(),
	})
	require.ErrorIs(t, err, errTipUnreadable)
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
	b := zap.NewBuilder(zap.HeaderSize + blkSize)
	ob := b.StartObject(8) // eight bytes where the header needs a hundred
	ob.SetInt64(blkTime, 0)
	ob.FinishAsRoot()
	short := b.Finish()

	// It is a well-formed ZAP message: the refusal has to come from us.
	_, err := zap.Parse(short)
	require.NoError(t, err, "precondition: the bytes parse as ZAP")

	_, err = parseBlockBytes(nil, short)
	require.ErrorContains(t, err, "header")
}
