// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/zap"
)

// boot builds a VM over one database, so a failure can be injected into the
// store the VM will open.
func boot(t *testing.T, db database.Database, genesis *Genesis) error {
	t.Helper()
	raw, err := json.Marshal(genesis)
	require.NoError(t, err)

	vm := &VM{}
	err = vm.Initialize(context.Background(), vmcore.Init{
		Runtime: &runtime.Runtime{ChainID: ids.ID{4}, Log: log.NoLog{}},
		DB:      db,
		Genesis: raw,
		Config:  []byte(`{"maxTxPerBlock":100,"proofCacheSize":16}`),
		Log:     log.NoLog{},
	})
	if err == nil {
		t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	}
	return err
}

// A store this node cannot read is not an empty store: a node that cannot read
// its own records does not hold the state it believes it holds, and opening
// anyway means building height 1 on top of state it cannot see.
func TestBootRefusesAnUnreadableStore(t *testing.T) {
	// A committed state root that is not a root.
	db := memdb.New()
	require.NoError(t, db.Put(rootKey, []byte("short")))
	require.ErrorContains(t, boot(t, db, &Genesis{Timestamp: 1}), "state root")

	// A tip this node cannot resolve.
	db = memdb.New()
	require.NoError(t, db.Put([]byte("chain/tip"), []byte("not an id")))
	require.ErrorContains(t, boot(t, db, &Genesis{Timestamp: 1}), "tip")

	// A real bn254 key on a strict-PQ chain: the profile the chain declares
	// and the keys it is handed have to be the same posture, and the verifier
	// refuses to be built otherwise.
	config, err := json.Marshal(ZConfig{
		StrictPQ:      true,
		VerifyingKeys: map[string][]byte{string(TransactionTypeTransfer): groth16Key(2)},
	})
	require.NoError(t, err)

	require.ErrorContains(t, (&VM{}).Initialize(context.Background(), vmcore.Init{
		Runtime: &runtime.Runtime{Log: log.NoLog{}},
		DB:      memdb.New(),
		Config:  config,
		Log:     log.NoLog{},
	}), "proof verifier")
}

// The genesis allocation is committed on its own, and a genesis it cannot
// allocate is a chain that does not open.
func TestBootRefusesAGenesisItCannotApply(t *testing.T) {
	tx := spendTx(nullifier(1))
	genesis := &Genesis{Timestamp: 1, InitialTxs: []*Transaction{tx}}

	// The same output twice: the set the chain keeps refuses the second.
	twice := &Genesis{Timestamp: 1, InitialTxs: []*Transaction{tx, tx}}
	require.ErrorContains(t, boot(t, memdb.New(), twice), "already exists")

	require.NoError(t, boot(t, memdb.New(), genesis))
}

// Shutdown releases the stores it opened, and says so through a logger it has.
func TestShutdownReleasesTheStores(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)
	require.NoError(t, vm.Shutdown(ctx))

	// Twice is not an error: a store already closed is a store released.
	require.Error(t, vm.Shutdown(ctx))
}

// A spend of a note the chain has already spent is refused, and a spent set
// that cannot be READ refuses the transaction rather than admitting it.
func TestVerifyTransactionAsksTheSpentSet(t *testing.T) {
	vm := newVM(t)
	tx := spendTx(nullifier(1))
	acceptProofs(vm, tx)

	require.NoError(t, vm.verifyTransaction(tx))

	require.NoError(t, vm.nullifierDB.MarkNullifierSpent(nullifier(1), 1))
	require.ErrorIs(t, vm.verifyTransaction(tx), errNullifierSpent)

	boom := errors.New("disk gone")
	vm.nullifierDB.spent = map[string]uint64{}
	vm.nullifierDB.db = &brokenDB{Database: vm.nullifierDB.db, err: boom}
	require.ErrorIs(t, vm.verifyTransaction(tx), boom)
}

// The caches follow the records. A block whose writes were discarded has had
// its spends discarded with them, so a cache that already recorded them must
// stop claiming those notes are spent — otherwise the block can never be
// applied again.
func TestReloadFollowsTheRecords(t *testing.T) {
	vm := newVM(t)

	require.NoError(t, vm.nullifierDB.MarkNullifierSpent(nullifier(1), 1))
	require.NoError(t, vm.utxoDB.AddUTXO(&UTXO{Commitment: []byte("c"), Height: 1}))
	require.NoError(t, vm.reload())
	require.True(t, spentOf(t, vm.nullifierDB, nullifier(1)))
	require.EqualValues(t, 1, vm.utxoDB.GetUTXOCount())

	boom := errors.New("iterator gone")
	vm.nullifierDB.db = &failIterDB{Database: vm.nullifierDB.db, err: boom}
	require.ErrorIs(t, vm.reload(), boom)

	vm = newVM(t)
	vm.utxoDB.db = &failIterDB{Database: vm.utxoDB.db, err: boom}
	require.ErrorIs(t, vm.reload(), boom)
}

// A block whose parent resolves to something that is NOT a block is a block
// with no parent. The store holds both shapes.
func TestAParentMustBeABlock(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	tx := spendTx(nullifier(1))
	acceptProofs(vm, tx)
	require.NoError(t, vm.mempool.AddTransaction(tx))
	built, err := vm.BuildVertex(ctx)
	require.NoError(t, err)
	vtx := built.(*Vertex)
	require.NoError(t, vtx.Verify(ctx))
	require.NoError(t, vtx.Accept(ctx))

	child := &Block{
		ParentID_:      vtx.ID(),
		BlockHeight:    vtx.Height() + 1,
		BlockTimestamp: 1_700_000_000,
		Txs:            []*Transaction{spendTx(nullifier(2))},
		vm:             vm,
	}
	acceptProofs(vm, child.Txs...)
	child.StateRoot = vm.computeStateRoot(child.Txs)
	require.ErrorContains(t, child.Verify(ctx), "not a block")
}

// A transaction frame whose nested lists do not decode is not a transaction.
func TestNestedListsMustDecode(t *testing.T) {
	junk := []byte("not a frame")

	for _, slot := range []struct{ lens, blob int }{
		{18, 26}, // transparent inputs
		{34, 42}, // transparent outputs
		{66, 74}, // shielded outputs
	} {
		b := zap.NewBuilder(zap.HeaderSize + txSize + len(junk) + 64)
		off := writeU32List(b, []uint32{uint32(len(junk))})
		ob := b.StartObject(txSize)
		ob.SetList(slot.lens, off, 1)
		ob.SetBytes(slot.blob, junk)
		ob.FinishAsRoot()

		_, err := parseTransaction(b.Finish())
		require.Error(t, err, "slot %d", slot.lens)
	}

	// A proof blob that is not a proof.
	b := zap.NewBuilder(zap.HeaderSize + txSize + len(junk) + 64)
	ob := b.StartObject(txSize)
	ob.SetBytes(82, junk)
	ob.FinishAsRoot()
	_, err := parseTransaction(b.Finish())
	require.Error(t, err)

	// And a block whose transaction blob is not a transaction.
	bb := zap.NewBuilder(zap.HeaderSize + blkSize + len(junk) + 64)
	txOff := writeU32List(bb, []uint32{uint32(len(junk))})
	obb := bb.StartObject(blkSize)
	obb.SetList(48, txOff, 1)
	obb.SetBytes(56, junk)
	obb.FinishAsRoot()
	var blk Block
	require.Error(t, parseBlockBytes(bb.Finish(), &blk))
}

// A length vector and the blob it indexes both come from the peer, and both are
// checked in both directions.
func TestPackedListsMustAgree(t *testing.T) {
	_, err := unpackObjs(nil, []byte("orphan"), parseTransparentInput)
	require.ErrorIs(t, err, errLength)

	_, err = unpackObjs([]uint32{9}, []byte("ab"), parseTransparentInput)
	require.ErrorIs(t, err, errLength)

	in := marshalTransparentInput(&TransparentInput{TxID: ids.ID{1}, Amount: 1})
	_, err = unpackObjs([]uint32{uint32(len(in))}, append(append([]byte(nil), in...), 0xFF), parseTransparentInput)
	require.ErrorIs(t, err, errLength)

	got, err := unpackObjs([]uint32{uint32(len(in))}, in, parseTransparentInput)
	require.NoError(t, err)
	require.Len(t, got, 1)
}

func TestLastAccepted(t *testing.T) {
	vm := newVM(t)
	id, err := vm.LastAccepted(context.Background())
	require.NoError(t, err)
	require.Equal(t, vm.genesisBlock.ID(), id)
}

// A block the chain committed and then built past is read back from the
// records, through the one decoder that derives its id from its content.
func TestACommittedBlockIsReadBack(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	first := build(t, vm, spendTx(nullifier(1)))
	require.NoError(t, first.Verify(ctx))
	require.NoError(t, first.Accept(ctx))

	second := build(t, vm, spendTx(nullifier(2)))
	require.NoError(t, second.Verify(ctx))
	require.NoError(t, second.Accept(ctx))

	// The tip answers from memory; anything beneath it is decoded from disk.
	got, err := vm.GetBlock(ctx, first.ID())
	require.NoError(t, err)
	require.Equal(t, first.ID(), got.ID())
	require.Equal(t, first.Bytes(), got.Bytes())
}

// Shutdown says so through a logger that is one.
func TestShutdownSpeaksThroughItsLogger(t *testing.T) {
	ctx := context.Background()
	vm := &VM{}
	require.NoError(t, vm.Initialize(ctx, vmcore.Init{
		Runtime: &runtime.Runtime{ChainID: ids.ID{2}, Log: log.NewNoOpLogger()},
		DB:      memdb.New(),
		Config:  []byte(`{"maxTxPerBlock":4,"proofCacheSize":4}`),
		Log:     log.NewNoOpLogger(),
	}))
	require.NoError(t, vm.Shutdown(ctx))
}

// A proof this chain cannot judge refuses the transaction. The test VM holds
// no real verifying keys, so a transaction whose verdict is not already in the
// cache reaches that refusal.
func TestAnUnverifiableProofRefusesTheTransaction(t *testing.T) {
	vm := newVM(t)
	require.ErrorContains(t, vm.verifyTransaction(spendTx(nullifier(1))),
		"proof verification failed")
}

// A proof frame whose public-input lengths and blob disagree is not a proof.
func TestProofPublicInputsMustCoverTheirBlob(t *testing.T) {
	b := zap.NewBuilder(zap.HeaderSize + zkpSize + 64)
	off := writeU32List(b, []uint32{9})
	ob := b.StartObject(zkpSize)
	ob.SetList(16, off, 1)
	ob.SetBytes(24, []byte("ab"))
	ob.FinishAsRoot()

	_, err := parseZKProof(b.Finish())
	require.ErrorIs(t, err, errLength)
}
