// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"bytes"
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
)

// refusingDB is a real database whose flush to disk can be made to fail. That
// is how a block fails in the field: the writes are complete and staged, and
// making them durable is what does not happen.
type refusingDB struct {
	database.Database
	refuse bool
}

func (d *refusingDB) NewBatch() database.Batch {
	return &refusingBatch{Batch: d.Database.NewBatch(), db: d}
}

type refusingBatch struct {
	database.Batch
	db *refusingDB
}

var errRefused = errors.New("flush refused")

func (b *refusingBatch) Write() error {
	if b.db.refuse {
		return errRefused
	}
	return b.Batch.Write()
}

func newRefusingVM(t *testing.T) (*VM, *refusingDB) {
	t.Helper()
	db := &refusingDB{Database: memdb.New()}

	genesisBytes, err := json.Marshal(&Genesis{Timestamp: 1607144400, InitialTxs: []*Transaction{}})
	require.NoError(t, err)
	configBytes, err := json.Marshal(ZConfig{
		ProofSystem: "groth16", MaxUTXOsPerBlock: 100, ProofCacheSize: 1000,
	})
	require.NoError(t, err)

	vmImpl := &VM{}
	require.NoError(t, vmImpl.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: ids.GenerateTestID(), Log: log.NoLog{}},
		DB:       db,
		Genesis:  genesisBytes,
		Config:   configBytes,
		ToEngine: make(chan vmcore.Message, 1),
		Log:      log.NoLog{},
	}))
	return vmImpl, db
}

// TestABlockThatCannotCommitSpendsNothing is the defect this chain had. Accept
// used to mark the block accepted and move lastAccepted before writing
// anything, then issue a Put per nullifier and per output, each returning
// early. A failure partway left some notes spent and some outputs created
// under a tip the chain had already advanced — a shielded pool half applied.
//
// Worse, the spent-nullifier cache was updated as it went. Since
// MarkNullifierSpent refuses a nullifier it already holds, the very block that
// failed could never be applied again: the chain was stuck at that height with
// notes it believed spent and no block recording the spend.
func TestABlockThatCannotCommitSpendsNothing(t *testing.T) {
	vmImpl, db := newRefusingVM(t)
	defer vmImpl.Shutdown(context.Background())

	spent := nullifier(7)
	tx := spendTx(spent)
	acceptProofs(vmImpl, tx)
	require.NoError(t, vmImpl.mempool.AddTransaction(tx))

	built, err := vmImpl.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := built.(*Block)

	tipBefore, heightBefore := vmImpl.chain.Tip()
	rootBefore := append([]byte(nil), vmImpl.stateTree.GetRoot()...)

	db.refuse = true
	require.ErrorIs(t, blk.Accept(context.Background()), errRefused)

	// Nothing landed.
	has, err := db.Database.Has(makeNullifierKey(spent))
	require.NoError(t, err)
	require.False(t, has, "a note must not be spent by a block that did not commit")
	has, err = db.Database.Has(makeUTXOKey(tx.Outputs[0].Commitment))
	require.NoError(t, err)
	require.False(t, has, "nor an output created by one")

	// And nothing in memory believes it did. This is the part that mattered:
	// the nullifier cache is what decides whether a note can be spent, and a
	// cache holding a spend the database does not have is a note lost forever.
	require.False(t, vmImpl.nullifierDB.IsNullifierSpent(spent),
		"the spent-nullifier cache must agree with the database")
	require.True(t, bytes.Equal(rootBefore, vmImpl.stateTree.GetRoot()),
		"the committed state root must not have advanced")

	tip, height := vmImpl.chain.Tip()
	require.Equal(t, tipBefore, tip)
	require.Equal(t, heightBefore, height)
	require.True(t, vmImpl.mempool.HasTransaction(tx.ID),
		"the transaction is still waiting, so the work is not lost")

	// The block can be applied again, which is the whole point of rolling the
	// caches back: under the old code MarkNullifierSpent would refuse, and the
	// chain could never make progress past this height.
	db.refuse = false
	require.NoError(t, blk.Accept(context.Background()))

	has, err = db.Database.Has(makeNullifierKey(spent))
	require.NoError(t, err)
	require.True(t, has)
	require.True(t, vmImpl.nullifierDB.IsNullifierSpent(spent))
	require.False(t, bytes.Equal(rootBefore, vmImpl.stateTree.GetRoot()))

	tip, height = vmImpl.chain.Tip()
	require.Equal(t, blk.ID(), tip)
	require.Equal(t, uint64(1), height)
	require.False(t, vmImpl.mempool.HasTransaction(tx.ID))
}

// TestAVertexThatCannotCommitSpendsNothing holds the DAG path to the same
// rule. A vertex is not a block — several parents, no timestamp — but it
// changes state the same way and goes through the same store.
func TestAVertexThatCannotCommitSpendsNothing(t *testing.T) {
	vmImpl, db := newRefusingVM(t)
	defer vmImpl.Shutdown(context.Background())

	spent := nullifier(9)
	tx := spendTx(spent)
	acceptProofs(vmImpl, tx)
	require.NoError(t, vmImpl.mempool.AddTransaction(tx))

	built, err := vmImpl.BuildVertex(context.Background())
	require.NoError(t, err)
	vtx := built.(*Vertex)

	tipBefore, heightBefore := vmImpl.chain.Tip()

	db.refuse = true
	require.ErrorIs(t, vtx.Accept(context.Background()), errRefused)

	has, err := db.Database.Has(makeNullifierKey(spent))
	require.NoError(t, err)
	require.False(t, has)
	require.False(t, vmImpl.nullifierDB.IsNullifierSpent(spent))

	tip, height := vmImpl.chain.Tip()
	require.Equal(t, tipBefore, tip)
	require.Equal(t, heightBefore, height)
	require.True(t, vmImpl.mempool.HasTransaction(tx.ID))

	db.refuse = false
	require.NoError(t, vtx.Accept(context.Background()))
	require.True(t, vmImpl.nullifierDB.IsNullifierSpent(spent))
	tip, _ = vmImpl.chain.Tip()
	require.Equal(t, vtx.ID(), tip)
}

// TestGenesisIsDurableWithoutABlock pins the one mutation outside consensus.
// Left staged on the view, a genesis allocation would ride on whichever block
// committed first and vanish from a chain that never accepted one.
func TestGenesisIsDurableWithoutABlock(t *testing.T) {
	db := memdb.New()

	seeded := spendTx(nullifier(3))
	genesisBytes, err := json.Marshal(&Genesis{
		Timestamp:  1607144400,
		InitialTxs: []*Transaction{seeded},
	})
	require.NoError(t, err)

	vmImpl := &VM{}
	require.NoError(t, vmImpl.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: ids.GenerateTestID(), Log: log.NoLog{}},
		DB:       db,
		Genesis:  genesisBytes,
		ToEngine: make(chan vmcore.Message, 1),
		Log:      log.NoLog{},
	}))
	defer vmImpl.Shutdown(context.Background())

	// Straight from the database, behind the view: committed, not staged.
	has, err := db.Has(makeUTXOKey(seeded.Outputs[0].Commitment))
	require.NoError(t, err)
	require.True(t, has, "a genesis allocation is durable before any block exists")
}
