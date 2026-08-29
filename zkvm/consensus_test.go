// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// newVM builds an initialized Z-Chain on a fresh memdb.
func newVM(t *testing.T) *VM {
	t.Helper()
	return newVMOn(t, ids.GenerateTestID(), 1)
}

func newVMOn(t *testing.T, chainID ids.ID, networkID uint32) *VM {
	t.Helper()
	vm := bootOn(t, memdb.New(), chainID, networkID, &Genesis{Timestamp: 1607144400})
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	return vm
}

// bootOn brings a Z-Chain up over db exactly as the node does.
func bootOn(t *testing.T, db database.Database, chainID ids.ID, networkID uint32, genesis *Genesis) *VM {
	t.Helper()

	raw, err := json.Marshal(genesis)
	require.NoError(t, err)

	// A NON-strict chain: acceptProofs seeds the verified-proof cache, and the
	// strict-PQ gate runs ahead of that cache by design. The default profile is
	// strict — TestZChain_DefaultIsStrictPQ pins that — and this is the
	// supported permissive deployment.
	config, err := json.Marshal(ZConfig{MaxTxPerBlock: 100, ProofCacheSize: 1000})
	require.NoError(t, err)

	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: chainID, NetworkID: networkID, Log: log.NoLog{}},
		DB:       db,
		Genesis:  raw,
		Config:   config,
		ToEngine: make(chan vmcore.Message, 1),
		Log:      log.NoLog{},
	}))
	return vm
}

// A chain that allocated its genesis and has not yet accepted a block must
// come back knowing it allocated. Seeding used to record no tip, so Open — for
// which a missing tip IS a fresh chain — reported this node fresh on every
// boot and asked for the allocation again. The UTXO set refuses a duplicate,
// so the second start failed: a node that could not restart until it produced
// a block, which it could not do without starting.
//
// The chain is held constant and only the node varies. A fresh chain id per
// boot would make a restart look like a different chain, and this test would
// pass for the wrong reason.
func TestARestartBeforeTheFirstBlockDoesNotAllocateAgain(t *testing.T) {
	db, chainID := memdb.New(), ids.GenerateTestID()
	allocation := spendTx(nullifier(200))
	genesis := &Genesis{Timestamp: 1607144400, InitialTxs: []*Transaction{allocation}}

	first := bootOn(t, db, chainID, 1, genesis)
	held, err := first.utxoDB.GetUTXO(allocation.Outputs[0].Commitment)
	require.NoError(t, err, "the allocation is in the set")
	root := first.root.Get()

	// A second VM over the same database is the restart. The first is left
	// open rather than shut down: Shutdown closes the base database, which the
	// node owns and a real restart re-opens, and closing it here would take the
	// disk out from under the node coming up.
	second := bootOn(t, db, chainID, 1, genesis)
	t.Cleanup(func() { _ = second.Shutdown(context.Background()) })

	again, err := second.utxoDB.GetUTXO(allocation.Outputs[0].Commitment)
	require.NoError(t, err, "and it is still there, once")
	require.Equal(t, held.Commitment, again.Commitment)
	require.Equal(t, root, second.root.Get(), "the allocation was not re-run")

	tip, height := second.chain.Tip()
	require.Equal(t, second.genesisBlock.ID(), tip, "the chain is still sitting on genesis")
	require.Zero(t, height)
}

// build assembles one block from the pool and returns it, having made its
// proofs verify.
func build(t *testing.T, vm *VM, txs ...*Transaction) *Block {
	t.Helper()
	acceptProofs(vm, txs...)
	for _, tx := range txs {
		require.NoError(t, vm.mempool.AddTransaction(tx))
	}
	built, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	return built.(*Block)
}

// A chain's identity is in every id it makes, and on none of its wire. Two
// chains given the same genesis and the same transaction produce different
// blocks, so one chain's block has no parent on the other rather than chaining
// onto it verbatim.
func TestChainBindingSeparatesTwoChains(t *testing.T) {
	id := ids.GenerateTestID()

	sameChain := newVMOn(t, id, 1).genesisBlock.ID()
	require.Equal(t, sameChain, newVMOn(t, id, 1).genesisBlock.ID(),
		"the same chain and the same genesis derive the same block")

	require.NotEqual(t, sameChain, newVMOn(t, ids.GenerateTestID(), 1).genesisBlock.ID(),
		"a different ChainID is a different chain")
	require.NotEqual(t, sameChain, newVMOn(t, id, 2).genesisBlock.ID(),
		"a different NetworkID is a different chain")

	// And the binding is nowhere in the bytes: two chains encode the block
	// identically and disagree only on what it is called.
	a, b := newVMOn(t, id, 1), newVMOn(t, ids.GenerateTestID(), 1)
	require.Equal(t, a.genesisBlock.Bytes(), b.genesisBlock.Bytes())
	require.NotEqual(t, a.genesisBlock.ID(), b.genesisBlock.ID())
}

// A genesis that names no timestamp is stamped 0, not "now". The timestamp is
// hashed into the genesis id, so a wall-clock reading gave every node a
// different chain for the same genesis file, and a different one per restart.
func TestGenesisIsDeterministic(t *testing.T) {
	g, err := ParseGenesis(nil)
	require.NoError(t, err)
	require.Zero(t, g.Timestamp)

	g, err = ParseGenesis([]byte(`{}`))
	require.NoError(t, err)
	require.Zero(t, g.Timestamp)

	g, err = ParseGenesis([]byte(`{"timestamp":7}`))
	require.NoError(t, err)
	require.EqualValues(t, 7, g.Timestamp)

	_, err = ParseGenesis([]byte(`{`))
	require.Error(t, err)

	id := ids.GenerateTestID()
	first := newVMOn(t, id, 1).genesisBlock.ID()
	time.Sleep(2 * time.Millisecond)
	require.Equal(t, first, newVMOn(t, id, 1).genesisBlock.ID(),
		"the same genesis file must name the same chain a moment later")
}

// A block extends the tip, or a block verified above it. Height alone is not
// that check: a block whose parent is a long-accepted ancestor satisfies
// height == parent+1 perfectly well, and accepting it rewinds the tip and
// leaves the height index naming an orphan as canonical.
func TestBlockMustExtendTheTip(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	genesis := vm.genesisBlock
	first := build(t, vm, spendTx(nullifier(1)))
	require.NoError(t, first.Verify(ctx))
	require.NoError(t, first.Accept(ctx))

	tip, height := vm.chain.Tip()
	require.Equal(t, first.ID(), tip)
	require.EqualValues(t, 1, height)

	// A sibling of the accepted block: same parent, same height, different
	// content. Its height still follows its parent's.
	sibling := &Block{
		ParentID_:      genesis.ID(),
		BlockHeight:    1,
		BlockTimestamp: first.BlockTimestamp,
		Txs:            []*Transaction{spendTx(nullifier(2))},
		vm:             vm,
	}
	acceptProofs(vm, sibling.Txs...)
	sibling.StateRoot = vm.computeStateRoot(sibling.Txs)

	require.ErrorIs(t, sibling.Verify(ctx), chain.ErrNotOnTip)

	// The tip did not move, and the height index still names the block the
	// chain accepted.
	at1, err := vm.GetBlockIDAtHeight(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, first.ID(), at1)
}

// The tip moves between Verify and Accept — a sibling accepted concurrently is
// exactly that window — so Accept asks again.
func TestAcceptRecheckesTheTip(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	first := build(t, vm, spendTx(nullifier(1)))
	require.NoError(t, first.Verify(ctx))

	// A competitor verifies against the same tip and is accepted first.
	winner := &Block{
		ParentID_:      vm.genesisBlock.ID(),
		BlockHeight:    1,
		BlockTimestamp: first.BlockTimestamp,
		Txs:            []*Transaction{spendTx(nullifier(9))},
		vm:             vm,
	}
	acceptProofs(vm, winner.Txs...)
	winner.StateRoot = vm.computeStateRoot(winner.Txs)
	require.NoError(t, winner.Verify(ctx))
	require.NoError(t, winner.Accept(ctx))

	// The block that verified against the old tip is refused, not written.
	require.ErrorIs(t, first.Accept(ctx), chain.ErrNotOnTip)

	tip, _ := vm.chain.Tip()
	require.Equal(t, winner.ID(), tip)
	require.False(t, spentOf(t, vm.nullifierDB, nullifier(1)),
		"a block that was not accepted spent nothing")
}

// One store, two shapes, one tip, accepted at once. A vertex is not a block —
// it has several parents and no timestamp — but it changes state the same way
// and through the same store, which keeps a single tip for both. Neither is
// sequenced behind the other here: the tip each is judged against is whatever
// the store holds when it lets that one in.
func TestABlockAndAVertexRaceForOneTip(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	// The vertex, assembled the way the DAG engine assembles one.
	vtx := spendTx(nullifier(1))
	acceptProofs(vm, vtx)
	require.NoError(t, vm.mempool.AddTransaction(vtx))
	built, err := vm.BuildVertex(ctx)
	require.NoError(t, err)
	v := built.(*Vertex)

	// A block on the same parent, spending a different note.
	btx := spendTx(nullifier(2))
	acceptProofs(vm, btx)
	b := &Block{
		ParentID_:      vm.genesisBlock.ID(),
		BlockHeight:    1,
		BlockTimestamp: time.Now().Unix(),
		Txs:            []*Transaction{btx},
		vm:             vm,
	}
	b.StateRoot = vm.computeStateRoot(b.Txs)

	require.NoError(t, v.Verify(ctx))
	require.NoError(t, b.Verify(ctx), "both check out against the tip they share")

	won, lost := race(t, v.Accept, b.Accept)
	require.NoError(t, won)
	require.ErrorIs(t, lost, chain.ErrNotOnTip)

	tip, height := vm.chain.Tip()
	require.EqualValues(t, 1, height, "one of them landed, not both")
	require.Contains(t, []ids.ID{v.ID(), b.ID()}, tip)
	require.Equal(t, tip == v.ID(), spentOf(t, vm.nullifierDB, nullifier(1)),
		"the vertex's note is spent exactly when the vertex is the tip")
	require.Equal(t, tip == b.ID(), spentOf(t, vm.nullifierDB, nullifier(2)),
		"and the block's exactly when the block is")
}

// race runs two accepts at the same time and returns them as the one that
// landed and the one that did not. Both failing, or both landing, is reported
// as such rather than hidden: the caller holds one of each.
func race(t *testing.T, accept ...func(context.Context) error) (won, lost error) {
	t.Helper()
	errs := make(chan error, len(accept))
	start := make(chan struct{})
	for _, a := range accept {
		go func(a func(context.Context) error) {
			<-start
			errs <- a(context.Background())
		}(a)
	}
	close(start)

	won, lost = <-errs, <-errs
	if won != nil {
		won, lost = lost, won
	}
	return won, lost
}

func TestBlockVerifyRefusals(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)
	parent := vm.genesisBlock

	valid := func() *Block {
		tx := spendTx(nullifier(1))
		acceptProofs(vm, tx)
		b := &Block{
			ParentID_:      parent.ID(),
			BlockHeight:    1,
			BlockTimestamp: parent.BlockTimestamp + 1,
			Txs:            []*Transaction{tx},
			vm:             vm,
		}
		b.StateRoot = vm.computeStateRoot(b.Txs)
		return b
	}
	require.NoError(t, valid().Verify(ctx))

	t.Run("genesis with a parent", func(t *testing.T) {
		b := valid()
		b.BlockHeight = 0
		require.ErrorIs(t, b.Verify(ctx), errInvalidBlock)
	})

	t.Run("more transactions than this node would build", func(t *testing.T) {
		b := valid()
		b.Txs = make([]*Transaction, vm.config.MaxTxPerBlock+1)
		for i := range b.Txs {
			b.Txs[i] = spendTx(nullifier(byte(i)))
		}
		require.ErrorIs(t, b.Verify(ctx), errInvalidBlock)
	})

	t.Run("timestamp beyond the skew allowance", func(t *testing.T) {
		b := valid()
		b.BlockTimestamp = time.Now().Unix() + maxClockSkew + 5
		require.ErrorIs(t, b.Verify(ctx), errFutureBlock)
	})

	t.Run("one note spent twice", func(t *testing.T) {
		b := valid()
		b.Txs = []*Transaction{spendTx(nullifier(1)), spendTx(nullifier(1))}
		acceptProofs(vm, b.Txs...)
		b.StateRoot = vm.computeStateRoot(b.Txs)
		require.ErrorIs(t, b.Verify(ctx), errDuplicateNullifier)
	})

	t.Run("a transaction the proposer could not have built", func(t *testing.T) {
		b := valid()
		b.Txs[0].Type = TransactionType(99)
		b.StateRoot = vm.computeStateRoot(b.Txs)
		require.ErrorIs(t, b.Verify(ctx), errInvalidTransactionType)
	})

	t.Run("a transaction that expired before this height", func(t *testing.T) {
		b := valid()
		b.Txs[0].Expiry = 0
		b.Txs[0].Expiry = 0
		acceptProofs(vm, b.Txs...)
		b.StateRoot = vm.computeStateRoot(b.Txs)
		require.ErrorIs(t, b.Verify(ctx), errNoExpiry)

		b = valid()
		b.BlockHeight = 5
		b.Txs[0].Expiry = 1
		acceptProofs(vm, b.Txs...)
		b.StateRoot = vm.computeStateRoot(b.Txs)
		require.ErrorIs(t, b.Verify(ctx), errExpired)
	})

	t.Run("a parent nothing can resolve", func(t *testing.T) {
		b := valid()
		b.ParentID_ = ids.GenerateTestID()
		require.Error(t, b.Verify(ctx))
	})

	t.Run("a height that does not follow its parent", func(t *testing.T) {
		b := valid()
		b.BlockHeight = 2
		require.ErrorIs(t, b.Verify(ctx), errInvalidHeight)
	})

	t.Run("a timestamp behind its parent", func(t *testing.T) {
		b := valid()
		b.BlockTimestamp = parent.BlockTimestamp - 1
		require.ErrorIs(t, b.Verify(ctx), errInvalidTimestamp)
	})

	t.Run("a state root that is not the one the block earns", func(t *testing.T) {
		b := valid()
		b.StateRoot = make([]byte, 32)
		require.ErrorIs(t, b.Verify(ctx), errInvalidStateRoot)
	})
}

// A parent that resolves to something that is not a block is not a parent. The
// store holds both shapes, so asking for a block by a vertex id has an answer
// and it is not one the caller can use.
func TestAVertexIsNotAParentBlock(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	tx := spendTx(nullifier(3))
	acceptProofs(vm, tx)
	require.NoError(t, vm.mempool.AddTransaction(tx))

	built, err := vm.BuildVertex(ctx)
	require.NoError(t, err)
	vtx := built.(*Vertex)
	require.NoError(t, vtx.Verify(ctx))
	require.NoError(t, vtx.Accept(ctx))

	_, err = vm.GetBlock(ctx, vtx.ID())
	require.ErrorContains(t, err, "is not a block")
}

func TestBlockAccessorsAndSummary(t *testing.T) {
	vm := newVM(t)
	tx := spendTx(nullifier(4))
	b := &Block{
		ParentID_:      ids.ID{2},
		BlockHeight:    5,
		BlockTimestamp: 1_700_000_000,
		Txs:            []*Transaction{tx},
		StateRoot:      []byte("root"),
		vm:             vm,
	}

	require.Equal(t, ids.ID{2}, b.Parent())
	require.Equal(t, ids.ID{2}, b.ParentID())
	require.EqualValues(t, 5, b.Height())
	require.Equal(t, time.Unix(1_700_000_000, 0), b.Timestamp())
	require.Equal(t, uint8(choices.Unknown), b.Status())
	require.NotEmpty(t, b.Bytes())
	require.Equal(t, b.Bytes(), b.Bytes(), "the encoding is computed once")

	// Every field the block carries is part of its identity.
	before := b.ID()
	require.Equal(t, before, b.ID(), "the id is computed once")
	other := *b
	other.ID_, other.bytes = ids.Empty, nil
	other.StateRoot = []byte("different")
	require.NotEqual(t, before, other.ID())

	s := b.ToSummary()
	require.Equal(t, b.ID(), s.ID)
	require.EqualValues(t, 5, s.Height)
	require.EqualValues(t, 1_700_000_000, s.Timestamp)
	require.Equal(t, 1, s.TxCount)
	require.Equal(t, []byte("root"), s.StateRoot)
}

// A rejected block returns what it carried to the pool, and is forgotten.
func TestRejectReturnsTheTransactions(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	blk := build(t, vm, spendTx(nullifier(5)))
	require.NoError(t, blk.Verify(ctx))
	vm.mempool.RemoveTransaction(blk.Txs[0].ID)
	require.Zero(t, vm.mempool.Size())

	require.NoError(t, blk.Reject(ctx))
	require.Equal(t, uint8(choices.Rejected), blk.Status())
	require.Equal(t, 1, vm.mempool.Size(), "a rejected block's transactions are still pending")

	_, err := vm.GetBlock(ctx, blk.ID())
	require.Error(t, err, "a rejected block is not one the chain holds")
}

// Assembly clamps its timestamp to the parent's. A parent may legally be up to
// maxClockSkew ahead of this node's clock, and Verify refuses a block below its
// parent — so an unclamped time.Now() builds what this node itself refuses.
func TestBuildClampsToTheParentTimestamp(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	// A parent stamped in the future, within the allowance.
	ahead := time.Now().Unix() + maxClockSkew - 5
	first := build(t, vm, spendTx(nullifier(1)))
	first.BlockTimestamp = ahead
	first.ID_ = ids.Empty
	first.bytes = nil
	require.NoError(t, first.Verify(ctx))
	require.NoError(t, first.Accept(ctx))

	second := build(t, vm, spendTx(nullifier(2)))
	require.GreaterOrEqual(t, second.BlockTimestamp, ahead,
		"a block built on a parent ahead of this clock must not fall behind it")
	require.NoError(t, second.Verify(ctx))
}

// Assembly runs the predicate Verify runs, and drops what it cannot build.
// Without that, a transaction with an out-of-range Type went into every block
// and was refused by every node including the proposer, forever.
func TestAssemblyDropsWhatItCannotBuild(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	poison := spendTx(nullifier(1))
	poison.Type = TransactionType(99)
	poison.ID = poison.ComputeID()
	acceptProofs(vm, poison)
	require.NoError(t, vm.mempool.AddTransaction(poison))
	require.Equal(t, 1, vm.mempool.Size())

	_, err := vm.BuildBlock(ctx)
	require.ErrorIs(t, err, errNoTransactions)
	require.Zero(t, vm.mempool.Size(), "the pool must not keep what no block can carry")

	// The same for the vertex path.
	require.NoError(t, vm.mempool.AddTransaction(poison))
	_, err = vm.BuildVertex(ctx)
	require.ErrorIs(t, err, errNoTransactions)
	require.Zero(t, vm.mempool.Size())

	// And with nothing pending at all.
	_, err = vm.BuildBlock(ctx)
	require.ErrorIs(t, err, errNoTransactions)
	_, err = vm.BuildVertex(ctx)
	require.ErrorIs(t, err, errNoTransactions)
}

// A block the chain has passed makes room in the pool. Assembly removes what
// it PUTS IN a block; nothing else removed a transaction the chain has moved
// past, so one that never fits in a block — because better-paying ones keep
// filling it — held a slot forever, and a pool full of those refuses every
// honest arrival paying the same floor.
func TestAcceptDrainsWhatTheChainHasPassed(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)
	vm.config.MaxTxPerBlock = 1

	// A cheap transaction that expires at height 1, and richer ones that keep
	// crowding it out of every block.
	stale := spendTx(nullifier(8))
	stale.Expiry = 1
	stale.Fee = 1
	stale.ID = stale.ComputeID()
	acceptProofs(vm, stale)
	require.NoError(t, vm.mempool.AddTransaction(stale))

	for height := 1; height <= 2; height++ {
		rich := spendTx(nullifier(byte(20 + height)))
		rich.Fee = 1 << 40
		rich.ID = rich.ComputeID()
		acceptProofs(vm, rich)
		require.NoError(t, vm.mempool.AddTransaction(rich))

		built, err := vm.BuildBlock(ctx)
		require.NoError(t, err)
		blk := built.(*Block)
		require.Equal(t, []*Transaction{rich}, blk.Txs, "the block took the richer transaction")

		require.NoError(t, blk.Verify(ctx))
		require.NoError(t, blk.Accept(ctx))

		if height == 1 {
			require.Equal(t, 1, vm.mempool.Size(),
				"the chain has not passed the height it expires at yet")
		}
	}

	require.Zero(t, vm.mempool.Size(),
		"a transaction the chain has moved past holds no slot")
}

func TestVertexRefusals(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	tx := spendTx(nullifier(1))
	acceptProofs(vm, tx)
	require.NoError(t, vm.mempool.AddTransaction(tx))
	built, err := vm.BuildVertex(ctx)
	require.NoError(t, err)
	valid := built.(*Vertex)

	require.EqualValues(t, 0, valid.Epoch())
	require.Equal(t, []ids.ID{vm.genesisBlock.ID()}, valid.Parents())
	require.Len(t, valid.Txs(), 1)
	require.Equal(t, choices.Processing, valid.Status())
	require.NoError(t, valid.Verify(ctx))

	t.Run("more transactions than this node would build", func(t *testing.T) {
		v := *valid
		v.txs = make([]*Transaction, vm.config.MaxTxPerBlock+1)
		for i := range v.txs {
			v.txs[i] = spendTx(nullifier(byte(i)))
		}
		require.ErrorIs(t, v.Verify(ctx), errInvalidBlock)
	})

	t.Run("parents that do not name the tip", func(t *testing.T) {
		v := *valid
		v.parents = []ids.ID{ids.GenerateTestID()}
		require.ErrorIs(t, v.Verify(ctx), chain.ErrNotOnTip)
		require.ErrorIs(t, v.Accept(ctx), chain.ErrNotOnTip)

		v.parents = nil
		require.ErrorIs(t, v.Verify(ctx), chain.ErrNotOnTip)
		require.ErrorIs(t, v.Accept(ctx), chain.ErrNotOnTip)

		// A vertex naming SEVERAL parents extends no single block, and the
		// store keeps one tip. Naming the tip among them is not naming it.
		tip, _ := vm.chain.Tip()
		v.parents = []ids.ID{tip, ids.GenerateTestID()}
		require.ErrorIs(t, v.Verify(ctx), chain.ErrNotOnTip)
		require.ErrorIs(t, v.Accept(ctx), chain.ErrNotOnTip)
	})

	t.Run("a height that does not follow the tip", func(t *testing.T) {
		v := *valid
		v.height = 1 << 40
		require.ErrorIs(t, v.Verify(ctx), errInvalidHeight)
	})

	t.Run("one note spent twice", func(t *testing.T) {
		v := *valid
		v.txs = []*Transaction{spendTx(nullifier(1)), spendTx(nullifier(1))}
		acceptProofs(vm, v.txs...)
		require.ErrorIs(t, v.Verify(ctx), errDuplicateNullifier)
	})

	t.Run("a transaction no block could carry", func(t *testing.T) {
		v := *valid
		bad := spendTx(nullifier(2))
		bad.Type = TransactionType(99)
		acceptProofs(vm, bad)
		v.txs = []*Transaction{bad}
		require.ErrorIs(t, v.Verify(ctx), errInvalidTransactionType)
	})

	t.Run("rejected, and its transactions returned", func(t *testing.T) {
		v := *valid
		vm.mempool.RemoveTransaction(tx.ID)
		require.NoError(t, v.Reject(ctx))
		require.Equal(t, choices.Rejected, v.Status())
		require.Equal(t, 1, vm.mempool.Size())
	})
}

func TestVertexConflictsAcrossTheInterface(t *testing.T) {
	vm := newVM(t)
	a := &Vertex{vm: vm, txs: []*Transaction{spendTx(nullifier(1))}}
	b := &Vertex{vm: vm, txs: []*Transaction{spendTx(nullifier(1))}}
	c := &Vertex{vm: vm, txs: []*Transaction{spendTx(nullifier(2))}}

	require.True(t, a.ConflictsVertex(b))
	require.False(t, a.ConflictsVertex(c))
	require.False(t, a.ConflictsVertex(notAVertex{}))
}

type notAVertex struct{ vertexShape }

// vertexShape satisfies the interface without being a *Vertex.
type vertexShape interface {
	ID() ids.ID
	Bytes() []byte
	Height() uint64
	Epoch() uint32
	Parents() []ids.ID
	Txs() []ids.ID
	Status() choices.Status
	Verify(context.Context) error
	Accept(context.Context) error
	Reject(context.Context) error
}

// A vertex carries exactly the bytes it was sent. Trailing bytes rode along in
// v.bytes — which is what the store writes to disk — so one logical vertex had
// unboundedly many encodings under one id, and a peer could park megabytes
// under a legitimate one.
func TestVertexWireIsCanonical(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	tx := spendTx(nullifier(1))
	acceptProofs(vm, tx)
	require.NoError(t, vm.mempool.AddTransaction(tx))
	built, err := vm.BuildVertex(ctx)
	require.NoError(t, err)
	raw := built.Bytes()

	parsed, err := vm.ParseVertex(ctx, raw)
	require.NoError(t, err)
	require.Equal(t, built.ID(), parsed.ID())
	require.Equal(t, raw, parsed.Bytes())

	for _, tail := range [][]byte{{0}, {0xFF}, make([]byte, 64)} {
		_, err := vm.ParseVertex(ctx, append(append([]byte(nil), raw...), tail...))
		require.ErrorIs(t, err, errTrailingBytes, "trailing %d bytes accepted", len(tail))
	}
}

func TestVertexWireRefusesTruncation(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	_, err := vm.ParseVertex(ctx, make([]byte, 15))
	require.ErrorIs(t, err, errInvalidBlock)

	u32 := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		return b
	}
	head := func(height uint64, parents uint32) []byte {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, height)
		return append(b, append(u32(0), u32(parents)...)...)
	}

	// A parent count the remaining bytes cannot back.
	_, err = vm.ParseVertex(ctx, head(1, 1<<20))
	require.ErrorIs(t, err, errInvalidBlock)

	// No room for the transaction count.
	_, err = vm.ParseVertex(ctx, head(1, 0))
	require.ErrorIs(t, err, errInvalidBlock)

	// A transaction count the remaining bytes cannot back.
	_, err = vm.ParseVertex(ctx, append(head(1, 0), u32(1<<20)...))
	require.ErrorIs(t, err, errInvalidBlock)

	// A declared transaction length past the end.
	_, err = vm.ParseVertex(ctx, append(head(1, 0), append(u32(1), u32(1<<20)...)...))
	require.ErrorIs(t, err, errInvalidBlock)

	// A length prefix with no transaction after it.
	_, err = vm.ParseVertex(ctx, append(head(1, 0), u32(1)...))
	require.ErrorIs(t, err, errInvalidBlock)

	// A transaction body that is not a transaction.
	body := []byte("not a frame")
	_, err = vm.ParseVertex(ctx, append(head(1, 0), append(u32(1), append(u32(uint32(len(body))), body...)...)...))
	require.Error(t, err)

	// A parent that IS backed round-trips.
	withParent := append(head(1, 1), make([]byte, 32)...)
	v, err := vm.ParseVertex(ctx, append(withParent, u32(0)...))
	require.NoError(t, err)
	require.Len(t, v.Parents(), 1)
}

// The height index names blocks the chain accepted, and the encoding a block
// reports is the encoding its id was taken over.
func TestParsedBlockKeepsItsBytesAndItsIdentity(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	blk := build(t, vm, spendTx(nullifier(1)))
	raw := blk.Bytes()

	parsed, err := vm.ParseBlock(ctx, raw)
	require.NoError(t, err)
	require.Equal(t, blk.ID(), parsed.ID())
	require.Equal(t, raw, parsed.Bytes())

	_, err = vm.ParseBlock(ctx, []byte("not a frame"))
	require.Error(t, err)
}

func TestVMLifecycle(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	require.NoError(t, vm.SetState(ctx, 0))
	v, err := vm.Version(ctx)
	require.NoError(t, err)
	require.Equal(t, Version.String(), v)

	require.NoError(t, vm.SetPreference(ctx, vm.genesisBlock.ID()))

	handlers, err := vm.CreateHandlers(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, handlers)

	mux, err := vm.NewHTTPHandler(ctx)
	require.NoError(t, err)
	require.NotNil(t, mux)

	require.NoError(t, vm.Connected(ctx, ids.EmptyNodeID, nil))
	require.NoError(t, vm.Disconnected(ctx, ids.EmptyNodeID))
	require.NoError(t, vm.Request(ctx, ids.EmptyNodeID, 0, time.Now(), nil))
	require.NoError(t, vm.Response(ctx, ids.EmptyNodeID, 0, nil))
	require.NoError(t, vm.RequestFailed(ctx, ids.EmptyNodeID, 0, nil))
	require.NoError(t, vm.Gossip(ctx, ids.EmptyNodeID, nil))
	require.NoError(t, vm.CrossChainRequest(ctx, ids.Empty, 0, time.Now(), nil))
	require.NoError(t, vm.CrossChainResponse(ctx, ids.Empty, 0, nil))
	require.NoError(t, vm.CrossChainRequestFailed(ctx, ids.Empty, 0, nil))

	// WaitForEvent reports the work the mempool has, and gives up with the
	// caller.
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	_, err = vm.WaitForEvent(stopped)
	require.ErrorIs(t, err, context.Canceled)
}

func TestInitializeRefusals(t *testing.T) {
	ctx := context.Background()
	boot := func(init vmcore.Init) error { return (&VM{}).Initialize(ctx, init) }

	require.ErrorContains(t, boot(vmcore.Init{}), "runtime is nil")
	require.ErrorContains(t, boot(vmcore.Init{Runtime: &runtime.Runtime{}}), "database is nil")
	require.ErrorContains(t, boot(vmcore.Init{
		Runtime: &runtime.Runtime{}, DB: memdb.New(),
	}), "invalid logger type")
	require.ErrorContains(t, boot(vmcore.Init{
		Runtime: &runtime.Runtime{Log: log.NoLog{}}, DB: memdb.New(), Config: []byte(`{`),
	}), "failed to parse config")
	require.ErrorContains(t, boot(vmcore.Init{
		Runtime: &runtime.Runtime{Log: log.NoLog{}}, DB: memdb.New(), Genesis: []byte(`{`),
	}), "failed to parse genesis")

	// A config naming no bound gets the default rather than none.
	vm := &VM{}
	require.NoError(t, vm.Initialize(ctx, vmcore.Init{
		Runtime: &runtime.Runtime{Log: log.NoLog{}},
		DB:      memdb.New(),
		Config:  []byte(`{"strictPQ":false}`),
		Log:     log.NoLog{},
	}))
	require.EqualValues(t, defaultMaxTxPerBlock, vm.config.MaxTxPerBlock)
	require.EqualValues(t, defaultProofCacheSize, vm.config.ProofCacheSize)
	require.NoError(t, vm.Shutdown(ctx))
}

// Genesis allocates outside any block, and it is committed on its own: staged,
// it would ride on whichever block landed first and vanish from a chain that
// never accepted one.
func TestGenesisAllocationIsDurable(t *testing.T) {
	ctx := context.Background()
	db := memdb.New()

	tx := spendTx(nullifier(1))
	genesis, err := json.Marshal(&Genesis{Timestamp: 1, InitialTxs: []*Transaction{tx}})
	require.NoError(t, err)

	boot := func() *VM {
		vm := &VM{}
		require.NoError(t, vm.Initialize(ctx, vmcore.Init{
			Runtime: &runtime.Runtime{ChainID: ids.ID{9}, Log: log.NoLog{}},
			DB:      db,
			Genesis: genesis,
			Log:     log.NoLog{},
		}))
		return vm
	}

	first := boot()
	require.EqualValues(t, 1, first.utxoDB.GetUTXOCount())
	root := append([]byte(nil), first.root.Get()...)

	restarted := boot()
	require.EqualValues(t, 1, restarted.utxoDB.GetUTXOCount(),
		"a restarted node holds what genesis allocated")
	require.Equal(t, root, restarted.root.Get())
	require.NoError(t, restarted.Shutdown(ctx))
}

func TestHealthReportsTheChain(t *testing.T) {
	vm := newVM(t)
	h, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	require.True(t, h.Healthy)
	require.Equal(t, "0", h.Details["utxoCount"])
	require.Equal(t, "0", h.Details["nullifierCount"])
	require.Equal(t, "0", h.Details["lastBlockHeight"])
}
