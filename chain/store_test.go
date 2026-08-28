// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
)

// ---- a block that records what was asked of it ----

// testBlock writes one record per name it carries and counts its own Publish.
// Splitting Write from Publish is the property under test, so the test block
// keeps them honestly separate: Write only writes, Publish only publishes.
type testBlock struct {
	id        ids.ID
	parent    ids.ID
	height    uint64
	records   [][]byte
	failAfter int // records to write before failing; -1 never fails
	published int
	raw       []byte
}

func newBlock(id byte, parent ids.ID, height uint64, records ...string) *testBlock {
	b := &testBlock{
		id:        ids.ID{id},
		parent:    parent,
		height:    height,
		failAfter: -1,
		raw:       []byte{id, byte(height)},
	}
	for _, r := range records {
		b.records = append(b.records, []byte(r))
	}
	return b
}

var errWriteRefused = errors.New("write refused")

func (b *testBlock) ID() ids.ID           { return b.id }
func (b *testBlock) Parent() ids.ID       { return b.parent }
func (b *testBlock) ParentID() ids.ID     { return b.parent }
func (b *testBlock) Height() uint64       { return b.height }
func (b *testBlock) Timestamp() time.Time { return time.Unix(int64(b.height), 0) }
func (b *testBlock) Status() uint8        { return 0 }
func (b *testBlock) Bytes() []byte        { return b.raw }

func (b *testBlock) Verify(context.Context) error { return nil }
func (b *testBlock) Accept(context.Context) error { return nil }
func (b *testBlock) Reject(context.Context) error { return nil }

func (b *testBlock) Write(db database.Database) error {
	for i, r := range b.records {
		if b.failAfter >= 0 && i == b.failAfter {
			return errWriteRefused
		}
		if err := db.Put(r, []byte{byte(b.height)}); err != nil {
			return err
		}
	}
	return nil
}

func (b *testBlock) Publish() { b.published++ }

// ---- a database that can refuse ----

// refusingDB is a real database that fails its batch write once armed, which
// is how a commit fails in the field: the staged writes are complete and the
// flush to disk is what does not happen.
type refusingDB struct {
	database.Database
	refuseCommit bool
}

func (d *refusingDB) NewBatch() database.Batch {
	return &refusingBatch{Batch: d.Database.NewBatch(), db: d}
}

type refusingBatch struct {
	database.Batch
	db *refusingDB
}

var errCommitRefused = errors.New("commit refused")

func (b *refusingBatch) Write() error {
	if b.db.refuseCommit {
		return errCommitRefused
	}
	return b.Batch.Write()
}

// ---- fixture ----

type fixture struct {
	base    *refusingDB
	store   *Store
	reloads int
	genesis *testBlock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{base: &refusingDB{Database: memdb.New()}}
	f.store = New(f.base, func() error { f.reloads++; return nil })
	f.genesis = newBlock(0, ids.Empty, 0)
	_, fresh, err := f.store.Open(f.genesis, f.parse)
	require.NoError(t, err)
	require.True(t, fresh)
	return f
}

func (f *fixture) parse(raw []byte) (Block, error) {
	if len(raw) != 2 {
		return nil, errors.New("bad block")
	}
	return newBlock(raw[0], ids.Empty, uint64(raw[1])), nil
}

// committed reads straight from the base database, behind the view, so it says
// what actually landed rather than what is merely staged.
func (f *fixture) committed(t *testing.T, key []byte) bool {
	t.Helper()
	ok, err := f.base.Database.Has(key)
	require.NoError(t, err)
	return ok
}

// ---- the discipline ----

func TestAcceptCommitsTheBlockAndItsWritesTogether(t *testing.T) {
	f := newFixture(t)
	b := newBlock(1, f.genesis.ID(), 1, "alpha", "beta")

	require.NoError(t, f.store.Accept(b))

	// Everything the block touched is in committed state, not merely staged:
	// the records it wrote, the block itself, its height entry and the tip.
	require.True(t, f.committed(t, []byte("alpha")))
	require.True(t, f.committed(t, []byte("beta")))
	require.True(t, f.committed(t, blockKey(b.ID())))
	require.True(t, f.committed(t, heightKey(1)))
	require.True(t, f.committed(t, tipKey))

	tip, height := f.store.Tip()
	require.Equal(t, b.ID(), tip)
	require.Equal(t, uint64(1), height)
	require.Equal(t, 1, b.published)
	require.Zero(t, f.reloads, "nothing failed, so nothing was reloaded")
}

func TestAFailedWriteLeavesNothingAndDoesNotAdvance(t *testing.T) {
	f := newFixture(t)
	before, beforeHeight := f.store.Tip()

	b := newBlock(1, f.genesis.ID(), 1, "alpha", "beta", "gamma")
	b.failAfter = 2 // alpha and beta are staged, gamma refuses

	require.ErrorIs(t, f.store.Accept(b), errWriteRefused)

	// The two writes that succeeded are the whole point: they were staged, and
	// staged is not landed.
	require.False(t, f.committed(t, []byte("alpha")), "a discarded block leaves no record")
	require.False(t, f.committed(t, []byte("beta")))
	require.False(t, f.committed(t, []byte("gamma")))
	require.False(t, f.committed(t, blockKey(b.ID())))
	require.False(t, f.committed(t, heightKey(1)))
	require.False(t, f.committed(t, tipKey))

	// And the chain does not believe the block happened.
	tip, height := f.store.Tip()
	require.Equal(t, before, tip)
	require.Equal(t, beforeHeight, height)
	require.Zero(t, b.published, "a block that did not commit publishes nothing")
	require.Equal(t, 1, f.reloads, "the caches are rebuilt from what committed")

	// The writes that succeeded are still only staged, and staged writes that
	// are not discarded ride along on whatever commits next. That is the shape
	// the "landed nothing" check above cannot see, because a staged write and a
	// discarded one look identical until something commits.
	next := newBlock(2, f.genesis.ID(), 1, "delta")
	require.NoError(t, f.store.Accept(next))
	require.False(t, f.committed(t, []byte("alpha")), "the abandoned block's writes did not ride along")
	require.False(t, f.committed(t, []byte("beta")))
	require.True(t, f.committed(t, []byte("delta")))
}

func TestAFailedCommitLeavesNothingAndDoesNotAdvance(t *testing.T) {
	f := newFixture(t)
	before, beforeHeight := f.store.Tip()

	b := newBlock(1, f.genesis.ID(), 1, "alpha", "beta")
	f.base.refuseCommit = true

	require.ErrorIs(t, f.store.Accept(b), errCommitRefused)

	require.False(t, f.committed(t, []byte("alpha")))
	require.False(t, f.committed(t, []byte("beta")))
	require.False(t, f.committed(t, blockKey(b.ID())))
	require.False(t, f.committed(t, tipKey))

	tip, height := f.store.Tip()
	require.Equal(t, before, tip)
	require.Equal(t, beforeHeight, height)
	require.Zero(t, b.published)
	require.Equal(t, 1, f.reloads)

	// The staged writes are gone from the view too, so the next block does not
	// inherit them.
	f.base.refuseCommit = false
	next := newBlock(2, f.genesis.ID(), 1, "delta")
	require.NoError(t, f.store.Accept(next))
	require.False(t, f.committed(t, []byte("alpha")), "the abandoned block's writes did not ride along")
	require.True(t, f.committed(t, []byte("delta")))
}

func TestABlockWithNoEncodingIsRefusedWhole(t *testing.T) {
	f := newFixture(t)
	b := newBlock(1, f.genesis.ID(), 1, "alpha")
	b.raw = nil

	require.Error(t, f.store.Accept(b))
	require.False(t, f.committed(t, []byte("alpha")))
	tip, _ := f.store.Tip()
	require.Equal(t, f.genesis.ID(), tip)
}

func TestAReloadFailureIsReportedBesideItsCause(t *testing.T) {
	base := &refusingDB{Database: memdb.New()}
	broken := errors.New("caches unreadable")
	store := New(base, func() error { return broken })
	genesis := newBlock(0, ids.Empty, 0)
	_, _, err := store.Open(genesis, func([]byte) (Block, error) { return nil, nil })
	require.NoError(t, err)

	b := newBlock(1, genesis.ID(), 1, "alpha")
	b.failAfter = 0

	err = store.Accept(b)
	require.ErrorIs(t, err, errWriteRefused, "the cause is still reported")
	require.ErrorIs(t, err, broken, "and so is the failure to recover from it")
}

func TestTheChainStillWorksAfterAFailedBlock(t *testing.T) {
	f := newFixture(t)

	doomed := newBlock(1, f.genesis.ID(), 1, "alpha")
	doomed.failAfter = 0
	require.ErrorIs(t, f.store.Accept(doomed), errWriteRefused)

	good := newBlock(2, f.genesis.ID(), 1, "beta")
	require.NoError(t, f.store.Accept(good))

	tip, height := f.store.Tip()
	require.Equal(t, good.ID(), tip)
	require.Equal(t, uint64(1), height)
	require.True(t, f.committed(t, []byte("beta")))
}

// ---- blocks in flight ----

func TestTrackMakesABlockFindableAndPrunesWhatIsDecided(t *testing.T) {
	f := newFixture(t)

	one := newBlock(1, f.genesis.ID(), 1, "alpha")
	two := newBlock(2, one.ID(), 2, "beta")
	f.store.Track(one)
	f.store.Track(two)

	// A child resolves its parent while the parent is still in flight, which is
	// what lets a follower verify a run of blocks rather than only the first.
	got, err := f.store.Block(one.ID(), f.parse)
	require.NoError(t, err)
	require.Equal(t, one.ID(), got.ID())

	// A competitor at the same height that the engine simply abandons — it is
	// never accepted and never rejected, so nothing but pruning will ever
	// remove it.
	orphan := newBlock(7, f.genesis.ID(), 1, "orphan")
	f.store.Track(orphan)

	require.NoError(t, f.store.Accept(one))

	// Accepting height 1 decides everything at or below it.
	f.store.RLock()
	_, stillOne := f.store.flight[one.ID()]
	_, stillOrphan := f.store.flight[orphan.ID()]
	_, stillTwo := f.store.flight[two.ID()]
	f.store.RUnlock()
	require.False(t, stillOne, "an accepted block is no longer in flight")
	require.False(t, stillOrphan, "and neither is one the engine abandoned at that height")
	require.True(t, stillTwo, "a block above the tip is still in flight")

	// The accepted one is now found in committed state instead.
	got, err = f.store.Block(one.ID(), f.parse)
	require.NoError(t, err)
	require.Equal(t, one.ID(), got.ID())
}

func TestABlockAtOrBelowTheTipIsNeverTracked(t *testing.T) {
	f := newFixture(t)
	one := newBlock(1, f.genesis.ID(), 1)
	require.NoError(t, f.store.Accept(one))

	f.store.Track(newBlock(9, ids.Empty, 1))
	f.store.Track(newBlock(8, ids.Empty, 0))

	f.store.RLock()
	n := len(f.store.flight)
	f.store.RUnlock()
	require.Zero(t, n, "a block the chain has already passed is not in flight")
}

func TestDropForgetsABlockInFlight(t *testing.T) {
	f := newFixture(t)
	b := newBlock(1, f.genesis.ID(), 1)
	f.store.Track(b)
	f.store.Drop(b.ID())

	_, err := f.store.Block(b.ID(), f.parse)
	require.ErrorIs(t, err, ErrNoBlock)
}

func TestProposeBuildsOnTheTipAndTracksWhatItBuilt(t *testing.T) {
	f := newFixture(t)
	first := newBlock(1, f.genesis.ID(), 1)
	require.NoError(t, f.store.Accept(first))

	var sawParent ids.ID
	var sawHeight uint64
	built, err := f.store.Propose(func(parent ids.ID, height uint64) (Block, error) {
		sawParent, sawHeight = parent, height
		return newBlock(2, parent, height+1), nil
	})
	require.NoError(t, err)
	require.Equal(t, first.ID(), sawParent)
	require.Equal(t, uint64(1), sawHeight)

	got, err := f.store.Block(built.ID(), f.parse)
	require.NoError(t, err)
	require.Equal(t, built.ID(), got.ID())
}

func TestProposingNothingIsNotAnErrorAndTracksNothing(t *testing.T) {
	f := newFixture(t)
	built, err := f.store.Propose(func(ids.ID, uint64) (Block, error) { return nil, nil })
	require.NoError(t, err)
	require.Nil(t, built)

	f.store.RLock()
	n := len(f.store.flight)
	f.store.RUnlock()
	require.Zero(t, n)
}

// ---- what committed state answers ----

func TestIDAtHeightNamesOnlyAcceptedBlocks(t *testing.T) {
	f := newFixture(t)
	one := newBlock(1, f.genesis.ID(), 1)
	require.NoError(t, f.store.Accept(one))

	got, err := f.store.IDAtHeight(1)
	require.NoError(t, err)
	require.Equal(t, one.ID(), got)

	// A block merely in flight has no height entry: the index is written in the
	// same commit as the block, so it cannot name one the chain did not accept.
	f.store.Track(newBlock(2, one.ID(), 2))
	_, err = f.store.IDAtHeight(2)
	require.ErrorIs(t, err, ErrNoBlock)
}

func TestAcceptedIsTrueOfTheTipAndOfWhatIsBeneathIt(t *testing.T) {
	f := newFixture(t)
	one := newBlock(1, f.genesis.ID(), 1)
	two := newBlock(2, one.ID(), 2)
	require.NoError(t, f.store.Accept(one))
	require.NoError(t, f.store.Accept(two))

	require.True(t, f.store.Accepted(two.ID()), "the tip")
	require.True(t, f.store.Accepted(one.ID()), "and everything under it")

	inFlight := newBlock(3, two.ID(), 3)
	f.store.Track(inFlight)
	require.False(t, f.store.Accepted(inFlight.ID()), "but not one still in flight")
}

func TestOpenResumesFromTheRecordedTip(t *testing.T) {
	f := newFixture(t)
	one := newBlock(1, f.genesis.ID(), 1)
	require.NoError(t, f.store.Accept(one))

	// A second store over the same database is a restart.
	restarted := New(f.base, nil)
	at, fresh, err := restarted.Open(f.genesis, f.parse)
	require.NoError(t, err)
	require.False(t, fresh, "this chain has run before")
	require.Equal(t, one.ID(), at.ID())

	tip, height := restarted.Tip()
	require.Equal(t, one.ID(), tip)
	require.Equal(t, uint64(1), height)
}

func TestOpenOnAnEmptyStoreStartsAtGenesisAndSaysSo(t *testing.T) {
	store := New(memdb.New(), nil)
	genesis := newBlock(0, ids.Empty, 0)
	at, fresh, err := store.Open(genesis, func([]byte) (Block, error) { return nil, errors.New("unreachable") })
	require.NoError(t, err)
	require.True(t, fresh)
	require.Equal(t, genesis.ID(), at.ID())

	tip, height := store.Tip()
	require.Equal(t, genesis.ID(), tip)
	require.Zero(t, height)
}

func TestAnUnknownBlockIsReportedAsMissing(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.Block(ids.ID{99}, f.parse)
	require.ErrorIs(t, err, ErrNoBlock)
}

// TestConcurrentReadersDoNotRaceAnAccept runs under -race, where a second
// mutex over any of the store's state shows up as a data race rather than as a
// rare wrong answer.
func TestConcurrentReadersDoNotRaceAnAccept(t *testing.T) {
	f := newFixture(t)
	done := make(chan struct{})

	for i := 0; i < 4; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					f.store.Tip()
					f.store.Accepted(ids.ID{1})
					_, _ = f.store.IDAtHeight(1)
					_, _ = f.store.Block(ids.ID{1}, f.parse)
				}
			}
		}()
	}

	parent := f.genesis.ID()
	for h := uint64(1); h <= 50; h++ {
		b := newBlock(byte(h), parent, h)
		f.store.Track(b)
		require.NoError(t, f.store.Accept(b))
		parent = b.ID()
	}
	close(done)

	_, height := f.store.Tip()
	require.Equal(t, uint64(50), height)
}
