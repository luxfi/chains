// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"errors"
	"testing"

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

	// enter runs from ID, which the store calls first under its lock, so it
	// runs exactly when this block is admitted and not before.
	enter func()
	// stall runs from Write, so it holds the store's lock open for as long as
	// it blocks — which is how a test puts a second Accept behind this one.
	stall func()
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

// newGenesis is the block a chain starts from. Its id is deliberately not the
// zero id: a real genesis id is a hash, and a fixture whose genesis id IS
// ids.Empty cannot tell a chain sitting on genesis from a store that never
// opened, which is a difference the store has to act on.
func newGenesis() *testBlock { return newBlock(255, ids.Empty, 0) }

var errWriteRefused = errors.New("write refused")

func (b *testBlock) Parent() ids.ID { return b.parent }
func (b *testBlock) Height() uint64 { return b.height }
func (b *testBlock) Bytes() []byte  { return b.raw }

func (b *testBlock) ID() ids.ID {
	if b.enter != nil {
		b.enter()
	}
	return b.id
}

func (b *testBlock) Write(db database.Database) error {
	if b.stall != nil {
		b.stall()
	}
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
	store   *Store[*testBlock]
	reloads int
	genesis *testBlock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{base: &refusingDB{Database: memdb.New()}}
	f.store = New[*testBlock](f.base, func() error { f.reloads++; return nil })
	f.genesis = newGenesis()
	_, fresh, err := f.store.Open(f.genesis, f.parse)
	require.NoError(t, err)
	require.True(t, fresh)
	return f
}

func (f *fixture) parse(raw []byte) (*testBlock, error) {
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

// ---- what a block has to extend ----

// A block extends the tip or it is not accepted, and the tip it is judged
// against is the one at the commit. Verify reached its verdict against an
// earlier one.
func TestAcceptRefusesABlockThatDoesNotExtendTheTip(t *testing.T) {
	f := newFixture(t)
	first := newBlock(1, f.genesis.ID(), 1, "alpha")
	require.NoError(t, f.store.Accept(first))

	// A sibling: everything about it is impeccable except the parent, which
	// was the tip when it was built and is not the tip now.
	sibling := newBlock(2, f.genesis.ID(), 1, "beta")
	require.ErrorIs(t, f.store.Accept(sibling), ErrNotOnTip)

	require.False(t, f.committed(t, []byte("beta")), "a refused block writes nothing")
	require.False(t, f.committed(t, blockKey(sibling.ID())))
	require.Zero(t, sibling.published)
	require.Zero(t, f.reloads, "nothing was staged, so there is nothing to roll back")

	tip, height := f.store.Tip()
	require.Equal(t, first.ID(), tip, "the chain did not rewind")
	require.Equal(t, uint64(1), height)
	at1, err := f.store.IDAtHeight(1)
	require.NoError(t, err)
	require.Equal(t, first.ID(), at1, "and the height index still names what was accepted")
}

// A store that never opened knows no tip. A block naming no parent matches
// that emptiness exactly, so comparing parent to tip and nothing else would
// let one install itself as the beginning of a chain that has none.
func TestAcceptRefusesAStoreThatNeverOpened(t *testing.T) {
	store := New[*testBlock](memdb.New(), nil)
	require.ErrorIs(t, store.Accept(newBlock(1, ids.Empty, 1, "alpha")), ErrNotOpen)
}

// The tip moves DURING an accept, not between two of them. The second block is
// admitted to the lock only once the first has committed under it, and the tip
// it is then judged against is the one the first left — which is the whole
// reason the check lives here: a caller that asks before calling releases its
// reading, and the store reopens exactly this window.
//
// Nothing here is sequenced by hand. The first block holds the lock open from
// inside its own Write while the second is set going, and the second records
// what it saw at the moment the store let it in.
func TestATipThatMovesDuringAnAcceptIsCaughtUnderTheLock(t *testing.T) {
	f := newFixture(t)
	held, release := make(chan struct{}), make(chan struct{})

	mover := newBlock(1, f.genesis.ID(), 1, "alpha")
	mover.stall = func() { close(held); <-release }

	// Both name genesis: two siblings that verified against the same tip.
	victim := newBlock(2, f.genesis.ID(), 1, "beta")
	var moverPublishedWhenAdmitted int
	victim.enter = func() { moverPublishedWhenAdmitted = mover.published }

	moved := make(chan error, 1)
	go func() { moved <- f.store.Accept(mover) }()
	<-held // the mover is inside the lock and has committed nothing

	refused := make(chan error, 1)
	go func() { refused <- f.store.Accept(victim) }()

	close(release)
	require.NoError(t, <-moved)
	require.ErrorIs(t, <-refused, ErrNotOnTip)
	require.Equal(t, 1, moverPublishedWhenAdmitted,
		"the victim was let into the lock only after the mover had committed and published, "+
			"so the tip it was judged against is the one the mover left")

	tip, height := f.store.Tip()
	require.Equal(t, mover.ID(), tip, "the chain did not rewind")
	require.Equal(t, uint64(1), height)
	at1, err := f.store.IDAtHeight(1)
	require.NoError(t, err)
	require.Equal(t, mover.ID(), at1, "and the height index names the block that was accepted")
	require.False(t, f.committed(t, []byte("beta")))
	require.Zero(t, victim.published)
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
	store := New[*testBlock](base, func() error { return broken })
	genesis := newGenesis()
	_, _, err := store.Open(genesis, func([]byte) (*testBlock, error) { return nil, nil })
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

func TestSeedIsDurableBeforeAnyBlock(t *testing.T) {
	f := newFixture(t)

	require.NoError(t, f.store.Seed(func(db database.Database) error {
		return db.Put([]byte("allocation"), []byte{1})
	}))

	// Committed, not merely staged: a chain that never accepts a block must
	// still have what its genesis allocated.
	require.True(t, f.committed(t, []byte("allocation")))
}

// Seeding is what makes a chain no longer fresh, so the tip goes in the same
// commit as the allocation. Without it a chain that had allocated and not yet
// accepted a block reported itself fresh on every boot and allocated again —
// a duplicate its own state refuses, leaving a node that cannot restart until
// it produces a block it cannot produce.
func TestSeedRecordsTheTipSoTheNextBootIsNotFresh(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.store.Seed(func(db database.Database) error {
		return db.Put([]byte("allocation"), []byte{1})
	}))
	require.True(t, f.committed(t, tipKey))

	// A second store over the same database is a restart.
	restarted := New[*testBlock](f.base, nil)
	at, fresh, err := restarted.Open(f.genesis, f.parse)
	require.NoError(t, err)
	require.False(t, fresh, "this chain has allocated its genesis")
	require.Equal(t, f.genesis.ID(), at.ID(), "and is still sitting on it")

	tip, height := restarted.Tip()
	require.Equal(t, f.genesis.ID(), tip)
	require.Zero(t, height)
}

// A store that never opened has no genesis to seed, and seeding one anyway
// would write the zero id over the tip the chain has yet to record.
func TestSeedRefusesAStoreThatNeverOpened(t *testing.T) {
	base := memdb.New()
	store := New[*testBlock](base, nil)
	require.ErrorIs(t, store.Seed(func(db database.Database) error {
		return db.Put([]byte("allocation"), []byte{1})
	}), ErrNotOpen)

	recorded, err := base.Has(tipKey)
	require.NoError(t, err)
	require.False(t, recorded, "and nothing was written")
	allocated, err := base.Has([]byte("allocation"))
	require.NoError(t, err)
	require.False(t, allocated)
}

func TestASeedThatFailsLeavesNothing(t *testing.T) {
	f := newFixture(t)
	refused := errors.New("allocation refused")

	err := f.store.Seed(func(db database.Database) error {
		if err := db.Put([]byte("partial"), []byte{1}); err != nil {
			return err
		}
		return refused
	})
	require.ErrorIs(t, err, refused)
	require.False(t, f.committed(t, []byte("partial")))
	require.Equal(t, 1, f.reloads)

	// The tip is part of that nothing: a chain still owed its allocation must
	// come back fresh and be asked for it again.
	require.False(t, f.committed(t, tipKey))
	restarted := New[*testBlock](f.base, nil)
	_, fresh, err := restarted.Open(f.genesis, f.parse)
	require.NoError(t, err)
	require.True(t, fresh)

	// And what it staged does not ride along on the first block.
	require.NoError(t, f.store.Accept(newBlock(1, f.genesis.ID(), 1, "alpha")))
	require.False(t, f.committed(t, []byte("partial")))
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

	var saw *testBlock
	built, err := f.store.Propose(func(parent *testBlock) (*testBlock, error) {
		saw = parent
		return newBlock(2, parent.ID(), parent.Height()+1), nil
	})
	require.NoError(t, err)
	require.Equal(t, first.ID(), saw.ID())
	require.Equal(t, uint64(1), saw.Height())

	got, err := f.store.Block(built.ID(), f.parse)
	require.NoError(t, err)
	require.Equal(t, built.ID(), got.ID())
}

func TestAProposalThatRefusesTracksNothing(t *testing.T) {
	f := newFixture(t)
	nothing := errors.New("nothing to propose")

	built, err := f.store.Propose(func(*testBlock) (*testBlock, error) { return nil, nothing })
	require.ErrorIs(t, err, nothing)
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
	restarted := New[*testBlock](f.base, nil)
	at, fresh, err := restarted.Open(f.genesis, f.parse)
	require.NoError(t, err)
	require.False(t, fresh, "this chain has run before")
	require.Equal(t, one.ID(), at.ID())

	tip, height := restarted.Tip()
	require.Equal(t, one.ID(), tip)
	require.Equal(t, uint64(1), height)
}

func TestOpenOnAnEmptyStoreStartsAtGenesisAndSaysSo(t *testing.T) {
	store := New[*testBlock](memdb.New(), nil)
	genesis := newGenesis()
	at, fresh, err := store.Open(genesis, func([]byte) (*testBlock, error) { return nil, errors.New("unreachable") })
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

func TestAProposalFollowsTheEnginesPreference(t *testing.T) {
	f := newFixture(t)
	one := newBlock(1, f.genesis.ID(), 1)
	require.NoError(t, f.store.Accept(one))

	// A second block in flight above the tip, which the engine prefers.
	two := newBlock(2, one.ID(), 2)
	f.store.Track(two)
	f.store.Prefer(two.ID())

	var saw *testBlock
	_, err := f.store.Propose(func(parent *testBlock) (*testBlock, error) {
		saw = parent
		return newBlock(3, parent.ID(), parent.Height()+1), nil
	})
	require.NoError(t, err)
	require.Equal(t, two.ID(), saw.ID(), "a proposal extends the preferred fork")
	require.Equal(t, uint64(2), saw.Height())
}

func TestAPreferenceTheStoreCannotResolveFallsBackToTheTip(t *testing.T) {
	f := newFixture(t)
	one := newBlock(1, f.genesis.ID(), 1)
	require.NoError(t, f.store.Accept(one))
	f.store.Prefer(ids.ID{99})

	var saw *testBlock
	_, err := f.store.Propose(func(parent *testBlock) (*testBlock, error) {
		saw = parent
		return newBlock(3, parent.ID(), parent.Height()+1), nil
	})
	require.NoError(t, err)
	require.Equal(t, one.ID(), saw.ID())
}
