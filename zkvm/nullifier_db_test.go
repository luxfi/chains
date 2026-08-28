// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"errors"
	"sync"
	"testing"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

// spentOf asks the spent set, and fails the test on a read that FAILED rather
// than reading it as "not spent" — which is the shape the production code had
// and the shape that reopens a double spend.
func spentOf(t *testing.T, ndb *NullifierDB, nullifier []byte) bool {
	t.Helper()
	_, spent, err := ndb.Spent(nullifier)
	require.NoError(t, err)
	return spent
}

// brokenDB fails every read with something that is NOT ErrNotFound.
type brokenDB struct {
	database.Database
	err error
}

func (d *brokenDB) Get([]byte) ([]byte, error) { return nil, d.err }

// TestSpentCountIsReadOffTheRecords pins that the count describes the records
// and cannot drift from them. It starts from the state a total kept alongside
// would disagree with: a record on disk with no counter beside it.
func TestSpentCountIsReadOffTheRecords(t *testing.T) {
	db := memdb.New()

	// The record landed; a counter write, had there been one, did not.
	require.NoError(t, db.Put(makeNullifierKey([]byte("orphan")), make([]byte, 8)))

	ndb, err := NewNullifierDB(db, log.NoLog{})
	require.NoError(t, err)
	require.True(t, spentOf(t, ndb, []byte("orphan")), "the set is rebuilt from the records")
	require.Equal(t, uint64(1), ndb.GetNullifierCount(),
		"the count is read off the records, so it cannot disagree with the set it describes")
}

// The count follows ordinary spending, and a nullifier is spent once.
func TestSpentCountFollowsTheSet(t *testing.T) {
	ndb, err := NewNullifierDB(memdb.New(), log.NoLog{})
	require.NoError(t, err)
	require.Zero(t, ndb.GetNullifierCount())

	require.NoError(t, ndb.MarkNullifierSpent([]byte("a"), 1))
	require.NoError(t, ndb.MarkNullifierSpent([]byte("b"), 2))
	require.Equal(t, uint64(2), ndb.GetNullifierCount())

	// The set is permanent: spending the same note again is refused, and there
	// is no removal path that could make room for it.
	require.ErrorIs(t, ndb.MarkNullifierSpent([]byte("a"), 3), errNullifierSpent)
	require.Equal(t, uint64(2), ndb.GetNullifierCount())

	height, spent, err := ndb.Spent([]byte("b"))
	require.NoError(t, err)
	require.True(t, spent)
	require.Equal(t, uint64(2), height, "the set records which block spent the note")

	_, spent, err = ndb.Spent([]byte("never"))
	require.NoError(t, err)
	require.False(t, spent)
}

// A read that FAILED is not "not spent". The old IsNullifierSpent ended
// `_, err := Get(key); return err == nil`, so an unreadable set answered "this
// note is unspent" for every note in it — and verifyTransaction, whose only
// double-spend gate that is, admitted the spend.
func TestFailedReadIsNotAnUnspentNote(t *testing.T) {
	boom := errors.New("disk gone")
	ndb, err := NewNullifierDB(memdb.New(), log.NoLog{})
	require.NoError(t, err)
	ndb.db = &brokenDB{Database: ndb.db, err: boom}

	_, spent, err := ndb.Spent([]byte("n"))
	require.ErrorIs(t, err, boom)
	require.False(t, spent)
}

// TestNullifierReadDoesNotWriteTheSet. Spent must not memoise what it loaded
// while holding only the read lock: a read lock promises every other reader
// that nothing is changing, so two callers missing at once would write the same
// map at the same time, which is a runtime throw that takes the process down
// rather than an error anyone can handle. Consensus and RPC both sit here.
func TestNullifierReadDoesNotWriteTheSet(t *testing.T) {
	ndb, err := NewNullifierDB(memdb.New(), log.NoLog{})
	require.NoError(t, err)
	require.NoError(t, ndb.MarkNullifierSpent([]byte("n"), 4))

	// A record on disk that the in-memory set does not know about is what a
	// memoising read would fill in.
	ndb.spent = map[string]uint64{}

	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			height, spent, err := ndb.Spent([]byte("n"))
			switch {
			case err != nil:
				t.Errorf("read failed: %v", err)
			case !spent:
				t.Error("record on disk read as unspent")
			case height != 4:
				t.Errorf("read height %d, want 4", height)
			}
		}()
	}
	readers.Wait()

	require.Empty(t, ndb.spent, "a read must not change the set it reads")
}

// TestShortRecordIsNotAHeight. Blocks are stored in the same database under
// their raw id, so the nullifier prefix can turn up over a value that is not a
// height. load already passes over anything that is not eight bytes; the read
// path has to agree with it, or reading one of those is a panic where a miss
// was meant.
func TestShortRecordIsNotAHeight(t *testing.T) {
	db := memdb.New()
	require.NoError(t, db.Put(makeNullifierKey([]byte("n")), []byte{1}))

	ndb, err := NewNullifierDB(db, log.NoLog{})
	require.NoError(t, err)
	require.Zero(t, ndb.GetNullifierCount())

	_, _, err = ndb.Spent([]byte("n"))
	require.ErrorContains(t, err, "not a height")
}

// A set that cannot be read at startup is not an empty set.
func TestUnreadableSetDoesNotOpen(t *testing.T) {
	boom := errors.New("iterator gone")
	_, err := NewNullifierDB(&failIterDB{Database: memdb.New(), err: boom}, log.NoLog{})
	require.ErrorIs(t, err, boom)
}

type failIterDB struct {
	database.Database
	err error
}

func (d *failIterDB) NewIteratorWithPrefix([]byte) database.Iterator {
	return &brokenIter{err: d.err}
}

type brokenIter struct {
	database.Iterator
	err error
}

func (i *brokenIter) Next() bool    { return false }
func (i *brokenIter) Error() error  { return i.err }
func (i *brokenIter) Release()      {}
func (i *brokenIter) Key() []byte   { return nil }
func (i *brokenIter) Value() []byte { return nil }
