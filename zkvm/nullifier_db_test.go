// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"sync"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

// TestSpentCountIsReadOffTheRecords. The count used to be a running total
// written beside the records, so a node that died between the two writes came
// back with a number that disagreed with its own set — and one removal from
// there drove an unsigned counter below zero, reporting 1.8e19 spent notes to
// every dashboard from then on.
//
// Counting the set cannot disagree with the set, so this starts from the state
// that used to be unrecoverable: a record on disk with no counter beside it.
func TestSpentCountIsReadOffTheRecords(t *testing.T) {
	db := memdb.New()

	// The record landed; a counter write, had there been one, did not.
	require.NoError(t, db.Put(makeNullifierKey([]byte("orphan")), make([]byte, 8)))

	ndb, err := NewNullifierDB(db, log.NoLog{})
	require.NoError(t, err)
	require.True(t, ndb.IsNullifierSpent([]byte("orphan")), "the set is rebuilt from the records")
	require.Equal(t, uint64(1), ndb.GetNullifierCount(),
		"the count is read off the records, so it cannot disagree with the set it describes")

	require.NoError(t, ndb.RemoveNullifier([]byte("orphan")))
	require.False(t, ndb.IsNullifierSpent([]byte("orphan")))
	require.Zero(t, ndb.GetNullifierCount(),
		"removing the last record must leave zero, not wrap to 2^64-1")
}

// The count has to follow ordinary spending too, not just the recovery path.
func TestSpentCountFollowsTheSet(t *testing.T) {
	ndb, err := NewNullifierDB(memdb.New(), log.NoLog{})
	require.NoError(t, err)
	require.Zero(t, ndb.GetNullifierCount())

	require.NoError(t, ndb.MarkNullifierSpent([]byte("a"), 1))
	require.NoError(t, ndb.MarkNullifierSpent([]byte("b"), 1))
	require.Equal(t, uint64(2), ndb.GetNullifierCount())

	require.NoError(t, ndb.RemoveNullifier([]byte("a")))
	require.Equal(t, uint64(1), ndb.GetNullifierCount())

	// A nullifier that was never spent is not a removal, and must not be
	// counted as one.
	require.Error(t, ndb.RemoveNullifier([]byte("never")))
	require.Equal(t, uint64(1), ndb.GetNullifierCount())
}

// TestNullifierReadDoesNotWriteTheSet. GetNullifierHeight used to memoise what
// it loaded while holding only the read lock, and a read lock promises every
// other reader that nothing is changing — so two callers missing at once wrote
// the same map at the same time, which is a runtime throw that takes the
// process down rather than an error anyone can handle. Consensus and RPC both
// sit on this path.
func TestNullifierReadDoesNotWriteTheSet(t *testing.T) {
	ndb, err := NewNullifierDB(memdb.New(), log.NoLog{})
	require.NoError(t, err)
	require.NoError(t, ndb.MarkNullifierSpent([]byte("n"), 4))

	// A record on disk that the in-memory set does not know about is what a
	// memoising read would fill in.
	ndb.nullifierCache = map[string]uint64{}

	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			height, err := ndb.GetNullifierHeight([]byte("n"))
			switch {
			case err != nil:
				t.Errorf("read failed: %v", err)
			case height != 4:
				t.Errorf("read height %d, want 4", height)
			}
		}()
	}
	readers.Wait()

	require.Empty(t, ndb.nullifierCache, "a read must not change the set it reads")
}

// TestShortRecordIsNotAHeight. Blocks are stored in the same database under
// their raw id, so the nullifier prefix can turn up over a value that is not a
// height. loadNullifiers already passes over anything that is not eight bytes;
// the read path has to agree with it, or reading one of those is a panic where
// a miss was meant.
func TestShortRecordIsNotAHeight(t *testing.T) {
	db := memdb.New()
	require.NoError(t, db.Put(makeNullifierKey([]byte("n")), []byte{1}))

	ndb, err := NewNullifierDB(db, log.NoLog{})
	require.NoError(t, err)
	require.Zero(t, ndb.GetNullifierCount())

	_, err = ndb.GetNullifierHeight([]byte("n"))
	require.ErrorContains(t, err, "not found")
}
