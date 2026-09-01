// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"reflect"
	"sync"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

// TestRestartedNodeRefusesADuplicateCommitment. Block.Accept refuses a block
// carrying a commitment the set already holds. The set lives in
// memory and was never rebuilt, so that verdict depended on how recently the
// node was started: a restarted validator accepted what a running one refused,
// and the two ended up on different chains.
func TestRestartedNodeRefusesADuplicateCommitment(t *testing.T) {
	db := memdb.New()
	utxo := &UTXO{TxID: ids.ID{7}, Commitment: []byte("commitment"), Height: 3}

	live, err := NewUTXODB(db, log.NoLog{})
	require.NoError(t, err)
	require.NoError(t, live.AddUTXO(utxo))
	require.ErrorContains(t, live.AddUTXO(utxo), "already exists")
	require.Equal(t, uint64(1), live.GetUTXOCount())

	restarted, err := NewUTXODB(db, log.NoLog{})
	require.NoError(t, err)
	require.ErrorContains(t, restarted.AddUTXO(utxo), "already exists",
		"a restarted node must reach the same verdict as a running one")
	require.Equal(t, uint64(1), restarted.GetUTXOCount())
}

// TestUTXOCountIsReadOffTheRecords pins that the count describes the records and
// cannot drift from them. It starts from the state a total kept alongside would
// disagree with: a record on disk with no total beside it.
func TestUTXOCountIsReadOffTheRecords(t *testing.T) {
	db := memdb.New()
	utxo := &UTXO{TxID: ids.ID{1}, Commitment: []byte("orphan"), Height: 1}

	record := utxo.Marshal()
	require.NoError(t, db.Put(makeUTXOKey(utxo.Commitment), record))

	udb, err := NewUTXODB(db, log.NoLog{})
	require.NoError(t, err)
	require.Equal(t, uint64(1), udb.GetUTXOCount(),
		"the count is read off the records, so it cannot disagree with the set it describes")

	// There is no removal path: a spend is recorded by its nullifier, and
	// deleting the output the note names would destroy the record of it.
	typ := reflect.TypeOf(udb)
	for _, name := range []string{"RemoveUTXO", "PruneOldUTXOs", "Delete", "Clear"} {
		_, found := typ.MethodByName(name)
		require.False(t, found, "%s must not exist", name)
	}
}

// TestRestartRebuildsTheSet. The set decides whether a commitment already
// exists. It lives in memory, so a restart that left it empty had the node
// accepting an output it was already holding.
func TestRestartRebuildsTheSet(t *testing.T) {
	db := memdb.New()
	live, err := NewUTXODB(db, log.NoLog{})
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		require.NoError(t, live.AddUTXO(&UTXO{
			TxID: ids.ID{byte(i)}, OutputIndex: uint32(i),
			Commitment: []byte{'c', byte(i)}, Ciphertext: []byte{'n', byte(i)}, Height: 5,
		}))
	}

	restarted, err := NewUTXODB(db, log.NoLog{})
	require.NoError(t, err)
	require.Equal(t, uint64(3), restarted.GetUTXOCount(), "the set is rebuilt from the records")

	for i := 0; i < 3; i++ {
		utxo, err := restarted.GetUTXO([]byte{'c', byte(i)})
		require.NoError(t, err)
		require.Equal(t, uint64(5), utxo.Height)
		require.Equal(t, []byte{'n', byte(i)}, utxo.Ciphertext,
			"the body comes back whole, not just its key")
	}

	_, err = restarted.GetUTXO([]byte("never"))
	require.ErrorIs(t, err, errNoUTXO)
}

// TestUTXOReadDoesNotWriteTheSet. GetUTXO must not memoise what it loads while
// holding only the read lock, and a read lock promises every other reader that
// nothing is changing — so two clients asking for uncached commitments wrote
// the same map at the same time, which is a runtime throw that takes the
// process down rather than an error anyone can handle.
func TestUTXOReadDoesNotWriteTheSet(t *testing.T) {
	udb, err := NewUTXODB(memdb.New(), log.NoLog{})
	require.NoError(t, err)
	require.NoError(t, udb.AddUTXO(&UTXO{TxID: ids.ID{1}, Commitment: []byte("c"), Height: 1}))

	// A record on disk that the in-memory set does not know about is what a
	// memoising read would fill in.
	udb.utxoCache = map[string]uint64{}

	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			utxo, err := udb.GetUTXO([]byte("c"))
			switch {
			case err != nil:
				t.Errorf("read failed: %v", err)
			case utxo.Height != 1:
				t.Errorf("read height %d, want 1", utxo.Height)
			}
		}()
	}
	readers.Wait()

	require.Empty(t, udb.utxoCache, "a read must not change the set it reads")
}

// TestForeignRecordIsNotAUTXO. Blocks are stored in the same database under
// their raw 32-byte id, and one id in 256 begins with the UTXO prefix byte, so
// a prefix scan alone would adopt other people's records into the set. A record
// counts as a UTXO only when it names the commitment its own key is made of.
func TestForeignRecordIsNotAUTXO(t *testing.T) {
	db := memdb.New()

	record := (&UTXO{TxID: ids.ID{1}, Commitment: []byte("orphan"), Height: 1}).Marshal()
	foreign := ids.ID{utxoPrefix, 1}
	require.NoError(t, db.Put(foreign[:], record))

	udb, err := NewUTXODB(db, log.NoLog{})
	require.NoError(t, err)
	require.Zero(t, udb.GetUTXOCount(), "someone else's key is not a commitment")
}
