// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"encoding/binary"
	"errors"
	"sync"

	"github.com/luxfi/log"

	"github.com/luxfi/database"
)

// nullifierPrefix keys the spent set. A nullifier record is the height of the
// block that spent it.
const nullifierPrefix = 0x20

var errNullifierSpent = errors.New("zkvm: nullifier already spent")

// NullifierDB is the spent set: the whole of what stops a shielded note being
// spent twice.
type NullifierDB struct {
	db  database.Database
	log log.Logger

	// spent is the entire set, loaded at startup and never pruned — which is
	// why the count is read off it rather than kept beside it and reconciled.
	spent map[string]uint64 // nullifier -> height when spent

	mu sync.RWMutex
}

// NewNullifierDB creates a new nullifier database
func NewNullifierDB(db database.Database, log log.Logger) (*NullifierDB, error) {
	ndb := &NullifierDB{
		db:    db,
		log:   log,
		spent: make(map[string]uint64),
	}

	if err := ndb.load(); err != nil {
		return nil, err
	}

	return ndb, nil
}

// MarkNullifierSpent records a spend.
func (ndb *NullifierDB) MarkNullifierSpent(nullifier []byte, height uint64) error {
	ndb.mu.Lock()
	defer ndb.mu.Unlock()

	key := string(nullifier)
	if _, exists := ndb.spent[key]; exists {
		return errNullifierSpent
	}

	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, height)
	if err := ndb.db.Put(makeNullifierKey(nullifier), heightBytes); err != nil {
		return err
	}
	ndb.spent[key] = height

	ndb.log.Debug("Marked nullifier as spent",
		log.Uint64("height", height),
		log.Int("nullifiers", len(ndb.spent)),
	)

	return nil
}

// Spent reports whether a nullifier has been spent and at what height.
//
// It is ONE question with one answer, because the two it used to be —
// IsNullifierSpent returning a bool and GetNullifierHeight returning a height —
// could not report a failed read at all. `_, err := Get(key); return err == nil`
// answers "not spent" for a set that could not be read, and that answer is what
// lets an already-spent note be spent again. A read that failed is an error
// here, and verifyTransaction refuses the transaction rather than admitting it.
//
// A miss falls through to the records and returns what it finds without
// memoising it. Memoising would be a write on a path that holds only the read
// lock, and a read lock promises every other reader that nothing is changing:
// two callers missing at once would write the same map at the same time, which
// is a runtime throw, not a returned error. The write lock is not the answer
// either — it would serialise every reader of a path consensus and RPC both sit
// on, to save a lookup the set already answers.
func (ndb *NullifierDB) Spent(nullifier []byte) (uint64, bool, error) {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()

	if height, exists := ndb.spent[string(nullifier)]; exists {
		return height, true, nil
	}

	raw, err := ndb.db.Get(makeNullifierKey(nullifier))
	switch {
	case errors.Is(err, database.ErrNotFound):
		return 0, false, nil
	case err != nil:
		return 0, false, err
	case len(raw) != 8:
		return 0, false, errors.New("zkvm: nullifier record is not a height")
	}
	return binary.BigEndian.Uint64(raw), true, nil
}

// GetNullifierCount returns the number of spent nullifiers, counted off the set
// itself. Every record is loaded at startup and nullifiers are never pruned, so
// the set is the whole of them; a total kept alongside would be a second write
// that has to agree with the first, and this cannot disagree with what it
// describes.
func (ndb *NullifierDB) GetNullifierCount() uint64 {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()
	return uint64(len(ndb.spent))
}

// Nullifiers are permanent and MUST NOT be pruned or removed. Deleting a spent
// nullifier lets a previously spent note be spent again, so there is no
// removal path here — not for reorg, not for compaction. If storage becomes a
// concern, a Merkle accumulator is the compaction.

// load reads the whole set from the database.
func (ndb *NullifierDB) load() error {
	it := ndb.db.NewIteratorWithPrefix([]byte{nullifierPrefix})
	defer it.Release()

	for it.Next() {
		key, val := it.Key(), it.Value()
		if len(key) < 2 || len(val) != 8 {
			continue
		}
		ndb.spent[string(key[1:])] = binary.BigEndian.Uint64(val)
	}

	return it.Error()
}

// reload rebuilds the set from what the database now says. A block whose
// writes were discarded has had its nullifiers discarded with them, so a set
// that already recorded them must stop claiming those notes are spent —
// otherwise the block can never be applied again.
func (ndb *NullifierDB) reload() error {
	ndb.mu.Lock()
	defer ndb.mu.Unlock()

	ndb.spent = make(map[string]uint64)
	return ndb.load()
}

// makeNullifierKey creates a database key for a nullifier
func makeNullifierKey(nullifier []byte) []byte {
	key := make([]byte, 1+len(nullifier))
	key[0] = nullifierPrefix
	copy(key[1:], nullifier)
	return key
}

// Close closes the nullifier database
func (ndb *NullifierDB) Close() {
	ndb.mu.Lock()
	defer ndb.mu.Unlock()

	ndb.spent = nil
}
