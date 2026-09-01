// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/log"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

// Database prefix for UTXO records: utxoPrefix || commitment -> marshalled UTXO.
const utxoPrefix = 0x10

// errNoUTXO — the commitment names no unspent output. Distinct from a read
// that failed, which is reported as the failure it is.
var errNoUTXO = errors.New("zkvm: no such utxo")

// UTXO represents an unspent transaction output
type UTXO struct {
	TxID        ids.ID `json:"txId"`
	OutputIndex uint32 `json:"outputIndex"`
	Commitment  []byte `json:"commitment"`  // Output commitment
	Ciphertext  []byte `json:"ciphertext"`  // Encrypted note
	EphemeralPK []byte `json:"ephemeralPK"` // Ephemeral public key
	Height      uint64 `json:"height"`      // Block height when created
}

// UTXODB manages the UTXO set
type UTXODB struct {
	db  database.Database
	log log.Logger

	// The set itself: commitment -> height when created. It is rebuilt from the
	// records at startup, so a restarted node knows the same commitments a
	// running one does — which is what Block.Accept consults to refuse a
	// duplicate. Membership and the count are read off it; the bodies stay in
	// the records.
	utxoCache map[string]uint64

	mu sync.RWMutex
}

// NewUTXODB creates a new UTXO database
func NewUTXODB(db database.Database, log log.Logger) (*UTXODB, error) {
	udb := &UTXODB{
		db:        db,
		log:       log,
		utxoCache: make(map[string]uint64),
	}

	if err := udb.loadUTXOs(); err != nil {
		return nil, err
	}

	return udb, nil
}

// AddUTXO adds a new UTXO to the set
func (udb *UTXODB) AddUTXO(utxo *UTXO) error {
	udb.mu.Lock()
	defer udb.mu.Unlock()

	// Create unique key from commitment
	commitmentStr := string(utxo.Commitment)

	// Check if already exists
	if _, exists := udb.utxoCache[commitmentStr]; exists {
		return errors.New("UTXO already exists")
	}

	if err := udb.db.Put(makeUTXOKey(utxo.Commitment), utxo.Marshal()); err != nil {
		return err
	}

	// Update the set and the height index
	udb.utxoCache[commitmentStr] = utxo.Height

	udb.log.Debug("Added UTXO",
		log.String("txID", utxo.TxID.String()),
		log.Uint32("outputIndex", utxo.OutputIndex),
		log.Uint64("height", utxo.Height),
	)

	return nil
}

// GetUTXO retrieves a UTXO by commitment.
//
// The body comes from the records every time. Memoising it here would be a
// write on a path that holds only the read lock, and a read lock promises every
// other reader that nothing is changing: two RPC clients asking for different
// commitments would write the same map at the same time, which is a runtime
// throw, not a returned error. The lock is still held so that a read cannot
// land between the record delete and the set delete a removal does together.
func (udb *UTXODB) GetUTXO(commitment []byte) (*UTXO, error) {
	udb.mu.RLock()
	defer udb.mu.RUnlock()

	return udb.read(commitment)
}

// GetUTXOCount returns the total number of UTXOs.
//
// It counts the set rather than reading a running total kept beside it. A total
// is a second write, and a node that dies between the two comes back with a
// number that disagrees with its own records — from which one removal drives an
// unsigned counter below zero and reports 1.8e19 unspent notes forever.
// Counting the set cannot disagree with the set.
func (udb *UTXODB) GetUTXOCount() uint64 {
	udb.mu.RLock()
	defer udb.mu.RUnlock()
	return uint64(len(udb.utxoCache))
}

// loadUTXOs rebuilds the set and the height index from the records.
//
// The records share a keyspace with other writers, so a key carrying the UTXO
// prefix counts as a UTXO only if the record under it names the commitment its
// own key is made of. Anything else belongs to someone else and is left alone.
func (udb *UTXODB) loadUTXOs() error {
	it := udb.db.NewIteratorWithPrefix([]byte{utxoPrefix})
	defer it.Release()

	for it.Next() {
		key := it.Key()
		if len(key) < 2 {
			continue
		}
		commitment := key[1:]

		var utxo UTXO
		if err := parseUTXO(it.Value(), &utxo); err != nil {
			continue
		}
		if !bytes.Equal(utxo.Commitment, commitment) {
			continue
		}

		commitmentStr := string(commitment)
		udb.utxoCache[commitmentStr] = utxo.Height
	}

	return it.Error()
}

// reload rebuilds the set and the height index from what the database now
// says, discarding whatever a block that did not commit had already added.
func (udb *UTXODB) reload() error {
	udb.mu.Lock()
	defer udb.mu.Unlock()

	udb.utxoCache = make(map[string]uint64)
	return udb.loadUTXOs()
}

// read returns the record for a commitment. It touches no shared state, so it
// is safe under either lock.
func (udb *UTXODB) read(commitment []byte) (*UTXO, error) {
	utxoBytes, err := udb.db.Get(makeUTXOKey(commitment))
	switch {
	case errors.Is(err, database.ErrNotFound):
		return nil, errNoUTXO
	case err != nil:
		// A read that FAILED is not a UTXO that is absent. Reported as absent
		// it says a note was never created, rather than that the disk is gone.
		return nil, fmt.Errorf("zkvm: read utxo: %w", err)
	}

	var utxo UTXO
	if err := parseUTXO(utxoBytes, &utxo); err != nil {
		return nil, err
	}

	return &utxo, nil
}

// makeUTXOKey creates a database key for a UTXO
func makeUTXOKey(commitment []byte) []byte {
	key := make([]byte, 1+len(commitment))
	key[0] = utxoPrefix
	copy(key[1:], commitment)
	return key
}

// Close closes the UTXO database
func (udb *UTXODB) Close() {
	udb.mu.Lock()
	defer udb.mu.Unlock()

	udb.utxoCache = nil
}
