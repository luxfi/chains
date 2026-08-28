// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"bytes"
	"errors"
	"sync"

	"github.com/luxfi/log"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

// Database prefix for UTXO records: utxoPrefix || commitment -> marshalled UTXO.
const utxoPrefix = 0x10

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

	// Indexes
	heightIndex map[uint64][]string // height -> commitments

	mu sync.RWMutex
}

// NewUTXODB creates a new UTXO database
func NewUTXODB(db database.Database, log log.Logger) (*UTXODB, error) {
	udb := &UTXODB{
		db:          db,
		log:         log,
		utxoCache:   make(map[string]uint64),
		heightIndex: make(map[uint64][]string),
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

	// Serialize UTXO
	utxoBytes, err := utxo.Marshal()
	if err != nil {
		return err
	}

	// Store in database
	key := makeUTXOKey(utxo.Commitment)
	if err := udb.db.Put(key, utxoBytes); err != nil {
		return err
	}

	// Update the set and the height index
	udb.utxoCache[commitmentStr] = utxo.Height
	udb.heightIndex[utxo.Height] = append(udb.heightIndex[utxo.Height], commitmentStr)

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

// RemoveUTXO removes a UTXO from the set
func (udb *UTXODB) RemoveUTXO(commitment []byte) error {
	udb.mu.Lock()
	defer udb.mu.Unlock()

	commitmentStr := string(commitment)

	// The set holds every commitment, so absence here is absence on disk.
	height, exists := udb.utxoCache[commitmentStr]
	if !exists {
		return errors.New("UTXO not found")
	}

	// Remove from database
	key := makeUTXOKey(commitment)
	if err := udb.db.Delete(key); err != nil {
		return err
	}

	// Remove from the set
	delete(udb.utxoCache, commitmentStr)

	// Update height index
	if heightUTXOs, exists := udb.heightIndex[height]; exists {
		for i, c := range heightUTXOs {
			if c == commitmentStr {
				udb.heightIndex[height] = append(heightUTXOs[:i], heightUTXOs[i+1:]...)
				break
			}
		}
	}

	return nil
}

// GetUTXOsByHeight returns all UTXOs created at a specific height
func (udb *UTXODB) GetUTXOsByHeight(height uint64) ([]*UTXO, error) {
	udb.mu.RLock()
	defer udb.mu.RUnlock()

	commitments, exists := udb.heightIndex[height]
	if !exists {
		return nil, nil
	}

	utxos := make([]*UTXO, 0, len(commitments))
	for _, commitmentStr := range commitments {
		utxo, err := udb.read([]byte(commitmentStr))
		if err != nil {
			return nil, err
		}
		utxos = append(utxos, utxo)
	}

	return utxos, nil
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

// GetAllCommitments returns all UTXO commitments (for Merkle tree)
func (udb *UTXODB) GetAllCommitments() [][]byte {
	udb.mu.RLock()
	defer udb.mu.RUnlock()

	commitments := make([][]byte, 0, len(udb.utxoCache))
	for commitmentStr := range udb.utxoCache {
		commitments = append(commitments, []byte(commitmentStr))
	}

	return commitments
}

// PruneOldUTXOs removes UTXOs older than a certain height
func (udb *UTXODB) PruneOldUTXOs(minHeight uint64) error {
	udb.mu.Lock()
	defer udb.mu.Unlock()

	pruneCount := 0

	// Find heights to prune
	var heightsToPrune []uint64
	for height := range udb.heightIndex {
		if height < minHeight {
			heightsToPrune = append(heightsToPrune, height)
		}
	}

	// Prune UTXOs at each height
	for _, height := range heightsToPrune {
		commitments := udb.heightIndex[height]
		for _, commitmentStr := range commitments {
			commitment := []byte(commitmentStr)

			// Remove from database
			key := makeUTXOKey(commitment)
			if err := udb.db.Delete(key); err != nil {
				udb.log.Warn("Failed to prune UTXO", log.Reflect("error", err))
				continue
			}

			// Remove from the set
			delete(udb.utxoCache, commitmentStr)
			pruneCount++
		}

		// Remove height index
		delete(udb.heightIndex, height)
	}

	udb.log.Info("Pruned old UTXOs",
		log.Int("pruneCount", pruneCount),
		log.Uint64("minHeight", minHeight),
		log.Int("remainingUTXOs", len(udb.utxoCache)),
	)

	return nil
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
		udb.heightIndex[utxo.Height] = append(udb.heightIndex[utxo.Height], commitmentStr)
	}

	return it.Error()
}

// reload rebuilds the set and the height index from what the database now
// says, discarding whatever a block that did not commit had already added.
func (udb *UTXODB) reload() error {
	udb.mu.Lock()
	defer udb.mu.Unlock()

	udb.utxoCache = make(map[string]uint64)
	udb.heightIndex = make(map[uint64][]string)
	return udb.loadUTXOs()
}

// read returns the record for a commitment. It touches no shared state, so it
// is safe under either lock.
func (udb *UTXODB) read(commitment []byte) (*UTXO, error) {
	key := makeUTXOKey(commitment)
	utxoBytes, err := udb.db.Get(key)
	if err != nil {
		return nil, errors.New("UTXO not found")
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
	udb.heightIndex = nil
}
