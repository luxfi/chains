// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"encoding/binary"
	"errors"
	"sync"

	"github.com/luxfi/log"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

const (
	// Database prefixes
	utxoPrefix   = 0x10
	utxoCountKey = "utxo_count"
	utxoIndexKey = "utxo_index"
)

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

	// Caches
	utxoCache map[string]*UTXO // commitment -> UTXO
	utxoCount uint64

	// Indexes
	heightIndex map[uint64][]string // height -> commitments

	mu sync.RWMutex
}

// NewUTXODB creates a new UTXO database
func NewUTXODB(db database.Database, log log.Logger) (*UTXODB, error) {
	udb := &UTXODB{
		db:          db,
		log:         log,
		utxoCache:   make(map[string]*UTXO),
		heightIndex: make(map[uint64][]string),
	}

	// Load UTXO count
	countBytes, err := db.Get([]byte(utxoCountKey))
	if err == database.ErrNotFound {
		udb.utxoCount = 0
	} else if err != nil {
		return nil, err
	} else {
		udb.utxoCount = binary.BigEndian.Uint64(countBytes)
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
	utxoBytes, err := Codec.Marshal(codecVersion, utxo)
	if err != nil {
		return err
	}

	// Store in database
	key := makeUTXOKey(utxo.Commitment)
	if err := udb.db.Put(key, utxoBytes); err != nil {
		return err
	}

	// Update cache
	udb.utxoCache[commitmentStr] = utxo

	// Update height index
	udb.heightIndex[utxo.Height] = append(udb.heightIndex[utxo.Height], commitmentStr)

	// Update count
	udb.utxoCount++
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, udb.utxoCount)
	if err := udb.db.Put([]byte(utxoCountKey), countBytes); err != nil {
		return err
	}

	udb.log.Debug("Added UTXO",
		log.String("txID", utxo.TxID.String()),
		log.Uint32("outputIndex", utxo.OutputIndex),
		log.Uint64("height", utxo.Height),
	)

	return nil
}

// GetUTXO retrieves a UTXO by commitment
func (udb *UTXODB) GetUTXO(commitment []byte) (*UTXO, error) {
	udb.mu.RLock()
	defer udb.mu.RUnlock()

	commitmentStr := string(commitment)

	// Check cache
	if utxo, exists := udb.utxoCache[commitmentStr]; exists {
		return utxo, nil
	}

	// Load from database
	key := makeUTXOKey(commitment)
	utxoBytes, err := udb.db.Get(key)
	if err != nil {
		return nil, errors.New("UTXO not found")
	}

	var utxo UTXO
	if _, err := Codec.Unmarshal(utxoBytes, &utxo); err != nil {
		return nil, err
	}

	// Update cache
	udb.utxoCache[commitmentStr] = &utxo

	return &utxo, nil
}

// RemoveUTXO removes a UTXO from the set
func (udb *UTXODB) RemoveUTXO(commitment []byte) error {
	udb.mu.Lock()
	defer udb.mu.Unlock()

	commitmentStr := string(commitment)

	// Get UTXO to find height
	utxo, exists := udb.utxoCache[commitmentStr]
	if !exists {
		// Try loading from DB
		var err error
		utxo, err = udb.getUTXONoLock(commitment)
		if err != nil {
			return errors.New("UTXO not found")
		}
	}

	// Remove from database
	key := makeUTXOKey(commitment)
	if err := udb.db.Delete(key); err != nil {
		return err
	}

	// Remove from cache
	delete(udb.utxoCache, commitmentStr)

	// Update height index
	if heightUTXOs, exists := udb.heightIndex[utxo.Height]; exists {
		for i, c := range heightUTXOs {
			if c == commitmentStr {
				udb.heightIndex[utxo.Height] = append(heightUTXOs[:i], heightUTXOs[i+1:]...)
				break
			}
		}
	}

	// Update count
	udb.utxoCount--
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, udb.utxoCount)
	if err := udb.db.Put([]byte(utxoCountKey), countBytes); err != nil {
		return err
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
		if utxo, exists := udb.utxoCache[commitmentStr]; exists {
			utxos = append(utxos, utxo)
		}
	}

	return utxos, nil
}

// GetUTXOCount returns the total number of UTXOs
func (udb *UTXODB) GetUTXOCount() uint64 {
	udb.mu.RLock()
	defer udb.mu.RUnlock()
	return udb.utxoCount
}

// GetAllCommitments returns all UTXO commitments (for Merkle tree)
func (udb *UTXODB) GetAllCommitments() [][]byte {
	udb.mu.RLock()
	defer udb.mu.RUnlock()

	commitments := make([][]byte, 0, len(udb.utxoCache))
	for _, utxo := range udb.utxoCache {
		commitments = append(commitments, utxo.Commitment)
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

			// Remove from cache
			delete(udb.utxoCache, commitmentStr)
			pruneCount++
		}

		// Remove height index
		delete(udb.heightIndex, height)
	}

	// Update count
	udb.utxoCount -= uint64(pruneCount)
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, udb.utxoCount)
	if err := udb.db.Put([]byte(utxoCountKey), countBytes); err != nil {
		return err
	}

	udb.log.Info("Pruned old UTXOs",
		log.Int("pruneCount", pruneCount),
		log.Uint64("minHeight", minHeight),
		log.Uint64("remainingUTXOs", udb.utxoCount),
	)

	return nil
}

// loadUTXOs loads UTXOs from database to cache
func (udb *UTXODB) loadUTXOs() error {
	return nil
}

// getUTXONoLock retrieves a UTXO without locking (internal use)
func (udb *UTXODB) getUTXONoLock(commitment []byte) (*UTXO, error) {
	key := makeUTXOKey(commitment)
	utxoBytes, err := udb.db.Get(key)
	if err != nil {
		return nil, errors.New("UTXO not found")
	}

	var utxo UTXO
	if _, err := Codec.Unmarshal(utxoBytes, &utxo); err != nil {
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
