// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/luxfi/log"

	"github.com/luxfi/database"
)

// StateTree manages a sparse Merkle tree of the UTXO set
type StateTree struct {
	db  database.Database
	log log.Logger

	// Current state
	currentRoot []byte
	treeHeight  int

	// Merkle tree cache (path -> hash)
	nodeCache map[string][]byte

	mu sync.RWMutex
}

const (
	// Default empty tree leaf hash
	emptyLeafHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

// NewStateTree creates a new sparse Merkle tree
func NewStateTree(db database.Database, log log.Logger) (*StateTree, error) {
	st := &StateTree{
		db:          db,
		log:         log,
		treeHeight:  256, // 256 levels for 256-bit hashes
		nodeCache:   make(map[string][]byte),
		currentRoot: make([]byte, 32),
	}

	// Initialize with empty tree root (all zeros for sparse Merkle tree)
	st.currentRoot = make([]byte, 32)

	// Try to load existing root from database
	if rootBytes, err := db.Get([]byte("state_root")); err == nil {
		st.currentRoot = rootBytes
	}

	return st, nil
}

// RootAfter returns the state root that results from applying txs on top of the
// current root, as SHA-256 over
//
//	currentRoot ‖ every output commitment (tx order) ‖ every nullifier (tx order)
//
// It is PURE: the tree is not mutated, so computing a root is safe to do inside
// Block.Verify. Verifying the same block twice, or verifying a block that is
// later rejected and then verifying its competitor, all yield the root that
// block's proposer computed. Only Finalize advances currentRoot, and only Accept
// calls Finalize.
//
// There is exactly ONE root function. A hardware-conditional digest (a GPU
// Poseidon path with a SHA-256 fallback) would make the consensus-committed root
// depend on whether the node has an accelerator, so validators with and without
// one would reject each other's blocks.
func (st *StateTree) RootAfter(txs []*Transaction) []byte {
	st.mu.RLock()
	defer st.mu.RUnlock()

	h := sha256.New()
	h.Write(st.currentRoot)
	for _, tx := range txs {
		for _, output := range tx.Outputs {
			h.Write(output.Commitment)
		}
	}
	for _, tx := range txs {
		for _, nullifier := range tx.Nullifiers {
			h.Write(nullifier)
		}
	}
	return h.Sum(nil)
}

// Finalize advances the committed root. It is the only mutation of tree state,
// and Accept is its only caller.
func (st *StateTree) Finalize(newRoot []byte) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	// The record first: a root held in memory that is not in the database is a
	// root this node alone believes.
	if err := st.db.Put([]byte("state_root"), newRoot); err != nil {
		return err
	}
	st.currentRoot = newRoot

	st.log.Debug("State tree finalized",
		log.String("root", fmt.Sprintf("%x", newRoot[:8])),
	)

	return nil
}

// reload puts the committed root back, discarding an advance that belonged to
// a block whose writes were discarded.
func (st *StateTree) reload() error {
	st.mu.Lock()
	defer st.mu.Unlock()

	root, err := st.db.Get([]byte("state_root"))
	if err != nil {
		st.currentRoot = make([]byte, 32)
		return nil
	}
	st.currentRoot = root
	return nil
}

// GetRoot returns the current state root
func (st *StateTree) GetRoot() []byte {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.currentRoot
}

// GetMerkleProof generates a Merkle proof for a commitment in the sparse Merkle tree
func (st *StateTree) GetMerkleProof(commitment []byte) ([][]byte, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	// Hash the commitment to get the leaf index
	leafHash := sha256.Sum256(commitment)
	leafIndex := leafHash[:]

	// Generate proof path (sibling hashes from leaf to root)
	proof := make([][]byte, st.treeHeight)

	currentHash := leafHash[:]
	for level := 0; level < st.treeHeight; level++ {
		// Determine if we're on left or right branch
		bit := getBit(leafIndex, level)

		// Get sibling hash from database or use empty hash
		siblingPath := getSiblingPath(leafIndex, level)
		siblingHash, err := st.getNodeHash(siblingPath)
		if err != nil {
			// Sibling doesn't exist, use empty hash
			siblingHash = make([]byte, 32)
		}

		proof[level] = siblingHash

		// Compute parent hash
		if bit == 0 {
			currentHash = hashPair(currentHash, siblingHash)
		} else {
			currentHash = hashPair(siblingHash, currentHash)
		}
	}

	return proof, nil
}

// VerifyMerkleProof verifies a sparse Merkle proof
func (st *StateTree) VerifyMerkleProof(commitment []byte, proof [][]byte, root []byte) bool {
	if len(proof) != st.treeHeight {
		return false
	}

	// Hash the commitment to get the leaf
	leafHash := sha256.Sum256(commitment)
	leafIndex := leafHash[:]

	// Recompute root from leaf using proof
	currentHash := leafHash[:]
	for level := 0; level < st.treeHeight; level++ {
		bit := getBit(leafIndex, level)
		siblingHash := proof[level]

		if siblingHash == nil || len(siblingHash) != 32 {
			return false
		}

		// Hash current with sibling based on bit position
		if bit == 0 {
			currentHash = hashPair(currentHash, siblingHash)
		} else {
			currentHash = hashPair(siblingHash, currentHash)
		}
	}

	// Verify computed root matches expected root
	return bytes.Equal(currentHash, root)
}

// Close closes the state tree
func (st *StateTree) Close() {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.nodeCache = nil
}

// Helper functions for sparse Merkle tree

// getBit returns the bit at position 'pos' in the byte array (0 or 1)
func getBit(data []byte, pos int) byte {
	byteIndex := pos / 8
	bitIndex := pos % 8

	if byteIndex >= len(data) {
		return 0
	}

	// Read bit from MSB to LSB within each byte
	return (data[byteIndex] >> (7 - bitIndex)) & 1
}

// getSiblingPath returns the path to the sibling node at a given level
func getSiblingPath(leafIndex []byte, level int) []byte {
	// Create a copy and flip the bit at the level position
	path := make([]byte, len(leafIndex))
	copy(path, leafIndex)

	byteIndex := level / 8
	bitIndex := level % 8

	if byteIndex < len(path) {
		// Flip the bit
		path[byteIndex] ^= (1 << (7 - bitIndex))
	}

	return path
}

// hashPair hashes two nodes together using SHA-256
func hashPair(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// getNodeHash retrieves a node hash from the database or cache
func (st *StateTree) getNodeHash(path []byte) ([]byte, error) {
	// Check cache first
	pathKey := string(path)
	if hash, ok := st.nodeCache[pathKey]; ok {
		return hash, nil
	}

	// Try database
	dbKey := append([]byte("smt_node_"), path...)
	hash, err := st.db.Get(dbKey)
	if err != nil {
		return nil, err
	}

	// Cache for future use
	st.nodeCache[pathKey] = hash
	return hash, nil
}
