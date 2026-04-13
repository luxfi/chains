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

	// Pending changes
	pendingAdds    [][]byte
	pendingRemoves [][]byte

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

// ApplyTransaction applies a transaction to the state tree
func (st *StateTree) ApplyTransaction(tx *Transaction) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	// Remove spent UTXOs (nullifiers)
	for _, nullifier := range tx.Nullifiers {
		st.pendingRemoves = append(st.pendingRemoves, nullifier)
	}

	// Add new UTXOs (output commitments)
	for _, output := range tx.Outputs {
		st.pendingAdds = append(st.pendingAdds, output.Commitment)
	}

	return nil
}

// ComputeRoot computes the new Merkle root after pending changes.
// Uses GPU-accelerated Poseidon hash when available for ZK-friendly hashing.
// Falls back to SHA-256 when GPU is unavailable.
func (st *StateTree) ComputeRoot() ([]byte, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	// Collect all inputs for hashing
	inputs := make([][]byte, 0, 1+len(st.pendingAdds)+len(st.pendingRemoves))
	inputs = append(inputs, st.currentRoot)
	inputs = append(inputs, st.pendingAdds...)
	inputs = append(inputs, st.pendingRemoves...)

	// Try GPU Poseidon hash (ZK-friendly)
	if result, err := poseidonHashGPU(inputs); err == nil && len(result) > 0 {
		// Pad to 32 bytes for consistency
		root := make([]byte, 32)
		copy(root, result)
		return root, nil
	}

	// CPU fallback: SHA-256
	h := sha256.New()
	for _, input := range inputs {
		h.Write(input)
	}
	return h.Sum(nil), nil
}

// Finalize commits the pending changes and updates the root
func (st *StateTree) Finalize(newRoot []byte) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	// Update root
	st.currentRoot = newRoot

	// Clear pending changes
	st.pendingAdds = nil
	st.pendingRemoves = nil

	// Save root to database
	if err := st.db.Put([]byte("state_root"), newRoot); err != nil {
		return err
	}

	st.log.Debug("State tree finalized",
		log.String("root", fmt.Sprintf("%x", newRoot[:8])),
		log.Int("adds", len(st.pendingAdds)),
		log.Int("removes", len(st.pendingRemoves)),
	)

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

	st.pendingAdds = nil
	st.pendingRemoves = nil
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

// setNodeHash stores a node hash in the database and cache
func (st *StateTree) setNodeHash(path []byte, hash []byte) error {
	// Update cache
	pathKey := string(path)
	st.nodeCache[pathKey] = hash

	// Store in database
	dbKey := append([]byte("smt_node_"), path...)
	return st.db.Put(dbKey, hash)
}

// computeRoot computes the root hash after applying pending changes
func (st *StateTree) computeRootFromLeaves(leaves map[string][]byte) ([]byte, error) {
	// Build tree bottom-up from all leaves

	if len(leaves) == 0 {
		return make([]byte, 32), nil // Empty root
	}

	// For each leaf, update its path to the root
	for leafPath, leafHash := range leaves {
		if err := st.updateLeafPath([]byte(leafPath), leafHash); err != nil {
			return nil, err
		}
	}

	// Root is at the top level
	return st.currentRoot, nil
}

// updateLeafPath updates a leaf and propagates changes to the root
func (st *StateTree) updateLeafPath(leafIndex []byte, leafHash []byte) error {
	currentHash := leafHash

	for level := 0; level < st.treeHeight; level++ {
		bit := getBit(leafIndex, level)
		siblingPath := getSiblingPath(leafIndex, level)

		// Get sibling hash
		siblingHash, err := st.getNodeHash(siblingPath)
		if err != nil {
			// Sibling doesn't exist, use empty hash
			siblingHash = make([]byte, 32)
		}

		// Compute parent hash
		var parentHash []byte
		if bit == 0 {
			parentHash = hashPair(currentHash, siblingHash)
		} else {
			parentHash = hashPair(siblingHash, currentHash)
		}

		// Get parent path by truncating to level+1 bits
		parentPath := getParentPath(leafIndex, level+1)

		// Store parent hash
		if err := st.setNodeHash(parentPath, parentHash); err != nil {
			return err
		}

		currentHash = parentHash
	}

	// Update root
	st.currentRoot = currentHash
	return nil
}

// getParentPath gets the path to a node's parent
func getParentPath(path []byte, bitsToKeep int) []byte {
	result := make([]byte, len(path))
	copy(result, path)

	// Zero out bits beyond bitsToKeep
	for i := bitsToKeep; i < len(result)*8; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		if byteIndex < len(result) {
			result[byteIndex] &^= (1 << (7 - bitIndex))
		}
	}

	return result
}
