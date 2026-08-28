// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"errors"
	"fmt"
	"sync"

	"crypto/sha256"

	"github.com/luxfi/log"

	"github.com/luxfi/database"
)

// rootKey holds the committed state root.
var rootKey = []byte("state_root")

// Root is the committed state root and the fold that produces the next one.
//
// It was a "sparse Merkle tree": 256 levels, a node cache, GetMerkleProof and
// VerifyMerkleProof. None of it was reachable — the root is the SHA-256 fold
// below and always was — and the unreachable half held a map written under a
// READ lock, which in Go is a fatal throw rather than a bug you get to debug.
// A type named for a structure it does not have costs exactly that.
type Root struct {
	db  database.Database
	log log.Logger

	committed []byte

	mu sync.RWMutex
}

// NewRoot opens the committed state root.
func NewRoot(db database.Database, log log.Logger) (*Root, error) {
	r := &Root{db: db, log: log, committed: make([]byte, 32)}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// After returns the state root that results from applying txs on top of the
// committed root, as SHA-256 over
//
//	committed ‖ every output commitment (tx order) ‖ every nullifier (tx order)
//
// It is PURE: nothing is mutated, so computing a root is safe inside
// Block.Verify. Verifying the same block twice, or verifying a block that is
// later rejected and then verifying its competitor, all yield the root that
// block's proposer computed. Only Finalize advances the committed root, and
// only Accept calls Finalize.
//
// There is exactly ONE root function. A hardware-conditional digest (a GPU
// Poseidon path with a SHA-256 fallback) would make the consensus-committed
// root depend on whether the node has an accelerator, so validators with and
// without one would reject each other's blocks.
func (r *Root) After(txs []*Transaction) []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	h := sha256.New()
	h.Write(r.committed)
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

// Finalize advances the committed root. It is the only mutation, and Accept is
// its only caller.
func (r *Root) Finalize(next []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// The record first: a root held in memory that is not in the database is a
	// root this node alone believes.
	if err := r.db.Put(rootKey, next); err != nil {
		return err
	}
	r.committed = next

	r.log.Debug("State root finalized", log.String("root", fmt.Sprintf("%x", next[:8])))
	return nil
}

// Get returns the committed state root.
func (r *Root) Get() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.committed
}

// reload puts the committed root back, discarding an advance that belonged to
// a block whose writes were discarded.
//
// A read that FAILED is not an absent root. Both the constructor and this
// rollback path used to answer any error with the empty root and report
// success — so an unreadable database booted the node believing the shielded
// state was empty, and it then disagreed with the network on every block it
// saw, permanently. Only database.ErrNotFound means a chain with no root yet.
func (r *Root) reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	raw, err := r.db.Get(rootKey)
	switch {
	case errors.Is(err, database.ErrNotFound):
		r.committed = make([]byte, 32)
		return nil
	case err != nil:
		return fmt.Errorf("zkvm: read state root: %w", err)
	case len(raw) != 32:
		return fmt.Errorf("zkvm: state root is %d bytes, want 32", len(raw))
	}
	r.committed = raw
	return nil
}

// Close releases the root.
func (r *Root) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.committed = nil
}
