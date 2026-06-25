// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package state manages persistent state for the S-Chain — the Lux storage VM.
//
// M0 persists exactly two things over the chain's database namespace:
//
//  1. MANIFESTS         — the (bucket, object) -> {fileIds, size, etag} mapping
//     that records which content blobs make up an object.
//  2. LAST-BLOCK pointer — the last-accepted block id + height, the recovery
//     anchor.
//
// Every accessor reads/writes through the supplied database.Database, which the
// VM hands in as a *versiondb.Database (the per-block in-memory version layer).
// A Put therefore stages into the version layer during block processing and
// becomes durable ONLY when the VM commits the batch at Accept — the exact
// commit discipline dexvm/state/state.go follows. This package never imports the
// zapdb engine directly; it speaks only the luxfi/database interface, so the VM
// is free to swap the backing store.
package state

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

var (
	// ErrStateCorrupted is returned when a stored value cannot be decoded into
	// its expected shape — a corrupt record must never be silently reinterpreted.
	ErrStateCorrupted = errors.New("state corrupted")

	// Database prefixes. Manifests are keyed manifest/<bucket>/<object>; the
	// last-block pointer is a single fixed key.
	prefixManifest  = []byte("manifest/")
	prefixLastBlock = []byte("lastBlock")
)

// Manifest is the committed content manifest for one object: the file blobs that
// compose it plus the object-level metadata an S3 HEAD returns. It is encoded as
// a deterministic JSON body (no maps, declaration-order fields), the same
// self-describing, protobuf-free style dexvm uses for its structured values.
type Manifest struct {
	FileIDs []string `json:"fileIds"`
	Size    int64    `json:"size"`
	ETag    string   `json:"etag"`
}

// State manages the S-Chain's persistent state over the version layer `db`.
type State struct {
	mu sync.RWMutex
	db database.Database

	lastBlockID     ids.ID
	lastBlockHeight uint64
}

// New creates a state manager over db — the per-block version layer the VM
// commits atomically at Accept. Mirrors dexstate.New (dexvm/state/state.go:96),
// minus the durable receipt side-channel the storage VM does not need in M0.
func New(db database.Database) *State {
	return &State{db: db}
}

// Initialize loads the last-accepted block pointer from the database.
func (s *State) Initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.db.Get(prefixLastBlock)
	if err != nil && !errors.Is(err, database.ErrNotFound) {
		return fmt.Errorf("failed to load last block: %w", err)
	}
	if len(data) >= 40 {
		copy(s.lastBlockID[:], data[:32])
		s.lastBlockHeight = binary.BigEndian.Uint64(data[32:40])
	}
	return nil
}

// ---------------------------------------------------------------------------
// Manifests — the (bucket, object) -> manifest mapping.
// ---------------------------------------------------------------------------

// manifestKey builds the deterministic key manifest/<bucket>/<object>. bucket
// and object are length-prefixed so distinct (bucket, object) splits can never
// collide (e.g. ("a/b","c") vs ("a","b/c")).
func manifestKey(bucket, object string) []byte {
	k := make([]byte, 0, len(prefixManifest)+4+len(bucket)+4+len(object))
	k = append(k, prefixManifest...)
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(bucket)))
	k = append(k, lp[:]...)
	k = append(k, bucket...)
	binary.BigEndian.PutUint32(lp[:], uint32(len(object)))
	k = append(k, lp[:]...)
	k = append(k, object...)
	return k
}

// PutManifest stages a manifest into the version layer. It becomes durable only
// when the VM commits the block's batch at Accept — before that, a GetManifest
// on a freshly-constructed reader over the base DB does not see it. This is the
// versiondb/CommitBatch discipline the M0 proof asserts.
func (s *State) PutManifest(bucket, object string, m Manifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	val, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	return s.db.Put(manifestKey(bucket, object), val)
}

// GetManifest returns the manifest for (bucket, object). found is false when no
// manifest exists. Reads through the version layer, so it observes a manifest
// staged in this block before commit (the in-flight view) and the durable store
// after commit — identical to dexvm's versiondb-backed reads.
func (s *State) GetManifest(bucket, object string) (m Manifest, found bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, gerr := s.db.Get(manifestKey(bucket, object))
	if gerr != nil {
		if errors.Is(gerr, database.ErrNotFound) {
			return Manifest{}, false, nil
		}
		return Manifest{}, false, gerr
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, false, ErrStateCorrupted
	}
	return m, true, nil
}

// ---------------------------------------------------------------------------
// Last-accepted block pointer.
// ---------------------------------------------------------------------------

// SetLastBlock records the last accepted block id + height (32+8 bytes).
func (s *State) SetLastBlock(blockID ids.ID, height uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data := make([]byte, 40)
	copy(data[:32], blockID[:])
	binary.BigEndian.PutUint64(data[32:], height)
	if err := s.db.Put(prefixLastBlock, data); err != nil {
		return err
	}
	s.lastBlockID = blockID
	s.lastBlockHeight = height
	return nil
}

// GetLastBlock returns the last accepted block id and height.
func (s *State) GetLastBlock() (ids.ID, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastBlockID, s.lastBlockHeight
}
