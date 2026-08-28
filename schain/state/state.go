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

	"golang.org/x/crypto/sha3"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

var (
	// ErrStateCorrupted is returned when a stored value cannot be decoded into
	// its expected shape — a corrupt record must never be silently reinterpreted.
	ErrStateCorrupted = errors.New("state corrupted")

	// Database prefixes. Manifests are keyed manifest/<bucket>/<object>; allocator
	// counters are keyed alloc/<range>; the last-block pointer is a single fixed
	// key. Manifests and allocator counters are BOTH committed object state and
	// BOTH folded into Root() — the last-block pointer is consensus binding folded
	// separately into the block header, never into the state root.
	prefixManifest  = []byte("manifest/")
	prefixAlloc     = []byte("alloc/")
	prefixLastBlock = []byte("lastBlock")

	// rootPrefixes is the ordered list of committed-state prefixes Root() walks.
	// The order is FIXED (it is part of the root's definition): two validators
	// must absorb the same prefixes in the same order to agree. Adding a new
	// committed keyspace means appending here AND bumping stateRootDomain.
	rootPrefixes = [][]byte{prefixManifest, prefixAlloc}
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
// Allocator counters — the per-range monotonic id sequence (alloc/<range>).
//
// This is the leaderless pinned-writer replacement for raft's global volume-id
// (MaxVolumeIdCommand) + fileId sequence (MemorySequencer). Each range carries
// its OWN counter, so disjoint ranges allocate independently (their counters are
// disjoint state keys) while same-range allocations serialize through the one
// HRW owner. The counter is COMMITTED VM state (not owner-local memory), so it
// survives owner re-pin at an epoch boundary with no id reuse (DESIGN §6.5).
// ---------------------------------------------------------------------------

// allocKey builds the deterministic key alloc/<range>. range is length-prefixed
// for symmetry with manifestKey, so no two distinct ranges can ever collide on a
// shared key boundary.
func allocKey(rng string) []byte {
	k := make([]byte, 0, len(prefixAlloc)+4+len(rng))
	k = append(k, prefixAlloc...)
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(rng)))
	k = append(k, lp[:]...)
	k = append(k, rng...)
	return k
}

// Alloc is a range's allocator state: the next id it will hand out, and the
// nonce of the last allocation that moved it. Both live under ONE key, so a
// read-modify-write cannot leave the cursor and the nonce disagreeing — an
// advanced cursor with a stale nonce is a replayable allocation.
type Alloc struct {
	Next  uint64
	Nonce uint64
}

// allocSize is the canonical stored width of an Alloc: Next‖Nonce, big-endian.
const allocSize = 16

// GetAlloc returns a range's allocator state. An absent range reads as the zero
// Alloc — its first allocation starts at id 0 and accepts any nonce above 0.
// Reads through the version layer, so it observes state staged in this block
// before commit and the durable value after commit.
func (s *State) GetAlloc(rng string) (Alloc, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := s.db.Get(allocKey(rng))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return Alloc{}, nil
		}
		return Alloc{}, err
	}
	if len(data) != allocSize {
		return Alloc{}, ErrStateCorrupted
	}
	return Alloc{
		Next:  binary.BigEndian.Uint64(data[:8]),
		Nonce: binary.BigEndian.Uint64(data[8:]),
	}, nil
}

// SetAlloc stages a range's allocator state into the version layer. It becomes
// durable only when the VM commits the block's batch at Accept — the same
// versiondb/CommitBatch discipline as PutManifest. The value is a fixed-width
// big-endian pair so the stored bytes are canonical (GetAlloc rejects any other
// width as corruption).
func (s *State) SetAlloc(rng string, a Alloc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var buf [allocSize]byte
	binary.BigEndian.PutUint64(buf[:8], a.Next)
	binary.BigEndian.PutUint64(buf[8:], a.Nonce)
	return s.db.Put(allocKey(rng), buf[:])
}

// ---------------------------------------------------------------------------
// State root — the deterministic commitment that makes the chain safe for more
// than one validator. Covers the manifest AND allocator keyspaces.
// ---------------------------------------------------------------------------

// Root returns a deterministic SHA-256 commitment over the COMMITTED object
// keyspaces: every manifest/<bucket>/<object> -> {fileIds,size,etag} entry AND
// every alloc/<range> -> counter entry the chain holds after this block's writes
// are staged. It is the value the block header binds, so two validators whose
// committed state actually diverges — a different object set, a changed
// etag/size/fileIds for an object, OR a different allocator counter for a range —
// ALWAYS produce different roots. Divergence can never hide behind a matching
// block hash. This is the manifest-VM analog of dexvm's State.StateHash
// (dexvm/state/state.go:395), covering the storage VM's two committed keyspaces.
//
// The walk iterates each rootPrefix in turn via the zapdb prefix iterator
// NewIteratorWithStartAndPrefix(nil, prefix), so it reads through the versiondb
// (this block's staged in-memory writes merged over the durable base, deleted
// keys dropped). Only the manifest + alloc keyspaces are folded — the last-block
// pointer is consensus binding folded separately into the header via
// blockHash/height, NOT object state, so it is excluded here exactly as dexvm
// excludes its proposer-local receipt prefix.
//
// The prefix order (rootPrefixes) is fixed and the keys within each prefix come
// out in lexicographic order, so the digest is independent of write history. Each
// field (domain, key, value) is framed with SP 800-185 left_encode of its BIT
// length before it is absorbed, so no two distinct (key,value) splits can collide
// by concatenation — the same canonicalization the validator NodeID scheme uses
// (ids/node_id_scheme.go). And because every key is absorbed WITH its full
// prefix, a manifest key and an alloc key can never alias even if their suffixes
// coincide. The hash is SHAKE256 (SHA-3): not length-extendable (unlike SHA-256),
// domain-separated by stateRootDomain, and PQ-strength (256-bit output → 128-bit
// collision/preimage even under Grover).
func (s *State) Root() (ids.ID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	h := sha3.NewShake256()
	// Domain separation: bind every digest to this construction + version.
	_, _ = h.Write(leftEncode(uint64(len(stateRootDomain)) * 8))
	_, _ = h.Write([]byte(stateRootDomain))
	absorb := func(b []byte) {
		_, _ = h.Write(leftEncode(uint64(len(b)) * 8))
		_, _ = h.Write(b)
	}

	for _, prefix := range rootPrefixes {
		it := s.db.NewIteratorWithStartAndPrefix(nil, prefix)
		for it.Next() {
			absorb(it.Key())
			absorb(it.Value())
		}
		if err := it.Error(); err != nil {
			it.Release()
			return ids.Empty, fmt.Errorf("state root: iterate %q: %w", prefix, err)
		}
		it.Release()
	}
	var out ids.ID
	_, _ = h.Read(out[:])
	return out, nil
}

// stateRootDomain is the SP 800-185 customization string binding the state root
// to this construction and version. Bumping it invalidates every prior root. V3
// widens an allocator entry from a bare cursor to the cursor plus the nonce of
// the allocation that last moved it, so the root commits to which allocations
// have been spent.
const stateRootDomain = "SCHAIN_STATE_ROOT_V3"

// leftEncode is SP 800-185 left_encode: a length-self-describing prefix so the
// concatenation of framed fields is unambiguous (no two field boundaries can be
// confused). Mirrors leftEncodeNodeID in ids/node_id_scheme.go.
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x01, 0x00}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, byte(8-i))
	return append(out, buf[i:]...)
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
