// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package state manages persistent state for the DEX VM proxy.
//
// PROXY STATELESSNESS INVARIANT: this holds ZERO canonical DEX state. There are
// NO order / pool / position / tick / feeGrowth keys — matching + DEX state
// live ONLY on the d-chain. The proxy persists exactly four things, all proper
// to an atomic transport layer:
//
//  1. NONCES            — per-account replay protection for proxy txs.
//  2. RELAY RECEIPTS    — in-flight clob_* relays bound to (blockHash, txIndex),
//     so a re-execution / reorg / retry maps to exactly one
//     d-chain match (replay-idempotency).
//  3. CONSUMED UTXOs    — the atomic-UTXO consumption set: source-chain UTXO ids
//     already claimed by an Import, so the same exported
//     value can never be imported twice.
//  4. COLLATERAL ESCROW — the locked-collateral ledger: per collateral ref, the
//     (asset, amount) an Import locked into the proxy. It is
//     the value-conservation witness: a settle credits the
//     realized proceeds and REFUNDS the unfilled remainder of
//     this locked amount, so value_in == value_out exactly.
//     This is NOT canonical DEX state — it is the transport
//     layer's record of value in flight, the exact analogue
//     of the consumed-UTXO set for the return leg.
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

var (
	ErrStateCorrupted   = errors.New("state corrupted")
	ErrUTXOAlreadySpent = errors.New("atomic UTXO already consumed")

	// ErrEscrowConsumed is returned when a collateral escrow is settled twice.
	ErrEscrowConsumed = errors.New("collateral escrow already settled")

	// Database prefixes — replay nonces, relay receipts, consumed UTXOs,
	// collateral escrow.
	prefixNonce     = []byte("nonce:")
	prefixReceipt   = []byte("receipt:")
	prefixConsumed  = []byte("consumed:")
	prefixEscrow    = []byte("escrow:")
	prefixLastBlock = []byte("lastBlock")
)

// Receipt records an in-flight ZAP relay: the d-chain operation it triggered,
// keyed by the consensus binding (blockHash, txIndex) so the same logical order
// (submit, place, or cancel) maps to exactly one relay across re-execution /
// reorg / retry.
type Receipt struct {
	BlockHash ids.ID `json:"blockHash"`
	TxIndex   uint32 `json:"txIndex"`
	// RespHash is the SHA-256 of the d-chain's response wire bytes (clob_submit
	// fills, or a clob_place / clob_cancel ack) — the idempotency witness. A
	// retry that finds this receipt is a no-op; it never re-relays.
	RespHash ids.ID `json:"respHash"`
}

// State manages the proxy's persistent state.
type State struct {
	mu sync.RWMutex
	db database.Database

	// receiptDB is the DURABLE base layer for relay receipts ONLY — the
	// underlying disk DB, NOT the versiondb in-memory layer that `db` wraps. A
	// receipt is a WRITE-AHEAD INTENT that gates an irreversible external side
	// effect (the d-chain relay), so it must be durable the instant it is written
	// — BEFORE the relay fires and INDEPENDENT of the consensus commit/abort
	// timing. Every other key (nonce/escrow/consumed/lastBlock) is ordinary block
	// state and commits with the block at accept via `db`; db.Abort discards that
	// in-memory layer on a crash-before-accept, which is correct for block state
	// but would be fatal for the relay witness (it would re-fire the relay on
	// re-Verify). Routing receipts to receiptDB decomplects the witness's
	// durability from the block-commit lifecycle.
	receiptDB database.Database

	lastBlockID     ids.ID
	lastBlockHeight uint64
}

// New creates a new state manager. db is the per-block state layer (a versiondb
// committed atomically at accept); receiptDB is the DURABLE base DB the relay
// write-ahead receipts are written through to, so an idempotency witness
// survives a crash between Verify and Accept (db.Abort discards db's in-memory
// layer; receiptDB is untouched). Pass the same base DB the versiondb wraps.
func New(db, receiptDB database.Database) *State {
	return &State{db: db, receiptDB: receiptDB}
}

// Initialize loads the last-accepted block pointer from the database.
func (s *State) Initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lastBlockBytes, err := s.db.Get(prefixLastBlock)
	if err != nil && !errors.Is(err, database.ErrNotFound) {
		return fmt.Errorf("failed to load last block: %w", err)
	}
	if len(lastBlockBytes) >= 40 {
		copy(s.lastBlockID[:], lastBlockBytes[:32])
		s.lastBlockHeight = binary.BigEndian.Uint64(lastBlockBytes[32:40])
	}
	return nil
}

// ---------------------------------------------------------------------------
// Nonces — replay protection for proxy txs.
// ---------------------------------------------------------------------------

func nonceKey(addr ids.ShortID) []byte {
	return append(append([]byte{}, prefixNonce...), addr[:]...)
}

// GetNonce returns the current nonce for an account (0 if unseen).
func (s *State) GetNonce(addr ids.ShortID) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := s.db.Get(nonceKey(addr))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return 0, nil
		}
		return 0, err
	}
	if len(data) < 8 {
		return 0, ErrStateCorrupted
	}
	return binary.BigEndian.Uint64(data), nil
}

// SetNonce persists the nonce for an account.
func (s *State) SetNonce(addr ids.ShortID, nonce uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], nonce)
	return s.db.Put(nonceKey(addr), buf[:])
}

// ---------------------------------------------------------------------------
// Atomic-UTXO consumption set — each exported UTXO claimable exactly once.
// ---------------------------------------------------------------------------

func consumedKey(utxoID ids.ID) []byte {
	return append(append([]byte{}, prefixConsumed...), utxoID[:]...)
}

// IsConsumed reports whether an exported UTXO was already claimed by an Import.
func (s *State) IsConsumed(utxoID ids.ID) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := s.db.Get(consumedKey(utxoID))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, database.ErrNotFound) {
		return false, nil
	}
	return false, err
}

// MarkConsumed records that an exported UTXO has been claimed. It refuses a
// double-spend: a UTXO already in the set returns ErrUTXOAlreadySpent.
func (s *State) MarkConsumed(utxoID ids.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Get(consumedKey(utxoID)); err == nil {
		return ErrUTXOAlreadySpent
	} else if !errors.Is(err, database.ErrNotFound) {
		return err
	}
	return s.db.Put(consumedKey(utxoID), []byte{1})
}

// ---------------------------------------------------------------------------
// Collateral escrow — locked-value ledger for the conservation return leg.
// ---------------------------------------------------------------------------

func escrowKey(ref ids.ID) []byte {
	return append(append([]byte{}, prefixEscrow...), ref[:]...)
}

// escrowValueSize is the fixed collateral-escrow value width: owner(20) |
// asset(32) | amount(8). The OWNER leads the record — it is the AUTHORITATIVE
// settle-authority + payout target, the recorded owner of the consumed C->D UTXO
// (executeImport reads it back from shared memory and binds the credited outputs to
// it). Persisting it here is the CRITICAL escrow-theft fix: the settle leg derives
// who may settle and where the proceeds/refund go from THIS recorded owner, never
// from the unauthenticated relay tx sender, so an attacker naming a victim's
// collateral ref can neither settle it nor redirect its value.
const escrowValueSize = 20 + 32 + 8

// PutEscrow records the (owner, asset, amount) an Import locked under a collateral
// ref. The stored value is owner(20)||asset(32)||amount(8). owner is the recorded
// owner of the consumed C->D object (the authenticated cross-chain value's owner,
// bound in executeImport) — the only account that may later settle this escrow and
// the sole payout target for its proceeds + refund. Recording is the import leg of
// the conservation equation; the matching ConsumeEscrow at settle pays the refund.
func (s *State) PutEscrow(ref ids.ID, owner ids.ShortID, asset ids.ID, amount uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	val := make([]byte, escrowValueSize)
	copy(val[0:20], owner[:])
	copy(val[20:52], asset[:])
	binary.BigEndian.PutUint64(val[52:60], amount)
	return s.db.Put(escrowKey(ref), val)
}

// GetEscrow returns the (owner, asset, amount) locked under a collateral ref. found
// is false when no escrow exists (e.g. a relay that was not preceded by an import
// in this proxy — then there is nothing to refund and nothing to settle). owner is
// the recorded owner the settle leg binds settle-authority and the payout target to.
func (s *State) GetEscrow(ref ids.ID) (owner ids.ShortID, asset ids.ID, amount uint64, found bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, gerr := s.db.Get(escrowKey(ref))
	if gerr != nil {
		if errors.Is(gerr, database.ErrNotFound) {
			return ids.ShortEmpty, ids.Empty, 0, false, nil
		}
		return ids.ShortEmpty, ids.Empty, 0, false, gerr
	}
	if len(data) < escrowValueSize {
		return ids.ShortEmpty, ids.Empty, 0, false, ErrStateCorrupted
	}
	copy(owner[:], data[0:20])
	copy(asset[:], data[20:52])
	amount = binary.BigEndian.Uint64(data[52:60])
	return owner, asset, amount, true, nil
}

// ConsumeEscrow deletes a collateral escrow once it has been settled, so the
// same locked collateral can never be refunded twice. It refuses to consume an
// absent escrow (ErrEscrowConsumed) — the settle path's single-claim guard,
// mirroring MarkConsumed on the import leg.
func (s *State) ConsumeEscrow(ref ids.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Get(escrowKey(ref)); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return ErrEscrowConsumed
		}
		return err
	}
	return s.db.Delete(escrowKey(ref))
}

// ---------------------------------------------------------------------------
// Relay receipts — replay-idempotency for in-flight d-chain matches.
//
// Receipts are the proxy's WRITE-AHEAD INTENT LOG over the d-chain relay and so
// live in the DURABLE receiptDB, never the versiondb `db` (which is aborted on a
// crash-before-accept). The lifecycle is two-phase, both phases durable:
//
//  1. RecordRelayIntent(blockHash, txIndex) — written BEFORE the relay fires.
//     Its mere presence is the double-submit guard: a crash/restart between
//     Verify and Accept leaves this witness on disk, so re-Verify sees the
//     receipt and skips the relay. RespHash is zero at this point.
//  2. PutReceipt(r) — written AFTER the relay returns, finalizing the witness
//     with the response hash (provenance for the optional fraud-proof channel).
//
// Phase 1 alone fully closes the double-spend window; phase 2 is provenance.
// ---------------------------------------------------------------------------

func receiptKey(blockHash ids.ID, txIndex uint32) []byte {
	k := append(append([]byte{}, prefixReceipt...), blockHash[:]...)
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], txIndex)
	return append(k, idx[:]...)
}

// GetReceipt returns the relay receipt bound to (blockHash, txIndex), if any. It
// reads the DURABLE receiptDB so a write-ahead intent recorded before a crash is
// seen on the post-restart re-Verify — the heart of the double-submit guard.
func (s *State) GetReceipt(blockHash ids.ID, txIndex uint32) (*Receipt, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := s.receiptDB.Get(receiptKey(blockHash, txIndex))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if len(data) < 64 {
		return nil, false, ErrStateCorrupted
	}
	r := &Receipt{BlockHash: blockHash, TxIndex: txIndex}
	copy(r.RespHash[:], data[32:64])
	return r, true, nil
}

// RecordRelayIntent durably records the write-ahead intent to relay
// (blockHash, txIndex) — phase 1 — BEFORE the relay fires. After this returns,
// a crash that aborts the versiondb cannot erase the witness, so re-Verify finds
// it (GetReceipt) and refuses to re-submit. RespHash is left zero until the
// relay returns and PutReceipt finalizes it. Writing through receiptDB.Put makes
// the witness durable immediately (not deferred to the block commit).
func (s *State) RecordRelayIntent(blockHash ids.ID, txIndex uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	val := make([]byte, 64)
	copy(val[0:32], blockHash[:])
	// val[32:64] (RespHash) stays zero: the intent is recorded; the response is
	// not known yet. Presence — not content — is the idempotency guard.
	return s.receiptDB.Put(receiptKey(blockHash, txIndex), val)
}

// PutReceipt finalizes a relay receipt — phase 2 — after the relay returns,
// stamping the response hash onto the already-durable intent. The stored value
// is blockHash||respHash (the txIndex lives in the key); blockHash is
// redundant-but-cheap provenance. Written to the DURABLE receiptDB so it shares
// one home with the intent it upgrades.
func (s *State) PutReceipt(r *Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	val := make([]byte, 64)
	copy(val[0:32], r.BlockHash[:])
	copy(val[32:64], r.RespHash[:])
	return s.receiptDB.Put(receiptKey(r.BlockHash, r.TxIndex), val)
}

// ---------------------------------------------------------------------------
// Last-accepted block pointer.
// ---------------------------------------------------------------------------

// SetLastBlock sets the last accepted block.
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

// GetLastBlock returns the last accepted block ID and height.
func (s *State) GetLastBlock() (ids.ID, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastBlockID, s.lastBlockHeight
}

// ---------------------------------------------------------------------------
// State commitment — a faithful hash of EVERY persisted key/value.
// ---------------------------------------------------------------------------

// StateHash returns a deterministic SHA-256 commitment over the proxy's CONSENSUS
// state: every consumed-UTXO marker, collateral escrow, replay nonce, and the
// last-block pointer. It is the value the block's StateRoot binds, so two nodes
// whose consensus state actually diverges (a different consumed set, a settled-
// vs-unsettled escrow) ALWAYS produce different roots — divergence can never hide
// behind a matching block hash.
//
// RELAY RECEIPTS ARE DELIBERATELY EXCLUDED (RED finding #9). Under the carried-
// fills model the d-chain relay is performed exactly ONCE, by the block PROPOSER,
// at build (VM.obtainFills); the proposer writes a relay receipt as proposer-LOCAL
// idempotency bookkeeping, but a VALIDATOR that merely parses the block bytes never
// relays and so never writes that receipt. Folding receipts into the StateRoot
// would therefore make the proposer's root diverge from every validator's for the
// IDENTICAL block — reintroducing a fork. The receipt is liveness bookkeeping, not
// consensus state, and must not be committed here. (It remains durable in
// receiptDB and is still GetReceipt-able to gate a proposer rebuild.)
//
// The walk reads the versiondb `db` (which merges this block's staged in-memory
// writes over the durable base and drops deleted keys, e.g. a consumed escrow is
// absent), skipping the receipt prefix. Keys come out in lexicographic order, so
// the digest is order-independent of write history and identical across nodes.
// Every entry is folded length-prefixed (len(key)||key||len(value)||value) so no
// two distinct keyspaces collide by concatenation. The state is tiny by the
// proxy-statelessness invariant, so the walk per block is cheap.
func (s *State) StateHash() (ids.ID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	h := sha256.New()
	var lenBuf [8]byte
	fold := func(key, val []byte) {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(key)))
		h.Write(lenBuf[:])
		h.Write(key)
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(val)))
		h.Write(lenBuf[:])
		h.Write(val)
	}

	// Consensus state from the versiondb, EXCLUDING relay receipts (proposer-local
	// bookkeeping; see the doc above — folding them forks proposer vs validator).
	dbIt := s.db.NewIterator()
	defer dbIt.Release()
	for dbIt.Next() {
		key := dbIt.Key()
		if bytes.HasPrefix(key, prefixReceipt) {
			continue
		}
		fold(key, dbIt.Value())
	}
	if err := dbIt.Error(); err != nil {
		return ids.Empty, fmt.Errorf("state hash: iterate db: %w", err)
	}

	return ids.ID(h.Sum(nil)), nil
}

// Close is a no-op flush hook (the proxy writes through to the DB directly).
func (s *State) Close() error { return nil }
