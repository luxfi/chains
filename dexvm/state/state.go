// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package state manages persistent state for the DEX VM proxy.
//
// PROXY STATELESSNESS INVARIANT: this holds ZERO canonical DEX state. There are
// NO order / pool / position / tick / feeGrowth keys — matching + DEX state
// live ONLY on the d-chain. The proxy persists exactly three things, all proper
// to an atomic transport layer:
//
//  1. NONCES            — per-account replay protection for proxy txs.
//  2. RELAY RECEIPTS    — in-flight clob_* relays bound to (blockHash, txIndex),
//                         so a re-execution / reorg / retry maps to exactly one
//                         d-chain match (replay-idempotency).
//  3. CONSUMED UTXOs    — the atomic-UTXO consumption set: source-chain UTXO ids
//                         already claimed by an Import, so the same exported
//                         value can never be imported twice.
//  4. COLLATERAL ESCROW — the locked-collateral ledger: per collateral ref, the
//                         (asset, amount) an Import locked into the proxy. It is
//                         the value-conservation witness: a settle credits the
//                         realized proceeds and REFUNDS the unfilled remainder of
//                         this locked amount, so value_in == value_out exactly.
//                         This is NOT canonical DEX state — it is the transport
//                         layer's record of value in flight, the exact analogue
//                         of the consumed-UTXO set for the return leg.
package state

import (
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

// Receipt records an in-flight ZAP relay: the d-chain match it triggered, keyed
// by the consensus binding (blockHash, txIndex) so the same logical order maps
// to exactly one match across re-execution / reorg / retry.
type Receipt struct {
	BlockHash ids.ID `json:"blockHash"`
	TxIndex   uint32 `json:"txIndex"`
	// FillsHash is the SHA-256 of the d-chain's returned fills wire bytes — the
	// idempotency witness. A retry that re-derives the same fills is a no-op.
	FillsHash ids.ID `json:"fillsHash"`
}

// State manages the proxy's persistent state.
type State struct {
	mu sync.RWMutex
	db database.Database

	lastBlockID     ids.ID
	lastBlockHeight uint64
}

// New creates a new state manager.
func New(db database.Database) *State {
	return &State{db: db}
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

// PutEscrow records the (asset, amount) an Import locked under a collateral ref.
// The stored value is asset(32)||amount(8). Recording is the import leg of the
// conservation equation; the matching ConsumeEscrow at settle pays the refund.
func (s *State) PutEscrow(ref ids.ID, asset ids.ID, amount uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	val := make([]byte, 40)
	copy(val[0:32], asset[:])
	binary.BigEndian.PutUint64(val[32:40], amount)
	return s.db.Put(escrowKey(ref), val)
}

// GetEscrow returns the (asset, amount) locked under a collateral ref. found is
// false when no escrow exists (e.g. a relay that was not preceded by an import
// in this proxy — then there is nothing to refund and nothing to settle).
func (s *State) GetEscrow(ref ids.ID) (asset ids.ID, amount uint64, found bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, gerr := s.db.Get(escrowKey(ref))
	if gerr != nil {
		if errors.Is(gerr, database.ErrNotFound) {
			return ids.Empty, 0, false, nil
		}
		return ids.Empty, 0, false, gerr
	}
	if len(data) < 40 {
		return ids.Empty, 0, false, ErrStateCorrupted
	}
	copy(asset[:], data[0:32])
	amount = binary.BigEndian.Uint64(data[32:40])
	return asset, amount, true, nil
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
// ---------------------------------------------------------------------------

func receiptKey(blockHash ids.ID, txIndex uint32) []byte {
	k := append(append([]byte{}, prefixReceipt...), blockHash[:]...)
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], txIndex)
	return append(k, idx[:]...)
}

// GetReceipt returns the relay receipt bound to (blockHash, txIndex), if any.
func (s *State) GetReceipt(blockHash ids.ID, txIndex uint32) (*Receipt, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := s.db.Get(receiptKey(blockHash, txIndex))
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
	copy(r.FillsHash[:], data[32:64])
	return r, true, nil
}

// PutReceipt records a relay receipt. The stored value is blockHash||fillsHash
// (the txIndex lives in the key); blockHash is redundant-but-cheap provenance.
func (s *State) PutReceipt(r *Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	val := make([]byte, 64)
	copy(val[0:32], r.BlockHash[:])
	copy(val[32:64], r.FillsHash[:])
	return s.db.Put(receiptKey(r.BlockHash, r.TxIndex), val)
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

// Close is a no-op flush hook (the proxy writes through to the DB directly).
func (s *State) Close() error { return nil }
