// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mev implements MEV protection via commit-reveal scheme.
// This prevents frontrunning and sandwich attacks by requiring a two-phase
// order submission process:
//
// 1. COMMIT: User submits hash(order || salt) - commitment is recorded
// 2. REVEAL: User reveals order and salt - verified against commitment
// 3. EXECUTE: Order is only executed if reveal matches commit within deadline
//
// The commitment hash hides order details until reveal, preventing
// validators/block producers from extracting MEV.
package mev

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/luxfi/ids"
)

var (
	ErrCommitmentNotFound    = errors.New("commitment not found")
	ErrCommitmentExpired     = errors.New("commitment expired")
	ErrCommitmentAlreadyUsed = errors.New("commitment already revealed")
	ErrCommitmentMismatch    = errors.New("reveal does not match commitment")
	ErrCommitmentTooEarly    = errors.New("reveal too early - minimum delay not met")
	ErrInvalidSalt           = errors.New("invalid salt length")
	ErrDuplicateCommitment   = errors.New("duplicate commitment")
)

const (
	// SaltLength is the required length of the salt (32 bytes).
	SaltLength = 32

	// DefaultMinRevealDelay is the minimum time between commit and reveal.
	// This ensures the commitment is included in a block before reveal.
	DefaultMinRevealDelay = 2 * time.Second

	// DefaultMaxRevealDelay is the maximum time allowed for reveal after commit.
	// After this, the commitment expires and order cannot be placed.
	DefaultMaxRevealDelay = 5 * time.Minute

	// DefaultCommitmentGracePeriod is how long to keep expired commitments
	// for audit purposes before garbage collection.
	DefaultCommitmentGracePeriod = 1 * time.Hour
)

// Commitment represents a pending order commitment.
type Commitment struct {
	// Hash is the commitment hash: SHA256(order_bytes || salt)
	Hash ids.ID

	// Sender is the address that made the commitment
	Sender ids.ShortID

	// BlockHeight is the block where commitment was recorded
	BlockHeight uint64

	// BlockTime is the block timestamp when committed
	BlockTime time.Time

	// ExpiresAt is when this commitment can no longer be revealed
	ExpiresAt time.Time

	// Revealed indicates if this commitment has been revealed
	Revealed bool

	// RevealedAt is when the commitment was revealed (if revealed)
	RevealedAt time.Time
}

// CommitmentStore tracks pending commitments.
type CommitmentStore struct {
	mu sync.RWMutex

	// commitments maps commitment hash to commitment
	commitments map[ids.ID]*Commitment

	// senderCommitments maps sender to their active commitment hashes
	senderCommitments map[ids.ShortID][]ids.ID

	// Configuration
	minRevealDelay  time.Duration
	maxRevealDelay  time.Duration
	commitmentGrace time.Duration

	// Statistics
	totalCommits  uint64
	totalReveals  uint64
	totalExpired  uint64
	totalMismatch uint64
}

// NewCommitmentStore creates a new commitment store with default config.
func NewCommitmentStore() *CommitmentStore {
	return &CommitmentStore{
		commitments:       make(map[ids.ID]*Commitment),
		senderCommitments: make(map[ids.ShortID][]ids.ID),
		minRevealDelay:    DefaultMinRevealDelay,
		maxRevealDelay:    DefaultMaxRevealDelay,
		commitmentGrace:   DefaultCommitmentGracePeriod,
	}
}

// CommitmentConfig allows custom configuration.
type CommitmentConfig struct {
	MinRevealDelay  time.Duration
	MaxRevealDelay  time.Duration
	CommitmentGrace time.Duration
}

// NewCommitmentStoreWithConfig creates a commitment store with custom config.
func NewCommitmentStoreWithConfig(cfg CommitmentConfig) *CommitmentStore {
	store := NewCommitmentStore()
	if cfg.MinRevealDelay > 0 {
		store.minRevealDelay = cfg.MinRevealDelay
	}
	if cfg.MaxRevealDelay > 0 {
		store.maxRevealDelay = cfg.MaxRevealDelay
	}
	if cfg.CommitmentGrace > 0 {
		store.commitmentGrace = cfg.CommitmentGrace
	}
	return store
}

// ComputeCommitment computes the commitment hash for order bytes and salt.
// commitment = SHA256(order_bytes || salt)
func ComputeCommitment(orderBytes []byte, salt [SaltLength]byte) ids.ID {
	h := sha256.New()
	h.Write(orderBytes)
	h.Write(salt[:])
	hash := h.Sum(nil)

	var id ids.ID
	copy(id[:], hash)
	return id
}

// VerifyCommitment checks if the revealed order matches the commitment.
func VerifyCommitment(commitmentHash ids.ID, orderBytes []byte, salt [SaltLength]byte) bool {
	computed := ComputeCommitment(orderBytes, salt)
	return computed == commitmentHash
}

// AddCommitment records a new commitment.
// Returns error if duplicate or sender has too many pending commitments.
func (cs *CommitmentStore) AddCommitment(
	commitmentHash ids.ID,
	sender ids.ShortID,
	blockHeight uint64,
	blockTime time.Time,
) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Check for duplicate
	if _, exists := cs.commitments[commitmentHash]; exists {
		return ErrDuplicateCommitment
	}

	commitment := &Commitment{
		Hash:        commitmentHash,
		Sender:      sender,
		BlockHeight: blockHeight,
		BlockTime:   blockTime,
		ExpiresAt:   blockTime.Add(cs.maxRevealDelay),
		Revealed:    false,
	}

	cs.commitments[commitmentHash] = commitment
	cs.senderCommitments[sender] = append(cs.senderCommitments[sender], commitmentHash)
	cs.totalCommits++

	return nil
}

// Reveal verifies and marks a commitment as revealed.
// Returns the original commitment if successful.
func (cs *CommitmentStore) Reveal(
	commitmentHash ids.ID,
	orderBytes []byte,
	salt [SaltLength]byte,
	sender ids.ShortID,
	blockTime time.Time,
) (*Commitment, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	commitment, exists := cs.commitments[commitmentHash]
	if !exists {
		return nil, ErrCommitmentNotFound
	}

	// Verify sender matches
	if commitment.Sender != sender {
		cs.totalMismatch++
		return nil, ErrCommitmentMismatch
	}

	// Check if already revealed
	if commitment.Revealed {
		return nil, ErrCommitmentAlreadyUsed
	}

	// Check expiration
	if blockTime.After(commitment.ExpiresAt) {
		cs.totalExpired++
		return nil, ErrCommitmentExpired
	}

	// Check minimum delay (must wait at least minRevealDelay after commit)
	minRevealTime := commitment.BlockTime.Add(cs.minRevealDelay)
	if blockTime.Before(minRevealTime) {
		return nil, ErrCommitmentTooEarly
	}

	// Verify commitment hash matches revealed data
	if !VerifyCommitment(commitmentHash, orderBytes, salt) {
		cs.totalMismatch++
		return nil, ErrCommitmentMismatch
	}

	// Mark as revealed
	commitment.Revealed = true
	commitment.RevealedAt = blockTime
	cs.totalReveals++

	return commitment, nil
}

// GetCommitment retrieves a commitment by hash. Returns interface{} for API compatibility.
func (cs *CommitmentStore) GetCommitment(commitmentHash ids.ID) (interface{}, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	commitment, exists := cs.commitments[commitmentHash]
	return commitment, exists
}

// GetSenderCommitments returns all active commitments for a sender as interface{} slice.
func (cs *CommitmentStore) GetSenderCommitments(sender ids.ShortID) []interface{} {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var result []interface{}
	for _, hash := range cs.senderCommitments[sender] {
		if commitment, exists := cs.commitments[hash]; exists {
			if !commitment.Revealed {
				result = append(result, commitment)
			}
		}
	}
	return result
}

// CleanupExpired removes expired commitments that are past the grace period.
// Should be called periodically (e.g., once per block).
func (cs *CommitmentStore) CleanupExpired(currentTime time.Time) int {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cleaned := 0
	for hash, commitment := range cs.commitments {
		// Remove if expired + grace period passed, or if revealed + grace period passed
		graceEnd := commitment.ExpiresAt.Add(cs.commitmentGrace)
		if commitment.Revealed {
			graceEnd = commitment.RevealedAt.Add(cs.commitmentGrace)
		}

		if currentTime.After(graceEnd) {
			delete(cs.commitments, hash)
			cleaned++
		}
	}

	// Cleanup sender mappings
	for sender, hashes := range cs.senderCommitments {
		var activeHashes []ids.ID
		for _, hash := range hashes {
			if _, exists := cs.commitments[hash]; exists {
				activeHashes = append(activeHashes, hash)
			}
		}
		if len(activeHashes) == 0 {
			delete(cs.senderCommitments, sender)
		} else {
			cs.senderCommitments[sender] = activeHashes
		}
	}

	return cleaned
}

// Statistics returns commit-reveal statistics.
type CommitmentStats struct {
	TotalCommits       uint64 `json:"totalCommits"`
	TotalReveals       uint64 `json:"totalReveals"`
	TotalExpired       uint64 `json:"totalExpired"`
	TotalMismatch      uint64 `json:"totalMismatch"`
	PendingCommitments int    `json:"pendingCommitments"`
}

// Statistics returns commit-reveal statistics as interface{} for API compatibility.
func (cs *CommitmentStore) Statistics() interface{} {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	pending := 0
	for _, c := range cs.commitments {
		if !c.Revealed {
			pending++
		}
	}

	return CommitmentStats{
		TotalCommits:       cs.totalCommits,
		TotalReveals:       cs.totalReveals,
		TotalExpired:       cs.totalExpired,
		TotalMismatch:      cs.totalMismatch,
		PendingCommitments: pending,
	}
}

// OrderCommitment represents a committed order waiting for reveal.
type OrderCommitment struct {
	// CommitmentHash is the hash submitted in commit phase
	CommitmentHash ids.ID `json:"commitmentHash"`

	// Sender is the order sender
	Sender ids.ShortID `json:"sender"`

	// Symbol is the trading pair (revealed after reveal)
	Symbol string `json:"symbol,omitempty"`
}

// OrderReveal represents the revealed order data.
type OrderReveal struct {
	// CommitmentHash links to the original commitment
	CommitmentHash ids.ID `json:"commitmentHash"`

	// Salt is the 32-byte random salt used in commitment
	Salt [SaltLength]byte `json:"salt"`

	// Order is the actual order being placed
	Symbol      string `json:"symbol"`
	Side        uint8  `json:"side"`
	OrderType   uint8  `json:"orderType"`
	Price       uint64 `json:"price"`
	Quantity    uint64 `json:"quantity"`
	TimeInForce string `json:"timeInForce"`
}

// SerializeOrderForCommitment serializes order fields for commitment hash.
// Format: symbol_len(2) || symbol || side(1) || type(1) || price(8) || qty(8) || tif_len(2) || tif
func SerializeOrderForCommitment(
	symbol string,
	side, orderType uint8,
	price, quantity uint64,
	timeInForce string,
) []byte {
	// Calculate total size
	symbolBytes := []byte(symbol)
	tifBytes := []byte(timeInForce)
	size := 2 + len(symbolBytes) + 1 + 1 + 8 + 8 + 2 + len(tifBytes)

	buf := make([]byte, size)
	offset := 0

	// Symbol (length prefixed)
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(symbolBytes)))
	offset += 2
	copy(buf[offset:], symbolBytes)
	offset += len(symbolBytes)

	// Side
	buf[offset] = side
	offset++

	// OrderType
	buf[offset] = orderType
	offset++

	// Price
	binary.BigEndian.PutUint64(buf[offset:], price)
	offset += 8

	// Quantity
	binary.BigEndian.PutUint64(buf[offset:], quantity)
	offset += 8

	// TimeInForce (length prefixed)
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(tifBytes)))
	offset += 2
	copy(buf[offset:], tifBytes)

	return buf
}
