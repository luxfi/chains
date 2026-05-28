// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

// swap_store.go: authoritative swap state for the B-Chain.
//
// The bridge is permissionless and non-custodial. Validators run this
// VM collectively, so swap state lives in consensus — every daemon /
// SDK client that queries bridge_getStatus or bridge_submitRequest
// reads from the same canonical record set.
//
// This file ships the in-process record store + lifecycle. Block-
// level persistence is added in a follow-up commit (these records are
// gossiped via Warp 2.0 envelopes today and the in-process map is
// rebuilt from envelopes after consensus accepts them).
//
// ON-WIRE STATUS NAMES are intentionally generic ("pending",
// "deposited", "signing", ...) — the daemon's local enum (specific to
// its UX cache) maps onto these via mapChainStatusToLocal.

// BridgeRequestStatus is the canonical on-chain lifecycle state.
type BridgeRequestStatus string

const (
	StatusPending   BridgeRequestStatus = "pending"
	StatusDeposited BridgeRequestStatus = "deposited"
	StatusSigning   BridgeRequestStatus = "signing"
	StatusSigned    BridgeRequestStatus = "signed"
	StatusReleasing BridgeRequestStatus = "releasing"
	StatusCompleted BridgeRequestStatus = "completed"
	StatusFailed    BridgeRequestStatus = "failed"
	StatusCancelled BridgeRequestStatus = "cancelled"
)

// BridgeRequestRecord is the chain-side record of a bridge intent.
// Field naming matches the JSON-RPC wire shape the daemon's bchain
// client consumes (snake-cased via JSON tags).
type BridgeRequestRecord struct {
	RequestID    string              `json:"requestId"`
	SourceChain  string              `json:"sourceChain"`
	DestChain    string              `json:"destChain"`
	SourceAsset  string              `json:"sourceAsset"`
	DestAsset    string              `json:"destAsset"`
	Amount       string              `json:"amount"`
	Recipient    string              `json:"recipient"`
	Sender       string              `json:"sender"`
	Status       BridgeRequestStatus `json:"status"`
	CreatedAt    int64               `json:"createdAt"`
	SourceTxHash string              `json:"sourceTxHash,omitempty"`
	DestTxHash   string              `json:"destTxHash,omitempty"`
	Signature    string              `json:"signature,omitempty"`
	FeeAmount    string              `json:"feeAmount,omitempty"`
	NetAmount    string              `json:"netAmount,omitempty"`
}

// SwapStore is the chain-side record set. Concurrency-safe.
//
// The interface is intentionally narrow — implementations decide
// whether records persist via the VM's database, are reconstructed
// from accepted blocks at startup, or both. The in-memory default
// (newInMemorySwapStore) covers the genesis case.
type SwapStore interface {
	Put(rec *BridgeRequestRecord) error
	Get(requestID string) (*BridgeRequestRecord, error)
	Patch(requestID string, fn func(*BridgeRequestRecord)) (*BridgeRequestRecord, error)
	List(filter SwapListFilter) ([]*BridgeRequestRecord, error)
}

// SwapListFilter narrows List queries. Empty fields mean "any".
type SwapListFilter struct {
	Status      BridgeRequestStatus
	SourceChain string
	Limit       int // 0 → no limit
}

// ErrSwapNotFound is returned by Get / Patch when the id isn't
// present. Distinct from other failures so callers can branch on it.
var ErrSwapNotFound = errors.New("bridgevm: swap not found")

// =============================================================================
// in-memory SwapStore
// =============================================================================

// inMemorySwapStore is the default SwapStore. Records are held in an
// id-keyed map under a single RWMutex; safe for concurrent use.
type inMemorySwapStore struct {
	mu     sync.RWMutex
	byID   map[string]*BridgeRequestRecord
	now    func() time.Time
	idMake func() string
}

// newInMemorySwapStore returns an empty in-memory store.
func newInMemorySwapStore() *inMemorySwapStore {
	return &inMemorySwapStore{
		byID:   make(map[string]*BridgeRequestRecord),
		now:    time.Now,
		idMake: randRequestID,
	}
}

// Put inserts a new record, assigning an id if absent.
func (s *inMemorySwapStore) Put(rec *BridgeRequestRecord) error {
	if rec == nil {
		return errors.New("bridgevm: nil record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.RequestID == "" {
		rec.RequestID = s.idMake()
	}
	if rec.Status == "" {
		rec.Status = StatusPending
	}
	if rec.CreatedAt == 0 {
		rec.CreatedAt = s.now().Unix()
	}
	cp := *rec
	s.byID[rec.RequestID] = &cp
	return nil
}

// Get returns a copy of the record. Copying isolates callers from
// concurrent mutations.
func (s *inMemorySwapStore) Get(requestID string) (*BridgeRequestRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.byID[requestID]
	if !ok {
		return nil, ErrSwapNotFound
	}
	cp := *rec
	return &cp, nil
}

// Patch applies fn under the store's lock.
func (s *inMemorySwapStore) Patch(requestID string, fn func(*BridgeRequestRecord)) (*BridgeRequestRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[requestID]
	if !ok {
		return nil, ErrSwapNotFound
	}
	cp := *rec
	fn(&cp)
	s.byID[requestID] = &cp
	out := cp
	return &out, nil
}

// List returns records matching the filter, newest-first.
func (s *inMemorySwapStore) List(filter SwapListFilter) ([]*BridgeRequestRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*BridgeRequestRecord, 0, len(s.byID))
	for _, rec := range s.byID {
		if filter.Status != "" && rec.Status != filter.Status {
			continue
		}
		if filter.SourceChain != "" && rec.SourceChain != filter.SourceChain {
			continue
		}
		cp := *rec
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt > out[j].CreatedAt
	})
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

// randRequestID is the canonical id format: "req_<8-byte hex>".
// 64 bits of cryptographic randomness — collision risk is
// astronomically low and we don't depend on monotonicity.
func randRequestID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "req_" + hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return "req_" + hex.EncodeToString(buf[:])
}
