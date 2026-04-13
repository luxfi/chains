// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"container/heap"
	"errors"
	"sync"
	"time"

	"github.com/luxfi/log"

	"github.com/luxfi/ids"
)

// Mempool manages pending transactions
type Mempool struct {
	log     log.Logger
	maxSize int

	// Transaction storage
	txs    map[ids.ID]*MempoolTx
	txHeap TxHeap

	// Nullifier tracking to prevent conflicts
	nullifiers map[string]ids.ID // nullifier -> txID

	mu sync.RWMutex
}

// MempoolTx represents a transaction in the mempool
type MempoolTx struct {
	tx         *Transaction
	addedAt    time.Time
	feePerByte uint64
	priority   int // For heap ordering
}

// NewMempool creates a new mempool
func NewMempool(maxSize int, log log.Logger) *Mempool {
	return &Mempool{
		log:        log,
		maxSize:    maxSize,
		txs:        make(map[ids.ID]*MempoolTx),
		txHeap:     make(TxHeap, 0),
		nullifiers: make(map[string]ids.ID),
	}
}

// AddTransaction adds a transaction to the mempool
func (mp *Mempool) AddTransaction(tx *Transaction) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	// Check if transaction already exists
	if _, exists := mp.txs[tx.ID]; exists {
		return nil // Already in mempool
	}

	// Check for nullifier conflicts
	for _, nullifier := range tx.Nullifiers {
		if existingTxID, exists := mp.nullifiers[string(nullifier)]; exists {
			mp.log.Debug("Nullifier conflict in mempool",
				log.String("newTx", tx.ID.String()),
				log.String("existingTx", existingTxID.String()),
			)
			return errors.New("nullifier already in mempool")
		}
	}

	// Check mempool size limit
	if len(mp.txs) >= mp.maxSize {
		// Remove lowest priority transaction
		if mp.txHeap.Len() > 0 {
			lowest := heap.Pop(&mp.txHeap).(*MempoolTx)
			mp.removeTxNoLock(lowest.tx.ID)
		}
	}

	// Fixed size estimate for fee calculation
	txSize := uint64(256)
	feePerByte := tx.Fee / txSize

	// Create mempool entry
	mempoolTx := &MempoolTx{
		tx:         tx,
		addedAt:    time.Now(),
		feePerByte: feePerByte,
	}

	// Add to storage
	mp.txs[tx.ID] = mempoolTx
	heap.Push(&mp.txHeap, mempoolTx)

	// Track nullifiers
	for _, nullifier := range tx.Nullifiers {
		mp.nullifiers[string(nullifier)] = tx.ID
	}

	mp.log.Debug("Added transaction to mempool",
		log.String("txID", tx.ID.String()),
		log.Uint64("fee", tx.Fee),
		log.Int("mempoolSize", len(mp.txs)),
	)

	return nil
}

// RemoveTransaction removes a transaction from the mempool
func (mp *Mempool) RemoveTransaction(txID ids.ID) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.removeTxNoLock(txID)
}

// removeTxNoLock removes a transaction without locking (internal use)
func (mp *Mempool) removeTxNoLock(txID ids.ID) {
	mempoolTx, exists := mp.txs[txID]
	if !exists {
		return
	}

	// Remove from storage
	delete(mp.txs, txID)

	// Remove nullifiers
	for _, nullifier := range mempoolTx.tx.Nullifiers {
		delete(mp.nullifiers, string(nullifier))
	}

	// Remove from heap (expensive, but necessary)
	for i, tx := range mp.txHeap {
		if tx.tx.ID == txID {
			heap.Remove(&mp.txHeap, i)
			break
		}
	}
}

// GetPendingTransactions returns pending transactions sorted by priority
func (mp *Mempool) GetPendingTransactions(limit int) []*Transaction {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	// Create a copy of the heap to sort
	tempHeap := make(TxHeap, len(mp.txHeap))
	copy(tempHeap, mp.txHeap)
	heap.Init(&tempHeap)

	// Extract top transactions
	txs := make([]*Transaction, 0, limit)
	for i := 0; i < limit && tempHeap.Len() > 0; i++ {
		mempoolTx := heap.Pop(&tempHeap).(*MempoolTx)
		txs = append(txs, mempoolTx.tx)
	}

	return txs
}

// HasTransaction checks if a transaction is in the mempool
func (mp *Mempool) HasTransaction(txID ids.ID) bool {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	_, exists := mp.txs[txID]
	return exists
}

// HasNullifier checks if a nullifier is already in the mempool
func (mp *Mempool) HasNullifier(nullifier []byte) bool {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	_, exists := mp.nullifiers[string(nullifier)]
	return exists
}

// Size returns the number of transactions in the mempool
func (mp *Mempool) Size() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	return len(mp.txs)
}

// Clear removes all transactions from the mempool
func (mp *Mempool) Clear() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.txs = make(map[ids.ID]*MempoolTx)
	mp.txHeap = make(TxHeap, 0)
	mp.nullifiers = make(map[string]ids.ID)

	mp.log.Info("Mempool cleared")
}

// PruneExpired removes expired transactions
func (mp *Mempool) PruneExpired(currentHeight uint64) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	var toRemove []ids.ID

	for txID, mempoolTx := range mp.txs {
		if mempoolTx.tx.Expiry > 0 && mempoolTx.tx.Expiry < currentHeight {
			toRemove = append(toRemove, txID)
		}
	}

	for _, txID := range toRemove {
		mp.removeTxNoLock(txID)
	}

	if len(toRemove) > 0 {
		mp.log.Info("Pruned expired transactions",
			log.Int("count", len(toRemove)),
			log.Uint64("currentHeight", currentHeight),
		)
	}
}

// TxHeap implements heap.Interface for priority ordering
type TxHeap []*MempoolTx

func (h TxHeap) Len() int { return len(h) }

func (h TxHeap) Less(i, j int) bool {
	// Higher fee per byte = higher priority
	return h[i].feePerByte > h[j].feePerByte
}

func (h TxHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].priority = i
	h[j].priority = j
}

func (h *TxHeap) Push(x interface{}) {
	n := len(*h)
	tx := x.(*MempoolTx)
	tx.priority = n
	*h = append(*h, tx)
}

func (h *TxHeap) Pop() interface{} {
	old := *h
	n := len(old)
	tx := old[n-1]
	*h = old[0 : n-1]
	return tx
}
