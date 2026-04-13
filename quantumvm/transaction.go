// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/chains/quantumvm/quantum"
)

// Transaction represents a QVM transaction
type Transaction interface {
	ID() ids.ID
	Bytes() []byte
	Verify() error
	Execute() error
	GetQuantumSignature() *quantum.QuantumSignature
	Timestamp() time.Time
}

// BaseTransaction provides common transaction functionality
type BaseTransaction struct {
	id               ids.ID
	timestamp        time.Time
	nonce            uint64
	data             []byte
	quantumSignature *quantum.QuantumSignature
}

// ID returns the transaction ID
func (tx *BaseTransaction) ID() ids.ID {
	if tx.id == ids.Empty {
		tx.id, _ = ids.ToID(tx.Bytes())
	}
	return tx.id
}

// Bytes returns the transaction bytes
func (tx *BaseTransaction) Bytes() []byte {
	size := 8 + 8 + len(tx.data) // timestamp + nonce + data
	bytes := make([]byte, 0, size)

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(tx.timestamp.Unix()))
	bytes = append(bytes, timestampBytes...)

	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, tx.nonce)
	bytes = append(bytes, nonceBytes...)

	bytes = append(bytes, tx.data...)

	return bytes
}

// GetQuantumSignature returns the quantum signature
func (tx *BaseTransaction) GetQuantumSignature() *quantum.QuantumSignature {
	return tx.quantumSignature
}

// Timestamp returns the transaction timestamp
func (tx *BaseTransaction) Timestamp() time.Time {
	return tx.timestamp
}

// Verify verifies the transaction
func (tx *BaseTransaction) Verify() error {
	if tx.quantumSignature == nil {
		return errors.New("missing quantum signature")
	}
	return nil
}

// Execute executes the transaction
func (tx *BaseTransaction) Execute() error {
	// Implementation depends on transaction type
	return nil
}

// TransactionPool manages pending transactions
type TransactionPool struct {
	pending   map[ids.ID]Transaction
	queue     []Transaction
	maxSize   int
	batchSize int
	log       log.Logger
	mu        sync.RWMutex
	closed    bool
	closeChan chan struct{}
}

// NewTransactionPool creates a new transaction pool
func NewTransactionPool(maxSize, batchSize int, logger log.Logger) *TransactionPool {
	return &TransactionPool{
		pending:   make(map[ids.ID]Transaction),
		queue:     make([]Transaction, 0, maxSize),
		maxSize:   maxSize,
		batchSize: batchSize,
		log:       logger,
		closeChan: make(chan struct{}),
	}
}

// AddTransaction adds a transaction to the pool
func (p *TransactionPool) AddTransaction(tx Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return errors.New("pool is closed")
	}

	if len(p.pending) >= p.maxSize {
		return errors.New("pool is full")
	}

	txID := tx.ID()
	if _, exists := p.pending[txID]; exists {
		return errors.New("transaction already exists")
	}

	// Verify transaction
	if err := tx.Verify(); err != nil {
		return err
	}

	p.pending[txID] = tx
	p.queue = append(p.queue, tx)

	return nil
}

// RemoveTransaction removes a transaction from the pool
func (p *TransactionPool) RemoveTransaction(txID ids.ID) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.pending[txID]; !exists {
		return errors.New("transaction not found")
	}

	delete(p.pending, txID)

	// Remove from queue
	newQueue := make([]Transaction, 0, len(p.queue)-1)
	for _, tx := range p.queue {
		if tx.ID() != txID {
			newQueue = append(newQueue, tx)
		}
	}
	p.queue = newQueue

	return nil
}

// GetPendingTransactions returns pending transactions up to the limit
func (p *TransactionPool) GetPendingTransactions(limit int) []Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if limit <= 0 || limit > len(p.queue) {
		limit = len(p.queue)
	}

	txs := make([]Transaction, limit)
	copy(txs, p.queue[:limit])

	return txs
}

// PendingCount returns the number of pending transactions
func (p *TransactionPool) PendingCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.pending)
}

// Close closes the transaction pool
func (p *TransactionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.closed {
		p.closed = true
		close(p.closeChan)
		p.pending = nil
		p.queue = nil
	}
}

// TransactionWorker processes transactions in parallel
type TransactionWorker struct {
	vm            *VM
	quantumSigner *quantum.QuantumSigner
}

// ProcessBatch processes a batch of transactions.
// Uses GPU batch ML-DSA verification when available and batch is large enough.
func (w *TransactionWorker) ProcessBatch(txs []Transaction) ([]Transaction, error) {
	// Phase 1: basic validation (no crypto)
	var verified []Transaction
	for _, tx := range txs {
		if err := tx.Verify(); err != nil {
			w.vm.log.Debug("transaction verification failed", "txID", tx.ID(), "error", err)
			continue
		}
		if w.vm.Config.QuantumStampEnabled && tx.GetQuantumSignature() == nil {
			w.vm.log.Debug("missing quantum signature", "txID", tx.ID())
			continue
		}
		verified = append(verified, tx)
	}

	if len(verified) == 0 {
		return nil, nil
	}

	// Phase 2: quantum signature verification (GPU batch when possible)
	sigValid := make([]bool, len(verified))
	if w.vm.Config.QuantumStampEnabled {
		msgs := make([][]byte, len(verified))
		sigs := make([]*quantum.QuantumSignature, len(verified))
		for i, tx := range verified {
			msgs[i] = tx.Bytes()
			sigs[i] = tx.GetQuantumSignature()
		}

		// ParallelVerifyWithThreshold picks GPU or CPU automatically
		err := w.quantumSigner.ParallelVerifyWithThreshold(msgs, sigs, w.vm.Config.GPUBatchThreshold)
		if err == nil {
			// All passed
			for i := range sigValid {
				sigValid[i] = true
			}
		} else {
			// Batch failed -- verify individually to find which ones are bad
			for i := range verified {
				if verr := w.quantumSigner.Verify(msgs[i], sigs[i]); verr == nil {
					sigValid[i] = true
				} else {
					w.vm.log.Debug("quantum signature verification failed", "txID", verified[i].ID(), "error", verr)
				}
			}
		}
	} else {
		for i := range sigValid {
			sigValid[i] = true
		}
	}

	// Phase 3: execute valid transactions
	validTxs := make([]Transaction, 0, len(verified))
	for i, tx := range verified {
		if !sigValid[i] {
			continue
		}
		if err := tx.Execute(); err != nil {
			w.vm.log.Debug("transaction execution failed", "txID", tx.ID(), "error", err)
			continue
		}
		validTxs = append(validTxs, tx)
	}

	return validTxs, nil
}
