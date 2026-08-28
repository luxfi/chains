// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	luxvm "github.com/luxfi/vm"
)

var (
	errPoolClosed   = errors.New("quantumvm: transaction pool is closed")
	errPoolFull     = errors.New("quantumvm: transaction pool is full")
	errDuplicateTx  = errors.New("quantumvm: transaction already in the pool")
	errTxNotInPool  = errors.New("quantumvm: transaction not in the pool")
	errMissingStamp = errors.New("quantumvm: missing quantum signature")
)

// Transaction represents a QVM transaction
type Transaction interface {
	ID() ids.ID
	Bytes() []byte
	Verify() error
	Execute() error
	GetQuantumSignature() *quantum.QuantumSignature
	Timestamp() time.Time
	// Fee returns the user-paid tx burn in nLUX. Q-Chain's policy is the
	// committee-only sentinel, which refuses every amount (LP-0130 §6).
	Fee() uint64
}

// BaseTransaction provides common transaction functionality
type BaseTransaction struct {
	id               ids.ID
	timestamp        time.Time
	nonce            uint64
	data             []byte
	fee              uint64
	quantumSignature *quantum.QuantumSignature
}

// ID returns the transaction ID — the content hash of the canonical ZAP wire
// (sha256(Bytes())), matching the other VMs in this repo. The prior
// ids.ToID(Bytes()) required an exactly-32-byte input and silently yielded
// ids.Empty for the always-≥32-byte wire, collapsing every tx to one pool slot.
func (tx *BaseTransaction) ID() ids.ID {
	if tx.id == ids.Empty {
		tx.id = ids.ID(sha256.Sum256(tx.Bytes()))
	}
	return tx.id
}

// GetQuantumSignature returns the quantum signature
func (tx *BaseTransaction) GetQuantumSignature() *quantum.QuantumSignature {
	return tx.quantumSignature
}

// Timestamp returns the transaction timestamp
func (tx *BaseTransaction) Timestamp() time.Time {
	return tx.timestamp
}

// Fee returns the user-paid tx burn (nLUX).
func (tx *BaseTransaction) Fee() uint64 {
	return tx.fee
}

// Verify verifies the transaction
func (tx *BaseTransaction) Verify() error {
	if tx.quantumSignature == nil {
		return errMissingStamp
	}
	return nil
}

// Execute executes the transaction
func (tx *BaseTransaction) Execute() error {
	return nil
}

// TransactionPool manages pending transactions
type TransactionPool struct {
	pending map[ids.ID]Transaction
	queue   []Transaction
	maxSize int
	log     log.Logger
	mu      sync.RWMutex
	closed  bool

	// work tells consensus a block can be built. The pool is what learns that
	// first, whichever path the transaction arrived by.
	work luxvm.Latch
}

// NewTransactionPool creates a new transaction pool
func NewTransactionPool(maxSize int, logger log.Logger) *TransactionPool {
	return &TransactionPool{
		pending: make(map[ids.ID]Transaction),
		queue:   make([]Transaction, 0, maxSize),
		maxSize: maxSize,
		log:     logger,
	}
}

// AddTransaction adds a transaction to the pool
func (p *TransactionPool) AddTransaction(tx Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return errPoolClosed
	}
	if len(p.pending) >= p.maxSize {
		return errPoolFull
	}

	txID := tx.ID()
	if _, exists := p.pending[txID]; exists {
		return errDuplicateTx
	}
	if err := tx.Verify(); err != nil {
		return err
	}

	p.pending[txID] = tx
	p.queue = append(p.queue, tx)

	// Consensus builds nothing until it is told there is something to build.
	p.work.Signal()

	return nil
}

// WaitForEvent blocks until there is a transaction to build a block from, or
// the caller gives up.
func (p *TransactionPool) WaitForEvent(ctx context.Context) (luxvm.Message, error) {
	return p.work.WaitForEvent(ctx)
}

// signalIfWork re-arms the builder while the pool still holds anything.
//
// The latch carries one signal, so N arrivals wake one build and a build that
// takes fewer than N leaves the rest with nothing to wake them: they sit in the
// pool until some unrelated transaction arrives, which on a quiet chain is
// never. Whoever drains the pool says so afterwards.
func (p *TransactionPool) signalIfWork() {
	p.mu.RLock()
	work := len(p.queue) > 0
	p.mu.RUnlock()
	if work {
		p.work.Signal()
	}
}

// RemoveTransaction removes a transaction from the pool
func (p *TransactionPool) RemoveTransaction(txID ids.ID) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.pending[txID]; !exists {
		return errTxNotInPool
	}

	delete(p.pending, txID)

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

	p.closed = true
	p.pending = nil
	p.queue = nil
}

// TransactionWorker processes transactions in parallel
type TransactionWorker struct {
	vm            *VM
	quantumSigner *quantum.QuantumSigner
}

// ProcessBatch VERIFIES a batch, reporting what survived and what did not. Both
// halves matter: the survivors go in the block, and the rest have to leave the
// pool — a transaction whose quantum stamp has aged out will never verify again,
// and left in place it holds its slot for good.
//
// It does not execute anything. Effects belong to Accept, on every node, once:
// running them here ran them on a block the network may never accept, ran them
// twice when the builder rebuilt, and ran them nowhere at all on a node that
// received the block rather than building it.
//
// Uses GPU batch ML-DSA verification when available and the batch is large enough.
func (w *TransactionWorker) ProcessBatch(txs []Transaction) (valid, rejected []Transaction) {
	// Phase 1: basic validation. A missing signature is caught here, by the
	// transaction itself; phase 2 decides whether the one present is good.
	var verified []Transaction
	for _, tx := range txs {
		if err := tx.Verify(); err != nil {
			w.vm.log.Debug("transaction verification failed", "txID", tx.ID(), "error", err)
			rejected = append(rejected, tx)
			continue
		}
		verified = append(verified, tx)
	}

	if len(verified) == 0 {
		return nil, rejected
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
		if err := w.quantumSigner.ParallelVerifyWithThreshold(msgs, sigs, w.vm.Config.GPUBatchThreshold); err == nil {
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

	// Phase 3: separate what verified from what did not
	valid = make([]Transaction, 0, len(verified))
	for i, tx := range verified {
		if !sigValid[i] {
			rejected = append(rejected, tx)
			continue
		}
		valid = append(valid, tx)
	}

	return valid, rejected
}
