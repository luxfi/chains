// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// Block is a K-Chain block: an ordered batch of fee-settled key operations.
type Block struct {
	id           ids.ID
	parentID     ids.ID
	height       uint64
	timestamp    time.Time
	transactions []*Transaction
	vm           *VM
}

func (b *Block) computeID() ids.ID {
	h := sha256.New()
	h.Write(b.parentID[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], b.height)
	h.Write(u8[:])
	binary.BigEndian.PutUint64(u8[:], uint64(b.timestamp.Unix()))
	h.Write(u8[:])
	for _, tx := range b.transactions {
		id := tx.ID()
		h.Write(id[:])
	}
	return ids.ID(h.Sum(nil))
}

func (b *Block) ID() ids.ID {
	if b.id == ids.Empty {
		b.id = b.computeID()
	}
	return b.id
}

func (b *Block) ParentID() ids.ID     { return b.parentID }
func (b *Block) Parent() ids.ID       { return b.parentID }
func (b *Block) Height() uint64       { return b.height }
func (b *Block) Timestamp() time.Time { return b.timestamp }

// Verify checks the block can be accepted WITHOUT mutating state.
//
// Position first: the parent must exist, this block must sit exactly one above
// it, and its timestamp must not move backwards or run more than maxFutureSkew
// ahead of the verifying node. Those are not bookkeeping. Block time is the
// clock every authorization decision below is made against (AuthPolicy.
// ExpiresAt), so an unbounded timestamp lets a proposer rewind past an expiry
// and revive a permit the chain has already retired — or jump forward and retire
// one early. Unbounded height lets a proposer rewind the chain's height, and a
// block claiming height 0 used to skip the parent check outright.
//
// Then content: every transaction is well-formed, authenticated, correctly
// ordered by nonce, authorized, and affordable — including the cumulative fees
// of several transactions from the same payer. A block that fails any check is
// never accepted (fail closed); verifying a block never moves funds.
func (b *Block) Verify(ctx context.Context) error {
	b.vm.stateLock.RLock()
	defer b.vm.stateLock.RUnlock()

	parent, err := b.vm.getBlockLocked(b.parentID)
	if err != nil {
		return fmt.Errorf("keyvm: verify parent: %w", err)
	}
	if b.height != parent.height+1 {
		return fmt.Errorf("keyvm: %w: %d after parent %d", ErrBadHeight, b.height, parent.height)
	}
	if b.timestamp.Before(parent.timestamp) {
		return ErrTimeRewound
	}
	// The ceiling is the local clock plus the skew allowance, but never below the
	// parent: the chain already accepted that time, so reusing it must stay legal
	// even on a node whose own clock has slipped behind the tip. Without the
	// floor such a node refuses every block including the ones it builds itself,
	// and can never catch up.
	ceiling := b.vm.clock.Time().Add(maxFutureSkew)
	if parent.timestamp.After(ceiling) {
		ceiling = parent.timestamp
	}
	if b.timestamp.After(ceiling) {
		return ErrTimeAhead
	}

	r := newRunning()
	for _, tx := range b.transactions {
		if err := b.vm.checkTx(tx, b.timestamp.Unix(), r); err != nil {
			return err
		}
	}
	return nil
}

// Accept settles and applies the block atomically. For each transaction it
// METERS the operation's gas, BURNS the fee from the payer (debit + supply
// reduction), then APPLIES the state effect — all written through the VM's
// versiondb, which is committed exactly once. Any failure aborts the whole
// block (no partial application, no unpaid operation): the versiondb is rolled
// back and the caches are reloaded from the unchanged base DB.
func (b *Block) Accept(ctx context.Context) error {
	now := b.timestamp.Unix()

	b.vm.stateLock.Lock()
	defer b.vm.stateLock.Unlock()

	if err := b.settleAndApply(now); err != nil {
		b.abort()
		return err
	}

	// Block, height index and last-accepted pointer land in the same commit.
	if err := b.vm.recordAccepted(b); err != nil {
		b.abort()
		return err
	}
	if err := b.vm.versdb.Commit(); err != nil {
		b.abort()
		return fmt.Errorf("keyvm: commit block %s: %w", b.id, err)
	}

	// In-memory state advances only AFTER the commit landed. Advancing it first
	// would leave the VM serving a tip whose writes are not durable.
	b.vm.lastAccepted = b.id
	b.vm.lastBlock = b
	b.vm.height = b.height
	b.vm.prunePending(b.height)
	b.vm.dropFromMempool(b.transactions)

	b.vm.log.Info("K-Chain block accepted",
		log.String("blockID", b.id.String()),
		log.Uint64("height", b.height),
		log.Int("txs", len(b.transactions)),
	)
	return nil
}

// abort rolls back the versiondb and reloads caches from the unchanged base DB.
// The caller (Accept) holds stateLock.
func (b *Block) abort() {
	b.vm.versdb.Abort()
	if err := b.vm.loadStateLocked(); err != nil {
		b.vm.log.Error("keyvm: reload caches after abort", log.String("error", err.Error()))
	}
}

// settleAndApply burns each tx fee and applies its effect. Caller holds
// stateLock and is responsible for Abort on error.
func (b *Block) settleAndApply(now int64) error {
	for _, tx := range b.transactions {
		// Replay/order guard: nonce must be exactly the payer's next. Reads the
		// versiondb so earlier txs in this same block (buffered) are seen.
		if tx.Nonce != b.vm.nonceOf(tx.Payer)+1 {
			return ErrBadNonce
		}
		// Pillar (b): meter the operation against the payer's gas limit — the same
		// function admission and Verify priced it with, so settlement can never
		// charge a number either of them did not check.
		feeAmt, err := meter(tx)
		if err != nil {
			return err
		}
		// Pillar (a)+(c): debit + burn the fee from the payer's balance.
		if err := fee.Charge(b.vm.ledger, tx.Payer, feeAmt); err != nil {
			return err
		}
		// Apply the operation's state effect (atomically with the burn).
		if err := tx.Apply(b.vm, now); err != nil {
			return err
		}
		// Advance the payer's nonce (atomically with the burn + effect).
		if err := b.vm.setNonce(tx.Payer, tx.Nonce); err != nil {
			return err
		}
	}
	return nil
}

// Reject discards the block and returns its transactions to the mempool so they
// can be retried in a later block.
func (b *Block) Reject(ctx context.Context) error {
	b.vm.stateLock.Lock()
	delete(b.vm.pendingBlocks, b.id)
	b.vm.requeue(b.transactions)
	b.vm.stateLock.Unlock()
	return nil
}

// Status returns 0=processing, 1=accepted.
func (b *Block) Status() uint8 {
	b.vm.stateLock.RLock()
	defer b.vm.stateLock.RUnlock()
	if b.id == b.vm.lastAccepted {
		return 1
	}
	if ok, _ := b.vm.versdb.Has(append([]byte(BlockPrefix), b.id[:]...)); ok {
		return 1
	}
	return 0
}
