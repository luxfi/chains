// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

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

// Block is an F-Chain block: an ordered batch of fee-settled confidential-
// compute operations.
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

// MaxFutureSkew is how far ahead of the verifying node's clock a block's
// timestamp may be. Chain time drives every expiry F enforces, so without a cap
// a proposer stamping year 36812 would expire every permit and every pending
// request at once.
const MaxFutureSkew = 60 * time.Second

// Verify checks the block can be accepted WITHOUT mutating state: it sits
// correctly on its parent in height and time, and every transaction is
// well-formed, authenticated, correctly ordered and paid for. A block that
// fails any check is never accepted (fail closed); verifying a block never
// moves funds.
//
// Verify does NOT decide authorization. That verdict depends on state earlier
// transactions in the same block may change, so a block-time verdict can differ
// from the application-time one — and a block every validator certifies and no
// validator can apply halts the chain. Authorization is decided once, in
// Accept, where failing it reverts the one transaction instead of the block.
func (b *Block) Verify(ctx context.Context) error {
	if b.height == 0 {
		return fmt.Errorf("fhevm: %w: genesis is not a proposed block", ErrInvalidBlock)
	}
	parent, err := b.vm.GetBlock(ctx, b.parentID)
	if err != nil {
		return fmt.Errorf("fhevm: verify parent: %w", err)
	}
	// Chain time and height are the parent's, advanced. Without this a proposer
	// picks both freely: it can rewind time to revive an expired permit, or jump
	// forward to expire everything at once.
	if b.height != parent.Height()+1 {
		return fmt.Errorf("fhevm: %w: height %d does not follow parent %d",
			ErrInvalidBlock, b.height, parent.Height())
	}
	if b.timestamp.Before(parent.Timestamp()) {
		return fmt.Errorf("fhevm: %w: timestamp %d precedes parent %d",
			ErrInvalidBlock, b.timestamp.Unix(), parent.Timestamp().Unix())
	}
	if b.timestamp.After(b.vm.clock.Time().Add(MaxFutureSkew)) {
		return fmt.Errorf("fhevm: %w: timestamp %d is beyond the %s skew allowance",
			ErrInvalidBlock, b.timestamp.Unix(), MaxFutureSkew)
	}
	if len(b.transactions) == 0 {
		return fmt.Errorf("fhevm: %w: empty block", ErrInvalidBlock)
	}
	if len(b.transactions) > MaxBlockTxs {
		return fmt.Errorf("fhevm: %w: %d transactions exceeds %d",
			ErrInvalidBlock, len(b.transactions), MaxBlockTxs)
	}

	b.vm.stateLock.RLock()
	defer b.vm.stateLock.RUnlock()

	batch := newBatch(b.vm)
	for _, tx := range b.transactions {
		if err := batch.admit(tx); err != nil {
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

	// Persist block, height index and last-accepted pointer in the same commit.
	if err := b.vm.state.Put(append([]byte(BlockPrefix), b.id[:]...), b.Bytes()); err != nil {
		b.abort()
		return err
	}
	if err := b.vm.state.Put(heightKey(b.height), b.id[:]); err != nil {
		b.abort()
		return err
	}
	if err := b.vm.state.Put(lastAcceptedKey, b.id[:]); err != nil {
		b.abort()
		return err
	}
	if err := b.vm.versdb.Commit(); err != nil {
		b.abort()
		return fmt.Errorf("fhevm: commit block %s: %w", b.id, err)
	}

	b.vm.lastAccepted = b.id
	b.vm.lastBlock = b
	b.vm.height = b.height
	delete(b.vm.pendingBlocks, b.id)
	b.vm.release(b.transactions)

	b.vm.log.Info("F-Chain block accepted",
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
		b.vm.log.Error("fhevm: reload caches after abort", log.String("error", err.Error()))
	}
}

// settleAndApply burns each tx fee and applies its effect. Caller holds
// stateLock and is responsible for Abort on error.
//
// A transaction that fails AUTHORIZATION here REVERTS rather than aborting the
// block: its fee is burned, its nonce is consumed, and its state effect does
// not happen. Every validator reaches that verdict from the same committed
// state in the same order, so a reverted transaction is not a disagreement —
// and the alternative, aborting, would mean a block every validator certified
// and no validator could apply, which halts the chain at that height. The payer
// pays for the block space it used either way, so a revert is not free.
//
// The error return is therefore reserved for what a validator genuinely cannot
// proceed past: a failed write, a failed burn, a nonce that Verify should have
// caught. Those abort the block and roll it back whole.
func (b *Block) settleAndApply(now int64) error {
	for _, tx := range b.transactions {
		// Replay/order guard: nonce must be exactly the payer's next. Reads the
		// versiondb so earlier txs in this same block (buffered) are seen.
		if tx.Nonce != b.vm.nonceOf(tx.Payer)+1 {
			return ErrBadNonce
		}
		gasUsed, err := GasFor(tx)
		if err != nil {
			return err
		}
		// Meter the operation against the payer's gas limit.
		meter := fee.NewGasMeter(fee.Gas(tx.GasLimit))
		if err := meter.Consume(gasUsed); err != nil {
			return err
		}
		feeAmt, err := fee.Cost(meter.Used(), GasPrice)
		if err != nil {
			return err
		}
		// Debit + burn the fee from the payer's balance.
		if err := fee.Charge(b.vm.ledger, tx.Payer, feeAmt); err != nil {
			return err
		}
		// Apply the operation's state effect (atomically with the burn) — or, if
		// authorization refuses it, leave state untouched. Apply reports which.
		if _, err := tx.Apply(b.vm, now); err != nil {
			return err
		}
		// Advance the payer's nonce (atomically with the burn + effect).
		if err := b.vm.setNonce(tx.Payer, tx.Nonce); err != nil {
			return err
		}
	}
	return nil
}

// Reject discards the block. Its transactions were never removed from the
// mempool — BuildBlock selects from the mempool rather than draining it — so
// there is nothing to give back and nothing that can be lost by an engine that
// drops a block without rejecting it.
func (b *Block) Reject(ctx context.Context) error {
	b.vm.stateLock.Lock()
	delete(b.vm.pendingBlocks, b.id)
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
	if ok, _ := b.vm.state.Has(append([]byte(BlockPrefix), b.id[:]...)); ok {
		return 1
	}
	return 0
}
