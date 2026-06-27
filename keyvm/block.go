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

// Bytes serializes the block (parent, height, timestamp, transactions).
func (b *Block) Bytes() []byte {
	data := make([]byte, 0, 256)
	data = append(data, b.parentID[:]...)
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], b.height)
	data = append(data, u8[:]...)
	binary.BigEndian.PutUint64(u8[:], uint64(b.timestamp.Unix()))
	data = append(data, u8[:]...)
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], uint32(len(b.transactions)))
	data = append(data, u4[:]...)
	for _, tx := range b.transactions {
		txb := tx.Bytes()
		binary.BigEndian.PutUint32(u4[:], uint32(len(txb)))
		data = append(data, u4[:]...)
		data = append(data, txb...)
	}
	return data
}

func parseBlock(vm *VM, data []byte) (*Block, error) {
	c := &cursor{b: data}
	b := &Block{vm: vm}
	parent, err := c.fixed(32)
	if err != nil {
		return nil, err
	}
	copy(b.parentID[:], parent)
	if b.height, err = c.u64(); err != nil {
		return nil, err
	}
	ts, err := c.u64()
	if err != nil {
		return nil, err
	}
	b.timestamp = time.Unix(int64(ts), 0)
	cnt, err := c.fixed(4)
	if err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(cnt))
	b.transactions = make([]*Transaction, 0, n)
	for i := 0; i < n; i++ {
		txb, err := c.bytes()
		if err != nil {
			return nil, err
		}
		tx, err := ParseTransaction(txb)
		if err != nil {
			return nil, err
		}
		b.transactions = append(b.transactions, tx)
	}
	b.id = b.computeID()
	return b, nil
}

// Verify checks the block can be accepted WITHOUT mutating state: the parent
// exists, every transaction is well-formed and authenticated, and every payer
// can afford its fee — including the cumulative fees of multiple transactions
// from the same payer within this block. A block that fails any check is never
// accepted (fail closed); verifying a block never moves funds.
func (b *Block) Verify(ctx context.Context) error {
	if b.height > 0 {
		if _, err := b.vm.GetBlock(ctx, b.parentID); err != nil {
			return fmt.Errorf("keyvm: verify parent: %w", err)
		}
	}

	b.vm.stateLock.RLock()
	defer b.vm.stateLock.RUnlock()

	spent := make(map[fee.Account]uint64)         // running per-payer debit within this block
	expectedNonce := make(map[fee.Account]uint64) // running per-payer nonce within this block
	for _, tx := range b.transactions {
		if err := tx.SyntacticVerify(); err != nil {
			return err
		}
		if err := tx.authenticate(); err != nil {
			return err
		}
		// Replay/order guard runs BEFORE authorization so a replayed tx is
		// rejected as such regardless of the operation's other preconditions.
		expN, ok := expectedNonce[tx.Payer]
		if !ok {
			expN = b.vm.nonceOf(tx.Payer) + 1
		}
		if tx.Nonce != expN {
			return ErrBadNonce
		}
		expectedNonce[tx.Payer] = expN + 1
		if err := tx.checkAuth(b.vm, b.timestamp.Unix()); err != nil {
			return err
		}
		gasUsed, err := GasFor(tx)
		if err != nil {
			return err
		}
		if uint64(gasUsed) > tx.GasLimit {
			return fmt.Errorf("keyvm: %w: gas %d > limit %d", fee.ErrOutOfGas, gasUsed, tx.GasLimit)
		}
		feeAmt, err := fee.Cost(gasUsed, GasPrice)
		if err != nil {
			return err
		}
		bal, err := b.vm.ledger.Balance(tx.Payer)
		if err != nil {
			return err
		}
		prev := spent[tx.Payer]
		next, over := addBlockSpend(prev, feeAmt)
		if over || bal < next {
			return fee.ErrInsufficientFunds
		}
		spent[tx.Payer] = next
	}
	return nil
}

func addBlockSpend(a, b uint64) (uint64, bool) {
	s := a + b
	return s, s < a
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

	// Persist block + last-accepted pointer in the same commit.
	if err := b.vm.state.Put(append([]byte(BlockPrefix), b.id[:]...), b.Bytes()); err != nil {
		b.abort()
		return err
	}
	if err := b.vm.state.Put(lastAcceptedKey, b.id[:]); err != nil {
		b.abort()
		return err
	}
	if err := b.vm.versdb.Commit(); err != nil {
		b.abort()
		return fmt.Errorf("keyvm: commit block %s: %w", b.id, err)
	}

	b.vm.lastAccepted = b.id
	b.vm.lastBlock = b
	b.vm.height = b.height
	b.vm.shutdownLock.Lock()
	delete(b.vm.pendingBlocks, b.id)
	b.vm.shutdownLock.Unlock()
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
		gasUsed, err := GasFor(tx)
		if err != nil {
			return err
		}
		// Pillar (b): meter the operation against the payer's gas limit.
		meter := fee.NewGasMeter(fee.Gas(tx.GasLimit))
		if err := meter.Consume(gasUsed); err != nil {
			return err
		}
		feeAmt, err := fee.Cost(meter.Used(), GasPrice)
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
	b.vm.shutdownLock.Lock()
	delete(b.vm.pendingBlocks, b.id)
	b.vm.shutdownLock.Unlock()
	b.vm.requeue(b.transactions)
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
