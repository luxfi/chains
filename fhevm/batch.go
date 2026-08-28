// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"fmt"

	"github.com/luxfi/chains/fee"
)

// MaxBlockTxs bounds how many transactions one block carries. Without it a
// proposer's block size is whatever the mempool happens to hold.
const MaxBlockTxs = 1024

// batch is the running state a block's transactions must satisfy AS A
// SEQUENCE: nonces strictly in order per payer, fees affordable against a
// running per-payer debit, and no two transactions claiming one effect.
//
// One rule, two policies. Block.Verify runs it over a received block and
// refuses the whole block on the first transaction that does not fit;
// BuildBlock runs it over the mempool and simply leaves out what does not fit.
// A proposer therefore cannot build a block its own Verify would reject, and
// one unfit transaction can no longer take the rest of the mempool down with
// it.
//
// What is deliberately NOT here is authorization. checkAuth reads state that
// earlier transactions in the same block may change, so a block-time
// authorization verdict can differ from the application-time one — and a block
// that passes Verify on every validator and then fails to apply on every
// validator halts the chain. Authorization is decided once, at application
// time, and a transaction that fails it REVERTS: it pays its fee and has no
// effect (block.go settleAndApply). Verify's job is that the block is
// well-formed, authentic, ordered and paid for.
type batch struct {
	vm      *VM
	nonce   map[fee.Account]uint64 // next nonce owed by each payer
	spent   map[fee.Account]uint64 // running debit per payer
	claimed map[[32]byte]struct{}  // effects already taken in this block
}

func newBatch(vm *VM) *batch {
	return &batch{
		vm:      vm,
		nonce:   make(map[fee.Account]uint64),
		spent:   make(map[fee.Account]uint64),
		claimed: make(map[[32]byte]struct{}),
	}
}

// admit tests one transaction against the running state and, if it fits,
// records its consumption of that state. Caller holds vm.stateLock.
func (b *batch) admit(tx *Transaction) error {
	if err := tx.SyntacticVerify(); err != nil {
		return err
	}
	if err := tx.authenticate(b.vm.chainID); err != nil {
		return err
	}

	// Replay/order guard: a payer's nonces are consecutive from its committed
	// one, counting the transactions already taken from it in this block.
	want, seen := b.nonce[tx.Payer]
	if !seen {
		committed, err := b.vm.nonceOf(tx.Payer)
		if err != nil {
			return err
		}
		want = committed + 1
	}
	if tx.Nonce != want {
		return ErrBadNonce
	}

	eff := tx.effect()
	if _, dup := b.claimed[eff]; dup {
		return ErrDuplicateEffect
	}

	gasUsed, err := GasFor(tx)
	if err != nil {
		return err
	}
	if uint64(gasUsed) > tx.GasLimit {
		return fmt.Errorf("fhevm: %w: gas %d > limit %d", fee.ErrOutOfGas, gasUsed, tx.GasLimit)
	}
	feeAmt, err := fee.Cost(gasUsed, GasPrice)
	if err != nil {
		return err
	}
	bal, err := b.vm.ledger.Balance(tx.Payer)
	if err != nil {
		return err
	}
	next, over := addSpend(b.spent[tx.Payer], feeAmt)
	if over || bal < next {
		return fee.ErrInsufficientFunds
	}

	b.nonce[tx.Payer] = want + 1
	b.spent[tx.Payer] = next
	b.claimed[eff] = struct{}{}
	return nil
}

func addSpend(a, b uint64) (uint64, bool) {
	s := a + b
	return s, s < a
}
