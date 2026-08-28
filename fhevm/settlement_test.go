// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/chains/mpcvm/fhe"
)

// TestFeeSettledThroughConsensus is the headline proof that an F-Chain
// operation is paid for by BURNING real on-chain balance inside a consensus
// block — not by an unbacked integer a caller writes into a JSON request.
func TestFeeSettledThroughConsensus(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	bal, err := vm.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, testFund, bal, "genesis must fund the payer")
	burned0, err := vm.Burned()
	require.NoError(t, err)

	tx := registerTx(t, k, testScheme, digestOf("treasury"), 1)

	// The fee is computed from the schedule, NOT supplied by the caller:
	// register + ckks-n14 = (21000 + 60000) gas, plus 16 gas for every byte the
	// transaction puts on the chain, all at 1000 nLUX/gas.
	expectedFee, err := FeeFor(tx)
	require.NoError(t, err)
	stored := fee.Gas(len(tx.Payload) + len(tx.Scheme))
	require.Equal(t, uint64((21_000+60_000+stored*GasPerByte)*GasPrice), expectedFee)
	require.Greater(t, expectedFee, uint64(81_000_000), "stored bytes are not free")

	txID, err := vm.SubmitTx(tx)
	require.NoError(t, err)
	require.Equal(t, tx.ID(), txID)

	blkIntf, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := blkIntf.(*Block)

	require.NoError(t, blk.Verify(context.Background()))

	// Verify must NOT move funds (read-only affordability check).
	balPre, err := vm.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, testFund, balPre, "Verify must not debit")

	require.NoError(t, blk.Accept(context.Background()))

	// Accept settles: balance debited by EXACTLY the metered fee...
	balPost, err := vm.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, testFund-expectedFee, balPost, "payer must be debited the metered fee")

	// ...and the same amount is BURNED (circulating supply reduced).
	burned1, err := vm.Burned()
	require.NoError(t, err)
	require.Equal(t, burned0+expectedFee, burned1, "fee must be burned, not credited anywhere")

	// The operation took effect THROUGH consensus (not a synchronous RPC).
	rec, ok := vm.Ciphertext(tx.Subject)
	require.True(t, ok, "the register effect must be applied in Accept")
	require.Equal(t, k.addr, fee.Account(rec.Owner))
	require.Equal(t, testScheme, rec.Scheme)
	require.Equal(t, digestOf("treasury"), rec.Digest)
	require.Equal(t, blk.timestamp.Unix(), rec.RegisteredAt,
		"a record's timestamp comes from the accepting block, never a validator's clock")

	// Block is the new tip; mempool drained.
	la, err := vm.LastAccepted(context.Background())
	require.NoError(t, err)
	require.Equal(t, blk.ID(), la)
	require.Empty(t, vm.mempool)
}

// TestUnfundedPayerCannotSettle proves the fee is balance-backed: a payer
// without funds cannot get an operation accepted. Admission rejects it, and
// even if forced into a block, Verify fails closed.
func TestUnfundedPayerCannotSettle(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	// Fund with far less than one operation's fee.
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000}, committee, 1)

	tx := registerTx(t, k, testScheme, digestOf("x"), 1)

	_, err := vm.SubmitTx(tx)
	require.ErrorIs(t, err, fee.ErrInsufficientFunds, "admission must reject an unaffordable tx")

	// Force it into a block anyway: consensus Verify must still refuse it.
	blk := forceBlock(vm, tx)
	require.ErrorIs(t, blk.Verify(context.Background()), fee.ErrInsufficientFunds)

	// State untouched: no ciphertext, nothing burned.
	_, ok := vm.Ciphertext(tx.Subject)
	require.False(t, ok)
	burned, _ := vm.Burned()
	require.Zero(t, burned)
}

// TestCumulativeFeesWithinBlock proves affordability is checked against the
// payer's RUNNING debit inside the block, not its opening balance: two
// operations that each fit alone but do not fit together never share a block,
// and a peer proposing both is refused.
func TestCumulativeFeesWithinBlock(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)

	a := registerTx(t, k, testScheme, digestOf("a"), 1)
	b := registerTx(t, k, testScheme, digestOf("b"), 2)
	one, err := FeeFor(a)
	require.NoError(t, err)
	// Enough for one operation and one nLUX, never for two.
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): one + 1}, committee, 1)
	_, err = vm.SubmitTx(a)
	require.NoError(t, err)
	_, err = vm.SubmitTx(b)
	require.NoError(t, err, "each is affordable on its own at admission")

	// The proposer takes what fits and leaves the rest queued, rather than
	// proposing a block its own Verify would reject.
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.Len(t, blk.(*Block).transactions, 1, "only the affordable one is taken")
	require.NoError(t, blk.(*Block).Verify(context.Background()))
	require.Len(t, vm.mempool, 2, "selection does not drain the queue")

	// A peer proposing both is refused.
	require.ErrorIs(t, forceBlock(vm, a, b).Verify(context.Background()), fee.ErrInsufficientFunds)
}

// TestGasLimitEnforced proves the payer's declared ceiling is real: an
// operation costing more gas than the payer allowed is never included and never
// charged.
func TestGasLimitEnforced(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	tx := registerTx(t, k, testScheme, digestOf("tight"), 1)
	tx.GasLimit = 1 // far below the scheduled 81,000
	k.sign(t, tx)

	_, err := vm.SubmitTx(tx)
	require.NoError(t, err, "admission prices the operation but does not meter it")

	// Nothing else is queued, so the proposer has nothing it can build.
	_, err = vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errNoPendingTxs)

	// And a peer proposing it is refused.
	require.ErrorIs(t, forceBlock(vm, tx).Verify(context.Background()), fee.ErrOutOfGas)

	burned, _ := vm.Burned()
	require.Zero(t, burned, "an unmetered operation is never charged")
}

// TestTamperedOrUnsignedTxRejected proves authorization integrity at the VM
// boundary: F authenticates the payer by PUBLIC-key signature, so a tampered,
// unsigned, or impersonating transaction cannot spend or act.
func TestTamperedOrUnsignedTxRejected(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	tampered := registerTx(t, k, testScheme, digestOf("x"), 1)
	tampered.Nonce = 2
	_, err := vm.SubmitTx(tampered)
	require.ErrorIs(t, err, ErrBadSignature)

	unsigned := registerTx(t, k, testScheme, digestOf("y"), 1)
	unsigned.Auth, unsigned.Sig = nil, nil
	_, err = vm.SubmitTx(unsigned)
	require.ErrorIs(t, err, ErrUnsignedTx)

	other := newTestKey(t)
	impersonating := registerTx(t, k, testScheme, digestOf("z"), 1)
	other.sign(t, impersonating)
	_, err = vm.SubmitTx(impersonating)
	require.ErrorIs(t, err, ErrPayerMismatch)

	burned, _ := vm.Burned()
	require.Zero(t, burned)
}

// TestReplayRejected proves a captured signed transaction cannot be resubmitted
// to drain the payer through repeated fee burns: nonce enforcement rejects it
// at admission and again in consensus Verify, and no second burn occurs.
func TestReplayRejected(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	tx := registerTx(t, k, testScheme, digestOf("replay"), 1)
	acceptOne(t, vm, tx)
	balAfter, _ := vm.Balance(k.addr)

	// Resubmit the identical signed tx: rejected at admission (nonce consumed).
	_, err := vm.SubmitTx(tx)
	require.ErrorIs(t, err, ErrBadNonce)

	// Forced into a block, consensus Verify rejects it too — no second burn.
	require.ErrorIs(t, forceBlock(vm, tx).Verify(context.Background()), ErrBadNonce)

	bal2, _ := vm.Balance(k.addr)
	require.Equal(t, balAfter, bal2, "replay must not burn the payer again")
}

// TestNonceMustBeSequential proves admission enforces the SAME nonce rule
// consensus does, counted over what is already queued. It used to accept any
// nonce above the committed one, so a payer could queue a gap that made every
// block containing it unverifiable — and a Verify-failed block is discarded
// without Reject, so the queue behind it went too.
func TestNonceMustBeSequential(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	// A gap is refused outright.
	_, err := vm.SubmitTx(registerTx(t, k, testScheme, digestOf("skip"), 2))
	require.ErrorIs(t, err, ErrBadNonce)
	require.Empty(t, vm.mempool)

	// Consecutive nonces queue, including ahead of the committed one.
	_, err = vm.SubmitTx(registerTx(t, k, testScheme, digestOf("one"), 1))
	require.NoError(t, err)
	_, err = vm.SubmitTx(registerTx(t, k, testScheme, digestOf("two"), 2))
	require.NoError(t, err, "the second follows the first that is already queued")
	_, err = vm.SubmitTx(registerTx(t, k, testScheme, digestOf("four"), 4))
	require.ErrorIs(t, err, ErrBadNonce, "and a gap after them is still a gap")

	blk := acceptQueued(t, vm)
	require.Len(t, blk.transactions, 2)
	require.Empty(t, vm.mempool, "acceptance is what clears the queue")

	// After acceptance the payer continues from the committed nonce.
	_, err = vm.SubmitTx(registerTx(t, k, testScheme, digestOf("three"), 3))
	require.NoError(t, err)
}

// TestDuplicateEffectRefused proves one payer cannot queue two transactions
// that claim the same effect. Without this guard both pass every individual
// check and only collide in Accept, aborting the block that carried them —
// which, since Reject requeues, would rebuild the same doomed pair forever.
func TestDuplicateEffectRefused(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	first := registerTx(t, k, testScheme, digestOf("same"), 1)
	second := registerTx(t, k, testScheme, digestOf("same"), 2) // same handle, next nonce

	_, err := vm.SubmitTx(first)
	require.NoError(t, err)
	_, err = vm.SubmitTx(second)
	require.ErrorIs(t, err, ErrDuplicateEffect, "admission must refuse the second claim")
	require.Len(t, vm.mempool, 1)

	// A peer could still propose a block containing both. Consensus refuses it.
	require.ErrorIs(t, forceBlock(vm, first, second).Verify(context.Background()), ErrDuplicateEffect)

	// The honest first transaction is unaffected.
	acceptQueued(t, vm)
	_, ok := vm.Ciphertext(first.Subject)
	require.True(t, ok)

	// And once it is committed, a later duplicate is refused by state.
	third := registerTx(t, k, testScheme, digestOf("same"), 2)
	_, err = vm.SubmitTx(third)
	require.ErrorIs(t, err, ErrCiphertextExists)
}

// TestUnauthorizedTransactionReverts proves an authorization failure costs the
// payer its fee and nothing else. The pair here passes Verify honestly — at
// that moment the permit is still active — and only conflicts once the
// revocation lands, which is exactly the case no per-transaction check can see
// coming. Aborting the block there would mean one every validator certified and
// none could apply, which halts the chain; reverting the one transaction does
// not.
func TestUnauthorizedTransactionReverts(t *testing.T) {
	owner := newTestKey(t)
	grantee := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{
		owner.hexAddr():   testFund,
		grantee.hexAddr(): testFund,
	}, committee, 1)

	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)

	burnedBefore, _ := vm.Burned()
	granteeBefore, _ := vm.Balance(grantee.addr)

	// Revocation first, then a request the revocation invalidates. The owner has
	// already spent nonces 1 and 2 seeding the permit.
	revoke := revokeTx(t, owner, permitID, 3)
	request := requestTx(t, grantee, testScheme, handle, permitID, 0, 1)

	blk := forceBlock(vm, revoke, request)
	require.NoError(t, blk.Verify(context.Background()),
		"both are well-formed, ordered and paid for — authorization is not Verify's question")
	require.NoError(t, blk.Accept(context.Background()),
		"the block applies; only the transaction that lost its authority reverts")

	// The revocation took effect.
	pm, ok := vm.Permit(permitID)
	require.True(t, ok)
	require.Equal(t, StatusRevoked, pm.Status)

	// The request did not.
	_, ok = vm.Decrypt(deriveRequestID(handle, grantee.addr, 1))
	require.False(t, ok, "a reverted transaction leaves no record")

	// But it paid: the fee is burned and the nonce consumed, so a revert is not
	// free block space.
	requestFee, err := FeeFor(request)
	require.NoError(t, err)
	revokeFee, err := FeeFor(revoke)
	require.NoError(t, err)
	burnedAfter, _ := vm.Burned()
	require.Equal(t, burnedBefore+requestFee+revokeFee, burnedAfter)
	granteeAfter, _ := vm.Balance(grantee.addr)
	require.Equal(t, granteeBefore-requestFee, granteeAfter)

	// The nonce advanced, so the reverted transaction cannot be retried as-is.
	_, err = vm.SubmitTx(request)
	require.ErrorIs(t, err, ErrBadNonce)
}

// TestAbortRollsBackTheWholeBlock proves the commit boundary: when settlement
// cannot proceed at all — here a nonce Verify would have caught, reached by
// calling Accept directly — the versiondb is rolled back and the caches are
// reloaded, so no part of the block survives.
func TestAbortRollsBackTheWholeBlock(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	good := registerTx(t, k, testScheme, digestOf("good"), 1)
	gapped := registerTx(t, k, testScheme, digestOf("gapped"), 3) // 2 is missing

	blk := forceBlock(vm, good, gapped)
	require.ErrorIs(t, blk.Verify(context.Background()), ErrBadNonce,
		"consensus would never accept this block")
	require.ErrorIs(t, blk.Accept(context.Background()), ErrBadNonce)

	// The first transaction had already been applied and burned in memory when
	// the second failed. Neither survives.
	_, ok := vm.Ciphertext(good.Subject)
	require.False(t, ok)
	_, ok = vm.Ciphertext(gapped.Subject)
	require.False(t, ok)
	burned, _ := vm.Burned()
	require.Zero(t, burned)
	bal, _ := vm.Balance(k.addr)
	require.Equal(t, testFund, bal)
	nonce, err := vm.nonceOf(k.addr)
	require.NoError(t, err)
	require.Zero(t, nonce)

	// And the chain still works.
	acceptOne(t, vm, good)
	_, ok = vm.Ciphertext(good.Subject)
	require.True(t, ok)
}

// forceBlock builds a block directly from the given transactions, bypassing the
// mempool — the way a peer's proposal arrives.
func forceBlock(vm *VM, txs ...*Transaction) *Block {
	vm.stateLock.RLock()
	parentID, height := vm.lastAccepted, vm.height
	vm.stateLock.RUnlock()
	blk := &Block{
		parentID:     parentID,
		height:       height + 1,
		timestamp:    time.Now(),
		transactions: txs,
		vm:           vm,
	}
	blk.id = blk.computeID()
	return blk
}

// seedPermit registers a ciphertext owned by owner and grants grantee a permit
// over it, returning the handle and permit id. It is the starting state every
// decryption test needs. It spends the owner's nonces 1 and 2, so the owner's
// next transaction carries nonce 3.
func seedPermit(t *testing.T, vm *VM, owner, grantee testKey, ops uint32, expiry int64) (handle, permitID [32]byte) {
	t.Helper()
	reg := registerTx(t, owner, testScheme, digestOf("seed-"+owner.hexAddr()), 1)
	acceptOne(t, vm, reg)
	handle = reg.Subject

	grant := grantTx(t, owner, handle, grantee.addr, ops, expiry, 2)
	acceptOne(t, vm, grant)
	permitID = derivePermitID(handle, owner.addr, grantee.addr, ops, expiry, 2)

	_, ok := vm.Permit(permitID)
	require.True(t, ok, "the grant must create the permit its inputs derive")
	return handle, permitID
}
