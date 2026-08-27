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

	// The fee is computed from the per-scheme gas schedule, NOT supplied by the
	// caller: register + ckks-n14 = (21000 + 60000) gas * 1000 nLUX/gas.
	expectedFee, err := FeeFor(tx)
	require.NoError(t, err)
	require.Equal(t, uint64(81_000_000), expectedFee)

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
// operations that each fit alone but do not fit together are refused.
func TestCumulativeFeesWithinBlock(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)

	one, err := FeeFor(&Transaction{Type: TxRegisterCiphertext, Scheme: testScheme})
	require.NoError(t, err)
	// Enough for one operation and one nLUX, never for two.
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): one + 1}, committee, 1)

	a := registerTx(t, k, testScheme, digestOf("a"), 1)
	b := registerTx(t, k, testScheme, digestOf("b"), 2)
	_, err = vm.SubmitTx(a)
	require.NoError(t, err)
	_, err = vm.SubmitTx(b)
	require.NoError(t, err, "each is affordable on its own at admission")

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.ErrorIs(t, blk.(*Block).Verify(context.Background()), fee.ErrInsufficientFunds)
}

// TestGasLimitEnforced proves the payer's declared ceiling is real: an
// operation costing more gas than the payer allowed is refused rather than
// silently charged.
func TestGasLimitEnforced(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	tx := registerTx(t, k, testScheme, digestOf("tight"), 1)
	tx.GasLimit = 1 // far below the scheduled 81,000
	k.sign(t, tx)

	_, err := vm.SubmitTx(tx)
	require.NoError(t, err, "admission prices the operation but does not meter it")

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.ErrorIs(t, blk.(*Block).Verify(context.Background()), fee.ErrOutOfGas)

	burned, _ := vm.Burned()
	require.Zero(t, burned, "a refused block burns nothing")
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

// TestNonceMustBeSequential proves a payer's transactions are ordered: a gap is
// refused, so a signed transaction cannot be held back and injected later out
// of order.
func TestNonceMustBeSequential(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	// Nonce 2 without 1: admission accepts it (it is greater than the last
	// used), but consensus requires exactly the next one.
	skipped := registerTx(t, k, testScheme, digestOf("skip"), 2)
	_, err := vm.SubmitTx(skipped)
	require.NoError(t, err)
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.ErrorIs(t, blk.(*Block).Verify(context.Background()), ErrBadNonce)
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

// TestAcceptIsAtomic proves a block that fails partway through applies NOTHING
// and burns NOTHING. The pair here passes Verify honestly — at that moment the
// permit is still active — and only collides once the revocation lands, which
// is exactly the case a per-transaction check cannot see coming.
func TestAcceptIsAtomic(t *testing.T) {
	owner := newTestKey(t)
	grantee := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{
		owner.hexAddr():   testFund,
		grantee.hexAddr(): testFund,
	}, committee, 1)

	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)

	burnedBefore, _ := vm.Burned()
	ownerBefore, _ := vm.Balance(owner.addr)
	granteeBefore, _ := vm.Balance(grantee.addr)

	// Revocation first, then a request that the revocation invalidates. The
	// owner has already spent nonces 1 and 2 seeding the permit.
	revoke := revokeTx(t, owner, permitID, 3)
	request := requestTx(t, grantee, testScheme, handle, permitID, 0, 1)

	blk := forceBlock(vm, revoke, request)
	require.NoError(t, blk.Verify(context.Background()),
		"both are valid against committed state — the conflict is created by the block itself")

	require.ErrorIs(t, blk.Accept(context.Background()), ErrPermitRevoked)

	// Nothing applied: the permit is still active, no request exists.
	pm, ok := vm.Permit(permitID)
	require.True(t, ok)
	require.Equal(t, StatusActive, pm.Status, "the revocation must be rolled back with the block")
	_, ok = vm.Decrypt(deriveRequestID(handle, grantee.addr, 1))
	require.False(t, ok)

	// Nothing burned, no balance moved.
	burnedAfter, _ := vm.Burned()
	require.Equal(t, burnedBefore, burnedAfter, "an aborted block burns nothing")
	ownerAfter, _ := vm.Balance(owner.addr)
	granteeAfter, _ := vm.Balance(grantee.addr)
	require.Equal(t, ownerBefore, ownerAfter)
	require.Equal(t, granteeBefore, granteeAfter)

	// The chain is still usable: the revocation alone succeeds.
	acceptOne(t, vm, revokeTx(t, owner, permitID, 3))
	pm, _ = vm.Permit(permitID)
	require.Equal(t, StatusRevoked, pm.Status)
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
