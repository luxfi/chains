// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// replay_test.go — an authorization is spent once. A signature stays valid for
// as long as the key does, so what stops an owner's allocate from being
// resubmitted is state, not cryptography.
package schain

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	mldsa65 "github.com/luxfi/crypto/pq/mldsa/mldsa65"
	mldsa87 "github.com/luxfi/crypto/pq/mldsa/mldsa87"
	"github.com/luxfi/ids"

	"github.com/luxfi/chains/schain/pinning"
	"github.com/luxfi/chains/schain/state"
	"github.com/luxfi/chains/schain/txs"
)

// withFixedEpoch installs a validator set at ONE epoch across every height —
// the production shape, where the epoch is a P-Chain height that holds still
// while the chain advances many blocks. The per-height epoch the other tests use
// hides a replay behind the epoch check.
func withFixedEpoch(t *testing.T, cvm *ChainVM, vals []testVal, proposer testVal, epoch uint64) {
	t.Helper()
	mem := membersOf(vals)
	cvm.SetBlockContextBuilder(func(context.Context, uint64) (BlockContext, error) {
		return BlockContext{
			Members:         mem,
			Proposer:        proposer.nodeID,
			Epoch:           epoch,
			IdentityChainID: testIdentityChainID,
		}, nil
	})
	signer, err := NewMLDSA65Signer(testIdentityChainID, proposer.pub, proposer.sk)
	require.NoError(t, err)
	cvm.SetAllocateSigner(signer)
}

// TestReplayedAllocateIsRefused is the regression test for an authorization with
// no spend record. Every gate the allocate passes the first time — the epoch is
// current, the fingerprint matches the local set, the signer IS the range owner,
// the ML-DSA signature verifies — passes again for the identical bytes at the
// next block. The nonce was covered by the signature but compared to nothing, so
// anyone who saw the owner's allocate could resubmit it and consume the range's
// id space again, for free, as often as they liked.
func TestReplayedAllocateIsRefused(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)
	vals := newTestValidators(t, 5)
	const rng, epoch = "hot-range", uint64(7)
	owner := ownerVal(t, rng, vals)
	withFixedEpoch(t, cvm, vals, owner, epoch)

	// The owner allocates, honestly, once.
	base, next, err := allocate(t, cvm, rng, 6)
	require.NoError(t, err)
	require.Equal(t, uint64(0), base)
	require.Equal(t, uint64(6), next)

	// Capture the exact authorization the owner published. Any peer sees it.
	cvm.lock.RLock()
	accepted := cvm.blocks[cvm.lastAcceptedID]
	cvm.lock.RUnlock()
	require.Len(t, accepted.txs, 1)
	parsed, err := parser.Parse(accepted.txs[0])
	require.NoError(t, err)
	captured := parsed.(*txs.AllocateTx)
	require.True(t, captured.IsSigned())

	// Every gate still passes on the captured bytes: same epoch, same set, same
	// owner, same valid signature. Only the spend record refuses it.
	require.Equal(t, epoch, captured.Epoch)
	require.Equal(t, owner.nodeID, captured.Signer)
	require.NoError(t, verifyAllocateSig(captured, testIdentityChainID),
		"the captured signature is and stays valid — cryptography cannot refuse a replay")

	replay := carry(t, cvm, captured.Bytes())
	require.ErrorIs(t, replay.Verify(ctx), errAllocateReplay)
	require.ErrorIs(t, replay.Accept(ctx), errAllocateReplay)

	after, err := cvm.inner.state.GetAlloc(rng)
	require.NoError(t, err)
	require.Equal(t, uint64(6), after.Next, "a replay must not consume the range's id space")
	require.Equal(t, captured.Nonce, after.Nonce)

	// And the owner's NEXT honest allocate still works — the guard refuses a
	// spent nonce, not the owner.
	base2, next2, err := allocate(t, cvm, rng, 4)
	require.NoError(t, err)
	require.Equal(t, uint64(6), base2)
	require.Equal(t, uint64(10), next2)
}

// TestAllocateNoncesAreOrderedNotMerelyDistinct proves the rule is a
// strictly-increasing nonce per range, so an allocate from BELOW the range's
// high-water mark is refused even though its bytes were never submitted before.
func TestAllocateNoncesAreOrderedNotMerelyDistinct(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)
	vals := newTestValidators(t, 5)
	const rng, epoch = "ordered", uint64(3)
	owner := ownerVal(t, rng, vals)
	withFixedEpoch(t, cvm, vals, owner, epoch)

	_, next, err := allocate(t, cvm, rng, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(2), next)

	spent, err := cvm.inner.state.GetAlloc(rng)
	require.NoError(t, err)
	require.Positive(t, spent.Nonce)

	// A never-seen allocate whose nonce sits below the mark.
	fp := pinning.EpochFingerprint(epoch, membersOf(vals))
	stale := txs.NewAllocateTx(rng, 3).WithAuthorization(
		epoch, spent.Nonce-1, fp, owner.nodeID, uint8(ids.NodeIDSchemeMLDSA65),
		owner.pub.Bytes(), signAllocateAs(t, owner, rng, 3, epoch, spent.Nonce-1, fp),
	)
	require.NoError(t, verifyAllocateSig(stale, testIdentityChainID), "a valid signature")
	require.ErrorIs(t, carry(t, cvm, stale.Bytes()).Verify(ctx), errAllocateReplay)

	// The same nonce as the mark is refused too: spent is spent.
	same := txs.NewAllocateTx(rng, 3).WithAuthorization(
		epoch, spent.Nonce, fp, owner.nodeID, uint8(ids.NodeIDSchemeMLDSA65),
		owner.pub.Bytes(), signAllocateAs(t, owner, rng, 3, epoch, spent.Nonce, fp),
	)
	require.ErrorIs(t, carry(t, cvm, same.Bytes()).Verify(ctx), errAllocateReplay)

	// One above it is accepted, which is what makes the two refusals about the
	// nonce and not about the allocate.
	ahead := txs.NewAllocateTx(rng, 3).WithAuthorization(
		epoch, spent.Nonce+1, fp, owner.nodeID, uint8(ids.NodeIDSchemeMLDSA65),
		owner.pub.Bytes(), signAllocateAs(t, owner, rng, 3, epoch, spent.Nonce+1, fp),
	)
	blk := carry(t, cvm, ahead.Bytes())
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))
	after, err := cvm.inner.state.GetAlloc(rng)
	require.NoError(t, err)
	require.Equal(t, uint64(5), after.Next)
	require.Equal(t, spent.Nonce+1, after.Nonce)
}

// TestSpentNonceIsPerRange proves the spend record is scoped to the range it
// belongs to: one range's high-water mark never refuses another's allocation.
func TestSpentNonceIsPerRange(t *testing.T) {
	cvm, _ := newTestVM(t)
	vals := newTestValidators(t, 1) // one validator owns every range
	const epoch = uint64(11)
	withFixedEpoch(t, cvm, vals, vals[0], epoch)

	// Advance range A several times so its mark is high.
	for i := 0; i < 3; i++ {
		_, _, err := allocate(t, cvm, "A", 2)
		require.NoError(t, err)
	}
	markA, err := cvm.inner.state.GetAlloc("A")
	require.NoError(t, err)
	require.Equal(t, uint64(6), markA.Next)

	// A fresh range starts from nothing and is unaffected by A's mark.
	base, next, err := allocate(t, cvm, "B", 5)
	require.NoError(t, err)
	require.Equal(t, uint64(0), base)
	require.Equal(t, uint64(5), next)

	markB, err := cvm.inner.state.GetAlloc("B")
	require.NoError(t, err)
	require.NotEqual(t, markA.Next, markB.Next, "ranges allocate independently")

	stillA, err := cvm.inner.state.GetAlloc("A")
	require.NoError(t, err)
	require.Equal(t, markA, stillA, "allocating B must not move A")
}

// TestBuilderDropsWhatItCannotAuthorize is the liveness half of the pinned-writer
// gate. A safety violation must fail a block a peer proposes — but on this node's
// OWN build it must only cost the offending transaction its place, not every
// other transaction queued behind it. It used to fail the whole build and drain
// the mempool, so one unauthorized allocate anyone could submit destroyed every
// manifest waiting to be committed.
func TestBuilderDropsWhatItCannotAuthorize(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)
	vals := newTestValidators(t, 5)
	const rng, epoch = "guarded", uint64(1)
	owner := ownerVal(t, rng, vals)
	attacker := nonOwnerVal(t, rng, vals)
	withFixedEpoch(t, cvm, vals, owner, epoch)

	// An attacker's perfectly-signed allocate for a range it does not own,
	// submitted alongside honest manifest work.
	fp := pinning.EpochFingerprint(epoch, membersOf(vals))
	forged := txs.NewAllocateTx(rng, 4).WithAuthorization(
		epoch, 1, fp, attacker.nodeID, uint8(ids.NodeIDSchemeMLDSA65),
		attacker.pub.Bytes(), signAllocateAs(t, attacker, rng, 4, epoch, 1, fp),
	)
	require.NoError(t, cvm.SubmitTx(forged.Bytes()))
	require.NoError(t, cvm.SubmitTx(manifestTx("b", "honest-one")))
	require.NoError(t, cvm.SubmitTx(manifestTx("b", "honest-two")))

	blk, err := cvm.BuildBlock(ctx)
	require.NoError(t, err, "one unauthorized transaction must not stop the build")
	require.Len(t, blk.(*Block).txs, 2, "the unauthorized allocate is left out")
	require.NoError(t, blk.Verify(ctx), "a block this node builds is one it verifies")
	require.NoError(t, blk.Accept(ctx))

	for _, object := range []string{"honest-one", "honest-two"} {
		_, found, err := cvm.inner.GetManifest("b", object)
		require.NoError(t, err)
		require.Truef(t, found, "honest work must survive an unauthorized neighbour (%s)", object)
	}
	after, err := cvm.inner.state.GetAlloc(rng)
	require.NoError(t, err)
	require.Zero(t, after.Next, "the unauthorized allocate must not have taken effect")

	// And a verifier handed the same forged transaction inside a block refuses
	// the whole block — the safety half is unchanged.
	require.ErrorIs(t, carry(t, cvm, forged.Bytes()).Verify(ctx), errNonOwnerAllocate)
}

// TestMalformedTxIsDroppedNotFatal proves a transaction the codec or its own
// Verify rejects costs only itself: it stages nothing and the block still
// carries everything else.
func TestMalformedTxIsDroppedNotFatal(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	// Force past SubmitTx's validation, as a peer relay could.
	cvm.lock.Lock()
	cvm.pendingTxs = [][]byte{
		[]byte("not a transaction"),
		txs.NewPutManifestTx("", "o", []string{"f"}, 1, "e").Bytes(), // empty bucket
		manifestTx("b", "survivor"),
	}
	cvm.lock.Unlock()

	blk, err := cvm.BuildBlock(ctx)
	require.NoError(t, err)
	require.Len(t, blk.(*Block).txs, 1)
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))

	_, found, err := cvm.inner.GetManifest("b", "survivor")
	require.NoError(t, err)
	require.True(t, found)
}

// TestSubmitRefusesWhatItCannotRead proves the mempool door validates before
// admitting: bytes that do not decode, and transactions whose own Verify refuses
// them, never reach the pending pool.
func TestSubmitRefusesWhatItCannotRead(t *testing.T) {
	cvm, _ := newTestVM(t)

	require.Error(t, cvm.SubmitTx(nil))
	require.ErrorIs(t, cvm.SubmitTx([]byte{0xff}), txs.ErrInvalidTxType)
	require.ErrorIs(t, cvm.SubmitTx(txs.NewPutManifestTx("", "o", []string{"f"}, 1, "e").Bytes()),
		txs.ErrEmptyBucket)
	require.ErrorIs(t, cvm.SubmitTx(txs.NewPutManifestTx("b", "", []string{"f"}, 1, "e").Bytes()),
		txs.ErrEmptyObject)
	require.ErrorIs(t, cvm.SubmitTx(txs.NewPutManifestTx("b", "o", nil, 1, "e").Bytes()),
		txs.ErrNoFileIDs)
	require.ErrorIs(t, cvm.SubmitTx(txs.NewAllocateTx("", 1).Bytes()), txs.ErrEmptyRange)
	require.ErrorIs(t, cvm.SubmitTx(txs.NewAllocateTx("r", 0).Bytes()), txs.ErrZeroCount)

	cvm.lock.RLock()
	defer cvm.lock.RUnlock()
	require.Empty(t, cvm.pendingTxs, "nothing refused may reach the pool")
}

// TestAllocateOverflowRefused proves the range's id space is finite and the
// exhaustion is refused rather than wrapped: reissuing ids from 0 would break
// the uniqueness the whole allocator exists for.
func TestAllocateOverflowRefused(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)
	vals := newTestValidators(t, 1)
	const rng, epoch = "exhausted", uint64(2)
	withFixedEpoch(t, cvm, vals, vals[0], epoch)

	// Park the range's cursor just below the top of its space.
	require.NoError(t, cvm.inner.state.SetAlloc(rng, state.Alloc{Next: ^uint64(0) - 1}))
	require.NoError(t, cvm.inner.commit())

	fp := pinning.EpochFingerprint(epoch, membersOf(vals))
	tx := txs.NewAllocateTx(rng, 4).WithAuthorization(
		epoch, 1, fp, vals[0].nodeID, uint8(ids.NodeIDSchemeMLDSA65),
		vals[0].pub.Bytes(), signAllocateAs(t, vals[0], rng, 4, epoch, 1, fp),
	)
	// Overflow is a soft failure, not a safety violation: it stages nothing and
	// the block is otherwise fine.
	blk := carry(t, cvm, tx.Bytes())
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))

	after, err := cvm.inner.state.GetAlloc(rng)
	require.NoError(t, err)
	require.Equal(t, ^uint64(0)-1, after.Next, "an overflowing allocation must not wrap the cursor")
}

// TestUnknownTransactionTypeIsRefused proves the parser and the applier agree on
// what a transaction is: a type byte neither knows is refused, not applied as
// whichever type sits first in the switch.
func TestUnknownTransactionTypeIsRefused(t *testing.T) {
	cvm, _ := newTestVM(t)
	require.ErrorIs(t, cvm.inner.processTx([]byte{0x7f, 0x00}, BlockContext{}), txs.ErrInvalidTxType)
	require.Error(t, cvm.inner.processTx(nil, BlockContext{}))
}

// TestGateErrorsAreExactlyTheSafetyViolations proves the classification a block
// is judged by: every pinned-writer refusal fails the whole block, and nothing
// else does. A soft failure misfiled as a gate error hands a denial of service
// to anyone who can submit a malformed transaction.
func TestGateErrorsAreExactlyTheSafetyViolations(t *testing.T) {
	for _, err := range []error{
		errNonOwnerAllocate, errNoValidatorSet, errAllocateReplay, errUnsignedAllocate,
		errUnknownSignerScheme, errSignerKeyMismatch, errBadAllocateSig,
		errEpochMismatch, errEpochFingerprintMismatch,
	} {
		require.Truef(t, isAllocateGateError(err), "%v must fail the block", err)
	}
	for _, err := range []error{
		nil, txs.ErrInvalidTxType, txs.ErrEmptyBucket, txs.ErrNoFileIDs,
		txs.ErrZeroCount, errStoreDown, errBadHeight,
	} {
		require.Falsef(t, isAllocateGateError(err), "%v must not fail the block", err)
	}
}

// TestMLDSA87SignerAuthorizes proves the high-value validator scheme is a real
// second signer and not a declaration: an ML-DSA-87 owner's allocate is
// authorized, and its NodeID binds its key exactly as the 65 scheme's does.
func TestMLDSA87SignerAuthorizes(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	var seed [mldsa87.SeedSize]byte
	seed[0] = 0x87
	pub, sk, err := mldsa87.NewKeyFromSeed(seed[:])
	require.NoError(t, err)

	signer, err := NewMLDSA87Signer(testIdentityChainID, pub, sk)
	require.NoError(t, err)
	derived, _, err := ids.NodeIDSchemeMLDSA87.DeriveMLDSA(testIdentityChainID, pub.Bytes())
	require.NoError(t, err)
	require.Equal(t, derived, signer.NodeID(), "the NodeID commits to the key")

	const rng, epoch = "pq-range", uint64(5)
	mem := []pinning.Member{{NodeID: signer.NodeID(), Weight: 10}}
	cvm.SetBlockContextBuilder(func(context.Context, uint64) (BlockContext, error) {
		return BlockContext{Members: mem, Proposer: signer.NodeID(), Epoch: epoch,
			IdentityChainID: testIdentityChainID}, nil
	})
	cvm.SetAllocateSigner(signer)

	base, next, err := allocate(t, cvm, rng, 9)
	require.NoError(t, err)
	require.Equal(t, uint64(0), base)
	require.Equal(t, uint64(9), next)

	// A 65-scheme key claiming the 87 owner's NodeID does not bind to it: the
	// NodeID is a commitment to the key AND to the scheme it was derived under.
	var seed65 [mldsa65.SeedSize]byte
	seed65[0] = 0x65
	pub65, sk65, err := mldsa65.NewKeyFromSeed(seed65[:])
	require.NoError(t, err)
	fp := pinning.EpochFingerprint(epoch, mem)
	sig, err := mldsa65.Sign(sk65, txs.AllocateSigningBytes(rng, 1, epoch, 99, fp), allocateSigContext, false)
	require.NoError(t, err)
	foreign := txs.NewAllocateTx(rng, 1).WithAuthorization(
		epoch, 99, fp, signer.NodeID(), uint8(ids.NodeIDSchemeMLDSA65), pub65.Bytes(), sig,
	)
	require.ErrorIs(t, carry(t, cvm, foreign.Bytes()).Verify(ctx), errSignerKeyMismatch)
}

// TestSignerSchemeMustBePostQuantum proves the verifier accepts only the ML-DSA
// family: a scheme byte naming anything else is refused rather than falling
// through to a default verification.
func TestSignerSchemeMustBePostQuantum(t *testing.T) {
	vals := newTestValidators(t, 1)
	const rng, epoch = "scheme", uint64(1)
	fp := pinning.EpochFingerprint(epoch, membersOf(vals))
	sig := signAllocateAs(t, vals[0], rng, 1, epoch, 1, fp)

	classical := txs.NewAllocateTx(rng, 1).WithAuthorization(
		epoch, 1, fp, vals[0].nodeID, 0x00, vals[0].pub.Bytes(), sig,
	)
	require.ErrorIs(t, verifyAllocateSig(classical, testIdentityChainID), errUnknownSignerScheme)

	// An unparseable public key under a real scheme is refused too, not treated
	// as a key that simply fails to verify.
	garbled := txs.NewAllocateTx(rng, 1).WithAuthorization(
		epoch, 1, fp, vals[0].nodeID, uint8(ids.NodeIDSchemeMLDSA65), []byte("not-a-key"), sig,
	)
	require.ErrorIs(t, verifyAllocateSig(garbled, testIdentityChainID), errSignerKeyMismatch)

	// And an entirely unsigned allocate.
	require.ErrorIs(t, verifyAllocateSig(txs.NewAllocateTx(rng, 1), testIdentityChainID),
		errUnsignedAllocate)
}
