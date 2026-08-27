// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/mpcvm/fhe"
)

// These tests exercise the operations F actually exposes — registering an
// encrypted value, granting and withdrawing access to it, asking the committee
// to decrypt it, and rotating the committee — and the threshold rules that make
// each of them safe.

// fundAll builds a genesis allocation funding every given key.
func fundAll(keys ...testKey) map[string]uint64 {
	alloc := make(map[string]uint64, len(keys))
	for _, k := range keys {
		alloc[k.hexAddr()] = testFund
	}
	return alloc
}

// newDecryptVM seats an n-member committee at threshold t and funds the members
// plus the two given users.
func newDecryptVM(t *testing.T, n, threshold int, users ...testKey) (*VM, []fhe.CommitteeMember, []testKey) {
	t.Helper()
	committee, keys := newCommittee(t, n)
	vm := newTestVM(t, fundAll(append(append([]testKey{}, keys...), users...)...), committee, threshold)
	return vm, committee, keys
}

// TestConfidentialLifecycle walks one encrypted value from registration to a
// completed threshold decryption — the whole reason F exists, end to end.
func TestConfidentialLifecycle(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)

	// 1. The owner registers an encrypted value. F stores its digest, never it.
	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	ct, ok := vm.Ciphertext(handle)
	require.True(t, ok)
	require.Equal(t, uint64(0), ct.Epoch, "a ciphertext is bound to the epoch it was registered in")

	// 2. The grantee, holding the permit, asks the committee to decrypt.
	req := requestTx(t, grantee, testScheme, handle, permitID, 0, 1)
	acceptOne(t, vm, req)
	requestID := deriveRequestID(handle, grantee.addr, 1)

	rec, ok := vm.Decrypt(requestID)
	require.True(t, ok)
	require.Equal(t, fhe.RequestPending, rec.Status)
	require.Equal(t, handle, rec.CiphertextHandle)
	require.Equal(t, permitID, rec.PermitID)
	require.Equal(t, uint64(0), rec.Epoch)
	require.Greater(t, rec.Expiry, rec.CreatedAt, "an unbounded request would outlive the committee that can answer it")
	require.Equal(t, rec.CreatedAt+DefaultRequestWindow, rec.Expiry)

	// 3. Two of three members attest the same result handle. F never sees the
	//    plaintext — the committee combines its shares off-chain and agrees on
	//    the handle of what came out.
	result := digestOf("decrypted-result-handle")
	acceptOne(t, vm, fulfillTx(t, members[0], requestID, result, 1))
	rec, _ = vm.Decrypt(requestID)
	require.Equal(t, fhe.RequestPending, rec.Status, "one member is not a threshold")
	require.Len(t, rec.Attestations, 1)

	acceptOne(t, vm, fulfillTx(t, members[1], requestID, result, 1))
	rec, _ = vm.Decrypt(requestID)
	require.Equal(t, fhe.RequestCompleted, rec.Status, "the threshold answers the request")
	require.Equal(t, result, rec.ResultHandle)
	require.Len(t, rec.Attestations, 2)
	require.NotZero(t, rec.CompletedAt)

	// 4. The answer is final: a third attestation is refused.
	_, err := vm.SubmitTx(fulfillTx(t, members[2], requestID, result, 1))
	require.ErrorIs(t, err, ErrRequestClosed)
}

// TestConflictingAttestationCannotStall proves a lying member buys nothing but
// its own burnt fee. It attests first, and wrong; the honest members still
// reach the threshold on the true result, because votes are tallied per value
// rather than pinned by whoever spoke first.
func TestConflictingAttestationCannotStall(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)
	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)

	liar, truth := digestOf("forged"), digestOf("true-result")

	acceptOne(t, vm, fulfillTx(t, members[2], requestID, liar, 1))
	rec, _ := vm.Decrypt(requestID)
	require.Equal(t, fhe.RequestPending, rec.Status)

	acceptOne(t, vm, fulfillTx(t, members[0], requestID, truth, 1))
	acceptOne(t, vm, fulfillTx(t, members[1], requestID, truth, 1))

	rec, _ = vm.Decrypt(requestID)
	require.Equal(t, fhe.RequestCompleted, rec.Status)
	require.Equal(t, truth, rec.ResultHandle, "the honest majority decides the answer")
	require.Len(t, rec.Attestations, 3, "the false vote is recorded, and counted against its own value")

	// The liar paid for the privilege.
	bal, _ := vm.Balance(members[2].addr)
	require.Less(t, bal, testFund)
}

// TestOnlyCommitteeAnswers proves a stranger cannot answer a decryption
// request, and a member cannot vote twice.
func TestOnlyCommitteeAnswers(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	stranger := newTestKey(t)
	committee, members := newCommittee(t, 3)
	vm := newTestVM(t, fundAll(append(append([]testKey{}, members...), owner, grantee, stranger)...), committee, 2)

	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)
	result := digestOf("r")

	_, err := vm.SubmitTx(fulfillTx(t, stranger, requestID, result, 1))
	require.ErrorIs(t, err, ErrNotCommittee)

	// Even the requester, who has every right to the answer, is not a member.
	_, err = vm.SubmitTx(fulfillTx(t, grantee, requestID, result, 2))
	require.ErrorIs(t, err, ErrNotCommittee)

	acceptOne(t, vm, fulfillTx(t, members[0], requestID, result, 1))

	// One member, one vote — including a member trying to change its mind.
	_, err = vm.SubmitTx(fulfillTx(t, members[0], requestID, result, 2))
	require.ErrorIs(t, err, ErrAlreadyAttested)
	_, err = vm.SubmitTx(fulfillTx(t, members[0], requestID, digestOf("other"), 2))
	require.ErrorIs(t, err, ErrAlreadyAttested)
}

// TestUnknownRequestCannotBeAnswered proves an attestation to a request that
// was never made is refused, so the committee cannot invent answers.
func TestUnknownRequestCannotBeAnswered(t *testing.T) {
	vm, _, members := newDecryptVM(t, 3, 2)
	_, err := vm.SubmitTx(fulfillTx(t, members[0], digestOf("never-asked"), digestOf("r"), 1))
	require.ErrorIs(t, err, ErrRequestNotFound)
}

// TestExpiredRequestCannotBeAnswered proves a request outlives nothing: once
// its window closes, no attestation is accepted and it can never complete.
func TestExpiredRequestCannotBeAnswered(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)

	now := time.Now()
	vm.clock.Set(now)
	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)

	expiry := now.Unix() + 60
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, expiry, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)

	// Still answerable inside the window.
	require.NoError(t, fulfillTx(t, members[0], requestID, digestOf("r"), 1).checkAuth(vm, expiry))

	// One second past it, closed.
	vm.clock.Set(time.Unix(expiry+1, 0))
	_, err := vm.SubmitTx(fulfillTx(t, members[0], requestID, digestOf("r"), 1))
	require.ErrorIs(t, err, ErrRequestExpired)

	// And the read surface says so, rather than reporting it as still pending.
	var reply GetDecryptReply
	require.NoError(t, (&Service{vm: vm}).GetDecrypt(nil,
		&GetDecryptArgs{RequestID: hexOf(requestID)}, &reply))
	require.Equal(t, fhe.RequestExpired.String(), reply.Request.Status)
}

// TestPermitGatesDecryption proves the permit is the whole authority for a
// decryption request: it must exist, be unrevoked, be unexpired, name THIS
// handle, name THIS grantee, and confer decrypt specifically.
func TestPermitGatesDecryption(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	stranger := newTestKey(t)
	committee, members := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(append(append([]testKey{}, members...), owner, grantee, stranger)...), committee, 1)

	now := time.Now()
	vm.clock.Set(now)
	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)

	t.Run("no such permit", func(t *testing.T) {
		_, err := vm.SubmitTx(requestTx(t, grantee, testScheme, handle, digestOf("nope"), 0, 1))
		require.ErrorIs(t, err, ErrPermitNotFound)
	})

	t.Run("permit belongs to someone else", func(t *testing.T) {
		_, err := vm.SubmitTx(requestTx(t, stranger, testScheme, handle, permitID, 0, 1))
		require.ErrorIs(t, err, ErrUnauthorized)
	})

	t.Run("permit is for another handle", func(t *testing.T) {
		// A second ciphertext the grantee has no permit for.
		other := registerTx(t, owner, testScheme, digestOf("other-value"), 3)
		acceptOne(t, vm, other)
		_, err := vm.SubmitTx(requestTx(t, grantee, testScheme, other.Subject, permitID, 0, 1))
		require.ErrorIs(t, err, ErrPermitInvalid)
	})

	t.Run("ciphertext was never registered", func(t *testing.T) {
		_, err := vm.SubmitTx(requestTx(t, grantee, testScheme, digestOf("unregistered"), permitID, 0, 1))
		require.ErrorIs(t, err, ErrCiphertextNotFound)
	})

	t.Run("permit confers compute but not decrypt", func(t *testing.T) {
		computeOnly := grantTx(t, owner, handle, grantee.addr, fhe.PermitOpCompute, 0, 4)
		acceptOne(t, vm, computeOnly)
		id := derivePermitID(handle, owner.addr, grantee.addr, fhe.PermitOpCompute, 0, 4)
		_, err := vm.SubmitTx(requestTx(t, grantee, testScheme, handle, id, 0, 1))
		require.ErrorIs(t, err, ErrPermitInvalid)
	})

	t.Run("permit has expired", func(t *testing.T) {
		expiry := now.Unix() + 30
		short := grantTx(t, owner, handle, grantee.addr, fhe.PermitOpDecrypt, expiry, 5)
		acceptOne(t, vm, short)
		id := derivePermitID(handle, owner.addr, grantee.addr, fhe.PermitOpDecrypt, expiry, 5)

		vm.clock.Set(time.Unix(expiry+1, 0))
		_, err := vm.SubmitTx(requestTx(t, grantee, testScheme, handle, id, 0, 1))
		require.ErrorIs(t, err, ErrPermitExpired)
		vm.clock.Set(now)
	})

	t.Run("permit was revoked", func(t *testing.T) {
		acceptOne(t, vm, revokeTx(t, owner, permitID, 6))
		pm, _ := vm.Permit(permitID)
		require.Equal(t, StatusRevoked, pm.Status)

		_, err := vm.SubmitTx(requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
		require.ErrorIs(t, err, ErrPermitRevoked)
	})
}

// TestOnlyOwnerGrantsAndRevokes proves a capability over an encrypted value
// comes from its owner and from nobody else — including the grantee, who cannot
// pass its access on, and cannot keep it after the owner withdraws it.
func TestOnlyOwnerGrantsAndRevokes(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	stranger := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(owner, grantee, stranger), committee, 1)

	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)

	// A stranger cannot grant over someone else's ciphertext...
	_, err := vm.SubmitTx(grantTx(t, stranger, handle, stranger.addr, fhe.PermitOpDecrypt, 0, 1))
	require.ErrorIs(t, err, ErrUnauthorized)

	// ...nor can the grantee pass its own access along.
	_, err = vm.SubmitTx(grantTx(t, grantee, handle, stranger.addr, fhe.PermitOpDecrypt, 0, 1))
	require.ErrorIs(t, err, ErrUnauthorized)

	// Granting over a ciphertext nobody registered is refused.
	_, err = vm.SubmitTx(grantTx(t, owner, digestOf("ghost"), grantee.addr, fhe.PermitOpDecrypt, 0, 3))
	require.ErrorIs(t, err, ErrCiphertextNotFound)

	// A stranger cannot withdraw someone else's grant.
	_, err = vm.SubmitTx(revokeTx(t, stranger, permitID, 1))
	require.ErrorIs(t, err, ErrUnauthorized)

	// Revoking something that was never granted is refused.
	_, err = vm.SubmitTx(revokeTx(t, owner, digestOf("no-permit"), 3))
	require.ErrorIs(t, err, ErrPermitNotFound)

	// The owner can, and once withdrawn it stays withdrawn.
	acceptOne(t, vm, revokeTx(t, owner, permitID, 3))
	_, err = vm.SubmitTx(revokeTx(t, owner, permitID, 4))
	require.ErrorIs(t, err, ErrPermitRevoked)
}

// TestRegisterIsContentAddressed proves a handle names its content: the same
// body under the same scheme is the same handle, so it cannot be registered
// twice, and a handle cannot be claimed by someone who does not have the body
// to hash.
func TestRegisterIsContentAddressed(t *testing.T) {
	a, b := newTestKey(t), newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(a, b), committee, 1)

	body := digestOf("the-encrypted-body")
	acceptOne(t, vm, registerTx(t, a, testScheme, body, 1))

	// A different account cannot re-register the same content.
	_, err := vm.SubmitTx(registerTx(t, b, testScheme, body, 1))
	require.ErrorIs(t, err, ErrCiphertextExists)

	// The same content under a DIFFERENT scheme is a different value, and is
	// registrable — a CKKS ciphertext and a BFV one are not the same object.
	acceptOne(t, vm, registerTx(t, b, "bfv-n13", body, 1))
	require.Len(t, vm.Ciphertexts(), 2)

	one, ok := vm.Ciphertext(deriveHandle(body, testScheme))
	require.True(t, ok)
	require.Equal(t, testScheme, one.Scheme)
	two, ok := vm.Ciphertext(deriveHandle(body, "bfv-n13"))
	require.True(t, ok)
	require.Equal(t, "bfv-n13", two.Scheme)
}

// TestEpochAdvance proves the committee installs its own successor by threshold
// vote, and that the change takes effect only when the threshold is reached.
func TestEpochAdvance(t *testing.T) {
	vm, _, members := newDecryptVM(t, 3, 2)
	next, nextKeys := newCommittee(t, 3)
	nextPK := []byte("epoch-1-network-key")

	// Fund the incoming committee so it can answer once seated.
	for _, k := range nextKeys {
		vm.stateLock.Lock()
		require.NoError(t, vm.ledger.Credit(k.addr, testFund))
		require.NoError(t, vm.versdb.Commit())
		vm.stateLock.Unlock()
	}

	// One vote is not enough.
	acceptOne(t, vm, advanceTx(t, members[0], 1, next, 2, nextPK, 1))
	require.Equal(t, uint64(0), vm.CurrentEpoch(), "one member is not a threshold")
	cur, _ := vm.Epoch(0)
	require.Len(t, cur.Attestations, 1)
	require.Equal(t, fhe.EpochActive, cur.Status)

	// The second vote installs it, atomically with the block.
	blk := func() *Block {
		_, err := vm.SubmitTx(advanceTx(t, members[1], 1, next, 2, nextPK, 1))
		require.NoError(t, err)
		return acceptQueued(t, vm)
	}()
	require.Equal(t, uint64(1), vm.CurrentEpoch())

	old, _ := vm.Epoch(0)
	require.Equal(t, fhe.EpochEnded, old.Status)
	require.Equal(t, blk.timestamp.Unix(), old.EndTime)

	installed, ok := vm.Epoch(1)
	require.True(t, ok)
	require.Equal(t, fhe.EpochActive, installed.Status)
	require.Equal(t, 2, installed.Threshold)
	require.Equal(t, nextPK, installed.PublicKey)
	require.Len(t, installed.Committee, 3)
	require.Empty(t, installed.Attestations, "a fresh epoch starts with no votes cast")

	// The outgoing committee no longer decides anything.
	further, _ := newCommittee(t, 3)
	_, err := vm.SubmitTx(advanceTx(t, members[2], 2, further, 2, []byte("k"), 1))
	require.ErrorIs(t, err, ErrNotCommittee)

	// The incoming one does.
	require.NoError(t, advanceTx(t, nextKeys[0], 2, further, 2, []byte("k"), 1).checkAuth(vm, time.Now().Unix()))
}

// TestEpochAdvanceRefusals proves the rules around who may rotate the committee
// and to what.
func TestEpochAdvanceRefusals(t *testing.T) {
	stranger := newTestKey(t)
	committee, members := newCommittee(t, 3)
	vm := newTestVM(t, fundAll(append(append([]testKey{}, members...), stranger)...), committee, 2)
	next, _ := newCommittee(t, 3)
	pk := []byte("k")

	// A stranger cannot propose a successor.
	_, err := vm.SubmitTx(advanceTx(t, stranger, 1, next, 2, pk, 1))
	require.ErrorIs(t, err, ErrNotCommittee)

	// Nor can a member skip an epoch or re-elect the current one.
	_, err = vm.SubmitTx(advanceTx(t, members[0], 2, next, 2, pk, 1))
	require.ErrorIs(t, err, ErrEpochMismatch)
	_, err = vm.SubmitTx(advanceTx(t, members[0], 0, next, 2, pk, 1))
	require.ErrorIs(t, err, ErrEpochMismatch)

	// One member, one vote — and voting for a rival proposal is still a second
	// vote, so a member cannot split the tally by itself.
	acceptOne(t, vm, advanceTx(t, members[0], 1, next, 2, pk, 1))
	_, err = vm.SubmitTx(advanceTx(t, members[0], 1, next, 2, pk, 2))
	require.ErrorIs(t, err, ErrAlreadyAttested)
	rival, _ := newCommittee(t, 3)
	_, err = vm.SubmitTx(advanceTx(t, members[0], 1, rival, 2, pk, 2))
	require.ErrorIs(t, err, ErrAlreadyAttested)
}

// TestRequestBindsToTheSeatedEpoch proves an answer comes from the committee
// that was seated when the request was made. A later committee holds different
// key shares and never saw the permit, so it must not be able to answer.
func TestRequestBindsToTheSeatedEpoch(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)
	next, nextKeys := newCommittee(t, 3)
	for _, k := range nextKeys {
		vm.stateLock.Lock()
		require.NoError(t, vm.ledger.Credit(k.addr, testFund))
		require.NoError(t, vm.versdb.Commit())
		vm.stateLock.Unlock()
	}

	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)

	// Rotate the committee out from under the pending request.
	acceptOne(t, vm, advanceTx(t, members[0], 1, next, 2, []byte("k"), 1))
	acceptOne(t, vm, advanceTx(t, members[1], 1, next, 2, []byte("k"), 1))
	require.Equal(t, uint64(1), vm.CurrentEpoch())

	// The NEW committee cannot answer the OLD request.
	_, err := vm.SubmitTx(fulfillTx(t, nextKeys[0], requestID, digestOf("r"), 1))
	require.ErrorIs(t, err, ErrNotCommittee)

	// The committee that was seated when it was asked still can.
	result := digestOf("r")
	acceptOne(t, vm, fulfillTx(t, members[0], requestID, result, 2))
	acceptOne(t, vm, fulfillTx(t, members[1], requestID, result, 2))
	rec, _ := vm.Decrypt(requestID)
	require.Equal(t, fhe.RequestCompleted, rec.Status)

	// A request made now belongs to the new epoch.
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 2))
	fresh, _ := vm.Decrypt(deriveRequestID(handle, grantee.addr, 2))
	require.Equal(t, uint64(1), fresh.Epoch)
}

// TestCommitteelessChainAnswersNothing proves a chain whose genesis seated
// nobody refuses every threshold decision rather than accepting one from
// anybody.
func TestCommitteelessChainAnswersNothing(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm := newTestVM(t, fundAll(owner, grantee), nil, 0)

	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)

	// There is no epoch record to name a committee, so nothing can answer.
	_, err := vm.SubmitTx(fulfillTx(t, owner, requestID, digestOf("r"), 3))
	require.ErrorIs(t, err, ErrEpochNotFound)

	// And nobody can seat themselves.
	next, _ := newCommittee(t, 3)
	_, err = vm.SubmitTx(advanceTx(t, owner, 1, next, 2, []byte("k"), 3))
	require.ErrorIs(t, err, ErrNotCommittee)
}

// TestBuildBlockWithoutParent proves block building fails closed rather than
// dereferencing a missing tip.
func TestBuildBlockWithoutParent(t *testing.T) {
	vm := &VM{}
	vm.mempool = []*Transaction{sampleTx()}
	_, err := vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errNoParentBlock)
	require.Len(t, vm.mempool, 1, "the transactions must go back to the mempool")
}

// TestBuildBlockRefusesWhenShuttingDown proves a stopping VM proposes nothing.
func TestBuildBlockRefusesWhenShuttingDown(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	_, err := vm.SubmitTx(registerTx(t, k, testScheme, digestOf("x"), 1))
	require.NoError(t, err)
	require.NoError(t, vm.Shutdown(context.Background()))
	_, err = vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errVMShutdown)
}

// TestBuildBlockWithEmptyMempool proves an idle VM proposes nothing.
func TestBuildBlockWithEmptyMempool(t *testing.T) {
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, nil, committee, 1)
	_, err := vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errNoPendingTxs)
}

// TestHeightIndexRejectsCorruptEntry proves the height index is validated when
// it is read, so a damaged entry surfaces as an error instead of a truncated id.
func TestHeightIndexRejectsCorruptEntry(t *testing.T) {
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, nil, committee, 1)

	vm.stateLock.Lock()
	require.NoError(t, vm.state.Put(heightKey(5), []byte{1, 2, 3}))
	require.NoError(t, vm.versdb.Commit())
	vm.stateLock.Unlock()

	_, err := vm.GetBlockIDAtHeight(context.Background(), 5)
	require.ErrorIs(t, err, ErrInvalidPayload)
}

// TestStateSurvivesReload proves the caches are a projection of the database
// and not the truth: rebuilding them from disk yields the same chain.
func TestStateSurvivesReload(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)

	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)
	acceptOne(t, vm, fulfillTx(t, members[0], requestID, digestOf("r"), 1))

	before, _ := vm.Decrypt(requestID)
	height, epoch := vm.height, vm.CurrentEpoch()

	require.NoError(t, vm.loadState())

	require.Equal(t, height, vm.height)
	require.Equal(t, epoch, vm.CurrentEpoch())
	after, ok := vm.Decrypt(requestID)
	require.True(t, ok)
	require.Equal(t, before.Attestations, after.Attestations)
	require.Equal(t, before.Status, after.Status)
	_, ok = vm.Ciphertext(handle)
	require.True(t, ok)
	pm, ok := vm.Permit(permitID)
	require.True(t, ok)
	require.Equal(t, StatusActive, pm.Status)
	ep, ok := vm.Epoch(0)
	require.True(t, ok)
	require.Len(t, ep.Committee, 3)
}
