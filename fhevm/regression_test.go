// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/chains/mpcvm/fhe"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/zap"
)

// Each test here pins a defence that an adversarial review found missing. They
// are written against the attack, not against the implementation: if a future
// change reopens the hole, the test that named it fails.

// C1: Transaction.effect() qualified an epoch-advance vote by the PROPOSAL, but
// the decision a member votes on is the epoch, of which exactly one is ever
// open. Two votes from one member for two different committees therefore had
// two different effects, survived admission and Verify, and collided in Accept
// — and a block that passes Verify on every validator and then fails Accept on
// every validator halts the chain at that height by design.
func TestC1_OneMemberCannotDoubleVoteOnAnEpoch(t *testing.T) {
	vm, _, members := newDecryptVM(t, 3, 2)
	proposalA, _ := newCommittee(t, 3)
	proposalB, _ := newCommittee(t, 3)

	voteA := advanceTx(t, members[0], 1, proposalA, 2, []byte("k"), 1)
	voteB := advanceTx(t, members[0], 1, proposalB, 2, []byte("k"), 2)

	require.Equal(t, voteA.effect(), voteB.effect(),
		"one member, one open decision, one effect — whatever it votes for")

	_, err := vm.SubmitTx(voteA)
	require.NoError(t, err)
	_, err = vm.SubmitTx(voteB)
	require.ErrorIs(t, err, ErrDuplicateEffect, "admission must refuse the second vote")

	// A peer can still propose the pair. Consensus must refuse the block rather
	// than certify it and then fail to apply it.
	require.ErrorIs(t, forceBlock(vm, voteA, voteB).Verify(context.Background()),
		ErrDuplicateEffect, "Verify must refuse a block carrying both")
}

// H1: a payer could queue a nonce gap. Admission took it (any nonce above the
// committed one), Verify refused the block for it, and the engine discards a
// Verify-failed block WITHOUT calling Reject — so the transaction vanished and
// its effect claim did not. Register's effect is payer-independent, so any
// funded account could permanently block any handle on that node, for free, and
// take the rest of the queue with it every round.
func TestH1_PoisonedQueueIsImpossible(t *testing.T) {
	attacker := newTestKey(t)
	victim := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(attacker, victim), committee, 1)

	target := digestOf("a-handle-someone-else-wants")

	// The gap never enters the queue, so it can never poison a block.
	_, err := vm.SubmitTx(registerTx(t, attacker, testScheme, target, 3))
	require.ErrorIs(t, err, ErrBadNonce)
	require.Empty(t, vm.mempool)
	require.Empty(t, vm.claims, "a refused transaction claims nothing")

	// The victim's honest registration goes through untouched.
	honest := registerTx(t, victim, testScheme, target, 1)
	_, err = vm.SubmitTx(honest)
	require.NoError(t, err)
	acceptQueued(t, vm)
	rec, ok := vm.Ciphertext(honest.Subject)
	require.True(t, ok)
	require.Equal(t, victim.addr, fee.Account(rec.Owner))
}

// H1: even a well-nonced transaction that is selected into a block and then
// discarded must leave its claim intact and its place in the queue, because the
// engine is free to drop a proposal it never accepts or rejects.
func TestH1_ClaimTracksTheQueueExactly(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	tx := registerTx(t, k, testScheme, digestOf("claimed"), 1)
	_, err := vm.SubmitTx(tx)
	require.NoError(t, err)
	require.Len(t, vm.claims, 1)
	require.Equal(t, uint64(1), vm.queued[k.addr])

	// Build and then walk away from the proposal entirely — no Accept, no Reject.
	_, err = vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.Len(t, vm.mempool, 1, "the transaction is still queued")
	require.Len(t, vm.claims, 1, "and still holds exactly its own claim")

	// It still works, and acceptance is what clears both.
	acceptQueued(t, vm)
	require.Empty(t, vm.mempool)
	require.Empty(t, vm.claims)
	require.Empty(t, vm.queued)

	// With the claim released, the handle is reachable again by whoever needs it
	// — a claim can no longer outlive the transaction that made it.
	_, ok := vm.Ciphertext(tx.Subject)
	require.True(t, ok)
}

// H1: one unfit transaction must not take a block's worth of honest ones with
// it. BuildBlock runs the same admission rule Verify runs and simply leaves out
// what does not fit.
func TestH1_OneUnfitTransactionDoesNotDestroyTheBlock(t *testing.T) {
	rich := newTestKey(t)
	poor := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{
		rich.hexAddr(): testFund,
		poor.hexAddr(): 1_000, // cannot afford a single operation
	}, committee, 1)

	good := registerTx(t, rich, testScheme, digestOf("good"), 1)
	_, err := vm.SubmitTx(good)
	require.NoError(t, err)

	// The poor payer's transaction is refused at admission, but a peer could
	// still gossip it into our mempool shape; put it there directly to prove
	// selection copes.
	broke := registerTx(t, poor, testScheme, digestOf("broke"), 1)
	vm.mempoolLock.Lock()
	vm.mempool = append(vm.mempool, broke)
	vm.mempoolLock.Unlock()

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.Len(t, blk.(*Block).transactions, 1, "the unaffordable one is left out")
	require.NoError(t, blk.(*Block).Verify(context.Background()),
		"a proposer cannot build a block its own Verify would reject")
	require.NoError(t, blk.(*Block).Accept(context.Background()))

	_, ok := vm.Ciphertext(good.Subject)
	require.True(t, ok, "the honest transaction is not collateral damage")
}

// H2: nothing bounded a block's timestamp or height against its parent, and
// chain time drives every expiry F enforces. A proposer could rewind time to
// revive an expired permit, jump to year 36812 to expire everything at once, or
// skip heights entirely.
func TestH2_ChainTimeAndHeightAreBounded(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	base := time.Now()
	vm.clock.Set(base)
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("tip"), 1))
	parent := vm.lastBlock

	next := registerTx(t, k, testScheme, digestOf("next"), 2)
	_, err := vm.SubmitTx(next)
	require.NoError(t, err)

	at := func(ts time.Time, height uint64) *Block {
		blk := &Block{
			parentID: vm.lastAccepted, height: height, timestamp: ts,
			transactions: []*Transaction{next}, vm: vm,
		}
		blk.id = blk.computeID()
		return blk
	}

	// Time may not run backwards past the parent.
	require.ErrorIs(t,
		at(parent.timestamp.Add(-time.Second), parent.height+1).Verify(context.Background()),
		ErrInvalidBlock)

	// Nor leap beyond the skew allowance.
	require.ErrorIs(t,
		at(vm.clock.Time().Add(MaxFutureSkew+time.Second), parent.height+1).Verify(context.Background()),
		ErrInvalidBlock)
	require.ErrorIs(t,
		at(time.Unix(1<<40, 0), parent.height+1).Verify(context.Background()),
		ErrInvalidBlock)

	// Heights are consecutive.
	require.ErrorIs(t, at(vm.clock.Time(), parent.height+2).Verify(context.Background()), ErrInvalidBlock)
	require.ErrorIs(t, at(vm.clock.Time(), parent.height).Verify(context.Background()), ErrInvalidBlock)

	// A block that sits correctly on its parent is fine, including one exactly
	// at the parent's timestamp and one at the edge of the allowance.
	require.NoError(t, at(parent.timestamp, parent.height+1).Verify(context.Background()))
	require.NoError(t, at(vm.clock.Time().Add(MaxFutureSkew), parent.height+1).Verify(context.Background()))
}

// H2: a proposer must never produce a block its own Verify would reject. Two
// blocks inside one clock tick is the ordinary case — chain time steps forward
// anyway — and a clock so far behind its own tip that it cannot step forward
// legally declines to propose.
func TestH2_ProposerNeverBuildsABlockItWouldReject(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	base := time.Now()
	vm.clock.Set(base)
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("first"), 1))
	parent := vm.lastBlock

	// The clock has not moved: the ordinary two-blocks-in-one-tick case.
	_, err := vm.SubmitTx(registerTx(t, k, testScheme, digestOf("second"), 2))
	require.NoError(t, err)
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.True(t, blk.Timestamp().After(parent.Timestamp()),
		"chain time advances even when the proposer's clock does not")
	require.NoError(t, blk.(*Block).Verify(context.Background()))
	require.NoError(t, blk.(*Block).Accept(context.Background()))

	// A clock an hour behind its own tip cannot step forward legally, so it
	// proposes nothing rather than a block it would itself reject.
	vm.clock.Set(base.Add(-time.Hour))
	_, err = vm.SubmitTx(registerTx(t, k, testScheme, digestOf("third"), 3))
	require.NoError(t, err)
	_, err = vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errClockBehind)
}

// H3: the package claimed it holds no ciphertext body "structurally, not as a
// matter of discipline". It was discipline. Gas had no length term, nothing
// bounded Payload or Scheme, encoding/json ignored members it did not know, and
// Accept persists the transaction verbatim — so a megabyte of ciphertext rode
// onto the chain inside a register payload, for the same 81,000,000 nLUX a
// hundred bytes cost, and came back out of the block store.
func TestH3_BytesArePricedAndBounded(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	digest := digestOf("smuggled")
	handle := deriveHandle(digest, testScheme)

	// A payload that is a superset of the schema is refused outright: there is
	// no member to hide anything in.
	fat, err := json.Marshal(struct {
		Digest [32]byte `json:"digest"`
		Type   uint8    `json:"type"`
		Level  int      `json:"level"`
		Size   uint32   `json:"size"`
		Body   []byte   `json:"body"`
	}{Digest: digest, Type: 4, Level: 3, Size: 4096, Body: bytes.Repeat([]byte("X"), 1024)})
	require.NoError(t, err)

	smuggle := k.sign(t, &Transaction{
		Type: TxRegisterCiphertext, Scheme: testScheme, Payer: k.addr,
		Subject: handle, GasLimit: testGas, Nonce: 1, Payload: fat,
	})
	require.ErrorIs(t, smuggle.SyntacticVerify(), ErrInvalidPayload,
		"a payload the schema does not describe is not a payload")
	_, err = vm.SubmitTx(smuggle)
	require.ErrorIs(t, err, ErrInvalidPayload)

	// Trailing bytes after a well-formed payload are refused too.
	trailing := k.sign(t, &Transaction{
		Type: TxRegisterCiphertext, Scheme: testScheme, Payer: k.addr,
		Subject: handle, GasLimit: testGas, Nonce: 1,
		Payload: append(mustJSON(t, RegisterPayload{Digest: digest, Type: 4, Level: 3, Size: 4096}),
			[]byte(`{"body":"more"}`)...),
	})
	require.ErrorIs(t, trailing.SyntacticVerify(), ErrInvalidPayload)

	// Bulk is bounded outright, whatever shape it claims. The payload here is
	// VALID and decodes to exactly the schema — whitespace is not content — so
	// the only thing that can refuse it is the length bound itself. Filling it
	// with bytes that are not JSON would prove nothing: the decoder would refuse
	// those with or without a bound, and the test would pass over a chain that
	// had none.
	padded := append(mustJSON(t, RegisterPayload{Digest: digest, Type: 4, Level: 3, Size: 4096}),
		bytes.Repeat([]byte(" "), MaxPayload)...)
	require.Greater(t, len(padded), MaxPayload)
	huge := k.sign(t, &Transaction{
		Type: TxRegisterCiphertext, Scheme: testScheme, Payer: k.addr,
		Subject: handle, GasLimit: testGas, Nonce: 1, Payload: padded,
	})
	require.ErrorIs(t, huge.SyntacticVerify(), ErrInvalidPayload)

	// The control: the same value, unpadded, is accepted — so what was refused
	// was the size and nothing else.
	require.NoError(t, k.sign(t, &Transaction{
		Type: TxRegisterCiphertext, Scheme: testScheme, Payer: k.addr,
		Subject: handle, GasLimit: testGas, Nonce: 1,
		Payload: mustJSON(t, RegisterPayload{Digest: digest, Type: 4, Level: 3, Size: 4096}),
	}).SyntacticVerify())

	// And Scheme is not a second unpriced channel on the operations that ignore
	// it: it is bounded on every operation.
	_, permitID := seedPermit(t, vm, k, k, fhe.PermitOpDecrypt, 0)
	wide := k.sign(t, &Transaction{
		Type: TxRevokePermit, Payer: k.addr, Subject: permitID,
		Scheme:   string(bytes.Repeat([]byte("A"), MaxScheme+1)),
		GasLimit: testGas, Nonce: 3, Payload: mustJSON(t, RevokePayload{}),
	})
	require.ErrorIs(t, wide.SyntacticVerify(), ErrInvalidPayload)
}

// H3: what a transaction stores it pays for. Two identical operations differing
// only in payload length must not cost the same.
func TestH3_LongerPayloadCostsMore(t *testing.T) {
	base, err := GasFor(&Transaction{Type: TxRevokePermit, Payload: mustJSON(nil, RevokePayload{})})
	require.NoError(t, err)

	long, err := GasFor(&Transaction{
		Type:    TxRevokePermit,
		Payload: mustJSON(nil, RevokePayload{Reason: string(bytes.Repeat([]byte("r"), 1000))}),
	})
	require.NoError(t, err)

	require.Greater(t, long, base, "a longer payload must cost more")
	require.GreaterOrEqual(t, uint64(long-base), uint64(1000*GasPerByte),
		"every stored byte is priced")

	// The scheme string is stored too, so it is priced too.
	wide, err := GasFor(&Transaction{
		Type: TxRevokePermit, Scheme: "0123456789abcdef",
		Payload: mustJSON(nil, RevokePayload{}),
	})
	require.NoError(t, err)
	require.Equal(t, base+fee.Gas(16*GasPerByte), wide)
}

// H3: a committee is bounded, so the unauthenticated work a transaction can
// demand before its signature is checked is bounded with it.
func TestH3_CommitteeIsBounded(t *testing.T) {
	big, _ := newCommittee(t, MaxCommittee+1)
	require.ErrorIs(t, ValidateCommittee(big, 2, []byte("k")), ErrInvalidCommittee)

	ok, _ := newCommittee(t, MaxCommittee)
	require.NoError(t, ValidateCommittee(ok, 2, []byte("k")))
}

// H5: ValidateCommittee deduplicated NodeID, but a member's VOTING IDENTITY is
// addressOf(PublicKey). n seats sharing one key passed every check and seated a
// threshold only one account could ever vote toward — so no decryption could
// complete and the committee could never rotate itself out, while the chain
// reported itself fully seated and healthy.
func TestH5_CommitteeIsDedupedByVotingIdentity(t *testing.T) {
	one := newTestKey(t)
	shared := make([]fhe.CommitteeMember, 3)
	for i := range shared {
		shared[i] = fhe.CommitteeMember{
			NodeID:    ids.GenerateTestNodeID(), // distinct
			PublicKey: one.pub,                  // identical
			Weight:    1,
		}
	}
	sort.Slice(shared, func(i, j int) bool { return shared[i].NodeID.Compare(shared[j].NodeID) < 0 })
	for i := range shared {
		shared[i].Index = i
	}

	require.ErrorIs(t, ValidateCommittee(shared, 3, []byte("pk")), ErrInvalidCommittee,
		"three seats and one voter is not a three-of-three committee")

	// Genesis refuses it too, so a chain cannot be born unable to answer.
	logger := log.NewNoOpLogger()
	gb, err := json.Marshal(Genesis{
		Version: 1, Timestamp: time.Now().Unix(),
		Committee: shared, Threshold: 3, PublicKey: []byte("pk"),
	})
	require.NoError(t, err)
	vm := &VM{}
	err = vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: logger},
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  gb,
	})
	require.ErrorIs(t, err, ErrInvalidCommittee)

	// And an epoch proposal carrying one is refused before anyone votes on it.
	advance := &Transaction{
		Type: TxAdvanceEpoch, Nonce: 1,
		Subject: committeeDigest(1, 3, []byte("pk"), shared),
		Payload: mustJSON(t, AdvancePayload{Epoch: 1, Committee: shared, Threshold: 3, PublicKey: []byte("pk")}),
	}
	require.ErrorIs(t, advance.SyntacticVerify(), ErrInvalidCommittee)
}

// H4: one vote per member, no revote, no timeout, no reset — and the tally only
// cleared when the advance that could not happen happened. A committee that
// split its vote could never rotate again, which at unanimity one member could
// do alone, and which an honest DKG race could do with no adversary at all.
// A member's LATEST vote is now its vote.
func TestH4_ASplitVoteCanBeResolved(t *testing.T) {
	vm, _, members := newDecryptVM(t, 3, 3) // unanimity: the worst case
	agreed, _ := newCommittee(t, 3)
	stale, _ := newCommittee(t, 3)
	pk := []byte("k")

	// One member votes for a proposal the others will not back.
	acceptOne(t, vm, advanceTx(t, members[0], 1, stale, 3, pk, 1))
	acceptOne(t, vm, advanceTx(t, members[1], 1, agreed, 3, pk, 1))
	acceptOne(t, vm, advanceTx(t, members[2], 1, agreed, 3, pk, 1))
	require.Equal(t, uint64(0), vm.CurrentEpoch(), "no proposal has unanimity yet")

	ep, _ := vm.Epoch(0)
	require.Len(t, ep.Attestations, 3, "one entry per member, not one per vote")

	// The dissenter changes its mind. Its new vote REPLACES the old one.
	acceptOne(t, vm, advanceTx(t, members[0], 1, agreed, 3, pk, 2))

	require.Equal(t, uint64(1), vm.CurrentEpoch(), "the committee converged and rotated")
	installed, ok := vm.Epoch(1)
	require.True(t, ok)
	require.Len(t, installed.Committee, 3)
	require.Empty(t, installed.Attestations, "a fresh epoch starts with no votes cast")

	old, _ := vm.Epoch(0)
	require.Len(t, old.Attestations, 3, "a member's second vote replaced its first")
	require.Equal(t, 3, tally(old.Attestations, committeeDigest(1, 3, pk, agreed)))
}

// H4: the same applies to a decryption. A member that attested a result nobody
// else saw can withdraw it in favour of the one the committee agreed on.
func TestH4_AMemberCanCorrectItsAttestation(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 3, owner, grantee)

	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)

	wrong, right := digestOf("wrong"), digestOf("right")
	acceptOne(t, vm, fulfillTx(t, members[0], requestID, wrong, 1))
	acceptOne(t, vm, fulfillTx(t, members[1], requestID, right, 1))
	acceptOne(t, vm, fulfillTx(t, members[2], requestID, right, 1))

	rec, _ := vm.Decrypt(requestID)
	require.Equal(t, fhe.RequestPending, rec.Status, "two of three is not unanimity")

	acceptOne(t, vm, fulfillTx(t, members[0], requestID, right, 2))
	rec, _ = vm.Decrypt(requestID)
	require.Equal(t, fhe.RequestCompleted, rec.Status)
	require.Equal(t, right, rec.ResultHandle)
	require.Len(t, rec.Attestations, 3, "one entry per member")
	require.Zero(t, tally(rec.Attestations, wrong), "the withdrawn vote counts for nothing")
}

// H6: pendingBlocks was written under one mutex (BuildBlock) and read under
// another (the Accept-abort path, via loadStateLocked). Two mutexes over one
// map is a data race, and a concurrent map access in Go is a fatal throw the
// process cannot recover from. It has one owner now: stateLock, with the rest
// of the chain state. Run under -race.
func TestH6_BlockBookkeepingHasOneOwner(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("seed"), 1))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	nonce := uint64(2)

	// Proposer: writes pendingBlocks.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := vm.SubmitTx(registerTx(t, k, testScheme, digestOf(strconv.FormatUint(nonce, 10)), nonce)); err == nil {
				nonce++
			}
			_, _ = vm.BuildBlock(context.Background())
		}
	}()

	// Cache reload: the Accept-abort path, which reads pendingBlocks.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = vm.loadState()
		}
	}()

	// Readers on the consensus surface.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			tip, _ := vm.LastAccepted(context.Background())
			_, _ = vm.GetBlock(context.Background(), tip)
			_, _ = vm.HealthCheck(context.Background())
			_, _ = vm.GetBlockIDAtHeight(context.Background(), 1)
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// M1: DecryptRecord.PermitID was written and read by nothing but the RPC view,
// so an owner who withdrew a capability watched the committee answer the
// request anyway and deliver the plaintext to the callback. Revocation now
// reaches an in-flight request.
func TestM1_RevocationStopsAnInFlightDecryption(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)

	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)

	// One member has already answered when the owner withdraws consent.
	result := digestOf("plaintext-handle")
	acceptOne(t, vm, fulfillTx(t, members[0], requestID, result, 1))
	acceptOne(t, vm, revokeTx(t, owner, permitID, 3))

	// The committee can no longer complete it.
	_, err := vm.SubmitTx(fulfillTx(t, members[1], requestID, result, 1))
	require.ErrorIs(t, err, ErrPermitRevoked)

	// And a peer forcing it into a block gets a revert, not an answer.
	forced := fulfillTx(t, members[1], requestID, result, 1)
	blk := forceBlock(vm, forced)
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))

	rec, _ := vm.Decrypt(requestID)
	require.Equal(t, fhe.RequestPending, rec.Status, "a revoked permit answers nothing")
	require.Len(t, rec.Attestations, 1, "the second attestation never landed")
}

// M1: expiry bounds the ASK, not the ANSWER. A permit that ran out after a
// request was properly made does not strand it — the grantee asked in time, and
// the committee answering later is not the grantee acting.
func TestM1_ExpiryDoesNotStrandAnAnsweredRequest(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)

	base := time.Now()
	vm.clock.Set(base)
	permitExpiry := base.Unix() + 60
	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, permitExpiry)

	// The request is made in time, with a window that outlasts the permit.
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, base.Unix()+10_000, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)

	// The permit lapses; the committee answers afterwards.
	vm.clock.Set(time.Unix(permitExpiry+1, 0))
	result := digestOf("answer")
	acceptOne(t, vm, fulfillTx(t, members[0], requestID, result, 1))
	acceptOne(t, vm, fulfillTx(t, members[1], requestID, result, 1))

	rec, _ := vm.Decrypt(requestID)
	require.Equal(t, fhe.RequestCompleted, rec.Status,
		"the grantee asked while it could; a lapsed permit is not a withdrawn one")
	require.Equal(t, result, rec.ResultHandle)
}

// L1: wire.go claimed "canonical: parse rejects trailing bytes". That was true
// of a transaction and not of a block — parseBlock walked the transaction blob
// by the declared lengths and never checked it had consumed it, so a block had
// many valid encodings and one id.
func TestL1_BlockEncodingIsCanonical(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("canon"), 1))
	blk := vm.lastBlock

	// Its own encoding round-trips.
	again, err := vm.ParseBlock(context.Background(), blk.Bytes())
	require.NoError(t, err)
	require.Equal(t, blk.ID(), again.ID())

	// Bytes inside the transaction blob that no length covers are refused.
	padded := blockBytesWithBlobPadding(blk, bytes.Repeat([]byte{0xAA}, 4096))
	require.NotEqual(t, blk.Bytes(), padded)
	_, err = vm.ParseBlock(context.Background(), padded)
	require.ErrorIs(t, err, ErrInvalidPayload)

	// So are bytes after the message.
	_, err = vm.ParseBlock(context.Background(), append(blk.Bytes(), 0xff))
	require.ErrorIs(t, err, ErrInvalidPayload)
}

// L2: the type walk had three blind spots — it did not descend into interface
// fields, it exempted every 32-byte array from the name check, and its token
// list is a denylist, which cannot be complete. The denylist stays as a
// tripwire for NEW types; what actually holds the line is the schema pin below.
func TestL2_WalkerSeesWhatItClaimedTo(t *testing.T) {
	type viaInterface struct {
		Handle [32]byte
		Extra  any
	}
	require.NotEmpty(t, walkType(reflect.TypeOf(viaInterface{}), "iface", map[reflect.Type]bool{}),
		"a persisted record cannot hold an interface: it would hold anything")

	type viaFixedArray struct {
		SecretShare [32]byte
	}
	require.NotEmpty(t, walkType(reflect.TypeOf(viaFixedArray{}), "arr", map[reflect.Type]bool{}),
		"a share is exactly 32 bytes; being id-sized is not being an id")

	// The real records still pass.
	for _, r := range persistedTypes() {
		require.Emptyf(t, walkType(r, r.Name(), map[reflect.Type]bool{}),
			"%s must pass its own walk", r.Name())
	}
}

// H2, residual: chain time is monotone and bounded ahead, and that is ALL a
// chain can promise about it. Within [parent timestamp, local clock + skew] the
// proposer still chooses, so a permit that lapsed during a gap in block
// production can still authorize one request in the block that closes the gap.
//
// This test measures that freedom rather than leaving it unexamined: the window
// is exactly the time since the last block. On a chain producing blocks it is
// seconds; on an idle chain it is the length of the idle period. Removing it
// entirely means expiries counted in block heights, which no proposer can
// rewind — a change to the grant API, recorded in LLM.md, not a patch.
func TestH2_ProposerFreedomIsExactlyTheGapSinceTheLastBlock(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, _ := newDecryptVM(t, 3, 2, owner, grantee)

	base := time.Now()
	vm.clock.Set(base)
	expiry := base.Unix() + 60
	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, expiry)
	parent := vm.lastBlock

	// Long past the permit's expiry, admission refuses the request.
	vm.clock.Set(time.Unix(expiry+100_000, 0))
	req := requestTx(t, grantee, testScheme, handle, permitID, 0, 1)
	_, err := vm.SubmitTx(req)
	require.ErrorIs(t, err, ErrPermitExpired)

	at := func(ts time.Time) *Block {
		blk := &Block{
			parentID: vm.lastAccepted, height: parent.height + 1, timestamp: ts,
			transactions: []*Transaction{req}, vm: vm,
		}
		blk.id = blk.computeID()
		return blk
	}

	// The proposer cannot go below the parent, which is the bound that exists.
	require.ErrorIs(t, at(parent.timestamp.Add(-time.Second)).Verify(context.Background()),
		ErrInvalidBlock)

	// Inside the window it can, and the request is authorized — by a permit that
	// has, in wall-clock terms, expired. The block is valid; the transaction
	// applies. This is the residual, and it is exactly this large.
	inside := at(time.Unix(expiry-1, 0))
	require.NoError(t, inside.Verify(context.Background()))
	require.NoError(t, inside.Accept(context.Background()))
	_, ok := vm.Decrypt(deriveRequestID(handle, grantee.addr, 1))
	require.True(t, ok)

	// And it closes behind itself: chain time has now passed the expiry, so no
	// later block can reach back. A second request is refused by consensus, not
	// merely by admission.
	vm.clock.Set(time.Unix(expiry+100_000, 0))
	later := requestTx(t, grantee, testScheme, handle, permitID, 0, 2)
	next := &Block{
		parentID: vm.lastAccepted, height: vm.height + 1,
		timestamp:    vm.lastBlock.timestamp.Add(2 * time.Second), // now past the expiry
		transactions: []*Transaction{later}, vm: vm,
	}
	next.id = next.computeID()
	require.NoError(t, next.Verify(context.Background()))
	require.NoError(t, next.Accept(context.Background()))
	_, ok = vm.Decrypt(deriveRequestID(handle, grantee.addr, 2))
	require.False(t, ok, "the expired permit authorizes nothing once chain time passes it")
}

// blockBytesWithBlobPadding rebuilds a block's wire form with extra bytes
// appended to the transaction blob that no TxLens entry covers. It is
// Block.Bytes verbatim apart from that one append, which is what makes it a
// fair test of the parser rather than of the builder.
func blockBytesWithBlobPadding(b *Block, pad []byte) []byte {
	txLens := make([]uint32, len(b.transactions))
	var txBlob []byte
	for i, tx := range b.transactions {
		txb := tx.Bytes()
		txLens[i] = uint32(len(txb))
		txBlob = append(txBlob, txb...)
	}
	txBlob = append(txBlob, pad...)

	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(txBlob) + 4*len(txLens) + 128)
	txLensOff := writeU32List(bld, txLens)
	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, b.parentID[:])
	ob.SetUint64(blkHeight, b.height)
	ob.SetInt64(blkTime, b.timestamp.Unix())
	ob.SetList(blkTxLens, txLensOff, len(txLens))
	ob.SetBytes(blkTxBlob, txBlob)
	ob.FinishAsRoot()
	return bld.Finish()
}

// M3: a follower could not verify a block whose parent it had only parsed. The
// in-flight block set was written in exactly one place — BuildBlock — so a block
// arriving from a peer was never findable by id, and its child failed with
// "verify parent: not found" no matter what it contained.
//
// The parent lookup is what this fixes. Note what it does NOT fix: Verify checks
// nonces against COMMITTED state, so two blocks in flight from the SAME payer
// still cannot both verify — the second reads a nonce the first has not yet
// committed. Verifying against the parent's resulting state needs a per-block
// overlay and is a separate change; keyvm has the same limit.
func TestM3_AFollowerCanVerifyAgainstAParentItOnlyParsed(t *testing.T) {
	first, second := newTestKey(t), newTestKey(t)
	committee, _ := newCommittee(t, 1)
	proposer := newTestVM(t, fundAll(first, second), committee, 1)
	follower := newTestVM(t, fundAll(first, second), committee, 1)

	build := func(k testKey, handle string) *Block {
		_, err := proposer.SubmitTx(registerTx(t, k, testScheme, digestOf(handle), 1))
		require.NoError(t, err)
		blk, err := proposer.BuildBlock(context.Background())
		require.NoError(t, err)
		return blk.(*Block)
	}

	b1 := build(first, "one")
	require.NoError(t, b1.Accept(context.Background()))
	b2 := build(second, "two") // built on b1, still in flight

	// The follower accepts neither. b2 must still verify: its parent is a block
	// the follower has only parsed.
	p1, err := follower.ParseBlock(context.Background(), b1.Bytes())
	require.NoError(t, err)
	require.NoError(t, p1.Verify(context.Background()))

	p2, err := follower.ParseBlock(context.Background(), b2.Bytes())
	require.NoError(t, err)
	require.NoError(t, p2.Verify(context.Background()),
		"a verified parent must be findable, whoever built it")
}

// M3: the tracker must not become the leak that an unreleased claim was. The
// engine may drop a block it never accepts and never rejects, so nothing else
// removes it — anything at or below the last accepted height is decided or
// orphaned and must not be retained.
func TestM3_TheInFlightSetIsBounded(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	for nonce := uint64(1); nonce <= 4; nonce++ {
		acceptOne(t, vm, registerTx(t, k, testScheme, digestOf(string(rune('a'+nonce))), nonce))
	}

	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	for id, blk := range vm.pendingBlocks {
		require.Greater(t, blk.height, vm.height,
			"block %s at height %d is at or below the accepted height %d", id, blk.height, vm.height)
	}
}

// C2: Verify required only that a block's height was its parent's plus one, and
// never that the parent was the TIP. A block at height 2 whose parent is the
// long-since-accepted block at height 1 satisfies that perfectly, so a chain at
// height 3 verified it, accepted it, and rewound: the last-accepted pointer, the
// in-memory height and the height index all moved back to the orphan, while the
// index still named the abandoned block at height 3. Every peer bootstrapping
// from that index was served an incoherent chain.
func TestC2_AnOrphanCannotRewindTheChain(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("one"), 1))
	forkPoint, forkTime := vm.lastAccepted, vm.lastBlock.timestamp
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("two"), 2))
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("three"), 3))
	tip, height := vm.lastAccepted, vm.height
	require.Equal(t, uint64(3), height)

	// Everything else about this block is impeccable: the height follows its
	// parent, the time follows its parent and is inside the skew allowance, and
	// its transaction carries the payer's next nonce against committed state.
	orphan := &Block{
		parentID:     forkPoint,
		height:       2,
		timestamp:    forkTime.Add(time.Second),
		transactions: []*Transaction{registerTx(t, k, testScheme, digestOf("rewind"), 4)},
		vm:           vm,
	}
	orphan.id = orphan.computeID()

	require.ErrorIs(t, orphan.Verify(context.Background()), ErrNotOnTip)
	require.ErrorIs(t, orphan.Accept(context.Background()), ErrNotOnTip,
		"Accept decides this too: Verify judged an earlier tip")

	require.Equal(t, height, vm.height, "the chain did not rewind")
	require.Equal(t, tip, vm.lastAccepted)
	at2, err := vm.GetBlockIDAtHeight(context.Background(), 2)
	require.NoError(t, err)
	require.NotEqual(t, orphan.id, at2, "the height index still names the accepted chain")
	_, ok := vm.Ciphertext(orphan.transactions[0].Subject)
	require.False(t, ok, "and applied nothing")

	// The control: the same transaction in a block that DOES extend the tip is
	// accepted. What was refused is the parent, not the contents.
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("rewind"), 4))
	require.Equal(t, uint64(4), vm.height)
}

// C2: Accept re-decides it because the tip moves between the two calls. The
// engine may verify a block, accept a sibling, and only then accept the first —
// at which point it no longer extends anything.
func TestC2_ATipThatMovesAfterVerifyIsCaughtByAccept(t *testing.T) {
	first, second := newTestKey(t), newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(first, second), committee, 1)

	a := forceBlock(vm, registerTx(t, first, testScheme, digestOf("a"), 1))
	b := forceBlock(vm, registerTx(t, second, testScheme, digestOf("b"), 1))
	require.NotEqual(t, a.id, b.id, "two distinct siblings on one parent")

	require.NoError(t, a.Verify(context.Background()))
	require.NoError(t, b.Verify(context.Background()), "both verify against the same tip")

	require.NoError(t, a.Accept(context.Background()))
	require.ErrorIs(t, b.Accept(context.Background()), ErrNotOnTip,
		"the sibling no longer extends the tip, whatever Verify said earlier")
	require.Equal(t, uint64(1), vm.height)
}

// H7: MaxBlockTxs was applied by Verify, and Verify runs after the parse — so
// nothing bounded what a peer could make this node parse, hash and allocate
// before a single check had run. An 8 MB message carrying 1,524 transactions
// parsed to completion. Both bounds belong at the first byte, and neither
// implies the other: the byte bound limits what is read, the count bound limits
// what is verified, and a small message can still declare a great many tiny
// transactions.
func TestH7_ABlockIsBoundedInBytesAndInCount(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	// Bytes: a block over the size bound is refused before it is decoded.
	fat := registerTx(t, k, testScheme, digestOf("fat"), 1)
	fat.Payload = bytes.Repeat([]byte("A"), MaxPayload)
	k.sign(t, fat)
	bulk := make([]*Transaction, 0, 32)
	for len(bulk) < 32 {
		bulk = append(bulk, fat)
	}
	huge := &Block{parentID: vm.lastAccepted, height: 1, timestamp: vm.clock.Time(), transactions: bulk, vm: vm}
	raw := huge.Bytes()
	require.Greater(t, len(raw), MaxBlockSize)
	_, err := vm.ParseBlock(context.Background(), raw)
	require.ErrorIs(t, err, ErrInvalidPayload, "an oversize block is refused at the first byte")

	// Count: a block UNDER the size bound may still declare more transactions
	// than may ever be verified, so the count is bounded at the parse too.
	tiny := &Transaction{Type: TxRevokePermit, Nonce: 1, Payload: mustJSON(t, RevokePayload{})}
	many := make([]*Transaction, 0, MaxBlockTxs+1)
	for len(many) < MaxBlockTxs+1 {
		many = append(many, tiny)
	}
	crowd := &Block{parentID: vm.lastAccepted, height: 1, timestamp: vm.clock.Time(), transactions: many, vm: vm}
	crowded := crowd.Bytes()
	require.LessOrEqual(t, len(crowded), MaxBlockSize, "this one is small; only the count is out of bounds")
	_, err = vm.ParseBlock(context.Background(), crowded)
	require.ErrorIs(t, err, ErrInvalidPayload)

	// A block this node builds is held to the byte bound too, so a proposer
	// cannot produce one its peers refuse to parse.
	require.ErrorIs(t, huge.Verify(context.Background()), ErrInvalidBlock)

	// The control: one transaction under both bounds round-trips.
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("ordinary"), 1))
	_, err = vm.ParseBlock(context.Background(), vm.lastBlock.Bytes())
	require.NoError(t, err)
}

// H7: selection stops at the byte bound as well as the count, so the proposer
// and the parser agree. Stopping only on the count let 1024 ordinary
// transactions — each carrying an ML-DSA-65 public key and signature — build a
// 5 MB block this node's own parser refuses.
func TestH7_SelectionStopsAtTheByteBound(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1 << 50}, committee, 1)

	// Ordinary register transactions — nothing oversized about any of them. What
	// makes them heavy is the fixed part: an ML-DSA-65 public key and signature,
	// about 5 KB a transaction, which no payload bound touches.
	const queued = 450
	for nonce := uint64(1); nonce <= queued; nonce++ {
		_, err := vm.SubmitTx(registerTx(t, k, testScheme, digestOf(strconv.FormatUint(nonce, 10)), nonce))
		require.NoError(t, err)
	}
	require.Len(t, vm.mempool, queued)

	blkIntf, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := blkIntf.(*Block)

	require.LessOrEqual(t, len(blk.Bytes()), MaxBlockSize,
		"the proposer stopped at the size its own parser enforces")
	require.Less(t, len(blk.transactions), queued, "so it could not take them all")
	require.Less(t, len(blk.transactions), MaxBlockTxs,
		"and the BYTE bound is what stopped it, well before the count bound")

	require.NoError(t, blk.Verify(context.Background()))
	_, err = vm.ParseBlock(context.Background(), blk.Bytes())
	require.NoError(t, err, "what it built, it can parse")

	// The rest is still queued and goes out in the next block.
	require.NoError(t, blk.Accept(context.Background()))
	require.Len(t, vm.mempool, queued-len(blk.transactions))
	next := acceptQueued(t, vm)
	require.NotEmpty(t, next.transactions)
}

// H8: nothing bound a transaction or a block to the chain it was meant for. An
// address is the hash of a public key, so the same payer exists on every
// F-Chain; a transaction lifted from one authenticated verbatim on the others
// and burned a balance there for an operation nobody asked for. Blocks were
// worse: every chain whose genesis carried the same timestamp had the SAME
// genesis id, so one chain's block resolved its parent on all of them.
func TestH8_ASignatureAndABlockNameOneChain(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	other := ids.ID{'a', 'n', 'o', 't', 'h', 'e', 'r'}

	home := newTestVM(t, fundAll(k), committee, 1)
	away := newVMOnChain(t, other, fundAll(k), committee, 1)

	// Same genesis bytes, same timestamp, different chains: different ids.
	require.NotEqual(t, home.lastAccepted, away.lastAccepted,
		"two chains must not share a genesis block")

	// A transaction signed for home does not authenticate away.
	tx := registerTx(t, k, testScheme, digestOf("mine"), 1)
	require.NoError(t, tx.authenticate(home.chainID))
	require.ErrorIs(t, tx.authenticate(away.chainID), ErrBadSignature)
	_, err := away.SubmitTx(tx)
	require.ErrorIs(t, err, ErrBadSignature, "the replay is refused at admission")

	// Nor inside a block: a peer forcing it in gets a refusal, not an effect.
	forced := &Block{
		parentID: away.lastAccepted, height: 1, timestamp: away.clock.Time(),
		transactions: []*Transaction{tx}, vm: away,
	}
	forced.id = forced.computeID()
	require.ErrorIs(t, forced.Verify(context.Background()), ErrBadSignature)

	// And home's whole block does not land away: its parent is a genesis away
	// has never heard of.
	acceptOne(t, home, tx)
	parsed, err := away.ParseBlock(context.Background(), home.lastBlock.Bytes())
	require.NoError(t, err, "the bytes are well formed; it is the chain that differs")
	require.Error(t, parsed.Verify(context.Background()))
	require.Zero(t, away.height, "nothing from another chain moved this one")

	// The control: signed for away, it works away.
	native := k.signFor(t, other, registerTx(t, k, testScheme, digestOf("theirs"), 1))
	_, err = away.SubmitTx(native)
	require.NoError(t, err)
}

// newVMOnChain seats a chain with an explicitly named id. Only a test that is
// about more than one chain needs it; every other one uses testChainID, because
// production runs one chain with one id.
func newVMOnChain(t *testing.T, chain ids.ID, alloc map[string]uint64, committee []fhe.CommitteeMember, threshold int) *VM {
	t.Helper()
	logger := log.NewNoOpLogger()
	gb, err := json.Marshal(Genesis{
		Version: 1, Timestamp: testGenesisTime, Alloc: alloc,
		Committee: committee, Threshold: threshold, PublicKey: []byte("network-fhe-public-key"),
	})
	require.NoError(t, err)
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: chain, NetworkID: 96369, Log: logger},
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  gb,
	}))
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	return vm
}

// L3: what an UNAUTHENTICATED transaction can make this node do before its
// signature is checked. The answer must be bounded by its own declared size,
// and it is: bytes and count are bounded at the parse, the payload and scheme
// are bounded before either is decoded, and the one expensive decode — parsing
// a committee's ML-DSA-65 public keys — is bounded by MaxCommittee.
func TestL3_UnauthenticatedWorkIsBoundedBySize(t *testing.T) {
	k := newTestKey(t)

	// The costly branch: an epoch proposal makes SyntacticVerify parse a public
	// key per member, and that runs before authenticate. MaxCommittee bounds it.
	over, _ := newCommittee(t, MaxCommittee+1)
	huge := &Transaction{
		Type: TxAdvanceEpoch, Nonce: 1,
		Subject: committeeDigest(1, 2, []byte("pk"), over),
		Payload: mustJSON(t, AdvancePayload{Epoch: 1, Committee: over, Threshold: 2, PublicKey: []byte("pk")}),
	}
	require.ErrorIs(t, huge.SyntacticVerify(), ErrInvalidCommittee,
		"the committee is refused by COUNT, before any of its keys is parsed")

	// Every other byte channel is bounded before it is decoded at all.
	for name, tx := range map[string]*Transaction{
		"payload": {Type: TxRevokePermit, Nonce: 1, Payload: bytes.Repeat([]byte("A"), MaxPayload+1)},
		"scheme":  {Type: TxRevokePermit, Nonce: 1, Scheme: string(bytes.Repeat([]byte("A"), MaxScheme+1)), Payload: mustJSON(t, RevokePayload{})},
		"auth":    {Type: TxRevokePermit, Nonce: 1, Payload: mustJSON(t, RevokePayload{}), Auth: bytes.Repeat([]byte("A"), 9)},
		"sig":     {Type: TxRevokePermit, Nonce: 1, Payload: mustJSON(t, RevokePayload{}), Sig: bytes.Repeat([]byte("A"), 9)},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, tx.SyntacticVerify(), ErrInvalidPayload)
		})
	}

	// And the order holds where it matters: a transaction whose signature is
	// wrong is refused, so nothing beyond the bounded checks above is ever done
	// on an unauthenticated one.
	forged := registerTx(t, k, testScheme, digestOf("forged"), 1)
	forged.Sig[0] ^= 0xff
	require.ErrorIs(t, forged.authenticate(testChainID), ErrBadSignature)
}

// The receive path must decide exactly what the build path decides. A sibling
// VM's parser discarded the transaction set, so a signature check gated on the
// set being non-empty ran only on blocks that node had built itself: the same
// block was refused in memory and accepted off the wire. Here the same block is
// fed in BOTH ways and the two verdicts are required to agree — for a sound
// block and for each way one can be unsound.
func TestTheWireVerdictIsTheMemoryVerdict(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	bothWays := func(t *testing.T, blk *Block) (inMemory, offWire error) {
		t.Helper()
		inMemory = blk.Verify(context.Background())
		parsed, err := vm.ParseBlock(context.Background(), blk.Bytes())
		if err != nil {
			return inMemory, err
		}
		return inMemory, parsed.Verify(context.Background())
	}

	build := func(txs ...*Transaction) *Block {
		b := &Block{
			parentID: vm.lastAccepted, height: vm.height + 1,
			timestamp: vm.clock.Time(), transactions: txs, vm: vm,
		}
		b.id = b.computeID()
		return b
	}

	// Sound: both accept.
	sound := build(registerTx(t, k, testScheme, digestOf("sound"), 1))
	mem, wire := bothWays(t, sound)
	require.NoError(t, mem)
	require.NoError(t, wire)

	// Forged signature: both refuse, and for the same reason.
	forged := registerTx(t, k, testScheme, digestOf("forged"), 1)
	forged.Sig = append([]byte(nil), forged.Sig...)
	forged.Sig[0] ^= 0xff
	forged.id = ids.Empty
	mem, wire = bothWays(t, build(forged))
	require.ErrorIs(t, mem, ErrBadSignature)
	require.ErrorIs(t, wire, ErrBadSignature)

	// Unsigned: a transaction carrying no authorization at all must not become
	// authorized by travelling.
	unsigned := registerTx(t, k, testScheme, digestOf("unsigned"), 1)
	unsigned.Auth, unsigned.Sig, unsigned.id = nil, nil, ids.Empty
	mem, wire = bothWays(t, build(unsigned))
	require.ErrorIs(t, mem, ErrUnsignedTx)
	require.ErrorIs(t, wire, ErrUnsignedTx)

	// A nonce out of order: refused both ways.
	mem, wire = bothWays(t, build(registerTx(t, k, testScheme, digestOf("gap"), 9)))
	require.ErrorIs(t, mem, ErrBadNonce)
	require.ErrorIs(t, wire, ErrBadNonce)

	// And an empty block does not become non-empty by being parsed.
	mem, _ = bothWays(t, build())
	require.ErrorIs(t, mem, ErrInvalidBlock)
}

// A fixed-width field read past the end of its message copies NOTHING, leaving
// the destination zeroed — the shape that silently turned a short signature
// into a well-formed unverifiable envelope in a sibling package. Here it cannot
// pass: a zeroed field re-serializes to bytes that are not the bytes that
// arrived, and the canonical rule refuses the difference.
func TestATruncatedFixedFieldIsRefusedNotZeroFilled(t *testing.T) {
	sound := sampleTx().Bytes()
	n, err := zapLen(sound)
	require.NoError(t, err)

	// Shrink the leading message's declared size so Payer and Subject fall
	// outside it. zapLen still passes — it reads only the size — and zap.Parse
	// still passes, because the header is intact.
	for _, cut := range []int{txPayer + 4, txSubject + 4, txSubject + 20} {
		truncated := append([]byte(nil), sound...)
		size := zap.HeaderSize + cut
		require.Less(t, size, n, "the cut must actually fall inside the message")
		binary.LittleEndian.PutUint32(truncated[12:16], uint32(size))

		if _, err := zapLen(truncated); err != nil {
			t.Fatalf("cut %d: the length field is sound, zapLen must pass: %v", cut, err)
		}
		_, err := ParseTransaction(truncated)
		require.Errorf(t, err, "cut %d: a field read past the end must refuse, not zero-fill", cut)
	}

	// The control: uncut, it parses and its fixed fields survive intact.
	parsed, err := ParseTransaction(sound)
	require.NoError(t, err)
	require.Equal(t, sampleTx().Payer, parsed.Payer)
	require.Equal(t, sampleTx().Subject, parsed.Subject)
}
