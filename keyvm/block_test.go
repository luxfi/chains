// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
)

// blockAt builds a block by hand, the way a hostile proposer would: any parent,
// any height, any timestamp. It bypasses BuildBlock deliberately — BuildBlock is
// honest, and what Verify has to survive is a proposer that is not.
func blockAt(vm *VM, parent ids.ID, height uint64, ts time.Time, txs ...*Transaction) *Block {
	b := &Block{parentID: parent, height: height, timestamp: ts, transactions: txs, vm: vm}
	b.id = b.computeID()
	return b
}

// expiringKey registers a key whose policy authorizes `guest` only until
// expiry, and returns an Authorize transaction from guest that a chain running
// at or after expiry must refuse.
func expiringKey(t *testing.T, vm *VM, owner, guest testKey, name string, expiry int64, nonce uint64) *Transaction {
	t.Helper()
	reg := &Transaction{
		Type: TxRegisterKey, Algorithm: "ml-dsa-65", Payer: owner.addr,
		KeyID: deriveKeyID(name), GasLimit: 300_000, Nonce: 1,
		Payload: mustJSON(t, RegisterKeyPayload{
			Name: name, PublicKey: []byte("PUB"), Threshold: 2, TotalShares: 3,
			Commitments: [][]byte{{1}},
			Policy:      AuthPolicy{Authorized: []fee_Account{guest.addr}, ExpiresAt: expiry},
		}),
	}
	owner.sign(t, reg)
	acceptOne(t, vm, reg)

	invoke := &Transaction{
		Type: TxAuthorize, Algorithm: "ml-dsa-65", Payer: guest.addr,
		KeyID: deriveKeyID(name), GasLimit: 300_000, Nonce: nonce,
		Payload: mustJSON(t, AuthorizePayload{Ceremony: CeremonySign, Message: []byte("m")}),
	}
	guest.sign(t, invoke)
	return invoke
}

// TestVerifyRefusesRewoundTimestampRevivingExpiredPermit is the regression test
// for an unbounded block timestamp. Block time is the clock every authorization
// decision is made against, so a proposer that may stamp any time it likes may
// stamp one BEFORE a policy's ExpiresAt and get a permit the chain has already
// retired honoured again. The guard is monotonicity against the parent: the only
// times a block may carry are ones at which the permit was genuinely still live.
func TestVerifyRefusesRewoundTimestampRevivingExpiredPermit(t *testing.T) {
	owner, guest := newTestKey(t), newTestKey(t)
	vm := newTestVM(t, map[string]uint64{
		owner.hexAddr(): 1_000_000_000, guest.hexAddr(): 1_000_000_000,
	})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	expiry := genesisTime.Add(time.Hour)
	invoke := expiringKey(t, vm, owner, guest, "expiring", expiry.Unix(), 1)

	// Move the chain past the expiry with an unrelated block, so the parent's
	// timestamp is itself past it.
	vm.clock.Set(expiry.Add(time.Minute))
	filler := registerTx(t, owner, "filler", 300_000, 2)
	acceptOne(t, vm, filler)

	// The permit is now dead: at the honest tip time, the guest is refused.
	live := blockAt(vm, vm.lastAccepted, vm.height+1, vm.clock.Time(), invoke)
	require.ErrorIs(t, live.Verify(context.Background()), ErrUnauthorized,
		"an expired permit must authorize nobody")

	// A proposer rewinds the block clock to before the expiry. This is the
	// attack: the SAME transaction, revived by a timestamp of the proposer's
	// choosing. Verify must refuse the block on its position, before it ever
	// judges the transaction's authorization.
	rewound := blockAt(vm, vm.lastAccepted, vm.height+1, expiry.Add(-time.Minute), invoke)
	require.ErrorIs(t, rewound.Verify(context.Background()), ErrTimeRewound)

	// And the permit stayed dead: no ceremony was recorded.
	require.Empty(t, vm.ceremonies, "a refused block must record nothing")
}

// TestVerifyRefusesFutureTimestamp is the other half of the same guard: a
// proposer that could stamp a block arbitrarily far ahead could retire a live
// permit early.
func TestVerifyRefusesFutureTimestamp(t *testing.T) {
	owner, guest := newTestKey(t), newTestKey(t)
	vm := newTestVM(t, map[string]uint64{
		owner.hexAddr(): 1_000_000_000, guest.hexAddr(): 1_000_000_000,
	})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	expiry := genesisTime.Add(time.Hour)
	invoke := expiringKey(t, vm, owner, guest, "future", expiry.Unix(), 1)

	// Inside the skew allowance the block is judged on its merits and the live
	// permit is honoured.
	ok := blockAt(vm, vm.lastAccepted, vm.height+1, vm.clock.Time().Add(maxFutureSkew), invoke)
	require.NoError(t, ok.Verify(context.Background()))

	// Past it — here, past the permit's expiry — the block is refused on
	// position, so the permit cannot be retired ahead of time.
	ahead := blockAt(vm, vm.lastAccepted, vm.height+1, expiry.Add(time.Minute), invoke)
	require.ErrorIs(t, ahead.Verify(context.Background()), ErrTimeAhead)
}

// TestVerifyRefusesDetachedBlock proves a block must name a parent the chain
// holds, at exactly one height above it. Height 0 used to skip the parent check
// outright, so a block claiming it was verifiable with any parent at all and,
// once accepted, rewound the chain's height.
func TestVerifyRefusesDetachedBlock(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	tx := registerTx(t, k, "detached", 200_000, 1)
	now := vm.clock.Time()

	unknownParent := blockAt(vm, ids.GenerateTestID(), 1, now, tx)
	require.ErrorIs(t, unknownParent.Verify(context.Background()), database.ErrNotFound)

	// Claiming height 0 no longer buys an exemption from the parent check.
	atZero := blockAt(vm, ids.GenerateTestID(), 0, now, tx)
	require.Error(t, atZero.Verify(context.Background()))

	// A real parent, but the wrong height above it.
	skipped := blockAt(vm, vm.lastAccepted, 7, now, tx)
	require.ErrorIs(t, skipped.Verify(context.Background()), ErrBadHeight)

	// Height 0 against the real genesis parent is still wrong: parent+1 or nothing.
	sameHeight := blockAt(vm, vm.lastAccepted, 0, now, tx)
	require.ErrorIs(t, sameHeight.Verify(context.Background()), ErrBadHeight)

	// The honest position verifies, which is what makes the three refusals above
	// about position and not about the transaction.
	require.NoError(t, blockAt(vm, vm.lastAccepted, 1, now, tx).Verify(context.Background()))
}

// TestVerifyRefusesCumulativeOverspend proves a payer's fees are summed ACROSS
// the transactions of one block. Two transactions each individually affordable,
// together not, must fail the block — otherwise a payer spends a balance it
// does not have.
func TestVerifyRefusesCumulativeOverspend(t *testing.T) {
	k := newTestKey(t)
	one, err := FeeFor(registerTx(t, k, "a", 300_000, 1))
	require.NoError(t, err)

	// Fund for one operation and a sliver — enough for either transaction alone.
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): one + 1})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	first := registerTx(t, k, "a", 300_000, 1)
	second := registerTx(t, k, "b", 300_000, 2)

	require.NoError(t, blockAt(vm, vm.lastAccepted, 1, vm.clock.Time(), first).
		Verify(context.Background()), "either transaction alone is affordable")

	both := blockAt(vm, vm.lastAccepted, 1, vm.clock.Time(), first, second)
	require.ErrorIs(t, both.Verify(context.Background()), fee.ErrInsufficientFunds)
}

// TestAcceptIsAtomic proves a block that fails partway applies NOTHING: no fee
// burned, no record written, no cache advanced, and the chain tip unmoved. The
// second transaction here is authorized at Verify time but unauthorized by the
// time it applies, because the first revoked the key underneath it.
func TestAcceptIsAtomic(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	acceptOne(t, vm, registerTx(t, k, "victim", 300_000, 1))
	keyID := deriveKeyID("victim")

	revoke := &Transaction{
		Type: TxRevokeKey, Payer: k.addr, KeyID: keyID, GasLimit: 300_000, Nonce: 2,
		Payload: mustJSON(t, RevokePayload{Reason: "rotation"}),
	}
	k.sign(t, revoke)
	after := &Transaction{
		Type: TxAuthorize, Algorithm: "ml-dsa-65", Payer: k.addr, KeyID: keyID,
		GasLimit: 300_000, Nonce: 3,
		Payload: mustJSON(t, AuthorizePayload{Ceremony: CeremonySign, Message: []byte("m")}),
	}
	k.sign(t, after)

	balBefore, err := vm.Balance(k.addr)
	require.NoError(t, err)
	burnedBefore, err := vm.Burned()
	require.NoError(t, err)
	tipBefore := vm.lastAccepted
	nonceBefore := vm.nonceOf(k.addr)

	blk := blockAt(vm, vm.lastAccepted, vm.height+1, vm.clock.Time(), revoke, after)
	require.ErrorIs(t, blk.Accept(context.Background()), ErrKeyRevoked)

	balAfter, err := vm.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, balBefore, balAfter, "a failed block must burn nothing, not even the first fee")
	burnedAfter, err := vm.Burned()
	require.NoError(t, err)
	require.Equal(t, burnedBefore, burnedAfter)
	require.Equal(t, tipBefore, vm.lastAccepted, "a failed block must not move the tip")

	// The revocation itself is rolled back, in the cache as well as the store.
	rec, ok := vm.KeyByName("victim")
	require.True(t, ok)
	require.Equal(t, StatusActive, rec.Status, "the aborted revoke must not survive in the cache")
	require.Equal(t, nonceBefore, vm.nonceOf(k.addr), "no nonce may be consumed by a failed block")
}

// failingDB refuses writes the caller nominates, so a store failure can be
// aimed at one key rather than at everything.
type failingDB struct {
	database.Database
	mu     sync.Mutex
	refuse func(key []byte) bool
}

// breakWrites refuses every write from now on.
func (d *failingDB) breakWrites() { d.refuseKeys(func([]byte) bool { return true }) }

// refuseKeys refuses the writes for which want reports true.
func (d *failingDB) refuseKeys(want func([]byte) bool) {
	d.mu.Lock()
	d.refuse = want
	d.mu.Unlock()
}

func (d *failingDB) heal() { d.refuseKeys(nil) }

func (d *failingDB) failing(key []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.refuse != nil && d.refuse(key)
}

var errStoreDown = errors.New("store is down")

func (d *failingDB) Put(k, v []byte) error {
	if d.failing(k) {
		return errStoreDown
	}
	return d.Database.Put(k, v)
}

func (d *failingDB) NewBatch() database.Batch {
	return &failingBatch{Batch: d.Database.NewBatch(), db: d}
}

type failingBatch struct {
	database.Batch
	db *failingDB
}

func (b *failingBatch) Write() error {
	if b.db.failing(nil) {
		return errStoreDown
	}
	return b.Batch.Write()
}

// TestFailedCommitDoesNotAdvanceTheChain proves in-memory state follows the
// commit rather than leading it. If the tip, height and caches advanced before
// the write landed, a store that refused the write would leave the VM serving a
// tip whose contents do not exist.
func TestFailedCommitDoesNotAdvanceTheChain(t *testing.T) {
	k := newTestKey(t)
	db := &failingDB{Database: memdb.New()}
	vm := newTestVMOn(t, db, map[string]uint64{k.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	_, err := vm.SubmitTx(registerTx(t, k, "durable", 300_000, 1))
	require.NoError(t, err)
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.NoError(t, blk.Verify(context.Background()))

	tipBefore, heightBefore := vm.lastAccepted, vm.height
	db.breakWrites()
	require.ErrorIs(t, blk.Accept(context.Background()), errStoreDown)

	require.Equal(t, tipBefore, vm.lastAccepted, "an uncommitted block must not become the tip")
	require.Equal(t, heightBefore, vm.height)
	_, ok := vm.KeyByName("durable")
	require.False(t, ok, "an uncommitted block's effects must not survive in the cache")
	require.Equal(t, uint8(0), blk.(*Block).Status(), "an uncommitted block is not accepted")
}

// TestRejectReturnsWorkAndReleasesTheBlock proves a rejected block gives its
// transactions back to the mempool (they were never applied, so they are still
// valid) and stops being retained.
func TestRejectReturnsWorkAndReleasesTheBlock(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	tx := registerTx(t, k, "requeued", 300_000, 1)
	_, err := vm.SubmitTx(tx)
	require.NoError(t, err)
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.Empty(t, vm.mempool, "BuildBlock drains what it took")

	require.NoError(t, blk.Reject(context.Background()))
	require.Len(t, vm.mempool, 1, "a rejected block returns its work")

	vm.stateLock.RLock()
	_, held := vm.pendingBlocks[blk.ID()]
	vm.stateLock.RUnlock()
	require.False(t, held, "a rejected block must not be retained")

	// And the returned transaction still builds and accepts.
	next, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.NoError(t, next.Verify(context.Background()))
	require.NoError(t, next.Accept(context.Background()))
	_, ok := vm.KeyByName("requeued")
	require.True(t, ok)
}

// TestAcceptReleasesAbandonedBlocks proves the processing-block index is bounded.
// The engine issues a block per build and is under no obligation to accept or
// reject every one of them; a block only ever released on those two paths grows
// without limit. Nothing at or below the accepted height can still be accepted,
// so releasing those loses nothing reachable.
func TestAcceptReleasesAbandonedBlocks(t *testing.T) {
	payers := []testKey{newTestKey(t), newTestKey(t), newTestKey(t), newTestKey(t)}
	alloc := map[string]uint64{}
	for _, p := range payers {
		alloc[p.hexAddr()] = 10_000_000_000
	}
	vm := newTestVM(t, alloc)
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	// Three competing blocks at height 1, each built and then simply abandoned —
	// neither accepted nor rejected, which is what the engine does to the losers
	// of a poll.
	var abandoned []ids.ID
	for i := 0; i < 3; i++ {
		_, err := vm.SubmitTx(registerTx(t, payers[i], "orphan", 300_000, 1))
		require.NoError(t, err)
		blk, err := vm.BuildBlock(ctx)
		require.NoError(t, err)
		abandoned = append(abandoned, blk.ID())
	}
	vm.stateLock.RLock()
	require.Len(t, vm.pendingBlocks, 3)
	vm.stateLock.RUnlock()

	// A fourth block wins height 1.
	_, err := vm.SubmitTx(registerTx(t, payers[3], "winner", 300_000, 1))
	require.NoError(t, err)
	winner, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, winner.Verify(ctx))
	require.NoError(t, winner.Accept(ctx))

	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	require.Empty(t, vm.pendingBlocks,
		"blocks abandoned at or below the accepted height must be released")
	for _, id := range abandoned {
		require.NotContains(t, vm.pendingBlocks, id)
	}
}

// TestHeightIndexNamesOnlyAcceptedBlocks proves the height index is written in
// the block's own commit: a built-but-unaccepted block is not in it, an accepted
// one is, and an absent height reports not-found rather than a zero id.
func TestHeightIndexNamesOnlyAcceptedBlocks(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 10_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	_, err := vm.SubmitTx(registerTx(t, k, "indexed", 300_000, 1))
	require.NoError(t, err)
	blk, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, blk.Verify(ctx))

	_, err = vm.GetBlockIDAtHeight(ctx, 1)
	require.ErrorIs(t, err, database.ErrNotFound, "a verified-but-unaccepted block is not indexed")

	require.NoError(t, blk.Accept(ctx))
	got, err := vm.GetBlockIDAtHeight(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, blk.ID(), got)

	_, err = vm.GetBlockIDAtHeight(ctx, 99)
	require.ErrorIs(t, err, database.ErrNotFound)
}

// TestBlockIndexIsOneLock is the race regression. The processing-block map used
// to be written under shutdownLock by BuildBlock and read under stateLock by the
// cache reload an aborted Accept performs — two mutexes over one map, which the
// Go runtime answers with a fatal throw, not an error. Run under -race this
// fails on the old code and passes on the new.
func TestBlockIndexIsOneLock(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	// Sign up front: ML-DSA is slow enough that signing inside the loops would
	// keep the two goroutines from ever overlapping on the map.
	const rounds = 500
	good := registerTx(t, k, "racer", 300_000, 1)
	bad := registerTx(t, k, "racer", 300_000, 999) // wrong nonce: Accept always aborts
	tip, height := vm.lastAccepted, vm.height

	var wg sync.WaitGroup
	wg.Add(3)

	// Builder: writes the map.
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			vm.mempoolLock.Lock()
			vm.mempool = append(vm.mempool, good)
			vm.mempoolLock.Unlock()
			_, _ = vm.BuildBlock(ctx)
		}
	}()
	// An aborting Accept reloads the caches, which reads the map.
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			_ = blockAt(vm, tip, height+1, vm.clock.Time(), bad).Accept(ctx)
		}
	}()
	// Reader: the engine asking for blocks.
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			_, _ = vm.GetBlock(ctx, tip)
			_, _ = vm.LastAccepted(ctx)
		}
	}()
	wg.Wait()
}
