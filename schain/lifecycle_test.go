// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// lifecycle_test.go — the VM's boundary with the chains manager: boot, the
// block codec, the surfaces the manager drives, and every refusal on the way in.
package schain

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/zapdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	vmcore "github.com/luxfi/vm"

	"github.com/luxfi/chains/schain/pinning"
	"github.com/luxfi/chains/schain/txs"
)

// TestFactoryBuildsADrivableVM proves the factory hands the chains manager a VM
// that boots and answers, rather than a value that merely satisfies the
// interface.
func TestFactoryBuildsADrivableVM(t *testing.T) {
	ctx := context.Background()
	raw, err := (&Factory{}).New(log.Root())
	require.NoError(t, err)
	cvm, ok := raw.(*ChainVM)
	require.True(t, ok)
	require.Equal(t, VMID, ids.ID{'s', 'c', 'h', 'a', 'i', 'n'})

	// Before boot it refuses to build: a VM with no state cannot propose.
	_, err = cvm.BuildBlock(ctx)
	require.ErrorIs(t, err, errVMNotInitialized)

	require.NoError(t, cvm.Initialize(ctx, initFor(memdb.New())))
	require.Same(t, cvm.inner, cvm.GetInnerVM())

	// Now it answers the surfaces the manager drives.
	version, err := cvm.Version(ctx)
	require.NoError(t, err)
	require.Equal(t, "schain/0.1.0", version)

	health, err := cvm.HealthCheck(ctx)
	require.NoError(t, err)
	require.True(t, health.Healthy, "an initialized VM is healthy")

	require.NoError(t, cvm.SetState(ctx, 1))
	require.NoError(t, cvm.Connected(ctx, ids.GenerateTestNodeID(), nil))
	require.NoError(t, cvm.Disconnected(ctx, ids.GenerateTestNodeID()))

	require.Zero(t, cvm.inner.GetBlockHeight(), "a fresh chain sits at genesis")
	seal(t, cvm, manifestTx("b", "o"))
	require.Equal(t, uint64(1), cvm.inner.GetBlockHeight())
	require.False(t, cvm.inner.GetLastBlockTime().IsZero())

	require.NoError(t, cvm.Shutdown(ctx))
	health, err = cvm.HealthCheck(ctx)
	require.NoError(t, err)
	require.True(t, health.Healthy, "health reports initialization, not liveness")
}

// TestHTTPSurfaceIsEmpty proves the VM publishes no HTTP surface: the S3 API is
// a later milestone, and an empty handler set must produce a working mux rather
// than a nil one the node would then dereference.
func TestHTTPSurfaceIsEmpty(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	mux, err := cvm.NewHTTPHandler(ctx)
	require.NoError(t, err)
	require.NotNil(t, mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestWaitForEventParksUntilCancelled proves the engine-notification contract:
// this VM triggers builds through SubmitTx, so WaitForEvent parks and returns
// the context's own error rather than inventing an event.
func TestWaitForEventParksUntilCancelled(t *testing.T) {
	cvm, _ := newTestVM(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := cvm.WaitForEvent(ctx)
		done <- err
	}()

	select {
	case <-done:
		t.Fatal("WaitForEvent returned before the context was cancelled")
	case <-time.After(20 * time.Millisecond):
	}

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

// TestShutdownReportsAStoreItCannotClose proves a failed close is reported
// rather than swallowed — a half-closed store that boots again is how two
// writers end up on one database.
func TestShutdownReportsAStoreItCannotClose(t *testing.T) {
	ctx := context.Background()
	cvm := newVMOn(t, memdb.New())
	require.NoError(t, cvm.Shutdown(ctx))
	require.Error(t, cvm.Shutdown(ctx), "closing an already-closed store must be reported")
}

// TestBootRefusesAStoreItCannotRead proves the VM does not start on state it
// could not load: an unreadable last-block pointer means the recovery anchor is
// unknown, and starting from an assumed genesis would rewrite history.
func TestBootRefusesAStoreItCannotRead(t *testing.T) {
	db := &blindDB{Database: memdb.New()}
	db.blind(func(key []byte) bool { return string(key) == "lastBlock" })

	cvm := NewChainVM(log.Root())
	err := cvm.Initialize(context.Background(), initFor(db))
	require.ErrorIs(t, err, errStoreDown)
}

// blindDB refuses reads of the keys the caller nominates.
type blindDB struct {
	database.Database
	mu     sync.Mutex
	refuse func(key []byte) bool
}

func (d *blindDB) blind(want func([]byte) bool) {
	d.mu.Lock()
	d.refuse = want
	d.mu.Unlock()
}

func (d *blindDB) failing(key []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.refuse != nil && d.refuse(key)
}

func (d *blindDB) Get(k []byte) ([]byte, error) {
	if d.failing(k) {
		return nil, errStoreDown
	}
	return d.Database.Get(k)
}

// TestUnreadableAllocatorStateRefusesTheAllocation proves the allocator fails
// closed on a store it cannot read: an unreadable cursor must not be treated as
// a cursor at zero, which would reissue ids the range has already handed out.
func TestUnreadableAllocatorStateRefusesTheAllocation(t *testing.T) {
	ctx := context.Background()
	db := &blindDB{Database: memdb.New()}
	cvm := newVMOn(t, db)

	vals := newTestValidators(t, 1)
	const rng, epoch = "unreadable", uint64(4)
	withFixedEpoch(t, cvm, vals, vals[0], epoch)

	fp := pinning.EpochFingerprint(epoch, membersOf(vals))
	tx := txs.NewAllocateTx(rng, 3).WithAuthorization(
		epoch, 1, fp, vals[0].nodeID, uint8(ids.NodeIDSchemeMLDSA65),
		vals[0].pub.Bytes(), signAllocateAs(t, vals[0], rng, 3, epoch, 1, fp),
	)
	db.blind(func([]byte) bool { return true })
	blk := carry(t, cvm, tx.Bytes())
	require.NoError(t, blk.Verify(ctx), "an unreadable cursor is a soft failure, not a gate violation")
	db.blind(nil)

	after, err := cvm.inner.state.GetAlloc(rng)
	require.NoError(t, err)
	require.Zero(t, after.Next, "nothing may be allocated off a cursor nobody could read")
}

// TestAllocateRefusesASetWithNoEligibleOwner proves ownership fails closed twice
// over: an empty member set, and a set whose members all carry zero stake and so
// can own nothing. Defaulting to "the proposer owns it" is the one answer that
// would break the single-writer property.
func TestAllocateRefusesASetWithNoEligibleOwner(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)
	vals := newTestValidators(t, 3)

	// Present but weightless: pinning.Owner reports no owner.
	weightless := make([]pinning.Member, len(vals))
	for i, v := range vals {
		weightless[i] = pinning.Member{NodeID: v.nodeID, Weight: 0}
	}
	cvm.SetBlockContextBuilder(func(context.Context, uint64) (BlockContext, error) {
		return BlockContext{Members: weightless, Proposer: vals[0].nodeID, Epoch: 1,
			IdentityChainID: testIdentityChainID}, nil
	})

	blk := carry(t, cvm, txs.NewAllocateTx("nobody-owns-this", 1).Bytes())
	require.ErrorIs(t, blk.Verify(ctx), errNoValidatorSet)
}

// TestBuildRefusesWithoutATipToExtend proves block assembly fails closed when
// the preferred tip is not a block this node holds.
func TestBuildRefusesWithoutATipToExtend(t *testing.T) {
	cvm, _ := newTestVM(t)
	require.NoError(t, cvm.SubmitTx(manifestTx("b", "o")))

	cvm.lock.Lock()
	cvm.preferredID = ids.GenerateTestID()
	cvm.lock.Unlock()

	_, err := cvm.BuildBlock(context.Background())
	require.ErrorContains(t, err, "preferred block not found")
}

// TestBuildReportsAContextItCannotResolve proves the consensus inputs are a
// hard prerequisite: if the validator set for this height cannot be resolved,
// the block is not built rather than built against an empty set that would fail
// every allocate closed anyway.
func TestBuildReportsAContextItCannotResolve(t *testing.T) {
	cvm, _ := newTestVM(t)
	boom := errors.New("no validator set at this height")
	cvm.SetBlockContextBuilder(func(context.Context, uint64) (BlockContext, error) {
		return BlockContext{}, boom
	})

	require.NoError(t, cvm.SubmitTx(manifestTx("b", "o")))
	_, err := cvm.BuildBlock(context.Background())
	require.ErrorIs(t, err, boom)

	// And a block arriving from a peer cannot be parsed into an unresolvable
	// context either.
	blk := &Block{vm: cvm, parentID: genesisBlockID, height: 1,
		timestamp: time.Now(), txs: [][]byte{manifestTx("b", "o")}}
	_, err = cvm.ParseBlock(context.Background(), blk.Bytes())
	require.ErrorIs(t, err, boom)
}

// TestBuildClampsItsClockToTheTip proves the proposer never stamps a block
// before its parent, so a node whose clock has slipped still produces a block it
// can itself verify.
func TestBuildClampsItsClockToTheTip(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	cvm.inner.clock.Set(time.Now().Add(time.Hour))
	first := seal(t, cvm, manifestTx("b", "first"))

	cvm.inner.clock.Set(time.Now()) // an hour behind the tip
	require.NoError(t, cvm.SubmitTx(manifestTx("b", "second")))
	blk, err := cvm.BuildBlock(ctx)
	require.NoError(t, err)
	require.False(t, blk.Timestamp().Before(first.timestamp),
		"a proposer must not stamp before its parent")
	require.NoError(t, blk.Verify(ctx), "the clamped block must verify on this very node")
	require.NoError(t, blk.Accept(ctx))
}

// TestSignerRefusesWhatItCannotRead proves the proposer's signing pass reports
// bytes it cannot parse rather than passing them through to the block.
func TestSignerRefusesWhatItCannotRead(t *testing.T) {
	cvm, _ := newTestVM(t)
	vals := newTestValidators(t, 1)
	withFixedEpoch(t, cvm, vals, vals[0], 1)

	cvm.lock.Lock()
	cvm.pendingTxs = [][]byte{[]byte("not a transaction")}
	cvm.lock.Unlock()

	_, err := cvm.BuildBlock(context.Background())
	require.ErrorIs(t, err, txs.ErrInvalidTxType)

	cvm.lock.RLock()
	defer cvm.lock.RUnlock()
	require.Empty(t, cvm.pendingTxs, "a failed build must not leave the offending bytes queued")
}

// TestParseBlockIsTheSameBlock proves a block that travels the wire is the block
// that was built: same id, same contents, and the index hands back the instance
// it already holds rather than a second copy of it.
func TestParseBlockIsTheSameBlock(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	require.NoError(t, cvm.SubmitTx(manifestTx("b", "relayed")))
	built, err := cvm.BuildBlock(ctx)
	require.NoError(t, err)

	same, err := cvm.ParseBlock(ctx, built.(*Block).Bytes())
	require.NoError(t, err)
	require.Same(t, built, same, "a block already held is returned, not re-parsed into a twin")

	// A peer that has never seen it parses an equal block.
	peer, _ := newTestVM(t)
	relayed, err := peer.ParseBlock(ctx, built.(*Block).Bytes())
	require.NoError(t, err)
	require.Equal(t, built.ID(), relayed.ID())
	require.Equal(t, built.Height(), relayed.Height())
	require.Equal(t, built.Parent(), relayed.Parent())
	require.Equal(t, built.(*Block).timestamp.UnixNano(), relayed.(*Block).timestamp.UnixNano())
	require.Equal(t, built.(*Block).stateRoot, relayed.(*Block).stateRoot)
	require.NoError(t, relayed.Verify(ctx))
	require.NoError(t, relayed.Accept(ctx))

	_, found, err := peer.inner.GetManifest("b", "relayed")
	require.NoError(t, err)
	require.True(t, found, "a relayed block applies exactly as the built one")
}

// TestParseBlockRefusesMalformedBytes proves every decode failure is a refusal
// rather than a panic or a partially-built block: a short header, a transaction
// length running past the buffer, a truncated transaction, and trailing bytes.
func TestParseBlockRefusesMalformedBytes(t *testing.T) {
	cvm, _ := newTestVM(t)
	blk := &Block{vm: cvm, parentID: genesisBlockID, height: 1, timestamp: time.Now(),
		txs: [][]byte{manifestTx("b", "o")}}
	data := blk.Bytes()

	for _, cut := range []int{0, 1, 8, 8 + 8 + 32, len(data) - 4, len(data) - 1} {
		_, err := parseBlock(cvm, data[:cut])
		require.ErrorIsf(t, err, errInvalidBlock, "truncation to %d bytes must be refused", cut)
	}

	// Trailing bytes past the last declared transaction.
	_, err := parseBlock(cvm, append(append([]byte(nil), data...), 0xff))
	require.ErrorIs(t, err, errInvalidBlock)

	// A transaction count promising more than the buffer holds.
	overrun := append([]byte(nil), data...)
	binary.BigEndian.PutUint32(overrun[8+8+32+32:], 99)
	_, err = parseBlock(cvm, overrun)
	require.ErrorIs(t, err, errInvalidBlock)

	// A transaction length running past the buffer.
	long := append([]byte(nil), data...)
	binary.BigEndian.PutUint32(long[8+8+32+32+4:], 1<<20)
	_, err = parseBlock(cvm, long)
	require.ErrorIs(t, err, errInvalidBlock)
}

// TestLoggingChainDrivesEveryPath runs a full chain with a REAL logger
// installed, so the logging branches every operation carries are executed rather
// than skipped as they are under the no-op logger the other tests use.
func TestLoggingChainDrivesEveryPath(t *testing.T) {
	ctx := context.Background()
	db, err := zapdb.New(t.TempDir(), nil, "schain-logging", metric.NewRegistry())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	init := initFor(db)
	init.Runtime.Log = log.Root()
	cvm := NewChainVM(log.Root())
	require.NoError(t, cvm.Initialize(ctx, init))

	vals := newTestValidators(t, 1)
	withFixedEpoch(t, cvm, vals, vals[0], 3)

	// A block carrying a good allocate, a good manifest and a doomed transaction.
	require.NoError(t, cvm.SubmitTx(txs.NewAllocateTx("logged", 2).Bytes()))
	require.NoError(t, cvm.SubmitTx(manifestTx("b", "logged")))
	cvm.lock.Lock()
	cvm.pendingTxs = append(cvm.pendingTxs, txs.NewPutManifestTx("b", "bad", nil, 0, "").Bytes())
	cvm.lock.Unlock()

	blk, err := cvm.BuildBlock(ctx)
	require.NoError(t, err)
	require.Len(t, blk.(*Block).txs, 2, "the invalid manifest is left out")
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))

	alloc, err := cvm.inner.state.GetAlloc("logged")
	require.NoError(t, err)
	require.Equal(t, uint64(2), alloc.Next)
	require.NoError(t, cvm.Shutdown(ctx))
}

// TestVerifyRefusesAfterShutdown proves the VM stops applying once stopped: a
// block arriving during shutdown must not be half-applied to a store that is
// closing underneath it.
func TestVerifyRefusesAfterShutdown(t *testing.T) {
	ctx := context.Background()
	cvm := newVMOn(t, memdb.New())

	blk := carry(t, cvm, manifestTx("b", "late"))
	cvm.inner.lock.Lock()
	cvm.inner.shutdown = true
	cvm.inner.lock.Unlock()

	require.ErrorIs(t, blk.Verify(ctx), errShutdown)
	require.ErrorIs(t, blk.Accept(ctx), errShutdown)
}

// TestCommitOnAVMWithNoStoreIsANoOp proves the commit path tolerates a VM that
// was never given a database — it reports success with nothing to write rather
// than dereferencing a nil store.
func TestCommitOnAVMWithNoStoreIsANoOp(t *testing.T) {
	require.NoError(t, (&VM{}).commit())

	// And an initialized VM with nothing staged commits an empty batch cleanly.
	cvm := newVMOn(t, memdb.New())
	require.NoError(t, cvm.inner.commit())
	require.NoError(t, cvm.inner.commit())
}

// TestStateRootFailureRefusesTheBlock proves a block whose state root cannot be
// computed is refused rather than accepted with an empty root — a root nobody
// could compute is a root no validator can check.
func TestStateRootFailureRefusesTheBlock(t *testing.T) {
	ctx := context.Background()
	db := &blindIterDB{Database: memdb.New()}
	cvm := newVMOn(t, db)

	blk := carry(t, cvm, manifestTx("b", "unrootable"))
	db.setBlind(true)
	require.ErrorIs(t, blk.Verify(ctx), errStoreDown)
	db.setBlind(false)

	_, found, err := cvm.inner.GetManifest("b", "unrootable")
	require.NoError(t, err)
	require.False(t, found, "a block whose root could not be computed must apply nothing")
}

// blindIterDB hands out iterators that report an error instead of data, the way
// a store fails the full-keyspace scan the state root walks.
type blindIterDB struct {
	database.Database
	mu    sync.Mutex
	blind bool
}

func (d *blindIterDB) setBlind(v bool) {
	d.mu.Lock()
	d.blind = v
	d.mu.Unlock()
}

func (d *blindIterDB) blinded() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.blind
}

func (d *blindIterDB) NewIteratorWithStartAndPrefix(start, prefix []byte) database.Iterator {
	if d.blinded() {
		return &brokenIterator{}
	}
	return d.Database.NewIteratorWithStartAndPrefix(start, prefix)
}

type brokenIterator struct{ database.Iterator }

func (*brokenIterator) Next() bool    { return false }
func (*brokenIterator) Error() error  { return errStoreDown }
func (*brokenIterator) Key() []byte   { return nil }
func (*brokenIterator) Value() []byte { return nil }
func (*brokenIterator) Release()      {}

// TestEngineNotificationNeverBlocks proves the mempool door does not stall on a
// consumer that has stopped reading: the signal is a cue to build, so a full
// channel means the engine already knows, and dropping the extra is correct
// where blocking would wedge every submitter behind it.
func TestEngineNotificationNeverBlocks(t *testing.T) {
	cvm, toEngine := newTestVM(t)
	for i := 0; i < cap(toEngine)*2; i++ {
		require.NoError(t, cvm.SubmitTx(manifestTx("b", string(rune('a'+i)))))
	}
	require.Len(t, toEngine, cap(toEngine))

	cvm.lock.RLock()
	defer cvm.lock.RUnlock()
	require.Len(t, cvm.pendingTxs, cap(toEngine)*2, "every submission is queued, signalled or not")
}

// TestBuildRefusesAfterShutdown proves a stopped VM produces no blocks, whatever
// is queued.
func TestBuildRefusesAfterShutdown(t *testing.T) {
	cvm := newVMOn(t, memdb.New())
	require.NoError(t, cvm.SubmitTx(manifestTx("b", "late")))

	cvm.inner.lock.Lock()
	cvm.inner.shutdown = true
	cvm.inner.lock.Unlock()

	_, err := cvm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errShutdown)
}

// TestCommitRefusesAClosedStore proves the commit reports a store it can no
// longer write to, rather than returning success with nothing written.
func TestCommitRefusesAClosedStore(t *testing.T) {
	cvm := newVMOn(t, memdb.New())
	require.NoError(t, cvm.Shutdown(context.Background()))
	require.Error(t, cvm.inner.commit(), "committing to a closed store must be reported")
}

// TestBuildReportsASignerThatCannotSign proves an allocate this node owns but
// cannot authorize stops the build rather than travelling unsigned — an unsigned
// allocate would fail closed at every verifier anyway, so building the block
// would only waste a round.
func TestBuildReportsASignerThatCannotSign(t *testing.T) {
	cvm, _ := newTestVM(t)
	vals := newTestValidators(t, 1)
	withFixedEpoch(t, cvm, vals, vals[0], 1)

	boom := errors.New("staking key is unavailable")
	cvm.lock.Lock()
	cvm.allocateSigner.sign = func(msg, ctx []byte) ([]byte, error) { return nil, boom }
	cvm.lock.Unlock()

	require.NoError(t, cvm.SubmitTx(txs.NewAllocateTx("unsignable", 1).Bytes()))
	_, err := cvm.BuildBlock(context.Background())
	require.ErrorIs(t, err, boom)
}

// TestVerifyRefusesAKeyItCannotParse proves the signature check refuses an
// unparseable public key rather than treating it as a key whose signature simply
// does not verify. The key is reached only by claiming the NodeID it derives to,
// which is exactly what a forger with arbitrary bytes would do.
func TestVerifyRefusesAKeyItCannotParse(t *testing.T) {
	garbage := []byte("this is not an ML-DSA public key")
	for _, scheme := range []ids.NodeIDScheme{ids.NodeIDSchemeMLDSA65, ids.NodeIDSchemeMLDSA87} {
		claimed, _, err := scheme.DeriveMLDSA(testIdentityChainID, garbage)
		require.NoError(t, err)

		tx := txs.NewAllocateTx("r", 1).WithAuthorization(
			1, 1, ids.Empty, claimed, uint8(scheme), garbage, []byte("signature"),
		)
		require.ErrorIsf(t, verifyAllocateSig(tx, testIdentityChainID), errBadAllocateSig,
			"scheme %d must refuse a key it cannot parse", scheme)
	}
}

// TestInnerVMBootsWithoutARuntime proves the storage VM supplies its own logger
// when the manager hands it no consensus runtime, rather than dereferencing one.
func TestInnerVMBootsWithoutARuntime(t *testing.T) {
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{DB: memdb.New()}))
	health, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	require.True(t, health.Healthy)
	require.NoError(t, vm.Shutdown(context.Background()))
}
