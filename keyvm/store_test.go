// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
)

// blindDB refuses reads of the keys the caller nominates. The chain's writes are
// buffered in the version layer, so the way a live store fails a block is by
// failing to answer a READ — a balance it cannot look up, a record it cannot
// iterate.
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

func (d *blindDB) Has(k []byte) (bool, error) {
	if d.failing(k) {
		return false, errStoreDown
	}
	return d.Database.Has(k)
}

// balanceKeyOf is the ledger's key for an account — the one read that decides
// whether a payer can pay.
func balanceKeyOf(a fee_Account) []byte {
	return append([]byte("fee/bal/"), a[:]...)
}

// TestUnreadableBalanceRefusesTheBlock proves affordability failing CLOSED. If
// the store cannot answer what a payer holds, the block is refused at Verify and
// again at Accept — it is never treated as though the payer could pay.
func TestUnreadableBalanceRefusesTheBlock(t *testing.T) {
	k := newTestKey(t)
	db := &blindDB{Database: memdb.New()}
	vm := newTestVMOn(t, db, map[string]uint64{k.hexAddr(): 10_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	tx := registerTx(t, k, "unreadable", 300_000, 1)
	blk := blockAt(vm, vm.lastAccepted, 1, vm.clock.Time(), tx)

	want := balanceKeyOf(k.addr)
	db.blind(func(key []byte) bool { return bytes.Equal(key, want) })

	require.ErrorIs(t, blk.Verify(context.Background()), errStoreDown)
	require.ErrorIs(t, blk.Accept(context.Background()), errStoreDown)
	require.ErrorIs(t, func() error { _, err := vm.SubmitTx(tx); return err }(), errStoreDown)

	db.blind(nil)
	_, present := vm.KeyByName("unreadable")
	require.False(t, present, "nothing may be applied on a balance nobody could read")
	burned, err := vm.Burned()
	require.NoError(t, err)
	require.Zero(t, burned)

	// With the store answering again, the same block is fine — the refusals
	// above were about the unreadable balance, not about the block.
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))
}

// TestBalanceAndBurnedSurfaceStoreErrors proves the public balance queries
// report a store failure rather than answering zero. A balance that reads as
// zero when the store is unreachable is worse than an error: it looks like a
// funded account was drained.
func TestBalanceAndBurnedSurfaceStoreErrors(t *testing.T) {
	k := newTestKey(t)
	db := &blindDB{Database: memdb.New()}
	vm := newTestVMOn(t, db, map[string]uint64{k.hexAddr(): 4_242})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	db.blind(func([]byte) bool { return true })
	_, err := vm.Balance(k.addr)
	require.ErrorIs(t, err, errStoreDown)
	_, err = vm.Burned()
	require.ErrorIs(t, err, errStoreDown)

	h, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	require.Equal(t, "0", h.Details["burnedNLUX"], "health degrades to zero rather than failing")

	db.blind(nil)
	bal, err := vm.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, uint64(4_242), bal)
}

// TestWriteRacingShutdownFailsClosed proves a block landing on a closed store
// applies nothing. Shutdown closes the version layer, so every read and write a
// block would perform fails from that point; the block must abort rather than
// half-apply.
func TestWriteRacingShutdownFailsClosed(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 10_000_000_000})

	blk := blockAt(vm, vm.lastAccepted, 1, vm.clock.Time(),
		registerTx(t, k, "racing", 300_000, 1))

	require.NoError(t, vm.Shutdown(context.Background()))
	require.Error(t, blk.Accept(context.Background()))
	require.Equal(t, uint8(0), blk.Status(), "a block that could not be written is not accepted")
}

// TestStatusReadsTheStoreNotJustTheTip proves an accepted block still reports
// accepted after a later block replaces it as the tip — status is a fact about
// the chain, not about which block happens to be last.
func TestStatusReadsTheStoreNotJustTheTip(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	_, err := vm.SubmitTx(registerTx(t, k, "first", 300_000, 1))
	require.NoError(t, err)
	first, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.Equal(t, uint8(0), first.(*Block).Status(), "a built block is still processing")
	require.NoError(t, first.Verify(ctx))
	require.NoError(t, first.Accept(ctx))
	require.Equal(t, uint8(1), first.(*Block).Status())

	_, err = vm.SubmitTx(registerTx(t, k, "second", 300_000, 2))
	require.NoError(t, err)
	second, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, second.Verify(ctx))
	require.NoError(t, second.Accept(ctx))

	require.Equal(t, uint8(1), first.(*Block).Status(),
		"a block that is no longer the tip is still accepted")
	require.Equal(t, uint8(1), second.(*Block).Status())

	// A block the chain never saw is not accepted.
	stranger := blockAt(vm, ids.GenerateTestID(), 9, vm.clock.Time())
	require.Equal(t, uint8(0), stranger.Status())
}

// TestGenesisRefusesToSeedOnABrokenStore proves the chain does not start on a
// store that cannot hold it: if the allocation and the genesis block cannot be
// committed, Initialize fails rather than serving a chain with no funds.
func TestGenesisRefusesToSeedOnABrokenStore(t *testing.T) {
	k := newTestKey(t)
	db := &failingDB{Database: memdb.New()}
	db.breakWrites()

	err := (&VM{}).Initialize(context.Background(), initFor(t, db,
		map[string]uint64{k.hexAddr(): 10}))
	require.ErrorIs(t, err, errStoreDown)
}

// TestAbortRestoresTheCachesFromTheStore proves the rollback is not merely a
// versiondb Abort: the in-memory caches, which a failed block has already
// mutated, are rebuilt from the unchanged base. A cache left holding the failed
// block's writes would answer queries with state no validator agreed to.
func TestAbortRestoresTheCachesFromTheStore(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	acceptOne(t, vm, registerTx(t, k, "kept", 300_000, 1))
	before := vm.Keys()
	require.Len(t, before, 1)

	// A block whose FIRST transaction applies and whose second cannot: the
	// register lands in the cache, then the block fails.
	good := registerTx(t, k, "transient", 300_000, 2)
	doomed := registerTx(t, k, "transient", 300_000, 2) // duplicate nonce
	blk := blockAt(vm, vm.lastAccepted, vm.height+1, vm.clock.Time(), good, doomed)
	require.ErrorIs(t, blk.Accept(context.Background()), ErrBadNonce)

	after := vm.Keys()
	require.Len(t, after, 1, "the aborted register must be gone from the cache")
	require.Equal(t, "kept", after[0].Name)
	_, present := vm.KeyByName("transient")
	require.False(t, present)

	// And the chain still works afterwards.
	acceptOne(t, vm, registerTx(t, k, "later", 300_000, 2))
	require.Len(t, vm.Keys(), 2)
}

// TestSettlementNeedsRealFunds proves Charge is the authoritative debit. Even
// handed a block that skipped Verify entirely, Accept refuses to settle an
// operation the payer cannot afford.
func TestSettlementNeedsRealFunds(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	blk := blockAt(vm, vm.lastAccepted, 1, vm.clock.Time(),
		registerTx(t, k, "unpayable", 300_000, 1))
	require.ErrorIs(t, blk.Accept(context.Background()), fee.ErrInsufficientFunds)

	bal, err := vm.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, uint64(1), bal, "a refused settlement must take nothing")
}
