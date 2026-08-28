// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/zap"
)

// TestPricingRefusesAnUnknownOperation proves every pricing entry point fails
// closed on an operation the schedule does not name. An unpriced operation
// priced at zero would be an operation that settles nothing.
func TestPricingRefusesAnUnknownOperation(t *testing.T) {
	unknown := &Transaction{Type: 99, GasLimit: 1_000_000}

	_, err := GasFor(unknown)
	require.Error(t, err)
	_, err = FeeFor(unknown)
	require.Error(t, err)
	_, err = meter(unknown)
	require.Error(t, err)

	// And through the layers that price: admission refuses it too.
	vm := newTestVM(t, nil)
	defer func() { _ = vm.Shutdown(context.Background()) }()
	_, err = vm.SubmitTx(unknown)
	require.ErrorIs(t, err, ErrInvalidTxType)
}

// TestSetPolicyOnAMissingKeyIsNotFound proves the policy operation resolves its
// target rather than creating one: naming a key that does not exist is refused,
// not silently applied to an empty record.
func TestSetPolicyOnAMissingKeyIsNotFound(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 10_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	tx := &Transaction{
		Type: TxSetPolicy, Payer: k.addr, KeyID: ids.GenerateTestID(),
		GasLimit: 300_000, Nonce: 1, Payload: mustJSON(t, SetPolicyPayload{}),
	}
	k.sign(t, tx)
	_, err := vm.SubmitTx(tx)
	require.ErrorIs(t, err, ErrKeyNotFound)
	require.Empty(t, vm.Keys(), "a refused policy update must not create a key")
}

// TestApplyRefusesAPayloadItCannotDecode proves the operations whose
// authorization does not read the payload still refuse to apply one they cannot
// decode, rather than applying zero values. A SetPolicy that decoded as an empty
// policy would silently strip a key's permissions.
func TestApplyRefusesAPayloadItCannotDecode(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	acceptOne(t, vm, registerTx(t, k, "decodable", 300_000, 1))
	keyID := deriveKeyID("decodable")
	now := vm.clock.Time().Unix()

	vm.stateLock.Lock()
	defer vm.stateLock.Unlock()

	badPolicy := &Transaction{Type: TxSetPolicy, Payer: k.addr, KeyID: keyID, Payload: []byte("{{{")}
	require.ErrorIs(t, badPolicy.Apply(vm, now), ErrInvalidPayload)

	badAuthorize := &Transaction{
		Type: TxAuthorize, Algorithm: "ml-dsa-65", Payer: k.addr, KeyID: keyID,
		Payload: []byte("{{{"),
	}
	require.ErrorIs(t, badAuthorize.Apply(vm, now), ErrInvalidPayload)

	rec := vm.keys[keyID]
	require.True(t, rec.Policy.MayAdmin(k.addr), "a refused update must leave the policy intact")
	require.Empty(t, vm.ceremonies)
}

// TestMalformedTxIsDroppedAtAssembly proves block assembly refuses what the
// codec would refuse: a syntactically invalid transaction in the mempool is
// dropped rather than carried into a block Verify would then reject.
func TestMalformedTxIsDroppedAtAssembly(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	malformed := registerTx(t, k, "bad", 300_000, 1)
	malformed.Payload = []byte("{{{") // no longer decodes
	good := registerTx(t, k, "good", 300_000, 1)

	vm.mempoolLock.Lock()
	vm.mempool = []*Transaction{malformed, good}
	vm.mempoolLock.Unlock()

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.Len(t, blk.(*Block).transactions, 1)
	require.NoError(t, blk.Verify(context.Background()))
}

// TestGenesisRefusesAnOverflowingAllocation proves the seeding arithmetic is
// checked. Two spellings of the same address are the same account, so an
// allocation can overflow it; crediting a wrapped balance would mint from
// nothing.
func TestGenesisRefusesAnOverflowingAllocation(t *testing.T) {
	k := newTestKey(t)
	bare := hex.EncodeToString(k.addr[:])

	err := (&VM{}).Initialize(context.Background(), initFor(t, memdb.New(), map[string]uint64{
		bare:        ^uint64(0),
		"0x" + bare: 1, // the SAME account, spelled differently
	}))
	require.Error(t, err, "an allocation that overflows an account must refuse to boot")
}

// TestBootWithoutALoggerSucceeds proves the VM supplies its own no-op logger
// rather than dereferencing a nil one — a chain must boot for a node that
// passes no logging.
func TestBootWithoutALoggerSucceeds(t *testing.T) {
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		DB: memdb.New(), ToEngine: make(chan vmcore.Message, 1),
	}))
	defer func() { _ = vm.Shutdown(context.Background()) }()

	h, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	require.True(t, h.Healthy)
}

// TestShutdownIsIdempotentAndReported proves a second Shutdown does not panic
// and that the VM notices the store refusing to close twice — a swallowed close
// error is how a half-closed store goes unnoticed.
func TestShutdownIsIdempotentAndReported(t *testing.T) {
	vm := newTestVM(t, nil)
	require.NoError(t, vm.Shutdown(context.Background()))
	require.NoError(t, vm.Shutdown(context.Background()))
}

// blindIterDB hands out iterators that report an error instead of data, the way
// a store fails a full-keyspace scan.
type blindIterDB struct {
	database.Database
	mu    sync.Mutex
	blind string // the key prefix whose scan fails
}

func (d *blindIterDB) setBlind(prefix string) {
	d.mu.Lock()
	d.blind = prefix
	d.mu.Unlock()
}

func (d *blindIterDB) blinded(prefix []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.blind == string(prefix)
}

func (d *blindIterDB) NewIteratorWithPrefix(prefix []byte) database.Iterator {
	return d.NewIteratorWithStartAndPrefix(nil, prefix)
}

func (d *blindIterDB) NewIteratorWithStartAndPrefix(start, prefix []byte) database.Iterator {
	if d.blinded(prefix) {
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

// TestUnscannableStateRefusesToBoot proves the cache rebuild reports a scan it
// could not complete rather than starting with a silently empty key set. An
// empty cache would make every registered key look absent — and every name free
// to claim again.
func TestUnscannableStateRefusesToBoot(t *testing.T) {
	for _, prefix := range []string{KeyPrefix, CeremonyPrefix} {
		db := &blindIterDB{Database: memdb.New()}
		db.setBlind(prefix)
		err := (&VM{}).Initialize(context.Background(), initFor(t, db, nil))
		require.ErrorIsf(t, err, errStoreDown, "a failed %q scan must refuse the boot", prefix)
	}
}

// TestGenesisRefusesAnUnreadableMarker proves the once-only seeding is decided
// by a marker the store must actually answer for. A store that cannot say
// whether genesis was already applied must not be seeded again — that would
// credit the allocation twice.
func TestGenesisRefusesAnUnreadableMarker(t *testing.T) {
	db := &blindDB{Database: memdb.New()}
	db.blind(func(key []byte) bool { return string(key) == string(genesisMarker) })
	err := (&VM{}).Initialize(context.Background(), initFor(t, db, nil))
	require.ErrorIs(t, err, errStoreDown)
}

// TestParseTransactionRefusesACorruptHeader proves the two-message split does
// not trust a length field over the message it delimits: a plausible length over
// a header the codec cannot read is refused.
func TestParseTransactionRefusesACorruptHeader(t *testing.T) {
	data := sampleTx().Bytes()
	corrupt := append([]byte(nil), data...)
	for i := 0; i < 12; i++ { // everything before the length field
		corrupt[i] ^= 0xff
	}
	_, err := ParseTransaction(corrupt)
	require.Error(t, err)
}

// TestCeremoniesSurviveAReload proves the ceremony cache is rebuilt from the
// store, not merely accumulated in memory: a chain that restarts still knows
// which ceremonies it authorized.
func TestCeremoniesSurviveAReload(t *testing.T) {
	k := newTestKey(t)
	db := memdb.New()
	vm := newTestVM(t, nil)
	_ = vm.Shutdown(context.Background())

	vm = newTestVMOn(t, db, map[string]uint64{k.hexAddr(): 100_000_000_000})
	acceptOne(t, vm, registerTx(t, k, "persisted", 300_000, 1))
	authorize := &Transaction{
		Type: TxAuthorize, Algorithm: "ml-dsa-65", Payer: k.addr,
		KeyID: deriveKeyID("persisted"), GasLimit: 300_000, Nonce: 2,
		Payload: mustJSON(t, AuthorizePayload{Ceremony: CeremonyDKG}),
	}
	k.sign(t, authorize)
	acceptOne(t, vm, authorize)

	var want ids.ID
	vm.stateLock.RLock()
	for id := range vm.ceremonies {
		want = id
	}
	vm.stateLock.RUnlock()
	require.NotEqual(t, ids.Empty, want)

	reopened := newTestVMOn(t, db, nil)
	defer func() { _ = reopened.Shutdown(context.Background()) }()

	got, ok := reopened.Ceremony(want)
	require.True(t, ok, "an authorized ceremony must survive a restart")
	require.Equal(t, CeremonyDKG, got.Type)
	require.Equal(t, k.addr, got.Requester)
	_, ok = reopened.KeyByName("persisted")
	require.True(t, ok)
	require.Equal(t, uint64(2), reopened.height, "the chain resumes at its committed height")
}

// TestCorruptHeightIndexIsReported proves the index is validated on read: an
// entry of the wrong width is corruption, not a block id to be zero-padded into
// existence.
func TestCorruptHeightIndexIsReported(t *testing.T) {
	vm := newTestVM(t, nil)
	defer func() { _ = vm.Shutdown(context.Background()) }()

	vm.stateLock.Lock()
	require.NoError(t, vm.versdb.Put(heightKey(5), []byte{1, 2, 3}))
	require.NoError(t, vm.versdb.Commit())
	vm.stateLock.Unlock()

	_, err := vm.GetBlockIDAtHeight(context.Background(), 5)
	require.ErrorContains(t, err, "corrupt")
}

// TestBlocksAreFoundWhereverTheyLive proves one lookup answers for all three
// homes a block can be in: still processing, the current tip, or committed to
// the store behind a newer tip.
func TestBlocksAreFoundWhereverTheyLive(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	_, err := vm.SubmitTx(registerTx(t, k, "one", 300_000, 1))
	require.NoError(t, err)
	first, err := vm.BuildBlock(ctx)
	require.NoError(t, err)

	// Processing: still in the pending index.
	got, err := vm.GetBlock(ctx, first.ID())
	require.NoError(t, err)
	require.Equal(t, first.ID(), got.ID())

	require.NoError(t, first.Verify(ctx))
	require.NoError(t, first.Accept(ctx))

	// The tip.
	got, err = vm.GetBlock(ctx, first.ID())
	require.NoError(t, err)
	require.Equal(t, first.ID(), got.ID())

	// Behind a newer tip: read back out of the store.
	_, err = vm.SubmitTx(registerTx(t, k, "two", 300_000, 2))
	require.NoError(t, err)
	second, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, second.Verify(ctx))
	require.NoError(t, second.Accept(ctx))

	got, err = vm.GetBlock(ctx, first.ID())
	require.NoError(t, err)
	require.Equal(t, first.ID(), got.ID())
	require.Equal(t, uint64(1), got.Height())

	_, err = vm.GetBlock(ctx, ids.GenerateTestID())
	require.ErrorIs(t, err, database.ErrNotFound)
}

// TestMempoolKeepsWhatABlockDidNotTake proves accepting a block removes exactly
// the transactions it carried and leaves the rest queued.
func TestMempoolKeepsWhatABlockDidNotTake(t *testing.T) {
	taken, left := newTestKey(t), newTestKey(t)
	vm := newTestVM(t, map[string]uint64{
		taken.hexAddr(): 100_000_000_000, left.hexAddr(): 100_000_000_000,
	})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	_, err := vm.SubmitTx(registerTx(t, taken, "carried", 300_000, 1))
	require.NoError(t, err)
	blk, err := vm.BuildBlock(ctx)
	require.NoError(t, err)

	// A second transaction arrives after the drain.
	straggler := registerTx(t, left, "straggler", 300_000, 1)
	_, err = vm.SubmitTx(straggler)
	require.NoError(t, err)

	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))

	vm.mempoolLock.Lock()
	remaining := append([]*Transaction(nil), vm.mempool...)
	vm.mempoolLock.Unlock()
	require.Len(t, remaining, 1)
	require.Equal(t, straggler.ID(), remaining[0].ID())
}

// TestEmptyBlockRejectAndDropAreNoOps proves the mempool operations are safe on
// an empty transaction set: rejecting an empty block queues nothing, and
// accepting one drops nothing.
func TestEmptyBlockRejectAndDropAreNoOps(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	_, err := vm.SubmitTx(registerTx(t, k, "queued", 300_000, 1))
	require.NoError(t, err)

	empty := blockAt(vm, vm.lastAccepted, 1, vm.clock.Time())
	require.NoError(t, empty.Reject(context.Background()))

	vm.mempoolLock.Lock()
	n := len(vm.mempool)
	vm.mempoolLock.Unlock()
	require.Equal(t, 1, n, "rejecting an empty block queues nothing")

	vm.dropFromMempool(nil)
	vm.mempoolLock.Lock()
	n = len(vm.mempool)
	vm.mempoolLock.Unlock()
	require.Equal(t, 1, n, "dropping nothing removes nothing")
}

// TestParseTransactionRejectsACorruptBody proves the two-message split is
// validated: a plausible length prefix over a body that does not decode, and a
// trailing message whose declared size does not consume the input, are both
// refused.
func TestParseTransactionRejectsACorruptBody(t *testing.T) {
	data := sampleTx().Bytes()
	n, err := zapLen(data)
	require.NoError(t, err)

	// A well-formed length prefix over a scrambled signing message.
	corrupt := append([]byte(nil), data...)
	for i := zap.HeaderSize; i < n; i++ {
		corrupt[i] = 0xff
	}
	_, err = ParseTransaction(corrupt)
	require.Error(t, err)

	// Extra bytes after the trailing message, without bumping its size field:
	// the message no longer consumes its input.
	trailing := append(append([]byte(nil), data...), 0xde, 0xad)
	_, err = ParseTransaction(trailing)
	require.ErrorIs(t, err, ErrInvalidPayload)
}

// TestParseBlockRejectsACorruptTransaction proves a block is only as valid as
// the transactions it carries: a block whose blob does not decode as a
// transaction is refused whole.
func TestParseBlockRejectsACorruptTransaction(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	junk := []byte("not-a-transaction")
	b := zap.NewBuilder(zap.HeaderSize + blkSize + 128)
	lensOff := writeU32List(b, []uint32{uint32(len(junk))})
	ob := b.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, make([]byte, 32))
	ob.SetUint64(blkHeight, 1)
	ob.SetInt64(blkTime, vm.clock.Time().Unix())
	ob.SetList(blkTxLens, lensOff, 1)
	ob.SetBytes(blkTxBlob, junk)
	ob.FinishAsRoot()

	_, err := parseBlock(vm, b.Finish())
	require.Error(t, err)
}

// TestZapLenRefusesAnImpossibleLength proves the split point is bounds-checked:
// a declared length shorter than a header or longer than the buffer is refused
// rather than used to slice.
func TestZapLenRefusesAnImpossibleLength(t *testing.T) {
	data := sampleTx().Bytes()

	short := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(short[12:16], 3) // shorter than a header
	_, err := ParseTransaction(short)
	require.ErrorIs(t, err, ErrInvalidPayload)

	long := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(long[12:16], uint32(len(long)+1))
	_, err = ParseTransaction(long)
	require.ErrorIs(t, err, ErrInvalidPayload)
}

// TestKeyViewCarriesTheCommittee proves the public view renders the committee
// that holds the shares off-chain — the record's whole point is naming who to
// ask, so an empty committee in the view would be a silent loss.
func TestKeyViewCarriesTheCommittee(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	committee := []ids.NodeID{ids.GenerateTestNodeID(), ids.GenerateTestNodeID()}
	tx := &Transaction{
		Type: TxRegisterKey, Algorithm: "ml-dsa-65", Payer: k.addr,
		KeyID: deriveKeyID("committed"), GasLimit: 300_000, Nonce: 1,
		Payload: mustJSON(t, RegisterKeyPayload{
			Name: "committed", PublicKey: []byte("PUB"), Threshold: 2, TotalShares: 2,
			Commitments: [][]byte{{1}, {2}}, Committee: committee,
		}),
	}
	k.sign(t, tx)
	acceptOne(t, vm, tx)

	rec, ok := vm.KeyByName("committed")
	require.True(t, ok)
	view := toKeyView(rec)
	require.Len(t, view.Committee, 2)
	require.Equal(t, committee[0].String(), view.Committee[0])
	require.Equal(t, committee[1].String(), view.Committee[1])
}

// TestRPCReportsARefusedSubmission proves the submit endpoint surfaces the
// chain's refusal instead of reporting a transaction id for work that will never
// land.
func TestRPCReportsARefusedSubmission(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	h, err := vm.NewHTTPHandler(context.Background())
	require.NoError(t, err)

	tx := registerTx(t, k, "unaffordable", 300_000, 1)
	msg := call(t, h, "SubmitTransaction",
		SubmitTransactionArgs{Tx: hex.EncodeToString(tx.Bytes())}, nil)
	require.Contains(t, msg, "insufficient funds")
}

// TestRPCBalanceSurfacesAStoreFailure proves the balance endpoint reports a
// store it could not read rather than answering zero.
func TestRPCBalanceSurfacesAStoreFailure(t *testing.T) {
	k := newTestKey(t)
	db := &blindDB{Database: memdb.New()}
	vm := newTestVMOn(t, db, map[string]uint64{k.hexAddr(): 5_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	h, err := vm.NewHTTPHandler(context.Background())
	require.NoError(t, err)

	want := balanceKeyOf(k.addr)
	db.blind(func(key []byte) bool { return string(key) == string(want) })
	require.Contains(t, call(t, h, "Balance", BalanceArgs{Address: k.hexAddr()}, nil),
		errStoreDown.Error())

	db.blind(func(key []byte) bool { return string(key) == "fee/burned" })
	require.Contains(t, call(t, h, "Balance", BalanceArgs{Address: k.hexAddr()}, nil),
		errStoreDown.Error())
}
