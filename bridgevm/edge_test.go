// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// The paths a chain takes when something is missing, unreadable, or refused.

// TestAChainThatCannotReadItsTipDoesNotStart. A tip pointing at a block the
// store no longer holds is a broken chain, and starting anyway would mean
// starting somewhere else.
func TestAChainThatCannotReadItsTipDoesNotStart(t *testing.T) {
	db := memdb.New()
	vm := bootOn(t, db, testConfig())
	pend(vm, requestFor(1, 100))
	blk := buildAndAccept(t, vm)

	// The tip is recorded; the block it names is gone.
	require.NoError(t, db.Delete(blockRecordKey(blk.ID())))
	require.Error(t, (&VM{}).Initialize(context.Background(), initFor(db, testConfig())))
}

// blockRecordKey is where the shared store keeps a block's bytes.
func blockRecordKey(id ids.ID) []byte {
	return append([]byte("chain/block/"), id[:]...)
}

// A tip that is not an id at all is not a chain either.
func TestAChainWithAnUnreadableTipDoesNotStart(t *testing.T) {
	db := memdb.New()
	require.NoError(t, db.Put([]byte("chain/tip"), make([]byte, ids.IDLen)))
	// Zero is a well-formed id naming no block.
	require.Error(t, (&VM{}).Initialize(context.Background(), initFor(db, testConfig())))
}

// TestARelayerThatIsNotReadingReportsIt. A node with chains wired and a
// threshold key, but nothing watching for locks, has nothing to relay: saying
// healthy routes transfers at it.
func TestARelayerThatIsNotReadingReportsIt(t *testing.T) {
	vm, _, _ := custodyRig(t)
	ready, reason, chains := vm.readiness()
	require.False(t, ready)
	require.Equal(t, "not watching for locks", reason)
	require.Equal(t, 2, chains)
}

// TestAnEmptyGroupIsNotAKey. A CMP group with no shares in it sums to the
// identity point, which marshals to a perfectly well-formed 33 bytes. Handed
// back as a key it made an empty config look like a finished keygen: the node
// reported itself ready to attest, and bridge_getInfo agreed, on a chain that
// could verify nothing.
func TestAnEmptyGroupIsNotAKey(t *testing.T) {
	vm := boot(t)
	require.Nil(t, vm.mpcGroupPublicKey())

	vm.mpcConfig = emptyGroupConfig()
	require.Nil(t, vm.mpcGroupPublicKey(), "the identity point was reported as a custody key")

	// So the node does not claim it can attest.
	vm.mu.Lock()
	vm.evmByChainID[dstChain] = &countingClient{}
	vm.mu.Unlock()
	ready, reason, _ := vm.readiness()
	require.False(t, ready)
	require.Equal(t, "no threshold signing key", reason)

	var reply HealthReply
	require.NoError(t, (&Service{vm: vm}).Health(nil, &HealthArgs{}, &reply))
	require.False(t, reply.MPCReady)

	// And it releases nothing on an attestation it cannot check.
	vm.attestClient = refusingAttester{}
	_, err := vm.releaseTransfer(context.Background(), transferFor(1, 100))
	require.Error(t, err)
}

// TestTheWatcherPollsOnItsOwn drives the loop rather than the pass: a watcher
// that is started must read without being asked.
func TestTheWatcherPollsOnItsOwn(t *testing.T) {
	vm := boot(t)
	src := &fakeSource{head: 1000}
	w := watcherOn(vm, src)
	w.every = 2 * time.Millisecond
	w.wg.Add(1)
	go w.run()
	defer w.stop()

	require.Eventually(t, func() bool { return src.timesRead() >= 2 },
		5*time.Second, time.Millisecond, "a running watcher never read its chain")
}

// A chain that has not moved since the last pass is not asked again.
func TestAChainThatHasNotMovedIsNotAskedAgain(t *testing.T) {
	vm := boot(t)
	src := &fakeSource{head: 1000}
	w := watcherOn(vm, src)
	w.pass()
	w.pass()
	require.Empty(t, src.asked, "the same settled head was asked for twice")
}

// A range this node cannot read leaves the cursor where it was.
func TestARangeThatCannotBeReadDoesNotAdvanceTheCursor(t *testing.T) {
	vm := boot(t)
	src := &failingRange{fakeSource: &fakeSource{head: 1000}}
	w := watcherOn(vm, src)
	w.pass()
	before := w.cursor[srcChain]

	src.mu.Lock()
	src.head = 2000
	src.mu.Unlock()
	w.pass()
	require.Equal(t, before, w.cursor[srcChain])
}

type failingRange struct{ *fakeSource }

func (f *failingRange) FetchLockEvents(context.Context, *big.Int, *big.Int) ([]lock, error) {
	return nil, errUnreadable
}

// A request with no recipient parses back as one with no recipient rather than
// as twenty zero bytes, so the digest check sees what was actually sent.
func TestAnEmptyFieldParsesBackEmpty(t *testing.T) {
	vm := boot(t)
	req := &BridgeRequest{ID: ids.GenerateTestID(), SrcChainID: srcChain, DstChainID: dstChain, Amount: 1}
	blk := blockOn(t, vm, vm.genesisBlock, now(), req)

	back, err := vm.ParseBlock(context.Background(), blk.Bytes())
	require.NoError(t, err)
	require.Nil(t, back.(*Block).BridgeRequests[0].Recipient)
	require.ErrorContains(t, back.Verify(context.Background()), "20 bytes")
	require.Nil(t, appendBytes(nil))
	require.Nil(t, appendBytes([]byte{}))
}

// A block whose length list is longer than its blob is refused, and so is one
// whose blob has bytes no length claims.
func TestALengthListMustAccountForTheBlob(t *testing.T) {
	vm := boot(t)
	req := requestFor(1, 100)
	rb := marshalBridgeRequest(req)

	bld := zap.NewBuilder(zap.HeaderSize + blkSize + 2*len(rb) + 256)
	lensOff := writeU32List(bld, []uint32{uint32(len(rb))})
	ob := bld.StartObject(blkSize)
	gid := vm.genesisBlock.ID()
	ob.SetBytesFixed(blkParent, gid[:])
	ob.SetUint64(blkHeight, 1)
	ob.SetInt64(blkTime, now())
	ob.SetList(blkReqLens, lensOff, 1)
	ob.SetBytes(blkReqBlob, append(append([]byte(nil), rb...), rb...))
	ob.FinishAsRoot()

	_, err := vm.ParseBlock(context.Background(), bld.Finish())
	require.ErrorContains(t, err, "canonical")
}

// A block that cannot stage its settlement records does not commit.
func TestABlockThatCannotWriteASettlementDoesNotCommit(t *testing.T) {
	vm := boot(t)
	blk := blockOn(t, vm, vm.genesisBlock, now(), requestFor(1, 100))
	require.NoError(t, blk.Verify(context.Background()))

	require.ErrorIs(t, blk.write(&refusingPut{Database: memdb.New(), prefix: settledPrefix}), errUnreadable)
	require.ErrorIs(t, blk.write(&refusingPut{Database: memdb.New(), prefix: movedPrefix}), errUnreadable)
}

type refusingPut struct {
	database.Database
	prefix []byte
}

func (d *refusingPut) Put(key, value []byte) error {
	if len(key) >= len(d.prefix) && string(key[:len(d.prefix)]) == string(d.prefix) {
		return errUnreadable
	}
	return d.Database.Put(key, value)
}

// =============================================================================
// The RPC surface's remaining answers
// =============================================================================

func TestRPC_ReplaceSignerWithANamedReplacement(t *testing.T) {
	srv, vm := newRPCRig(t)
	node, replacement := ids.GenerateTestNodeID(), ids.GenerateTestNodeID()
	require.NoError(t, registerSigner(vm, node))

	var reply ReplaceSignerReply
	code, msg := callRPC(t, srv.URL, "bridge_replaceSigner", ReplaceSignerArgs{
		NodeID: node.String(), ReplacementNodeID: replacement.String(),
	}, &reply)
	require.Zero(t, code, msg)
	require.Equal(t, replacement.String(), reply.ReplacementNodeID)
	require.True(t, vm.HasSigner(replacement))
}

func TestRPC_TheWaitlistIsNamed(t *testing.T) {
	srv, vm := newRPCRig(t)
	vm.config.MaxSigners = 1
	first, waiting := ids.GenerateTestNodeID(), ids.GenerateTestNodeID()
	require.NoError(t, registerSigner(vm, first))
	require.NoError(t, registerSigner(vm, waiting))

	var reply GetWaitlistReply
	code, msg := callRPC(t, srv.URL, "bridge_getWaitlist", nil, &reply)
	require.Zero(t, code, msg)
	require.Equal(t, 1, reply.WaitlistSize)
	require.Equal(t, []string{waiting.String()}, reply.NodeIDs)
}

func TestRPC_SlashRefusesAPercentThatIsNotOne(t *testing.T) {
	srv, vm := newRPCRig(t)
	node := ids.GenerateTestNodeID()
	require.NoError(t, registerSigner(vm, node))

	code, msg := callRPC(t, srv.URL, "bridge_slashSigner", SlashSignerArgs{
		NodeID: node.String(), SlashPercent: 0,
	}, &SlashSignerReply{})
	require.NotZero(t, code)
	require.Contains(t, msg, "between 1 and 100")
}

func TestRPC_SubmitRefusesWhatItCannotQuote(t *testing.T) {
	srv, _ := newRPCRig(t)
	code, _ := callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
		SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
		SourceAsset: "NOSUCHASSET", DestAsset: "LUX", Amount: "1",
		Recipient: "0xabc", Sender: "0xabc",
	}, &SubmitRequestReply{})
	require.NotZero(t, code, "a swap nobody can price must not be recorded")
}

// bridge_getInfo answers with the group key once M-Chain's keygen has landed,
// and with the node that is answering.
func TestRPC_GetInfoOnceThereIsAGroupKey(t *testing.T) {
	vm, _, _ := custodyRig(t)
	srv, _ := serveVM(t, vm)

	var reply GetBridgeInfoReply
	code, msg := callRPC(t, srv.URL, "bridge_getInfo", nil, &reply)
	require.Zero(t, code, msg)
	require.True(t, reply.MPCReady)
	require.Equal(t, hexEncode(vm.mpcGroupPublicKey()), reply.MPCPublicKey)
	require.Equal(t, vm.rt.NodeID.String(), reply.NodeID)

	var key GetMPCPublicKeyReply
	code, msg = callRPC(t, srv.URL, "bridge_getMPCPublicKey", nil, &key)
	require.Zero(t, code, msg)
	require.Equal(t, reply.MPCPublicKey, key.PublicKey)
}

// A counter bridge_getInfo cannot read is reported, not summed as zero.
func TestRPC_GetInfoSaysWhenItCannotRead(t *testing.T) {
	vm := bootOn(t, &unreadableDB{Database: memdb.New(), prefix: movedPrefix, err: errUnreadable},
		testConfig())
	srv, _ := serveVM(t, vm)

	code, msg := callRPC(t, srv.URL, "bridge_getInfo", nil, &GetBridgeInfoReply{})
	require.NotZero(t, code)
	require.Contains(t, msg, errUnreadable.Error())
}

// =============================================================================
// The swap store's refusals
// =============================================================================

func TestTheSwapStoreRefusesNothing(t *testing.T) {
	store := newInMemorySwapStore()
	require.ErrorContains(t, store.Put(nil), "nil record")

	_, err := store.Patch("req_nope", func(*BridgeRequestRecord) {})
	require.ErrorIs(t, err, ErrSwapNotFound)

	rec := &BridgeRequestRecord{RequestID: "req_fixed", SourceChain: "a"}
	require.NoError(t, store.Put(rec))
	got, err := store.Get("req_fixed")
	require.NoError(t, err)
	require.Equal(t, StatusPending, got.Status)
	require.NotZero(t, got.CreatedAt)

	all, err := store.List(SwapListFilter{Limit: 1})
	require.NoError(t, err)
	require.Len(t, all, 1)
}

// =============================================================================
// The quote engine's refusals
// =============================================================================

func TestTheQuoteEngineRefusesWhatItCannotPrice(t *testing.T) {
	_, err := (&QuoteEngine{}).Quote(QuoteInput{Amount: 1})
	require.ErrorContains(t, err, "no PriceFeed configured")

	q := &QuoteEngine{Feed: defaultPriceFeed()}
	_, err = q.Quote(QuoteInput{Amount: 1, SourceAsset: "ETH", DestinationAsset: "NOSUCHASSET"})
	require.ErrorContains(t, err, "destination price")

	// A destination priced at nothing would divide the whole transfer by zero.
	feed := &StaticPriceFeed{prices: map[string]float64{"ETH": 3000, "FREE": 0}}
	_, err = (&QuoteEngine{Feed: feed}).Quote(QuoteInput{Amount: 1, SourceAsset: "ETH", DestinationAsset: "FREE"})
	require.ErrorContains(t, err, "must be > 0")
}

// A configured fee rate is the one that is charged on an exit.
func TestAConfiguredFeeRateIsTheOneCharged(t *testing.T) {
	q := &QuoteEngine{Feed: defaultPriceFeed(), FeeRate: 0.5, Slippage: 0.01}
	res, err := q.Quote(QuoteInput{
		Amount: 100, SourceNetwork: "LUX_TESTNET", SourceAsset: "LUX",
		DestinationNetwork: "ETHEREUM_SEPOLIA", DestinationAsset: "LUX",
	})
	require.NoError(t, err)
	require.InDelta(t, 50.0, res.ServiceFee, 1e-9)
	require.InDelta(t, 50.0, res.ReceiveAmount, 1e-9)
	require.InDelta(t, 0.01, res.Slippage, 1e-9)
}

// =============================================================================
// A store that refuses
// =============================================================================

// refusingStore accepts reads and refuses every write, which is what a
// persistent swap store does when its disk is gone.
type refusingStore struct{ SwapStore }

func (refusingStore) Put(*BridgeRequestRecord) error { return errUnreadable }
func (refusingStore) Patch(string, func(*BridgeRequestRecord)) (*BridgeRequestRecord, error) {
	return nil, errUnreadable
}

func TestRPC_AStoreThatRefusesIsReported(t *testing.T) {
	srv, vm := newRPCRig(t)

	// A record the store keeps, so cancel gets past its read.
	var sub SubmitRequestReply
	code, msg := callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
		SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
		SourceAsset: "ETH", DestAsset: "LUX", Amount: "1",
		Recipient: "0xabc", Sender: "0xabc",
	}, &sub)
	require.Zero(t, code, msg)

	vm.swapStore = refusingStore{SwapStore: vm.swapStore}

	code, msg = callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
		SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
		SourceAsset: "ETH", DestAsset: "LUX", Amount: "1",
		Recipient: "0xabc", Sender: "0xabc",
	}, &SubmitRequestReply{})
	require.NotZero(t, code)
	require.Contains(t, msg, errUnreadable.Error())

	code, msg = callRPC(t, srv.URL, "bridge_cancelRequest",
		CancelRequestArgs{RequestID: sub.RequestID}, &CancelRequestReply{})
	require.NotZero(t, code)
	require.Contains(t, msg, errUnreadable.Error())
}

// A submitted amount that is not a positive number is refused before anything
// is priced or recorded.
func TestRPC_SubmitRefusesAnAmountThatIsNotOne(t *testing.T) {
	srv, _ := newRPCRig(t)
	for _, amount := range []string{"", "0", "-5", "lots"} {
		code, _ := callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
			SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
			SourceAsset: "ETH", DestAsset: "LUX", Amount: amount,
			Recipient: "0xabc", Sender: "0xabc",
		}, &SubmitRequestReply{})
		require.NotZero(t, code, "amount %q was accepted", amount)
	}
}

// =============================================================================
// A store this node cannot enumerate
// =============================================================================

// unlistableDB answers reads but cannot be walked, which is what a corrupted
// index looks like. Booting past it would mean deciding whether this database
// holds a live chain without being able to look.
type unlistableDB struct{ database.Database }

func (unlistableDB) NewIteratorWithPrefix([]byte) database.Iterator {
	return &brokenIterator{}
}

type brokenIterator struct{ database.Iterator }

func (*brokenIterator) Next() bool    { return false }
func (*brokenIterator) Error() error  { return errUnreadable }
func (*brokenIterator) Release()      {}
func (*brokenIterator) Key() []byte   { return nil }
func (*brokenIterator) Value() []byte { return nil }

func TestAStoreThatCannotBeWalkedDoesNotBoot(t *testing.T) {
	err := (&VM{}).Initialize(context.Background(),
		initFor(unlistableDB{Database: memdb.New()}, testConfig()))
	require.ErrorContains(t, err, "read settlement records")
}

// An endpoint that is not an endpoint is refused at dial, before anything is
// signed for the chain it claims to be.
func TestAnEndpointThatCannotBeDialledIsRefused(t *testing.T) {
	_, err := newEVMChainClient(context.Background(),
		chainCfg("zoo", uint64(dstChain), "gopher://not-a-thing"), relayerKey(t), nil)
	require.ErrorContains(t, err, "dial")
}
