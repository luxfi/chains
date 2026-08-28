// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/internal/bridgeattest"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// What a block may be, stated as the attacks it refuses. Every test here feeds
// a block the way a peer does — assembled by hand or handed in as wire bytes —
// because a block this node built is the one case that proves nothing.

// =============================================================================
// Replay. On a bridge this is the money: a transfer settled twice is a deposit
// released twice.
// =============================================================================

// TestOneTransferCannotRideTwiceInOneBlock. Verify read the running total once
// per transfer and never added the block's own amounts, so a block carrying
// the same transfer a hundred times passed every check a hundred times.
func TestOneTransferCannotRideTwiceInOneBlock(t *testing.T) {
	vm := boot(t)
	req := requestFor(1, 500)
	blk := blockOn(t, vm, vm.genesisBlock, now(), req, req)

	require.ErrorIs(t, blk.Verify(context.Background()), errReplay)
}

// TestATransferSettledByAnEarlierBlockCannotBeSettledAgain is replay across
// blocks. The record of what had been settled lived in a map in memory and was
// never consulted by Verify at all.
func TestATransferSettledByAnEarlierBlockCannotBeSettledAgain(t *testing.T) {
	vm := boot(t)
	req := requestFor(1, 500)
	pend(vm, req)
	first := buildAndAccept(t, vm)
	require.Equal(t, req.ID, first.BridgeRequests[0].ID)

	// The same transfer, presented again by a peer.
	again := blockOn(t, vm, first, now(), requestFor(1, 500))
	require.ErrorIs(t, again.Verify(context.Background()), errReplay)
}

// TestATransferSettledBeforeARestartCannotBeSettledAfterOne. The settled set
// was memory, so a restart forgot every transfer the chain had ever released
// and a re-observed lock was released a second time.
func TestATransferSettledBeforeARestartCannotBeSettledAgain(t *testing.T) {
	db := memdb.New()
	vm := bootOn(t, db, testConfig())
	pend(vm, requestFor(1, 500))
	first := buildAndAccept(t, vm)

	restarted := bootOn(t, db, testConfig())
	again := blockOn(t, restarted, first, now(), requestFor(1, 500))
	require.ErrorIs(t, again.Verify(context.Background()), errReplay)
}

// TestATransferInFlightCannotAlsoRideItsSibling. Two blocks one after the
// other, neither accepted yet: the second is checked against the state its
// parent decided, not against the tip, or the same transfer settles twice as
// soon as both are accepted.
func TestATransferInFlightCannotAlsoRideItsChild(t *testing.T) {
	vm := boot(t)
	req := requestFor(1, 500)

	first := blockOn(t, vm, vm.genesisBlock, now(), req)
	require.NoError(t, first.Verify(context.Background()))

	second := blockOn(t, vm, first, now(), requestFor(1, 500))
	require.ErrorIs(t, second.Verify(context.Background()), errReplay,
		"the child must see what its parent already settled")
}

// TestTheDailyCapHoldsAcrossBlocksInFlight. Checked against the tip alone, a
// run of blocks that are all in the air each get the whole day's allowance.
func TestTheDailyCapHoldsAcrossBlocksInFlight(t *testing.T) {
	cfg := testConfig()
	cfg.MaxBridgeAmount = 100
	cfg.DailyBridgeLimit = 150
	vm := bootOn(t, memdb.New(), cfg)

	at := now()
	first := blockOn(t, vm, vm.genesisBlock, at, requestFor(1, 100))
	require.NoError(t, first.Verify(context.Background()))

	// 100 of 150 is spoken for by a block that is not accepted yet.
	second := blockOn(t, vm, first, at, requestFor(2, 100))
	require.ErrorContains(t, second.Verify(context.Background()), "daily cap")

	// What is left, fits.
	third := blockOn(t, vm, first, at, requestFor(3, 50))
	require.NoError(t, third.Verify(context.Background()))
}

// =============================================================================
// A request's name is its contents.
// =============================================================================

// TestARequestMustBeTheDigestOfWhatItCarries. The id was a label the proposer
// chose. Everything downstream keys off it — the replay guard, the daily
// counter, what the release worker is handed — so a proposer could present one
// deposit under a hundred names, or one name carrying a different amount to a
// different recipient each time.
func TestARequestMustBeTheDigestOfWhatItCarries(t *testing.T) {
	vm := boot(t)

	renamed := requestFor(1, 500)
	renamed.ID = ids.GenerateTestID()
	require.ErrorContains(t,
		blockOn(t, vm, vm.genesisBlock, now(), renamed).Verify(context.Background()),
		"not the digest")

	// And every field the digest covers: change one and the name no longer fits.
	for name, mutate := range map[string]func(*BridgeRequest){
		"amount":      func(r *BridgeRequest) { r.Amount++ },
		"recipient":   func(r *BridgeRequest) { r.Recipient[0] ^= 0xff },
		"nonce":       func(r *BridgeRequest) { r.Nonce++ },
		"asset":       func(r *BridgeRequest) { r.Asset[0] ^= 0xff },
		"source":      func(r *BridgeRequest) { r.SrcChainID = 4242 },
		"destination": func(r *BridgeRequest) { r.DstChainID = 4242 },
	} {
		req := requestFor(1, 500)
		mutate(req)
		require.ErrorContains(t,
			blockOn(t, vm, vm.genesisBlock, now(), req).Verify(context.Background()),
			"not the digest", "a changed %s was accepted under the original name", name)
	}
}

func TestARequestMustBeWellFormed(t *testing.T) {
	vm := boot(t)
	cfg := &vm.config

	// A recipient that is not an address cannot be released to.
	short := requestFor(1, 500)
	short.Recipient = short.Recipient[:19]
	require.ErrorContains(t, admissible(cfg, short), "20 bytes")

	// A transfer to nowhere has no gateway to route to.
	noDst := requestFor(1, 500)
	noDst.DstChainID = 0
	require.ErrorContains(t, admissible(cfg, noDst), "destination chain id")

	// A transfer from nowhere cannot have its source lock re-checked. Named by
	// its own digest, so the check under test is the one that answers.
	fromNowhere := transferFor(1, 500)
	fromNowhere.SrcChainID = 0
	require.ErrorContains(t, admissible(cfg, requestOf(fromNowhere)), "no source chain")

	// A chain does not bridge to itself.
	selfBridge := transferFor(1, 500)
	selfBridge.DstChainID = selfBridge.SrcChainID
	require.ErrorContains(t, admissible(cfg, requestOf(selfBridge)), "to itself")

	// Nothing is not an amount.
	zero := requestOf(transferFor(1, 0))
	require.ErrorContains(t, admissible(cfg, zero), "moves nothing")

	// And the per-transfer cap.
	big := requestOf(transferFor(1, cfg.MaxBridgeAmount+1))
	require.ErrorContains(t, admissible(cfg, big), "per-transfer cap")
}

// =============================================================================
// Where a block sits in the chain.
// =============================================================================

// TestABlockOnAnOldSiblingIsRefused. Verify asked only that a block's height
// followed its parent's, never that the parent was the tip, so an old sibling
// rewound the chain — and the height index then served that orphan to
// bootstrapping peers as the block at that height.
func TestABlockOnAnOldSiblingIsRefused(t *testing.T) {
	vm := boot(t)
	pend(vm, requestFor(1, 100))
	one := buildAndAccept(t, vm)
	pend(vm, requestFor(2, 100))
	two := buildAndAccept(t, vm)
	require.Equal(t, uint64(2), two.BlockHeight)

	// A block built on block one, which the chain has already built past.
	rewind := blockOn(t, vm, one, now(), requestFor(3, 100))
	require.ErrorContains(t, rewind.Verify(context.Background()), "beneath the tip")

	// And the height index still names what was accepted.
	at, err := vm.GetBlockIDAtHeight(context.Background(), 2)
	require.NoError(t, err)
	require.Equal(t, two.ID(), at)
}

func TestABlockMustFollowItsParent(t *testing.T) {
	vm := boot(t)
	skipped := blockOn(t, vm, vm.genesisBlock, now(), requestFor(1, 100))
	skipped.BlockHeight = 7
	skipped.ID_ = skipped.computeID()
	require.ErrorContains(t, skipped.Verify(context.Background()), "does not follow parent")
}

func TestABlockWithNoParentIsRefused(t *testing.T) {
	vm := boot(t)
	orphan := &Block{
		ParentID_:      ids.GenerateTestID(),
		BlockHeight:    1,
		BlockTimestamp: now(),
		BridgeRequests: []*BridgeRequest{requestFor(1, 100)},
		vm:             vm,
	}
	orphan.ID_ = orphan.computeID()
	require.ErrorContains(t, orphan.Verify(context.Background()), "parent")
}

// TestABlockInFlightCanBeAParent is the other half of the tip rule, and the
// reason Verify registers what it accepts. Tracking only self-built blocks let
// a follower verify the first block of a run and fail the second with "parent
// not found" — the ordinary shape whenever more than one block is in the air.
func TestABlockInFlightCanBeAParent(t *testing.T) {
	vm := boot(t)

	first := blockOn(t, vm, vm.genesisBlock, now(), requestFor(1, 100))
	require.NoError(t, first.Verify(context.Background()))

	// The store must be able to resolve it as a parent now.
	found, err := vm.GetBlock(context.Background(), first.ID())
	require.NoError(t, err)
	require.Equal(t, first.ID(), found.ID())

	second := blockOn(t, vm, first, now(), requestFor(2, 100))
	require.NoError(t, second.Verify(context.Background()),
		"a follower must be able to verify the second block of a run")

	require.NoError(t, first.Accept(context.Background()))
	require.NoError(t, second.Accept(context.Background()))
	tip, height := vm.chain.Tip()
	require.Equal(t, second.ID(), tip)
	require.Equal(t, uint64(2), height)
}

// A parent this node never checked is not a parent it can account for.
func TestAParentThatWasNeverVerifiedIsRefused(t *testing.T) {
	vm := boot(t)
	unchecked := blockOn(t, vm, vm.genesisBlock, now(), requestFor(1, 100))
	vm.chain.Track(unchecked)

	child := blockOn(t, vm, unchecked, now(), requestFor(2, 100))
	require.ErrorContains(t, child.Verify(context.Background()), "not been verified here")
}

// TestAcceptOnlyExtendsTheTip. A block whose parent has been built past must
// not be committed on top of what did get accepted: the height index would
// then name it, and a bootstrapping peer would take the orphan for canonical.
func TestAcceptOnlyExtendsTheTip(t *testing.T) {
	vm := boot(t)
	pend(vm, requestFor(1, 100))
	one := buildAndAccept(t, vm)

	sibling := blockOn(t, vm, vm.genesisBlock, now(), requestFor(2, 100))
	require.ErrorContains(t, sibling.Accept(context.Background()), "not the tip")
	tip, _ := vm.chain.Tip()
	require.Equal(t, one.ID(), tip)
}

// Genesis is given, not verified. A second one is a peer handing this chain a
// new beginning.
func TestGenesisIsNotVerifiable(t *testing.T) {
	vm := boot(t)
	require.ErrorContains(t, vm.genesisBlock.Verify(context.Background()), "genesis")

	imposter := &Block{ParentID_: ids.Empty, BlockHeight: 0, BlockTimestamp: now(), vm: vm}
	imposter.ID_ = imposter.computeID()
	require.ErrorContains(t, imposter.Verify(context.Background()), "genesis")
}

// =============================================================================
// Chain time.
// =============================================================================

// TestChainTimeOnlyMovesForward. Chain time cuts the window the daily cap is
// measured over, so a proposer free to stamp a block before its parent could
// step back into a window it had already spent — and one free to stamp it far
// ahead could expire every window at once.
func TestChainTimeOnlyMovesForward(t *testing.T) {
	vm := boot(t)
	pend(vm, requestFor(1, 100))
	first := buildAndAccept(t, vm)

	rewound := blockOn(t, vm, first, first.BlockTimestamp-1, requestFor(2, 100))
	require.ErrorContains(t, rewound.Verify(context.Background()), "precedes parent")

	future := blockOn(t, vm, first, now()+maxClockSkew+30, requestFor(2, 100))
	require.ErrorIs(t, future.Verify(context.Background()), errFutureBlock)

	// The same time as the parent is fine — blocks are stamped in seconds.
	same := blockOn(t, vm, first, first.BlockTimestamp, requestFor(2, 100))
	require.NoError(t, same.Verify(context.Background()))
}

// A proposer whose own clock is behind its parent must not build a block its
// own Verify would refuse.
func TestABuiltBlockNeverPrecedesItsParent(t *testing.T) {
	vm := boot(t)
	pend(vm, requestFor(1, 100))
	first := blockOn(t, vm, vm.genesisBlock, now()+maxClockSkew/2, requestFor(1, 100))
	require.NoError(t, first.Verify(context.Background()))
	require.NoError(t, first.Accept(context.Background()))

	pend(vm, requestFor(2, 100))
	second := build(t, vm)
	require.GreaterOrEqual(t, second.BlockTimestamp, first.BlockTimestamp)
	require.NoError(t, second.Verify(context.Background()))
}

// =============================================================================
// The wire.
// =============================================================================

// TestABlockIsBoundedBeforeItIsParsed. Nothing bounded a peer's message, so an
// eight-megabyte "block" was decoded, hashed and verified before anything
// noticed it was not one.
func TestABlockIsBoundedBeforeItIsParsed(t *testing.T) {
	vm := boot(t)
	_, err := vm.ParseBlock(context.Background(), make([]byte, maxBlockBytes+1))
	require.ErrorContains(t, err, "over the")
}

func TestTooManyTransfersIsRefusedAtBothEnds(t *testing.T) {
	vm := boot(t)
	reqs := make([]*BridgeRequest, 0, maxRequestsPerBlock+1)
	for i := 0; i <= maxRequestsPerBlock; i++ {
		reqs = append(reqs, requestFor(uint64(i+1), 1))
	}
	blk := blockOn(t, vm, vm.genesisBlock, now(), reqs...)
	require.ErrorContains(t, blk.Verify(context.Background()), "over the")

	_, err := vm.ParseBlock(context.Background(), blk.Bytes())
	require.ErrorContains(t, err, "over the", "the wire must refuse it too")
}

func TestAnEmptyBlockIsRefused(t *testing.T) {
	vm := boot(t)
	require.ErrorContains(t,
		blockOn(t, vm, vm.genesisBlock, now()).Verify(context.Background()),
		"carries no transfers")
}

// TestTheEncodingIsCanonical. The block id is a hash of the block's contents,
// so an encoding with room for slack gives one block an unbounded number of
// distinct byte strings — and two nodes holding "the same" block hold
// different bytes.
func TestTheEncodingIsCanonical(t *testing.T) {
	vm := boot(t)
	blk := blockOn(t, vm, vm.genesisBlock, now(), requestFor(1, 100))
	raw := blk.Bytes()

	back, err := vm.ParseBlock(context.Background(), raw)
	require.NoError(t, err)
	require.Equal(t, blk.ID(), back.ID())
	require.Equal(t, raw, back.Bytes())

	// Bytes past the end.
	_, err = vm.ParseBlock(context.Background(), append(append([]byte(nil), raw...), 0))
	require.Error(t, err)

	// Padding inside a request's own declared length, which leaves the block's
	// id untouched and its bytes different.
	padded := paddedRequestBlock(t, vm, requestFor(1, 100))
	_, err = vm.ParseBlock(context.Background(), padded)
	require.ErrorContains(t, err, "canonical")

	// Truncation, and bytes that are not a message at all.
	_, err = vm.ParseBlock(context.Background(), raw[:len(raw)-1])
	require.Error(t, err)
	_, err = vm.ParseBlock(context.Background(), []byte{1, 2, 3})
	require.Error(t, err)
	_, err = vm.ParseBlock(context.Background(), nil)
	require.Error(t, err)
}

// paddedRequestBlock encodes a block whose one request carries two bytes of
// slack inside the length the block declares for it.
func paddedRequestBlock(t *testing.T, vm *VM, req *BridgeRequest) []byte {
	t.Helper()
	rb := append(marshalBridgeRequest(req), 0xAA, 0xBB)

	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(rb) + 128)
	lensOff := writeU32List(bld, []uint32{uint32(len(rb))})
	ob := bld.StartObject(blkSize)
	gid := vm.genesisBlock.ID()
	ob.SetBytesFixed(blkParent, gid[:])
	ob.SetUint64(blkHeight, 1)
	ob.SetInt64(blkTime, now())
	ob.SetList(blkReqLens, lensOff, 1)
	ob.SetBytes(blkReqBlob, rb)
	ob.FinishAsRoot()
	return bld.Finish()
}

// A request length that runs past the blob it is cut from is refused rather
// than read out of bounds.
func TestARequestLengthOutsideTheBlobIsRefused(t *testing.T) {
	vm := boot(t)
	bld := zap.NewBuilder(zap.HeaderSize + blkSize + 256)
	lensOff := writeU32List(bld, []uint32{4096})
	ob := bld.StartObject(blkSize)
	gid := vm.genesisBlock.ID()
	ob.SetBytesFixed(blkParent, gid[:])
	ob.SetUint64(blkHeight, 1)
	ob.SetInt64(blkTime, now())
	ob.SetList(blkReqLens, lensOff, 1)
	ob.SetBytes(blkReqBlob, []byte{1, 2, 3})
	ob.FinishAsRoot()

	_, err := vm.ParseBlock(context.Background(), bld.Finish())
	require.ErrorContains(t, err, "out of bounds")
}

// A request whose own bytes are not a message is refused, not read as zeroes.
func TestARequestThatIsNotAMessageIsRefused(t *testing.T) {
	vm := boot(t)
	junk := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	bld := zap.NewBuilder(zap.HeaderSize + blkSize + 256)
	lensOff := writeU32List(bld, []uint32{uint32(len(junk))})
	ob := bld.StartObject(blkSize)
	gid := vm.genesisBlock.ID()
	ob.SetBytesFixed(blkParent, gid[:])
	ob.SetUint64(blkHeight, 1)
	ob.SetInt64(blkTime, now())
	ob.SetList(blkReqLens, lensOff, 1)
	ob.SetBytes(blkReqBlob, junk)
	ob.FinishAsRoot()

	_, err := vm.ParseBlock(context.Background(), bld.Finish())
	require.Error(t, err)
}

// TestTheReceivePathVerifiesWhatTheBuildPathVerifies. A block handed in as
// wire bytes and the same block held as an object must get the same verdict,
// or a check runs only on what this node built itself.
func TestTheReceivePathVerifiesWhatTheBuildPathVerifies(t *testing.T) {
	vm := boot(t)
	renamed := requestFor(1, 500)
	renamed.ID = ids.GenerateTestID()

	inMemory := blockOn(t, vm, vm.genesisBlock, now(), renamed)
	fromWire, err := vm.ParseBlock(context.Background(), inMemory.Bytes())
	require.NoError(t, err)

	memErr := inMemory.Verify(context.Background())
	wireErr := fromWire.Verify(context.Background())
	require.Error(t, memErr)
	require.Error(t, wireErr)
	require.Equal(t, memErr.Error(), wireErr.Error(),
		"the same block must get the same verdict however it arrived")
}

// =============================================================================
// Which chain a block belongs to.
// =============================================================================

// TestABlockOfAnotherChainIsNotABlockOfThisOne. The id hashed the parent, the
// height, the time and the transfers — nothing that said which chain. Two
// chains running this VM from the same genesis therefore agreed on every block
// id, so a testnet block was a mainnet block, byte for byte.
func TestABlockOfAnotherChainIsNotABlockOfThisOne(t *testing.T) {
	here := boot(t)
	elsewhere := boot(t)
	elsewhere.chainID = ids.ID{'a', 'n', 'o', 't', 'h', 'e', 'r'}
	elsewhere.genesisBlock.ID_ = elsewhere.genesisBlock.computeID()
	_, _, err := elsewhere.chain.Open(elsewhere.genesisBlock, elsewhere.parseBlock)
	require.NoError(t, err)

	require.NotEqual(t, here.genesisBlock.ID(), elsewhere.genesisBlock.ID(),
		"two chains agree on their genesis id")

	pend(elsewhere, requestFor(1, 100))
	theirs := build(t, elsewhere)
	require.NoError(t, theirs.Verify(context.Background()))

	// The same bytes, offered to this chain.
	ours, err := here.ParseBlock(context.Background(), theirs.Bytes())
	require.NoError(t, err)
	require.NotEqual(t, theirs.ID(), ours.ID(), "one block, two chains, one id")
	require.ErrorContains(t, ours.Verify(context.Background()), "parent")
}

// =============================================================================
// Booting.
// =============================================================================

// TestAChainDoesNotRestartOverItself. Open reports a fresh database on ANY
// failure to read the tip, not only on its absence. Believing that on a live
// chain commits genesis over the tip and re-opens a daily cap that has already
// been spent — durably, with Initialize returning nil.
func TestAChainDoesNotRestartOverItself(t *testing.T) {
	db := memdb.New()
	vm := bootOn(t, db, testConfig())
	pend(vm, requestFor(1, 500))
	buildAndAccept(t, vm)

	// Whatever went wrong with the tip, the settlements are still there, and
	// they say this database is not a new chain.
	require.NoError(t, db.Delete([]byte("chain/tip")))

	err := (&VM{}).Initialize(context.Background(), initFor(db, testConfig()))
	require.ErrorContains(t, err, "refusing to restart the chain over it")
}

func TestAFreshDatabaseStartsAtGenesis(t *testing.T) {
	vm := boot(t)
	tip, height := vm.chain.Tip()
	require.Equal(t, vm.genesisBlock.ID(), tip)
	require.Zero(t, height)

	id, err := vm.LastAccepted(context.Background())
	require.NoError(t, err)
	require.Equal(t, vm.genesisBlock.ID(), id)

	got, err := vm.GetBlock(context.Background(), tip)
	require.NoError(t, err)
	require.Equal(t, tip, got.ID())
}

func now() int64 { return time.Now().Unix() }

func requestOf(bt bridgeattest.BridgeTransfer) *BridgeRequest {
	req := &BridgeRequest{
		ID:         ids.ID(bt.Digest()),
		SrcChainID: bt.SrcChainID,
		DstChainID: bt.DstChainID,
		Nonce:      bt.Nonce,
		Asset:      ids.ID(bt.Asset),
		Amount:     bt.Amount,
		Recipient:  append([]byte(nil), bt.Recipient[:]...),
	}
	return req
}
