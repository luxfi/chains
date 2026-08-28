// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// commit_test.go — the block-lifecycle proofs: what a block commits, when it
// commits it, where it may sit in the chain, and what a proposer puts in one.
package schain

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/zapdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/metric"

	"github.com/luxfi/chains/schain/txs"
)

// manifestTx is a well-formed PutManifest mutation.
func manifestTx(bucket, object string) []byte {
	return txs.NewPutManifestTx(bucket, object, []string{"1,2a,3"}, 7, "e").Bytes()
}

// seal drives one submitted transaction through Build -> Verify -> Accept the
// way the engine does.
func seal(t *testing.T, cvm *ChainVM, txBytes []byte) *Block {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, cvm.SubmitTx(txBytes))
	blk, err := cvm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))
	return blk.(*Block)
}

// TestAcceptCommitsItsOwnWrites is the regression test for a block committing
// whatever happened to be staged. Every apply starts by dropping the version
// layer, so the layer belongs to whichever block was processed LAST — verify a
// sibling between a block's Verify and its Accept and the commit carried the
// sibling's writes under this block's id. Accept re-applies its own
// transactions from committed state, so what it commits is what it contains.
func TestAcceptCommitsItsOwnWrites(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	// Two competing blocks at height 1, each carrying a different manifest.
	mine := carry(t, cvm, manifestTx("b", "mine"))
	sibling := carry(t, cvm, manifestTx("b", "sibling"))

	require.NoError(t, mine.Verify(ctx))
	// The engine verifies the sibling before deciding — which drops my staging
	// and replaces it with the sibling's.
	require.NoError(t, sibling.Verify(ctx))

	require.NoError(t, mine.Accept(ctx))

	_, found, err := cvm.inner.GetManifest("b", "mine")
	require.NoError(t, err)
	require.True(t, found, "the accepted block must commit its OWN manifest")

	_, found, err = cvm.inner.GetManifest("b", "sibling")
	require.NoError(t, err)
	require.False(t, found, "a block that was never accepted must commit nothing")
}

// brokenBatchDB refuses the batch write a commit performs, so a commit can be
// made to fail without the apply failing.
type brokenBatchDB struct {
	database.Database
	mu     sync.Mutex
	broken bool
}

func (d *brokenBatchDB) breakCommit() {
	d.mu.Lock()
	d.broken = true
	d.mu.Unlock()
}

func (d *brokenBatchDB) failing() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.broken
}

var errStoreDown = errors.New("store is down")

func (d *brokenBatchDB) NewBatch() database.Batch {
	return &brokenBatch{Batch: d.Database.NewBatch(), db: d}
}

type brokenBatch struct {
	database.Batch
	db *brokenBatchDB
}

func (b *brokenBatch) Write() error {
	if b.db.failing() {
		return errStoreDown
	}
	return b.Batch.Write()
}

// newVMOn builds an initialized ChainVM over a caller-supplied database.
func newVMOn(t *testing.T, db database.Database) *ChainVM {
	t.Helper()
	cvm := NewChainVM(logNoop())
	require.NoError(t, cvm.Initialize(context.Background(), initFor(db)))
	return cvm
}

// TestFailedCommitDoesNotAdvanceTheChain proves the tip follows the commit
// rather than leading it. A chain whose last-accepted pointer moved ahead of a
// write that never landed serves reads out of state that does not exist.
func TestFailedCommitDoesNotAdvanceTheChain(t *testing.T) {
	ctx := context.Background()
	raw, err := zapdb.New(t.TempDir(), nil, "schain-commit-test", metric.NewRegistry())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })

	db := &brokenBatchDB{Database: raw}
	cvm := newVMOn(t, db)

	require.NoError(t, cvm.SubmitTx(manifestTx("b", "durable")))
	blk, err := cvm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, blk.Verify(ctx))

	tipBefore, err := cvm.LastAccepted(ctx)
	require.NoError(t, err)

	db.breakCommit()
	require.ErrorIs(t, blk.Accept(ctx), errStoreDown)

	tipAfter, err := cvm.LastAccepted(ctx)
	require.NoError(t, err)
	require.Equal(t, tipBefore, tipAfter, "an uncommitted block must not become the tip")
	require.Equal(t, uint8(StatusProcessing), blk.Status(), "an uncommitted block is not accepted")
	_, err = cvm.GetBlockIDAtHeight(ctx, 1)
	require.ErrorIs(t, err, errBlockNotFound, "an uncommitted block must not be indexed")
}

// TestBlockPositionIsChecked proves a block must sit in the chain before its
// contents are applied. None of this was checked: a block could name any parent,
// claim any height and carry any timestamp — and the height it claimed became
// the chain's height and part of every state root computed after it.
func TestBlockPositionIsChecked(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)
	seal(t, cvm, manifestTx("b", "first"))

	cvm.lock.RLock()
	tip, tipHeight := cvm.lastAcceptedID, cvm.lastAcceptedHeight
	tipTime := cvm.blocks[tip].timestamp
	cvm.lock.RUnlock()

	at := func(parent ids.ID, height uint64, ts time.Time) *Block {
		b := &Block{vm: cvm, parentID: parent, height: height, timestamp: ts,
			txs: [][]byte{manifestTx("b", "positioned")}, status: StatusProcessing}
		return b
	}

	require.ErrorIs(t, at(ids.GenerateTestID(), tipHeight+1, tipTime).Verify(ctx), errBlockNotFound)
	require.ErrorIs(t, at(tip, tipHeight, tipTime).Verify(ctx), errBadHeight)
	require.ErrorIs(t, at(tip, tipHeight+9, tipTime).Verify(ctx), errBadHeight)
	require.ErrorIs(t, at(tip, tipHeight+1, tipTime.Add(-time.Second)).Verify(ctx), errTimeRewound)
	require.ErrorIs(t, at(tip, tipHeight+1, time.Now().Add(time.Hour)).Verify(ctx), errTimeAhead)

	// Nothing above was applied: the refused blocks touched no state.
	_, found, err := cvm.inner.GetManifest("b", "positioned")
	require.NoError(t, err)
	require.False(t, found)

	// The honest position is accepted, which is what makes the refusals above
	// about position and not about the manifest.
	honest := carry(t, cvm, manifestTx("b", "positioned"))
	require.NoError(t, honest.Verify(ctx))
	require.NoError(t, honest.Accept(ctx))
	_, found, err = cvm.inner.GetManifest("b", "positioned")
	require.NoError(t, err)
	require.True(t, found)
}

// TestSkewCeilingFloorsAtTheParent proves a node whose clock has slipped behind
// the tip still accepts a block stamped at the parent's own time — otherwise it
// refuses every block including the ones it builds, and can never catch up.
func TestSkewCeilingFloorsAtTheParent(t *testing.T) {
	cvm, _ := newTestVM(t)

	// The chain's tip is stamped an hour ahead of this node's clock.
	future := time.Now().Add(time.Hour)
	cvm.inner.clock.Set(future)
	seal(t, cvm, manifestTx("b", "ahead"))

	cvm.inner.clock.Set(time.Now()) // the node's clock is now an hour behind the tip

	cvm.lock.RLock()
	tip, height := cvm.lastAcceptedID, cvm.lastAcceptedHeight
	parentTime := cvm.blocks[tip].timestamp
	cvm.lock.RUnlock()

	atParentTime := &Block{vm: cvm, parentID: tip, height: height + 1, timestamp: parentTime,
		txs: [][]byte{manifestTx("b", "catchup")}, status: StatusProcessing}
	require.NoError(t, cvm.checkPosition(atParentTime),
		"a time the chain already accepted must stay legal")

	beyond := &Block{vm: cvm, parentID: tip, height: height + 1,
		timestamp: parentTime.Add(maxFutureSkew + time.Second), status: StatusProcessing}
	require.ErrorIs(t, cvm.checkPosition(beyond), errTimeAhead,
		"the floor is the parent's time, not a licence to run further ahead")
}

// TestAcceptReleasesAbandonedBlocks proves the block index is bounded. The
// engine issues a block per build and abandons the losers of a poll without ever
// rejecting them; a block only ever released on accept or reject accumulates
// without limit.
func TestAcceptReleasesAbandonedBlocks(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	var abandoned []ids.ID
	for i := 0; i < 3; i++ {
		blk := carry(t, cvm, manifestTx("b", string(rune('a'+i))))
		abandoned = append(abandoned, blk.id)
	}
	winner := carry(t, cvm, manifestTx("b", "winner"))
	require.NoError(t, winner.Verify(ctx))
	require.NoError(t, winner.Accept(ctx))

	cvm.lock.RLock()
	defer cvm.lock.RUnlock()
	for _, id := range abandoned {
		require.NotContains(t, cvm.blocks, id,
			"a block abandoned at or below the accepted height must be released")
	}
	require.Contains(t, cvm.blocks, winner.id, "the accepted chain is retained")
	require.Contains(t, cvm.blocks, genesisBlockID)
}

// TestRejectReleasesTheBlock proves a rejected block is dropped from the index
// and its staged writes with it.
func TestRejectReleasesTheBlock(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	blk := carry(t, cvm, manifestTx("rb", "ro"))
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Reject(ctx))

	require.Equal(t, uint8(StatusRejected), blk.Status())
	cvm.lock.RLock()
	_, held := cvm.blocks[blk.id]
	cvm.lock.RUnlock()
	require.False(t, held, "a rejected block must not be retained")

	_, found, err := cvm.inner.GetManifest("rb", "ro")
	require.NoError(t, err)
	require.False(t, found, "a rejected block's staged writes must be dropped")
}

// TestHeightIndexNamesTheAcceptedBlock proves the height lookup reads an index
// written when a block was accepted, rather than scanning the block map and
// returning whichever matching entry map iteration reached first — which for two
// blocks at one height is a different answer on different runs.
func TestHeightIndexNamesTheAcceptedBlock(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	genesis, err := cvm.GetBlockIDAtHeight(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, genesisBlockID, genesis)

	loser := carry(t, cvm, manifestTx("b", "loser"))
	require.NoError(t, loser.Verify(ctx))

	_, err = cvm.GetBlockIDAtHeight(ctx, 1)
	require.ErrorIs(t, err, errBlockNotFound, "a verified-but-unaccepted block is not indexed")

	winner := carry(t, cvm, manifestTx("b", "winner"))
	require.NoError(t, winner.Verify(ctx))
	require.NoError(t, winner.Accept(ctx))

	for i := 0; i < 20; i++ {
		got, err := cvm.GetBlockIDAtHeight(ctx, 1)
		require.NoError(t, err)
		require.Equal(t, winner.id, got, "the height index must name the ACCEPTED block, every time")
	}
	_, err = cvm.GetBlockIDAtHeight(ctx, 99)
	require.ErrorIs(t, err, errBlockNotFound)
}

// TestBlockIndexIsUnderTheLock is the race regression. Accept used to write the
// block index, the last-accepted pointer and the block's status with no lock
// held, while GetBlock, ParseBlock and BuildBlock read and wrote the same map
// under cvm.lock — which the Go runtime answers with a fatal throw, not an
// error. Run under -race this fails on the old code.
func TestBlockIndexIsUnderTheLock(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	const rounds = 300
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			blk := carry(t, cvm, manifestTx("b", "raced"))
			if err := blk.Verify(ctx); err == nil {
				_ = blk.Accept(ctx)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			_, _ = cvm.GetBlock(ctx, genesisBlockID)
			_, _ = cvm.LastAccepted(ctx)
			_, _ = cvm.GetBlockIDAtHeight(ctx, 0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			_, _ = cvm.ParseBlock(ctx, []byte("too short"))
			_ = cvm.SetPreference(ctx, genesisBlockID)
		}
	}()
	wg.Wait()
}

// TestBlocksAreFoundByID proves the block index answers for what it holds and
// refuses what it does not.
func TestBlocksAreFoundByID(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	blk := seal(t, cvm, manifestTx("b", "found"))
	got, err := cvm.GetBlock(ctx, blk.id)
	require.NoError(t, err)
	require.Equal(t, blk.id, got.ID())
	require.Equal(t, blk.parentID, got.(*Block).Parent())
	require.Equal(t, blk.parentID, got.(*Block).ParentID())
	require.Equal(t, blk.timestamp.UnixNano(), got.(*Block).Timestamp().UnixNano())
	require.Equal(t, uint8(StatusAccepted), got.(*Block).Status())

	_, err = cvm.GetBlock(ctx, ids.GenerateTestID())
	require.ErrorIs(t, err, errBlockNotFound)

	require.ErrorContains(t, cvm.SetPreference(ctx, ids.GenerateTestID()), "block not found")
	require.NoError(t, cvm.SetPreference(ctx, blk.id))
}
