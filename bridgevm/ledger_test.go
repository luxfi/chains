// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
)

// What the bridge cannot read, it does not guess. A spend counter or a
// settlement record that cannot be answered means the chain does not know what
// it has already moved, and the only safe answer to "may I move more" is no.

// unreadableDB answers a chosen prefix with an error and everything else
// normally — a corrupted or half-readable store, which is where a fail-open
// read costs the most.
type unreadableDB struct {
	database.Database
	prefix []byte
	err    error
}

func (d *unreadableDB) match(key []byte) bool {
	return d.err != nil && len(key) >= len(d.prefix) && string(key[:len(d.prefix)]) == string(d.prefix)
}

func (d *unreadableDB) Get(key []byte) ([]byte, error) {
	if d.match(key) {
		return nil, d.err
	}
	return d.Database.Get(key)
}

func (d *unreadableDB) Has(key []byte) (bool, error) {
	if d.match(key) {
		return false, d.err
	}
	return d.Database.Has(key)
}

var errUnreadable = errors.New("store unreadable")

func TestASpendItCannotReadIsNotZero(t *testing.T) {
	broken := &unreadableDB{Database: memdb.New(), prefix: movedPrefix, err: errUnreadable}
	s := newSpend(broken)

	_, err := s.movedOn(1, dstChain)
	require.ErrorIs(t, err, errUnreadable)

	// And the rule that reads it refuses rather than admitting on a total it
	// could not obtain.
	cfg := testConfig()
	require.ErrorIs(t, s.admit(&cfg, 1, requestFor(1, 100)), errUnreadable)
}

func TestASettlementItCannotReadIsNotAbsent(t *testing.T) {
	broken := &unreadableDB{Database: memdb.New(), prefix: settledPrefix, err: errUnreadable}
	s := newSpend(broken)

	_, err := s.isSettled(ids.GenerateTestID())
	require.ErrorIs(t, err, errUnreadable)

	cfg := testConfig()
	require.ErrorIs(t, s.admit(&cfg, 1, requestFor(1, 100)), errUnreadable)
}

// A counter of the wrong width is not a number this chain wrote, and reading
// its first eight bytes anyway would put the cap wherever the corruption says.
func TestACounterOfTheWrongWidthIsRefused(t *testing.T) {
	db := memdb.New()
	require.NoError(t, db.Put(movedKey(1, dstChain), []byte{1, 2, 3}))

	_, err := newSpend(db).movedOn(1, dstChain)
	require.ErrorContains(t, err, "want 8")

	_, err = readCounter(nil)
	require.ErrorContains(t, err, "want 8")
	v, err := readCounter(counterBytes(1 << 40))
	require.NoError(t, err)
	require.Equal(t, uint64(1<<40), v)
}

// A block that cannot stage what it decided does not commit: Accept rolls the
// whole thing back rather than recording the block without its spend.
func TestABlockThatCannotStageItsSpendDoesNotCommit(t *testing.T) {
	vm := boot(t)
	blk := blockOn(t, vm, vm.genesisBlock, now(), requestFor(1, 100))
	require.NoError(t, blk.Verify(context.Background()))

	broken := &unreadableDB{Database: memdb.New(), prefix: movedPrefix, err: errUnreadable}
	require.ErrorIs(t, blk.write(broken), errUnreadable)

	// A corrupt counter stops it in the same place.
	corrupt := memdb.New()
	require.NoError(t, corrupt.Put(movedKey(blk.BlockTimestamp/dayLength, dstChain), []byte{9}))
	require.ErrorContains(t, blk.write(corrupt), "want 8")
}

// TestOneWindowPerDayPerDestination pins the key: the day the block falls in
// and the numeric destination the transfer names. A label would split one
// route's counter in two the moment two nodes spelled it differently.
func TestOneWindowPerDayPerDestination(t *testing.T) {
	require.Equal(t, movedKey(7, dstChain), movedKey(7, dstChain))
	require.NotEqual(t, movedKey(7, dstChain), movedKey(8, dstChain))
	require.NotEqual(t, movedKey(7, dstChain), movedKey(7, srcChain))
	require.True(t, len(movedKey(7, dstChain)) == len(movedPrefix)+12)

	id := ids.GenerateTestID()
	require.Equal(t, settledKey(id), settledKey(id))
	require.NotEqual(t, settledKey(id), settledKey(ids.GenerateTestID()))
}

// The spend a child starts from is a copy, so a sibling asking the same
// question is not answered with what the child decided.
func TestAChildsSpendIsItsOwn(t *testing.T) {
	db := memdb.New()
	parent := newSpend(db)
	req := requestFor(1, 100)
	cfg := testConfig()
	require.NoError(t, parent.admit(&cfg, 1, req))

	child := parent.clone()
	require.NoError(t, child.admit(&cfg, 1, requestFor(2, 100)))

	settled, err := parent.isSettled(requestFor(2, 100).ID)
	require.NoError(t, err)
	require.False(t, settled, "the child's decision reached back into its parent")

	settled, err = child.isSettled(req.ID)
	require.NoError(t, err)
	require.True(t, settled, "the child did not inherit what its parent settled")
}

// A total near the top of the range does not wrap past the cap.
func TestTheCapDoesNotWrap(t *testing.T) {
	db := memdb.New()
	cfg := testConfig()
	cfg.MaxBridgeAmount = ^uint64(0)
	cfg.DailyBridgeLimit = 1000
	require.NoError(t, db.Put(movedKey(1, dstChain), counterBytes(999)))

	err := newSpend(db).admit(&cfg, 1, requestFor(1, ^uint64(0)))
	require.ErrorContains(t, err, "daily cap")
}
