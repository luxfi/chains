// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// conscious_refusal_test.go: the driver reports where it stopped.
//
// RunConsciousBlocks walks the whole lifecycle — fund, register, import, commit,
// reveal, settle, accept — and each step's failure has to arrive as a message
// naming that step. A driver that returned a zero trace and no error would look
// exactly like one that produced two conscious blocks.

import (
	"context"
	"errors"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func TestTheDriverNamesTheStepItStoppedAt(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// No engine at all.
	_, err := RunConsciousBlocks(ctx, &VM{})
	require.ErrorContains(err, "quorum engine not wired")

	// An engine but no chain under it.
	headless := oneVM(t)
	headless.lastAccepted = nil
	_, err = RunConsciousBlocks(ctx, headless)
	require.ErrorContains(err, "read genesis head")

	// A ledger that cannot be seeded.
	db := &breakable{Database: memdb.New()}
	broken := newVM(t, ids.GenerateTestID(), db)
	db.broken.Store(true)
	_, err = RunConsciousBlocks(ctx, broken)
	require.ErrorContains(err, "fund ledger")
	db.broken.Store(false)

	// An operator the driver expects to register is already registered.
	taken := oneVM(t)
	require.NoError(taken.FundLedger(map[common.Address]*uint256.Int{
		addrOf(0x10): new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3)),
	}))
	require.NoError(taken.quorum.RegisterOperator(taken.qstate, taken.qledger, addrOf(0x10),
		MinProviderBond, hashOf(0xAB), hashOf(0x80)))
	_, err = RunConsciousBlocks(ctx, taken)
	require.ErrorContains(err, "register operator 0")

	// The boundary will not vouch for the intent, so the perception block
	// carries nothing and there is no task to think about.
	closed := oneVM(t)
	closed.SetCommitVerifier(VerifierFunc(func(CIntent) error { return ErrIntentNotCommitted }))
	_, err = RunConsciousBlocks(ctx, closed)
	require.ErrorContains(err, "created no task")

	// And a stopped VM cannot propose at all.
	stopped := oneVM(t)
	require.NoError(stopped.Shutdown(ctx))
	_, err = acceptBlock(ctx, stopped)
	require.ErrorContains(err, "build")
}

// Seeding is the one write outside consensus, and it is durable at once or it
// does not happen: left staged, a genesis allocation would ride out on whichever
// block committed first.
func TestSeedingIsAllOrNothing(t *testing.T) {
	require := require.New(t)

	vm := oneVM(t)
	sentinel := hashOf(0x5E)
	require.ErrorIs(vm.Seed(func(st QuorumState, _ QuorumLedger) error {
		st.SetState(sentinel, oneHash())
		return errProbeStop
	}), errProbeStop)
	require.False(isSet(vm.qstate.GetState(sentinel)), "a failed seed left its write behind")

	db := &breakable{Database: memdb.New()}
	unwritable := newVM(t, ids.GenerateTestID(), db)
	db.broken.Store(true)
	require.ErrorIs(unwritable.Seed(func(st QuorumState, _ QuorumLedger) error {
		st.SetState(sentinel, oneHash())
		return nil
	}), errBroken)
	db.broken.Store(false)
	require.False(isSet(unwritable.qstate.GetState(sentinel)))

	// Funding is fail-closed at the ceiling, with no partial seeding.
	max := new(uint256.Int).Not(uint256.NewInt(0))
	require.NoError(vm.FundLedger(map[common.Address]*uint256.Int{addrOf(1): max}))
	require.ErrorIs(vm.FundLedger(map[common.Address]*uint256.Int{addrOf(1): uint256.NewInt(1)}),
		ErrCreditOverflow)
	require.Equal(max.String(), vm.qledger.GetBalance(addrOf(1)).String())
}

// A block carries some of what is buffered; the rest stays buffered. Dropping
// the whole buffer when a block landed would lose the work it did not carry.
func TestOnlyWhatABlockCarriedStopsBeingBuffered(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	seedOperators(t, vm, oneReward())
	carried := buildIntent(vm.quorum, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), oneReward())
	// A second intent naming a model nobody advertises: buffered, never carried.
	orphan := intentFor(vm.quorum, addrOf(0xF0), hashOf(0xDD), hashOf(0xCD), consciousN, consciousThreshold, uint256.NewInt(2), oneReward())
	vm.EnqueueCommittedIntent(carried)
	vm.EnqueueCommittedIntent(orphan)

	blk := build(t, vm)
	require.Len(blk.ImportedIntents, 1)
	require.NoError(blk.Verify(ctx))
	require.NoError(blk.Accept(ctx))

	require.Len(vm.pendingIntents, 1, "an intent no block carried was dropped anyway")
	require.Equal(orphan.IntentID, vm.pendingIntents[0].IntentID)
}

var errProbeStop = errors.New("test: stop here")
