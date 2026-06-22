// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// redb_consensus_test.go — Red-B consensus-safety regressions for the VM-level
// import seam (BuildBlock / Verify / Accept / Reject). These pin the fix for the
// CRITICAL finding "engine state committed before Accept": engine state + ledger
// value now stage in vm.qdb (versiondb) + a ledger snapshot and commit ONLY at
// Block.Accept; a rejected/discarded block rolls everything back.

import (
	"context"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/stretchr/testify/require"
)

// newAIVMForConsensus builds an initialized VM with an in-memory DB, accept-all
// commit verifier, and a funded ledger with `eligible` registered operators. The
// seed registrations are COMMITTED (vm.commitEngine) so they are durable and
// survive a later abortEngine — exactly like operators registered in prior
// accepted blocks on a live chain.
func newAIVMForConsensus(t *testing.T) (*VM, common.Address, []common.Address) {
	t.Helper()
	logger := log.NewNoOpLogger()
	rt := &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: logger}
	v := &VM{}
	require.NoError(t, v.Initialize(context.Background(), vmcore.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	}))
	v.SetCommitVerifier(acceptAll)

	e, st, _ := v.QuorumEngine()
	reqr := addr(0xF0)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	fund := new(uint256.Int).Mul(reward, uint256.NewInt(uint64(testN)))
	feeTotal := new(uint256.Int).Mul(RequestFeePerOperator, uint256.NewInt(uint64(testN)))
	fund.Add(fund, feeTotal)
	fund.Mul(fund, uint256.NewInt(8))

	opening := map[common.Address]*uint256.Int{reqr: fund}
	ops := make([]common.Address, eligible)
	for i := 0; i < eligible; i++ {
		ops[i] = addr(byte(0x10 + i))
		opening[ops[i]] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))
	}
	v.qledger = NewMemLedger(opening)
	for i, op := range ops {
		stake := new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2))
		require.NoError(t, e.RegisterOperator(st, v.qledger, op, stake, modelSpec, h(byte(0x80+i))))
	}
	// Commit the seed so registrations are durable (survive abortEngine).
	require.NoError(t, v.commitEngine())
	return v, reqr, ops
}

// REGRESSION (CRITICAL fix) — a REJECTED block rolls back all engine state and
// ledger value it staged: funds restored, intent NOT consumed (re-importable),
// no orphan task. Before the fix, importPending wrote straight to the durable DB
// and Reject discarded nothing.
func TestRegression_RejectedBlockRollsBackEngineState(t *testing.T) {
	require := require.New(t)
	v, reqr, _ := newAIVMForConsensus(t)
	e, st, lg := v.QuorumEngine()

	reward := uint256.NewInt(1_000_000_000_000_000_000)
	intent := mkIntent(e, reqr, testN, testThr, uint256.NewInt(1), reward)

	balBefore := lg.GetBalance(reqr)
	escBefore := lg.GetBalance(EscrowAccount)

	v.EnqueueCommittedIntent(intent)
	blk, err := v.BuildBlock(context.Background())
	require.NoError(err)
	b := blk.(*Block)
	require.Len(b.ImportedIntents, 1, "intent staged during BuildBlock")

	// Lose the round: reject.
	require.NoError(b.Reject(context.Background()))

	// Everything rolled back.
	require.Equal(balBefore.String(), lg.GetBalance(reqr).String(),
		"requester funds restored after reject")
	require.Equal(escBefore.String(), lg.GetBalance(EscrowAccount).String(),
		"escrow restored after reject")
	require.False(isSet(st.GetState(slotHash(nsIntentSeen, intent.IntentID))),
		"intent NOT consumed by a rejected block (re-importable)")

	// The intent can be re-imported into a fresh block and this time accepted.
	v.EnqueueCommittedIntent(intent)
	blk2, err := v.BuildBlock(context.Background())
	require.NoError(err)
	require.Len(blk2.(*Block).ImportedIntents, 1,
		"intent survives a rejected block and imports cleanly afterward")
	require.NoError(blk2.(*Block).Accept(context.Background()))
	// Now (and only now) is it durably consumed.
	require.True(isSet(st.GetState(slotHash(nsIntentSeen, intent.IntentID))),
		"intent consumed only after the importing block is ACCEPTED")
}

// REGRESSION (CRITICAL fix) — an ACCEPTED block durably commits the import:
// funds moved, intent consumed, task created, and the side effects persist.
func TestRegression_AcceptedBlockCommitsEngineState(t *testing.T) {
	require := require.New(t)
	v, reqr, _ := newAIVMForConsensus(t)
	e, st, lg := v.QuorumEngine()

	reward := uint256.NewInt(1_000_000_000_000_000_000)
	intent := mkIntent(e, reqr, testN, testThr, uint256.NewInt(1), reward)
	balBefore := lg.GetBalance(reqr)

	v.EnqueueCommittedIntent(intent)
	blk, err := v.BuildBlock(context.Background())
	require.NoError(err)
	b := blk.(*Block)
	require.NoError(b.Accept(context.Background()))

	require.True(lg.GetBalance(reqr).Lt(balBefore), "requester funds moved on accept")
	require.True(isSet(st.GetState(slotHash(nsIntentSeen, intent.IntentID))), "intent consumed on accept")
	taskID := st.GetState(slotHash(nsIntentTask, intent.IntentID))
	require.NotEqual(common.Hash{}, taskID, "task created on accept")
	require.Equal(TaskCommitting, e.GetTask(st, taskID).Status)
}

// REGRESSION — the default (no SetCommitVerifier) verifier is fail-closed: it
// admits NO buffered intent, so no task is created from the boundary.
func TestRegression_DefaultVerifierFailClosed(t *testing.T) {
	require := require.New(t)
	logger := log.NewNoOpLogger()
	rt := &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: logger}
	v := &VM{}
	require.NoError(v.Initialize(context.Background(), vmcore.Init{
		Runtime: rt, DB: memdb.New(), ToEngine: make(chan vmcore.Message, 8),
		Log: logger, Genesis: []byte(`{"timestamp":0,"version":1,"message":""}`),
	}))
	e, _, _ := v.QuorumEngine()
	reqr := addr(0xF0)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	fund := new(uint256.Int).Mul(reward, uint256.NewInt(uint64(testN*100)))
	opening := map[common.Address]*uint256.Int{reqr: fund}
	for i := 0; i < eligible; i++ {
		opening[addr(byte(0x10+i))] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))
	}
	v.qledger = NewMemLedger(opening)
	for i := 0; i < eligible; i++ {
		require.NoError(e.RegisterOperator(v.qstate, v.qledger, addr(byte(0x10+i)),
			new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2)), modelSpec, h(byte(0x80+i))))
	}
	require.NoError(v.commitEngine())
	intent := mkIntent(e, reqr, testN, testThr, uint256.NewInt(1), reward)
	v.EnqueueCommittedIntent(intent)
	blk, err := v.BuildBlock(context.Background())
	require.NoError(err)
	require.Len(blk.(*Block).ImportedIntents, 0, "default fail-closed verifier admits NO intent")
}
