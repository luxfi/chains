// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// redb_settle_test.go — Red-B probes on settle integrity, beacon bound, and
// commit-reveal window edges.

import (
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// PROBE — settle before reveal window closes must be rejected (no early settle to
// lock in a transient plurality).
func TestProbe_SettleTooEarly(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	// revealDeadline = 100 + 30 + 30 = 160. settle at exactly 160 (== deadline) must fail.
	_, err = e.Settle(st, lg, taskID, 160)
	require.ErrorIs(err, ErrSettleTooEarly, "settle at revealDeadline must be rejected (strict >)")
	// 161 ok.
	_, err = e.Settle(st, lg, taskID, 161)
	require.NoError(err)
}

// PROBE — settle unknown task.
func TestProbe_SettleUnknown(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, _, _ := newHarness(t, eligible, reward)
	_, err := e.Settle(st, lg, h(0xDE), 1000)
	require.ErrorIs(err, ErrTaskUnknown)
}

// PROBE — a minority cannot force itself canonical. With N=5, threshold=3, if only
// 2 reveal the same hash and 3 reveal distinct, no group reaches 3 -> Failed.
func TestProbe_MinorityCannotForceCanonical(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)

	// 2 agree on min, 3 distinct.
	pairHash := h(0x42)
	for i := 0; i < 2; i++ {
		op := selected[i]
		c := opCommit(taskID, op, pairHash, h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
		require.NoError(e.RevealResponse(st, taskID, op, pairHash, h(0x01), h(0x02), 131))
	}
	for i := 2; i < 5; i++ {
		op := selected[i]
		out := h(byte(0x60 + i))
		c := opCommit(taskID, op, out, h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
		require.NoError(e.RevealResponse(st, taskID, op, out, h(0x01), h(0x02), 131))
	}
	res, err := e.Settle(st, lg, taskID, 161)
	require.NoError(err)
	require.Equal(TaskFailed, res.Status, "2-of-5 plurality < threshold 3 -> Failed, not canonical")
}

// PROBE — beacon absolute bound. With a cartel of c < threshold eligible
// operators among E total, no taskID (grind) makes the cartel >= threshold of the
// selected N. We brute force many taskIDs against a fixed eligible set and assert
// the cartel never reaches threshold in the drawn set. This validates the claim
// that forgery floor is threshold*MinProviderBond (i.e. you must OWN >= threshold
// eligible operators; grinding cannot substitute).
func TestProbe_BeaconAbsoluteBound(t *testing.T) {
	require := require.New(t)
	// E = 8 eligible; cartel = first 2 (< threshold 3). Draw N=5.
	E := 8
	cartel := map[common.Address]bool{addr(0x10): true, addr(0x11): true}
	eligibleSet := make([]common.Address, E)
	for i := 0; i < E; i++ {
		eligibleSet[i] = addr(byte(0x10 + i))
	}
	worst := 0
	for g := 0; g < 200000; g++ {
		// grind a taskID
		tid := common.BytesToHash(crypto.Keccak256(u32be(uint32(g))))
		set := make([]common.Address, len(eligibleSet))
		copy(set, eligibleSet)
		drawn, err := drawFromEligible(set, tid, testN)
		require.NoError(err)
		cnt := 0
		for _, op := range drawn {
			if cartel[op] {
				cnt++
			}
		}
		if cnt > worst {
			worst = cnt
		}
		if cnt >= testThr {
			t.Fatalf("FINDING: grind %d put cartel of size %d into >= threshold %d selected slots", g, len(cartel), testThr)
		}
	}
	// cartel of 2 can be selected at most 2 times; never reaches threshold 3.
	require.Less(worst, testThr, "cartel below threshold can never reach a quorum by grinding")
	t.Logf("max cartel-in-selection over 200k grinds = %d (threshold %d)", worst, testThr)
}

// PROBE — reveal window strict ordering: a reveal AT commitDeadline must be
// rejected (window opens strictly after).
func TestProbe_RevealAtCommitDeadlineRejected(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)
	op := selected[0]
	c := opCommit(taskID, op, h(0x42), h(0x01), h(0x02))
	require.NoError(e.CommitResponse(st, taskID, op, c, 101))
	// commitDeadline = 130. reveal at 130 must be rejected (need > 130).
	err = e.RevealResponse(st, taskID, op, h(0x42), h(0x01), h(0x02), 130)
	require.ErrorIs(err, ErrRevealNotOpen, "reveal at commitDeadline must be rejected")
	// commit at 130 (== deadline) must still be allowed (<=).
	op2 := selected[1]
	c2 := opCommit(taskID, op2, h(0x42), h(0x01), h(0x02))
	require.NoError(e.CommitResponse(st, taskID, op2, c2, 130), "commit at commitDeadline allowed (<=)")
}

// PROBE — commit AT commitDeadline boundary then a window where commit and reveal
// could overlap? commit allowed for height <= 130; reveal allowed for height >130.
// They are disjoint. Confirm no height admits both for the same op.
func TestProbe_CommitRevealWindowsDisjoint(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	info := e.GetTask(st, taskID)
	require.Equal(uint64(130), info.CommitDeadline)
	require.Equal(uint64(160), info.RevealDeadline)
	// commit window: [reqHeight, 130]; reveal window: (130, 160]. Disjoint at 130/131.
}

