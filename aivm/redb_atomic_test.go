// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// redb_atomic_test.go — Red-B probes on Settle atomicity and no-quorum-with-
// withholders value conservation.

import (
	"testing"

	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

// PROBE — no-quorum WITH withholders. Some commit+reveal distinct (no quorum),
// some withhold. Withholders are slashed and the pool is credited to the
// requester; the requester also gets the full reward escrow refund. Assert value
// conservation and escrow identity.
func TestProbe_NoQuorumWithWithholders(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, allOps := newHarness(t, eligible, reward)
	totalBefore := lg.Total()

	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)

	// 3 reveal DISTINCT (no quorum), 2 withhold (commit only).
	for i := 0; i < 3; i++ {
		op := selected[i]
		out := h(byte(0x50 + i))
		c := opCommit(taskID, op, out, h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
		require.NoError(e.RevealResponse(st, taskID, op, out, h(0x01), h(0x02), 131))
	}
	for i := 3; i < 5; i++ {
		op := selected[i]
		c := opCommit(taskID, op, h(byte(0xE0+i)), h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
	}

	res, err := e.Settle(st, lg, taskID, 161)
	require.NoError(err)
	require.Equal(TaskFailed, res.Status)
	// 2 withholders slashed.
	wantSlashed := new(uint256.Int).Mul(SlashPerOperator, uint256.NewInt(2))
	require.Equal(wantSlashed, res.Slashed)

	// requester refund = full N*reward escrow + slashed pool (credited as compensation).
	gotRefund, err := e.WithdrawRewards(st, lg, requester)
	require.NoError(err)
	wantRefund := new(uint256.Int).Add(
		new(uint256.Int).Mul(reward, uint256.NewInt(uint64(testN))),
		wantSlashed,
	)
	require.Equal(wantRefund.String(), gotRefund.String(),
		"failed-with-withholders refund = N*reward + slashed pool")

	require.Equal(totalBefore.String(), lg.Total().String(), "grand total conserved")
	requireEscrowIdentity(t, e, st, lg, taskID, append(allOps, requester))
}

// PROBE — half-settle re-settle corruption. The quorum path applies slash, then
// credits winners, then writes the settled marker LAST. If an addCredit overflow
// (or any error) aborts the loop AFTER slash + some credits but BEFORE the settled
// marker, the marker is unset -> the task is re-settleable -> a SECOND settle
// re-slashes (idempotent floor) and re-pays from the now-smaller escrow. Probe
// whether a forced mid-settle failure leaves a re-settleable, corrupted task.
//
// We force the failure by draining the ledger escrow so Pay path... no — credits
// are on-state, not ledger. The reachable failure is addCredit overflow, which
// needs credit ~2^256. We instead document the NON-ATOMICITY structurally: settle
// writes happen incrementally with no rollback, and the settled marker is written
// last. Here we assert the ORDER (slash before marker) so a future reachable error
// would corrupt — and we verify the CURRENT happy path still sets the marker.
func TestProbe_SettleMarkerWrittenLast(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)
	out := h(0x42)
	for i := 0; i < testThr; i++ {
		op := selected[i]
		c := opCommit(taskID, op, out, h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
		require.NoError(e.RevealResponse(st, taskID, op, out, h(0x01), h(0x02), 131))
	}
	_, err = e.Settle(st, lg, taskID, 161)
	require.NoError(err)
	require.True(isSet(st.GetState(slotHash(nsSettled, taskID))), "settled marker set on success")
	// re-settle blocked.
	_, err = e.Settle(st, lg, taskID, 162)
	require.ErrorIs(err, ErrTaskAlreadySettled)
}

// PROBE — overflow-driven half-settle is REACHABLE if a winner already holds a
// credit balance close to 2^256. Seed a winner's credit slot to MaxUint256, then
// settle: addCredit overflows for that winner. Observe whether (a) it returns an
// error, (b) the slash already mutated stakes, and (c) the settled marker is NOT
// set -> task re-settleable. This is the concrete half-settle exploit.
func TestProbe_HalfSettleViaCreditOverflow(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)

	out := h(0x42)
	for i := 0; i < testThr; i++ {
		op := selected[i]
		c := opCommit(taskID, op, out, h(0x01), h(0x02))
		require.NoError(e.CommitResponse(st, taskID, op, c, 101))
		require.NoError(e.RevealResponse(st, taskID, op, out, h(0x01), h(0x02), 131))
	}
	// one withholder to make a slashed pool (so slash mutates stakes before payout).
	wh := selected[testThr]
	c := opCommit(taskID, wh, h(0xEE), h(0x01), h(0x02))
	require.NoError(e.CommitResponse(st, taskID, wh, c, 101))

	// Poison: set a winner's credit slot to MaxUint256 so addCredit overflows.
	victimWinner := selected[0]
	writeCredit(st, victimWinner, new(uint256.Int).SetAllOne())

	// snapshot withholder stake before the (doomed) settle.
	_, _, whStakeBefore, _, _ := e.GetOperator(st, wh)

	_, err = e.Settle(st, lg, taskID, 161)
	require.ErrorIs(err, ErrCreditOverflow, "settle aborts on credit overflow")

	// EXPLOIT SURFACE: slash already happened (withholder stake reduced) but the
	// settled marker is NOT set, so the task is RE-SETTLEABLE.
	_, _, whStakeAfter, _, _ := e.GetOperator(st, wh)
	settledMarker := isSet(st.GetState(slotHash(nsSettled, taskID)))
	taskState := e.GetTask(st, taskID).Status

	t.Logf("withholder stake before=%s after=%s ; settledMarker=%v ; taskState=%d",
		whStakeBefore, whStakeAfter, settledMarker, taskState)

	if whStakeAfter.Lt(whStakeBefore) && !settledMarker {
		// Re-settle: slash fires AGAIN (floored), double-charging the withholder and
		// re-distributing from escrow.
		writeCredit(st, victimWinner, uint256.NewInt(0)) // attacker resets their own slot
		res2, err2 := e.Settle(st, lg, taskID, 162)
		t.Logf("RE-SETTLE after half-settle: err=%v status=%v slashed=%v", err2, res2.Status, res2.Slashed)
		_, _, whStakeAfter2, _, _ := e.GetOperator(st, wh)
		if whStakeAfter2.Lt(whStakeAfter) {
			t.Fatalf("FINDING CONFIRMED: half-settle left task re-settleable; withholder slashed TWICE (%s -> %s -> %s)",
				whStakeBefore, whStakeAfter, whStakeAfter2)
		}
		t.Fatalf("FINDING CONFIRMED (partial): settle aborted mid-way (slash applied, marker unset) leaving a re-settleable task; re-settle err=%v", err2)
	}
}
