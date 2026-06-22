// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// redb_probe_test.go — Red-B adversarial probes. NOT regression tests; these are
// exploratory assertions used to CONFIRM or REFUTE attack hypotheses. Findings
// that confirm get a minimal fix + a dedicated regression test elsewhere.

import (
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// PROBE 1: nil RewardPerOperator / nil Fee through the import seam. CIntent
// fields are *uint256.Int pointers; a delivered intent with nil pointers reaches
// createTask -> MulOverflow on a nil receiver. Does it panic (DoS) or fail
// cleanly? The id-binding step hashes Fee via u256be (nil-safe), so a nil Fee can
// pass id binding if the committed id was computed with nil too.
func TestProbe_NilRewardPanics(t *testing.T) {
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)

	// Build an intent whose committed id was derived with Fee=nil (u256be(nil)=zero),
	// then deliver RewardPerOperator=nil. id binding uses Fee; reward is not in the id.
	cTx := h(0x11)
	callIdx := uint32(7)
	id := ComputeIntentID(e.CChainID, e.AChainID, cTx, callIdx, requester, modelSpec, promptHash, testN, testThr, nil)
	intent := CIntent{
		IntentID:          id,
		CChainID:          e.CChainID,
		AChainID:          e.AChainID,
		CTxHash:           cTx,
		CallIndex:         callIdx,
		Caller:            requester,
		ModelSpecHash:     modelSpec,
		PromptHash:        promptHash,
		N:                 testN,
		Threshold:         testThr,
		Fee:               nil, // nil fee
		RewardPerOperator: nil, // nil reward -> createTask MulOverflow(nil,...)
	}
	// Capture panic if any.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FINDING CONFIRMED: nil RewardPerOperator/Fee panics the import seam (consensus DoS): %v", r)
		}
	}()
	_, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	t.Logf("no panic; err=%v", err)
}

// PROBE 2: merkle proof-length is not bound to tree depth. VerifyReceiptProof
// folds exactly len(Siblings) levels and never checks idx is fully consumed or
// that the sibling count == ceil(log2(n)). Try to forge inclusion of a
// non-member by abusing a 1-leaf root (root == leafHash(L0)): an EMPTY-sibling
// proof verifies any X whose leafHash == root. More dangerous: in a multi-leaf
// tree, can a truncated proof validate a partial (internal) node as if it were a
// member receipt?
func TestProbe_MerkleProofLengthForgery(t *testing.T) {
	// Build a 4-leaf tree.
	raw := []common.Hash{h(1), h(2), h(3), h(4)}
	leaves := make([]common.Hash, len(raw))
	for i, x := range raw {
		leaves[i] = leafHash(x)
	}
	root := merkleRoot(leaves)

	// The left internal node = node(leafHash(1), leafHash(2)). If an attacker can
	// present a "receipt" whose leafHash equals this internal node value, and a
	// 1-sibling proof with the right node, they'd forge membership. But leafHash is
	// keccak(receiptHash) — attacker would need a receiptHash R with
	// keccak(R)==internalNode. Preimage resistance blocks it. Confirm the verifier
	// at least REJECTS a proof whose sibling count != tree depth for a known member.
	leftInternal := merkleNode(leaves[0], leaves[1])
	rightInternal := merkleNode(leaves[2], leaves[3])
	require.Equal(t, root, merkleNode(leftInternal, rightInternal))

	// Forge attempt: claim leftInternal is a member with an empty proof and root'
	// = leftInternal. There is no such standalone root on-chain, but show the
	// verifier has NO depth binding: an attacker who ever observes a root that
	// equals leafHash(X) (a 1-settle root) can prove X with zero siblings — which
	// is *correct* for that single member, so not itself a forgery.
	// The real check: does VerifyReceiptProof accept a SHORT proof against the real
	// 4-leaf root for a fabricated leaf? It must not.
	fakeLeafEqualsLeftInternal := leftInternal // pretend a receiptHash hashed to this
	shortProof := MerkleProof{Index: 0, Siblings: []common.Hash{rightInternal}}
	// cur = leafHash(fake) then node(cur, rightInternal). For this to equal root we
	// need leafHash(fake) == leftInternal. It won't unless attacker breaks preimage.
	got := VerifyReceiptProof(fakeLeafEqualsLeftInternal, shortProof, root)
	if got {
		t.Fatalf("FINDING: short-proof forgery verified a non-member under the 4-leaf root")
	}
	t.Logf("short-proof forgery rejected (leafHash domain-separates internal nodes): ok")
}

// PROBE 3: escrow identity across withdraw-after-slash. Slash an operator, then
// deregister + withdraw its (reduced) stake; the slashed wei was credited to
// winners. Assert balance(EscrowAccount) == Σstake + Σopen + Σcredit at the end
// AND grand total conserved.
func TestProbe_EscrowIdentityAfterSlashWithdraw(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, allOps := newHarness(t, eligible, reward)
	totalBefore := lg.Total()

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
	// withholders commit, don't reveal -> slashed
	withholder := selected[testThr]
	c := opCommit(taskID, withholder, h(0xEE), h(0x01), h(0x02))
	require.NoError(e.CommitResponse(st, taskID, withholder, c, 101))

	_, err = e.Settle(st, lg, taskID, 161)
	require.NoError(err)

	// Now the slashed withholder deregisters and withdraws its reduced stake.
	require.NoError(e.DeregisterOperator(st, withholder, 200))
	_, err = e.WithdrawStake(st, lg, withholder, 200+UnbondCooldownBlocks)
	require.NoError(err)

	// Winners withdraw their credit.
	for i := 0; i < testThr; i++ {
		_, _ = e.WithdrawRewards(st, lg, selected[i])
	}
	// requester withdraws any refund credit.
	_, _ = e.WithdrawRewards(st, lg, requester)

	require.Equal(totalBefore.String(), lg.Total().String(), "grand total conserved through slash+withdraw")
	requireEscrowIdentity(t, e, st, lg, taskID, append(allOps, requester))
}

// PROBE 4: double-withdraw of rewards. WithdrawRewards zeroes credit then Pays.
// Call twice; second must be ErrNoCredit (no double pay).
func TestProbe_DoubleWithdrawRewards(t *testing.T) {
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
	w := selected[0]
	first, err := e.WithdrawRewards(st, lg, w)
	require.NoError(err)
	require.False(first.IsZero())
	_, err = e.WithdrawRewards(st, lg, w)
	require.ErrorIs(err, ErrNoCredit, "second withdraw must pay nothing")
}

// PROBE 5: can a winner be paid TWICE by revealing under two selection slots?
// Selection draws DISTINCT indices from a deduped member array, so one operator
// occupies at most one slot. But verify slashStake/tally count an operator once.
// Construct a task; confirm |selected| distinct == N and each appears once in the
// selList.
func TestProbe_NoDuplicateSelection(t *testing.T) {
	require := require.New(t)
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, lg, requester, _ := newHarness(t, eligible, reward)
	intent := mkIntent(e, requester, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, intent, 100)
	require.NoError(err)
	seen := map[common.Address]bool{}
	for i := uint32(0); i < testN; i++ {
		op := e.SelectedAt(st, taskID, i)
		require.False(seen[op], "operator %s appears in two selection slots", op)
		seen[op] = true
	}
	require.Len(seen, testN)
}
