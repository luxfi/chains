// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
)

// signerVM is a VM with a signer set of the given size, booted the way the node
// boots one.
func signerVM(t *testing.T, maxSigners int) *VM {
	t.Helper()
	cfg := testConfig()
	cfg.MaxSigners = maxSigners
	return bootOn(t, memdb.New(), cfg)
}

func bondOf(v uint64) string { return strconv.FormatUint(v, 10) }

// TestSignerSetOptInRegistration: the first MaxSigners validators register
// without a reshare and the epoch does not move (LP-333).
func TestSignerSetOptInRegistration(t *testing.T) {
	require := require.New(t)
	vm := signerVM(t, 100)

	for i := 0; i < 10; i++ {
		result, err := vm.RegisterValidator(&RegisterValidatorInput{
			NodeID:     ids.GenerateTestNodeID().String(),
			BondAmount: bondOf(minValidatorBond),
		})
		require.NoError(err)
		require.True(result.Success)
		require.True(result.Registered)
		require.False(result.Waitlisted)
		require.False(result.ReshareNeeded)
		require.Equal(uint64(0), result.CurrentEpoch)
		require.Equal(i, result.SignerIndex)
	}

	require.Len(vm.signerSet.Signers, 10)
	require.Equal(uint64(0), vm.signerSet.CurrentEpoch)
	require.False(vm.signerSet.SetFrozen)

	// ⌈2·10/3⌉ = 7 signers required, so t = 6.
	require.Equal(6, vm.signerSet.ThresholdT)
}

// TestABondBelowTheRequirementIsNotASigner. The chain declared a bond and read
// the field without ever comparing it: a validator claiming nothing at all
// took a slot in the set that authorises releases.
func TestABondBelowTheRequirementIsNotASigner(t *testing.T) {
	vm := signerVM(t, 100)

	for _, bond := range []string{"", "0", "1", bondOf(minValidatorBond - 1), "not-a-number"} {
		_, err := vm.RegisterValidator(&RegisterValidatorInput{
			NodeID:     ids.GenerateTestNodeID().String(),
			BondAmount: bond,
		})
		require.Error(t, err, "bond %q was admitted", bond)
	}
	require.Empty(t, vm.signerSet.Signers)

	_, err := vm.RegisterValidator(&RegisterValidatorInput{
		NodeID:     ids.GenerateTestNodeID().String(),
		BondAmount: bondOf(minValidatorBond),
	})
	require.NoError(t, err)
	require.Len(t, vm.signerSet.Signers, 1)
}

// TestQuorumIsExactAtEverySmallSize. The threshold was int(n * 0.67): a float
// rounding down. At n=3 it asked for all three — a set that cannot lose a
// single signer and tolerates no Byzantine one — and at n=1 it clamped to
// asking two of one, which nothing can satisfy.
func TestQuorumIsExactAtEverySmallSize(t *testing.T) {
	// n: how many of n must agree
	want := map[int]int{0: 0, 1: 1, 2: 2, 3: 2, 4: 3, 5: 4, 6: 4, 7: 5, 100: 67}
	for n, q := range want {
		require.Equal(t, q, quorum(n), "quorum(%d)", n)
	}
	// And the two properties those numbers exist for, at every size a signer
	// set can reach: a quorum is reachable, it is a two-thirds majority, and
	// two quorums overlap in more signers than can be faulty — which is what
	// makes two of them unable to decide different things.
	for n := 1; n <= 512; n++ {
		q := quorum(n)
		faulty := (n - 1) / 3
		require.Positive(t, q, "quorum(%d) asks for nobody", n)
		require.LessOrEqual(t, q, n, "quorum(%d) asks for more signers than exist", n)
		require.GreaterOrEqual(t, 3*q, 2*n, "quorum(%d) is under a two-thirds majority", n)
		require.Greater(t, 2*q-n, faulty, "two quorums of %d out of %d can be disjoint in the honest signers", q, n)
	}
}

// TestThresholdFollowsTheSetSize keeps the reported threshold and the set in
// step through joins and removals.
func TestThresholdFollowsTheSetSize(t *testing.T) {
	vm := signerVM(t, 100)
	nodes := make([]ids.NodeID, 0, 7)
	for i := 1; i <= 7; i++ {
		node := ids.GenerateTestNodeID()
		nodes = append(nodes, node)
		require.NoError(t, registerSigner(vm, node))
		require.Equal(t, quorum(i)-1, vm.signerSet.ThresholdT, "after %d signers", i)
	}

	vm.RemoveSigner(nodes[0], nil)
	require.Equal(t, quorum(6)-1, vm.signerSet.ThresholdT)
}

// TestSignerSetFreezeAt100 tests that the set freezes at MaxSigners.
func TestSignerSetFreezeAt100(t *testing.T) {
	require := require.New(t)
	vm := signerVM(t, 5)

	for i := 0; i < 5; i++ {
		result, err := vm.RegisterValidator(&RegisterValidatorInput{
			NodeID:     ids.GenerateTestNodeID().String(),
			BondAmount: bondOf(minValidatorBond),
		})
		require.NoError(err)
		require.True(result.Registered)
	}
	require.True(vm.signerSet.SetFrozen)

	waiting := ids.GenerateTestNodeID()
	result, err := vm.RegisterValidator(&RegisterValidatorInput{
		NodeID:     waiting.String(),
		BondAmount: bondOf(minValidatorBond),
	})
	require.NoError(err)
	require.True(result.Success)
	require.False(result.Registered)
	require.True(result.Waitlisted)
	require.Equal(0, result.WaitlistIndex)
	require.Equal(uint64(0), result.CurrentEpoch, "a waitlist entry is not a reshare")

	// Asking twice from the waitlist is not two places in the queue.
	result, err = vm.RegisterValidator(&RegisterValidatorInput{
		NodeID:     waiting.String(),
		BondAmount: bondOf(minValidatorBond),
	})
	require.NoError(err)
	require.False(result.Success)
	require.True(result.Waitlisted)
	require.Len(vm.signerSet.Waitlist, 1)
}

// TestRemoveSignerTriggersReshare: removal is the ONLY thing that moves the
// epoch (LP-333).
func TestRemoveSignerTriggersReshare(t *testing.T) {
	require := require.New(t)
	vm := signerVM(t, 100)

	nodes := make([]ids.NodeID, 0, 3)
	for i := 0; i < 3; i++ {
		node := ids.GenerateTestNodeID()
		nodes = append(nodes, node)
		require.NoError(registerSigner(vm, node))
	}
	require.Equal(uint64(0), vm.signerSet.CurrentEpoch)

	result := vm.RemoveSigner(nodes[1], nil)
	require.True(result.Success)
	require.Equal(uint64(1), result.NewEpoch)
	require.Equal(2, result.ActiveSigners)
	require.Equal(nodes[1].String(), result.RemovedNodeID)
	require.False(vm.HasSigner(nodes[1]))

	// Removing someone who is not in the set changes nothing.
	result = vm.RemoveSigner(ids.GenerateTestNodeID(), nil)
	require.False(result.Success)
	require.Equal(uint64(1), vm.signerSet.CurrentEpoch)
}

// TestReplacementTakesTheVacatedSlot. The removed signer was spliced out and
// the replacement appended at the end, which moved every signer above it and
// left the stored slot numbers naming positions nobody held.
func TestReplacementTakesTheVacatedSlot(t *testing.T) {
	require := require.New(t)
	vm := signerVM(t, 100)

	nodes := make([]ids.NodeID, 0, 4)
	for i := 0; i < 4; i++ {
		node := ids.GenerateTestNodeID()
		nodes = append(nodes, node)
		require.NoError(registerSigner(vm, node))
	}
	replacement := ids.GenerateTestNodeID()

	result := vm.RemoveSigner(nodes[1], &replacement)
	require.True(result.Success)
	require.Equal(replacement.String(), result.ReplacementNodeID)
	require.NotEmpty(result.ReshareSession)
	require.Equal(4, result.ActiveSigners)

	require.Equal(replacement, vm.signerSet.Signers[1].NodeID, "the replacement takes the vacated slot")
	for i, signer := range vm.signerSet.Signers {
		require.Equal(i, signer.SlotIndex, "slot %d names a position its signer does not hold", i)
	}
}

// TestRemoveSignerWithWaitlistReplacement: with nobody named, the waitlist is
// where the replacement comes from.
func TestRemoveSignerWithWaitlistReplacement(t *testing.T) {
	require := require.New(t)
	vm := signerVM(t, 2)

	first, second := ids.GenerateTestNodeID(), ids.GenerateTestNodeID()
	require.NoError(registerSigner(vm, first))
	require.NoError(registerSigner(vm, second))
	waiting := ids.GenerateTestNodeID()
	require.NoError(registerSigner(vm, waiting))
	require.Len(vm.signerSet.Waitlist, 1)

	result := vm.RemoveSigner(first, nil)
	require.Equal(waiting.String(), result.ReplacementNodeID)
	require.Empty(vm.signerSet.Waitlist)
	require.True(vm.HasSigner(waiting))
}

// TestHasSigner
func TestHasSigner(t *testing.T) {
	vm := signerVM(t, 100)
	node := ids.GenerateTestNodeID()
	require.False(t, vm.HasSigner(node))
	require.NoError(t, registerSigner(vm, node))
	require.True(t, vm.HasSigner(node))
	require.False(t, vm.HasSigner(ids.GenerateTestNodeID()))
}

func TestGetSignerSetInfo(t *testing.T) {
	require := require.New(t)
	vm := signerVM(t, 10)

	info := vm.GetSignerSetInfo()
	require.Zero(info.TotalSigners)
	require.Equal(10, info.MaxSigners)
	require.Equal(10, info.RemainingSlots)
	require.Empty(info.PublicKey)

	for i := 0; i < 3; i++ {
		require.NoError(registerSigner(vm, ids.GenerateTestNodeID()))
	}
	vm.signerSet.PublicKey = []byte{0xde, 0xad}

	info = vm.GetSignerSetInfo()
	require.Equal(3, info.TotalSigners)
	require.Equal(7, info.RemainingSlots)
	require.Equal(quorum(3)-1, info.Threshold)
	require.Equal("dead", info.PublicKey)
	require.Len(info.Signers, 3)
}

// TestDuplicateRegistration: one validator, one slot.
func TestDuplicateRegistration(t *testing.T) {
	require := require.New(t)
	vm := signerVM(t, 100)
	node := ids.GenerateTestNodeID()

	require.NoError(registerSigner(vm, node))
	result, err := vm.RegisterValidator(&RegisterValidatorInput{
		NodeID:     node.String(),
		BondAmount: bondOf(minValidatorBond),
	})
	require.NoError(err)
	require.False(result.Success)
	require.Contains(result.Message, "already registered")
	require.Len(vm.signerSet.Signers, 1)

	_, err = vm.RegisterValidator(&RegisterValidatorInput{
		NodeID:     "not-a-node-id",
		BondAmount: bondOf(minValidatorBond),
	})
	require.Error(err)
}

func TestSlashSignerPartial(t *testing.T) {
	require := require.New(t)
	vm := signerVM(t, 100)
	node := ids.GenerateTestNodeID()

	// A bond well above the requirement, so a small slash leaves it a signer.
	_, err := vm.RegisterValidator(&RegisterValidatorInput{
		NodeID:     node.String(),
		BondAmount: bondOf(2 * minValidatorBond),
	})
	require.NoError(err)

	result, err := vm.SlashSigner(&SlashSignerInput{
		NodeID: node, Reason: "equivocation", SlashPercent: 10, Evidence: []byte("proof"),
	})
	require.NoError(err)
	require.True(result.Success)
	require.Equal(2*minValidatorBond/10, result.SlashedAmount)
	require.Equal(2*minValidatorBond-2*minValidatorBond/10, result.RemainingBond)
	require.Equal(1, result.TotalSlashCount)
	require.False(result.RemovedFromSet)
	require.True(vm.HasSigner(node))
	require.True(vm.signerSet.Signers[0].Slashed)
}

// A bond slashed below what the chain requires is not a bond, so its holder is
// not a signer. The minimum is read from the same declaration registration
// applies rather than a second copy of the number.
func TestSlashSignerRemoval(t *testing.T) {
	require := require.New(t)
	vm := signerVM(t, 100)
	node := ids.GenerateTestNodeID()
	require.NoError(registerSigner(vm, node))
	require.NoError(registerSigner(vm, ids.GenerateTestNodeID()))

	result, err := vm.SlashSigner(&SlashSignerInput{
		NodeID: node, Reason: "double sign", SlashPercent: 50,
	})
	require.NoError(err)
	require.True(result.RemovedFromSet)
	require.False(vm.HasSigner(node))
	require.Equal(uint64(1), vm.signerSet.CurrentEpoch)
	require.Equal(quorum(1)-1, vm.signerSet.ThresholdT)
}

func TestSlashSignerNotFound(t *testing.T) {
	vm := signerVM(t, 100)
	result, err := vm.SlashSigner(&SlashSignerInput{NodeID: ids.GenerateTestNodeID(), SlashPercent: 50})
	require.NoError(t, err)
	require.False(t, result.Success)
	require.Contains(t, result.Message, "not found")
}

func TestSlashSignerInvalidPercent(t *testing.T) {
	vm := signerVM(t, 100)
	node := ids.GenerateTestNodeID()
	require.NoError(t, registerSigner(vm, node))

	for _, pct := range []int{0, -1, 101, 1000} {
		_, err := vm.SlashSigner(&SlashSignerInput{NodeID: node, SlashPercent: pct})
		require.Error(t, err, "slash percent %d was accepted", pct)
	}
}
