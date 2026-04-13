// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"testing"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

const (
	// MinBridgeBond is the minimum bond required for bridge validators (1M LUX)
	MinBridgeBond = 1_000_000 * 1e9
)

// TestSignerSetOptInRegistration tests LP-333 opt-in registration
// First 100 validators should register WITHOUT triggering reshare
func TestSignerSetOptInRegistration(t *testing.T) {
	require := require.New(t)

	vm := &VM{
		config: BridgeConfig{
			MaxSigners:     100,
			ThresholdRatio: 0.67,
		},
		signerSet: &SignerSet{
			Signers:      make([]*SignerInfo, 0, 100),
			Waitlist:     make([]ids.NodeID, 0),
			CurrentEpoch: 0,
			SetFrozen:    false,
			ThresholdT:   0,
		},
	}

	// Register first 10 validators - should NOT trigger reshare
	for i := 0; i < 10; i++ {
		nodeID := ids.GenerateTestNodeID()
		input := &RegisterValidatorInput{
			NodeID: nodeID.String(),
		}

		result, err := vm.RegisterValidator(input)
		require.NoError(err)
		require.True(result.Success)
		require.True(result.Registered)
		require.False(result.Waitlisted)
		require.False(result.ReshareNeeded)           // LP-333: NO reshare on opt-in
		require.Equal(uint64(0), result.CurrentEpoch) // Epoch should NOT change
		require.Equal(i, result.SignerIndex)
	}

	// Verify signer set state
	require.Equal(10, len(vm.signerSet.Signers))
	require.Equal(uint64(0), vm.signerSet.CurrentEpoch) // Still epoch 0
	require.False(vm.signerSet.SetFrozen)

	// Threshold should be floor(10 * 0.67) = 6
	require.Equal(6, vm.signerSet.ThresholdT)
}

// TestSignerSetFreezeAt100 tests that set freezes at 100 signers
func TestSignerSetFreezeAt100(t *testing.T) {
	require := require.New(t)

	vm := &VM{
		config: BridgeConfig{
			MaxSigners:     5, // Use small number for test
			ThresholdRatio: 0.67,
		},
		signerSet: &SignerSet{
			Signers:      make([]*SignerInfo, 0, 5),
			Waitlist:     make([]ids.NodeID, 0),
			CurrentEpoch: 0,
			SetFrozen:    false,
			ThresholdT:   0,
		},
	}

	// Register up to max signers
	for i := 0; i < 5; i++ {
		nodeID := ids.GenerateTestNodeID()
		input := &RegisterValidatorInput{
			NodeID: nodeID.String(),
		}

		result, err := vm.RegisterValidator(input)
		require.NoError(err)
		require.True(result.Success)
		require.True(result.Registered)
		require.False(result.Waitlisted)
	}

	// Set should now be frozen
	require.True(vm.signerSet.SetFrozen)
	require.Equal(5, len(vm.signerSet.Signers))

	// Next registration should go to waitlist
	nodeID := ids.GenerateTestNodeID()
	input := &RegisterValidatorInput{
		NodeID: nodeID.String(),
	}

	result, err := vm.RegisterValidator(input)
	require.NoError(err)
	require.True(result.Success)
	require.False(result.Registered)
	require.True(result.Waitlisted)
	require.Equal(0, result.WaitlistIndex)
}

// TestRemoveSignerTriggersReshare tests LP-333 reshare on removal
// RemoveSigner is the ONLY operation that triggers reshare
func TestRemoveSignerTriggersReshare(t *testing.T) {
	require := require.New(t)

	// Setup VM with some signers
	nodeID1 := ids.GenerateTestNodeID()
	nodeID2 := ids.GenerateTestNodeID()
	nodeID3 := ids.GenerateTestNodeID()

	vm := &VM{
		config: BridgeConfig{
			MaxSigners:     100,
			ThresholdRatio: 0.67,
		},
		signerSet: &SignerSet{
			Signers: []*SignerInfo{
				{NodeID: nodeID1, SlotIndex: 0, Active: true},
				{NodeID: nodeID2, SlotIndex: 1, Active: true},
				{NodeID: nodeID3, SlotIndex: 2, Active: true},
			},
			Waitlist:     make([]ids.NodeID, 0),
			CurrentEpoch: 0,
			SetFrozen:    false,
			ThresholdT:   2,
		},
	}

	// Verify initial state
	require.Equal(3, len(vm.signerSet.Signers))
	require.Equal(uint64(0), vm.signerSet.CurrentEpoch)

	// Remove a signer - THIS should trigger reshare and increment epoch
	result, err := vm.RemoveSigner(nodeID2, nil)
	require.NoError(err)
	require.True(result.Success)
	require.Equal(nodeID2.String(), result.RemovedNodeID)
	require.Equal(uint64(1), result.NewEpoch) // Epoch incremented!
	require.Equal(2, result.ActiveSigners)

	// Verify epoch incremented
	require.Equal(uint64(1), vm.signerSet.CurrentEpoch)
}

// TestRemoveSignerWithWaitlistReplacement tests automatic replacement from waitlist
func TestRemoveSignerWithWaitlistReplacement(t *testing.T) {
	require := require.New(t)

	nodeID1 := ids.GenerateTestNodeID()
	nodeID2 := ids.GenerateTestNodeID()
	waitlistNode := ids.GenerateTestNodeID()

	vm := &VM{
		config: BridgeConfig{
			MaxSigners:     100,
			ThresholdRatio: 0.67,
		},
		signerSet: &SignerSet{
			Signers: []*SignerInfo{
				{NodeID: nodeID1, SlotIndex: 0, Active: true},
				{NodeID: nodeID2, SlotIndex: 1, Active: true},
			},
			Waitlist:     []ids.NodeID{waitlistNode},
			CurrentEpoch: 0,
			SetFrozen:    true, // Set is frozen
			ThresholdT:   1,
		},
	}

	// Remove signer - should be replaced from waitlist
	result, err := vm.RemoveSigner(nodeID1, nil)
	require.NoError(err)
	require.True(result.Success)
	require.Equal(nodeID1.String(), result.RemovedNodeID)
	require.Equal(waitlistNode.String(), result.ReplacementNodeID)
	require.Equal(uint64(1), result.NewEpoch)
	require.Equal(2, result.ActiveSigners) // Still 2 (replaced)
	require.Contains(result.Message, "waitlist")

	// Waitlist should now be empty
	require.Empty(vm.signerSet.Waitlist)
}

// TestHasSigner tests the HasSigner helper
func TestHasSigner(t *testing.T) {
	require := require.New(t)

	nodeID1 := ids.GenerateTestNodeID()
	nodeID2 := ids.GenerateTestNodeID()
	nodeIDNotInSet := ids.GenerateTestNodeID()

	vm := &VM{
		signerSet: &SignerSet{
			Signers: []*SignerInfo{
				{NodeID: nodeID1, SlotIndex: 0, Active: true},
				{NodeID: nodeID2, SlotIndex: 1, Active: true},
			},
		},
	}

	require.True(vm.HasSigner(nodeID1))
	require.True(vm.HasSigner(nodeID2))
	require.False(vm.HasSigner(nodeIDNotInSet))
}

// TestGetSignerSetInfo tests signer set info retrieval
func TestGetSignerSetInfo(t *testing.T) {
	require := require.New(t)

	nodeID1 := ids.GenerateTestNodeID()
	nodeID2 := ids.GenerateTestNodeID()

	vm := &VM{
		config: BridgeConfig{
			MaxSigners:     100,
			ThresholdRatio: 0.67,
		},
		signerSet: &SignerSet{
			Signers: []*SignerInfo{
				{NodeID: nodeID1, SlotIndex: 0, Active: true},
				{NodeID: nodeID2, SlotIndex: 1, Active: true},
			},
			Waitlist:     []ids.NodeID{ids.GenerateTestNodeID()},
			CurrentEpoch: 5,
			SetFrozen:    false,
			ThresholdT:   1,
			PublicKey:    []byte{0x01, 0x02, 0x03},
		},
	}

	info := vm.GetSignerSetInfo()
	require.Equal(2, info.TotalSigners)
	require.Equal(1, info.Threshold)
	require.Equal(100, info.MaxSigners)
	require.Equal(uint64(5), info.CurrentEpoch)
	require.False(info.SetFrozen)
	require.Equal(98, info.RemainingSlots) // 100 - 2
	require.Equal(1, info.WaitlistSize)
	require.Equal(2, len(info.Signers))
	require.Equal("010203", info.PublicKey)
}

// TestDuplicateRegistration tests that duplicate registration is rejected
func TestDuplicateRegistration(t *testing.T) {
	require := require.New(t)

	nodeID := ids.GenerateTestNodeID()

	vm := &VM{
		config: BridgeConfig{
			MaxSigners:     100,
			ThresholdRatio: 0.67,
		},
		signerSet: &SignerSet{
			Signers: []*SignerInfo{
				{NodeID: nodeID, SlotIndex: 0, Active: true},
			},
			Waitlist:     make([]ids.NodeID, 0),
			CurrentEpoch: 0,
			SetFrozen:    false,
			ThresholdT:   1,
		},
	}

	// Try to register same node again
	input := &RegisterValidatorInput{
		NodeID: nodeID.String(),
	}

	result, err := vm.RegisterValidator(input)
	require.NoError(err)
	require.False(result.Success)
	require.Contains(result.Message, "already registered")
}

// TestThresholdCalculation tests that threshold is calculated correctly
func TestThresholdCalculation(t *testing.T) {
	require := require.New(t)

	vm := &VM{
		config: BridgeConfig{
			MaxSigners:     100,
			ThresholdRatio: 0.67,
		},
		signerSet: &SignerSet{
			Signers:      make([]*SignerInfo, 0, 100),
			Waitlist:     make([]ids.NodeID, 0),
			CurrentEpoch: 0,
			SetFrozen:    false,
			ThresholdT:   0,
		},
	}

	testCases := []struct {
		numSigners        int
		expectedThreshold int
	}{
		{1, 1},    // floor(1 * 0.67) = 0, but minimum is 1
		{2, 1},    // floor(2 * 0.67) = 1
		{3, 2},    // floor(3 * 0.67) = 2
		{10, 6},   // floor(10 * 0.67) = 6
		{100, 67}, // floor(100 * 0.67) = 67
	}

	for _, tc := range testCases {
		// Reset signer set
		vm.signerSet.Signers = make([]*SignerInfo, 0, 100)
		vm.signerSet.ThresholdT = 0

		// Add signers
		for i := 0; i < tc.numSigners; i++ {
			nodeID := ids.GenerateTestNodeID()
			input := &RegisterValidatorInput{
				NodeID: nodeID.String(),
			}
			_, err := vm.RegisterValidator(input)
			require.NoError(err)
		}

		require.Equal(tc.expectedThreshold, vm.signerSet.ThresholdT,
			"threshold mismatch for %d signers", tc.numSigners)
	}
}

// TestSlashSignerPartial tests partial slashing of a signer's bond
func TestSlashSignerPartial(t *testing.T) {
	require := require.New(t)

	nodeID := ids.GenerateTestNodeID()
	initialBond := uint64(1_500_000 * 1e9) // 1.5M LUX bond

	vm := &VM{
		config: BridgeConfig{
			MaxSigners:     100,
			ThresholdRatio: 0.67,
		},
		signerSet: &SignerSet{
			Signers: []*SignerInfo{
				{
					NodeID:     nodeID,
					SlotIndex:  0,
					Active:     true,
					BondAmount: initialBond,
					Slashed:    false,
					SlashCount: 0,
				},
			},
			CurrentEpoch: 0,
			ThresholdT:   1,
		},
	}

	// Slash 10% of bond
	input := &SlashSignerInput{
		NodeID:       nodeID,
		Reason:       "failed to sign",
		SlashPercent: 10,
		Evidence:     []byte("proof"),
	}

	result, err := vm.SlashSigner(input)
	require.NoError(err)
	require.True(result.Success)
	require.Equal(nodeID.String(), result.NodeID)
	require.Equal(initialBond/10, result.SlashedAmount)             // 150K LUX slashed
	require.Equal(initialBond-initialBond/10, result.RemainingBond) // 1.35M remaining
	require.Equal(1, result.TotalSlashCount)
	require.False(result.RemovedFromSet) // Still above 1M minimum

	// Verify signer state
	require.True(vm.signerSet.Signers[0].Slashed)
	require.Equal(1, vm.signerSet.Signers[0].SlashCount)
}

// TestSlashSignerRemoval tests that slashing below 1M bond removes signer
func TestSlashSignerRemoval(t *testing.T) {
	require := require.New(t)

	nodeID := ids.GenerateTestNodeID()
	initialBond := uint64(1_100_000 * 1e9) // 1.1M LUX bond (just above minimum)

	vm := &VM{
		config: BridgeConfig{
			MaxSigners:     100,
			ThresholdRatio: 0.67,
		},
		signerSet: &SignerSet{
			Signers: []*SignerInfo{
				{
					NodeID:     nodeID,
					SlotIndex:  0,
					Active:     true,
					BondAmount: initialBond,
					Slashed:    false,
					SlashCount: 0,
				},
			},
			CurrentEpoch: 0,
			ThresholdT:   1,
		},
	}

	// Slash 20% — 1.1M * 0.8 = 880K remaining, below 1M minimum
	input := &SlashSignerInput{
		NodeID:       nodeID,
		Reason:       "double signing",
		SlashPercent: 20,
		Evidence:     []byte("proof"),
	}

	result, err := vm.SlashSigner(input)
	require.NoError(err)
	require.True(result.Success)
	require.True(result.RemovedFromSet)                 // Removed because bond < 1M
	require.Equal(uint64(1), vm.signerSet.CurrentEpoch) // Epoch incremented

	// Signer should be removed
	require.Empty(vm.signerSet.Signers)
}

// TestSlashSignerNotFound tests slashing a non-existent signer
func TestSlashSignerNotFound(t *testing.T) {
	require := require.New(t)

	nodeID := ids.GenerateTestNodeID()
	otherNodeID := ids.GenerateTestNodeID()

	vm := &VM{
		signerSet: &SignerSet{
			Signers: []*SignerInfo{
				{NodeID: nodeID, SlotIndex: 0, Active: true, BondAmount: MinBridgeBond},
			},
		},
	}

	// Try to slash a node that's not in the set
	input := &SlashSignerInput{
		NodeID:       otherNodeID,
		Reason:       "misbehavior",
		SlashPercent: 50,
	}

	result, err := vm.SlashSigner(input)
	require.NoError(err)
	require.False(result.Success)
	require.Contains(result.Message, "not found")
}

// TestSlashSignerInvalidPercent tests invalid slash percentages
func TestSlashSignerInvalidPercent(t *testing.T) {
	require := require.New(t)

	nodeID := ids.GenerateTestNodeID()

	vm := &VM{
		signerSet: &SignerSet{
			Signers: []*SignerInfo{
				{NodeID: nodeID, SlotIndex: 0, Active: true, BondAmount: MinBridgeBond},
			},
		},
	}

	// Test 0%
	_, err := vm.SlashSigner(&SlashSignerInput{
		NodeID:       nodeID,
		SlashPercent: 0,
	})
	require.Error(err)
	require.Contains(err.Error(), "between 1 and 100")

	// Test 101%
	_, err = vm.SlashSigner(&SlashSignerInput{
		NodeID:       nodeID,
		SlashPercent: 101,
	})
	require.Error(err)
	require.Contains(err.Error(), "between 1 and 100")
}
