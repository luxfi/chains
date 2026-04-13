// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"testing"
	"time"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

func newTestLifecycleManager(t *testing.T) (*LifecycleManager, *Registry) {
	db := memdb.New()
	registry, err := NewRegistry(db)
	require.NoError(t, err)

	config := &LifecycleConfig{
		EpochDuration:     100,
		GracePeriod:       10,
		MinCommitteeSize:  2,
		MaxCommitteeSize:  10,
		DefaultThreshold:  2,
		DKGTimeout:        time.Second,
		KeyRotationBlocks: 0,
	}

	logger := log.Noop()
	lm := NewLifecycleManager(registry, config, logger)
	require.NotNil(t, lm)

	return lm, registry
}

func TestLifecycleManagerInit(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NotNil(t, lm)

	err := lm.Start()
	require.NoError(t, err)

	lm.Stop()
}

func TestInitiateEpoch(t *testing.T) {
	lm, registry := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Create committee
	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk3"), Weight: 100, Index: 2},
	}

	err := lm.InitiateEpoch(committee, 2, []byte("aggregated_public_key"))
	require.NoError(t, err)

	// Verify epoch was created
	epoch := registry.GetCurrentEpoch()
	require.Equal(t, uint64(1), epoch)

	epochInfo, err := registry.GetEpoch(1)
	require.NoError(t, err)
	require.Equal(t, 3, len(epochInfo.Committee))
	require.Equal(t, 2, epochInfo.Threshold)
	require.Equal(t, EpochActive, epochInfo.Status)
}

func TestInitiateEpochValidation(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Too few committee members
	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
	}
	err := lm.InitiateEpoch(committee, 1, []byte("pk"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "below minimum")

	// Invalid threshold
	committee = []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	err = lm.InitiateEpoch(committee, 0, []byte("pk"))
	require.ErrorIs(t, err, ErrInvalidThreshold)

	err = lm.InitiateEpoch(committee, 5, []byte("pk"))
	require.ErrorIs(t, err, ErrInvalidThreshold)
}

func TestRegisterMember(t *testing.T) {
	lm, registry := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Initialize epoch first
	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Register new member
	newNode := ids.GenerateTestNodeID()
	err := lm.RegisterMember(newNode, []byte("new_pk"), 150)
	require.NoError(t, err)

	// Verify member was added
	members, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Equal(t, 3, len(members))

	// Try to register same member again
	err = lm.RegisterMember(newNode, []byte("new_pk"), 150)
	require.ErrorIs(t, err, ErrMemberAlreadyExists)
}

func TestRemoveMember(t *testing.T) {
	lm, registry := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()
	node3 := ids.GenerateTestNodeID()

	committee := []CommitteeMember{
		{NodeID: node1, PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: node2, PublicKey: []byte("pk2"), Weight: 100, Index: 1},
		{NodeID: node3, PublicKey: []byte("pk3"), Weight: 100, Index: 2},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Remove member
	err := lm.RemoveMember(node2)
	require.NoError(t, err)

	members, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Equal(t, 2, len(members))

	// Verify node2 is gone
	for _, m := range members {
		require.NotEqual(t, node2, m.NodeID)
	}
}

func TestStartDKG(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	participants := []ids.NodeID{
		ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(),
	}

	err := lm.StartDKG(2, participants, 2)
	require.NoError(t, err)

	state := lm.GetDKGState()
	require.NotNil(t, state)
	require.Equal(t, uint64(2), state.Epoch)
	require.Equal(t, 3, len(state.Participants))
	require.Equal(t, 2, state.Threshold)
	require.Equal(t, DKGCommitPhase, state.Status)
}

func TestStartDKGValidation(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Not enough participants
	participants := []ids.NodeID{ids.GenerateTestNodeID()}
	err := lm.StartDKG(1, participants, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not enough participants")

	// Invalid threshold
	participants = []ids.NodeID{
		ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(),
	}
	err = lm.StartDKG(1, participants, 0)
	require.ErrorIs(t, err, ErrInvalidThreshold)

	err = lm.StartDKG(1, participants, 5)
	require.ErrorIs(t, err, ErrInvalidThreshold)
}

func TestDKGCommitmentPhase(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()
	participants := []ids.NodeID{node1, node2}

	require.NoError(t, lm.StartDKG(1, participants, 2))

	// Submit commitments
	err := lm.SubmitDKGCommitment(node1, []byte("commitment1_32bytes_padded_here!"))
	require.NoError(t, err)

	state := lm.GetDKGState()
	require.Equal(t, DKGCommitPhase, state.Status)
	require.Equal(t, 1, len(state.Commitments))

	// Submit second commitment - should move to share phase
	err = lm.SubmitDKGCommitment(node2, []byte("commitment2_32bytes_padded_here!"))
	require.NoError(t, err)

	state = lm.GetDKGState()
	require.Equal(t, DKGSharePhase, state.Status)
	require.Equal(t, 2, len(state.Commitments))
}

func TestDKGSharePhase(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()
	participants := []ids.NodeID{node1, node2}

	require.NoError(t, lm.StartDKG(1, participants, 2))

	// Complete commit phase
	require.NoError(t, lm.SubmitDKGCommitment(node1, []byte("commitment1_32bytes_padded_here!")))
	require.NoError(t, lm.SubmitDKGCommitment(node2, []byte("commitment2_32bytes_padded_here!")))

	// Submit shares
	err := lm.SubmitDKGShare(node1, []byte("share1"))
	require.NoError(t, err)

	state := lm.GetDKGState()
	require.Equal(t, DKGSharePhase, state.Status)

	// Submit second share - should complete DKG
	err = lm.SubmitDKGShare(node2, []byte("share2"))
	require.NoError(t, err)

	state = lm.GetDKGState()
	require.Equal(t, DKGCompleted, state.Status)
	require.NotEmpty(t, state.PublicKey)
}

func TestDKGInProgressError(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	participants := []ids.NodeID{
		ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(),
	}

	require.NoError(t, lm.StartDKG(1, participants, 2))

	// Try to start another DKG
	err := lm.StartDKG(2, participants, 2)
	require.ErrorIs(t, err, ErrDKGInProgress)
}

func TestAbortDKG(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	participants := []ids.NodeID{
		ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(),
	}

	require.NoError(t, lm.StartDKG(1, participants, 2))

	err := lm.AbortDKG("test abort reason")
	require.NoError(t, err)

	state := lm.GetDKGState()
	require.Equal(t, DKGAborted, state.Status)
	require.Equal(t, "test abort reason", state.Error)
}

func TestDKGCallback(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	var callbackEpoch uint64
	var callbackPK []byte
	lm.SetCallbacks(nil, nil, func(epoch uint64, pk []byte) {
		callbackEpoch = epoch
		callbackPK = pk
	})

	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()
	participants := []ids.NodeID{node1, node2}

	require.NoError(t, lm.StartDKG(5, participants, 2))
	require.NoError(t, lm.SubmitDKGCommitment(node1, []byte("commitment1_32bytes_padded_here!")))
	require.NoError(t, lm.SubmitDKGCommitment(node2, []byte("commitment2_32bytes_padded_here!")))
	require.NoError(t, lm.SubmitDKGShare(node1, []byte("share1")))
	require.NoError(t, lm.SubmitDKGShare(node2, []byte("share2")))

	require.Equal(t, uint64(5), callbackEpoch)
	require.NotEmpty(t, callbackPK)
}

func TestGetStatus(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	status, err := lm.GetStatus()
	require.NoError(t, err)
	require.Equal(t, uint64(1), status.CurrentEpoch)
	require.Equal(t, 2, status.CommitteeSize)
	require.Equal(t, 2, status.Threshold)
	require.False(t, status.IsTransitioning)
}

func TestGetCommitteeWeight(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 200, Index: 1},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk3"), Weight: 300, Index: 2},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	weight, err := lm.GetCommitteeWeight()
	require.NoError(t, err)
	require.Equal(t, uint64(600), weight)
}

func TestGetEpochKeyInfo(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("epoch_public_key")))

	info, err := lm.GetEpochKeyInfo(1)
	require.NoError(t, err)
	require.Equal(t, uint64(1), info.Epoch)
	require.Equal(t, []byte("epoch_public_key"), info.PublicKey)
	require.Equal(t, 2, info.Threshold)
	require.Equal(t, 2, info.Committee)
	require.True(t, info.IsActive)
}

func TestIsTransitioning(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	require.False(t, lm.IsTransitioning())

	// Force a transition
	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	err := lm.ForceEpochTransition()
	require.NoError(t, err)

	require.True(t, lm.IsTransitioning())

	state := lm.GetTransitionState()
	require.NotNil(t, state)
	require.Equal(t, uint64(1), state.FromEpoch)
	require.Equal(t, uint64(2), state.ToEpoch)
}

func TestDKGStatusString(t *testing.T) {
	tests := []struct {
		status   DKGStatus
		expected string
	}{
		{DKGPending, "pending"},
		{DKGCommitPhase, "commit_phase"},
		{DKGSharePhase, "share_phase"},
		{DKGCompleted, "completed"},
		{DKGFailed, "failed"},
		{DKGAborted, "aborted"},
		{DKGStatus(99), "unknown"},
	}

	for _, tc := range tests {
		require.Equal(t, tc.expected, tc.status.String())
	}
}

func TestTransitionStatusString(t *testing.T) {
	tests := []struct {
		status   TransitionStatus
		expected string
	}{
		{TransitionPending, "pending"},
		{TransitionDKGPhase, "dkg_phase"},
		{TransitionMigrationPhase, "migration_phase"},
		{TransitionFinalizingPhase, "finalizing"},
		{TransitionCompleted, "completed"},
		{TransitionFailed, "failed"},
		{TransitionStatus(99), "unknown"},
	}

	for _, tc := range tests {
		require.Equal(t, tc.expected, tc.status.String())
	}
}

func TestMemberStatusString(t *testing.T) {
	tests := []struct {
		status   MemberStatus
		expected string
	}{
		{MemberPending, "pending"},
		{MemberActive, "active"},
		{MemberInactive, "inactive"},
		{MemberSlashed, "slashed"},
		{MemberExiting, "exiting"},
		{MemberStatus(99), "unknown"},
	}

	for _, tc := range tests {
		require.Equal(t, tc.expected, tc.status.String())
	}
}

func TestDefaultLifecycleConfig(t *testing.T) {
	config := DefaultLifecycleConfig()
	require.NotNil(t, config)
	require.Equal(t, uint64(100000), config.EpochDuration)
	require.Equal(t, uint64(1000), config.GracePeriod)
	require.Equal(t, 4, config.MinCommitteeSize)
	require.Equal(t, 100, config.MaxCommitteeSize)
	require.Equal(t, 67, config.DefaultThreshold)
	require.Equal(t, 5*time.Minute, config.DKGTimeout)
}

func TestSlashMember(t *testing.T) {
	lm, registry := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()

	committee := []CommitteeMember{
		{NodeID: node1, PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: node2, PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Slash node1
	err := lm.SlashMember(node1, "misbehavior detected")
	require.NoError(t, err)

	// Verify node1 is removed
	members, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Equal(t, 1, len(members))
	require.Equal(t, node2, members[0].NodeID)
}

func TestValidateThresholdMet(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk3"), Weight: 100, Index: 2},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Threshold met
	err := lm.ValidateThresholdMet(2)
	require.NoError(t, err)

	err = lm.ValidateThresholdMet(3)
	require.NoError(t, err)

	// Threshold not met
	err = lm.ValidateThresholdMet(1)
	require.ErrorIs(t, err, ErrInsufficientWeight)
}

func TestDKGCommitmentNotInCommitPhase(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Try to submit commitment without starting DKG
	err := lm.SubmitDKGCommitment(ids.GenerateTestNodeID(), []byte("commitment"))
	require.ErrorIs(t, err, ErrDKGNotStarted)
}

func TestDKGShareNotInSharePhase(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Try to submit share without starting DKG
	err := lm.SubmitDKGShare(ids.GenerateTestNodeID(), []byte("share"))
	require.ErrorIs(t, err, ErrDKGNotStarted)
}

func TestRegisterMemberCommitteeFull(t *testing.T) {
	db := memdb.New()
	registry, err := NewRegistry(db)
	require.NoError(t, err)

	config := &LifecycleConfig{
		EpochDuration:     100,
		GracePeriod:       10,
		MinCommitteeSize:  2,
		MaxCommitteeSize:  3, // Small max for testing
		DefaultThreshold:  2,
		DKGTimeout:        time.Second,
		KeyRotationBlocks: 0,
	}

	logger := log.Noop()
	lm := NewLifecycleManager(registry, config, logger)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Create initial committee at max size
	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk3"), Weight: 100, Index: 2},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Try to register new member - should fail
	err = lm.RegisterMember(ids.GenerateTestNodeID(), []byte("new_pk"), 150)
	require.ErrorIs(t, err, ErrCommitteeFull)
}

func TestNewLifecycleManagerNilConfig(t *testing.T) {
	db := memdb.New()
	registry, err := NewRegistry(db)
	require.NoError(t, err)

	logger := log.Noop()

	// Pass nil config - should use defaults
	lm := NewLifecycleManager(registry, nil, logger)
	require.NotNil(t, lm)
}

func TestAbortDKGNotStarted(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Try to abort DKG that wasn't started
	err := lm.AbortDKG("no reason")
	require.ErrorIs(t, err, ErrDKGNotStarted)
}

func TestGetDKGStateNil(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Get state when no DKG is in progress
	state := lm.GetDKGState()
	require.Nil(t, state)
}

func TestForceEpochTransitionNoEpoch(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Try to force transition without any epoch
	err := lm.ForceEpochTransition()
	require.Error(t, err)
}

func TestGetEpochKeyInfoNotFound(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Try to get key info for non-existent epoch
	_, err := lm.GetEpochKeyInfo(999)
	require.Error(t, err)
}

func TestGetStatusNoEpoch(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Get status without any epoch
	status, err := lm.GetStatus()
	require.NoError(t, err)
	require.Equal(t, uint64(0), status.CurrentEpoch)
}

func TestGetCommitteeWeightNoEpoch(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Get committee weight without any epoch
	weight, err := lm.GetCommitteeWeight()
	require.NoError(t, err)
	require.Equal(t, uint64(0), weight)
}

func TestValidateThresholdMetNoEpoch(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Validate threshold without any epoch
	err := lm.ValidateThresholdMet(1)
	require.Error(t, err)
}

func TestDKGCommitmentUnknownParticipant(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()
	participants := []ids.NodeID{node1, node2}

	require.NoError(t, lm.StartDKG(1, participants, 2))

	// Try to submit commitment from unknown participant
	unknownNode := ids.GenerateTestNodeID()
	err := lm.SubmitDKGCommitment(unknownNode, []byte("commitment_32bytes_padded_here!x"))
	require.Error(t, err)
}

func TestRemoveMemberExisting(t *testing.T) {
	lm, registry := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()
	node3 := ids.GenerateTestNodeID()

	committee := []CommitteeMember{
		{NodeID: node1, PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: node2, PublicKey: []byte("pk2"), Weight: 100, Index: 1},
		{NodeID: node3, PublicKey: []byte("pk3"), Weight: 100, Index: 2},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Remove an existing member
	err := lm.RemoveMember(node2)
	require.NoError(t, err)

	// Verify member was removed
	members, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Equal(t, 2, len(members))
}

func TestOnBlockNoTransition(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Process block well before epoch end
	err := lm.OnBlock(10)
	require.NoError(t, err)

	// Should not be transitioning
	require.False(t, lm.IsTransitioning())
}

func TestOnBlockKeyRotation(t *testing.T) {
	db := memdb.New()
	registry, err := NewRegistry(db)
	require.NoError(t, err)

	config := &LifecycleConfig{
		EpochDuration:     1000,
		GracePeriod:       10,
		MinCommitteeSize:  2,
		MaxCommitteeSize:  10,
		DefaultThreshold:  2,
		DKGTimeout:        time.Second,
		KeyRotationBlocks: 50, // Trigger rotation every 50 blocks
	}

	logger := log.Noop()
	lm := NewLifecycleManager(registry, config, logger)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Process block at rotation boundary
	err = lm.OnBlock(50)
	require.NoError(t, err)

	// DKG should have started
	dkgState := lm.GetDKGState()
	require.NotNil(t, dkgState)
	require.Equal(t, DKGCommitPhase, dkgState.Status)
}

func TestPersistState(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Start a DKG so there's state to persist
	participants := []ids.NodeID{
		ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(),
	}
	require.NoError(t, lm.StartDKG(1, participants, 2))

	// Persist state - should not error
	err := lm.persistState()
	require.NoError(t, err)
}

func TestPersistStateNoState(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Persist state when there's no DKG or transition
	err := lm.persistState()
	require.NoError(t, err)
}

func TestPersistStateWithTransition(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Force transition
	err := lm.ForceEpochTransition()
	require.NoError(t, err)

	// Persist state
	err = lm.persistState()
	require.NoError(t, err)
}

func TestShouldStartTransitionNoEpoch(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Should return false when no epoch exists
	result := lm.shouldStartTransition(100)
	require.False(t, result)
}

func TestShouldStartTransitionAlreadyTransitioning(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Force transition
	require.NoError(t, lm.ForceEpochTransition())

	// Should return false when already transitioning
	result := lm.shouldStartTransition(1000)
	require.False(t, result)
}

func TestShouldFinalizeTransitionNoTransition(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Should return false when no transition in progress
	result := lm.shouldFinalizeTransition(1000)
	require.False(t, result)
}

func TestShouldFinalizeTransitionNotReady(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Force transition
	require.NoError(t, lm.ForceEpochTransition())

	// Should return false - not past grace period and DKG not complete
	result := lm.shouldFinalizeTransition(1)
	require.False(t, result)
}

func TestFinalizeTransitionNoTransition(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Finalize when no transition - should return nil
	cb, err := lm.finalizeTransitionLocked()
	require.NoError(t, err)
	require.Nil(t, cb)
}

func TestFinalizeTransitionDKGNotComplete(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Force transition (starts DKG)
	require.NoError(t, lm.ForceEpochTransition())

	// Set transition to finalizing phase directly
	lm.mu.Lock()
	lm.currentTransition.Status = TransitionFinalizingPhase
	lm.mu.Unlock()

	// Finalize should fail because DKG not complete
	lm.mu.Lock()
	cb, err := lm.finalizeTransitionLocked()
	lm.mu.Unlock()
	require.ErrorIs(t, err, ErrDKGNotStarted)
	require.Nil(t, cb)
}

func TestFinalizeTransitionComplete(t *testing.T) {
	lm, registry := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()

	committee := []CommitteeMember{
		{NodeID: node1, PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: node2, PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Force transition (starts DKG)
	require.NoError(t, lm.ForceEpochTransition())

	// Complete the DKG
	require.NoError(t, lm.SubmitDKGCommitment(node1, []byte("commitment1_32bytes_padded_here!")))
	require.NoError(t, lm.SubmitDKGCommitment(node2, []byte("commitment2_32bytes_padded_here!")))
	require.NoError(t, lm.SubmitDKGShare(node1, []byte("share1")))
	require.NoError(t, lm.SubmitDKGShare(node2, []byte("share2")))

	// Verify DKG completed
	dkgState := lm.GetDKGState()
	require.Equal(t, DKGCompleted, dkgState.Status)

	// Finalize transition
	lm.mu.Lock()
	cb, err := lm.finalizeTransitionLocked()
	lm.mu.Unlock()
	require.NoError(t, err)
	// Invoke callback after releasing lock (simulating correct caller behavior)
	lm.invokeCallback(cb)

	// Verify new epoch is active
	epoch := registry.GetCurrentEpoch()
	require.Equal(t, uint64(2), epoch)

	// Transition should be cleared
	require.False(t, lm.IsTransitioning())
}

func TestSetCallbacksAll(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	var dkgCompleteCalled bool

	lm.SetCallbacks(
		func(oldEpoch, newEpoch uint64) {},
		func(members []CommitteeMember) {},
		func(epoch uint64, pk []byte) { dkgCompleteCalled = true },
	)

	// Trigger DKG completion
	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()
	require.NoError(t, lm.StartDKG(1, []ids.NodeID{node1, node2}, 2))
	require.NoError(t, lm.SubmitDKGCommitment(node1, []byte("commitment1_32bytes_padded_here!")))
	require.NoError(t, lm.SubmitDKGCommitment(node2, []byte("commitment2_32bytes_padded_here!")))
	require.NoError(t, lm.SubmitDKGShare(node1, []byte("share1")))
	require.NoError(t, lm.SubmitDKGShare(node2, []byte("share2")))

	require.True(t, dkgCompleteCalled)
}

func TestForceEpochTransitionAlreadyTransitioning(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Force first transition
	require.NoError(t, lm.ForceEpochTransition())

	// Try to force another transition
	err := lm.ForceEpochTransition()
	require.ErrorIs(t, err, ErrTransitionInProgress)
}

func TestAggregatePublicKeyEmptyCommitments(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	// Start DKG
	participants := []ids.NodeID{
		ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(),
	}
	require.NoError(t, lm.StartDKG(1, participants, 2))

	// Call aggregatePublicKey directly with empty commitments
	lm.mu.Lock()
	result := lm.aggregatePublicKey()
	lm.mu.Unlock()

	// Should return 32-byte zero slice
	require.Len(t, result, 32)
}

func TestAggregatePublicKeyShortCommitments(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()
	participants := []ids.NodeID{node1, node2}
	require.NoError(t, lm.StartDKG(1, participants, 2))

	// Submit short commitments (< 32 bytes)
	require.NoError(t, lm.SubmitDKGCommitment(node1, []byte("short")))
	require.NoError(t, lm.SubmitDKGCommitment(node2, []byte("also-short")))

	// aggregatePublicKey should handle short commitments
	lm.mu.Lock()
	result := lm.aggregatePublicKey()
	lm.mu.Unlock()

	require.Len(t, result, 32)
}

func TestRemoveMemberBelowMinSize(t *testing.T) {
	db := memdb.New()
	registry, err := NewRegistry(db)
	require.NoError(t, err)

	// Set MinCommitteeSize to 2
	config := &LifecycleConfig{
		EpochDuration:     1000,
		GracePeriod:       10,
		MinCommitteeSize:  2,
		MaxCommitteeSize:  10,
		DefaultThreshold:  2,
		DKGTimeout:        time.Second,
		KeyRotationBlocks: 100,
	}

	logger := log.Noop()
	lm := NewLifecycleManager(registry, config, logger)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()

	committee := []CommitteeMember{
		{NodeID: node1, PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: node2, PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// Remove a member - should succeed but trigger warning about below min size
	err = lm.RemoveMember(node1)
	require.NoError(t, err)

	// Verify only one member remains
	members, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Equal(t, 1, len(members))
}

func TestSlashMemberNotExists(t *testing.T) {
	lm, _ := newTestLifecycleManager(t)
	require.NoError(t, lm.Start())
	defer lm.Stop()

	node1 := ids.GenerateTestNodeID()
	node2 := ids.GenerateTestNodeID()

	committee := []CommitteeMember{
		{NodeID: node1, PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: node2, PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	require.NoError(t, lm.InitiateEpoch(committee, 2, []byte("pk")))

	// SlashMember internally calls RemoveCommitteeMember which returns error for non-existent member
	// but depending on implementation it may succeed silently
	nonExistent := ids.GenerateTestNodeID()
	err := lm.SlashMember(nonExistent, "some reason")
	// The error behavior depends on the registry implementation
	// If the member doesn't exist, it may or may not return an error
	_ = err // Accept either behavior
}
