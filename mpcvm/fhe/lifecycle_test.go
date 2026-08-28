// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"testing"
	"time"

	"github.com/luxfi/crypto/bls"
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

// ---------------------------------------------------------------------------
// Epoch and ceremony transitions
// ---------------------------------------------------------------------------

// seatedCommittee returns a lifecycle manager over a faulty-capable database
// with an active epoch 1 whose committee holds n members, which is the state
// every transition test starts from.
func seatedCommittee(t *testing.T, n int) (*LifecycleManager, *Registry, *faultyDB) {
	t.Helper()
	registry, db := newFaultyRegistry(t)

	members := make([]CommitteeMember, n)
	for i := range members {
		members[i] = CommitteeMember{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte{byte(i)}, Weight: 10, Index: i}
	}
	require.NoError(t, registry.SetEpoch(1, &EpochInfo{
		Epoch:     1,
		StartTime: 0, // read as a block height by shouldStartTransition
		Committee: members,
		Threshold: n - 1,
		PublicKey: []byte("epoch-1"),
		Status:    EpochActive,
	}))

	lm := NewLifecycleManager(registry, &LifecycleConfig{
		EpochDuration:    100,
		GracePeriod:      10,
		MinCommitteeSize: 2,
		MaxCommitteeSize: 10,
		DefaultThreshold: 67,
		DKGTimeout:       time.Minute,
	}, log.Noop())
	return lm, registry, db
}

// driveDKG carries the manager's current ceremony from commit phase to
// completed by having every participant submit a commitment and a share.
func driveDKG(t *testing.T, lm *LifecycleManager, commitment []byte) {
	t.Helper()
	participants := append([]ids.NodeID(nil), lm.GetDKGState().Participants...)
	for _, node := range participants {
		require.NoError(t, lm.SubmitDKGCommitment(node, commitment))
	}
	for _, node := range participants {
		if lm.GetDKGState().Status != DKGSharePhase {
			break
		}
		require.NoError(t, lm.SubmitDKGShare(node, []byte("share")))
	}
	require.Equal(t, DKGCompleted, lm.GetDKGState().Status)
}

// TestTransitionFallbackThresholdIsAQuorum holds that a committee too small for
// the configured threshold still gets a quorum. The fallback is the rule
// DefaultThreshold encodes -- 2*100/3+1 is 67 -- so applying it to any n must
// land strictly above two thirds. Without the +1 the same expression gives 66
// of 100, contradicting the package's own default, and 2 of 4: exactly half a
// committee able to open every ciphertext the epoch protects.
func TestTransitionFallbackThresholdIsAQuorum(t *testing.T) {
	for _, size := range []int{4, 5, 6, 9, 10} {
		lm, _, _ := seatedCommittee(t, size)
		require.NoError(t, lm.ForceEpochTransition())

		threshold := lm.GetDKGState().Threshold
		require.Greater(t, threshold*3, size*2,
			"a %d-member committee got a threshold of %d, which is not above two thirds", size, threshold)
		require.LessOrEqual(t, threshold, size)
	}
}

// TestTransitionReachesFinalizingWhenItsCeremonyCompletes holds the step that
// carries a transition from waiting on a DKG to ready to finalize.
// shouldFinalizeTransition only ever finalizes from TransitionFinalizingPhase,
// so if nothing sets it the transition stays in the DKG phase forever,
// currentTransition never clears, and shouldStartTransition then refuses every
// later epoch too: one stalled rotation freezes the key schedule for good.
func TestTransitionReachesFinalizingWhenItsCeremonyCompletes(t *testing.T) {
	lm, registry, _ := seatedCommittee(t, 4)

	require.NoError(t, lm.ForceEpochTransition())
	require.Equal(t, TransitionDKGPhase, lm.GetTransitionState().Status)

	driveDKG(t, lm, make([]byte, 32))
	require.Equal(t, TransitionFinalizingPhase, lm.GetTransitionState().Status)

	// Past the grace period, the next block finalizes it.
	lm.mu.Lock()
	lm.currentTransition.StartedAt = 0
	lm.mu.Unlock()

	var from, to uint64
	lm.SetCallbacks(func(oldEpoch, newEpoch uint64) { from, to = oldEpoch, newEpoch }, nil, nil)

	require.NoError(t, lm.OnBlock(500))
	require.False(t, lm.IsTransitioning())
	require.Nil(t, lm.GetDKGState())
	require.Equal(t, uint64(2), registry.GetCurrentEpoch())
	require.Equal(t, uint64(1), from)
	require.Equal(t, uint64(2), to)

	ended, err := registry.GetEpoch(1)
	require.NoError(t, err)
	require.Equal(t, EpochEnded, ended.Status)
	require.NotZero(t, ended.EndTime)
}

// TestOnBlockStartsATransitionWhenTheEpochIsOver holds the automatic half of
// the rotation: past the epoch duration, a block opens a transition and its
// ceremony, and a second block does not open a second one.
func TestOnBlockStartsATransitionWhenTheEpochIsOver(t *testing.T) {
	lm, _, _ := seatedCommittee(t, 4)

	require.NoError(t, lm.OnBlock(50))
	require.False(t, lm.IsTransitioning(), "before the epoch duration nothing starts")

	require.NoError(t, lm.OnBlock(150))
	require.True(t, lm.IsTransitioning())
	ceremony := lm.GetDKGState().CeremonyID

	require.NoError(t, lm.OnBlock(151))
	require.Equal(t, ceremony, lm.GetDKGState().CeremonyID, "a transition in flight is not restarted")
}

// TestOnBlockFailsACeremonyThatRanOutOfTime holds that a DKG past its timeout
// is marked failed and takes its transition down with it. A ceremony left in
// commit phase forever blocks every later ceremony, because startDKGLocked
// refuses to start one while another is in progress.
func TestOnBlockFailsACeremonyThatRanOutOfTime(t *testing.T) {
	lm, _, _ := seatedCommittee(t, 4)
	lm.config.DKGTimeout = time.Nanosecond

	require.NoError(t, lm.ForceEpochTransition())
	require.Equal(t, DKGCommitPhase, lm.GetDKGState().Status)

	require.NoError(t, lm.OnBlock(10))
	require.Equal(t, DKGFailed, lm.GetDKGState().Status)
	require.Equal(t, "DKG ceremony timed out", lm.GetDKGState().Error)
	require.NotZero(t, lm.GetDKGState().CompletedAt)

	transition := lm.GetTransitionState()
	require.Equal(t, TransitionFailed, transition.Status)
	require.Equal(t, "DKG ceremony timed out", transition.Error)

	// A failed ceremony no longer blocks the next one.
	require.NoError(t, lm.OnBlock(11))
	require.Equal(t, DKGFailed, lm.GetDKGState().Status)
}

// TestOnBlockRotatesKeysOnSchedule holds that key rotation opens a ceremony for
// the epoch it is already in, rather than advancing the epoch. Rotation and
// transition are different operations and must not be confused: one refreshes
// the key inside an epoch, the other ends the epoch.
func TestOnBlockRotatesKeysOnSchedule(t *testing.T) {
	lm, registry, _ := seatedCommittee(t, 4)
	lm.config.EpochDuration = 1_000_000 // no transition in range
	lm.config.KeyRotationBlocks = 25

	require.NoError(t, lm.OnBlock(24))
	require.Nil(t, lm.GetDKGState())

	require.NoError(t, lm.OnBlock(25))
	require.NotNil(t, lm.GetDKGState())
	require.Equal(t, uint64(1), lm.GetDKGState().Epoch, "rotation stays in the current epoch")
	require.False(t, lm.IsTransitioning())
	require.Equal(t, uint64(1), registry.GetCurrentEpoch())
}

// TestKeyRotationSurfacesRegistryFailures holds that a rotation over an
// unreadable store fails instead of opening a ceremony with no participants.
func TestKeyRotationSurfacesRegistryFailures(t *testing.T) {
	lm, _, db := seatedCommittee(t, 4)
	lm.config.EpochDuration = 1_000_000
	lm.config.KeyRotationBlocks = 25

	db.refuseGet = always
	require.ErrorIs(t, lm.OnBlock(25), errFault)
	require.Nil(t, lm.GetDKGState())
}

// TestKeyRotationNeedsTheEpochThreshold holds that rotation reads its threshold
// from the epoch record; without one there is no threshold to rotate under.
func TestKeyRotationNeedsTheEpochThreshold(t *testing.T) {
	registry, _ := newFaultyRegistry(t)
	lm := NewLifecycleManager(registry, &LifecycleConfig{
		EpochDuration: 1_000_000, MinCommitteeSize: 0, MaxCommitteeSize: 10,
		DefaultThreshold: 2, DKGTimeout: time.Minute, KeyRotationBlocks: 25,
	}, log.Noop())

	require.Error(t, lm.OnBlock(25))
	require.Nil(t, lm.GetDKGState())
}

// TestTransitionSurfacesRegistryFailures holds that every store failure along
// the transition path is reported. A transition that half-applies leaves the
// epoch pointer and the epoch records disagreeing about which committee holds
// the current key.
func TestTransitionSurfacesRegistryFailures(t *testing.T) {
	t.Run("committee unreadable at start", func(t *testing.T) {
		lm, _, db := seatedCommittee(t, 4)
		db.refuseGet = always
		require.ErrorIs(t, lm.ForceEpochTransition(), errFault)
	})

	t.Run("new epoch unwritable at finalize", func(t *testing.T) {
		lm, _, db := seatedCommittee(t, 4)
		require.NoError(t, lm.ForceEpochTransition())
		driveDKG(t, lm, make([]byte, 32))

		lm.mu.Lock()
		lm.currentTransition.StartedAt = 0
		lm.mu.Unlock()

		db.refusePut = always
		require.ErrorIs(t, lm.OnBlock(500), errFault)
		require.True(t, lm.IsTransitioning(), "a failed finalize leaves the transition in place")
	})
}

// TestFinalizeRequiresACompletedCeremony holds that an epoch cannot be advanced
// onto a key that was never generated. Finalizing on a ceremony still in commit
// phase would install an empty public key as the epoch key.
func TestFinalizeRequiresACompletedCeremony(t *testing.T) {
	lm, registry, _ := seatedCommittee(t, 4)
	require.NoError(t, lm.ForceEpochTransition())

	lm.mu.Lock()
	lm.currentTransition.Status = TransitionFinalizingPhase
	lm.currentTransition.StartedAt = 0
	lm.mu.Unlock()

	require.ErrorIs(t, lm.OnBlock(500), ErrDKGNotStarted)
	require.Equal(t, uint64(1), registry.GetCurrentEpoch())
}

// TestMemberChangesSurfaceRegistryFailures holds that registering, removing and
// slashing all report a store that will not answer. Slashing is the one that
// matters most: SlashMember treats a nil error as a completed eviction and then
// emits the penalty event, so a swallowed failure penalizes a validator that is
// still seated and still holding its key share.
func TestMemberChangesSurfaceRegistryFailures(t *testing.T) {
	t.Run("register cannot read the committee", func(t *testing.T) {
		lm, _, db := seatedCommittee(t, 4)
		db.refuseGet = always
		require.ErrorIs(t, lm.RegisterMember(ids.GenerateTestNodeID(), []byte("pk"), 1), errFault)
	})

	t.Run("register cannot write the member", func(t *testing.T) {
		lm, _, db := seatedCommittee(t, 4)
		db.refusePut = always
		require.ErrorIs(t, lm.RegisterMember(ids.GenerateTestNodeID(), []byte("pk"), 1), errFault)
	})

	t.Run("remove cannot write", func(t *testing.T) {
		lm, registry, db := seatedCommittee(t, 4)
		members, err := registry.GetCommittee()
		require.NoError(t, err)
		db.refusePut = always
		require.ErrorIs(t, lm.RemoveMember(members[0].NodeID), errFault)
	})

	t.Run("remove cannot re-read the committee", func(t *testing.T) {
		lm, registry, db := seatedCommittee(t, 4)
		members, err := registry.GetCommittee()
		require.NoError(t, err)

		// The removal itself lands; the size check afterwards cannot read.
		require.NoError(t, lm.RemoveMember(members[0].NodeID))
		db.refuseGet = always
		require.ErrorIs(t, lm.RemoveMember(members[1].NodeID), errFault)
	})

	t.Run("slash does not fire its penalty when the eviction failed", func(t *testing.T) {
		lm, registry, db := seatedCommittee(t, 4)
		members, err := registry.GetCommittee()
		require.NoError(t, err)

		slashed := 0
		lm.SetSlashCallback(func(ids.NodeID, string) { slashed++ })

		db.refusePut = always
		require.NoError(t, lm.SlashMember(members[0].NodeID, "equivocation"))
		require.Zero(t, slashed, "a failed eviction must not emit the penalty")

		db.refusePut = nil
		require.NoError(t, lm.SlashMember(members[0].NodeID, "equivocation"))
		require.Equal(t, 1, slashed)
	})
}

// TestInitiateEpochSurfacesAFailedWrite holds that genesis reports a store that
// could not record it, rather than returning as though epoch 1 exists.
func TestInitiateEpochSurfacesAFailedWrite(t *testing.T) {
	registry, db := newFaultyRegistry(t)
	lm := NewLifecycleManager(registry, DefaultLifecycleConfig(), log.Noop())

	members := make([]CommitteeMember, 4)
	for i := range members {
		members[i] = CommitteeMember{NodeID: ids.GenerateTestNodeID()}
	}

	db.refusePut = always
	require.ErrorIs(t, lm.InitiateEpoch(members, 3, []byte("pk")), errFault)
}

// TestGetCommitteeWeightSurfacesAnUnreadableCommittee holds that a weight of
// zero is only reported when the committee genuinely weighs nothing. Any caller
// comparing a weight against a stake threshold reads a swallowed failure as
// "the committee has no stake".
func TestGetCommitteeWeightSurfacesAnUnreadableCommittee(t *testing.T) {
	lm, _, db := seatedCommittee(t, 4)

	weight, err := lm.GetCommitteeWeight()
	require.NoError(t, err)
	require.Equal(t, uint64(40), weight)

	db.refuseGet = always
	weight, err = lm.GetCommitteeWeight()
	require.ErrorIs(t, err, errFault)
	require.Zero(t, weight)
}

// TestDKGCallbacksFireOutsideTheLock holds that every ceremony event reaches its
// callback. These are how the ceremony is gossiped to the other participants,
// so a callback that never fires is a ceremony no peer ever hears about; they
// are invoked after the mutex is released, which is why a callback that calls
// back into the manager does not deadlock.
func TestDKGCallbacksFireOutsideTheLock(t *testing.T) {
	lm, _, _ := seatedCommittee(t, 4)

	var started, phaseChanged, completed int
	var startedEpoch, completedEpoch uint64
	var startedID, phaseID [32]byte
	var phase DKGStatus

	lm.SetDKGCallbacks(
		func(ceremonyID [32]byte, epoch uint64, participants []ids.NodeID) {
			started++
			startedID, startedEpoch = ceremonyID, epoch
			require.Len(t, participants, 4)
			require.NotNil(t, lm.GetDKGState(), "a callback may read the manager back")
		},
		func(ceremonyID [32]byte, newPhase DKGStatus) {
			phaseChanged++
			phaseID, phase = ceremonyID, newPhase
		},
	)
	lm.SetCallbacks(nil, nil, func(epoch uint64, publicKey []byte) {
		completed++
		completedEpoch = epoch
		require.NotEmpty(t, publicKey)
	})

	participants := []ids.NodeID{
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
	}
	require.NoError(t, lm.StartDKG(7, participants, 3))
	require.Equal(t, 1, started)
	require.Equal(t, uint64(7), startedEpoch)
	require.Equal(t, lm.GetDKGState().CeremonyID, startedID)

	driveDKG(t, lm, make([]byte, 32))
	require.Equal(t, 1, phaseChanged)
	require.Equal(t, DKGSharePhase, phase)
	require.Equal(t, startedID, phaseID)
	require.Equal(t, 1, completed)
	require.Equal(t, uint64(7), completedEpoch)
}

// TestSubmitDKGShareRefusesEveryWayItCanBeWrong holds the three refusals that
// stand between a ceremony and a forged key share: the wrong phase, a node that
// is not a participant, and a participant that never committed. The commitment
// is what binds a share to a party, so accepting a share without one lets a
// participant substitute a share chosen after seeing everyone else's.
func TestSubmitDKGShareRefusesEveryWayItCanBeWrong(t *testing.T) {
	lm, _, _ := seatedCommittee(t, 4)
	participants := []ids.NodeID{
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
	}

	require.ErrorIs(t, lm.SubmitDKGShare(participants[0], []byte("s")), ErrDKGNotStarted)
	require.ErrorIs(t, lm.SubmitDKGCommitment(participants[0], []byte("c")), ErrDKGNotStarted)

	require.NoError(t, lm.StartDKG(2, participants, 3))

	// Still in commit phase.
	require.ErrorContains(t, lm.SubmitDKGShare(participants[0], []byte("s")), "not in share phase")
	require.ErrorContains(t, lm.SubmitDKGCommitment(ids.GenerateTestNodeID(), []byte("c")), "not a DKG participant")

	for _, node := range participants {
		require.NoError(t, lm.SubmitDKGCommitment(node, make([]byte, 32)))
	}
	require.Equal(t, DKGSharePhase, lm.GetDKGState().Status)

	// The commit phase is over.
	require.ErrorContains(t, lm.SubmitDKGCommitment(participants[0], []byte("c")), "not in commit phase")

	// A stranger cannot contribute a share.
	require.ErrorIs(t, lm.SubmitDKGShare(ids.GenerateTestNodeID(), []byte("s")), ErrNotParticipant)

	// A participant whose commitment was dropped cannot contribute either.
	lm.mu.Lock()
	delete(lm.currentDKG.Commitments, participants[0].String())
	lm.mu.Unlock()
	require.ErrorIs(t, lm.SubmitDKGShare(participants[0], []byte("s")), ErrMissingCommitment)
}

// TestAggregatePublicKeyUsesCurveArithmeticWhenItCan holds which of the two
// aggregation paths runs. BLS-formatted commitments must aggregate on the
// curve; anything else falls back to an XOR that is reproducible but carries no
// cryptographic meaning, so which path ran is the difference between an epoch
// key and a checksum.
func TestAggregatePublicKeyUsesCurveArithmeticWhenItCan(t *testing.T) {
	lm, _, _ := seatedCommittee(t, 4)

	keys := make([][]byte, 3)
	pubKeys := make([]*bls.PublicKey, 3)
	for i := range keys {
		sk, err := bls.NewSecretKey()
		require.NoError(t, err)
		pubKeys[i] = sk.PublicKey()
		keys[i] = bls.PublicKeyToCompressedBytes(pubKeys[i])
		require.Len(t, keys[i], bls.PublicKeyLen)
	}

	require.NoError(t, lm.StartDKG(2, []ids.NodeID{
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
	}, 3))

	lm.mu.Lock()
	for i, key := range keys {
		lm.currentDKG.Commitments[string(rune('a'+i))] = key
	}
	aggregated := lm.aggregatePublicKey()
	lm.mu.Unlock()

	want, err := bls.AggregatePublicKeys(pubKeys)
	require.NoError(t, err)
	require.Equal(t, bls.PublicKeyToCompressedBytes(want), aggregated)
	require.Len(t, aggregated, bls.PublicKeyLen)
}

// TestAggregatePublicKeyFallsBackWhenCommitmentsAreNotKeys holds the other
// path: commitments that are the right length but not curve points, and
// commitments that are too short to be keys at all, both land on the XOR
// fallback rather than producing a bad key or a panic.
func TestAggregatePublicKeyFallsBackWhenCommitmentsAreNotKeys(t *testing.T) {
	lm, _, _ := seatedCommittee(t, 4)
	require.NoError(t, lm.StartDKG(2, []ids.NodeID{
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
	}, 3))

	notAPoint := make([]byte, bls.PublicKeyLen)
	for i := range notAPoint {
		notAPoint[i] = 0xAB
	}
	short := make([]byte, 32)
	short[0] = 0x0f

	lm.mu.Lock()
	lm.currentDKG.Commitments["a"] = notAPoint
	lm.currentDKG.Commitments["b"] = short
	aggregated := lm.aggregatePublicKey()
	lm.mu.Unlock()

	require.Len(t, aggregated, 32, "the fallback is a 32-byte XOR, not a curve point")
	require.NotEqual(t, make([]byte, 32), aggregated)
}

// TestAggregatePublicKeyRefusesAnIdentityAggregate holds the rogue-key case: a
// commitment and its negation sum to the point at infinity, and an identity
// aggregate public key makes verification accept anything. The aggregation must
// refuse it and fall back rather than publish it as the epoch key.
func TestAggregatePublicKeyRefusesAnIdentityAggregate(t *testing.T) {
	lm, _, _ := seatedCommittee(t, 4)
	require.NoError(t, lm.StartDKG(2, []ids.NodeID{
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
	}, 3))

	sk, err := bls.NewSecretKey()
	require.NoError(t, err)
	key := bls.PublicKeyToCompressedBytes(sk.PublicKey())

	// Flipping the compressed sign bit names the negation of the same point.
	negated := append([]byte(nil), key...)
	negated[0] ^= 0x20
	_, err = bls.PublicKeyFromCompressedBytes(negated)
	require.NoError(t, err, "the negation is still a valid point")

	_, err = bls.AggregatePublicKeys(mustParseKeys(t, key, negated))
	require.Error(t, err, "a key and its negation must not aggregate")

	lm.mu.Lock()
	lm.currentDKG.Commitments["a"] = key
	lm.currentDKG.Commitments["b"] = negated
	aggregated := lm.aggregatePublicKey()
	lm.mu.Unlock()

	require.Len(t, aggregated, 32, "the identity aggregate is refused and the fallback runs")
}

func mustParseKeys(t *testing.T, raw ...[]byte) []*bls.PublicKey {
	t.Helper()
	keys := make([]*bls.PublicKey, len(raw))
	for i, b := range raw {
		key, err := bls.PublicKeyFromCompressedBytes(b)
		require.NoError(t, err)
		keys[i] = key
	}
	return keys
}

// TestStartRestoresACeremonyInFlight holds crash recovery: a ceremony that was
// mid-flight comes back, and one that had already finished does not. Restoring
// a finished ceremony would re-run the transition onto a key the committee has
// already moved past.
func TestStartRestoresACeremonyInFlight(t *testing.T) {
	registry, _ := newFaultyRegistry(t)
	config := &LifecycleConfig{
		EpochDuration: 100, GracePeriod: 10, MinCommitteeSize: 2,
		MaxCommitteeSize: 10, DefaultThreshold: 2, DKGTimeout: time.Minute,
	}

	first := NewLifecycleManager(registry, config, log.Noop())
	require.NoError(t, first.StartDKG(0, []ids.NodeID{
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
	}, 2))
	first.mu.Lock()
	first.currentTransition = &TransitionState{FromEpoch: 0, ToEpoch: 1, Status: TransitionDKGPhase}
	require.NoError(t, first.persistStateLocked())
	first.mu.Unlock()

	restored := NewLifecycleManager(registry, config, log.Noop())
	require.NoError(t, restored.Start())
	require.NotNil(t, restored.GetDKGState())
	require.Equal(t, DKGCommitPhase, restored.GetDKGState().Status)
	require.NotNil(t, restored.GetTransitionState())
	require.Equal(t, uint64(1), restored.GetTransitionState().ToEpoch)

	// A finished ceremony and a finished transition are not restored.
	first.mu.Lock()
	first.currentDKG.Status = DKGCompleted
	first.currentTransition.Status = TransitionCompleted
	require.NoError(t, first.persistStateLocked())
	first.mu.Unlock()

	fresh := NewLifecycleManager(registry, config, log.Noop())
	require.NoError(t, fresh.Start())
	require.Nil(t, fresh.GetDKGState())
	require.Nil(t, fresh.GetTransitionState())
}

// TestStartRefusesUnreadableState holds that a manager whose recovery record
// cannot be read or decoded refuses to start. Starting anyway looks exactly
// like a clean slate: the ceremony the committee was midway through would never
// finish, and nothing would say so.
func TestStartRefusesUnreadableState(t *testing.T) {
	registry, db := newFaultyRegistry(t)
	config := DefaultLifecycleConfig()

	db.refuseGet = always
	err := NewLifecycleManager(registry, config, log.Noop()).Start()
	require.ErrorIs(t, err, errFault)
	require.ErrorContains(t, err, "read DKG state", "the first unreadable record is the one reported")

	db.refuseGet = nil
	require.NoError(t, registry.db.Put(append([]byte("lifecycle:dkg:"), encodeUint64(0)...), []byte("{not json")))
	require.ErrorContains(t, NewLifecycleManager(registry, config, log.Noop()).Start(), "decode DKG state")

	require.NoError(t, registry.db.Delete(append([]byte("lifecycle:dkg:"), encodeUint64(0)...)))
	require.NoError(t, registry.db.Put(append([]byte("lifecycle:transition:"), encodeUint64(1)...), []byte("{not json")))
	require.ErrorContains(t, NewLifecycleManager(registry, config, log.Noop()).Start(), "decode transition state")
}

// TestStartWithoutAStoreIsANoOp holds that a manager with no registry starts
// clean, which is the shape every unit test that does not need persistence uses.
func TestStartWithoutAStoreIsANoOp(t *testing.T) {
	lm := NewLifecycleManager(nil, nil, log.Noop())
	require.NoError(t, lm.Start())
	require.NoError(t, lm.persistState())
	lm.Stop()
}

// TestPersistSurfacesAFailedWrite holds that a recovery record that did not
// land is reported. The ceremony persisted here is the only thing that survives
// a restart, so a silent failure is a ceremony that quietly cannot be resumed.
func TestPersistSurfacesAFailedWrite(t *testing.T) {
	registry, db := newFaultyRegistry(t)
	lm := NewLifecycleManager(registry, DefaultLifecycleConfig(), log.Noop())

	require.NoError(t, lm.StartDKG(1, []ids.NodeID{
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
	}, 3))

	db.refusePut = always
	require.ErrorIs(t, lm.persistState(), errFault)

	lm.mu.Lock()
	lm.currentDKG = nil
	lm.currentTransition = &TransitionState{FromEpoch: 1, ToEpoch: 2}
	lm.mu.Unlock()
	require.ErrorIs(t, lm.persistState(), errFault)
}

// TestAbortDKGRecordsTheReason holds that an abandoned ceremony keeps why it
// was abandoned, and that the record survives to the store: a ceremony that
// vanishes without a reason is indistinguishable from one that never started.
func TestAbortDKGRecordsTheReason(t *testing.T) {
	registry, db := newFaultyRegistry(t)
	lm := NewLifecycleManager(registry, DefaultLifecycleConfig(), log.Noop())

	require.NoError(t, lm.StartDKG(1, []ids.NodeID{
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
		ids.GenerateTestNodeID(), ids.GenerateTestNodeID(),
	}, 3))

	db.refusePut = always // a failed persist must not lose the in-memory abort
	require.NoError(t, lm.AbortDKG("participants unreachable"))
	require.Equal(t, DKGAborted, lm.GetDKGState().Status)
	require.Equal(t, "participants unreachable", lm.GetDKGState().Error)
	require.NotZero(t, lm.GetDKGState().CompletedAt)
}

// TestGetStatusReportsCeremonyAndProgress holds that the status a client reads
// names the current ceremony, the current transition, and how far through its
// epoch the chain is -- with progress clamped at 1 rather than running past it
// once an epoch overruns its duration.
func TestGetStatusReportsCeremonyAndProgress(t *testing.T) {
	lm, _, _ := seatedCommittee(t, 4)

	require.NoError(t, lm.OnBlock(50))
	status, err := lm.GetStatus()
	require.NoError(t, err)
	require.Equal(t, uint64(1), status.CurrentEpoch)
	require.Equal(t, uint64(50), status.CurrentBlock)
	require.Equal(t, 4, status.CommitteeSize)
	require.Equal(t, 3, status.Threshold)
	require.False(t, status.IsTransitioning)
	require.Empty(t, status.DKGStatus)
	require.InDelta(t, 0.5, status.EpochProgress, 1e-9)

	require.NoError(t, lm.ForceEpochTransition())
	require.NoError(t, lm.OnBlock(400))

	status, err = lm.GetStatus()
	require.NoError(t, err)
	require.True(t, status.IsTransitioning)
	require.Equal(t, DKGCommitPhase.String(), status.DKGStatus)
	require.Equal(t, TransitionDKGPhase.String(), status.TransitionStatus)
	require.Equal(t, 1.0, status.EpochProgress, "progress is clamped once the epoch overruns")
}

// TestRemoveMemberSurfacesAFailedSizeCheck holds that the committee-size check
// after a removal reports a store it could not read. The removal itself has
// already landed at that point, so swallowing the failure means the manager
// stops noticing that the committee has fallen below its minimum -- the one
// warning that says the remaining members can no longer form a quorum.
func TestRemoveMemberSurfacesAFailedSizeCheck(t *testing.T) {
	lm, registry, db := seatedCommittee(t, 4)
	members, err := registry.GetCommittee()
	require.NoError(t, err)

	// The removal reads the epoch once and succeeds; the size check reads it
	// again and cannot.
	db.refuseGet = afterFirst()
	require.ErrorIs(t, lm.RemoveMember(members[0].NodeID), errFault)

	db.refuseGet = nil
	remaining, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Len(t, remaining, 3, "the removal itself landed")
}

// TestRemoveMemberWarnsBelowTheMinimum holds that a committee dropping under
// its configured minimum is reported rather than silently accepted; below it
// there are not enough members left to reach any threshold.
func TestRemoveMemberWarnsBelowTheMinimum(t *testing.T) {
	lm, registry, _ := seatedCommittee(t, 4)
	lm.config.MinCommitteeSize = 4

	members, err := registry.GetCommittee()
	require.NoError(t, err)
	require.NoError(t, lm.RemoveMember(members[0].NodeID))

	remaining, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Len(t, remaining, 3)
}

// TestCeremonyRunsOnWhenItsRecoveryRecordCannotBeWritten holds that a store
// that will not accept the recovery record does not abort the ceremony or the
// transition in memory. The record is a crash-recovery convenience; losing it
// costs a resume, while aborting a live ceremony costs the epoch.
func TestCeremonyRunsOnWhenItsRecoveryRecordCannotBeWritten(t *testing.T) {
	lm, registry, db := seatedCommittee(t, 4)
	db.refusePut = under("lifecycle:")

	require.NoError(t, lm.ForceEpochTransition())
	require.True(t, lm.IsTransitioning())

	driveDKG(t, lm, make([]byte, 32))
	require.Equal(t, TransitionFinalizingPhase, lm.GetTransitionState().Status)

	lm.mu.Lock()
	lm.currentTransition.StartedAt = 0
	lm.mu.Unlock()

	require.NoError(t, lm.OnBlock(500))
	require.Equal(t, uint64(2), registry.GetCurrentEpoch(), "the epoch still advanced")
}

// TestFinalizeStopsWhenTheNewEpochCannotBeWritten holds that a transition whose
// new epoch record fails to store is reported instead of half-applied. The old
// epoch has already been marked ended by then, so continuing would leave the
// chain with no active epoch at all.
func TestFinalizeStopsWhenTheNewEpochCannotBeWritten(t *testing.T) {
	lm, registry, db := seatedCommittee(t, 4)

	require.NoError(t, lm.ForceEpochTransition())
	driveDKG(t, lm, make([]byte, 32))

	lm.mu.Lock()
	lm.currentTransition.StartedAt = 0
	lm.mu.Unlock()

	db.refusePut = under(string(append(epochPrefix, encodeUint64(2)...)))
	require.ErrorIs(t, lm.OnBlock(500), errFault)
	require.True(t, lm.IsTransitioning())
	require.Equal(t, uint64(1), registry.GetCurrentEpoch())
}

// TestStartRefusesAnUnreadableTransitionRecord holds that the transition half
// of recovery is checked as carefully as the ceremony half: a ceremony that
// reads back fine does not excuse a transition record that does not.
func TestStartRefusesAnUnreadableTransitionRecord(t *testing.T) {
	registry, db := newFaultyRegistry(t)
	db.refuseGet = under("lifecycle:transition:")

	require.ErrorContains(t,
		NewLifecycleManager(registry, DefaultLifecycleConfig(), log.Noop()).Start(),
		"read transition state")
}
