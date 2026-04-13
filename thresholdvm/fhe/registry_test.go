// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"testing"
	"time"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func newTestRegistry(t *testing.T) *Registry {
	db := memdb.New()
	registry, err := NewRegistry(db)
	require.NoError(t, err)
	return registry
}

func TestRegistryInit(t *testing.T) {
	registry := newTestRegistry(t)
	require.NotNil(t, registry)
	require.Equal(t, uint64(0), registry.GetCurrentEpoch())
}

func TestRegistryCiphertextMeta(t *testing.T) {
	registry := newTestRegistry(t)

	meta := &CiphertextMeta{
		Handle:  [32]byte{1, 2, 3, 4},
		Owner:   [20]byte{0xaa, 0xbb},
		Type:    1,
		Level:   14,
		Size:    1024,
		ChainID: ids.GenerateTestID(),
	}

	// Register ciphertext
	err := registry.RegisterCiphertext(meta)
	require.NoError(t, err)

	// Retrieve ciphertext
	retrieved, err := registry.GetCiphertextMeta(meta.Handle)
	require.NoError(t, err)
	require.Equal(t, meta.Handle, retrieved.Handle)
	require.Equal(t, meta.Owner, retrieved.Owner)
	require.Equal(t, meta.Type, retrieved.Type)
	require.Equal(t, meta.Level, retrieved.Level)
	require.Equal(t, meta.Size, retrieved.Size)

	// Test not found
	_, err = registry.GetCiphertextMeta([32]byte{0xff})
	require.ErrorIs(t, err, ErrCiphertextNotFound)

	// Delete ciphertext
	err = registry.DeleteCiphertext(meta.Handle)
	require.NoError(t, err)

	_, err = registry.GetCiphertextMeta(meta.Handle)
	require.ErrorIs(t, err, ErrCiphertextNotFound)
}

func TestRegistryDecryptRequest(t *testing.T) {
	registry := newTestRegistry(t)

	req := &DecryptRequest{
		RequestID:        [32]byte{1, 2, 3, 4, 5, 6, 7, 8},
		CiphertextHandle: [32]byte{0xaa, 0xbb},
		Requester:        [20]byte{0x11, 0x22},
		Callback:         [20]byte{0x33, 0x44},
		CallbackSelector: [4]byte{0xa, 0xb, 0xc, 0xd},
		SourceChain:      ids.GenerateTestID(),
		Nonce:            1,
		Expiry:           time.Now().Add(time.Hour).Unix(),
	}

	// Create request
	err := registry.CreateDecryptRequest(req)
	require.NoError(t, err)

	// Retrieve request
	retrieved, err := registry.GetDecryptRequest(req.RequestID)
	require.NoError(t, err)
	require.Equal(t, req.RequestID, retrieved.RequestID)
	require.Equal(t, req.CiphertextHandle, retrieved.CiphertextHandle)
	require.Equal(t, RequestPending, retrieved.Status)

	// Update status
	resultHandle := [32]byte{0xde, 0xad, 0xbe, 0xef}
	err = registry.UpdateDecryptRequest(req.RequestID, RequestCompleted, resultHandle, "")
	require.NoError(t, err)

	retrieved, err = registry.GetDecryptRequest(req.RequestID)
	require.NoError(t, err)
	require.Equal(t, RequestCompleted, retrieved.Status)
	require.Equal(t, resultHandle, retrieved.ResultHandle)

	// Test not found
	_, err = registry.GetDecryptRequest([32]byte{0xff})
	require.ErrorIs(t, err, ErrRequestNotFound)
}

func TestRegistryPermit(t *testing.T) {
	registry := newTestRegistry(t)

	permitID := [32]byte{0x11, 0x22, 0x33}
	handle := [32]byte{0x44, 0x55}
	grantee := [20]byte{0xcc, 0xdd}

	permit := &Permit{
		PermitID:   permitID,
		Handle:     handle,
		Grantee:    grantee,
		Grantor:    [20]byte{0xaa, 0xbb},
		Operations: PermitOpDecrypt | PermitOpReencrypt,
		Expiry:     time.Now().Add(time.Hour).Unix(),
		ChainID:    ids.GenerateTestID(),
	}

	// Create permit
	err := registry.CreatePermit(permit)
	require.NoError(t, err)

	// Get permit
	retrieved, err := registry.GetPermit(permit.PermitID)
	require.NoError(t, err)
	require.Equal(t, permit.PermitID, retrieved.PermitID)
	require.Equal(t, permit.Handle, retrieved.Handle)
	require.Equal(t, permit.Grantee, retrieved.Grantee)

	// Verify permit - valid operation
	err = registry.VerifyPermit(permitID, handle, grantee, PermitOpDecrypt)
	require.NoError(t, err)

	// Verify permit - wrong handle
	err = registry.VerifyPermit(permitID, [32]byte{0xff}, grantee, PermitOpDecrypt)
	require.Error(t, err)

	// Verify permit - wrong grantee
	err = registry.VerifyPermit(permitID, handle, [20]byte{0xff}, PermitOpDecrypt)
	require.Error(t, err)

	// Verify permit - disallowed operation
	err = registry.VerifyPermit(permitID, handle, grantee, PermitOpTransfer)
	require.Error(t, err)
}

func TestRegistryEpoch(t *testing.T) {
	registry := newTestRegistry(t)

	info := &EpochInfo{
		Epoch:     1,
		StartTime: time.Now().Unix(),
		Threshold: 67,
		PublicKey: []byte{0x04, 0xaa, 0xbb, 0xcc},
		Status:    EpochActive,
	}

	// Set epoch
	err := registry.SetEpoch(1, info)
	require.NoError(t, err)

	// Get epoch
	retrieved, err := registry.GetEpoch(1)
	require.NoError(t, err)
	require.Equal(t, uint64(1), retrieved.Epoch)
	require.Equal(t, 67, retrieved.Threshold)

	// Current epoch should be updated
	require.Equal(t, uint64(1), registry.GetCurrentEpoch())

	// Set higher epoch
	info2 := &EpochInfo{Epoch: 2, Threshold: 67, Status: EpochActive}
	err = registry.SetEpoch(2, info2)
	require.NoError(t, err)
	require.Equal(t, uint64(2), registry.GetCurrentEpoch())
}

// TestRegistryCommittee is covered by TestRegistryCommitteeFromEpoch
// since committee is embedded in EpochInfo

func TestRequestStatusString(t *testing.T) {
	require.Equal(t, "pending", RequestPending.String())
	require.Equal(t, "processing", RequestProcessing.String())
	require.Equal(t, "completed", RequestCompleted.String())
	require.Equal(t, "failed", RequestFailed.String())
	require.Equal(t, "expired", RequestExpired.String())
	require.Equal(t, "unknown", RequestStatus(99).String())
}

func TestRegistrySessionSaveAndGet(t *testing.T) {
	registry := newTestRegistry(t)

	session := &SessionState{
		SessionID:        "session-123",
		CiphertextHandle: [32]byte{0xaa, 0xbb, 0xcc},
		Threshold:        67,
		Participants:     []ids.NodeID{ids.GenerateTestNodeID(), ids.GenerateTestNodeID()},
		SharesReceived:   0,
		Status:           SessionActive,
	}

	// Save session
	err := registry.SaveSession(session)
	require.NoError(t, err)

	// Get session
	retrieved, err := registry.GetSession("session-123")
	require.NoError(t, err)
	require.Equal(t, session.SessionID, retrieved.SessionID)
	require.Equal(t, session.CiphertextHandle, retrieved.CiphertextHandle)
	require.Equal(t, session.Threshold, retrieved.Threshold)
	require.Equal(t, 2, len(retrieved.Participants))
	require.Equal(t, SessionActive, retrieved.Status)
	require.NotZero(t, retrieved.CreatedAt)
}

func TestRegistrySessionNotFound(t *testing.T) {
	registry := newTestRegistry(t)

	_, err := registry.GetSession("non-existent")
	require.ErrorIs(t, err, ErrSessionNotFound)
}

func TestRegistrySessionDelete(t *testing.T) {
	registry := newTestRegistry(t)

	session := &SessionState{
		SessionID: "session-to-delete",
		Status:    SessionActive,
	}

	// Save session
	err := registry.SaveSession(session)
	require.NoError(t, err)

	// Verify it exists
	_, err = registry.GetSession("session-to-delete")
	require.NoError(t, err)

	// Delete session
	err = registry.DeleteSession("session-to-delete")
	require.NoError(t, err)

	// Verify it's gone
	_, err = registry.GetSession("session-to-delete")
	require.ErrorIs(t, err, ErrSessionNotFound)
}

func TestRegistrySessionUpdate(t *testing.T) {
	registry := newTestRegistry(t)

	session := &SessionState{
		SessionID:      "session-update",
		SharesReceived: 0,
		Status:         SessionActive,
	}

	// Save session
	err := registry.SaveSession(session)
	require.NoError(t, err)

	// Update session
	session.SharesReceived = 10
	session.Status = SessionCompleted
	session.Result = []byte("decrypted result")
	err = registry.SaveSession(session)
	require.NoError(t, err)

	// Verify update
	retrieved, err := registry.GetSession("session-update")
	require.NoError(t, err)
	require.Equal(t, 10, retrieved.SharesReceived)
	require.Equal(t, SessionCompleted, retrieved.Status)
	require.Equal(t, []byte("decrypted result"), retrieved.Result)
}

func TestRegistryRevokePermit(t *testing.T) {
	registry := newTestRegistry(t)

	permit := &Permit{
		PermitID:   [32]byte{0x11, 0x22, 0x33},
		Handle:     [32]byte{0x44, 0x55},
		Grantee:    [20]byte{0xcc, 0xdd},
		Grantor:    [20]byte{0xaa, 0xbb},
		Operations: PermitOpDecrypt,
		Expiry:     time.Now().Add(time.Hour).Unix(),
		ChainID:    ids.GenerateTestID(),
	}

	// Create permit
	err := registry.CreatePermit(permit)
	require.NoError(t, err)

	// Verify it exists
	_, err = registry.GetPermit(permit.PermitID)
	require.NoError(t, err)

	// Revoke permit
	err = registry.RevokePermit(permit.PermitID)
	require.NoError(t, err)

	// Verify it's gone
	_, err = registry.GetPermit(permit.PermitID)
	require.ErrorIs(t, err, ErrPermitNotFound)
}

func TestRegistryVerifyPermitExpired(t *testing.T) {
	registry := newTestRegistry(t)

	permitID := [32]byte{0x11, 0x22, 0x33}
	handle := [32]byte{0x44, 0x55}
	grantee := [20]byte{0xcc, 0xdd}

	permit := &Permit{
		PermitID:   permitID,
		Handle:     handle,
		Grantee:    grantee,
		Grantor:    [20]byte{0xaa, 0xbb},
		Operations: PermitOpDecrypt,
		Expiry:     time.Now().Add(-time.Hour).Unix(), // Expired
		ChainID:    ids.GenerateTestID(),
	}

	// Create permit
	err := registry.CreatePermit(permit)
	require.NoError(t, err)

	// Verify permit - should fail because expired
	err = registry.VerifyPermit(permitID, handle, grantee, PermitOpDecrypt)
	require.ErrorIs(t, err, ErrPermitExpired)
}

func TestRegistryUpdateDecryptRequestNotFound(t *testing.T) {
	registry := newTestRegistry(t)

	// Update non-existent request
	err := registry.UpdateDecryptRequest([32]byte{0xff}, RequestCompleted, [32]byte{}, "")
	require.ErrorIs(t, err, ErrRequestNotFound)
}

func TestRegistryUpdateDecryptRequestWithError(t *testing.T) {
	registry := newTestRegistry(t)

	req := &DecryptRequest{
		RequestID:        [32]byte{1, 2, 3, 4, 5, 6, 7, 8},
		CiphertextHandle: [32]byte{0xaa, 0xbb},
		SourceChain:      ids.GenerateTestID(),
	}

	// Create request
	err := registry.CreateDecryptRequest(req)
	require.NoError(t, err)

	// Update with error
	err = registry.UpdateDecryptRequest(req.RequestID, RequestFailed, [32]byte{}, "decryption failed")
	require.NoError(t, err)

	// Retrieve and verify
	retrieved, err := registry.GetDecryptRequest(req.RequestID)
	require.NoError(t, err)
	require.Equal(t, RequestFailed, retrieved.Status)
	require.Equal(t, "decryption failed", retrieved.Error)
}

func TestRegistryAddAndRemoveCommitteeMember(t *testing.T) {
	registry := newTestRegistry(t)

	// First set up an epoch
	epochInfo := &EpochInfo{
		Epoch:     1,
		StartTime: time.Now().Unix(),
		Threshold: 67,
		Status:    EpochActive,
	}
	err := registry.SetEpoch(1, epochInfo)
	require.NoError(t, err)

	// Add committee member
	member := &CommitteeMember{
		NodeID:    ids.GenerateTestNodeID(),
		PublicKey: []byte("pk1"),
		Weight:    100,
		Index:     0,
	}
	err = registry.AddCommitteeMember(member)
	require.NoError(t, err)

	// Get committee
	members, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Equal(t, 1, len(members))
	require.Equal(t, member.NodeID, members[0].NodeID)

	// Get specific member
	retrieved, err := registry.GetCommitteeMember(member.NodeID)
	require.NoError(t, err)
	require.Equal(t, member.NodeID, retrieved.NodeID)

	// Remove member
	err = registry.RemoveCommitteeMember(member.NodeID)
	require.NoError(t, err)

	// Verify member is gone
	members, err = registry.GetCommittee()
	require.NoError(t, err)
	require.Equal(t, 0, len(members))
}

func TestRegistryGetCommitteeMemberNotFound(t *testing.T) {
	registry := newTestRegistry(t)

	_, err := registry.GetCommitteeMember(ids.GenerateTestNodeID())
	require.Error(t, err)
}

func TestRegistryAddCommitteeMemberUpdate(t *testing.T) {
	registry := newTestRegistry(t)

	// Set up an epoch
	err := registry.SetEpoch(1, &EpochInfo{Epoch: 1, Status: EpochActive})
	require.NoError(t, err)

	nodeID := ids.GenerateTestNodeID()

	// Add member
	member := &CommitteeMember{
		NodeID:    nodeID,
		PublicKey: []byte("pk1"),
		Weight:    100,
		Index:     0,
	}
	err = registry.AddCommitteeMember(member)
	require.NoError(t, err)

	// Update same member with different weight
	member.Weight = 200
	err = registry.AddCommitteeMember(member)
	require.NoError(t, err)

	// Verify the update
	retrieved, err := registry.GetCommitteeMember(nodeID)
	require.NoError(t, err)
	require.Equal(t, uint64(200), retrieved.Weight)

	// Make sure we don't have duplicates
	members, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Equal(t, 1, len(members))
}

func TestRegistryClose(t *testing.T) {
	registry := newTestRegistry(t)
	err := registry.Close()
	require.NoError(t, err)
}

func TestSessionStatusConstants(t *testing.T) {
	require.Equal(t, SessionStatus(0), SessionActive)
	require.Equal(t, SessionStatus(1), SessionCompleted)
	require.Equal(t, SessionStatus(2), SessionFailed)
	require.Equal(t, SessionStatus(3), SessionExpired)
}

func TestEpochStatusConstants(t *testing.T) {
	require.Equal(t, EpochStatus(0), EpochActive)
	require.Equal(t, EpochStatus(1), EpochEnded)
	require.Equal(t, EpochStatus(2), EpochPending)
}

func TestPermitOpConstants(t *testing.T) {
	require.Equal(t, uint32(1), PermitOpDecrypt)
	require.Equal(t, uint32(2), PermitOpReencrypt)
	require.Equal(t, uint32(4), PermitOpCompute)
	require.Equal(t, uint32(8), PermitOpTransfer)
}

func TestNewRegistryWithExistingEpoch(t *testing.T) {
	db := memdb.New()

	// First registry - set an epoch
	registry1, err := NewRegistry(db)
	require.NoError(t, err)

	// Advance epoch via SetEpoch
	epochInfo := &EpochInfo{
		Epoch:     5,
		StartTime: time.Now().Unix(),
		EndTime:   time.Now().Add(time.Hour).Unix(),
		Threshold: 67,
		Status:    EpochActive,
	}
	require.NoError(t, registry1.SetEpoch(5, epochInfo))
	require.Equal(t, uint64(5), registry1.GetCurrentEpoch())

	// Create second registry from same DB - should load existing epoch
	// Note: don't close first registry as memdb doesn't support reopening
	registry2, err := NewRegistry(db)
	require.NoError(t, err)
	require.Equal(t, uint64(5), registry2.GetCurrentEpoch())
}

func TestRegistrySetAndGetEpoch(t *testing.T) {
	registry := newTestRegistry(t)

	// Initial epoch should be 0
	require.Equal(t, uint64(0), registry.GetCurrentEpoch())

	// Set epoch 10
	epochInfo := &EpochInfo{
		Epoch:     10,
		StartTime: time.Now().Unix(),
		EndTime:   time.Now().Add(time.Hour).Unix(),
		Threshold: 67,
		Status:    EpochActive,
	}
	require.NoError(t, registry.SetEpoch(10, epochInfo))
	require.Equal(t, uint64(10), registry.GetCurrentEpoch())

	// Set higher epoch
	epochInfo.Epoch = 100
	require.NoError(t, registry.SetEpoch(100, epochInfo))
	require.Equal(t, uint64(100), registry.GetCurrentEpoch())
}
