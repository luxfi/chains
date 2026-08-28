// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/luxfi/database"
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

// ---------------------------------------------------------------------------
// What the registry does when the database does not cooperate
// ---------------------------------------------------------------------------

// errFault is what a database returns when it is neither working nor absent.
// Telling those two apart is the whole point of the tests below: "not found"
// means the record does not exist, anything else means the answer is unknown,
// and a store that conflates them reports emptiness it has not established.
var errFault = errors.New("disk fell over")

// faultyDB is a database that consults a hook before each read and each write.
// A hook returning an error refuses that one operation, so a test can place a
// failure on a particular key, on the nth call, or on everything, without the
// fake growing a knob per shape.
type faultyDB struct {
	database.Database
	refuseGet func(key []byte) error
	refusePut func(key []byte) error
}

func (f *faultyDB) Get(key []byte) ([]byte, error) {
	if f.refuseGet != nil {
		if err := f.refuseGet(key); err != nil {
			return nil, err
		}
	}
	return f.Database.Get(key)
}

func (f *faultyDB) Put(key, value []byte) error {
	if f.refusePut != nil {
		if err := f.refusePut(key); err != nil {
			return err
		}
	}
	return f.Database.Put(key, value)
}

// always refuses every key, which is what a dead disk looks like.
func always(key []byte) error { return errFault }

// under refuses only the keys a subsystem owns, which is how a test fails one
// record while the rest of a multi-write operation succeeds.
func under(prefix string) func([]byte) error {
	return func(key []byte) error {
		if bytes.HasPrefix(key, []byte(prefix)) {
			return errFault
		}
		return nil
	}
}

// afterFirst lets one call through and refuses the rest, which separates two
// reads of the same key inside one operation.
func afterFirst() func([]byte) error {
	seen := 0
	return func([]byte) error {
		seen++
		if seen > 1 {
			return errFault
		}
		return nil
	}
}

// newFaultyRegistry returns a registry over a working database plus the switch
// that breaks it, so a test can populate state first and fail afterwards.
func newFaultyRegistry(t *testing.T) (*Registry, *faultyDB) {
	t.Helper()
	db := &faultyDB{Database: memdb.New()}
	registry, err := NewRegistry(db)
	require.NoError(t, err)
	return registry, db
}

// corrupt writes bytes that are not JSON under a key, which is what a torn
// write or a format change leaves behind.
func corrupt(t *testing.T, r *Registry, prefix []byte, suffix []byte) {
	t.Helper()
	require.NoError(t, r.db.Put(append(prefix, suffix...), []byte("{not json")))
}

// TestNewRegistryRefusesAnUnreadableEpochPointer holds that a registry whose
// stored epoch cannot be read fails to open. Starting at epoch 0 instead would
// silently rewind the chain's key schedule and register new ciphertexts under
// an epoch whose committee has long since rotated out.
func TestNewRegistryRefusesAnUnreadableEpochPointer(t *testing.T) {
	registry, err := NewRegistry(&faultyDB{Database: memdb.New(), refuseGet: always})
	require.ErrorIs(t, err, errFault)
	require.Nil(t, registry)
}

// TestRegistryReportsUnreadableRecords holds that every read distinguishes
// "absent" from "unknown". Each getter maps a missing record to its own
// not-found error, and everything else has to come back as the failure it was.
func TestRegistryReportsUnreadableRecords(t *testing.T) {
	registry, db := newFaultyRegistry(t)
	db.refuseGet = always

	_, err := registry.GetCiphertextMeta([32]byte{1})
	require.ErrorIs(t, err, errFault)
	require.NotErrorIs(t, err, ErrCiphertextNotFound)

	_, err = registry.GetDecryptRequest([32]byte{1})
	require.ErrorIs(t, err, errFault)
	require.NotErrorIs(t, err, ErrRequestNotFound)

	_, err = registry.GetPermit([32]byte{1})
	require.ErrorIs(t, err, errFault)
	require.NotErrorIs(t, err, ErrPermitNotFound)

	_, err = registry.GetSession("s")
	require.ErrorIs(t, err, errFault)
	require.NotErrorIs(t, err, ErrSessionNotFound)

	_, err = registry.GetEpoch(1)
	require.ErrorIs(t, err, errFault)

	require.ErrorIs(t, registry.UpdateDecryptRequest([32]byte{1}, RequestCompleted, [32]byte{}, ""), errFault)
}

// TestRegistryReportsCorruptRecords holds that bytes that are not the record
// they claim to be are reported, not returned as a zero-valued record. A
// zero-valued CiphertextMeta names owner 0x00..00, which is an address an
// attacker can plausibly control.
func TestRegistryReportsCorruptRecords(t *testing.T) {
	registry := newTestRegistry(t)

	corrupt(t, registry, ciphertextPrefix, make([]byte, 32))
	_, err := registry.GetCiphertextMeta([32]byte{})
	require.ErrorContains(t, err, "unmarshal ciphertext meta")

	corrupt(t, registry, decryptRequestPrefix, make([]byte, 32))
	_, err = registry.GetDecryptRequest([32]byte{})
	require.ErrorContains(t, err, "unmarshal decrypt request")
	require.ErrorContains(t,
		registry.UpdateDecryptRequest([32]byte{}, RequestCompleted, [32]byte{}, ""),
		"unmarshal decrypt request")

	corrupt(t, registry, permitPrefix, make([]byte, 32))
	_, err = registry.GetPermit([32]byte{})
	require.ErrorContains(t, err, "unmarshal permit")

	corrupt(t, registry, sessionPrefix, []byte("s"))
	_, err = registry.GetSession("s")
	require.ErrorContains(t, err, "unmarshal session")

	corrupt(t, registry, epochPrefix, encodeUint64(0))
	_, err = registry.GetEpoch(0)
	require.ErrorContains(t, err, "unmarshal epoch info")
	_, err = registry.GetCommittee()
	require.ErrorContains(t, err, "unmarshal epoch info")
	require.ErrorContains(t, registry.AddCommitteeMember(&CommitteeMember{}), "unmarshal epoch info")
	require.ErrorContains(t, registry.RemoveCommitteeMember(ids.GenerateTestNodeID()), "unmarshal epoch info")
}

// TestRegistryReportsFailedWrites holds that a write that did not land is
// reported. A silent failure here loses a permit, a request or an epoch while
// the caller carries on as though it were stored.
func TestRegistryReportsFailedWrites(t *testing.T) {
	registry, db := newFaultyRegistry(t)
	db.refusePut = always

	require.ErrorIs(t, registry.RegisterCiphertext(&CiphertextMeta{}), errFault)
	require.ErrorIs(t, registry.CreateDecryptRequest(&DecryptRequest{}), errFault)
	require.ErrorIs(t, registry.CreatePermit(&Permit{}), errFault)
	require.ErrorIs(t, registry.SaveSession(&SessionState{SessionID: "s"}), errFault)
	require.ErrorIs(t, registry.SetEpoch(1, &EpochInfo{}), errFault)
	require.ErrorIs(t, registry.AddCommitteeMember(&CommitteeMember{NodeID: ids.GenerateTestNodeID()}), errFault)
}

// TestGetCommitteeDistinguishesEmptyFromUnreadable is the property that a
// committee of nobody is a fact about the chain, not a symptom of a broken
// disk. Reporting a read failure as an empty committee is a silent-empty: the
// lifecycle manager would weigh the committee at zero, index every new member
// at 0 on top of the existing ones, and open a DKG with no participants -- all
// without an error anywhere.
func TestGetCommitteeDistinguishesEmptyFromUnreadable(t *testing.T) {
	registry, db := newFaultyRegistry(t)

	// No epoch configured yet: genuinely empty.
	members, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Empty(t, members)

	db.refuseGet = always
	members, err = registry.GetCommittee()
	require.ErrorIs(t, err, errFault)
	require.Nil(t, members)

	_, err = registry.GetCommitteeMember(ids.GenerateTestNodeID())
	require.ErrorIs(t, err, errFault)
}

// TestAddCommitteeMemberKeepsTheCommitteeItCannotRead holds that a failed read
// does not become a fresh epoch record. The old code fell back to a blank
// EpochInfo on any error, so one unreadable Get replaced the whole committee
// with the single member being added -- and then wrote that over the real one.
func TestAddCommitteeMemberKeepsTheCommitteeItCannotRead(t *testing.T) {
	registry, db := newFaultyRegistry(t)

	seated := make([]CommitteeMember, 4)
	for i := range seated {
		seated[i] = CommitteeMember{NodeID: ids.GenerateTestNodeID(), Weight: 10, Index: i}
	}
	require.NoError(t, registry.SetEpoch(1, &EpochInfo{Epoch: 1, Committee: seated, Threshold: 3}))

	db.refuseGet = always
	require.ErrorIs(t, registry.AddCommitteeMember(&CommitteeMember{NodeID: ids.GenerateTestNodeID()}), errFault)

	db.refuseGet = nil
	after, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Len(t, after, 4, "a failed read must not shrink the committee")
}

// TestRemoveCommitteeMemberReportsAnUnreadableEpoch holds that "removed" is
// only reported when a removal happened. SlashMember treats a nil error as a
// completed eviction and then emits the slashing event, so a swallowed read
// failure penalizes a validator that is still seated and still holding a key
// share.
func TestRemoveCommitteeMemberReportsAnUnreadableEpoch(t *testing.T) {
	registry, db := newFaultyRegistry(t)

	node := ids.GenerateTestNodeID()
	require.NoError(t, registry.SetEpoch(1, &EpochInfo{
		Epoch:     1,
		Committee: []CommitteeMember{{NodeID: node}},
	}))

	db.refuseGet = always
	require.ErrorIs(t, registry.RemoveCommitteeMember(node), errFault)

	db.refuseGet = nil
	members, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Len(t, members, 1, "the member was never removed")

	db.refusePut = always
	require.ErrorIs(t, registry.RemoveCommitteeMember(node), errFault)
}

// TestAddCommitteeMemberSeatsTheFirstMemberWithoutAnEpoch holds that the first
// member can be registered before any epoch record exists, which is how a
// committee is bootstrapped.
func TestAddCommitteeMemberSeatsTheFirstMemberWithoutAnEpoch(t *testing.T) {
	registry := newTestRegistry(t)

	node := ids.GenerateTestNodeID()
	require.NoError(t, registry.AddCommitteeMember(&CommitteeMember{NodeID: node, Weight: 7}))

	members, err := registry.GetCommittee()
	require.NoError(t, err)
	require.Len(t, members, 1)
	require.Equal(t, node, members[0].NodeID)

	// And the epoch it created is active with the default threshold.
	info, err := registry.GetEpoch(0)
	require.NoError(t, err)
	require.Equal(t, EpochActive, info.Status)
	require.Equal(t, 67, info.Threshold)
}

// TestRemoveCommitteeMemberIsSilentWithoutAnEpoch holds that removing from a
// committee that was never seated is not an error -- there is nothing to
// remove, and that is a fact, not a failure.
func TestRemoveCommitteeMemberIsSilentWithoutAnEpoch(t *testing.T) {
	registry := newTestRegistry(t)
	require.NoError(t, registry.RemoveCommitteeMember(ids.GenerateTestNodeID()))
}

// TestVerifyPermitBindsToHandleGranteeOperationAndExpiry holds all four gates a
// permit carries. Each one alone is the difference between a permit and a
// blanket key: the handle stops it opening a different ciphertext, the grantee
// stops it being presented by someone else, the operation bitmask stops a
// compute grant being spent on a decryption, and the expiry stops it living
// forever.
func TestVerifyPermitBindsToHandleGranteeOperationAndExpiry(t *testing.T) {
	registry := newTestRegistry(t)

	handle := [32]byte{1}
	grantee := [20]byte{2}
	permitID := [32]byte{3}
	require.NoError(t, registry.CreatePermit(&Permit{
		PermitID:   permitID,
		Handle:     handle,
		Grantee:    grantee,
		Operations: PermitOpCompute,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}))

	require.NoError(t, registry.VerifyPermit(permitID, handle, grantee, PermitOpCompute))

	require.ErrorIs(t, registry.VerifyPermit(permitID, [32]byte{9}, grantee, PermitOpCompute), ErrPermitInvalid)
	require.ErrorIs(t, registry.VerifyPermit(permitID, handle, [20]byte{9}, PermitOpCompute), ErrPermitInvalid)
	require.ErrorIs(t, registry.VerifyPermit(permitID, handle, grantee, PermitOpDecrypt), ErrPermitInvalid)
	require.ErrorIs(t, registry.VerifyPermit([32]byte{9}, handle, grantee, PermitOpCompute), ErrPermitNotFound)
}

// TestPermitExpiryIsInclusiveAtTheDeadline holds where the expiry boundary
// falls: the check is `now > expiry`, so a permit is still valid during the
// second it names and dead from the next one. Both sides are pinned because a
// boundary that moves by one second changes which requests a rotation admits.
func TestPermitExpiryIsInclusiveAtTheDeadline(t *testing.T) {
	registry := newTestRegistry(t)

	handle := [32]byte{1}
	grantee := [20]byte{2}
	now := time.Now().Unix()

	live := [32]byte{10}
	require.NoError(t, registry.CreatePermit(&Permit{
		PermitID: live, Handle: handle, Grantee: grantee,
		Operations: PermitOpDecrypt, Expiry: now,
	}))
	require.NoError(t, registry.VerifyPermit(live, handle, grantee, PermitOpDecrypt),
		"a permit is valid through the second it expires at")

	dead := [32]byte{11}
	require.NoError(t, registry.CreatePermit(&Permit{
		PermitID: dead, Handle: handle, Grantee: grantee,
		Operations: PermitOpDecrypt, Expiry: now - 1,
	}))
	require.ErrorIs(t, registry.VerifyPermit(dead, handle, grantee, PermitOpDecrypt), ErrPermitExpired)

	forever := [32]byte{12}
	require.NoError(t, registry.CreatePermit(&Permit{
		PermitID: forever, Handle: handle, Grantee: grantee,
		Operations: PermitOpDecrypt, Expiry: 0,
	}))
	require.NoError(t, registry.VerifyPermit(forever, handle, grantee, PermitOpDecrypt),
		"expiry 0 means no expiry")
}
