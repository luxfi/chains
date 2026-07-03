// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

var (
	// Database prefixes for different registries
	ciphertextPrefix     = []byte("ct:")
	decryptRequestPrefix = []byte("dr:")
	permitPrefix         = []byte("pm:")
	sessionPrefix        = []byte("ss:")
	committeePrefix      = []byte("cm:")
	epochPrefix          = []byte("ep:")

	// Note: ErrCiphertextNotFound and ErrRequestNotFound are defined in relayer.go
	ErrPermitNotFound  = errors.New("permit not found")
	ErrSessionNotFound = errors.New("session not found")
	ErrPermitExpired   = errors.New("permit expired")
	ErrPermitInvalid   = errors.New("permit invalid")
	ErrEpochMismatch   = errors.New("epoch mismatch")
)

// CiphertextMeta stores metadata for registered ciphertexts
type CiphertextMeta struct {
	Handle       [32]byte `json:"handle"`
	Owner        [20]byte `json:"owner"`
	Type         uint8    `json:"type"`
	Level        int      `json:"level"`
	Epoch        uint64   `json:"epoch"`
	RegisteredAt int64    `json:"registered_at"`
	Size         uint32   `json:"size"`
	ChainID      ids.ID   `json:"chain_id"`
}

// DecryptRequest represents a threshold decryption request
type DecryptRequest struct {
	RequestID        [32]byte      `json:"request_id"`
	CiphertextHandle [32]byte      `json:"ciphertext_handle"`
	Requester        [20]byte      `json:"requester"`
	Callback         [20]byte      `json:"callback"`
	CallbackSelector [4]byte       `json:"callback_selector"`
	SourceChain      ids.ID        `json:"source_chain"`
	Epoch            uint64        `json:"epoch"`
	Nonce            uint64        `json:"nonce"`
	Expiry           int64         `json:"expiry"`
	Status           RequestStatus `json:"status"`
	CreatedAt        int64         `json:"created_at"`
	CompletedAt      int64         `json:"completed_at,omitempty"`
	ResultHandle     [32]byte      `json:"result_handle,omitempty"`
	Error            string        `json:"error,omitempty"`
}

// RequestStatus represents the status of a decrypt request
type RequestStatus uint8

const (
	RequestPending RequestStatus = iota
	RequestProcessing
	RequestCompleted
	RequestFailed
	RequestExpired
)

func (s RequestStatus) String() string {
	switch s {
	case RequestPending:
		return "pending"
	case RequestProcessing:
		return "processing"
	case RequestCompleted:
		return "completed"
	case RequestFailed:
		return "failed"
	case RequestExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// Permit represents an access control permit for FHE operations
type Permit struct {
	PermitID    [32]byte `json:"permit_id"`
	Handle      [32]byte `json:"handle"`
	Grantee     [20]byte `json:"grantee"`
	Grantor     [20]byte `json:"grantor"`
	Operations  uint32   `json:"operations"` // Bitmask of allowed operations
	Expiry      int64    `json:"expiry"`
	CreatedAt   int64    `json:"created_at"`
	Attestation []byte   `json:"attestation,omitempty"`
	ChainID     ids.ID   `json:"chain_id"`
}

// PermitOps defines allowed operations in permits
const (
	PermitOpDecrypt uint32 = 1 << iota
	PermitOpReencrypt
	PermitOpCompute
	PermitOpTransfer
)

// CommitteeMember represents a threshold committee member
type CommitteeMember struct {
	NodeID    ids.NodeID `json:"node_id"`
	PublicKey []byte     `json:"public_key"`
	Weight    uint64     `json:"weight"`
	Index     int        `json:"index"`
}

// EpochInfo stores epoch-related information
type EpochInfo struct {
	Epoch     uint64            `json:"epoch"`
	StartTime int64             `json:"start_time"`
	EndTime   int64             `json:"end_time,omitempty"`
	Committee []CommitteeMember `json:"committee"`
	Threshold int               `json:"threshold"`
	PublicKey []byte            `json:"public_key"`
	Status    EpochStatus       `json:"status"`
}

type EpochStatus uint8

const (
	EpochActive EpochStatus = iota
	EpochEnded
	EpochPending
)

// Registry provides persistent storage for FHE-related data
type Registry struct {
	db    database.Database
	mu    sync.RWMutex
	epoch uint64
}

// NewRegistry creates a new FHE registry with persistent storage
func NewRegistry(db database.Database) (*Registry, error) {
	r := &Registry{
		db: db,
	}

	// Load current epoch
	epochBytes, err := db.Get(append(epochPrefix, []byte("current")...))
	if err != nil && !errors.Is(err, database.ErrNotFound) {
		return nil, fmt.Errorf("failed to load epoch: %w", err)
	}
	if epochBytes != nil {
		r.epoch = binary.BigEndian.Uint64(epochBytes)
	}

	return r, nil
}

// ========================
// Ciphertext Registry
// ========================

// RegisterCiphertext stores ciphertext metadata
func (r *Registry) RegisterCiphertext(meta *CiphertextMeta) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	meta.RegisteredAt = time.Now().Unix()
	meta.Epoch = r.epoch

	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal ciphertext meta: %w", err)
	}

	key := append(ciphertextPrefix, meta.Handle[:]...)
	return r.db.Put(key, data)
}

// GetCiphertextMeta retrieves ciphertext metadata
func (r *Registry) GetCiphertextMeta(handle [32]byte) (*CiphertextMeta, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := append(ciphertextPrefix, handle[:]...)
	data, err := r.db.Get(key)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, ErrCiphertextNotFound
		}
		return nil, err
	}

	var meta CiphertextMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ciphertext meta: %w", err)
	}

	return &meta, nil
}

// DeleteCiphertext removes ciphertext metadata
func (r *Registry) DeleteCiphertext(handle [32]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := append(ciphertextPrefix, handle[:]...)
	return r.db.Delete(key)
}

// ========================
// Decrypt Request Registry
// ========================

// CreateDecryptRequest stores a new decrypt request
func (r *Registry) CreateDecryptRequest(req *DecryptRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	req.CreatedAt = time.Now().Unix()
	req.Status = RequestPending
	req.Epoch = r.epoch

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal decrypt request: %w", err)
	}

	key := append(decryptRequestPrefix, req.RequestID[:]...)
	return r.db.Put(key, data)
}

// GetDecryptRequest retrieves a decrypt request
func (r *Registry) GetDecryptRequest(requestID [32]byte) (*DecryptRequest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := append(decryptRequestPrefix, requestID[:]...)
	data, err := r.db.Get(key)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, ErrRequestNotFound
		}
		return nil, err
	}

	var req DecryptRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypt request: %w", err)
	}

	return &req, nil
}

// UpdateDecryptRequest updates a decrypt request status
func (r *Registry) UpdateDecryptRequest(requestID [32]byte, status RequestStatus, result [32]byte, errMsg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := append(decryptRequestPrefix, requestID[:]...)
	data, err := r.db.Get(key)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return ErrRequestNotFound
		}
		return err
	}

	var req DecryptRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("failed to unmarshal decrypt request: %w", err)
	}

	req.Status = status
	if status == RequestCompleted {
		req.CompletedAt = time.Now().Unix()
		req.ResultHandle = result
	}
	if errMsg != "" {
		req.Error = errMsg
	}

	updatedData, err := json.Marshal(&req)
	if err != nil {
		return fmt.Errorf("failed to marshal updated request: %w", err)
	}

	return r.db.Put(key, updatedData)
}

// ========================
// Permit Registry
// ========================

// CreatePermit stores a new permit
func (r *Registry) CreatePermit(permit *Permit) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	permit.CreatedAt = time.Now().Unix()

	data, err := json.Marshal(permit)
	if err != nil {
		return fmt.Errorf("failed to marshal permit: %w", err)
	}

	key := append(permitPrefix, permit.PermitID[:]...)
	return r.db.Put(key, data)
}

// GetPermit retrieves a permit
func (r *Registry) GetPermit(permitID [32]byte) (*Permit, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := append(permitPrefix, permitID[:]...)
	data, err := r.db.Get(key)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, ErrPermitNotFound
		}
		return nil, err
	}

	var permit Permit
	if err := json.Unmarshal(data, &permit); err != nil {
		return nil, fmt.Errorf("failed to unmarshal permit: %w", err)
	}

	return &permit, nil
}

// VerifyPermit checks if a permit is valid for the given operation
func (r *Registry) VerifyPermit(permitID [32]byte, handle [32]byte, grantee [20]byte, operation uint32) error {
	permit, err := r.GetPermit(permitID)
	if err != nil {
		return err
	}

	// Check handle matches
	if permit.Handle != handle {
		return ErrPermitInvalid
	}

	// Check grantee matches
	if permit.Grantee != grantee {
		return ErrPermitInvalid
	}

	// Check expiry
	if permit.Expiry > 0 && time.Now().Unix() > permit.Expiry {
		return ErrPermitExpired
	}

	// Check operation allowed
	if permit.Operations&operation == 0 {
		return ErrPermitInvalid
	}

	return nil
}

// RevokePermit removes a permit
func (r *Registry) RevokePermit(permitID [32]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := append(permitPrefix, permitID[:]...)
	return r.db.Delete(key)
}

// ========================
// Session Registry
// ========================

// SessionState stores the state of a threshold decryption session
type SessionState struct {
	SessionID        string        `json:"session_id"`
	CiphertextHandle [32]byte      `json:"ciphertext_handle"`
	Epoch            uint64        `json:"epoch"`
	Threshold        int           `json:"threshold"`
	Participants     []ids.NodeID  `json:"participants"`
	SharesReceived   int           `json:"shares_received"`
	Status           SessionStatus `json:"status"`
	CreatedAt        int64         `json:"created_at"`
	CompletedAt      int64         `json:"completed_at,omitempty"`
	Result           []byte        `json:"result,omitempty"`
}

type SessionStatus uint8

const (
	SessionActive SessionStatus = iota
	SessionCompleted
	SessionFailed
	SessionExpired
)

// SaveSession persists a session state
func (r *Registry) SaveSession(session *SessionState) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if session.CreatedAt == 0 {
		session.CreatedAt = time.Now().Unix()
	}
	session.Epoch = r.epoch

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	key := append(sessionPrefix, []byte(session.SessionID)...)
	return r.db.Put(key, data)
}

// GetSession retrieves a session state
func (r *Registry) GetSession(sessionID string) (*SessionState, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := append(sessionPrefix, []byte(sessionID)...)
	data, err := r.db.Get(key)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	var session SessionState
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &session, nil
}

// DeleteSession removes a session
func (r *Registry) DeleteSession(sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := append(sessionPrefix, []byte(sessionID)...)
	return r.db.Delete(key)
}

// ========================
// Committee/Epoch Management
// ========================

// SetEpoch updates the current epoch
func (r *Registry) SetEpoch(epoch uint64, info *EpochInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Store epoch info
	infoData, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal epoch info: %w", err)
	}

	epochKey := make([]byte, 8)
	binary.BigEndian.PutUint64(epochKey, epoch)
	if err := r.db.Put(append(epochPrefix, epochKey...), infoData); err != nil {
		return err
	}

	// Update current epoch pointer
	currentKey := append(epochPrefix, []byte("current")...)
	r.epoch = epoch
	return r.db.Put(currentKey, epochKey)
}

// GetEpoch retrieves epoch information
func (r *Registry) GetEpoch(epoch uint64) (*EpochInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	epochKey := make([]byte, 8)
	binary.BigEndian.PutUint64(epochKey, epoch)

	data, err := r.db.Get(append(epochPrefix, epochKey...))
	if err != nil {
		return nil, err
	}

	var info EpochInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal epoch info: %w", err)
	}

	return &info, nil
}

// GetCurrentEpoch returns the current epoch number
func (r *Registry) GetCurrentEpoch() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.epoch
}

// GetCommittee returns the committee for the current epoch
func (r *Registry) GetCommittee() ([]CommitteeMember, error) {
	info, err := r.GetEpoch(r.GetCurrentEpoch())
	if err != nil {
		return []CommitteeMember{}, nil // Return empty slice if no epoch configured
	}
	return info.Committee, nil
}

// AddCommitteeMember adds a member to the current epoch's committee
func (r *Registry) AddCommitteeMember(member *CommitteeMember) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	epoch := r.epoch
	key := append(epochPrefix, encodeUint64(epoch)...)
	data, err := r.db.Get(key)

	var info EpochInfo
	if err == nil {
		if err := json.Unmarshal(data, &info); err != nil {
			return fmt.Errorf("failed to unmarshal epoch info: %w", err)
		}
	} else {
		info = EpochInfo{Epoch: epoch, Status: EpochActive, Threshold: 67}
	}

	// Check if member already exists
	for i, m := range info.Committee {
		if m.NodeID == member.NodeID {
			info.Committee[i] = *member
			goto save
		}
	}
	info.Committee = append(info.Committee, *member)

save:
	updatedData, err := json.Marshal(&info)
	if err != nil {
		return fmt.Errorf("failed to marshal epoch info: %w", err)
	}
	return r.db.Put(key, updatedData)
}

// GetCommitteeMember returns a specific committee member
func (r *Registry) GetCommitteeMember(nodeID ids.NodeID) (*CommitteeMember, error) {
	members, err := r.GetCommittee()
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		if m.NodeID == nodeID {
			return &m, nil
		}
	}
	return nil, fmt.Errorf("committee member not found")
}

// RemoveCommitteeMember removes a member from the current epoch's committee
func (r *Registry) RemoveCommitteeMember(nodeID ids.NodeID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	epoch := r.epoch
	key := append(epochPrefix, encodeUint64(epoch)...)
	data, err := r.db.Get(key)
	if err != nil {
		return nil // No epoch, nothing to remove
	}

	var info EpochInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("failed to unmarshal epoch info: %w", err)
	}

	// Find and remove member
	newCommittee := make([]CommitteeMember, 0, len(info.Committee))
	for _, m := range info.Committee {
		if m.NodeID != nodeID {
			newCommittee = append(newCommittee, m)
		}
	}
	info.Committee = newCommittee

	updatedData, err := json.Marshal(&info)
	if err != nil {
		return fmt.Errorf("failed to marshal epoch info: %w", err)
	}
	return r.db.Put(key, updatedData)
}

// Close closes the registry
func (r *Registry) Close() error {
	return r.db.Close()
}

// encodeUint64 encodes a uint64 to bytes
func encodeUint64(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}
