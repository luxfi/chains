// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/multiparty"
	"github.com/luxfi/lattice/v7/schemes/ckks"
)

// Protocol constants
const (
	// ProtocolFHE is the protocol identifier for FHE operations
	ProtocolFHE = "fhe"

	// ProtocolFHEThreshold is the protocol for threshold FHE decryption
	ProtocolFHEThreshold = "fhe-threshold"
)

// FHEProtocolHandler implements threshold FHE operations for ThresholdVM integration
type FHEProtocolHandler struct {
	params    ckks.Parameters
	threshold int
	total     int

	// Key management
	publicKey   *rlwe.PublicKey
	secretShare *rlwe.SecretKey
	shamirShare *multiparty.ShamirSecretShare
	relinKey    *rlwe.RelinearizationKey
	galoisKeys  *rlwe.GaloisKey

	// Threshold decryptor
	decryptor *ThresholdDecryptor

	// Party identity
	partyID multiparty.ShamirPublicPoint

	// Active protocol sessions
	sessions   map[[32]byte]*FHESession
	sessionsMu sync.RWMutex
}

// FHESession represents an active FHE protocol session
type FHESession struct {
	ID        [32]byte
	Type      FHESessionType
	Status    FHESessionStatus
	Requester [20]byte // Contract address

	// For decryption
	Ciphertext *Ciphertext

	// For keygen
	KeygenRound int

	// Collected shares
	Shares     map[uint64][]byte
	ShareCount int

	// Result
	Result []byte
	Error  error

	mu sync.RWMutex
}

// FHESessionType represents the type of FHE protocol session
type FHESessionType uint8

const (
	SessionDecrypt FHESessionType = iota
	SessionKeygen
	SessionReshare
	SessionRefresh
)

// FHESessionStatus represents the status of an FHE session
type FHESessionStatus uint8

const (
	StatusPending FHESessionStatus = iota
	StatusCollecting
	StatusProcessing
	StatusCompleted
	StatusFailed
)

// FHEKeyShare wraps FHE key material to implement the KeyShare interface
type FHEKeyShare struct {
	PublicKeyBytes    []byte
	SecretKeyShare    *rlwe.SecretKey
	ShamirSecretShare *multiparty.ShamirSecretShare
	PartyIdentity     uint64
	ThresholdValue    int
	TotalPartiesValue int
	GenerationValue   uint64
}

func (s *FHEKeyShare) PublicKey() []byte {
	return s.PublicKeyBytes
}

func (s *FHEKeyShare) PartyID() uint64 {
	return s.PartyIdentity
}

func (s *FHEKeyShare) Threshold() int {
	return s.ThresholdValue
}

func (s *FHEKeyShare) TotalParties() int {
	return s.TotalPartiesValue
}

func (s *FHEKeyShare) Generation() uint64 {
	return s.GenerationValue
}

func (s *FHEKeyShare) Protocol() string {
	return ProtocolFHEThreshold
}

func (s *FHEKeyShare) Serialize() ([]byte, error) {
	// Serialize the secret key share
	skBytes, err := s.SecretKeyShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secret key: %w", err)
	}

	// Format: [pk_len(4)] [pk] [sk_len(4)] [sk] [party(8)] [thresh(4)] [total(4)] [gen(8)]
	result := make([]byte, 4+len(s.PublicKeyBytes)+4+len(skBytes)+8+4+4+8)
	offset := 0

	binary.BigEndian.PutUint32(result[offset:], uint32(len(s.PublicKeyBytes)))
	offset += 4
	copy(result[offset:], s.PublicKeyBytes)
	offset += len(s.PublicKeyBytes)

	binary.BigEndian.PutUint32(result[offset:], uint32(len(skBytes)))
	offset += 4
	copy(result[offset:], skBytes)
	offset += len(skBytes)

	binary.BigEndian.PutUint64(result[offset:], s.PartyIdentity)
	offset += 8
	binary.BigEndian.PutUint32(result[offset:], uint32(s.ThresholdValue))
	offset += 4
	binary.BigEndian.PutUint32(result[offset:], uint32(s.TotalPartiesValue))
	offset += 4
	binary.BigEndian.PutUint64(result[offset:], s.GenerationValue)

	return result, nil
}

// NewFHEProtocolHandler creates a new FHE protocol handler
func NewFHEProtocolHandler(params ckks.Parameters, threshold, total int, partyID uint64) (*FHEProtocolHandler, error) {
	config := ThresholdConfig{
		Threshold:     threshold,
		TotalParties:  total,
		PartyID:       partyID,
		NoiseFlooding: 1 << 30,
	}

	decryptor, err := NewThresholdDecryptor(params, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create threshold decryptor: %w", err)
	}

	return &FHEProtocolHandler{
		params:    params,
		threshold: threshold,
		total:     total,
		partyID:   multiparty.ShamirPublicPoint(partyID),
		decryptor: decryptor,
		sessions:  make(map[[32]byte]*FHESession),
	}, nil
}

// Name returns the protocol name
func (h *FHEProtocolHandler) Name() string {
	return ProtocolFHEThreshold
}

// SupportedOperations returns supported FHE operations
func (h *FHEProtocolHandler) SupportedOperations() []string {
	return []string{
		"decrypt",
		"keygen",
		"reshare",
		"refresh",
	}
}

// SetKeys sets the FHE key material
func (h *FHEProtocolHandler) SetKeys(pk *rlwe.PublicKey, sk *rlwe.SecretKey, shamir *multiparty.ShamirSecretShare) {
	h.publicKey = pk
	h.secretShare = sk
	h.shamirShare = shamir
	h.decryptor.SetKeyShare(sk)
	h.decryptor.SetShamirShare(shamir)
}

// SetEvaluationKeys sets the evaluation keys (relinearization, galois)
func (h *FHEProtocolHandler) SetEvaluationKeys(relin *rlwe.RelinearizationKey, galois *rlwe.GaloisKey) {
	h.relinKey = relin
	h.galoisKeys = galois
}

// StartDecryption initiates a threshold decryption session
func (h *FHEProtocolHandler) StartDecryption(
	ctx context.Context,
	ct *Ciphertext,
	requester [20]byte,
) ([32]byte, error) {
	if h.secretShare == nil {
		return [32]byte{}, errors.New("key share not initialized")
	}

	// Generate session ID
	sessionID := sha256.Sum256(append(ct.Handle[:], requester[:]...))

	session := &FHESession{
		ID:         sessionID,
		Type:       SessionDecrypt,
		Status:     StatusPending,
		Requester:  requester,
		Ciphertext: ct,
		Shares:     make(map[uint64][]byte),
	}

	h.sessionsMu.Lock()
	h.sessions[sessionID] = session
	h.sessionsMu.Unlock()

	// Start decryption via threshold decryptor
	_, err := h.decryptor.RequestDecryption(ctx, ct, func(result []complex128, err error) {
		h.onDecryptionComplete(sessionID, result, err)
	})
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to start decryption: %w", err)
	}

	return sessionID, nil
}

// onDecryptionComplete handles decryption completion callback
func (h *FHEProtocolHandler) onDecryptionComplete(sessionID [32]byte, result []complex128, err error) {
	h.sessionsMu.Lock()
	session, exists := h.sessions[sessionID]
	h.sessionsMu.Unlock()

	if !exists {
		return
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if err != nil {
		session.Status = StatusFailed
		session.Error = err
		return
	}

	// Convert complex result to bytes
	resultBytes := make([]byte, len(result)*16) // 8 bytes real + 8 bytes imag per value
	for i, v := range result {
		realPart := real(v)
		imagPart := imag(v)
		// Store as int64 for blockchain compatibility
		binary.BigEndian.PutUint64(resultBytes[i*16:], uint64(int64(realPart)))
		binary.BigEndian.PutUint64(resultBytes[i*16+8:], uint64(int64(imagPart)))
	}

	session.Result = resultBytes
	session.Status = StatusCompleted
}

// SubmitDecryptionShare processes a decryption share from another party
func (h *FHEProtocolHandler) SubmitDecryptionShare(
	sessionID [32]byte,
	partyID uint64,
	share []byte,
) error {
	h.sessionsMu.RLock()
	session, exists := h.sessions[sessionID]
	h.sessionsMu.RUnlock()

	if !exists {
		return errors.New("session not found")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.Status == StatusCompleted || session.Status == StatusFailed {
		return errors.New("session already finished")
	}

	session.Shares[partyID] = share
	session.ShareCount++
	session.Status = StatusCollecting

	// Check if we have enough shares
	if session.ShareCount >= h.threshold {
		session.Status = StatusProcessing
		// The threshold decryptor will handle the actual combination
	}

	return nil
}

// GetSessionStatus returns the status of a session
func (h *FHEProtocolHandler) GetSessionStatus(sessionID [32]byte) (*FHESession, error) {
	h.sessionsMu.RLock()
	defer h.sessionsMu.RUnlock()

	session, exists := h.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}

	return session, nil
}

// GetDecryptionResult returns the decryption result if available
func (h *FHEProtocolHandler) GetDecryptionResult(sessionID [32]byte) ([]byte, error) {
	h.sessionsMu.RLock()
	session, exists := h.sessions[sessionID]
	h.sessionsMu.RUnlock()

	if !exists {
		return nil, errors.New("session not found")
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.Status != StatusCompleted {
		if session.Status == StatusFailed {
			return nil, session.Error
		}
		return nil, errors.New("decryption not yet complete")
	}

	return session.Result, nil
}

// CleanupSession removes a completed session
func (h *FHEProtocolHandler) CleanupSession(sessionID [32]byte) {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	delete(h.sessions, sessionID)
	h.decryptor.CleanupSession(sessionID)
}

// GenerateDecryptionShare creates this party's decryption share for a ciphertext
func (h *FHEProtocolHandler) GenerateDecryptionShare(ct *Ciphertext) ([]byte, error) {
	if h.secretShare == nil {
		return nil, errors.New("key share not initialized")
	}

	// Use the underlying lattice library to generate the share
	level := ct.Ct.Level()
	publicShare := h.decryptor.e2sProtocol.AllocateShare(level)
	secretShare := multiparty.NewAdditiveShareBigint(h.params.MaxSlots())

	logBound := uint(h.params.LogDefaultScale()) + 10
	if err := h.decryptor.e2sProtocol.GenShare(
		h.secretShare,
		logBound,
		ct.Ct,
		&secretShare,
		&publicShare,
	); err != nil {
		return nil, fmt.Errorf("failed to generate share: %w", err)
	}

	// Serialize the public share
	shareBytes, err := publicShare.Value.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize share: %w", err)
	}

	return shareBytes, nil
}

// FHEMessage represents a message for FHE protocol communication
type FHEMessage struct {
	Type      FHEMessageType
	SessionID [32]byte
	PartyID   uint64
	Payload   []byte
}

// FHEMessageType represents the type of FHE protocol message
type FHEMessageType uint8

const (
	MsgDecryptRequest FHEMessageType = iota
	MsgDecryptShare
	MsgDecryptResult
	MsgKeygenRound1
	MsgKeygenRound2
	MsgKeygenComplete
	MsgReshareRequest
	MsgReshareShare
	MsgRefreshRequest
	MsgRefreshShare
)

// HandleMessage processes an incoming FHE protocol message
func (h *FHEProtocolHandler) HandleMessage(msg *FHEMessage) error {
	switch msg.Type {
	case MsgDecryptShare:
		return h.SubmitDecryptionShare(msg.SessionID, msg.PartyID, msg.Payload)
	case MsgDecryptRequest:
		// Parse ciphertext from payload and start decryption
		// This would be called when receiving a request from another node
		return nil
	default:
		return fmt.Errorf("unknown message type: %d", msg.Type)
	}
}

// CreateDecryptShareMessage creates a message containing our decryption share
func (h *FHEProtocolHandler) CreateDecryptShareMessage(sessionID [32]byte, share []byte) *FHEMessage {
	return &FHEMessage{
		Type:      MsgDecryptShare,
		SessionID: sessionID,
		PartyID:   uint64(h.partyID),
		Payload:   share,
	}
}
