// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

var (
	ErrEpochNotActive       = errors.New("epoch not active")
	ErrEpochAlreadyActive   = errors.New("epoch already active")
	ErrCommitteeFull        = errors.New("committee is full")
	ErrMemberNotFound       = errors.New("committee member not found")
	ErrMemberAlreadyExists  = errors.New("committee member already exists")
	ErrInsufficientWeight   = errors.New("insufficient committee weight")
	ErrDKGInProgress        = errors.New("DKG ceremony in progress")
	ErrDKGNotStarted        = errors.New("DKG ceremony not started")
	ErrDKGFailed            = errors.New("DKG ceremony failed")
	ErrMissingCommitment    = errors.New("participant must submit commitment first")
	ErrNotParticipant       = errors.New("node is not a DKG participant")
	ErrTransitionInProgress = errors.New("epoch transition in progress")
	ErrInvalidThreshold     = errors.New("invalid threshold")
	ErrEpochExpired         = errors.New("epoch has expired")
)

// LifecycleConfig configures the lifecycle manager
type LifecycleConfig struct {
	// EpochDuration is the duration of each epoch in blocks
	EpochDuration uint64 `json:"epoch_duration"`
	// GracePeriod is the number of blocks to allow pending requests during transition
	GracePeriod uint64 `json:"grace_period"`
	// MinCommitteeSize is the minimum number of committee members
	MinCommitteeSize int `json:"min_committee_size"`
	// MaxCommitteeSize is the maximum number of committee members
	MaxCommitteeSize int `json:"max_committee_size"`
	// DefaultThreshold is the default threshold (e.g., 67 for 67-of-100)
	DefaultThreshold int `json:"default_threshold"`
	// DKGTimeout is the timeout for DKG ceremonies
	DKGTimeout time.Duration `json:"dkg_timeout"`
	// KeyRotationBlocks is how often to rotate keys (0 = never)
	KeyRotationBlocks uint64 `json:"key_rotation_blocks"`
}

// DefaultLifecycleConfig returns sensible defaults
func DefaultLifecycleConfig() *LifecycleConfig {
	return &LifecycleConfig{
		EpochDuration:     100000, // ~1 day at 1 block/sec
		GracePeriod:       1000,   // ~16 minutes
		MinCommitteeSize:  4,
		MaxCommitteeSize:  100,
		DefaultThreshold:  67,
		DKGTimeout:        5 * time.Minute,
		KeyRotationBlocks: 0, // Disabled by default
	}
}

// DKGState represents the state of a DKG ceremony
type DKGState struct {
	CeremonyID   [32]byte          `json:"ceremony_id"`
	Epoch        uint64            `json:"epoch"`
	Participants []ids.NodeID      `json:"participants"`
	Threshold    int               `json:"threshold"`
	Shares       map[string][]byte `json:"shares"` // NodeID hex -> encrypted share
	Commitments  map[string][]byte `json:"commitments"`
	PublicKey    []byte            `json:"public_key,omitempty"`
	Status       DKGStatus         `json:"status"`
	StartedAt    int64             `json:"started_at"`
	CompletedAt  int64             `json:"completed_at,omitempty"`
	Error        string            `json:"error,omitempty"`
}

type DKGStatus uint8

const (
	DKGPending DKGStatus = iota
	DKGCommitPhase
	DKGSharePhase
	DKGCompleted
	DKGFailed
	DKGAborted
)

func (s DKGStatus) String() string {
	switch s {
	case DKGPending:
		return "pending"
	case DKGCommitPhase:
		return "commit_phase"
	case DKGSharePhase:
		return "share_phase"
	case DKGCompleted:
		return "completed"
	case DKGFailed:
		return "failed"
	case DKGAborted:
		return "aborted"
	default:
		return "unknown"
	}
}

// TransitionState tracks epoch transition progress
type TransitionState struct {
	FromEpoch       uint64           `json:"from_epoch"`
	ToEpoch         uint64           `json:"to_epoch"`
	Status          TransitionStatus `json:"status"`
	StartedAt       int64            `json:"started_at"`
	CompletedAt     int64            `json:"completed_at,omitempty"`
	PendingRequests int              `json:"pending_requests"`
	MigratedCount   int              `json:"migrated_count"`
	Error           string           `json:"error,omitempty"`
}

type TransitionStatus uint8

const (
	TransitionPending TransitionStatus = iota
	TransitionDKGPhase
	TransitionMigrationPhase
	TransitionFinalizingPhase
	TransitionCompleted
	TransitionFailed
)

func (s TransitionStatus) String() string {
	switch s {
	case TransitionPending:
		return "pending"
	case TransitionDKGPhase:
		return "dkg_phase"
	case TransitionMigrationPhase:
		return "migration_phase"
	case TransitionFinalizingPhase:
		return "finalizing"
	case TransitionCompleted:
		return "completed"
	case TransitionFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// MemberRegistration represents a pending committee member registration
type MemberRegistration struct {
	NodeID       ids.NodeID   `json:"node_id"`
	PublicKey    []byte       `json:"public_key"`
	Stake        uint64       `json:"stake"`
	RegisteredAt int64        `json:"registered_at"`
	ActivatedAt  int64        `json:"activated_at,omitempty"`
	Status       MemberStatus `json:"status"`
}

type MemberStatus uint8

const (
	MemberPending MemberStatus = iota
	MemberActive
	MemberInactive
	MemberSlashed
	MemberExiting
)

func (s MemberStatus) String() string {
	switch s {
	case MemberPending:
		return "pending"
	case MemberActive:
		return "active"
	case MemberInactive:
		return "inactive"
	case MemberSlashed:
		return "slashed"
	case MemberExiting:
		return "exiting"
	default:
		return "unknown"
	}
}

// deferredCallback holds callback information to invoke after releasing the mutex.
// This prevents deadlock by ensuring external callbacks are never called while holding locks.
type deferredCallback struct {
	// DKG completion callback data
	dkgComplete  bool
	dkgEpoch     uint64
	dkgPublicKey []byte

	// Epoch change callback data
	epochChange bool
	oldEpoch    uint64
	newEpoch    uint64
}

// LifecycleManager manages epoch and committee lifecycle
type LifecycleManager struct {
	registry *Registry
	config   *LifecycleConfig
	logger   log.Logger

	mu                sync.RWMutex
	currentDKG        *DKGState
	currentTransition *TransitionState

	// Callbacks
	onEpochChange     func(oldEpoch, newEpoch uint64)
	onCommitteeChange func(members []CommitteeMember)
	onDKGComplete     func(epoch uint64, publicKey []byte)
	onDKGStart        func(ceremonyID [32]byte, epoch uint64, participants []ids.NodeID)
	onDKGPhaseChange  func(ceremonyID [32]byte, phase DKGStatus)
	onSlash           func(nodeID ids.NodeID, reason string)

	// Block tracking
	currentBlock uint64

	ctx    context.Context
	cancel context.CancelFunc
}

// invokeCallback safely invokes deferred callbacks after the mutex is released.
// Must be called WITHOUT holding the mutex.
func (lm *LifecycleManager) invokeCallback(cb *deferredCallback) {
	if cb == nil {
		return
	}
	if cb.dkgComplete && lm.onDKGComplete != nil {
		lm.onDKGComplete(cb.dkgEpoch, cb.dkgPublicKey)
	}
	if cb.epochChange && lm.onEpochChange != nil {
		lm.onEpochChange(cb.oldEpoch, cb.newEpoch)
	}
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager(registry *Registry, config *LifecycleConfig, logger log.Logger) *LifecycleManager {
	if config == nil {
		config = DefaultLifecycleConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &LifecycleManager{
		registry: registry,
		config:   config,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start begins lifecycle management
func (lm *LifecycleManager) Start() error {
	lm.logger.Info("Starting FHE lifecycle manager")

	// Load any pending DKG or transition state
	if err := lm.loadState(); err != nil {
		return fmt.Errorf("failed to load lifecycle state: %w", err)
	}

	return nil
}

// Stop halts lifecycle management
func (lm *LifecycleManager) Stop() {
	lm.cancel()
	lm.logger.Info("Stopped FHE lifecycle manager")
}

// OnBlock processes a new block for lifecycle events
func (lm *LifecycleManager) OnBlock(blockHeight uint64) error {
	var cb *deferredCallback
	var err error

	func() {
		lm.mu.Lock()
		defer lm.mu.Unlock()

		lm.currentBlock = blockHeight

		// Check for DKG timeout
		if lm.currentDKG != nil &&
			lm.currentDKG.Status != DKGCompleted &&
			lm.currentDKG.Status != DKGFailed &&
			lm.currentDKG.Status != DKGAborted {
			startTime := time.Unix(lm.currentDKG.StartedAt, 0)
			if time.Since(startTime) > lm.config.DKGTimeout {
				lm.logger.Warn("DKG ceremony timed out",
					"ceremony_id", fmt.Sprintf("%x", lm.currentDKG.CeremonyID[:8]),
					"epoch", lm.currentDKG.Epoch,
					"started_at", lm.currentDKG.StartedAt,
					"timeout", lm.config.DKGTimeout)

				lm.currentDKG.Status = DKGFailed
				lm.currentDKG.Error = "DKG ceremony timed out"
				lm.currentDKG.CompletedAt = time.Now().Unix()

				// Also fail the transition if in progress
				if lm.currentTransition != nil &&
					lm.currentTransition.Status == TransitionDKGPhase {
					lm.currentTransition.Status = TransitionFailed
					lm.currentTransition.Error = "DKG ceremony timed out"
					lm.currentTransition.CompletedAt = time.Now().Unix()
				}
			}
		}

		// Check if we need to start an epoch transition
		if lm.shouldStartTransition(blockHeight) {
			err = lm.startTransitionLocked()
			return
		}

		// Check if we need to finalize a transition
		if lm.currentTransition != nil && lm.shouldFinalizeTransition(blockHeight) {
			cb, err = lm.finalizeTransitionLocked()
			return
		}

		// Check for key rotation
		if lm.config.KeyRotationBlocks > 0 && blockHeight%lm.config.KeyRotationBlocks == 0 {
			lm.logger.Info("Triggering key rotation", "block", blockHeight)
			err = lm.startKeyRotationLocked()
			return
		}
	}()

	// Invoke callback AFTER releasing the mutex to prevent deadlock
	lm.invokeCallback(cb)

	return err
}

// shouldStartTransition checks if we need to start a new epoch
func (lm *LifecycleManager) shouldStartTransition(blockHeight uint64) bool {
	if lm.currentTransition != nil {
		return false // Already transitioning
	}

	epoch := lm.registry.GetCurrentEpoch()
	epochInfo, err := lm.registry.GetEpoch(epoch)
	if err != nil {
		return false
	}

	// Check if epoch has exceeded duration
	epochStartBlock := uint64(epochInfo.StartTime) // Assuming StartTime is block height for now
	return blockHeight >= epochStartBlock+lm.config.EpochDuration
}

// shouldFinalizeTransition checks if transition can be finalized
func (lm *LifecycleManager) shouldFinalizeTransition(blockHeight uint64) bool {
	if lm.currentTransition == nil {
		return false
	}

	// Must be past grace period and DKG must be complete
	transitionStart := uint64(lm.currentTransition.StartedAt)
	if blockHeight < transitionStart+lm.config.GracePeriod {
		return false
	}

	return lm.currentTransition.Status == TransitionFinalizingPhase
}

// RegisterMember registers a new committee member candidate
func (lm *LifecycleManager) RegisterMember(nodeID ids.NodeID, publicKey []byte, stake uint64) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check if member already exists
	_, err := lm.registry.GetCommitteeMember(nodeID)
	if err == nil {
		return ErrMemberAlreadyExists
	}

	// Check committee size
	members, err := lm.registry.GetCommittee()
	if err != nil {
		return err
	}
	if len(members) >= lm.config.MaxCommitteeSize {
		return ErrCommitteeFull
	}

	// Add member (will be activated on next epoch)
	member := &CommitteeMember{
		NodeID:    nodeID,
		PublicKey: publicKey,
		Weight:    stake,
		Index:     len(members),
	}

	if err := lm.registry.AddCommitteeMember(member); err != nil {
		return err
	}

	lm.logger.Info("Registered committee member",
		"nodeID", nodeID,
		"stake", stake,
		"index", member.Index)

	return nil
}

// RemoveMember removes a committee member (effective next epoch)
func (lm *LifecycleManager) RemoveMember(nodeID ids.NodeID) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if err := lm.registry.RemoveCommitteeMember(nodeID); err != nil {
		return err
	}

	lm.logger.Info("Removed committee member", "nodeID", nodeID)

	// Check if we still have enough members
	members, err := lm.registry.GetCommittee()
	if err != nil {
		return err
	}

	if len(members) < lm.config.MinCommitteeSize {
		lm.logger.Warn("Committee below minimum size",
			"current", len(members),
			"min", lm.config.MinCommitteeSize)
	}

	return nil
}

// SlashMember slashes a misbehaving committee member
func (lm *LifecycleManager) SlashMember(nodeID ids.NodeID, reason string) error {
	var onSlash func(ids.NodeID, string)

	func() {
		lm.mu.Lock()
		defer lm.mu.Unlock()

		lm.logger.Warn("Slashing committee member",
			"nodeID", nodeID,
			"reason", reason)

		// Remove from active committee
		if err := lm.registry.RemoveCommitteeMember(nodeID); err != nil {
			return
		}

		// Capture callback to invoke after releasing lock
		onSlash = lm.onSlash
	}()

	// Emit slashing event for on-chain penalty via callback
	if onSlash != nil {
		onSlash(nodeID, reason)
	}

	return nil
}

// InitiateEpoch creates the first epoch (genesis)
func (lm *LifecycleManager) InitiateEpoch(committee []CommitteeMember, threshold int, publicKey []byte) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if len(committee) < lm.config.MinCommitteeSize {
		return fmt.Errorf("committee size %d below minimum %d", len(committee), lm.config.MinCommitteeSize)
	}

	if threshold <= 0 || threshold > len(committee) {
		return ErrInvalidThreshold
	}

	epochInfo := &EpochInfo{
		Epoch:     1,
		StartTime: time.Now().Unix(),
		Committee: committee,
		Threshold: threshold,
		PublicKey: publicKey,
		Status:    EpochActive,
	}

	if err := lm.registry.SetEpoch(1, epochInfo); err != nil {
		return err
	}

	lm.logger.Info("Initiated first epoch",
		"committee_size", len(committee),
		"threshold", threshold)

	return nil
}

// StartDKG initiates a DKG ceremony for a new epoch
func (lm *LifecycleManager) StartDKG(epoch uint64, participants []ids.NodeID, threshold int) error {
	var onDKGStart func([32]byte, uint64, []ids.NodeID)
	var ceremonyID [32]byte

	err := func() error {
		lm.mu.Lock()
		defer lm.mu.Unlock()
		err := lm.startDKGLocked(epoch, participants, threshold)
		if err == nil && lm.currentDKG != nil {
			ceremonyID = lm.currentDKG.CeremonyID
			onDKGStart = lm.onDKGStart
		}
		return err
	}()

	if err != nil {
		return err
	}

	// Broadcast DKG start message to participants via callback
	if onDKGStart != nil {
		onDKGStart(ceremonyID, epoch, participants)
	}

	return nil
}

// startDKGLocked is the internal version that doesn't acquire the lock
func (lm *LifecycleManager) startDKGLocked(epoch uint64, participants []ids.NodeID, threshold int) error {
	if lm.currentDKG != nil && lm.currentDKG.Status != DKGCompleted && lm.currentDKG.Status != DKGFailed && lm.currentDKG.Status != DKGAborted {
		return ErrDKGInProgress
	}

	if len(participants) < lm.config.MinCommitteeSize {
		return fmt.Errorf("not enough participants: %d < %d", len(participants), lm.config.MinCommitteeSize)
	}

	if threshold <= 0 || threshold > len(participants) {
		return ErrInvalidThreshold
	}

	var ceremonyID [32]byte
	if _, err := rand.Read(ceremonyID[:]); err != nil {
		return fmt.Errorf("failed to generate ceremony ID: %w", err)
	}

	lm.currentDKG = &DKGState{
		CeremonyID:   ceremonyID,
		Epoch:        epoch,
		Participants: participants,
		Threshold:    threshold,
		Shares:       make(map[string][]byte),
		Commitments:  make(map[string][]byte),
		Status:       DKGCommitPhase,
		StartedAt:    time.Now().Unix(),
	}

	lm.logger.Info("Started DKG ceremony",
		"ceremony_id", fmt.Sprintf("%x", ceremonyID[:8]),
		"epoch", epoch,
		"participants", len(participants),
		"threshold", threshold)

	return nil
}

// SubmitDKGCommitment receives a commitment from a participant
func (lm *LifecycleManager) SubmitDKGCommitment(nodeID ids.NodeID, commitment []byte) error {
	var onPhaseChange func([32]byte, DKGStatus)
	var ceremonyID [32]byte
	var movedToSharePhase bool

	err := func() error {
		lm.mu.Lock()
		defer lm.mu.Unlock()

		if lm.currentDKG == nil {
			return ErrDKGNotStarted
		}

		if lm.currentDKG.Status != DKGCommitPhase {
			return fmt.Errorf("DKG not in commit phase: %s", lm.currentDKG.Status)
		}

		// Verify participant
		found := false
		for _, p := range lm.currentDKG.Participants {
			if p == nodeID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("node %s not a DKG participant", nodeID)
		}

		lm.currentDKG.Commitments[nodeID.String()] = commitment

		lm.logger.Debug("Received DKG commitment",
			"nodeID", nodeID,
			"commitments", len(lm.currentDKG.Commitments),
			"total", len(lm.currentDKG.Participants))

		// Check if we have all commitments
		if len(lm.currentDKG.Commitments) == len(lm.currentDKG.Participants) {
			lm.currentDKG.Status = DKGSharePhase
			lm.logger.Info("DKG moving to share phase")
			movedToSharePhase = true
			ceremonyID = lm.currentDKG.CeremonyID
			onPhaseChange = lm.onDKGPhaseChange
		}

		return nil
	}()

	if err != nil {
		return err
	}

	// Broadcast share phase start via callback
	if movedToSharePhase && onPhaseChange != nil {
		onPhaseChange(ceremonyID, DKGSharePhase)
	}

	return nil
}

// SubmitDKGShare receives an encrypted share from a participant
func (lm *LifecycleManager) SubmitDKGShare(nodeID ids.NodeID, share []byte) error {
	var cb *deferredCallback
	var err error

	func() {
		lm.mu.Lock()
		defer lm.mu.Unlock()

		if lm.currentDKG == nil {
			err = ErrDKGNotStarted
			return
		}

		if lm.currentDKG.Status != DKGSharePhase {
			err = fmt.Errorf("DKG not in share phase: %s", lm.currentDKG.Status)
			return
		}

		// Verify this node is a DKG participant
		found := false
		for _, p := range lm.currentDKG.Participants {
			if p == nodeID {
				found = true
				break
			}
		}
		if !found {
			err = ErrNotParticipant
			return
		}

		// Verify this participant submitted a commitment (proves participation)
		if _, hasCommitment := lm.currentDKG.Commitments[nodeID.String()]; !hasCommitment {
			err = ErrMissingCommitment
			return
		}

		lm.currentDKG.Shares[nodeID.String()] = share

		lm.logger.Debug("Received DKG share",
			"nodeID", nodeID,
			"shares", len(lm.currentDKG.Shares),
			"total", len(lm.currentDKG.Participants))

		// Check if we have enough shares
		if len(lm.currentDKG.Shares) >= lm.currentDKG.Threshold {
			cb, err = lm.completeDKGLocked()
		}
	}()

	// Invoke callback AFTER releasing the mutex to prevent deadlock
	lm.invokeCallback(cb)

	return err
}

// completeDKGLocked finalizes the DKG ceremony.
// Returns callback info to be invoked AFTER the mutex is released.
func (lm *LifecycleManager) completeDKGLocked() (*deferredCallback, error) {
	// Aggregate public key from commitments
	// In a real implementation, this would use the actual DKG protocol
	publicKey := lm.aggregatePublicKey()

	lm.currentDKG.PublicKey = publicKey
	lm.currentDKG.Status = DKGCompleted
	lm.currentDKG.CompletedAt = time.Now().Unix()

	lm.logger.Info("DKG ceremony completed",
		"epoch", lm.currentDKG.Epoch,
		"public_key_len", len(publicKey))

	// Persist state after DKG completion (critical for crash recovery)
	if err := lm.persistStateLocked(); err != nil {
		lm.logger.Error("Failed to persist DKG completion state", "error", err)
	}

	// Return callback info - caller will invoke after releasing lock
	return &deferredCallback{
		dkgComplete:  true,
		dkgEpoch:     lm.currentDKG.Epoch,
		dkgPublicKey: publicKey,
	}, nil
}

// aggregatePublicKey combines commitments into the threshold public key.
// Uses BLS12-381 elliptic curve point addition for Feldman VSS commitment coefficients.
// The first 48 bytes of each commitment are the compressed BLS public key share (G1 point).
// Falls back to deterministic XOR combination for non-BLS commitments or testing.
func (lm *LifecycleManager) aggregatePublicKey() []byte {
	if len(lm.currentDKG.Commitments) == 0 {
		// Return 32-byte zero slice for empty commitments (maintains API compatibility)
		return make([]byte, 32)
	}

	// Try BLS aggregation first for proper cryptographic security
	var pubKeys []*bls.PublicKey
	for nodeID, commitment := range lm.currentDKG.Commitments {
		if len(commitment) >= bls.PublicKeyLen {
			// Parse BLS public key from commitment (first 48 bytes is compressed G1 point)
			pubKey, err := bls.PublicKeyFromCompressedBytes(commitment[:bls.PublicKeyLen])
			if err == nil {
				pubKeys = append(pubKeys, pubKey)
			} else {
				lm.logger.Debug("Commitment not in BLS format, using fallback",
					"nodeID", nodeID)
			}
		}
	}

	// If we have valid BLS keys, use proper curve arithmetic
	if len(pubKeys) > 0 {
		aggregatedPubKey, err := bls.AggregatePublicKeys(pubKeys)
		if err == nil {
			return bls.PublicKeyToCompressedBytes(aggregatedPubKey)
		}
		lm.logger.Warn("BLS aggregation failed, using fallback", "error", err)
	}

	// Fallback: deterministic XOR combination for non-BLS commitments or testing
	// This provides a unique, reproducible aggregate but is NOT cryptographically secure
	// Production deployments MUST use proper BLS-formatted commitments
	result := make([]byte, 32)
	for _, commitment := range lm.currentDKG.Commitments {
		if len(commitment) >= 32 {
			for i := 0; i < 32; i++ {
				result[i] ^= commitment[i]
			}
		}
	}
	return result
}

// AbortDKG aborts a DKG ceremony
func (lm *LifecycleManager) AbortDKG(reason string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.currentDKG == nil {
		return ErrDKGNotStarted
	}

	lm.currentDKG.Status = DKGAborted
	lm.currentDKG.Error = reason
	lm.currentDKG.CompletedAt = time.Now().Unix()

	lm.logger.Warn("DKG ceremony aborted", "reason", reason)

	// Persist aborted state for crash recovery
	if err := lm.persistStateLocked(); err != nil {
		lm.logger.Error("Failed to persist DKG abort state", "error", err)
	}

	return nil
}

// startTransitionLocked begins an epoch transition
func (lm *LifecycleManager) startTransitionLocked() error {
	currentEpoch := lm.registry.GetCurrentEpoch()
	newEpoch := currentEpoch + 1

	lm.currentTransition = &TransitionState{
		FromEpoch: currentEpoch,
		ToEpoch:   newEpoch,
		Status:    TransitionDKGPhase,
		StartedAt: time.Now().Unix(),
	}

	lm.logger.Info("Starting epoch transition",
		"from", currentEpoch,
		"to", newEpoch)

	// Persist transition state immediately for crash recovery
	if err := lm.persistStateLocked(); err != nil {
		lm.logger.Error("Failed to persist transition start state", "error", err)
	}

	// Get current committee for new DKG
	members, err := lm.registry.GetCommittee()
	if err != nil {
		return err
	}

	participants := make([]ids.NodeID, len(members))
	for i, m := range members {
		participants[i] = m.NodeID
	}

	// Start DKG for new epoch
	threshold := lm.config.DefaultThreshold
	if threshold > len(participants) {
		threshold = (len(participants) * 2) / 3 // 2/3 majority
	}

	return lm.startDKGLocked(newEpoch, participants, threshold)
}

// finalizeTransitionLocked completes the epoch transition.
// Returns callback info to be invoked AFTER the mutex is released.
func (lm *LifecycleManager) finalizeTransitionLocked() (*deferredCallback, error) {
	if lm.currentTransition == nil {
		return nil, nil
	}

	if lm.currentDKG == nil || lm.currentDKG.Status != DKGCompleted {
		return nil, ErrDKGNotStarted
	}

	// End current epoch
	currentEpoch := lm.registry.GetCurrentEpoch()
	epochInfo, err := lm.registry.GetEpoch(currentEpoch)
	if err == nil {
		epochInfo.Status = EpochEnded
		epochInfo.EndTime = time.Now().Unix()
		if err := lm.registry.SetEpoch(currentEpoch, epochInfo); err != nil {
			return nil, err
		}
	}

	// Create new epoch with DKG results
	members, _ := lm.registry.GetCommittee()
	newEpochInfo := &EpochInfo{
		Epoch:     lm.currentTransition.ToEpoch,
		StartTime: time.Now().Unix(),
		Committee: members,
		Threshold: lm.currentDKG.Threshold,
		PublicKey: lm.currentDKG.PublicKey,
		Status:    EpochActive,
	}

	if err := lm.registry.SetEpoch(lm.currentTransition.ToEpoch, newEpochInfo); err != nil {
		return nil, err
	}

	// Update transition state
	lm.currentTransition.Status = TransitionCompleted
	lm.currentTransition.CompletedAt = time.Now().Unix()

	oldEpoch := lm.currentTransition.FromEpoch
	newEpoch := lm.currentTransition.ToEpoch

	lm.logger.Info("Epoch transition completed",
		"from", oldEpoch,
		"to", newEpoch,
		"committee_size", len(members),
		"threshold", lm.currentDKG.Threshold)

	// Persist final state before clearing (critical for crash recovery)
	if err := lm.persistStateLocked(); err != nil {
		lm.logger.Error("Failed to persist transition completion state", "error", err)
	}

	// Clear transition state
	lm.currentTransition = nil
	lm.currentDKG = nil

	// Return callback info - caller will invoke after releasing lock
	return &deferredCallback{
		epochChange: true,
		oldEpoch:    oldEpoch,
		newEpoch:    newEpoch,
	}, nil
}

// startKeyRotationLocked initiates a key rotation within the current epoch
func (lm *LifecycleManager) startKeyRotationLocked() error {
	// Key rotation uses re-encryption rather than full epoch transition
	// This allows refreshing keys without changing the epoch

	currentEpoch := lm.registry.GetCurrentEpoch()
	members, err := lm.registry.GetCommittee()
	if err != nil {
		return err
	}

	participants := make([]ids.NodeID, len(members))
	for i, m := range members {
		participants[i] = m.NodeID
	}

	epochInfo, err := lm.registry.GetEpoch(currentEpoch)
	if err != nil {
		return err
	}

	// Start a new DKG but stay in the same epoch
	return lm.startDKGLocked(currentEpoch, participants, epochInfo.Threshold)
}

// GetDKGState returns the current DKG state
func (lm *LifecycleManager) GetDKGState() *DKGState {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.currentDKG
}

// GetTransitionState returns the current transition state
func (lm *LifecycleManager) GetTransitionState() *TransitionState {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.currentTransition
}

// IsTransitioning returns whether an epoch transition is in progress
func (lm *LifecycleManager) IsTransitioning() bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.currentTransition != nil
}

// GetCommitteeWeight calculates total committee weight
func (lm *LifecycleManager) GetCommitteeWeight() (uint64, error) {
	members, err := lm.registry.GetCommittee()
	if err != nil {
		return 0, err
	}

	var total uint64
	for _, m := range members {
		total += m.Weight
	}
	return total, nil
}

// ValidateThresholdMet checks if threshold requirements are met
func (lm *LifecycleManager) ValidateThresholdMet(participantCount int) error {
	epoch := lm.registry.GetCurrentEpoch()
	epochInfo, err := lm.registry.GetEpoch(epoch)
	if err != nil {
		return err
	}

	if participantCount < epochInfo.Threshold {
		return ErrInsufficientWeight
	}

	return nil
}

// SetCallbacks sets lifecycle event callbacks
func (lm *LifecycleManager) SetCallbacks(
	onEpochChange func(oldEpoch, newEpoch uint64),
	onCommitteeChange func(members []CommitteeMember),
	onDKGComplete func(epoch uint64, publicKey []byte),
) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.onEpochChange = onEpochChange
	lm.onCommitteeChange = onCommitteeChange
	lm.onDKGComplete = onDKGComplete
}

// SetDKGCallbacks sets DKG-specific event callbacks
func (lm *LifecycleManager) SetDKGCallbacks(
	onDKGStart func(ceremonyID [32]byte, epoch uint64, participants []ids.NodeID),
	onDKGPhaseChange func(ceremonyID [32]byte, phase DKGStatus),
) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.onDKGStart = onDKGStart
	lm.onDKGPhaseChange = onDKGPhaseChange
}

// SetSlashCallback sets the slashing event callback
func (lm *LifecycleManager) SetSlashCallback(onSlash func(nodeID ids.NodeID, reason string)) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.onSlash = onSlash
}

// loadState loads persisted lifecycle state
func (lm *LifecycleManager) loadState() error {
	if lm.registry == nil || lm.registry.db == nil {
		return nil
	}

	// Load any active DKG state
	currentEpoch := lm.registry.GetCurrentEpoch()
	dkgKey := append([]byte("lifecycle:dkg:"), encodeUint64(currentEpoch)...)
	if dkgData, err := lm.registry.db.Get(dkgKey); err == nil && len(dkgData) > 0 {
		var dkg DKGState
		if err := json.Unmarshal(dkgData, &dkg); err == nil {
			// Only restore if DKG is still in progress
			if dkg.Status != DKGCompleted && dkg.Status != DKGFailed && dkg.Status != DKGAborted {
				lm.currentDKG = &dkg
				lm.logger.Info("Restored DKG state from database",
					"epoch", dkg.Epoch,
					"status", dkg.Status.String())
			}
		}
	}

	// Load any active transition state
	transitionKey := append([]byte("lifecycle:transition:"), encodeUint64(currentEpoch+1)...)
	if transitionData, err := lm.registry.db.Get(transitionKey); err == nil && len(transitionData) > 0 {
		var transition TransitionState
		if err := json.Unmarshal(transitionData, &transition); err == nil {
			// Only restore if transition is still in progress
			if transition.Status != TransitionCompleted && transition.Status != TransitionFailed {
				lm.currentTransition = &transition
				lm.logger.Info("Restored transition state from database",
					"fromEpoch", transition.FromEpoch,
					"toEpoch", transition.ToEpoch,
					"status", transition.Status.String())
			}
		}
	}

	return nil
}

// persistStateLocked saves lifecycle state (caller must hold mutex)
func (lm *LifecycleManager) persistStateLocked() error {
	if lm.registry == nil || lm.registry.db == nil {
		return nil
	}

	// Persist DKG state if active
	if lm.currentDKG != nil {
		data, err := json.Marshal(lm.currentDKG)
		if err != nil {
			return err
		}
		key := append([]byte("lifecycle:dkg:"), encodeUint64(lm.currentDKG.Epoch)...)
		if err := lm.registry.db.Put(key, data); err != nil {
			return err
		}
	}

	// Persist transition state if active
	if lm.currentTransition != nil {
		data, err := json.Marshal(lm.currentTransition)
		if err != nil {
			return err
		}
		key := append([]byte("lifecycle:transition:"), encodeUint64(lm.currentTransition.ToEpoch)...)
		if err := lm.registry.db.Put(key, data); err != nil {
			return err
		}
	}

	return nil
}

// persistState saves lifecycle state (acquires lock)
func (lm *LifecycleManager) persistState() error {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.persistStateLocked()
}

// EpochKeyInfo returns the public key info for an epoch
type EpochKeyInfo struct {
	Epoch     uint64 `json:"epoch"`
	PublicKey []byte `json:"public_key"`
	Threshold int    `json:"threshold"`
	Committee int    `json:"committee_size"`
	IsActive  bool   `json:"is_active"`
}

// GetEpochKeyInfo returns key information for a specific epoch
func (lm *LifecycleManager) GetEpochKeyInfo(epoch uint64) (*EpochKeyInfo, error) {
	epochInfo, err := lm.registry.GetEpoch(epoch)
	if err != nil {
		return nil, err
	}

	return &EpochKeyInfo{
		Epoch:     epoch,
		PublicKey: epochInfo.PublicKey,
		Threshold: epochInfo.Threshold,
		Committee: len(epochInfo.Committee),
		IsActive:  epochInfo.Status == EpochActive,
	}, nil
}

// ForceEpochTransition manually triggers an epoch transition (admin only)
func (lm *LifecycleManager) ForceEpochTransition() error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.currentTransition != nil {
		return ErrTransitionInProgress
	}

	lm.logger.Warn("Forcing epoch transition")
	return lm.startTransitionLocked()
}

// GetLifecycleStatus returns overall lifecycle status
type LifecycleStatus struct {
	CurrentEpoch     uint64  `json:"current_epoch"`
	CurrentBlock     uint64  `json:"current_block"`
	CommitteeSize    int     `json:"committee_size"`
	Threshold        int     `json:"threshold"`
	IsTransitioning  bool    `json:"is_transitioning"`
	DKGStatus        string  `json:"dkg_status,omitempty"`
	TransitionStatus string  `json:"transition_status,omitempty"`
	EpochProgress    float64 `json:"epoch_progress"`
}

func (lm *LifecycleManager) GetStatus() (*LifecycleStatus, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	epoch := lm.registry.GetCurrentEpoch()
	epochInfo, err := lm.registry.GetEpoch(epoch)
	if err != nil {
		epochInfo = &EpochInfo{}
	}

	status := &LifecycleStatus{
		CurrentEpoch:    epoch,
		CurrentBlock:    lm.currentBlock,
		CommitteeSize:   len(epochInfo.Committee),
		Threshold:       epochInfo.Threshold,
		IsTransitioning: lm.currentTransition != nil,
	}

	if lm.currentDKG != nil {
		status.DKGStatus = lm.currentDKG.Status.String()
	}

	if lm.currentTransition != nil {
		status.TransitionStatus = lm.currentTransition.Status.String()
	}

	// Calculate epoch progress
	epochStart := uint64(epochInfo.StartTime)
	if lm.config.EpochDuration > 0 && lm.currentBlock >= epochStart {
		progress := float64(lm.currentBlock-epochStart) / float64(lm.config.EpochDuration)
		if progress > 1.0 {
			progress = 1.0
		}
		status.EpochProgress = progress
	}

	return status, nil
}
