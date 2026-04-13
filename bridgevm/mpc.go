// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/crypto/threshold"
	"github.com/luxfi/log"
)

var (
	// ErrInsufficientSigners is returned when there aren't enough active signers
	ErrInsufficientSigners = errors.New("insufficient active signers for threshold")

	// ErrSigningTimeout is returned when signing times out
	ErrSigningTimeout = errors.New("signing timeout")

	// ErrInvalidShare is returned when a signature share is invalid
	ErrInvalidShare = errors.New("invalid signature share")

	// ErrNoKeyShare is returned when the node doesn't have a key share
	ErrNoKeyShare = errors.New("no key share available")
)

// MPCKeyManager manages threshold key generation and shares
type MPCKeyManager struct {
	mu sync.RWMutex

	// Threshold scheme (BLS for now, can support others)
	scheme threshold.Scheme

	// Our key share (if we're a signer)
	keyShare threshold.KeyShare

	// Group public key
	groupKey threshold.PublicKey

	// Signer and aggregator
	signer     threshold.Signer
	aggregator threshold.Aggregator
	verifier   threshold.Verifier

	// Epoch tracking
	currentEpoch uint64

	log log.Logger
}

// NewMPCKeyManager creates a new MPC key manager
func NewMPCKeyManager(logger log.Logger) (*MPCKeyManager, error) {
	// Use BLS threshold scheme for non-interactive aggregation
	scheme, err := threshold.GetScheme(threshold.SchemeBLS)
	if err != nil {
		return nil, fmt.Errorf("failed to get BLS scheme: %w", err)
	}

	return &MPCKeyManager{
		scheme: scheme,
		log:    logger,
	}, nil
}

// GenerateKeys performs distributed key generation using trusted dealer model
// In production, this would use proper DKG, but for initial implementation
// we use trusted dealer for simplicity
func (m *MPCKeyManager) GenerateKeys(ctx context.Context, t, totalParties int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.log.Info("generating threshold keys",
		log.Int("threshold", t),
		log.Int("totalParties", totalParties),
	)

	// Use trusted dealer to generate shares
	dealerConfig := threshold.DealerConfig{
		Threshold:    t,
		TotalParties: totalParties,
	}

	dealer, err := m.scheme.NewTrustedDealer(dealerConfig)
	if err != nil {
		return fmt.Errorf("failed to create dealer: %w", err)
	}

	shares, groupKey, err := dealer.GenerateShares(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate shares: %w", err)
	}

	// Store group key
	m.groupKey = groupKey

	// For testing, we store the first share
	// In production, each node would receive their own share via secure channel
	if len(shares) > 0 {
		m.keyShare = shares[0]

		// Create signer
		m.signer, err = m.scheme.NewSigner(m.keyShare)
		if err != nil {
			return fmt.Errorf("failed to create signer: %w", err)
		}
	}

	// Create aggregator and verifier
	m.aggregator, err = m.scheme.NewAggregator(m.groupKey)
	if err != nil {
		return fmt.Errorf("failed to create aggregator: %w", err)
	}

	m.verifier, err = m.scheme.NewVerifier(m.groupKey)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	m.log.Info("threshold keys generated",
		log.String("groupKey", hex.EncodeToString(m.groupKey.Bytes())),
	)

	return nil
}

// SetKeyShare sets this node's key share (used when importing or receiving via DKG)
func (m *MPCKeyManager) SetKeyShare(share threshold.KeyShare) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.keyShare = share

	// Create signer
	signer, err := m.scheme.NewSigner(share)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}

	m.signer = signer

	// Update group key
	m.groupKey = share.GroupKey()

	// Update aggregator and verifier
	aggregator, err := m.scheme.NewAggregator(m.groupKey)
	if err != nil {
		return fmt.Errorf("failed to create aggregator: %w", err)
	}
	m.aggregator = aggregator

	verifier, err := m.scheme.NewVerifier(m.groupKey)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}
	m.verifier = verifier

	m.log.Info("key share updated",
		log.Int("index", share.Index()),
		log.Int("threshold", share.Threshold()),
	)

	return nil
}

// SignShare creates a signature share for a message
func (m *MPCKeyManager) SignShare(ctx context.Context, message []byte) (threshold.SignatureShare, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.signer == nil {
		return nil, ErrNoKeyShare
	}

	// BLS doesn't require nonces or signer indices for share generation
	share, err := m.signer.SignShare(ctx, message, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature share: %w", err)
	}

	m.log.Debug("created signature share",
		log.Int("index", m.signer.Index()),
	)

	return share, nil
}

// VerifyShare verifies a signature share from another signer
func (m *MPCKeyManager) VerifyShare(message []byte, share threshold.SignatureShare, publicShare []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.aggregator == nil {
		return errors.New("aggregator not initialized")
	}

	return m.aggregator.VerifyShare(message, share, publicShare)
}

// AggregateSignature combines signature shares into a final signature
func (m *MPCKeyManager) AggregateSignature(ctx context.Context, message []byte, shares []threshold.SignatureShare) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.aggregator == nil {
		return nil, errors.New("aggregator not initialized")
	}

	if len(shares) == 0 {
		return nil, ErrInsufficientSigners
	}

	// Check we have enough shares (threshold + 1)
	threshold := m.keyShare.Threshold()
	if len(shares) < threshold+1 {
		return nil, fmt.Errorf("need %d shares, got %d", threshold+1, len(shares))
	}

	m.log.Info("aggregating signature shares",
		log.Int("numShares", len(shares)),
		log.Int("threshold", threshold),
	)

	// BLS doesn't use nonce commitments
	signature, err := m.aggregator.Aggregate(ctx, message, shares, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate shares: %w", err)
	}

	return signature.Bytes(), nil
}

// VerifySignature verifies a final threshold signature
func (m *MPCKeyManager) VerifySignature(message, signature []byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.verifier == nil {
		return false
	}

	return m.verifier.VerifyBytes(message, signature)
}

// GetGroupPublicKey returns the threshold group public key
func (m *MPCKeyManager) GetGroupPublicKey() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.groupKey == nil {
		return nil
	}

	return m.groupKey.Bytes()
}

// GetKeyShareBytes returns the serialized key share
func (m *MPCKeyManager) GetKeyShareBytes() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.keyShare == nil {
		return nil
	}

	return m.keyShare.Bytes()
}

// SigningSession manages a distributed signing session
type SigningSession struct {
	mu sync.RWMutex

	// Session ID
	sessionID string

	// Message to sign
	message []byte

	// Participating signers
	signers []int

	// Collected shares
	shares map[int]threshold.SignatureShare

	// Public shares for verification
	publicShares map[int][]byte

	// Timeout
	deadline time.Time

	// Result
	signature []byte
	err       error
	done      chan struct{}

	log log.Logger
}

// NewSigningSession creates a new signing session
func NewSigningSession(sessionID string, message []byte, signers []int, timeout time.Duration, logger log.Logger) *SigningSession {
	return &SigningSession{
		sessionID:    sessionID,
		message:      message,
		signers:      signers,
		shares:       make(map[int]threshold.SignatureShare),
		publicShares: make(map[int][]byte),
		deadline:     time.Now().Add(timeout),
		done:         make(chan struct{}),
		log:          logger,
	}
}

// AddShare adds a signature share to the session
func (s *SigningSession) AddShare(signerIndex int, share threshold.SignatureShare, publicShare []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if session is still active
	if time.Now().After(s.deadline) {
		return ErrSigningTimeout
	}

	// Store share
	s.shares[signerIndex] = share
	s.publicShares[signerIndex] = publicShare

	s.log.Debug("signature share added",
		log.String("sessionID", s.sessionID),
		log.Int("signerIndex", signerIndex),
		log.Int("totalShares", len(s.shares)),
	)

	return nil
}

// GetShares returns all collected shares
func (s *SigningSession) GetShares() []threshold.SignatureShare {
	s.mu.RLock()
	defer s.mu.RUnlock()

	shares := make([]threshold.SignatureShare, 0, len(s.shares))
	for _, share := range s.shares {
		shares = append(shares, share)
	}
	return shares
}

// NumShares returns the number of collected shares
func (s *SigningSession) NumShares() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.shares)
}

// IsComplete checks if we have enough shares
func (s *SigningSession) IsComplete(threshold int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.shares) >= threshold+1
}

// SetResult sets the final signature or error
func (s *SigningSession) SetResult(signature []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.signature = signature
	s.err = err
	close(s.done)
}

// Wait waits for the session to complete or timeout
func (s *SigningSession) Wait(ctx context.Context) ([]byte, error) {
	timeout := time.Until(s.deadline)
	if timeout < 0 {
		return nil, ErrSigningTimeout
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-s.done:
		return s.signature, s.err
	case <-timer.C:
		return nil, ErrSigningTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// MPCCoordinator coordinates threshold signing across multiple parties
type MPCCoordinator struct {
	mu sync.RWMutex

	keyManager *MPCKeyManager

	// Active signing sessions
	sessions map[string]*SigningSession

	log log.Logger
}

// NewMPCCoordinator creates a new MPC coordinator
func NewMPCCoordinator(keyManager *MPCKeyManager, logger log.Logger) *MPCCoordinator {
	return &MPCCoordinator{
		keyManager: keyManager,
		sessions:   make(map[string]*SigningSession),
		log:        logger,
	}
}

// StartSigning initiates a new signing session
func (c *MPCCoordinator) StartSigning(ctx context.Context, sessionID string, message []byte, signers []int, timeout time.Duration) (*SigningSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if session already exists
	if _, exists := c.sessions[sessionID]; exists {
		return nil, fmt.Errorf("session %s already exists", sessionID)
	}

	session := NewSigningSession(sessionID, message, signers, timeout, c.log)
	c.sessions[sessionID] = session

	c.log.Info("signing session started",
		log.String("sessionID", sessionID),
		log.Int("numSigners", len(signers)),
	)

	// Start background task to aggregate when ready
	go c.monitorSession(ctx, sessionID)

	return session, nil
}

// GetSession returns an active signing session
func (c *MPCCoordinator) GetSession(sessionID string) (*SigningSession, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	session, exists := c.sessions[sessionID]
	return session, exists
}

// monitorSession monitors a signing session and aggregates when ready
func (c *MPCCoordinator) monitorSession(ctx context.Context, sessionID string) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			session, exists := c.sessions[sessionID]
			c.mu.RUnlock()

			if !exists {
				return
			}

			// Check if session has timed out
			if time.Now().After(session.deadline) {
				session.SetResult(nil, ErrSigningTimeout)
				c.removeSession(sessionID)
				return
			}

			// Check if we have enough shares
			threshold := c.keyManager.keyShare.Threshold()
			if session.IsComplete(threshold) {
				// Aggregate signature
				shares := session.GetShares()
				signature, err := c.keyManager.AggregateSignature(ctx, session.message, shares)

				session.SetResult(signature, err)
				c.removeSession(sessionID)
				return
			}
		}
	}
}

// removeSession removes a completed session
func (c *MPCCoordinator) removeSession(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.sessions, sessionID)

	c.log.Debug("signing session removed",
		log.String("sessionID", sessionID),
	)
}

// AddShareToVM adds a VM method to handle incoming signature shares
func (vm *VM) HandleSignatureShare(ctx context.Context, sessionID string, signerIndex int, shareBytes, publicShare []byte) error {
	// Get or create session
	session, exists := vm.mpcCoordinator.GetSession(sessionID)
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	// Parse signature share
	share, err := vm.mpcKeyManager.scheme.ParseSignatureShare(shareBytes)
	if err != nil {
		return fmt.Errorf("failed to parse share: %w", err)
	}

	// Verify share before adding
	if err := vm.mpcKeyManager.VerifyShare(session.message, share, publicShare); err != nil {
		vm.log.Warn("invalid signature share",
			"sessionID", sessionID,
			"signerIndex", signerIndex,
			"error", err,
		)
		return fmt.Errorf("invalid share: %w", err)
	}

	// Add to session
	return session.AddShare(signerIndex, share, publicShare)
}
