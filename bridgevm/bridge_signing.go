// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

var (
	// ErrMessageNotSigned is returned when a bridge message lacks required signatures
	ErrMessageNotSigned = errors.New("bridge message not signed")

	// ErrInvalidBridgeSignature is returned when signature verification fails
	ErrInvalidBridgeSignature = errors.New("invalid bridge signature")

	// ErrDeliveryNotConfirmed is returned when message delivery is not confirmed
	ErrDeliveryNotConfirmed = errors.New("delivery not confirmed")
)

// BridgeMessage represents a signed cross-chain message
type BridgeMessage struct {
	// Message identification
	ID        ids.ID    `json:"id"`
	Nonce     uint64    `json:"nonce"`
	Timestamp time.Time `json:"timestamp"`

	// Chain routing
	SourceChain string `json:"sourceChain"`
	DestChain   string `json:"destChain"`

	// Asset transfer
	Asset     ids.ID `json:"asset"`
	Amount    uint64 `json:"amount"`
	Recipient []byte `json:"recipient"`
	Sender    []byte `json:"sender"`

	// Source transaction proof
	SourceTxID    ids.ID `json:"sourceTxId"`
	Confirmations uint32 `json:"confirmations"`

	// Threshold signature
	Signature []byte `json:"signature"`
	SignedBy  []int  `json:"signedBy"` // Indices of signers who participated

	// Delivery confirmation
	DeliveryConfirmation *DeliveryConfirmation `json:"deliveryConfirmation,omitempty"`
}

// DeliveryConfirmation proves message was delivered on destination chain
type DeliveryConfirmation struct {
	DestTxID         ids.ID    `json:"destTxId"`
	DestBlockHeight  uint64    `json:"destBlockHeight"`
	DestConfirms     uint32    `json:"destConfirms"`
	ConfirmedAt      time.Time `json:"confirmedAt"`
	ConfirmSignature []byte    `json:"confirmSignature"` // Threshold signature on delivery
}

// SigningMessage returns the canonical bytes to sign for a bridge message
func (m *BridgeMessage) SigningMessage() []byte {
	h := sha256.New()

	// Include all critical fields in signing hash
	h.Write(m.ID[:])
	h.Write([]byte(fmt.Sprintf("%d", m.Nonce)))
	h.Write([]byte(m.SourceChain))
	h.Write([]byte(m.DestChain))
	h.Write(m.Asset[:])
	h.Write([]byte(fmt.Sprintf("%d", m.Amount)))
	h.Write(m.Recipient)
	h.Write(m.Sender)
	h.Write(m.SourceTxID[:])

	return h.Sum(nil)
}

// Verify verifies the threshold signature on the message
func (m *BridgeMessage) Verify(groupPublicKey []byte, verifier func([]byte, []byte) bool) error {
	if len(m.Signature) == 0 {
		return ErrMessageNotSigned
	}

	signingMsg := m.SigningMessage()

	if !verifier(signingMsg, m.Signature) {
		return ErrInvalidBridgeSignature
	}

	return nil
}

// BridgeSigner handles signing of bridge messages using MPC
type BridgeSigner struct {
	mpcKeyManager  *MPCKeyManager
	mpcCoordinator *MPCCoordinator
	log            log.Logger
}

// NewBridgeSigner creates a new bridge signer
func NewBridgeSigner(keyManager *MPCKeyManager, coordinator *MPCCoordinator, logger log.Logger) *BridgeSigner {
	return &BridgeSigner{
		mpcKeyManager:  keyManager,
		mpcCoordinator: coordinator,
		log:            logger,
	}
}

// RequestSignature initiates threshold signing for a bridge message
func (s *BridgeSigner) RequestSignature(ctx context.Context, message *BridgeMessage, signerIndices []int) (string, error) {
	signingMsg := message.SigningMessage()

	// Generate unique session ID
	sessionID := fmt.Sprintf("bridge-%s-%d", message.ID.String(), message.Nonce)

	s.log.Info("requesting bridge message signature",
		log.String("sessionID", sessionID),
		log.String("messageID", message.ID.String()),
		log.Int("numSigners", len(signerIndices)),
	)

	// Start signing session with 30 second timeout
	_, err := s.mpcCoordinator.StartSigning(ctx, sessionID, signingMsg, signerIndices, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to start signing: %w", err)
	}

	return sessionID, nil
}

// CreateSignatureShare creates this node's signature share for a bridge message
func (s *BridgeSigner) CreateSignatureShare(ctx context.Context, message *BridgeMessage) ([]byte, []byte, error) {
	signingMsg := message.SigningMessage()

	// Create signature share
	share, err := s.mpcKeyManager.SignShare(ctx, signingMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create share: %w", err)
	}

	// Get our public share for verification
	publicShare := s.mpcKeyManager.signer.PublicShare()

	s.log.Debug("created bridge message signature share",
		log.String("messageID", message.ID.String()),
		log.Int("signerIndex", share.Index()),
	)

	return share.Bytes(), publicShare, nil
}

// GetSignature retrieves the completed signature for a session
func (s *BridgeSigner) GetSignature(ctx context.Context, sessionID string) ([]byte, error) {
	session, exists := s.mpcCoordinator.GetSession(sessionID)
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	// Wait for signature to be ready
	signature, err := session.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return signature, nil
}

// SignBridgeMessage coordinates complete signing of a bridge message
// This is used by the coordinator node to orchestrate the signing
func (s *BridgeSigner) SignBridgeMessage(ctx context.Context, message *BridgeMessage, activeSigners []int) error {
	// Request signature from active signers
	sessionID, err := s.RequestSignature(ctx, message, activeSigners)
	if err != nil {
		return err
	}

	s.log.Info("waiting for signature shares",
		log.String("sessionID", sessionID),
	)

	// Wait for signature to be aggregated
	signature, err := s.GetSignature(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get signature: %w", err)
	}

	// Attach signature to message
	message.Signature = signature
	message.SignedBy = activeSigners

	s.log.Info("bridge message signed",
		log.String("messageID", message.ID.String()),
		log.String("signature", hex.EncodeToString(signature[:16])),
	)

	return nil
}

// VerifyBridgeMessage verifies a bridge message signature
func (s *BridgeSigner) VerifyBridgeMessage(message *BridgeMessage) error {
	groupKey := s.mpcKeyManager.GetGroupPublicKey()
	if len(groupKey) == 0 {
		return errors.New("group key not available")
	}

	verifier := func(msg, sig []byte) bool {
		return s.mpcKeyManager.VerifySignature(msg, sig)
	}

	return message.Verify(groupKey, verifier)
}

// DeliveryConfirmationSigner handles signing of delivery confirmations
type DeliveryConfirmationSigner struct {
	mpcKeyManager  *MPCKeyManager
	mpcCoordinator *MPCCoordinator
	log            log.Logger
}

// NewDeliveryConfirmationSigner creates a new delivery confirmation signer
func NewDeliveryConfirmationSigner(keyManager *MPCKeyManager, coordinator *MPCCoordinator, logger log.Logger) *DeliveryConfirmationSigner {
	return &DeliveryConfirmationSigner{
		mpcKeyManager:  keyManager,
		mpcCoordinator: coordinator,
		log:            logger,
	}
}

// SigningMessage returns the canonical bytes to sign for a delivery confirmation
func (dc *DeliveryConfirmation) SigningMessage(messageID ids.ID) []byte {
	h := sha256.New()

	h.Write(messageID[:])
	h.Write(dc.DestTxID[:])
	h.Write([]byte(fmt.Sprintf("%d", dc.DestBlockHeight)))
	h.Write([]byte(fmt.Sprintf("%d", dc.DestConfirms)))

	return h.Sum(nil)
}

// SignDeliveryConfirmation creates a threshold signature for delivery confirmation
func (s *DeliveryConfirmationSigner) SignDeliveryConfirmation(ctx context.Context, messageID ids.ID, confirmation *DeliveryConfirmation, activeSigners []int) error {
	signingMsg := confirmation.SigningMessage(messageID)

	// Generate unique session ID
	sessionID := fmt.Sprintf("delivery-%s-%s", messageID.String(), confirmation.DestTxID.String())

	s.log.Info("requesting delivery confirmation signature",
		log.String("sessionID", sessionID),
		log.String("messageID", messageID.String()),
		log.String("destTxID", confirmation.DestTxID.String()),
	)

	// Start signing session
	session, err := s.mpcCoordinator.StartSigning(ctx, sessionID, signingMsg, activeSigners, 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed to start signing: %w", err)
	}

	// Wait for signature
	signature, err := session.Wait(ctx)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	// Attach signature
	confirmation.ConfirmSignature = signature
	confirmation.ConfirmedAt = time.Now()

	s.log.Info("delivery confirmation signed",
		log.String("messageID", messageID.String()),
		log.String("destTxID", confirmation.DestTxID.String()),
	)

	return nil
}

// VerifyDeliveryConfirmation verifies a delivery confirmation signature
func (s *DeliveryConfirmationSigner) VerifyDeliveryConfirmation(messageID ids.ID, confirmation *DeliveryConfirmation) error {
	if len(confirmation.ConfirmSignature) == 0 {
		return ErrDeliveryNotConfirmed
	}

	signingMsg := confirmation.SigningMessage(messageID)

	if !s.mpcKeyManager.VerifySignature(signingMsg, confirmation.ConfirmSignature) {
		return ErrInvalidBridgeSignature
	}

	return nil
}

// BridgeMessageValidator validates bridge messages and their delivery confirmations
type BridgeMessageValidator struct {
	bridgeSigner           *BridgeSigner
	deliverySigner         *DeliveryConfirmationSigner
	minConfirmations       uint32
	requireDeliveryConfirm bool
	log                    log.Logger
}

// NewBridgeMessageValidator creates a new validator
func NewBridgeMessageValidator(
	bridgeSigner *BridgeSigner,
	deliverySigner *DeliveryConfirmationSigner,
	minConfirmations uint32,
	requireDeliveryConfirm bool,
	logger log.Logger,
) *BridgeMessageValidator {
	return &BridgeMessageValidator{
		bridgeSigner:           bridgeSigner,
		deliverySigner:         deliverySigner,
		minConfirmations:       minConfirmations,
		requireDeliveryConfirm: requireDeliveryConfirm,
		log:                    logger,
	}
}

// ValidateMessage performs full validation of a bridge message
func (v *BridgeMessageValidator) ValidateMessage(message *BridgeMessage) error {
	// Verify message has enough confirmations
	if message.Confirmations < v.minConfirmations {
		return fmt.Errorf("insufficient confirmations: %d < %d", message.Confirmations, v.minConfirmations)
	}

	// Verify bridge message signature
	if err := v.bridgeSigner.VerifyBridgeMessage(message); err != nil {
		return fmt.Errorf("invalid message signature: %w", err)
	}

	// Verify delivery confirmation if required
	if v.requireDeliveryConfirm {
		if message.DeliveryConfirmation == nil {
			return ErrDeliveryNotConfirmed
		}

		if err := v.deliverySigner.VerifyDeliveryConfirmation(message.ID, message.DeliveryConfirmation); err != nil {
			return fmt.Errorf("invalid delivery confirmation: %w", err)
		}

		// Check delivery confirmation has enough confirmations
		if message.DeliveryConfirmation.DestConfirms < v.minConfirmations {
			return fmt.Errorf("insufficient delivery confirmations: %d < %d",
				message.DeliveryConfirmation.DestConfirms, v.minConfirmations)
		}
	}

	v.log.Info("bridge message validated",
		log.String("messageID", message.ID.String()),
		log.String("sourceChain", message.SourceChain),
		log.String("destChain", message.DestChain),
		log.Bool("hasDeliveryConfirm", message.DeliveryConfirmation != nil),
	)

	return nil
}

// ValidateBeforeRelay validates a message before relaying to destination chain
func (v *BridgeMessageValidator) ValidateBeforeRelay(message *BridgeMessage) error {
	// Verify message has enough confirmations
	if message.Confirmations < v.minConfirmations {
		return fmt.Errorf("insufficient confirmations: %d < %d", message.Confirmations, v.minConfirmations)
	}

	// Verify bridge message signature
	if err := v.bridgeSigner.VerifyBridgeMessage(message); err != nil {
		return fmt.Errorf("invalid message signature: %w", err)
	}

	return nil
}

// ValidateAfterRelay validates delivery confirmation after message is relayed
func (v *BridgeMessageValidator) ValidateAfterRelay(message *BridgeMessage) error {
	if message.DeliveryConfirmation == nil {
		return ErrDeliveryNotConfirmed
	}

	if err := v.deliverySigner.VerifyDeliveryConfirmation(message.ID, message.DeliveryConfirmation); err != nil {
		return fmt.Errorf("invalid delivery confirmation: %w", err)
	}

	return nil
}
