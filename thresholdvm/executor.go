// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thresholdvm

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"

	"github.com/luxfi/threshold/protocols/cmp"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
	"github.com/luxfi/threshold/protocols/frost"
	frostconfig "github.com/luxfi/threshold/protocols/frost/keygen"
	"github.com/luxfi/threshold/protocols/lss"
	lssconfig "github.com/luxfi/threshold/protocols/lss/config"
)

// ProtocolExecutor manages MPC protocol execution using the threshold library.
// It provides the bridge between ThresholdVM session management and the
// actual MPC protocol implementations.
type ProtocolExecutor struct {
	pool   *pool.Pool
	logger log.Logger

	// Active handlers for message routing
	mu       sync.RWMutex
	handlers map[string]*protocol.Handler
}

// NewProtocolExecutor creates a new protocol executor.
func NewProtocolExecutor(workerPool *pool.Pool, logger log.Logger) *ProtocolExecutor {
	return &ProtocolExecutor{
		pool:     workerPool,
		logger:   logger,
		handlers: make(map[string]*protocol.Handler),
	}
}

// =============================================================================
// StartFunc Generators - Create protocol start functions
// =============================================================================

// LSSKeygenStartFunc returns a StartFunc for LSS key generation.
func (pe *ProtocolExecutor) LSSKeygenStartFunc(
	selfID party.ID,
	participants []party.ID,
	threshold int,
) protocol.StartFunc {
	return lss.Keygen(curve.Secp256k1{}, selfID, participants, threshold, pe.pool)
}

// LSSSignStartFunc returns a StartFunc for LSS signing.
func (pe *ProtocolExecutor) LSSSignStartFunc(
	config *lssconfig.Config,
	signers []party.ID,
	messageHash []byte,
) protocol.StartFunc {
	return lss.Sign(config, signers, messageHash, pe.pool)
}

// LSSReshareStartFunc returns a StartFunc for LSS resharing.
func (pe *ProtocolExecutor) LSSReshareStartFunc(
	config *lssconfig.Config,
	newParticipants []party.ID,
	newThreshold int,
) protocol.StartFunc {
	return lss.Reshare(config, newParticipants, newThreshold, pe.pool)
}

// LSSRefreshStartFunc returns a StartFunc for LSS key refresh.
func (pe *ProtocolExecutor) LSSRefreshStartFunc(config *lssconfig.Config) protocol.StartFunc {
	return lss.Refresh(config, pe.pool)
}

// CMPKeygenStartFunc returns a StartFunc for CMP key generation.
func (pe *ProtocolExecutor) CMPKeygenStartFunc(
	selfID party.ID,
	participants []party.ID,
	threshold int,
) protocol.StartFunc {
	return cmp.Keygen(curve.Secp256k1{}, selfID, participants, threshold, pe.pool)
}

// CMPSignStartFunc returns a StartFunc for CMP signing.
func (pe *ProtocolExecutor) CMPSignStartFunc(
	config *cmpconfig.Config,
	signers []party.ID,
	messageHash []byte,
) protocol.StartFunc {
	return cmp.Sign(config, signers, messageHash, pe.pool)
}

// CMPRefreshStartFunc returns a StartFunc for CMP key refresh.
func (pe *ProtocolExecutor) CMPRefreshStartFunc(config *cmpconfig.Config) protocol.StartFunc {
	return cmp.Refresh(config, pe.pool)
}

// FROSTKeygenStartFunc returns a StartFunc for FROST key generation.
func (pe *ProtocolExecutor) FROSTKeygenStartFunc(
	selfID party.ID,
	participants []party.ID,
	threshold int,
) protocol.StartFunc {
	return frost.Keygen(curve.Secp256k1{}, selfID, participants, threshold)
}

// FROSTKeygenTaprootStartFunc returns a StartFunc for FROST Taproot key generation.
func (pe *ProtocolExecutor) FROSTKeygenTaprootStartFunc(
	selfID party.ID,
	participants []party.ID,
	threshold int,
) protocol.StartFunc {
	return frost.KeygenTaproot(selfID, participants, threshold)
}

// FROSTSignStartFunc returns a StartFunc for FROST signing.
func (pe *ProtocolExecutor) FROSTSignStartFunc(
	config *frostconfig.Config,
	signers []party.ID,
	messageHash []byte,
) protocol.StartFunc {
	return frost.Sign(config, signers, messageHash)
}

// FROSTRefreshStartFunc returns a StartFunc for FROST key refresh.
func (pe *ProtocolExecutor) FROSTRefreshStartFunc(
	config *frostconfig.Config,
	participants []party.ID,
) protocol.StartFunc {
	return frost.Refresh(config, participants)
}

// =============================================================================
// Handler Management
// =============================================================================

// CreateHandler creates a new protocol handler for a session.
func (pe *ProtocolExecutor) CreateHandler(
	ctx context.Context,
	sessionID string,
	startFunc protocol.StartFunc,
) (*protocol.Handler, error) {
	handler, err := protocol.NewHandler(
		ctx,
		pe.logger,
		nil, // No metrics registry for now
		startFunc,
		[]byte(sessionID),
		protocol.DefaultConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create handler: %w", err)
	}

	pe.mu.Lock()
	pe.handlers[sessionID] = handler
	pe.mu.Unlock()

	return handler, nil
}

// GetHandler retrieves an active handler by session ID.
func (pe *ProtocolExecutor) GetHandler(sessionID string) (*protocol.Handler, bool) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	handler, ok := pe.handlers[sessionID]
	return handler, ok
}

// RemoveHandler removes a handler from active tracking.
func (pe *ProtocolExecutor) RemoveHandler(sessionID string) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if handler, ok := pe.handlers[sessionID]; ok {
		handler.Stop()
		delete(pe.handlers, sessionID)
	}
}

// AcceptMessage routes an incoming message to the appropriate handler.
func (pe *ProtocolExecutor) AcceptMessage(sessionID string, msg *protocol.Message) error {
	pe.mu.RLock()
	handler, ok := pe.handlers[sessionID]
	pe.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no active handler for session: %s", sessionID)
	}

	handler.Accept(msg)
	return nil
}

// =============================================================================
// High-Level Protocol Operations
// =============================================================================

// RunLSSKeygen executes a complete LSS key generation protocol.
// This is a convenience method that creates a handler and waits for completion.
// For multi-party scenarios, use CreateHandler and manage message routing manually.
func (pe *ProtocolExecutor) RunLSSKeygen(
	ctx context.Context,
	sessionID string,
	selfID party.ID,
	participants []party.ID,
	threshold int,
	messageRouter MessageRouter,
) (*lssconfig.Config, error) {
	startFunc := pe.LSSKeygenStartFunc(selfID, participants, threshold)
	return runProtocol[*lssconfig.Config](ctx, pe, sessionID, startFunc, messageRouter)
}

// RunLSSSign executes a complete LSS signing protocol.
func (pe *ProtocolExecutor) RunLSSSign(
	ctx context.Context,
	sessionID string,
	config *lssconfig.Config,
	signers []party.ID,
	messageHash []byte,
	messageRouter MessageRouter,
) (*ECDSASignature, error) {
	startFunc := pe.LSSSignStartFunc(config, signers, messageHash)
	return runProtocol[*ECDSASignature](ctx, pe, sessionID, startFunc, messageRouter)
}

// RunCMPKeygen executes a complete CMP key generation protocol.
func (pe *ProtocolExecutor) RunCMPKeygen(
	ctx context.Context,
	sessionID string,
	selfID party.ID,
	participants []party.ID,
	threshold int,
	messageRouter MessageRouter,
) (*cmpconfig.Config, error) {
	startFunc := pe.CMPKeygenStartFunc(selfID, participants, threshold)
	return runProtocol[*cmpconfig.Config](ctx, pe, sessionID, startFunc, messageRouter)
}

// RunCMPSign executes a complete CMP signing protocol.
func (pe *ProtocolExecutor) RunCMPSign(
	ctx context.Context,
	sessionID string,
	config *cmpconfig.Config,
	signers []party.ID,
	messageHash []byte,
	messageRouter MessageRouter,
) (*ECDSASignature, error) {
	startFunc := pe.CMPSignStartFunc(config, signers, messageHash)
	return runProtocol[*ECDSASignature](ctx, pe, sessionID, startFunc, messageRouter)
}

// RunCMPRefresh executes a complete CMP key refresh protocol.
func (pe *ProtocolExecutor) RunCMPRefresh(
	ctx context.Context,
	sessionID string,
	config *cmpconfig.Config,
	messageRouter MessageRouter,
) (*cmpconfig.Config, error) {
	startFunc := pe.CMPRefreshStartFunc(config)
	return runProtocol[*cmpconfig.Config](ctx, pe, sessionID, startFunc, messageRouter)
}

// RunFROSTKeygen executes a complete FROST key generation protocol.
func (pe *ProtocolExecutor) RunFROSTKeygen(
	ctx context.Context,
	sessionID string,
	selfID party.ID,
	participants []party.ID,
	threshold int,
	messageRouter MessageRouter,
) (*frostconfig.Config, error) {
	startFunc := pe.FROSTKeygenStartFunc(selfID, participants, threshold)
	return runProtocol[*frostconfig.Config](ctx, pe, sessionID, startFunc, messageRouter)
}

// MessageRouter defines the interface for routing MPC messages between parties.
type MessageRouter interface {
	// Send sends a message to the specified party (or broadcasts if To is empty)
	Send(msg *protocol.Message) error
	// Receive returns a channel for receiving incoming messages
	Receive() <-chan *protocol.Message
}

// runProtocol is a generic helper that runs a protocol to completion.
func runProtocol[T any](
	ctx context.Context,
	pe *ProtocolExecutor,
	sessionID string,
	startFunc protocol.StartFunc,
	router MessageRouter,
) (T, error) {
	var zero T

	handler, err := pe.CreateHandler(ctx, sessionID, startFunc)
	if err != nil {
		return zero, err
	}
	defer pe.RemoveHandler(sessionID)

	// Start message routing goroutines
	done := make(chan struct{})
	var routerErr error

	// Outgoing messages
	go func() {
		defer close(done)
		for msg := range handler.Listen() {
			if err := router.Send(msg); err != nil {
				routerErr = err
				return
			}
		}
	}()

	// Incoming messages
	go func() {
		for msg := range router.Receive() {
			handler.Accept(msg)
		}
	}()

	// Wait for protocol completion
	result, err := handler.WaitForResult()
	if err != nil {
		return zero, fmt.Errorf("protocol failed: %w", err)
	}

	// Wait for message routing to complete
	<-done
	if routerErr != nil {
		return zero, fmt.Errorf("message routing failed: %w", routerErr)
	}

	// Type assert the result
	typedResult, ok := result.(T)
	if !ok {
		return zero, fmt.Errorf("unexpected result type: %T", result)
	}

	return typedResult, nil
}

// =============================================================================
// Signature Types
// =============================================================================

// ECDSASignature wraps ECDSA signature from threshold library.
type ECDSASignature struct {
	R []byte
	S []byte
	V byte
}

// SchnorrSignature wraps Schnorr signature from FROST.
type SchnorrSignature struct {
	R []byte
	Z []byte
}

// =============================================================================
// Key Share Wrappers - Implement KeyShare interface for each protocol
// =============================================================================

// LSSKeyShare wraps lssconfig.Config to implement KeyShare.
type LSSKeyShare struct {
	Config *lssconfig.Config
}

// PublicKey returns the group public key.
func (s *LSSKeyShare) PublicKey() []byte {
	point, err := s.Config.PublicPoint()
	if err != nil {
		return nil
	}
	bytes, _ := point.MarshalBinary()
	return bytes
}

// PartyID returns this party's ID.
func (s *LSSKeyShare) PartyID() party.ID {
	return s.Config.ID
}

// Threshold returns the threshold t.
func (s *LSSKeyShare) Threshold() int {
	return s.Config.Threshold
}

// TotalParties returns total parties n.
func (s *LSSKeyShare) TotalParties() int {
	return len(s.Config.Public)
}

// Generation returns the key generation number.
func (s *LSSKeyShare) Generation() uint64 {
	return s.Config.Generation
}

// Protocol returns which protocol this share is for.
func (s *LSSKeyShare) Protocol() Protocol {
	return ProtocolLSS
}

// Serialize converts the share to bytes for storage.
func (s *LSSKeyShare) Serialize() ([]byte, error) {
	return s.Config.MarshalJSON()
}

// CMPKeyShare wraps cmpconfig.Config to implement KeyShare.
type CMPKeyShare struct {
	Config *cmpconfig.Config
}

// PublicKey returns the group public key.
func (s *CMPKeyShare) PublicKey() []byte {
	point := s.Config.PublicPoint()
	bytes, _ := point.MarshalBinary()
	return bytes
}

// PartyID returns this party's ID.
func (s *CMPKeyShare) PartyID() party.ID {
	return s.Config.ID
}

// Threshold returns the threshold t.
func (s *CMPKeyShare) Threshold() int {
	return s.Config.Threshold
}

// TotalParties returns total parties n.
func (s *CMPKeyShare) TotalParties() int {
	return len(s.Config.Public)
}

// Generation returns the key generation number.
func (s *CMPKeyShare) Generation() uint64 {
	return 0 // CMP doesn't have generation tracking
}

// Protocol returns which protocol this share is for.
func (s *CMPKeyShare) Protocol() Protocol {
	return ProtocolCGGMP21
}

// Serialize converts the share to bytes for storage.
func (s *CMPKeyShare) Serialize() ([]byte, error) {
	return s.Config.MarshalBinary()
}

// FROSTKeyShare wraps frostconfig.Config to implement KeyShare.
type FROSTKeyShare struct {
	Config *frostconfig.Config
}

// PublicKey returns the group public key.
func (s *FROSTKeyShare) PublicKey() []byte {
	bytes, _ := s.Config.PublicKey.MarshalBinary()
	return bytes
}

// PartyID returns this party's ID.
func (s *FROSTKeyShare) PartyID() party.ID {
	return s.Config.ID
}

// Threshold returns the threshold t.
func (s *FROSTKeyShare) Threshold() int {
	return s.Config.Threshold
}

// TotalParties returns total parties n.
func (s *FROSTKeyShare) TotalParties() int {
	// VerificationShares is *party.PointMap, access Points field
	if s.Config.VerificationShares == nil {
		return 0
	}
	return len(s.Config.VerificationShares.Points)
}

// Generation returns the key generation number.
func (s *FROSTKeyShare) Generation() uint64 {
	return 0 // FROST doesn't have generation tracking
}

// Protocol returns which protocol this share is for.
func (s *FROSTKeyShare) Protocol() Protocol {
	return ProtocolFrost
}

// Serialize converts the share to bytes for storage.
func (s *FROSTKeyShare) Serialize() ([]byte, error) {
	// FROST config doesn't have built-in marshal, use JSON
	return json.Marshal(s.Config)
}
