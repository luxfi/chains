// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/platformvm/warp"
)

const (
	// Function selectors (first 4 bytes of keccak256 hash)
	SelectorRequestDecryption         = 0x5a6d3af9 // requestDecryption(bytes32,uint8)
	SelectorRequestDecryptionCallback = 0x7b8c4d12 // requestDecryptionWithCallback(bytes32,uint8,address,bytes4)
)

var (
	ErrInvalidSelector = errors.New("invalid function selector")
	ErrInvalidPayload  = errors.New("invalid payload format")
)

// WarpHandler processes FHE-related Warp messages from C-Chain
type WarpHandler struct {
	logger  log.Logger
	relayer *Relayer
}

// NewWarpHandler creates a new Warp message handler for FHE decryption
func NewWarpHandler(logger log.Logger, relayer *Relayer) *WarpHandler {
	return &WarpHandler{
		logger:  logger,
		relayer: relayer,
	}
}

// HandleMessage processes an incoming Warp message for FHE decryption
func (h *WarpHandler) HandleMessage(ctx context.Context, msg *warp.Message) error {
	if msg == nil {
		return errors.New("nil message")
	}

	payload := msg.Payload
	if len(payload) < 4 {
		return ErrInvalidPayload
	}

	// Extract function selector
	selector := binary.BigEndian.Uint32(payload[:4])

	switch selector {
	case SelectorRequestDecryption:
		return h.handleDecryptionRequest(ctx, msg, payload[4:])
	case SelectorRequestDecryptionCallback:
		return h.handleDecryptionWithCallback(ctx, msg, payload[4:])
	default:
		h.logger.Debug("Unknown FHE selector",
			"selector", fmt.Sprintf("0x%08x", selector),
		)
		return ErrInvalidSelector
	}
}

// handleDecryptionRequest handles a simple decryption request
func (h *WarpHandler) handleDecryptionRequest(ctx context.Context, msg *warp.Message, data []byte) error {
	// Parse: ciphertextHash (32 bytes) + decryptionType (1 byte)
	if len(data) < 33 {
		return ErrInvalidPayload
	}

	ciphertextHash := common.BytesToHash(data[:32])
	decryptionType := data[32]

	h.logger.Info("Received decryption request",
		"ciphertextHash", ciphertextHash.Hex(),
		"type", decryptionType,
		"sourceChain", msg.SourceChainID,
	)

	// Create decryption request
	req := &DecryptionRequest{
		RequestID:      ciphertextHash,
		CiphertextHash: ciphertextHash,
		DecryptionType: decryptionType,
		SourceChainID:  msg.SourceChainID,
	}

	return h.relayer.SubmitRequest(ctx, req)
}

// handleDecryptionWithCallback handles a decryption request with callback
func (h *WarpHandler) handleDecryptionWithCallback(ctx context.Context, msg *warp.Message, data []byte) error {
	// Parse: ciphertextHash (32 bytes) + decryptionType (1 byte) + callbackAddress (20 bytes) + callbackSelector (4 bytes)
	if len(data) < 57 {
		return ErrInvalidPayload
	}

	ciphertextHash := common.BytesToHash(data[:32])
	decryptionType := data[32]
	callbackAddress := common.BytesToAddress(data[33:53])
	callbackSelector := binary.BigEndian.Uint32(data[53:57])

	h.logger.Info("Received decryption request with callback",
		"ciphertextHash", ciphertextHash.Hex(),
		"type", decryptionType,
		"callback", callbackAddress.Hex(),
		"selector", fmt.Sprintf("0x%08x", callbackSelector),
		"sourceChain", msg.SourceChainID,
	)

	req := &DecryptionRequest{
		RequestID:        ciphertextHash,
		CiphertextHash:   ciphertextHash,
		DecryptionType:   decryptionType,
		SourceChainID:    msg.SourceChainID,
		CallbackAddress:  callbackAddress,
		CallbackSelector: callbackSelector,
		HasCallback:      true,
	}

	return h.relayer.SubmitRequest(ctx, req)
}

// FHEDecryptionService manages FHE decryption operations
type FHEDecryptionService struct {
	logger log.Logger

	// Active handlers
	handlers   map[ids.ID]*WarpHandler
	handlersMu sync.RWMutex

	// Service state
	running bool
	cancel  context.CancelFunc
}

// NewFHEDecryptionService creates a new FHE decryption service
func NewFHEDecryptionService(logger log.Logger) *FHEDecryptionService {
	return &FHEDecryptionService{
		logger:   logger,
		handlers: make(map[ids.ID]*WarpHandler),
	}
}

// Start begins the FHE decryption service
func (s *FHEDecryptionService) Start(ctx context.Context) error {
	if s.running {
		return errors.New("service already running")
	}

	_, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.running = true

	s.logger.Info("FHE Decryption Service started")
	return nil
}

// Stop shuts down the FHE decryption service
func (s *FHEDecryptionService) Stop() error {
	if !s.running {
		return nil
	}

	if s.cancel != nil {
		s.cancel()
	}

	s.running = false
	s.logger.Info("FHE Decryption Service stopped")
	return nil
}

// RegisterHandler registers a Warp handler for a specific chain
func (s *FHEDecryptionService) RegisterHandler(chainID ids.ID, handler *WarpHandler) {
	s.handlersMu.Lock()
	defer s.handlersMu.Unlock()
	s.handlers[chainID] = handler
}

// GetHandler returns the handler for a specific chain
func (s *FHEDecryptionService) GetHandler(chainID ids.ID) (*WarpHandler, bool) {
	s.handlersMu.RLock()
	defer s.handlersMu.RUnlock()
	handler, ok := s.handlers[chainID]
	return handler, ok
}
