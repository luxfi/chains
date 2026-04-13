// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package network provides peer-to-peer networking and Warp messaging for the DEX VM.
package network

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

var (
	ErrInvalidMessage     = errors.New("invalid message")
	ErrUnknownMessageType = errors.New("unknown message type")
	ErrPeerNotConnected   = errors.New("peer not connected")
	ErrRequestTimeout     = errors.New("request timed out")
)

// MessageType represents the type of network message.
type MessageType uint8

const (
	MsgOrderGossip MessageType = iota
	MsgTradeGossip
	MsgOrderbookSync
	MsgPoolSync
	MsgCrossChainSwap
	MsgCrossChainTransfer
	MsgWarpMessage
)

func (t MessageType) String() string {
	switch t {
	case MsgOrderGossip:
		return "order_gossip"
	case MsgTradeGossip:
		return "trade_gossip"
	case MsgOrderbookSync:
		return "orderbook_sync"
	case MsgPoolSync:
		return "pool_sync"
	case MsgCrossChainSwap:
		return "cross_chain_swap"
	case MsgCrossChainTransfer:
		return "cross_chain_transfer"
	case MsgWarpMessage:
		return "warp_message"
	default:
		return "unknown"
	}
}

// Message represents a network message.
type Message struct {
	Type      MessageType
	RequestID uint32
	Payload   []byte
	ChainID   ids.ID // For cross-chain messages
	Sender    ids.NodeID
	Timestamp int64
}

// Encode encodes the message to bytes.
func (m *Message) Encode() []byte {
	// Format: type (1) + requestID (4) + chainID (32) + sender (20) + timestamp (8) + payloadLen (4) + payload
	size := 1 + 4 + 32 + 20 + 8 + 4 + len(m.Payload)
	data := make([]byte, size)

	offset := 0
	data[offset] = byte(m.Type)
	offset++

	binary.BigEndian.PutUint32(data[offset:], m.RequestID)
	offset += 4

	copy(data[offset:], m.ChainID[:])
	offset += 32

	copy(data[offset:], m.Sender[:])
	offset += 20

	binary.BigEndian.PutUint64(data[offset:], uint64(m.Timestamp))
	offset += 8

	binary.BigEndian.PutUint32(data[offset:], uint32(len(m.Payload)))
	offset += 4

	copy(data[offset:], m.Payload)

	return data
}

// DecodeMessage decodes a message from bytes.
func DecodeMessage(data []byte) (*Message, error) {
	if len(data) < 69 { // Minimum size
		return nil, ErrInvalidMessage
	}

	m := &Message{}
	offset := 0

	m.Type = MessageType(data[offset])
	offset++

	m.RequestID = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	copy(m.ChainID[:], data[offset:offset+32])
	offset += 32

	copy(m.Sender[:], data[offset:offset+20])
	offset += 20

	m.Timestamp = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	payloadLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if offset+int(payloadLen) > len(data) {
		return nil, ErrInvalidMessage
	}

	m.Payload = make([]byte, payloadLen)
	copy(m.Payload, data[offset:offset+int(payloadLen)])

	return m, nil
}

// Handler handles network messages for the DEX VM.
type Handler struct {
	mu      sync.RWMutex
	log     log.Logger
	chainID ids.ID

	// Pending requests
	pendingRequests map[uint32]chan *Message
	nextRequestID   uint32

	// Message handlers
	orderHandler func(*Message) error
	tradeHandler func(*Message) error
	syncHandler  func(*Message) error
	warpHandler  func(*Message) error

	// Statistics (atomic for thread-safe access)
	messagesSent     atomic.Uint64
	messagesReceived atomic.Uint64
	bytesIn          atomic.Uint64
	bytesOut         atomic.Uint64
}

// NewHandler creates a new network handler.
func NewHandler(log log.Logger, chainID ids.ID) *Handler {
	return &Handler{
		log:             log,
		chainID:         chainID,
		pendingRequests: make(map[uint32]chan *Message),
	}
}

// SetOrderHandler sets the handler for order gossip messages.
func (h *Handler) SetOrderHandler(handler func(*Message) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.orderHandler = handler
}

// SetTradeHandler sets the handler for trade gossip messages.
func (h *Handler) SetTradeHandler(handler func(*Message) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tradeHandler = handler
}

// SetSyncHandler sets the handler for sync messages.
func (h *Handler) SetSyncHandler(handler func(*Message) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.syncHandler = handler
}

// SetWarpHandler sets the handler for Warp messages.
func (h *Handler) SetWarpHandler(handler func(*Message) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.warpHandler = handler
}

// HandleGossip handles an incoming gossip message.
func (h *Handler) HandleGossip(ctx context.Context, nodeID ids.NodeID, msgBytes []byte) error {
	msg, err := DecodeMessage(msgBytes)
	if err != nil {
		h.log.Warn("Failed to decode gossip message", "error", err)
		return err
	}

	msg.Sender = nodeID

	// Use atomic counters - no lock needed for statistics
	h.messagesReceived.Add(1)
	h.bytesIn.Add(uint64(len(msgBytes)))

	// Copy handler reference under lock to avoid race with SetXxxHandler
	h.mu.RLock()
	orderHandler := h.orderHandler
	tradeHandler := h.tradeHandler
	h.mu.RUnlock()

	switch msg.Type {
	case MsgOrderGossip:
		if orderHandler != nil {
			return orderHandler(msg)
		}
	case MsgTradeGossip:
		if tradeHandler != nil {
			return tradeHandler(msg)
		}
	default:
		return ErrUnknownMessageType
	}

	return nil
}

// HandleRequest handles an incoming request message.
func (h *Handler) HandleRequest(
	ctx context.Context,
	nodeID ids.NodeID,
	requestID uint32,
	deadline time.Time,
	msgBytes []byte,
) ([]byte, error) {
	msg, err := DecodeMessage(msgBytes)
	if err != nil {
		return nil, err
	}

	msg.Sender = nodeID
	msg.RequestID = requestID

	// Use atomic counters - no lock needed for statistics
	h.messagesReceived.Add(1)
	h.bytesIn.Add(uint64(len(msgBytes)))

	// Copy handler reference under lock to avoid race with SetXxxHandler
	h.mu.RLock()
	syncHandler := h.syncHandler
	h.mu.RUnlock()

	var response *Message

	switch msg.Type {
	case MsgOrderbookSync:
		if syncHandler != nil {
			if err := syncHandler(msg); err != nil {
				return nil, err
			}
		}
		response = &Message{
			Type:      MsgOrderbookSync,
			RequestID: requestID,
			ChainID:   h.chainID,
			Timestamp: time.Now().UnixNano(),
		}
	case MsgPoolSync:
		if syncHandler != nil {
			if err := syncHandler(msg); err != nil {
				return nil, err
			}
		}
		response = &Message{
			Type:      MsgPoolSync,
			RequestID: requestID,
			ChainID:   h.chainID,
			Timestamp: time.Now().UnixNano(),
		}
	default:
		return nil, ErrUnknownMessageType
	}

	return response.Encode(), nil
}

// HandleResponse handles a response to a previously sent request.
func (h *Handler) HandleResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, responseBytes []byte) error {
	h.mu.Lock()
	respChan, exists := h.pendingRequests[requestID]
	if !exists {
		h.mu.Unlock()
		return nil // Request may have timed out
	}
	delete(h.pendingRequests, requestID)
	h.mu.Unlock()

	msg, err := DecodeMessage(responseBytes)
	if err != nil {
		return err
	}

	msg.Sender = nodeID
	msg.RequestID = requestID

	select {
	case respChan <- msg:
	default:
		// Channel full or closed
	}

	return nil
}

// HandleCrossChainRequest handles a cross-chain request via Warp.
func (h *Handler) HandleCrossChainRequest(
	ctx context.Context,
	sourceChainID ids.ID,
	requestID uint32,
	deadline time.Time,
	msgBytes []byte,
) ([]byte, error) {
	msg, err := DecodeMessage(msgBytes)
	if err != nil {
		return nil, err
	}

	msg.ChainID = sourceChainID
	msg.RequestID = requestID

	h.log.Debug("Received cross-chain request",
		"sourceChain", sourceChainID,
		"type", msg.Type,
		"requestID", requestID,
	)

	// Copy handler reference under lock to avoid race with SetXxxHandler
	h.mu.RLock()
	warpHandler := h.warpHandler
	h.mu.RUnlock()

	switch msg.Type {
	case MsgCrossChainSwap:
		if warpHandler != nil {
			if err := warpHandler(msg); err != nil {
				return nil, err
			}
		}
	case MsgCrossChainTransfer:
		if warpHandler != nil {
			if err := warpHandler(msg); err != nil {
				return nil, err
			}
		}
	case MsgWarpMessage:
		if warpHandler != nil {
			if err := warpHandler(msg); err != nil {
				return nil, err
			}
		}
	default:
		return nil, ErrUnknownMessageType
	}

	// Create response
	response := &Message{
		Type:      msg.Type,
		RequestID: requestID,
		ChainID:   h.chainID,
		Timestamp: time.Now().UnixNano(),
		Payload:   []byte("ok"),
	}

	return response.Encode(), nil
}

// HandleCrossChainResponse handles a cross-chain response.
func (h *Handler) HandleCrossChainResponse(
	ctx context.Context,
	sourceChainID ids.ID,
	requestID uint32,
	responseBytes []byte,
) error {
	h.mu.Lock()
	respChan, exists := h.pendingRequests[requestID]
	if !exists {
		h.mu.Unlock()
		return nil
	}
	delete(h.pendingRequests, requestID)
	h.mu.Unlock()

	msg, err := DecodeMessage(responseBytes)
	if err != nil {
		return err
	}

	msg.ChainID = sourceChainID
	msg.RequestID = requestID

	select {
	case respChan <- msg:
	default:
	}

	return nil
}

// SendRequest sends a request and waits for a response.
func (h *Handler) SendRequest(
	ctx context.Context,
	nodeID ids.NodeID,
	msg *Message,
	timeout time.Duration,
	sendFunc func(ids.NodeID, uint32, []byte) error,
) (*Message, error) {
	h.mu.Lock()
	requestID := h.nextRequestID
	h.nextRequestID++

	respChan := make(chan *Message, 1)
	h.pendingRequests[requestID] = respChan
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.pendingRequests, requestID)
		h.mu.Unlock()
	}()

	msg.RequestID = requestID
	msg.ChainID = h.chainID
	msg.Timestamp = time.Now().UnixNano()

	msgBytes := msg.Encode()

	// Use atomic counters - no lock needed for statistics
	h.messagesSent.Add(1)
	h.bytesOut.Add(uint64(len(msgBytes)))

	if err := sendFunc(nodeID, requestID, msgBytes); err != nil {
		return nil, err
	}

	// Wait for response
	select {
	case response := <-respChan:
		return response, nil
	case <-time.After(timeout):
		return nil, ErrRequestTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Gossip sends a gossip message to all peers.
func (h *Handler) Gossip(msg *Message, gossipFunc func([]byte) error) error {
	msg.ChainID = h.chainID
	msg.Timestamp = time.Now().UnixNano()

	msgBytes := msg.Encode()

	// Use atomic counters - no lock needed for statistics
	h.messagesSent.Add(1)
	h.bytesOut.Add(uint64(len(msgBytes)))

	return gossipFunc(msgBytes)
}

// Stats returns network statistics.
func (h *Handler) Stats() (sent, received, bytesIn, bytesOut uint64) {
	// Use atomic Load - no lock needed for statistics
	return h.messagesSent.Load(), h.messagesReceived.Load(), h.bytesIn.Load(), h.bytesOut.Load()
}

// WarpManager manages cross-chain Warp messaging.
type WarpManager struct {
	mu              sync.RWMutex
	log             log.Logger
	chainID         ids.ID
	trustedChains   map[ids.ID]bool
	pendingMessages map[ids.ID]*WarpMessage
}

// WarpMessage represents a cross-chain Warp message.
type WarpMessage struct {
	ID            ids.ID
	SourceChain   ids.ID
	DestChain     ids.ID
	Payload       []byte
	Signature     []byte
	Validators    []ids.NodeID
	ValidatorSigs [][]byte
	Timestamp     int64
	Deadline      int64
}

// NewWarpManager creates a new Warp manager.
func NewWarpManager(log log.Logger, chainID ids.ID, trustedChains []ids.ID) *WarpManager {
	trusted := make(map[ids.ID]bool)
	for _, chain := range trustedChains {
		trusted[chain] = true
	}

	return &WarpManager{
		log:             log,
		chainID:         chainID,
		trustedChains:   trusted,
		pendingMessages: make(map[ids.ID]*WarpMessage),
	}
}

// IsTrustedChain returns true if the chain is trusted for cross-chain messaging.
func (w *WarpManager) IsTrustedChain(chainID ids.ID) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.trustedChains[chainID]
}

// AddTrustedChain adds a chain to the trusted list.
func (w *WarpManager) AddTrustedChain(chainID ids.ID) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.trustedChains[chainID] = true
}

// RemoveTrustedChain removes a chain from the trusted list.
func (w *WarpManager) RemoveTrustedChain(chainID ids.ID) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.trustedChains, chainID)
}

// ProcessIncomingMessage processes an incoming Warp message.
func (w *WarpManager) ProcessIncomingMessage(msg *WarpMessage) error {
	// Verify source chain is trusted
	if !w.IsTrustedChain(msg.SourceChain) {
		return errors.New("source chain not trusted")
	}

	// Verify message is for this chain
	if msg.DestChain != w.chainID {
		return errors.New("message not for this chain")
	}

	// Verify deadline
	if msg.Deadline > 0 && time.Now().UnixNano() > msg.Deadline {
		return errors.New("message expired")
	}

	// Store pending message
	w.mu.Lock()
	w.pendingMessages[msg.ID] = msg
	w.mu.Unlock()

	w.log.Debug("Received Warp message",
		"id", msg.ID,
		"source", msg.SourceChain,
	)

	return nil
}

// CreateOutgoingMessage creates a Warp message to send to another chain.
func (w *WarpManager) CreateOutgoingMessage(
	destChain ids.ID,
	payload []byte,
	deadline time.Duration,
) *WarpMessage {
	return &WarpMessage{
		ID:          ids.GenerateTestID(),
		SourceChain: w.chainID,
		DestChain:   destChain,
		Payload:     payload,
		Timestamp:   time.Now().UnixNano(),
		Deadline:    time.Now().Add(deadline).UnixNano(),
	}
}

// GetPendingMessage returns a pending Warp message.
func (w *WarpManager) GetPendingMessage(id ids.ID) (*WarpMessage, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	msg, exists := w.pendingMessages[id]
	return msg, exists
}

// RemovePendingMessage removes a pending Warp message.
func (w *WarpManager) RemovePendingMessage(id ids.ID) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.pendingMessages, id)
}
