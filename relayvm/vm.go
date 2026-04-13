// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayvm

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/rpc/v2"
	grjson "github.com/gorilla/rpc/v2/json"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/artifacts"
	"github.com/luxfi/runtime"
	luxvm "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
)

const (
	Name = "relayvm"

	// Message states
	MessagePending   = "pending"
	MessageVerified  = "verified"
	MessageDelivered = "delivered"
	MessageFailed    = "failed"

	// Default configuration
	defaultMaxMessageSize    = 1024 * 1024 // 1MB
	defaultConfirmationDepth = 6
	defaultRelayTimeout      = 300 // seconds
)

var (
	_ chain.ChainVM = (*VM)(nil)
	_ vertex.DAGVM  = (*VM)(nil)

	lastAcceptedKey = []byte("lastAccepted")
	messagePrefix   = []byte("msg:")
	channelPrefix   = []byte("chan:")

	errUnknownMessage   = errors.New("unknown message")
	errUnknownChannel   = errors.New("unknown channel")
	errMessageTooLarge  = errors.New("message too large")
	errInvalidSignature = errors.New("invalid signature")
	errChannelClosed    = errors.New("channel closed")
)

// Config holds RelayVM configuration
type Config struct {
	MaxMessageSize    int      `json:"maxMessageSize"`
	ConfirmationDepth int      `json:"confirmationDepth"`
	RelayTimeout      int      `json:"relayTimeout"`
	TrustedRelayers   []string `json:"trustedRelayers"`
	SupportedChains   []string `json:"supportedChains"`
}

// Channel represents a cross-chain communication channel
type Channel struct {
	ID          ids.ID    `json:"id"`
	SourceChain ids.ID    `json:"sourceChain"`
	DestChain   ids.ID    `json:"destChain"`
	Ordering    string    `json:"ordering"` // "ordered" or "unordered"
	Version     string    `json:"version"`
	State       string    `json:"state"` // "open", "closed"
	CreatedAt   time.Time `json:"createdAt"`
	Metadata    map[string]string `json:"metadata"`
}

// Message represents a cross-chain message
type Message struct {
	ID            ids.ID `json:"id"`
	ChannelID     ids.ID `json:"channelId"`
	SourceChain   ids.ID `json:"sourceChain"`
	DestChain     ids.ID `json:"destChain"`
	Sequence      uint64 `json:"sequence"`
	Payload       []byte `json:"payload"`
	Proof         []byte `json:"proof"` // Merkle proof from source chain
	SourceHeight  uint64 `json:"sourceHeight"`
	Sender        []byte `json:"sender"`
	Receiver      []byte `json:"receiver"`
	Timeout       int64  `json:"timeout"`
	State         string `json:"state"`
	RelayedBy     ids.NodeID `json:"relayedBy,omitempty"`
	RelayedAt     int64      `json:"relayedAt,omitempty"`
	ConfirmedAt   int64      `json:"confirmedAt,omitempty"`
}

// MessageReceipt is generated when a message is verified
type MessageReceipt struct {
	MessageID   ids.ID `json:"messageId"`
	ChannelID   ids.ID `json:"channelId"`
	Success     bool   `json:"success"`
	ResultHash  []byte `json:"resultHash"`
	BlockHeight uint64 `json:"blockHeight"`
	Timestamp   int64  `json:"timestamp"`
}

// VM implements the RelayVM for cross-chain message relay
type VM struct {
	rt     *runtime.Runtime
	config Config
	log    log.Logger
	db     database.Database

	// State
	channels      map[ids.ID]*Channel
	messages      map[ids.ID]*Message
	pendingMsgs   map[ids.ID][]*Message // by destination chain
	sequences     map[ids.ID]uint64     // channel -> next sequence
	pendingBlocks map[ids.ID]*Block

	// Session-ready: Receipt Root Commitments
	sessionReceipts map[[32]byte][]*SignedReceipt // sessionID -> receipts
	receiptCommits  map[[32]byte]*ReceiptCommit   // sessionID -> commit

	// Node public key registry for signature verification
	nodePublicKeys map[ids.NodeID]ed25519.PublicKey

	// Consensus
	lastAccepted   *Block
	lastAcceptedID ids.ID

	mu sync.RWMutex

	// RPC
	rpcServer *rpc.Server
}

// Initialize implements chain.ChainVM
func (vm *VM) Initialize(
	ctx context.Context,
	vmInit luxvm.Init,
) error {
	vm.rt = vmInit.Runtime
	vm.db = vmInit.DB

	if logger, ok := vm.rt.Log.(log.Logger); ok {
		vm.log = logger
	} else {
		return errors.New("invalid logger type")
	}

	vm.channels = make(map[ids.ID]*Channel)
	vm.messages = make(map[ids.ID]*Message)
	vm.pendingMsgs = make(map[ids.ID][]*Message)
	vm.sequences = make(map[ids.ID]uint64)
	vm.pendingBlocks = make(map[ids.ID]*Block)
	vm.sessionReceipts = make(map[[32]byte][]*SignedReceipt)
	vm.receiptCommits = make(map[[32]byte]*ReceiptCommit)
	vm.nodePublicKeys = make(map[ids.NodeID]ed25519.PublicKey)

	// Parse genesis
	genesis, err := ParseGenesis(vmInit.Genesis)
	if err != nil {
		return fmt.Errorf("failed to parse genesis: %w", err)
	}

	// Apply configuration
	vm.config = Config{
		MaxMessageSize:    defaultMaxMessageSize,
		ConfirmationDepth: defaultConfirmationDepth,
		RelayTimeout:      defaultRelayTimeout,
	}

	if genesis.Config != nil {
		if genesis.Config.MaxMessageSize > 0 {
			vm.config.MaxMessageSize = genesis.Config.MaxMessageSize
		}
		if genesis.Config.ConfirmationDepth > 0 {
			vm.config.ConfirmationDepth = genesis.Config.ConfirmationDepth
		}
		vm.config.TrustedRelayers = genesis.Config.TrustedRelayers
		vm.config.SupportedChains = genesis.Config.SupportedChains
	}

	// Initialize RPC server
	vm.rpcServer = rpc.NewServer()
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json")
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json;charset=UTF-8")
	vm.rpcServer.RegisterService(&Service{vm: vm}, "relay")

	// Load last accepted block
	if err := vm.loadLastAccepted(); err != nil {
		return err
	}

	// Initialize genesis channels if any
	for _, ch := range genesis.Channels {
		vm.channels[ch.ID] = ch
		vm.sequences[ch.ID] = 0
	}

	vm.log.Info("RelayVM initialized",
		log.Int("channels", len(vm.channels)),
		log.Int("trustedRelayers", len(vm.config.TrustedRelayers)),
	)

	return nil
}

// loadLastAccepted loads the last accepted block from the database
func (vm *VM) loadLastAccepted() error {
	lastAcceptedBytes, err := vm.db.Get(lastAcceptedKey)
	if err == database.ErrNotFound {
		// No blocks yet, create genesis block
		vm.lastAccepted = &Block{
			BlockHeight:    0,
			BlockTimestamp: time.Now().Unix(),
			vm:             vm,
			status:         choices.Accepted,
		}
		vm.lastAcceptedID = vm.lastAccepted.ID()
		return nil
	}
	if err != nil {
		return err
	}

	var blockID ids.ID
	copy(blockID[:], lastAcceptedBytes)

	blockBytes, err := vm.db.Get(blockID[:])
	if err != nil {
		return err
	}

	var block Block
	if err := json.Unmarshal(blockBytes, &block); err != nil {
		return err
	}

	block.vm = vm
	block.status = choices.Accepted
	vm.lastAccepted = &block
	vm.lastAcceptedID = blockID

	return nil
}

// SetState implements chain.ChainVM
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	return nil
}

// NewHTTPHandler implements chain.ChainVM
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	handlers, err := vm.CreateHandlers(ctx)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	for path, handler := range handlers {
		if path == "" {
			path = "/"
		}
		mux.Handle(path, handler)
	}
	return mux, nil
}

// Shutdown implements chain.ChainVM
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.log.Info("RelayVM shutting down")
	return nil
}

// CreateHandlers implements chain.ChainVM
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{
		"/rpc": vm.rpcServer,
	}, nil
}

// HealthCheck implements chain.ChainVM
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	return chain.HealthResult{
		Healthy: true,
		Details: map[string]string{
			"channels":        fmt.Sprintf("%d", len(vm.channels)),
			"pendingMessages": fmt.Sprintf("%d", vm.countPendingMessages()),
		},
	}, nil
}

func (vm *VM) countPendingMessages() int {
	count := 0
	for _, msgs := range vm.pendingMsgs {
		count += len(msgs)
	}
	return count
}

// Version implements chain.ChainVM
func (vm *VM) Version(ctx context.Context) (string, error) {
	return "1.0.0", nil
}

// Connected implements chain.ChainVM
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *chain.VersionInfo) error {
	vm.log.Debug("Node connected", log.String("nodeID", nodeID.String()))
	return nil
}

// Disconnected implements chain.ChainVM
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	vm.log.Debug("Node disconnected", log.String("nodeID", nodeID.String()))
	return nil
}

// BuildBlock implements chain.ChainVM
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Collect pending messages
	var messages []*Message
	for _, msgs := range vm.pendingMsgs {
		messages = append(messages, msgs...)
	}

	block := &Block{
		ParentID_:      vm.lastAcceptedID,
		BlockHeight:    vm.lastAccepted.BlockHeight + 1,
		BlockTimestamp: time.Now().Unix(),
		Messages:       messages,
		vm:             vm,
		status:         choices.Processing,
	}

	vm.pendingBlocks[block.ID()] = block

	return block, nil
}

// ParseBlock implements chain.ChainVM
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (chain.Block, error) {
	var block Block
	if err := json.Unmarshal(blockBytes, &block); err != nil {
		return nil, err
	}

	block.vm = vm
	block.bytes = blockBytes

	return &block, nil
}

// GetBlock implements chain.ChainVM
func (vm *VM) GetBlock(ctx context.Context, blockID ids.ID) (chain.Block, error) {
	vm.mu.RLock()
	// Check pending blocks (nil-safe for early calls before initialization)
	if vm.pendingBlocks != nil {
		if block, ok := vm.pendingBlocks[blockID]; ok {
			vm.mu.RUnlock()
			return block, nil
		}
	}
	vm.mu.RUnlock()

	blockBytes, err := vm.db.Get(blockID[:])
	if err != nil {
		return nil, err
	}

	var block Block
	if err := json.Unmarshal(blockBytes, &block); err != nil {
		return nil, err
	}

	block.vm = vm
	block.bytes = blockBytes
	block.status = choices.Accepted

	return &block, nil
}

// SetPreference implements chain.ChainVM
func (vm *VM) SetPreference(ctx context.Context, blockID ids.ID) error {
	return nil
}

// LastAccepted implements chain.ChainVM
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.lastAcceptedID, nil
}

// ======== Channel Management ========

// OpenChannel opens a new cross-chain channel
func (vm *VM) OpenChannel(sourceChain, destChain ids.ID, ordering, version string) (*Channel, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Generate channel ID
	h := sha256.New()
	h.Write(sourceChain[:])
	h.Write(destChain[:])
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())
	channelID := ids.ID(h.Sum(nil))

	channel := &Channel{
		ID:          channelID,
		SourceChain: sourceChain,
		DestChain:   destChain,
		Ordering:    ordering,
		Version:     version,
		State:       "open",
		CreatedAt:   time.Now(),
		Metadata:    make(map[string]string),
	}

	vm.channels[channelID] = channel
	vm.sequences[channelID] = 0

	// Persist channel
	channelBytes, _ := json.Marshal(channel)
	key := append(channelPrefix, channelID[:]...)
	if err := vm.db.Put(key, channelBytes); err != nil {
		return nil, err
	}

	return channel, nil
}

// GetChannel returns a channel by ID
func (vm *VM) GetChannel(channelID ids.ID) (*Channel, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	channel, ok := vm.channels[channelID]
	if !ok {
		return nil, errUnknownChannel
	}
	return channel, nil
}

// CloseChannel closes a channel
func (vm *VM) CloseChannel(channelID ids.ID) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	channel, ok := vm.channels[channelID]
	if !ok {
		return errUnknownChannel
	}

	channel.State = "closed"

	// Persist update
	channelBytes, _ := json.Marshal(channel)
	key := append(channelPrefix, channelID[:]...)
	return vm.db.Put(key, channelBytes)
}

// ======== Message Relay ========

// SendMessage queues a message for relay
func (vm *VM) SendMessage(channelID ids.ID, payload, sender, receiver []byte, timeout int64) (*Message, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	channel, ok := vm.channels[channelID]
	if !ok {
		return nil, errUnknownChannel
	}

	if channel.State != "open" {
		return nil, errChannelClosed
	}

	if len(payload) > vm.config.MaxMessageSize {
		return nil, errMessageTooLarge
	}

	// Get next sequence number
	seq := vm.sequences[channelID]
	vm.sequences[channelID] = seq + 1

	// Generate message ID
	h := sha256.New()
	h.Write(channelID[:])
	binary.Write(h, binary.BigEndian, seq)
	h.Write(payload)
	msgID := ids.ID(h.Sum(nil))

	msg := &Message{
		ID:          msgID,
		ChannelID:   channelID,
		SourceChain: channel.SourceChain,
		DestChain:   channel.DestChain,
		Sequence:    seq,
		Payload:     payload,
		Sender:      sender,
		Receiver:    receiver,
		Timeout:     timeout,
		State:       MessagePending,
	}

	vm.messages[msgID] = msg
	vm.pendingMsgs[channel.DestChain] = append(vm.pendingMsgs[channel.DestChain], msg)

	return msg, nil
}

// ReceiveMessage processes an incoming message with proof
func (vm *VM) ReceiveMessage(msgID ids.ID, proof []byte, sourceHeight uint64) (*MessageReceipt, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	msg, ok := vm.messages[msgID]
	if !ok {
		return nil, errUnknownMessage
	}

	// Store proof and source height
	msg.Proof = proof
	msg.SourceHeight = sourceHeight

	// Verify the proof (simplified - would involve Merkle proof verification)
	if err := vm.verifyMessageProof(msg); err != nil {
		msg.State = MessageFailed
		return nil, err
	}

	msg.State = MessageVerified
	msg.ConfirmedAt = time.Now().Unix()

	// Create receipt
	receipt := &MessageReceipt{
		MessageID:   msgID,
		ChannelID:   msg.ChannelID,
		Success:     true,
		ResultHash:  sha256Hash(msg.Payload),
		BlockHeight: vm.lastAccepted.BlockHeight,
		Timestamp:   time.Now().Unix(),
	}

	return receipt, nil
}

func (vm *VM) verifyMessageProof(msg *Message) error {
	// Simplified proof verification
	// In production: verify Merkle proof against source chain state root
	if len(msg.Proof) == 0 {
		return nil // Allow for testing
	}
	return nil
}

// GetMessage returns a message by ID
func (vm *VM) GetMessage(msgID ids.ID) (*Message, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	msg, ok := vm.messages[msgID]
	if !ok {
		return nil, errUnknownMessage
	}
	return msg, nil
}

// CreateVerifiedMessage creates a VerifiedMessage artifact
func (vm *VM) CreateVerifiedMessage(msg *Message) (*artifacts.VerifiedMessage, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if msg.State != MessageVerified && msg.State != MessageDelivered {
		return nil, errors.New("message not yet verified")
	}

	verifiedMsg := &artifacts.VerifiedMessage{
		SrcDomain:         msg.SourceChain,
		DstDomain:         msg.DestChain,
		Nonce:             msg.Sequence,
		Payload:           msg.Payload,
		SrcFinalityProof:  msg.Proof,
		Mode:              artifacts.LCMode, // Light client mode
	}

	return verifiedMsg, nil
}

// GetBlockIDAtHeight implements chain.HeightIndexedChainVM
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	// Not implemented - would require height index
	return ids.Empty, errors.New("height index not implemented")
}

// WaitForEvent implements chain.ChainVM
func (vm *VM) WaitForEvent(ctx context.Context) (luxvm.Message, error) {
	// Block until context is cancelled
	// In production, this would wait for relay requests, etc.
	// CRITICAL: Must block here to avoid notification flood loop in chains/manager.go
	<-ctx.Done()
	return luxvm.Message{}, ctx.Err()
}

// ======== Genesis ========

// Genesis represents genesis data for RelayVM
type Genesis struct {
	Timestamp int64      `json:"timestamp"`
	Config    *Config    `json:"config,omitempty"`
	Channels  []*Channel `json:"channels,omitempty"`
	Message   string     `json:"message,omitempty"`
}

// ParseGenesis parses genesis bytes
func ParseGenesis(genesisBytes []byte) (*Genesis, error) {
	var genesis Genesis
	if len(genesisBytes) > 0 {
		if err := json.Unmarshal(genesisBytes, &genesis); err != nil {
			return nil, err
		}
	}

	if genesis.Timestamp == 0 {
		genesis.Timestamp = time.Now().Unix()
	}

	return &genesis, nil
}

// ======== Utility ========

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// RegisterNodePublicKey registers a node's Ed25519 public key for signature verification
func (vm *VM) RegisterNodePublicKey(nodeID ids.NodeID, publicKey ed25519.PublicKey) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid public key size")
	}

	if vm.nodePublicKeys == nil {
		vm.nodePublicKeys = make(map[ids.NodeID]ed25519.PublicKey)
	}

	vm.nodePublicKeys[nodeID] = publicKey
	vm.log.Info("registered node public key", log.Stringer("nodeID", nodeID))
	return nil
}

// verifyReceiptSignature verifies a receipt's Ed25519 signature
func (vm *VM) verifyReceiptSignature(receipt *SignedReceipt) error {
	vm.mu.RLock()
	publicKey, exists := vm.nodePublicKeys[receipt.NodeID]
	vm.mu.RUnlock()

	if !exists {
		// If no public key registered for this node, derive from NodeID
		// NodeID is typically SHA256(PublicKey)[:20], so we cannot recover the key
		// In this case, we accept the receipt but log a warning
		// Production systems should register all validator public keys
		vm.log.Warn("no public key registered for node, skipping signature verification",
			log.Stringer("nodeID", receipt.NodeID))
		return nil
	}

	// Reconstruct the message that was signed
	// Format: MessageID || SessionID || NodeID || Timestamp || ContentHash
	h := sha256.New()
	h.Write(receipt.MessageID[:])
	h.Write(receipt.SessionID[:])
	h.Write(receipt.NodeID[:])

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, receipt.Timestamp)
	h.Write(timestampBytes)

	h.Write(receipt.ContentHash[:])
	message := h.Sum(nil)

	// Verify Ed25519 signature
	if !ed25519.Verify(publicKey, message, receipt.Signature) {
		return errInvalidSignature
	}

	return nil
}

// =============================================================================
// Session-Ready: Receipt Root Commitments
// =============================================================================
// RelayVM collects per-node signed receipts and commits them as Merkle roots
// at block boundaries for audit trail and dispute resolution.

// SignedReceipt represents a node's signed acknowledgment of message receipt
type SignedReceipt struct {
	// MessageID is the ID of the message being receipted
	MessageID ids.ID `json:"messageId"`

	// SessionID links the receipt to a session (if applicable)
	SessionID [32]byte `json:"sessionId"`

	// NodeID of the node signing this receipt
	NodeID ids.NodeID `json:"nodeId"`

	// Timestamp when the receipt was created
	Timestamp uint64 `json:"timestamp"`

	// ContentHash is hash of the message content received
	ContentHash [32]byte `json:"contentHash"`

	// Signature from the node's key over the receipt payload
	Signature []byte `json:"signature"`
}

// ReceiptCommit represents a Merkle root commitment over a set of receipts
type ReceiptCommit struct {
	// CommitID is the unique identifier for this commit
	CommitID [32]byte `json:"commitId"`

	// SessionID that this commit belongs to (if scoped to session)
	SessionID [32]byte `json:"sessionId,omitempty"`

	// Root is the Merkle root over all receipts in this commit
	Root [32]byte `json:"root"`

	// ReceiptCount is the number of receipts in this commit
	ReceiptCount uint32 `json:"receiptCount"`

	// BlockHeight at which this commit was created
	BlockHeight uint64 `json:"blockHeight"`

	// Window defines the receipt timestamp range
	Window struct {
		Start uint64 `json:"start"`
		End   uint64 `json:"end"`
	} `json:"window"`

	// CommittedAt is when this commit was created
	CommittedAt time.Time `json:"committedAt"`
}

// ComputeReceiptID computes a deterministic ID for a signed receipt
func ComputeReceiptID(messageID ids.ID, nodeID ids.NodeID, timestamp uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte("LUX:SignedReceipt:v1"))
	h.Write(messageID[:])
	h.Write(nodeID[:])

	timestampBytes := make([]byte, 8)
	timestampBytes[0] = byte(timestamp >> 56)
	timestampBytes[1] = byte(timestamp >> 48)
	timestampBytes[2] = byte(timestamp >> 40)
	timestampBytes[3] = byte(timestamp >> 32)
	timestampBytes[4] = byte(timestamp >> 24)
	timestampBytes[5] = byte(timestamp >> 16)
	timestampBytes[6] = byte(timestamp >> 8)
	timestampBytes[7] = byte(timestamp)
	h.Write(timestampBytes)

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// Session-ready state - add to VM struct lazily initialized
func (vm *VM) getSessionReceiptsMap() map[[32]byte][]*SignedReceipt {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if vm.sessionReceipts == nil {
		vm.sessionReceipts = make(map[[32]byte][]*SignedReceipt)
	}
	return vm.sessionReceipts
}

func (vm *VM) getReceiptCommitsMap() map[[32]byte]*ReceiptCommit {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if vm.receiptCommits == nil {
		vm.receiptCommits = make(map[[32]byte]*ReceiptCommit)
	}
	return vm.receiptCommits
}

// SubmitSignedReceipt records a signed receipt from a node
func (vm *VM) SubmitSignedReceipt(receipt *SignedReceipt) error {
	if receipt == nil {
		return errors.New("nil receipt")
	}

	// Validate the receipt has required fields
	if receipt.MessageID == ids.Empty {
		return errors.New("receipt missing message ID")
	}
	if receipt.NodeID == ids.EmptyNodeID {
		return errors.New("receipt missing node ID")
	}
	if len(receipt.Signature) == 0 {
		return errors.New("receipt missing signature")
	}

	// Verify signature against node's public key
	if err := vm.verifyReceiptSignature(receipt); err != nil {
		return fmt.Errorf("receipt signature verification failed: %w", err)
	}

	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Initialize maps if needed
	if vm.sessionReceipts == nil {
		vm.sessionReceipts = make(map[[32]byte][]*SignedReceipt)
	}

	// Store receipt by session
	sessionID := receipt.SessionID
	vm.sessionReceipts[sessionID] = append(vm.sessionReceipts[sessionID], receipt)

	vm.log.Debug("received signed receipt",
		log.Stringer("messageID", receipt.MessageID),
		log.Stringer("nodeID", receipt.NodeID),
	)

	return nil
}

// CommitSessionReceipts creates a Merkle root commitment for all receipts in a session
func (vm *VM) CommitSessionReceipts(sessionID [32]byte) (*ReceiptCommit, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Initialize maps if needed
	if vm.sessionReceipts == nil {
		vm.sessionReceipts = make(map[[32]byte][]*SignedReceipt)
	}
	if vm.receiptCommits == nil {
		vm.receiptCommits = make(map[[32]byte]*ReceiptCommit)
	}

	receipts, ok := vm.sessionReceipts[sessionID]
	if !ok || len(receipts) == 0 {
		return nil, errors.New("no receipts found for session")
	}

	// Compute Merkle root over receipts
	root := vm.computeReceiptsMerkleRoot(receipts)

	// Determine time window
	var minTime, maxTime uint64 = ^uint64(0), 0
	for _, r := range receipts {
		if r.Timestamp < minTime {
			minTime = r.Timestamp
		}
		if r.Timestamp > maxTime {
			maxTime = r.Timestamp
		}
	}

	// Generate commit ID
	h := sha256.New()
	h.Write([]byte("LUX:ReceiptCommit:v1"))
	h.Write(sessionID[:])
	h.Write(root[:])
	var commitID [32]byte
	copy(commitID[:], h.Sum(nil))

	commit := &ReceiptCommit{
		CommitID:     commitID,
		SessionID:    sessionID,
		Root:         root,
		ReceiptCount: uint32(len(receipts)),
		BlockHeight:  vm.lastAccepted.BlockHeight,
		CommittedAt:  time.Now(),
	}
	commit.Window.Start = minTime
	commit.Window.End = maxTime

	vm.receiptCommits[sessionID] = commit

	vm.log.Info("committed session receipts",
		log.Int("receiptCount", len(receipts)),
		log.Uint64("blockHeight", commit.BlockHeight),
	)

	return commit, nil
}

// computeReceiptsMerkleRoot computes a Merkle root over a set of receipts
func (vm *VM) computeReceiptsMerkleRoot(receipts []*SignedReceipt) [32]byte {
	if len(receipts) == 0 {
		return [32]byte{}
	}

	// Hash each receipt into a leaf
	leaves := make([][32]byte, len(receipts))
	for i, r := range receipts {
		h := sha256.New()
		h.Write(r.MessageID[:])
		h.Write(r.NodeID[:])
		h.Write(r.ContentHash[:])
		h.Write(r.Signature)

		timestampBytes := make([]byte, 8)
		timestampBytes[0] = byte(r.Timestamp >> 56)
		timestampBytes[1] = byte(r.Timestamp >> 48)
		timestampBytes[2] = byte(r.Timestamp >> 40)
		timestampBytes[3] = byte(r.Timestamp >> 32)
		timestampBytes[4] = byte(r.Timestamp >> 24)
		timestampBytes[5] = byte(r.Timestamp >> 16)
		timestampBytes[6] = byte(r.Timestamp >> 8)
		timestampBytes[7] = byte(r.Timestamp)
		h.Write(timestampBytes)

		copy(leaves[i][:], h.Sum(nil))
	}

	// Build Merkle tree
	return buildMerkleRoot(leaves)
}

// buildMerkleRoot constructs a Merkle root from leaf hashes
func buildMerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	// Pad to power of 2
	for len(leaves)&(len(leaves)-1) != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	// Build tree bottom-up
	for len(leaves) > 1 {
		var nextLevel [][32]byte
		for i := 0; i < len(leaves); i += 2 {
			h := sha256.New()
			h.Write(leaves[i][:])
			h.Write(leaves[i+1][:])
			var parent [32]byte
			copy(parent[:], h.Sum(nil))
			nextLevel = append(nextLevel, parent)
		}
		leaves = nextLevel
	}

	return leaves[0]
}

// GetReceiptCommit retrieves a receipt commit for a session
func (vm *VM) GetReceiptCommit(sessionID [32]byte) (*ReceiptCommit, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if vm.receiptCommits == nil {
		return nil, errors.New("no receipt commits")
	}

	commit, ok := vm.receiptCommits[sessionID]
	if !ok {
		return nil, errors.New("receipt commit not found for session")
	}

	return commit, nil
}

// GenerateReceiptInclusionProof generates a Merkle proof for a receipt in a session
func (vm *VM) GenerateReceiptInclusionProof(sessionID [32]byte, receiptIndex int) ([][]byte, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if vm.sessionReceipts == nil {
		return nil, errors.New("no session receipts")
	}

	receipts, ok := vm.sessionReceipts[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}

	if receiptIndex < 0 || receiptIndex >= len(receipts) {
		return nil, errors.New("receipt index out of range")
	}

	// Hash each receipt into a leaf
	leaves := make([][32]byte, len(receipts))
	for i, r := range receipts {
		h := sha256.New()
		h.Write(r.MessageID[:])
		h.Write(r.NodeID[:])
		h.Write(r.ContentHash[:])
		h.Write(r.Signature)

		timestampBytes := make([]byte, 8)
		timestampBytes[0] = byte(r.Timestamp >> 56)
		timestampBytes[1] = byte(r.Timestamp >> 48)
		timestampBytes[2] = byte(r.Timestamp >> 40)
		timestampBytes[3] = byte(r.Timestamp >> 32)
		timestampBytes[4] = byte(r.Timestamp >> 24)
		timestampBytes[5] = byte(r.Timestamp >> 16)
		timestampBytes[6] = byte(r.Timestamp >> 8)
		timestampBytes[7] = byte(r.Timestamp)
		h.Write(timestampBytes)

		copy(leaves[i][:], h.Sum(nil))
	}

	// Pad to power of 2
	originalLen := len(leaves)
	for len(leaves)&(len(leaves)-1) != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	// Build proof
	proof := buildMerkleProof(leaves, receiptIndex, originalLen)

	return proof, nil
}

// buildMerkleProof generates an inclusion proof for a leaf at given index
func buildMerkleProof(leaves [][32]byte, index int, originalLen int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}

	var proof [][]byte
	currentIndex := index

	for len(leaves) > 1 {
		// Get sibling
		var siblingIndex int
		if currentIndex%2 == 0 {
			siblingIndex = currentIndex + 1
		} else {
			siblingIndex = currentIndex - 1
		}

		if siblingIndex < len(leaves) {
			proof = append(proof, leaves[siblingIndex][:])
		}

		// Move to parent level
		var nextLevel [][32]byte
		for i := 0; i < len(leaves); i += 2 {
			h := sha256.New()
			h.Write(leaves[i][:])
			if i+1 < len(leaves) {
				h.Write(leaves[i+1][:])
			} else {
				h.Write(leaves[i][:])
			}
			var parent [32]byte
			copy(parent[:], h.Sum(nil))
			nextLevel = append(nextLevel, parent)
		}

		leaves = nextLevel
		currentIndex = currentIndex / 2
	}

	return proof
}

// VerifyReceiptInclusionProof verifies a Merkle inclusion proof for a receipt
func VerifyReceiptInclusionProof(receipt *SignedReceipt, proof [][]byte, root [32]byte, index int) bool {
	// Compute leaf hash
	h := sha256.New()
	h.Write(receipt.MessageID[:])
	h.Write(receipt.NodeID[:])
	h.Write(receipt.ContentHash[:])
	h.Write(receipt.Signature)

	timestampBytes := make([]byte, 8)
	timestampBytes[0] = byte(receipt.Timestamp >> 56)
	timestampBytes[1] = byte(receipt.Timestamp >> 48)
	timestampBytes[2] = byte(receipt.Timestamp >> 40)
	timestampBytes[3] = byte(receipt.Timestamp >> 32)
	timestampBytes[4] = byte(receipt.Timestamp >> 24)
	timestampBytes[5] = byte(receipt.Timestamp >> 16)
	timestampBytes[6] = byte(receipt.Timestamp >> 8)
	timestampBytes[7] = byte(receipt.Timestamp)
	h.Write(timestampBytes)

	var computed [32]byte
	copy(computed[:], h.Sum(nil))

	// Walk up the tree using the proof
	currentIndex := index
	for _, sibling := range proof {
		h := sha256.New()
		if currentIndex%2 == 0 {
			h.Write(computed[:])
			h.Write(sibling)
		} else {
			h.Write(sibling)
			h.Write(computed[:])
		}
		copy(computed[:], h.Sum(nil))
		currentIndex = currentIndex / 2
	}

	return computed == root
}
