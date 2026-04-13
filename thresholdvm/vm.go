// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package tvm implements the Threshold VM (T-Chain) - MPC as a service for all Lux chains
package thresholdvm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/luxfi/vm/chain"
	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/version"
	"github.com/luxfi/runtime"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	lssconfig "github.com/luxfi/threshold/protocols/lss/config"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/warp"
)

var (
	_ chain.ChainVM = (*VM)(nil)

	Version = &version.Semantic{
		Major: 1,
		Minor: 0,
		Patch: 0,
	}

	// Error definitions
	ErrNotInitialized      = errors.New("MPC not initialized")
	ErrKeygenInProgress    = errors.New("keygen already in progress")
	ErrSigningInProgress   = errors.New("signing session already in progress")
	ErrInvalidThreshold    = errors.New("invalid threshold configuration")
	ErrInsufficientParties = errors.New("insufficient parties for operation")
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionExpired      = errors.New("session expired")
	ErrUnauthorizedChain   = errors.New("unauthorized chain")
	ErrQuotaExceeded       = errors.New("signing quota exceeded")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrKeyNotFound         = errors.New("key not found")
)

// ThresholdConfig contains VM configuration
type ThresholdConfig struct {
	// MPC Configuration
	Threshold    int `json:"threshold"`    // t: Threshold (t+1 parties needed)
	TotalParties int `json:"totalParties"` // n: Total number of MPC nodes

	// Session Configuration
	SessionTimeout      time.Duration `json:"sessionTimeout"`      // Max time for a signing session
	MaxActiveSessions   int           `json:"maxActiveSessions"`   // Max concurrent signing sessions
	MaxSessionsPerChain int           `json:"maxSessionsPerChain"` // Max sessions per requesting chain

	// Quota Configuration (daily limits)
	DailySigningQuota map[string]uint64 `json:"dailySigningQuota"` // ChainID -> daily signing limit

	// Authorized Chains that can request MPC services
	AuthorizedChains map[string]*ChainPermissions `json:"authorizedChains"`

	// Key Management
	KeyRotationPeriod time.Duration `json:"keyRotationPeriod"` // How often to rotate keys
	MaxKeyAge         time.Duration `json:"maxKeyAge"`         // Maximum age of a key before forced rotation
}

// ChainPermissions defines what a chain can do with MPC services
type ChainPermissions struct {
	ChainID           string   `json:"chainId"`
	ChainName         string   `json:"chainName"`
	CanSign           bool     `json:"canSign"`           // Can request signatures
	CanKeygen         bool     `json:"canKeygen"`         // Can request new key generation
	CanReshare        bool     `json:"canReshare"`        // Can request key resharing
	AllowedKeyTypes   []string `json:"allowedKeyTypes"`   // secp256k1, ed25519, etc.
	MaxSigningSize    int      `json:"maxSigningSize"`    // Max message size to sign
	RequirePreHash    bool     `json:"requirePreHash"`    // Require pre-hashed messages
	DailySigningLimit uint64   `json:"dailySigningLimit"` // Override global quota
}

// VM implements the Threshold VM for MPC-as-a-service
type VM struct {
	rt       *runtime.Runtime
	db       database.Database
	config   ThresholdConfig
	toEngine chan<- vmcore.Message
	log      log.Logger

	// Protocol Registry - supports multiple threshold protocols
	protocolRegistry *ProtocolRegistry

	// Protocol Executor - handles actual protocol execution with timeouts
	protocolExecutor *ProtocolExecutor

	// Message Router for multi-party communication
	messageRouter MessageRouter

	// LSS MPC Protocol Components (default protocol)
	lssConfig *lssconfig.Config // LSS config for this party (after keygen)
	partyID   party.ID          // This party's ID
	partyIDs  []party.ID        // All party IDs in the MPC group
	pool      *pool.Pool        // Worker pool for MPC operations
	mpcReady  bool              // Whether MPC is ready for signing

	// Key Management
	keys           map[string]*ManagedKey // KeyID -> Key configuration
	activeKeyID    string                 // Currently active key for signing
	keygenSessions map[string]*KeygenSession

	// Signing Sessions
	signingSessions map[string]*SigningSession
	sessionsByChain map[string][]string // ChainID -> SessionIDs

	// Quota Tracking
	dailySigningCount map[string]uint64 // ChainID -> count today
	quotaResetTime    time.Time         // When to reset quotas

	// Block Management
	preferred      ids.ID
	lastAcceptedID ids.ID
	pendingBlocks  map[ids.ID]*Block
	heightIndex    map[uint64]ids.ID

	// Network Stats
	stats *vmStats

	mu sync.RWMutex
}

// ManagedKey represents a threshold key managed by the T-Chain
type ManagedKey struct {
	KeyID        string            `json:"keyId"`
	KeyType      string            `json:"keyType"`      // secp256k1, ed25519
	PublicKey    []byte            `json:"publicKey"`    // Compressed public key
	Address      []byte            `json:"address"`      // Ethereum-style address (for secp256k1)
	Threshold    int               `json:"threshold"`    // t value
	TotalParties int               `json:"totalParties"` // n value
	Generation   uint64            `json:"generation"`   // Key generation number
	CreatedAt    time.Time         `json:"createdAt"`
	LastUsedAt   time.Time         `json:"lastUsedAt"`
	SignCount    uint64            `json:"signCount"` // Total signatures made
	Status       string            `json:"status"`    // active, rotating, expired
	Config       *lssconfig.Config `json:"-"`         // LSS configuration (not serialized)
	PartyIDs     []party.ID        `json:"partyIds"`
}

// KeygenSession tracks a key generation in progress
type KeygenSession struct {
	SessionID    string     `json:"sessionId"`
	KeyID        string     `json:"keyId"`
	KeyType      string     `json:"keyType"`
	Threshold    int        `json:"threshold"`
	TotalParties int        `json:"totalParties"`
	PartyIDs     []party.ID `json:"partyIds"`
	Status       string     `json:"status"` // pending, running, completed, failed
	RequestedBy  string     `json:"requestedBy"`
	StartedAt    time.Time  `json:"startedAt"`
	CompletedAt  time.Time  `json:"completedAt,omitempty"`
	Error        string     `json:"error,omitempty"`
	ProtocolName Protocol   `json:"-"` // Our local Protocol type
}

// SigningSession tracks a signing operation in progress
type SigningSession struct {
	SessionID       string          `json:"sessionId"`
	KeyID           string          `json:"keyId"`
	RequestingChain string          `json:"requestingChain"`
	MessageHash     []byte          `json:"messageHash"`
	MessageType     string          `json:"messageType"` // raw, eth_sign, typed_data
	Status          string          `json:"status"`      // pending, signing, completed, failed
	Signature       *ecdsaSignature `json:"signature,omitempty"`
	SignerParties   []party.ID      `json:"signerParties"`
	CreatedAt       time.Time       `json:"createdAt"`
	ExpiresAt       time.Time       `json:"expiresAt"`
	CompletedAt     time.Time       `json:"completedAt,omitempty"`
	Error           string          `json:"error,omitempty"`
	ProtocolName    Protocol        `json:"-"` // Our local Protocol type
}

// ecdsaSignature holds the signature components
type ecdsaSignature struct {
	R []byte `json:"r"`
	S []byte `json:"s"`
	V byte   `json:"v"` // Recovery ID
}

// vmStats tracks internal T-Chain statistics (with mutex for thread safety)
type vmStats struct {
	TotalSignatures    uint64
	TotalKeygens       uint64
	ActiveSessions     int
	SignaturesByChain  map[string]uint64
	AverageSigningTime time.Duration
	SuccessRate        float64
	mu                 sync.RWMutex
}

// Initialize implements the chain.ChainVM interface
func (vm *VM) Initialize(
	ctx context.Context,
	init vmcore.Init,
) error {
	vm.rt = init.Runtime
	vm.db = init.DB
	vm.toEngine = init.ToEngine
	// Use init.Log if provided, otherwise fallback to Runtime.Log
	if init.Log != nil {
		vm.log = init.Log
	} else if init.Runtime != nil {
		if logger, ok := init.Runtime.Log.(log.Logger); ok {
			vm.log = logger
		}
	}

	// Initialize maps
	vm.pendingBlocks = make(map[ids.ID]*Block)
	vm.heightIndex = make(map[uint64]ids.ID)
	vm.keys = make(map[string]*ManagedKey)
	vm.keygenSessions = make(map[string]*KeygenSession)
	vm.signingSessions = make(map[string]*SigningSession)
	vm.sessionsByChain = make(map[string][]string)
	vm.dailySigningCount = make(map[string]uint64)
	vm.quotaResetTime = time.Now().Add(24 * time.Hour)
	vm.stats = &vmStats{
		SignaturesByChain: make(map[string]uint64),
	}

	// Parse configuration
	if err := vm.parseConfig(init.Config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Initialize party ID from node ID
	vm.partyID = party.ID(vm.rt.NodeID.String())

	// Create worker pool for MPC operations
	vm.pool = pool.NewPool(16) // 16 workers for parallel MPC

	// Initialize protocol executor for handling protocol execution with proper timeouts
	vm.protocolExecutor = NewProtocolExecutor(vm.pool, vm.log)

	// Initialize protocol registry with all supported protocols
	vm.protocolRegistry = NewProtocolRegistry(vm.pool)

	// Wire the protocol executor to handlers that need it (CMP, LSS)
	if cmpHandler, err := vm.protocolRegistry.Get(ProtocolCGGMP21); err == nil {
		if h, ok := cmpHandler.(*CGGMP21Handler); ok {
			h.SetExecutor(vm.protocolExecutor)
			// Message router will be set when multi-party communication is established
		}
	}

	// Parse genesis - use JSON for simple genesis configuration
	genesis := &Genesis{}
	if len(init.Genesis) > 0 {
		if err := json.Unmarshal(init.Genesis, genesis); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}

	// Create genesis block
	genesisBlock := &Block{
		BlockHeight:    0,
		BlockTimestamp: genesis.Timestamp,
		ParentID_:      ids.Empty,
		Operations:     []*Operation{},
		vm:             vm,
	}

	genesisBlock.ID_ = genesisBlock.computeID()
	vm.lastAcceptedID = genesisBlock.ID()
	vm.heightIndex[0] = genesisBlock.ID()

	if err := vm.putBlock(genesisBlock); err != nil {
		return fmt.Errorf("failed to store genesis block: %w", err)
	}

	// Load existing keys from database
	if err := vm.loadKeys(); err != nil {
		vm.log.Warn("failed to load existing keys", log.String("error", err.Error()))
	}

	vm.log.Info("ThresholdVM initialized",
		log.Int("threshold", vm.config.Threshold),
		log.Int("totalParties", vm.config.TotalParties),
		log.Int("authorizedChains", len(vm.config.AuthorizedChains)),
	)

	return nil
}

func (vm *VM) parseConfig(configBytes []byte) error {
	if len(configBytes) == 0 {
		// Default configuration
		vm.config = ThresholdConfig{
			Threshold:           2,
			TotalParties:        3,
			SessionTimeout:      5 * time.Minute,
			MaxActiveSessions:   100,
			MaxSessionsPerChain: 10,
			KeyRotationPeriod:   30 * 24 * time.Hour,
			MaxKeyAge:           90 * 24 * time.Hour,
			DailySigningQuota:   make(map[string]uint64),
			AuthorizedChains:    make(map[string]*ChainPermissions),
		}

		// Default authorized chains (all internal Lux chains)
		vm.config.AuthorizedChains["X-Chain"] = &ChainPermissions{
			ChainID:           "X-Chain",
			ChainName:         "UTXO Chain",
			CanSign:           true,
			CanKeygen:         false,
			CanReshare:        false,
			AllowedKeyTypes:   []string{"secp256k1"},
			MaxSigningSize:    256,
			DailySigningLimit: 10000,
		}
		vm.config.AuthorizedChains["B-Chain"] = &ChainPermissions{
			ChainID:           "B-Chain",
			ChainName:         "Bridge Chain",
			CanSign:           true,
			CanKeygen:         true,
			CanReshare:        true,
			AllowedKeyTypes:   []string{"secp256k1"},
			MaxSigningSize:    1024,
			DailySigningLimit: 100000,
		}
		vm.config.AuthorizedChains["C-Chain"] = &ChainPermissions{
			ChainID:           "C-Chain",
			ChainName:         "Contract Chain",
			CanSign:           true,
			CanKeygen:         false,
			CanReshare:        false,
			AllowedKeyTypes:   []string{"secp256k1"},
			MaxSigningSize:    256,
			DailySigningLimit: 50000,
		}
		vm.config.AuthorizedChains["P-Chain"] = &ChainPermissions{
			ChainID:           "P-Chain",
			ChainName:         "Platform Chain",
			CanSign:           true,
			CanKeygen:         true,
			CanReshare:        true,
			AllowedKeyTypes:   []string{"secp256k1", "bls"},
			MaxSigningSize:    512,
			DailySigningLimit: 10000,
		}
		vm.config.AuthorizedChains["Q-Chain"] = &ChainPermissions{
			ChainID:           "Q-Chain",
			ChainName:         "Quantum Chain",
			CanSign:           true,
			CanKeygen:         true,
			CanReshare:        true,
			AllowedKeyTypes:   []string{"secp256k1", "dilithium"},
			MaxSigningSize:    512,
			DailySigningLimit: 10000,
		}

		return nil
	}

	if _, err := Codec.Unmarshal(configBytes, &vm.config); err != nil {
		return err
	}

	// Validate configuration
	if vm.config.Threshold < 1 {
		return ErrInvalidThreshold
	}
	if vm.config.TotalParties < vm.config.Threshold+1 {
		return ErrInsufficientParties
	}

	return nil
}

// InitializeMPC sets up the MPC group with party IDs
func (vm *VM) InitializeMPC(partyIDs []party.ID) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if len(partyIDs) < vm.config.Threshold+1 {
		return ErrInsufficientParties
	}

	vm.partyIDs = partyIDs

	// Check if we have an existing key
	if vm.activeKeyID != "" {
		if key, ok := vm.keys[vm.activeKeyID]; ok && key.Config != nil {
			vm.lssConfig = key.Config
			vm.mpcReady = true
			vm.log.Info("MPC initialized with existing key",
				log.String("keyID", vm.activeKeyID),
				log.Uint64("generation", key.Generation),
			)
			return nil
		}
	}

	vm.log.Info("MPC initialized without active key - keygen required",
		log.Int("parties", len(partyIDs)),
	)

	return nil
}

// StartKeygenWithProtocol initiates distributed key generation with a specific protocol
func (vm *VM) StartKeygenWithProtocol(keyID, protocol, requestedBy string, threshold, totalParties int) (*KeygenSession, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Check if requestor is authorized
	perms, ok := vm.config.AuthorizedChains[requestedBy]
	if !ok || !perms.CanKeygen {
		return nil, ErrUnauthorizedChain
	}

	// Validate protocol
	handler, err := vm.protocolRegistry.Get(Protocol(protocol))
	if err != nil {
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	// Check if protocol is allowed for this chain
	curves := handler.SupportedCurves()
	allowed := false
	for _, kt := range perms.AllowedKeyTypes {
		for _, curve := range curves {
			if kt == curve || kt == protocol {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return nil, fmt.Errorf("protocol %s not allowed for chain %s", protocol, requestedBy)
	}

	// Check if there's already a keygen in progress for this key
	for _, session := range vm.keygenSessions {
		if session.KeyID == keyID && (session.Status == "pending" || session.Status == "running") {
			return nil, ErrKeygenInProgress
		}
	}

	// Use provided values or defaults
	if threshold == 0 {
		threshold = vm.config.Threshold
	}
	if totalParties == 0 {
		totalParties = vm.config.TotalParties
	}

	// Create keygen session
	sessionID := ids.GenerateTestID().String()
	session := &KeygenSession{
		SessionID:    sessionID,
		KeyID:        keyID,
		KeyType:      protocol,
		Threshold:    threshold,
		TotalParties: totalParties,
		PartyIDs:     vm.partyIDs,
		Status:       "pending",
		RequestedBy:  requestedBy,
		StartedAt:    time.Now(),
	}

	vm.keygenSessions[sessionID] = session

	// Start keygen in background with the specified protocol
	go vm.runKeygenWithProtocol(session, handler)

	vm.log.Info("started keygen session with protocol",
		log.String("sessionID", sessionID),
		log.String("keyID", keyID),
		log.String("protocol", protocol),
		log.String("requestedBy", requestedBy),
	)

	return session, nil
}

func (vm *VM) runKeygenWithProtocol(session *KeygenSession, handler ProtocolHandler) {
	vm.mu.Lock()
	session.Status = "running"
	vm.mu.Unlock()

	ctx := context.Background()

	// Run keygen using the protocol handler
	share, err := handler.Keygen(ctx, vm.partyID, session.PartyIDs, session.Threshold)

	vm.mu.Lock()
	defer vm.mu.Unlock()

	if err != nil {
		session.Status = "failed"
		session.Error = err.Error()
		vm.log.Error("keygen failed",
			log.String("sessionID", session.SessionID),
			log.String("error", err.Error()),
		)
		return
	}

	// Create managed key
	pubKey := share.PublicKey()
	address := publicKeyToAddress(pubKey)

	key := &ManagedKey{
		KeyID:        session.KeyID,
		KeyType:      session.KeyType,
		PublicKey:    pubKey,
		Address:      address,
		Threshold:    session.Threshold,
		TotalParties: session.TotalParties,
		Generation:   share.Generation(),
		CreatedAt:    time.Now(),
		Status:       "active",
		PartyIDs:     session.PartyIDs,
	}

	// Store protocol-specific config if LSS
	if lssShare, ok := share.(*lssKeyShare); ok {
		key.Config = lssShare.config
		vm.lssConfig = lssShare.config
	}

	vm.keys[session.KeyID] = key
	vm.activeKeyID = session.KeyID
	vm.mpcReady = true

	session.Status = "completed"
	session.CompletedAt = time.Now()

	// Persist key to database
	if err := vm.persistKey(key); err != nil {
		vm.log.Error("failed to persist key",
			log.String("keyID", session.KeyID),
			log.String("error", err.Error()),
		)
	}

	vm.stats.mu.Lock()
	vm.stats.TotalKeygens++
	vm.stats.mu.Unlock()

	vm.log.Info("keygen completed",
		log.String("sessionID", session.SessionID),
		log.String("keyID", session.KeyID),
		log.String("protocol", session.KeyType),
		log.String("publicKey", hex.EncodeToString(pubKey)),
	)
}

// RefreshKey refreshes key shares without changing the public key
func (vm *VM) RefreshKey(keyID string, requestedBy string) (*KeygenSession, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Check if requestor is authorized
	perms, ok := vm.config.AuthorizedChains[requestedBy]
	if !ok || !perms.CanReshare {
		return nil, ErrUnauthorizedChain
	}

	key, ok := vm.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Create refresh session
	sessionID := ids.GenerateTestID().String()
	session := &KeygenSession{
		SessionID:    sessionID,
		KeyID:        keyID,
		KeyType:      key.KeyType,
		Threshold:    key.Threshold,
		TotalParties: key.TotalParties,
		PartyIDs:     key.PartyIDs,
		Status:       "pending",
		RequestedBy:  requestedBy,
		StartedAt:    time.Now(),
	}

	vm.keygenSessions[sessionID] = session

	// Start refresh in background
	go vm.runRefresh(session, key)

	vm.log.Info("started refresh session",
		log.String("sessionID", sessionID),
		log.String("keyID", keyID),
	)

	return session, nil
}

func (vm *VM) runRefresh(session *KeygenSession, existingKey *ManagedKey) {
	vm.mu.Lock()
	session.Status = "running"
	vm.mu.Unlock()

	ctx := context.Background()

	// Get protocol handler
	handler, err := vm.protocolRegistry.Get(Protocol(existingKey.KeyType))
	if err != nil {
		vm.mu.Lock()
		session.Status = "failed"
		session.Error = err.Error()
		vm.mu.Unlock()
		return
	}

	// Need to reconstruct KeyShare from ManagedKey
	// This is protocol-specific
	var share KeyShare
	if existingKey.Config != nil {
		share = &lssKeyShare{config: existingKey.Config}
	} else {
		vm.mu.Lock()
		session.Status = "failed"
		session.Error = "no key share available for refresh"
		vm.mu.Unlock()
		return
	}

	// Run refresh
	newShare, err := handler.Refresh(ctx, share)

	vm.mu.Lock()
	defer vm.mu.Unlock()

	if err != nil {
		session.Status = "failed"
		session.Error = err.Error()
		vm.log.Error("refresh failed",
			log.String("sessionID", session.SessionID),
			log.String("error", err.Error()),
		)
		return
	}

	// Update key with refreshed share
	if lssShare, ok := newShare.(*lssKeyShare); ok {
		existingKey.Config = lssShare.config
		existingKey.Generation = lssShare.Generation()
		if existingKey.KeyID == vm.activeKeyID {
			vm.lssConfig = lssShare.config
		}
	}

	existingKey.LastUsedAt = time.Now()

	session.Status = "completed"
	session.CompletedAt = time.Now()

	// Persist updated key
	if err := vm.persistKey(existingKey); err != nil {
		vm.log.Error("failed to persist refreshed key",
			log.String("keyID", session.KeyID),
			log.String("error", err.Error()),
		)
	}

	vm.log.Info("refresh completed",
		log.String("sessionID", session.SessionID),
		log.String("keyID", session.KeyID),
		log.Uint64("newGeneration", existingKey.Generation),
	)
}

// StartKeygen initiates distributed key generation (uses default LSS protocol)
func (vm *VM) StartKeygen(keyID, keyType, requestedBy string) (*KeygenSession, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Check if requestor is authorized
	perms, ok := vm.config.AuthorizedChains[requestedBy]
	if !ok || !perms.CanKeygen {
		return nil, ErrUnauthorizedChain
	}

	// Check if keytype is allowed
	allowed := false
	for _, kt := range perms.AllowedKeyTypes {
		if kt == keyType {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("key type %s not allowed for chain %s", keyType, requestedBy)
	}

	// Check if there's already a keygen in progress for this key
	for _, session := range vm.keygenSessions {
		if session.KeyID == keyID && (session.Status == "pending" || session.Status == "running") {
			return nil, ErrKeygenInProgress
		}
	}

	// Create keygen session
	sessionID := ids.GenerateTestID().String()
	session := &KeygenSession{
		SessionID:    sessionID,
		KeyID:        keyID,
		KeyType:      keyType,
		Threshold:    vm.config.Threshold,
		TotalParties: vm.config.TotalParties,
		PartyIDs:     vm.partyIDs,
		Status:       "pending",
		RequestedBy:  requestedBy,
		StartedAt:    time.Now(),
	}

	vm.keygenSessions[sessionID] = session

	// Start keygen in background
	go vm.runKeygen(session)

	vm.log.Info("started keygen session",
		log.String("sessionID", sessionID),
		log.String("keyID", keyID),
		log.String("keyType", keyType),
		log.String("requestedBy", requestedBy),
	)

	return session, nil
}

func (vm *VM) runKeygen(session *KeygenSession) {
	vm.mu.Lock()
	session.Status = "running"
	vm.mu.Unlock()

	// The LSS library returns protocol.StartFunc for async execution
	// For now, we'll use the protocol handler abstraction which wraps this
	handler, err := vm.protocolRegistry.Get(ProtocolLSS)
	if err != nil {
		vm.mu.Lock()
		session.Status = "failed"
		session.Error = err.Error()
		vm.mu.Unlock()
		return
	}

	ctx := context.Background()
	share, err := handler.Keygen(ctx, vm.partyID, session.PartyIDs, session.Threshold)

	vm.mu.Lock()
	defer vm.mu.Unlock()

	if err != nil {
		session.Status = "failed"
		session.Error = err.Error()
		vm.log.Error("keygen failed",
			log.String("sessionID", session.SessionID),
			log.String("error", err.Error()),
		)
		return
	}

	// Create managed key from share
	pubKeyBytes := share.PublicKey()
	address := publicKeyToAddress(pubKeyBytes)

	key := &ManagedKey{
		KeyID:        session.KeyID,
		KeyType:      session.KeyType,
		PublicKey:    pubKeyBytes,
		Address:      address,
		Threshold:    session.Threshold,
		TotalParties: session.TotalParties,
		Generation:   share.Generation(),
		CreatedAt:    time.Now(),
		Status:       "active",
		PartyIDs:     session.PartyIDs,
	}

	// Store protocol-specific config if LSS
	if lssShare, ok := share.(*lssKeyShare); ok && lssShare.config != nil {
		key.Config = lssShare.config
		vm.lssConfig = lssShare.config
	}

	vm.keys[session.KeyID] = key
	vm.activeKeyID = session.KeyID
	vm.mpcReady = true

	session.Status = "completed"
	session.CompletedAt = time.Now()

	// Persist key to database
	if err := vm.persistKey(key); err != nil {
		vm.log.Error("failed to persist key",
			log.String("keyID", session.KeyID),
			log.String("error", err.Error()),
		)
	}

	vm.stats.mu.Lock()
	vm.stats.TotalKeygens++
	vm.stats.mu.Unlock()

	vm.log.Info("keygen completed",
		log.String("sessionID", session.SessionID),
		log.String("keyID", session.KeyID),
		log.String("publicKey", hex.EncodeToString(pubKeyBytes)),
	)
}

// RequestSignature requests a threshold signature from the T-Chain
func (vm *VM) RequestSignature(
	requestingChain string,
	keyID string,
	messageHash []byte,
	messageType string,
) (*SigningSession, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Check if chain is authorized
	perms, ok := vm.config.AuthorizedChains[requestingChain]
	if !ok || !perms.CanSign {
		return nil, ErrUnauthorizedChain
	}

	// Check message size
	if len(messageHash) > perms.MaxSigningSize {
		return nil, fmt.Errorf("message too large: %d > %d", len(messageHash), perms.MaxSigningSize)
	}

	// Check quota
	vm.checkQuotaReset()
	count := vm.dailySigningCount[requestingChain]
	limit := perms.DailySigningLimit
	if vm.config.DailySigningQuota[requestingChain] > 0 {
		limit = vm.config.DailySigningQuota[requestingChain]
	}
	if count >= limit {
		return nil, ErrQuotaExceeded
	}

	// Check max active sessions
	if len(vm.signingSessions) >= vm.config.MaxActiveSessions {
		return nil, fmt.Errorf("max active sessions reached")
	}

	// Check max sessions per chain
	chainSessions := vm.sessionsByChain[requestingChain]
	activeSessions := 0
	for _, sid := range chainSessions {
		if s, ok := vm.signingSessions[sid]; ok && s.Status == "signing" {
			activeSessions++
		}
	}
	if activeSessions >= vm.config.MaxSessionsPerChain {
		return nil, fmt.Errorf("max sessions per chain reached")
	}

	// Get the key
	key, ok := vm.keys[keyID]
	if !ok {
		// Use active key if keyID is empty
		if keyID == "" && vm.activeKeyID != "" {
			key = vm.keys[vm.activeKeyID]
			keyID = vm.activeKeyID
		} else {
			return nil, ErrKeyNotFound
		}
	}

	if key.Config == nil {
		return nil, ErrNotInitialized
	}

	// Create signing session
	sessionID := ids.GenerateTestID().String()
	session := &SigningSession{
		SessionID:       sessionID,
		KeyID:           keyID,
		RequestingChain: requestingChain,
		MessageHash:     messageHash,
		MessageType:     messageType,
		Status:          "pending",
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(vm.config.SessionTimeout),
	}

	vm.signingSessions[sessionID] = session
	vm.sessionsByChain[requestingChain] = append(vm.sessionsByChain[requestingChain], sessionID)

	// Start signing in background
	go vm.runSigning(session, key)

	vm.log.Info("started signing session",
		log.String("sessionID", sessionID),
		log.String("keyID", keyID),
		log.String("requestingChain", requestingChain),
		log.String("messageHash", hex.EncodeToString(messageHash)),
	)

	return session, nil
}

func (vm *VM) runSigning(session *SigningSession, key *ManagedKey) {
	vm.mu.Lock()
	session.Status = "signing"
	vm.mu.Unlock()

	startTime := time.Now()

	// Get the protocol handler for this key type
	handler, err := vm.protocolRegistry.Get(Protocol(key.KeyType))
	if err != nil {
		// Fall back to LSS
		handler, err = vm.protocolRegistry.Get(ProtocolLSS)
		if err != nil {
			vm.mu.Lock()
			session.Status = "failed"
			session.Error = err.Error()
			vm.mu.Unlock()
			return
		}
	}

	// Create a KeyShare from the managed key for signing
	var share KeyShare
	if key.Config != nil {
		share = &lssKeyShare{
			config:  key.Config,
			pubKey:  key.PublicKey,
			partyID: vm.partyID,
			thresh:  key.Threshold,
			total:   key.TotalParties,
			gen:     key.Generation,
		}
	} else {
		vm.mu.Lock()
		session.Status = "failed"
		session.Error = "no key share available for signing"
		vm.mu.Unlock()
		return
	}

	// Create context with timeout based on session expiration
	// Use SessionTimeout from config for signing operations
	ctx, cancel := context.WithTimeout(context.Background(), vm.config.SessionTimeout)
	defer cancel()

	sig, err := handler.Sign(ctx, share, session.MessageHash, key.PartyIDs)

	vm.mu.Lock()
	defer vm.mu.Unlock()

	signingTime := time.Since(startTime)

	if err != nil {
		session.Status = "failed"
		session.Error = err.Error()
		vm.log.Error("signing failed",
			log.String("sessionID", session.SessionID),
			log.String("error", err.Error()),
		)
		return
	}

	// Convert signature to components
	session.Signature = &ecdsaSignature{
		R: sig.R().Bytes(),
		S: sig.S().Bytes(),
		V: sig.V(),
	}
	session.SignerParties = key.PartyIDs
	session.Status = "completed"
	session.CompletedAt = time.Now()

	// Update key usage
	key.LastUsedAt = time.Now()
	key.SignCount++

	// Update quota
	vm.dailySigningCount[session.RequestingChain]++

	// Update stats
	vm.stats.mu.Lock()
	vm.stats.TotalSignatures++
	vm.stats.SignaturesByChain[session.RequestingChain]++
	// Update average signing time
	if vm.stats.AverageSigningTime == 0 {
		vm.stats.AverageSigningTime = signingTime
	} else {
		vm.stats.AverageSigningTime = (vm.stats.AverageSigningTime + signingTime) / 2
	}
	vm.stats.mu.Unlock()

	vm.log.Info("signing completed",
		log.String("sessionID", session.SessionID),
		log.Duration("duration", signingTime),
		log.Int("signers", len(key.PartyIDs)),
	)
}

// GetSignature retrieves a completed signature
func (vm *VM) GetSignature(sessionID string) (*SigningSession, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	session, ok := vm.signingSessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if session.Status == "signing" && time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// GetPublicKey returns the public key for a key ID
func (vm *VM) GetPublicKey(keyID string) ([]byte, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if keyID == "" {
		keyID = vm.activeKeyID
	}

	key, ok := vm.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return key.PublicKey, nil
}

// GetAddress returns the Ethereum-style address for a key
func (vm *VM) GetAddress(keyID string) ([]byte, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if keyID == "" {
		keyID = vm.activeKeyID
	}

	key, ok := vm.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return key.Address, nil
}

// ReshareKey triggers key resharing (for adding/removing parties)
func (vm *VM) ReshareKey(keyID string, newPartyIDs []party.ID, requestedBy string) (*KeygenSession, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Check if requestor is authorized
	perms, ok := vm.config.AuthorizedChains[requestedBy]
	if !ok || !perms.CanReshare {
		return nil, ErrUnauthorizedChain
	}

	key, ok := vm.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	if len(newPartyIDs) < vm.config.Threshold+1 {
		return nil, ErrInsufficientParties
	}

	// Create reshare session
	sessionID := ids.GenerateTestID().String()
	session := &KeygenSession{
		SessionID:    sessionID,
		KeyID:        keyID,
		KeyType:      key.KeyType,
		Threshold:    vm.config.Threshold,
		TotalParties: len(newPartyIDs),
		PartyIDs:     newPartyIDs,
		Status:       "pending",
		RequestedBy:  requestedBy,
		StartedAt:    time.Now(),
	}

	vm.keygenSessions[sessionID] = session

	// Start resharing in background
	go vm.runReshare(session, key)

	vm.log.Info("started reshare session",
		log.String("sessionID", sessionID),
		log.String("keyID", keyID),
		log.Int("newParties", len(newPartyIDs)),
	)

	return session, nil
}

func (vm *VM) runReshare(session *KeygenSession, existingKey *ManagedKey) {
	vm.mu.Lock()
	session.Status = "running"
	vm.mu.Unlock()

	ctx := context.Background()

	// Get the protocol handler
	handler, err := vm.protocolRegistry.Get(Protocol(existingKey.KeyType))
	if err != nil {
		handler, err = vm.protocolRegistry.Get(ProtocolLSS)
		if err != nil {
			vm.mu.Lock()
			session.Status = "failed"
			session.Error = err.Error()
			vm.mu.Unlock()
			return
		}
	}

	// Create KeyShare from existing key
	var share KeyShare
	if existingKey.Config != nil {
		share = &lssKeyShare{
			config:  existingKey.Config,
			pubKey:  existingKey.PublicKey,
			partyID: vm.partyID,
			thresh:  existingKey.Threshold,
			total:   existingKey.TotalParties,
			gen:     existingKey.Generation,
		}
	} else {
		vm.mu.Lock()
		session.Status = "failed"
		session.Error = "no key share available for reshare"
		vm.mu.Unlock()
		return
	}

	// Run reshare protocol
	newShare, err := handler.Reshare(ctx, share, session.PartyIDs, vm.config.Threshold)

	vm.mu.Lock()
	defer vm.mu.Unlock()

	if err != nil {
		session.Status = "failed"
		session.Error = err.Error()
		vm.log.Error("reshare failed",
			log.String("sessionID", session.SessionID),
			log.String("error", err.Error()),
		)
		return
	}

	// Update key with new share
	if lssShare, ok := newShare.(*lssKeyShare); ok && lssShare.config != nil {
		existingKey.Config = lssShare.config
		existingKey.Generation = lssShare.Generation()
		if existingKey.KeyID == vm.activeKeyID {
			vm.lssConfig = lssShare.config
		}
	}
	existingKey.PartyIDs = session.PartyIDs
	existingKey.TotalParties = len(session.PartyIDs)
	existingKey.LastUsedAt = time.Now()

	// Update active partyIDs if this is the active key
	if existingKey.KeyID == vm.activeKeyID {
		vm.partyIDs = session.PartyIDs
	}

	session.Status = "completed"
	session.CompletedAt = time.Now()

	// Persist updated key
	if err := vm.persistKey(existingKey); err != nil {
		vm.log.Error("failed to persist reshared key",
			log.String("keyID", session.KeyID),
			log.String("error", err.Error()),
		)
	}

	vm.log.Info("reshare completed",
		log.String("sessionID", session.SessionID),
		log.String("keyID", session.KeyID),
		log.Uint64("newGeneration", existingKey.Generation),
	)
}

func (vm *VM) checkQuotaReset() {
	if time.Now().After(vm.quotaResetTime) {
		vm.dailySigningCount = make(map[string]uint64)
		vm.quotaResetTime = time.Now().Add(24 * time.Hour)
	}
}

// Cleanup expired sessions
func (vm *VM) cleanupExpiredSessions() {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	now := time.Now()
	for sessionID, session := range vm.signingSessions {
		if session.Status == "signing" && now.After(session.ExpiresAt) {
			session.Status = "failed"
			session.Error = "session expired"
		}
		// Keep completed/failed sessions for 1 hour for retrieval
		if (session.Status == "completed" || session.Status == "failed") &&
			now.Sub(session.CompletedAt) > time.Hour {
			delete(vm.signingSessions, sessionID)
		}
	}
}

// BuildBlock implements the chain.ChainVM interface
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Get parent block
	parentID := vm.preferred
	if parentID == ids.Empty {
		parentID = vm.lastAcceptedID
	}

	parent, err := vm.getBlock(parentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get parent block: %w", err)
	}

	// Collect operations from completed sessions
	var operations []*Operation
	for _, session := range vm.keygenSessions {
		if session.Status == "completed" {
			operations = append(operations, &Operation{
				Type:      OpTypeKeygen,
				SessionID: session.SessionID,
				KeyID:     session.KeyID,
				Timestamp: session.CompletedAt.Unix(),
			})
		}
	}

	for _, session := range vm.signingSessions {
		if session.Status == "completed" {
			operations = append(operations, &Operation{
				Type:            OpTypeSign,
				SessionID:       session.SessionID,
				KeyID:           session.KeyID,
				RequestingChain: session.RequestingChain,
				Timestamp:       session.CompletedAt.Unix(),
			})
		}
	}

	if len(operations) == 0 {
		return nil, errors.New("no operations to include")
	}

	// Create new block
	blk := &Block{
		ParentID_:      parentID,
		BlockHeight:    parent.Height() + 1,
		BlockTimestamp: time.Now().Unix(),
		Operations:     operations,
		vm:             vm,
	}

	blk.ID_ = blk.computeID()
	vm.pendingBlocks[blk.ID()] = blk
	vm.heightIndex[blk.BlockHeight] = blk.ID()

	vm.log.Info("built threshold block",
		log.Stringer("blockID", blk.ID()),
		log.Int("numOperations", len(operations)),
	)

	return blk, nil
}

// GetBlock implements the chain.ChainVM interface
func (vm *VM) GetBlock(ctx context.Context, id ids.ID) (chain.Block, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	// Check pending blocks (nil-safe for early calls before initialization)
	if vm.pendingBlocks != nil {
		if blk, exists := vm.pendingBlocks[id]; exists {
			return blk, nil
		}
	}

	return vm.getBlock(id)
}

// ParseBlock implements the chain.ChainVM interface
func (vm *VM) ParseBlock(ctx context.Context, bytes []byte) (chain.Block, error) {
	blk := &Block{vm: vm}
	if _, err := Codec.Unmarshal(bytes, blk); err != nil {
		return nil, err
	}
	blk.ID_ = blk.computeID()
	return blk, nil
}

// SetPreference implements the chain.ChainVM interface
func (vm *VM) SetPreference(ctx context.Context, id ids.ID) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.preferred = id
	return nil
}

// LastAccepted implements the chain.ChainVM interface
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.lastAcceptedID, nil
}

// CreateHandlers implements the common.VM interface
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	handlers := map[string]http.Handler{
		"/rpc":    vm.createRPCHandler(),
		"/health": http.HandlerFunc(vm.handleHealth),
	}
	return handlers, nil
}

// HealthCheck implements the common.VM interface
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	return chain.HealthResult{
		Healthy: vm.mpcReady,
		Details: map[string]string{
			"status":         "healthy",
			"mpcReady":       fmt.Sprintf("%t", vm.mpcReady),
			"activeKey":      vm.activeKeyID,
			"activeSessions": fmt.Sprintf("%d", len(vm.signingSessions)),
			"totalKeys":      fmt.Sprintf("%d", len(vm.keys)),
		},
	}, nil
}

// Shutdown implements the common.VM interface
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Persist all keys before shutdown
	for _, key := range vm.keys {
		if err := vm.persistKey(key); err != nil {
			vm.log.Error("failed to persist key on shutdown",
				log.String("keyID", key.KeyID),
				log.String("error", err.Error()),
			)
		}
	}

	return nil
}

// CreateStaticHandlers implements the common.VM interface
func (vm *VM) CreateStaticHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return nil, nil
}

// Connected implements the common.VM interface
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *chain.VersionInfo) error {
	return nil
}

// Disconnected implements the common.VM interface
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return nil
}

// Request implements the common.VM interface
func (vm *VM) Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, request []byte) error {
	// Handle MPC protocol messages
	return nil
}

// Response implements the common.VM interface
func (vm *VM) Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	return nil
}

// RequestFailed implements the common.VM interface
func (vm *VM) RequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, appErr *warp.Error) error {
	return nil
}

// Gossip implements the common.VM interface
func (vm *VM) Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	return nil
}

// Version implements the common.VM interface
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version.String(), nil
}

// CrossChainRequest implements the common.VM interface
// This is how other chains request MPC services
func (vm *VM) CrossChainRequest(ctx context.Context, chainID ids.ID, requestID uint32, deadline time.Time, request []byte) error {
	// Parse cross-chain MPC request
	var req CrossChainMPCRequest
	if _, err := Codec.Unmarshal(request, &req); err != nil {
		return err
	}

	switch req.Type {
	case "sign":
		session, err := vm.RequestSignature(
			req.RequestingChain,
			req.KeyID,
			req.MessageHash,
			req.MessageType,
		)
		if err != nil {
			return err
		}
		// Store request ID for response routing
		vm.mu.Lock()
		if session.SessionID != "" {
			// Map Lux requestID to our session
		}
		vm.mu.Unlock()

	case "keygen":
		_, err := vm.StartKeygen(req.KeyID, req.KeyType, req.RequestingChain)
		if err != nil {
			return err
		}

	case "reshare":
		_, err := vm.ReshareKey(req.KeyID, nil, req.RequestingChain)
		if err != nil {
			return err
		}
	}

	return nil
}

// CrossChainResponse implements the common.VM interface
func (vm *VM) CrossChainResponse(ctx context.Context, chainID ids.ID, requestID uint32, response []byte) error {
	return nil
}

// CrossChainRequestFailed implements the common.VM interface
func (vm *VM) CrossChainRequestFailed(ctx context.Context, chainID ids.ID, requestID uint32, appErr *warp.Error) error {
	return nil
}

// GetBlockIDAtHeight implements the chain.HeightIndexedChainVM interface
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	id, ok := vm.heightIndex[height]
	if !ok {
		return ids.Empty, errors.New("block not found at height")
	}
	return id, nil
}

// SetState implements the common.VM interface
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	return nil
}

// NewHTTPHandler returns HTTP handlers for the VM
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	return vm.createRPCHandler(), nil
}

// WaitForEvent blocks until an event occurs
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	// Block until context is cancelled - this VM doesn't proactively build blocks
	// CRITICAL: Must block here to avoid notification flood loop in chains/manager.go
	<-ctx.Done()
	return vmcore.Message{}, ctx.Err()
}

// Helper methods

func (vm *VM) putBlock(blk *Block) error {
	bytes, err := Codec.Marshal(codecVersion, blk)
	if err != nil {
		return err
	}
	id := blk.ID()
	return vm.db.Put(id[:], bytes)
}

func (vm *VM) getBlock(id ids.ID) (*Block, error) {
	bytes, err := vm.db.Get(id[:])
	if err != nil {
		return nil, err
	}

	blk := &Block{vm: vm}
	if _, err := Codec.Unmarshal(bytes, blk); err != nil {
		return nil, err
	}

	blk.ID_ = id
	return blk, nil
}

func (vm *VM) persistKey(key *ManagedKey) error {
	bytes, err := Codec.Marshal(codecVersion, key)
	if err != nil {
		return err
	}
	keyPrefix := []byte("key:")
	dbKey := append(keyPrefix, []byte(key.KeyID)...)
	return vm.db.Put(dbKey, bytes)
}

func (vm *VM) loadKeys() error {
	keyPrefix := []byte("key:")
	iter := vm.db.NewIteratorWithPrefix(keyPrefix)
	defer iter.Release()

	for iter.Next() {
		key := &ManagedKey{}
		if _, err := Codec.Unmarshal(iter.Value(), key); err != nil {
			continue
		}
		vm.keys[key.KeyID] = key
		if key.Status == "active" && (vm.activeKeyID == "" || key.CreatedAt.After(vm.keys[vm.activeKeyID].CreatedAt)) {
			vm.activeKeyID = key.KeyID
		}
	}

	return iter.Error()
}

func (vm *VM) handleHealth(w http.ResponseWriter, r *http.Request) {
	_, _ = vm.HealthCheck(nil) // Call for side effects; we use mpcReady directly
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// JSON encode health
	fmt.Fprintf(w, `{"status":"healthy","mpcReady":%t}`, vm.mpcReady)
}

// CrossChainMPCRequest is the request format for cross-chain MPC operations
type CrossChainMPCRequest struct {
	Type            string `json:"type"` // sign, keygen, reshare
	RequestingChain string `json:"requestingChain"`
	KeyID           string `json:"keyId"`
	KeyType         string `json:"keyType,omitempty"`
	MessageHash     []byte `json:"messageHash,omitempty"`
	MessageType     string `json:"messageType,omitempty"`
}

// Genesis represents the genesis state
type Genesis struct {
	Timestamp int64 `json:"timestamp"`
}

// Helper functions

func publicKeyToAddress(pubKey []byte) []byte {
	// Decompress public key if needed
	x, y := secp256k1.DecompressPubkey(pubKey)
	if x == nil || y == nil {
		// Already uncompressed or invalid
		if len(pubKey) >= 64 {
			// Hash uncompressed key (minus prefix if 65 bytes)
			toHash := pubKey
			if len(pubKey) == 65 {
				toHash = pubKey[1:]
			}
			hash := sha256.Sum256(toHash)
			return hash[12:] // Last 20 bytes
		}
		return nil
	}

	// Build uncompressed public key (64 bytes, no prefix)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	uncompressed := make([]byte, 64)
	copy(uncompressed[32-len(xBytes):32], xBytes)
	copy(uncompressed[64-len(yBytes):64], yBytes)

	// Hash uncompressed public key (should use Keccak256 for Ethereum compatibility)
	hash := sha256.Sum256(uncompressed)
	return hash[12:] // Last 20 bytes
}

// computeRecoveryID is no longer needed - we use sig.V() from the Signature interface

// =============================================================================
// Session-Ready: Attestation Domains
// =============================================================================
// QuantumVM threshold attests to:
// - Oracle observation commitments (oracle/write, oracle/read)
// - Session completion (session/complete)
// - Epoch beacon signatures (epoch/beacon)
// Domain separators prevent cross-protocol replay attacks.

// AttestationDomain defines the domain for a threshold attestation
type AttestationDomain string

const (
	// DomainOracleWrite attests to external write request commitments
	DomainOracleWrite AttestationDomain = "oracle/write"
	// DomainOracleRead attests to external read request commitments
	DomainOracleRead AttestationDomain = "oracle/read"
	// DomainSessionComplete attests to session completion (output hash + oracle obs + receipts root)
	DomainSessionComplete AttestationDomain = "session/complete"
	// DomainEpochBeacon attests to epoch beacon signatures for randomness
	DomainEpochBeacon AttestationDomain = "epoch/beacon"
)

// domainSeparators maps domains to their cryptographic separators
var domainSeparators = map[AttestationDomain][]byte{
	DomainOracleWrite:     []byte("LUX:QuantumAttest:oracle/write:v1"),
	DomainOracleRead:      []byte("LUX:QuantumAttest:oracle/read:v1"),
	DomainSessionComplete: []byte("LUX:QuantumAttest:session/complete:v1"),
	DomainEpochBeacon:     []byte("LUX:QuantumAttest:epoch/beacon:v1"),
}

// QuantumAttestation represents a threshold attestation over a commitment
type QuantumAttestation struct {
	// Domain specifies what is being attested (oracle/write, session/complete, etc.)
	Domain AttestationDomain `json:"domain"`

	// AttestationID is a unique identifier for this attestation
	AttestationID [32]byte `json:"attestationId"`

	// SubjectID is the ID of what is being attested (request_id, session_id, epoch number)
	SubjectID [32]byte `json:"subjectId"`

	// CommitmentRoot is the Merkle root being attested
	CommitmentRoot [32]byte `json:"commitmentRoot"`

	// Epoch in which this attestation was created
	Epoch uint64 `json:"epoch"`

	// Timestamp when attestation was created
	Timestamp time.Time `json:"timestamp"`

	// KeyID of the threshold key used for signing
	KeyID string `json:"keyId"`

	// Threshold used for this attestation
	Threshold int `json:"threshold"`

	// SignerCount is the number of parties that signed
	SignerCount int `json:"signerCount"`

	// Signature is the threshold signature over the attestation payload
	Signature *ecdsaSignature `json:"signature"`

	// SigningParties are the party IDs that participated
	SigningParties []party.ID `json:"signingParties"`
}

// OracleCommitAttestation contains details for oracle commit attestations
type OracleCommitAttestation struct {
	RequestID   [32]byte `json:"requestId"`
	Kind        uint8    `json:"kind"` // 0 = write, 1 = read
	Root        [32]byte `json:"root"`
	RecordCount uint32   `json:"recordCount"`
}

// SessionCompleteAttestation contains details for session completion attestations
type SessionCompleteAttestation struct {
	SessionID    [32]byte `json:"sessionId"`
	OutputHash   [32]byte `json:"outputHash"`
	OracleRoot   [32]byte `json:"oracleRoot"`
	ReceiptsRoot [32]byte `json:"receiptsRoot"`
	StepCount    uint32   `json:"stepCount"`
}

// EpochBeaconAttestation contains details for epoch beacon attestations
type EpochBeaconAttestation struct {
	Epoch       uint64   `json:"epoch"`
	Randomness  [32]byte `json:"randomness"`
	PreviousRef [32]byte `json:"previousRef"`
}

// ComputeAttestationPayload computes the payload to be signed for an attestation
func ComputeAttestationPayload(domain AttestationDomain, subjectID, commitmentRoot [32]byte, epoch uint64) [32]byte {
	h := sha256.New()

	// Domain separator
	separator, ok := domainSeparators[domain]
	if !ok {
		separator = []byte("LUX:QuantumAttest:unknown:v1")
	}
	h.Write(separator)

	// Subject ID (request_id, session_id, etc.)
	h.Write(subjectID[:])

	// Commitment root being attested
	h.Write(commitmentRoot[:])

	// Epoch for temporal binding
	epochBytes := make([]byte, 8)
	epochBytes[0] = byte(epoch >> 56)
	epochBytes[1] = byte(epoch >> 48)
	epochBytes[2] = byte(epoch >> 40)
	epochBytes[3] = byte(epoch >> 32)
	epochBytes[4] = byte(epoch >> 24)
	epochBytes[5] = byte(epoch >> 16)
	epochBytes[6] = byte(epoch >> 8)
	epochBytes[7] = byte(epoch)
	h.Write(epochBytes)

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// AttestOracleCommit creates a threshold attestation for an oracle commitment
func (vm *VM) AttestOracleCommit(
	requestingChain string,
	requestID [32]byte,
	kind uint8, // 0 = write, 1 = read
	commitRoot [32]byte,
	epoch uint64,
) (*QuantumAttestation, error) {
	// Determine domain based on kind
	var domain AttestationDomain
	if kind == 0 {
		domain = DomainOracleWrite
	} else {
		domain = DomainOracleRead
	}

	// Compute the payload to sign
	payload := ComputeAttestationPayload(domain, requestID, commitRoot, epoch)

	// Request threshold signature
	session, err := vm.RequestSignature(requestingChain, "", payload[:], "raw")
	if err != nil {
		return nil, fmt.Errorf("failed to request attestation signature: %w", err)
	}

	// Wait for signature completion (with timeout)
	ctx, cancel := context.WithTimeout(context.Background(), vm.config.SessionTimeout)
	defer cancel()

	var completedSession *SigningSession
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("attestation signing timed out")
		case <-time.After(100 * time.Millisecond):
			s, err := vm.GetSignature(session.SessionID)
			if err != nil {
				continue
			}
			if s.Status == "completed" {
				completedSession = s
				goto done
			}
			if s.Status == "failed" {
				return nil, fmt.Errorf("attestation signing failed: %s", s.Error)
			}
		}
	}
done:

	// Generate attestation ID
	attestID := sha256.Sum256(append(payload[:], []byte(completedSession.SessionID)...))

	attestation := &QuantumAttestation{
		Domain:         domain,
		AttestationID:  attestID,
		SubjectID:      requestID,
		CommitmentRoot: commitRoot,
		Epoch:          epoch,
		Timestamp:      time.Now(),
		KeyID:          completedSession.KeyID,
		Threshold:      vm.config.Threshold,
		SignerCount:    len(completedSession.SignerParties),
		Signature:      completedSession.Signature,
		SigningParties: completedSession.SignerParties,
	}

	vm.log.Info("created oracle commit attestation",
		log.String("domain", string(domain)),
		log.String("requestID", hex.EncodeToString(requestID[:])),
		log.Uint64("epoch", epoch),
	)

	return attestation, nil
}

// AttestSessionComplete creates a threshold attestation for session completion
func (vm *VM) AttestSessionComplete(
	requestingChain string,
	sessionID [32]byte,
	outputHash [32]byte,
	oracleRoot [32]byte,
	receiptsRoot [32]byte,
	epoch uint64,
) (*QuantumAttestation, error) {
	// Compute combined commitment root
	h := sha256.New()
	h.Write(outputHash[:])
	h.Write(oracleRoot[:])
	h.Write(receiptsRoot[:])
	var commitRoot [32]byte
	copy(commitRoot[:], h.Sum(nil))

	// Compute the payload to sign
	payload := ComputeAttestationPayload(DomainSessionComplete, sessionID, commitRoot, epoch)

	// Request threshold signature
	session, err := vm.RequestSignature(requestingChain, "", payload[:], "raw")
	if err != nil {
		return nil, fmt.Errorf("failed to request session attestation: %w", err)
	}

	// Wait for signature completion
	ctx, cancel := context.WithTimeout(context.Background(), vm.config.SessionTimeout)
	defer cancel()

	var completedSession *SigningSession
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("session attestation signing timed out")
		case <-time.After(100 * time.Millisecond):
			s, err := vm.GetSignature(session.SessionID)
			if err != nil {
				continue
			}
			if s.Status == "completed" {
				completedSession = s
				goto done
			}
			if s.Status == "failed" {
				return nil, fmt.Errorf("session attestation signing failed: %s", s.Error)
			}
		}
	}
done:

	attestID := sha256.Sum256(append(payload[:], []byte(completedSession.SessionID)...))

	attestation := &QuantumAttestation{
		Domain:         DomainSessionComplete,
		AttestationID:  attestID,
		SubjectID:      sessionID,
		CommitmentRoot: commitRoot,
		Epoch:          epoch,
		Timestamp:      time.Now(),
		KeyID:          completedSession.KeyID,
		Threshold:      vm.config.Threshold,
		SignerCount:    len(completedSession.SignerParties),
		Signature:      completedSession.Signature,
		SigningParties: completedSession.SignerParties,
	}

	vm.log.Info("created session complete attestation",
		log.String("sessionID", hex.EncodeToString(sessionID[:])),
		log.Uint64("epoch", epoch),
	)

	return attestation, nil
}

// AttestEpochBeacon creates a threshold attestation for epoch beacon randomness
func (vm *VM) AttestEpochBeacon(
	requestingChain string,
	epoch uint64,
	previousRef [32]byte,
) (*QuantumAttestation, error) {
	// Compute epoch subject ID
	var subjectID [32]byte
	epochBytes := make([]byte, 8)
	epochBytes[0] = byte(epoch >> 56)
	epochBytes[1] = byte(epoch >> 48)
	epochBytes[2] = byte(epoch >> 40)
	epochBytes[3] = byte(epoch >> 32)
	epochBytes[4] = byte(epoch >> 24)
	epochBytes[5] = byte(epoch >> 16)
	epochBytes[6] = byte(epoch >> 8)
	epochBytes[7] = byte(epoch)
	h := sha256.New()
	h.Write([]byte("LUX:EpochBeacon:"))
	h.Write(epochBytes)
	copy(subjectID[:], h.Sum(nil))

	// The commitment root for beacon is hash of previous ref (chain the beacons)
	var commitRoot [32]byte
	h2 := sha256.New()
	h2.Write(previousRef[:])
	h2.Write(epochBytes)
	copy(commitRoot[:], h2.Sum(nil))

	// Compute the payload to sign
	payload := ComputeAttestationPayload(DomainEpochBeacon, subjectID, commitRoot, epoch)

	// Request threshold signature
	session, err := vm.RequestSignature(requestingChain, "", payload[:], "raw")
	if err != nil {
		return nil, fmt.Errorf("failed to request beacon attestation: %w", err)
	}

	// Wait for signature completion
	ctx, cancel := context.WithTimeout(context.Background(), vm.config.SessionTimeout)
	defer cancel()

	var completedSession *SigningSession
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("beacon attestation signing timed out")
		case <-time.After(100 * time.Millisecond):
			s, err := vm.GetSignature(session.SessionID)
			if err != nil {
				continue
			}
			if s.Status == "completed" {
				completedSession = s
				goto done
			}
			if s.Status == "failed" {
				return nil, fmt.Errorf("beacon attestation signing failed: %s", s.Error)
			}
		}
	}
done:

	attestID := sha256.Sum256(append(payload[:], []byte(completedSession.SessionID)...))

	attestation := &QuantumAttestation{
		Domain:         DomainEpochBeacon,
		AttestationID:  attestID,
		SubjectID:      subjectID,
		CommitmentRoot: commitRoot,
		Epoch:          epoch,
		Timestamp:      time.Now(),
		KeyID:          completedSession.KeyID,
		Threshold:      vm.config.Threshold,
		SignerCount:    len(completedSession.SignerParties),
		Signature:      completedSession.Signature,
		SigningParties: completedSession.SignerParties,
	}

	vm.log.Info("created epoch beacon attestation",
		log.Uint64("epoch", epoch),
	)

	return attestation, nil
}

// VerifyAttestation verifies a QuantumAttestation is valid
func (vm *VM) VerifyAttestation(attestation *QuantumAttestation) error {
	if attestation == nil {
		return errors.New("nil attestation")
	}

	// Verify domain is valid
	if _, ok := domainSeparators[attestation.Domain]; !ok {
		return fmt.Errorf("invalid attestation domain: %s", attestation.Domain)
	}

	// Verify threshold requirements
	if attestation.SignerCount < attestation.Threshold+1 {
		return fmt.Errorf("insufficient signers: %d < %d required", attestation.SignerCount, attestation.Threshold+1)
	}

	// Recompute payload
	payload := ComputeAttestationPayload(
		attestation.Domain,
		attestation.SubjectID,
		attestation.CommitmentRoot,
		attestation.Epoch,
	)

	// Get the public key for verification
	pubKey, err := vm.GetPublicKey(attestation.KeyID)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// Verify signature
	if attestation.Signature == nil {
		return errors.New("missing signature")
	}

	// Reconstruct signature bytes for verification
	sigBytes := make([]byte, 65)
	copy(sigBytes[0:32], attestation.Signature.R)
	copy(sigBytes[32:64], attestation.Signature.S)
	sigBytes[64] = attestation.Signature.V

	// Use secp256k1 to verify
	recoveredPub, err := secp256k1.RecoverPubkey(payload[:], sigBytes)
	if err != nil {
		return fmt.Errorf("signature recovery failed: %w", err)
	}

	// Compare recovered public key with stored key
	// The threshold signature should recover to the group public key
	if !bytesEqual(recoveredPub, pubKey) && !bytesEqualCompressed(recoveredPub, pubKey) {
		return ErrInvalidSignature
	}

	return nil
}

// bytesEqual compares two byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// bytesEqualCompressed handles comparing compressed vs uncompressed pubkeys
func bytesEqualCompressed(uncompressed, compressed []byte) bool {
	if len(compressed) != 33 || len(uncompressed) < 64 {
		return false
	}
	// Compress the uncompressed key and compare
	x, y := secp256k1.DecompressPubkey(compressed)
	if x == nil || y == nil {
		return false
	}
	// Build uncompressed from compressed
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	rebuilt := make([]byte, 65)
	rebuilt[0] = 0x04
	copy(rebuilt[33-len(xBytes):33], xBytes)
	copy(rebuilt[65-len(yBytes):65], yBytes)
	// Compare against provided uncompressed (might be 64 or 65 bytes)
	if len(uncompressed) == 64 {
		return bytesEqual(rebuilt[1:], uncompressed)
	}
	return bytesEqual(rebuilt, uncompressed)
}

// DetectEquivocation checks if two attestations represent equivocation (slashable)
// Two attestations are equivocating if they have the same domain, subject, and epoch
// but different commitment roots
func DetectEquivocation(a, b *QuantumAttestation) bool {
	if a == nil || b == nil {
		return false
	}

	// Must be same domain
	if a.Domain != b.Domain {
		return false
	}

	// Must be same subject
	if a.SubjectID != b.SubjectID {
		return false
	}

	// Must be same epoch
	if a.Epoch != b.Epoch {
		return false
	}

	// Equivocation if commitment roots differ
	return a.CommitmentRoot != b.CommitmentRoot
}
