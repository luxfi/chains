// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package kmsvm implements the KMS Virtual Machine (K-Chain) for distributed
// key management using ML-KEM post-quantum cryptography and threshold sharing.
package keyvm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/rpc/v2"
	grjson "github.com/gorilla/rpc/v2/json"
	"golang.org/x/crypto/hkdf"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/cache"
	"github.com/luxfi/chains/keyvm/config"
	"github.com/luxfi/runtime"
	"github.com/luxfi/timer/mockable"
	"github.com/luxfi/vm/chain"
	vmcore "github.com/luxfi/vm"
)

const (
	// Version of the K-Chain VM
	Version = "1.0.0"

	// VMName is the human-readable name of K-Chain VM
	VMName = "keyvm"

	// MaxParallelOperations is the maximum number of concurrent crypto operations
	MaxParallelOperations = 100

	// SharePrefix is the database prefix for key shares
	SharePrefix = "share:"

	// KeyPrefix is the database prefix for key metadata
	KeyPrefix = "key:"
)

var (
	// Verify KeyVM implements chain.ChainVM interface
	_ chain.ChainVM = (*VM)(nil)

	errVMShutdown         = errors.New("VM is shutting down")
	errKeyNotFound        = errors.New("key not found")
	errKeyExists          = errors.New("key already exists")
	errInvalidThreshold   = errors.New("invalid threshold")
	errInsufficientShares = errors.New("insufficient shares for reconstruction")
	errInvalidSignature   = errors.New("invalid signature")
	errMLKEMNotEnabled    = errors.New("ML-KEM not enabled")
	errMLDSANotEnabled    = errors.New("ML-DSA not enabled")
	errValidatorNotFound  = errors.New("validator not found")
)

// secureZeroBytes overwrites a byte slice with zeros to clear sensitive data from memory.
// This helps prevent key material from remaining in memory after use.
func secureZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// KeyMetadata stores information about a distributed key.
type KeyMetadata struct {
	ID          ids.ID            `json:"id"`
	Name        string            `json:"name"`
	Algorithm   string            `json:"algorithm"`
	KeyType     string            `json:"keyType"`
	PublicKey   []byte            `json:"publicKey"`
	Threshold   int               `json:"threshold"`
	TotalShares int               `json:"totalShares"`
	Validators  []string          `json:"validators"`
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
	Status      string            `json:"status"`
	Tags        []string          `json:"tags"`
	Metadata    map[string]string `json:"metadata"`
}

// KeyShare represents a share of a distributed key.
type KeyShare struct {
	KeyID       ids.ID `json:"keyId"`
	ShareIndex  int    `json:"shareIndex"`
	ShareData   []byte `json:"shareData"` // Encrypted share
	ValidatorID string `json:"validatorId"`
	Timestamp   int64  `json:"timestamp"`
}

// VM implements the K-Chain Virtual Machine.
type VM struct {
	config.Config

	// Core components
	rt           *runtime.Runtime
	cancel       context.CancelFunc
	log          log.Logger
	db           database.Database
	versiondb    *versiondb.Database
	blockchainID ids.ID
	networkID    uint32
	toEngine     chan<- vmcore.Message

	// Key management
	keys       map[ids.ID]*KeyMetadata
	keysByName map[string]ids.ID
	shares     map[ids.ID][]*KeyShare
	keysLock   sync.RWMutex

	// ML-KEM keys cache
	mlkemCache    *cache.LRU[ids.ID, *mlkem.PrivateKey]
	mlkemPubCache *cache.LRU[ids.ID, *mlkem.PublicKey]

	// Transaction pool
	pendingTxs []*Transaction
	txLock     sync.Mutex

	// State management
	state         database.Database
	lastAccepted  ids.ID
	lastAccepted_ *Block
	pendingBlocks map[ids.ID]*Block
	height        uint64

	// HTTP service
	rpcServer *rpc.Server

	// Lifecycle
	shuttingDown bool
	shutdownLock sync.RWMutex

	// Clock
	clock mockable.Clock
}

// Genesis represents the genesis state
type Genesis struct {
	Version   int    `json:"version"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

// Initialize initializes the K-Chain VM with the unified Init struct.
func (vm *VM) Initialize(ctx context.Context, init vmcore.Init) error {
	_, vm.cancel = context.WithCancel(ctx)
	vm.rt = init.Runtime
	vm.db = init.DB
	vm.toEngine = init.ToEngine
	vm.versiondb = versiondb.New(init.DB)
	vm.state = vm.versiondb

	if logger, ok := vm.rt.Log.(log.Logger); ok {
		vm.log = logger
	} else {
		return errors.New("invalid logger type")
	}

	// Parse configuration
	cfg, err := config.ParseConfig(init.Config)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}
	vm.Config = cfg

	// Validate configuration
	if err := vm.Config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Initialize maps under lock to prevent races with early network messages
	vm.shutdownLock.Lock()
	vm.keys = make(map[ids.ID]*KeyMetadata)
	vm.keysByName = make(map[string]ids.ID)
	vm.shares = make(map[ids.ID][]*KeyShare)
	vm.pendingTxs = make([]*Transaction, 0)
	vm.pendingBlocks = make(map[ids.ID]*Block)
	vm.shutdownLock.Unlock()

	// Initialize caches
	vm.mlkemCache = cache.NewLRU[ids.ID, *mlkem.PrivateKey](vm.Config.ShareCacheSize)
	vm.mlkemPubCache = cache.NewLRU[ids.ID, *mlkem.PublicKey](vm.Config.ShareCacheSize)

	// Parse genesis (JSON format)
	genesis := &Genesis{}
	if len(init.Genesis) > 0 {
		if err := json.Unmarshal(init.Genesis, genesis); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}

	// Create genesis block
	genesisBlock := &Block{
		id:        ids.Empty,
		parentID:  ids.Empty,
		height:    0,
		timestamp: time.Unix(genesis.Timestamp, 0),
		vm:        vm,
	}
	genesisBlock.id = genesisBlock.computeID()
	vm.lastAccepted = genesisBlock.id
	vm.lastAccepted_ = genesisBlock

	// Load existing keys from database
	if err := vm.loadKeys(); err != nil {
		if !vm.log.IsZero() {
			vm.log.Warn("failed to load keys from database", log.String("error", err.Error()))
		}
	}

	// Initialize HTTP handlers
	if err := vm.initializeHTTPHandlers(); err != nil {
		return fmt.Errorf("failed to initialize HTTP handlers: %w", err)
	}

	if !vm.log.IsZero() {
		vm.log.Info("KMS VM initialized",
			log.String("version", Version),
			log.Bool("mlkemEnabled", vm.Config.MLKEMEnabled),
			log.Bool("mldsaEnabled", vm.Config.MLDSAEnabled),
			log.Int("threshold", vm.Config.DefaultThreshold),
			log.Int("totalShares", vm.Config.DefaultTotalShares),
		)
	}

	return nil
}

// CreateKey creates a new distributed key.
func (vm *VM) CreateKey(ctx context.Context, name, algorithm string, threshold, totalShares int) (*KeyMetadata, error) {
	vm.keysLock.Lock()
	defer vm.keysLock.Unlock()

	// Check if key already exists
	if _, exists := vm.keysByName[name]; exists {
		return nil, errKeyExists
	}

	// Validate threshold
	if threshold <= 0 || totalShares <= 0 || threshold > totalShares {
		return nil, errInvalidThreshold
	}

	// Generate key ID
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}
	keyID, _ := ids.ToID(idBytes)

	// Create key based on algorithm
	var pubKey []byte
	var keyType string

	switch algorithm {
	case "ml-kem-512", "ml-kem-768", "ml-kem-1024":
		if !vm.Config.MLKEMEnabled {
			return nil, errMLKEMNotEnabled
		}
		// Determine mode based on algorithm
		var mode mlkem.Mode
		switch algorithm {
		case "ml-kem-512":
			mode = mlkem.MLKEM512
		case "ml-kem-768":
			mode = mlkem.MLKEM768
		case "ml-kem-1024":
			mode = mlkem.MLKEM1024
		}
		// Generate ML-KEM key pair
		mlkemPubKey, privKey, err := mlkem.GenerateKey(mode)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ML-KEM key: %w", err)
		}
		pubKey = mlkemPubKey.Bytes()
		keyType = "encryption"

		// Cache the key
		vm.mlkemCache.Put(keyID, privKey)
		vm.mlkemPubCache.Put(keyID, mlkemPubKey)

	case "ml-dsa-44", "ml-dsa-65", "ml-dsa-87":
		if !vm.Config.MLDSAEnabled {
			return nil, errMLDSANotEnabled
		}
		// Determine mode based on algorithm
		var dsaMode mldsa.Mode
		switch algorithm {
		case "ml-dsa-44":
			dsaMode = mldsa.MLDSA44
		case "ml-dsa-65":
			dsaMode = mldsa.MLDSA65
		case "ml-dsa-87":
			dsaMode = mldsa.MLDSA87
		}
		// Generate ML-DSA key pair
		mldsaPrivKey, err := mldsa.GenerateKey(rand.Reader, dsaMode)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ML-DSA key: %w", err)
		}
		pubKey = mldsaPrivKey.PublicKey.Bytes()
		keyType = "signing"

	case "bls-threshold":
		keyType = "threshold-signing"
		// Generate BLS key pair
		blsSecretKey, err := bls.NewSecretKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate BLS key: %w", err)
		}
		blsPubKey := blsSecretKey.PublicKey()
		pubKey = bls.PublicKeyToCompressedBytes(blsPubKey)

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Create key metadata
	now := time.Now()
	meta := &KeyMetadata{
		ID:          keyID,
		Name:        name,
		Algorithm:   algorithm,
		KeyType:     keyType,
		PublicKey:   pubKey,
		Threshold:   threshold,
		TotalShares: totalShares,
		Validators:  vm.Config.Validators[:totalShares],
		CreatedAt:   now,
		UpdatedAt:   now,
		Status:      "active",
		Metadata:    make(map[string]string),
	}

	// Store key metadata
	vm.keys[keyID] = meta
	vm.keysByName[name] = keyID

	// Persist to database
	if err := vm.saveKeyMetadata(meta); err != nil {
		return nil, fmt.Errorf("failed to save key metadata: %w", err)
	}

	vm.log.Info("created new key",
		"keyID", keyID,
		"name", name,
		"algorithm", algorithm,
		"threshold", threshold,
		"totalShares", totalShares,
	)

	return meta, nil
}

// GetKey retrieves key metadata by ID.
func (vm *VM) GetKey(ctx context.Context, keyID ids.ID) (*KeyMetadata, error) {
	vm.keysLock.RLock()
	defer vm.keysLock.RUnlock()

	meta, exists := vm.keys[keyID]
	if !exists {
		return nil, errKeyNotFound
	}

	return meta, nil
}

// GetKeyByName retrieves key metadata by name.
func (vm *VM) GetKeyByName(ctx context.Context, name string) (*KeyMetadata, error) {
	vm.keysLock.RLock()
	defer vm.keysLock.RUnlock()

	keyID, exists := vm.keysByName[name]
	if !exists {
		return nil, errKeyNotFound
	}

	return vm.keys[keyID], nil
}

// ListKeys lists all keys.
func (vm *VM) ListKeys(ctx context.Context) ([]*KeyMetadata, error) {
	vm.keysLock.RLock()
	defer vm.keysLock.RUnlock()

	keys := make([]*KeyMetadata, 0, len(vm.keys))
	for _, meta := range vm.keys {
		keys = append(keys, meta)
	}

	return keys, nil
}

// DeleteKey deletes a key and its shares with secure zeroing of sensitive material.
func (vm *VM) DeleteKey(ctx context.Context, keyID ids.ID) error {
	vm.keysLock.Lock()
	defer vm.keysLock.Unlock()

	meta, exists := vm.keys[keyID]
	if !exists {
		return errKeyNotFound
	}

	// Secure zero key shares before deletion
	if shares, ok := vm.shares[keyID]; ok {
		for _, share := range shares {
			secureZeroBytes(share.ShareData)
		}
	}

	// Zero public key in metadata
	if meta != nil && len(meta.PublicKey) > 0 {
		secureZeroBytes(meta.PublicKey)
	}

	// Remove from maps
	delete(vm.keys, keyID)
	delete(vm.keysByName, meta.Name)
	delete(vm.shares, keyID)

	// Remove from caches (cache.Evict handles the eviction,
	// but we've already zeroed what we can access)
	vm.mlkemCache.Evict(keyID)
	vm.mlkemPubCache.Evict(keyID)

	// Delete from database
	if err := vm.deleteKeyFromDB(keyID); err != nil {
		vm.log.Warn("failed to delete key from database", "error", err)
	}

	vm.log.Info("deleted key", "keyID", keyID, "name", meta.Name)

	return nil
}

// Encrypt encrypts data using the key's ML-KEM public key.
func (vm *VM) Encrypt(ctx context.Context, keyID ids.ID, plaintext []byte) ([]byte, []byte, error) {
	vm.keysLock.RLock()
	meta, exists := vm.keys[keyID]
	vm.keysLock.RUnlock()

	if !exists {
		return nil, nil, errKeyNotFound
	}

	if meta.KeyType != "encryption" {
		return nil, nil, fmt.Errorf("key type %s does not support encryption", meta.KeyType)
	}

	// Get public key from cache
	pubKey, exists := vm.mlkemPubCache.Get(keyID)
	if !exists {
		return nil, nil, fmt.Errorf("public key not in cache")
	}

	// Encapsulate to get shared secret
	ciphertext, sharedSecret, err := pubKey.Encapsulate()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encapsulate: %w", err)
	}

	// Use AES-GCM for authenticated encryption
	// Derive a 32-byte key from the shared secret using HKDF (RFC 5869)
	// This provides proper key derivation with domain separation
	var key [32]byte
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("keyvm-mlkem-encryption-v1"))
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	encrypted := gcm.Seal(nonce, nonce, plaintext, nil)

	return encrypted, ciphertext, nil
}

// BuildBlock builds a new block from pending transactions.
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	vm.shutdownLock.Lock()
	defer vm.shutdownLock.Unlock()

	if vm.shuttingDown {
		return nil, errVMShutdown
	}

	vm.txLock.Lock()
	txs := vm.pendingTxs
	vm.pendingTxs = make([]*Transaction, 0)
	vm.txLock.Unlock()

	// Create block even without transactions for block-based consensus
	parent := vm.lastAccepted_
	if parent == nil {
		return nil, errors.New("no parent block")
	}

	// Create block
	newHeight := parent.height + 1
	blockData := make([]byte, 0, 100)
	blockData = append(blockData, vm.lastAccepted[:]...)
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, newHeight)
	blockData = append(blockData, heightBytes...)

	blockID, _ := ids.ToID(blockData)
	block := &Block{
		id:           blockID,
		parentID:     vm.lastAccepted,
		height:       newHeight,
		timestamp:    vm.clock.Time(),
		transactions: txs,
		vm:           vm,
	}

	if vm.pendingBlocks == nil {
		vm.pendingBlocks = make(map[ids.ID]*Block)
	}
	vm.pendingBlocks[blockID] = block

	if !vm.log.IsZero() {
		vm.log.Debug("built block",
			log.Stringer("blockID", blockID),
			log.Uint64("height", newHeight),
			log.Int("txCount", len(txs)),
		)
	}

	return block, nil
}

// ParseBlock parses a block from bytes.
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (chain.Block, error) {
	block := &Block{vm: vm}
	// Parse block - for now, minimal parsing
	if len(blockBytes) >= 32 {
		copy(block.parentID[:], blockBytes[:32])
	}
	if len(blockBytes) >= 40 {
		block.height = binary.BigEndian.Uint64(blockBytes[32:40])
	}
	if len(blockBytes) >= 48 {
		block.timestamp = time.Unix(int64(binary.BigEndian.Uint64(blockBytes[40:48])), 0)
	}
	block.id = block.computeID()
	return block, nil
}

// GetBlock retrieves a block by ID.
func (vm *VM) GetBlock(ctx context.Context, blockID ids.ID) (chain.Block, error) {
	vm.shutdownLock.RLock()
	defer vm.shutdownLock.RUnlock()

	// Check pending blocks (nil-safe for early calls before initialization)
	if vm.pendingBlocks != nil {
		if blk, exists := vm.pendingBlocks[blockID]; exists {
			return blk, nil
		}
	}

	// Check last accepted
	if vm.lastAccepted_ != nil && vm.lastAccepted_.id == blockID {
		return vm.lastAccepted_, nil
	}

	// Get from database
	if vm.state == nil {
		return nil, fmt.Errorf("block not found: state not initialized")
	}
	blockBytes, err := vm.state.Get(blockID[:])
	if err != nil {
		return nil, fmt.Errorf("block not found: %w", err)
	}
	return vm.ParseBlock(ctx, blockBytes)
}

// SetState sets the VM state.
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	if !vm.log.IsZero() {
		vm.log.Info("KMS VM state transition", log.Uint32("state", state))
	}
	return nil
}

// SetPreference sets the preferred block tip.
func (vm *VM) SetPreference(ctx context.Context, id ids.ID) error {
	return nil
}

// LastAccepted returns the last accepted block ID.
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	return vm.lastAccepted, nil
}

// GetBlockIDAtHeight returns the block ID at a given height.
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return ids.Empty, errors.New("height index not implemented")
}

// NewHTTPHandler returns an HTTP handler for the VM.
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

// WaitForEvent waits for a VM event.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	// Block until context is cancelled - this VM doesn't proactively build blocks
	// CRITICAL: Must block here to avoid notification flood loop in chains/manager.go
	<-ctx.Done()
	return vmcore.Message{}, ctx.Err()
}

// Shutdown shuts down the VM with secure cleanup of sensitive key material.
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.shutdownLock.Lock()
	vm.shuttingDown = true
	vm.shutdownLock.Unlock()

	vm.log.Info("shutting down KMS VM")

	// Cancel context
	if vm.cancel != nil {
		vm.cancel()
	}

	// Secure zero all key material before shutdown
	vm.keysLock.Lock()
	for _, shares := range vm.shares {
		for _, share := range shares {
			secureZeroBytes(share.ShareData)
		}
	}
	for _, meta := range vm.keys {
		if meta != nil && len(meta.PublicKey) > 0 {
			secureZeroBytes(meta.PublicKey)
		}
	}
	// Clear maps
	vm.shares = make(map[ids.ID][]*KeyShare)
	vm.keys = make(map[ids.ID]*KeyMetadata)
	vm.keysByName = make(map[string]ids.ID)
	vm.keysLock.Unlock()

	// Flush caches (this removes cached ML-KEM keys from memory)
	vm.mlkemCache.Flush()
	vm.mlkemPubCache.Flush()

	// Close database
	if vm.versiondb != nil {
		if err := vm.versiondb.Close(); err != nil {
			vm.log.Error("failed to close database", "error", err)
		}
	}

	vm.log.Info("KMS VM shutdown complete")
	return nil
}

// Version returns the VM version.
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version, nil
}

// Connected handles node connection events.
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *chain.VersionInfo) error {
	vm.log.Debug("node connected", "nodeID", nodeID, "version", nodeVersion)
	return nil
}

// Disconnected handles node disconnection events.
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	vm.log.Debug("node disconnected", "nodeID", nodeID)
	return nil
}

// HealthCheck returns VM health status.
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	vm.shutdownLock.RLock()
	shuttingDown := vm.shuttingDown
	vm.shutdownLock.RUnlock()

	vm.keysLock.RLock()
	keyCount := len(vm.keys)
	vm.keysLock.RUnlock()

	return chain.HealthResult{
		Healthy: !shuttingDown,
		Details: map[string]string{
			"version":      Version,
			"mlkemEnabled": fmt.Sprintf("%v", vm.Config.MLKEMEnabled),
			"mldsaEnabled": fmt.Sprintf("%v", vm.Config.MLDSAEnabled),
			"keyCount":     fmt.Sprintf("%d", keyCount),
			"validators":   fmt.Sprintf("%d", len(vm.Config.Validators)),
		},
	}, nil
}

// CreateHandlers returns HTTP handlers for the VM.
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{
		"/rpc": vm.rpcServer,
	}, nil
}

// CreateStaticHandlers returns static HTTP handlers.
func (vm *VM) CreateStaticHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return nil, nil
}

// Helper methods

func (vm *VM) initializeHTTPHandlers() error {
	vm.rpcServer = rpc.NewServer()

	service := &Service{vm: vm}
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json")
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json;charset=UTF-8")
	return vm.rpcServer.RegisterService(service, "kchain")
}

func (vm *VM) parseGenesis(genesisBytes []byte) error {
	vm.log.Info("parsing genesis", "size", len(genesisBytes))
	return nil
}

func (vm *VM) loadKeys() error {
	if vm.state == nil {
		return nil
	}

	// Iterate over all keys with KeyPrefix
	iter := vm.state.NewIteratorWithPrefix([]byte(KeyPrefix))
	defer iter.Release()

	for iter.Next() {
		value := iter.Value()
		var meta KeyMetadata
		if err := json.Unmarshal(value, &meta); err != nil {
			vm.log.Warn("failed to unmarshal key metadata", "error", err)
			continue
		}

		vm.keys[meta.ID] = &meta
		vm.keysByName[meta.Name] = meta.ID
	}

	if err := iter.Error(); err != nil {
		return fmt.Errorf("failed to iterate keys: %w", err)
	}

	vm.log.Info("loaded keys from database", "count", len(vm.keys))
	return nil
}

func (vm *VM) saveKeyMetadata(meta *KeyMetadata) error {
	if vm.state == nil {
		return errors.New("database not initialized")
	}

	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal key metadata: %w", err)
	}

	key := []byte(KeyPrefix + meta.ID.String())
	if err := vm.state.Put(key, data); err != nil {
		return fmt.Errorf("failed to store key metadata: %w", err)
	}

	return nil
}

func (vm *VM) deleteKeyFromDB(keyID ids.ID) error {
	if vm.state == nil {
		return errors.New("database not initialized")
	}

	key := []byte(KeyPrefix + keyID.String())
	if err := vm.state.Delete(key); err != nil {
		return fmt.Errorf("failed to delete key from database: %w", err)
	}

	return nil
}
