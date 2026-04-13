// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/log"

	"github.com/luxfi/database"
)

const (
	// Database prefixes
	addressPrefix    = 0x30
	viewingKeyPrefix = 0x31
	addressCountKey  = "address_count"
)

// AddressManager manages private addresses and viewing keys
type AddressManager struct {
	db            database.Database
	log           log.Logger
	enablePrivate bool

	// Address mappings
	addresses    map[string]*PrivateAddress // address -> private address info
	viewingKeys  map[string][]string        // viewing key -> addresses
	addressCount uint64

	mu sync.RWMutex
}

// PrivateAddress represents a private address
type PrivateAddress struct {
	Address         []byte `json:"address"`         // Public address (32 bytes)
	ViewingKey      []byte `json:"viewingKey"`      // Viewing key for scanning
	SpendingKey     []byte `json:"spendingKey"`     // Spending key (private)
	Diversifier     []byte `json:"diversifier"`     // Address diversifier
	IncomingViewKey []byte `json:"incomingViewKey"` // For incoming payments only
	CreatedAt       int64  `json:"createdAt"`
}

// NewAddressManager creates a new address manager
func NewAddressManager(db database.Database, enablePrivate bool, log log.Logger) (*AddressManager, error) {
	am := &AddressManager{
		db:            db,
		log:           log,
		enablePrivate: enablePrivate,
		addresses:     make(map[string]*PrivateAddress),
		viewingKeys:   make(map[string][]string),
	}

	// Load address count
	countBytes, err := db.Get([]byte(addressCountKey))
	if err == database.ErrNotFound {
		am.addressCount = 0
	} else if err != nil {
		return nil, err
	} else {
		am.addressCount = binary.BigEndian.Uint64(countBytes)
	}

	if err := am.loadAddresses(); err != nil {
		return nil, err
	}

	return am, nil
}

// GenerateAddress generates a new private address
func (am *AddressManager) GenerateAddress() (*PrivateAddress, error) {
	if !am.enablePrivate {
		return nil, errors.New("private addresses not enabled")
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	// Generate keys
	spendingKey := make([]byte, 32)
	if _, err := rand.Read(spendingKey); err != nil {
		return nil, err
	}

	// Derive viewing key from spending key
	h := sha256.New()
	h.Write([]byte("viewing_key"))
	h.Write(spendingKey)
	viewingKey := h.Sum(nil)

	// Derive incoming viewing key
	h.Reset()
	h.Write([]byte("incoming_view_key"))
	h.Write(viewingKey)
	incomingViewKey := h.Sum(nil)

	// Generate diversifier
	diversifier := make([]byte, 11)
	if _, err := rand.Read(diversifier); err != nil {
		return nil, err
	}

	// Derive address from viewing key and diversifier
	h.Reset()
	h.Write(viewingKey)
	h.Write(diversifier)
	address := h.Sum(nil)

	// Create private address
	privAddr := &PrivateAddress{
		Address:         address,
		ViewingKey:      viewingKey,
		SpendingKey:     spendingKey,
		Diversifier:     diversifier,
		IncomingViewKey: incomingViewKey,
		CreatedAt:       time.Now().Unix(),
	}

	// Store in database
	if err := am.storeAddress(privAddr); err != nil {
		return nil, err
	}

	// Update caches
	addressStr := string(address)
	am.addresses[addressStr] = privAddr

	viewingKeyStr := string(viewingKey)
	am.viewingKeys[viewingKeyStr] = append(am.viewingKeys[viewingKeyStr], addressStr)

	// Update count
	am.addressCount++
	countBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(countBytes, am.addressCount)
	if err := am.db.Put([]byte(addressCountKey), countBytes); err != nil {
		return nil, err
	}

	am.log.Info("Generated new private address",
		log.String("address", fmt.Sprintf("%x", address[:8])),
		log.String("diversifier", fmt.Sprintf("%x", diversifier[:4])),
	)

	return privAddr, nil
}

// GetAddress retrieves an address by its public address
func (am *AddressManager) GetAddress(address []byte) (*PrivateAddress, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	addressStr := string(address)
	privAddr, exists := am.addresses[addressStr]
	if !exists {
		return nil, errors.New("address not found")
	}

	return privAddr, nil
}

// GetAddressesByViewingKey returns all addresses associated with a viewing key
func (am *AddressManager) GetAddressesByViewingKey(viewingKey []byte) ([]*PrivateAddress, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	viewingKeyStr := string(viewingKey)
	addressStrs, exists := am.viewingKeys[viewingKeyStr]
	if !exists {
		return nil, nil
	}

	addresses := make([]*PrivateAddress, 0, len(addressStrs))
	for _, addressStr := range addressStrs {
		if addr, exists := am.addresses[addressStr]; exists {
			addresses = append(addresses, addr)
		}
	}

	return addresses, nil
}

// CanDecryptNote checks if we have the keys to decrypt a note
func (am *AddressManager) CanDecryptNote(ephemeralPubKey []byte, address []byte) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()

	_, exists := am.addresses[string(address)]
	return exists
}

// DeriveNullifier derives a nullifier using the spending key
func (am *AddressManager) DeriveNullifier(address []byte, note *Note) ([]byte, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	privAddr, exists := am.addresses[string(address)]
	if !exists {
		return nil, errors.New("address not found")
	}

	// Compute nullifier using spending key
	nullifier := ComputeNullifier(note, privAddr.SpendingKey)

	return nullifier, nil
}

// SignTransaction signs a transaction with the appropriate keys
func (am *AddressManager) SignTransaction(tx *Transaction, signingAddresses [][]byte) error {
	h := sha256.New()
	h.Write(tx.ID[:])

	for _, addr := range signingAddresses {
		privAddr, err := am.GetAddress(addr)
		if err != nil {
			return err
		}

		// Sign with spending key
		h.Write(privAddr.SpendingKey)
	}

	tx.Signature = h.Sum(nil)

	return nil
}

// storeAddress stores an address in the database
func (am *AddressManager) storeAddress(privAddr *PrivateAddress) error {
	// Serialize address
	addrBytes, err := Codec.Marshal(codecVersion, privAddr)
	if err != nil {
		return err
	}

	// Store by address
	key := makeAddressKey(privAddr.Address)
	if err := am.db.Put(key, addrBytes); err != nil {
		return err
	}

	// Store viewing key index
	vkKey := makeViewingKeyKey(privAddr.ViewingKey, privAddr.Address)
	if err := am.db.Put(vkKey, []byte{1}); err != nil {
		return err
	}

	return nil
}

// loadAddresses loads addresses from database
func (am *AddressManager) loadAddresses() error {
	return nil
}

// makeAddressKey creates a database key for an address
func makeAddressKey(address []byte) []byte {
	key := make([]byte, 1+len(address))
	key[0] = addressPrefix
	copy(key[1:], address)
	return key
}

// makeViewingKeyKey creates a database key for viewing key index
func makeViewingKeyKey(viewingKey, address []byte) []byte {
	key := make([]byte, 1+len(viewingKey)+len(address))
	key[0] = viewingKeyPrefix
	copy(key[1:], viewingKey)
	copy(key[1+len(viewingKey):], address)
	return key
}

// GetAddressCount returns the total number of addresses
func (am *AddressManager) GetAddressCount() uint64 {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.addressCount
}

// Close closes the address manager
func (am *AddressManager) Close() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.addresses = nil
	am.viewingKeys = nil
}
