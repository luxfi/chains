// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package state manages persistent state for the DEX VM.
package state

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

var (
	ErrAccountNotFound     = errors.New("account not found")
	ErrInsufficientBalance = errors.New("insufficient balance")
	ErrStateCorrupted      = errors.New("state corrupted")

	// Database prefixes
	prefixAccount   = []byte("account:")
	prefixBalance   = []byte("balance:")
	prefixOrder     = []byte("order:")
	prefixPool      = []byte("pool:")
	prefixPosition  = []byte("position:")
	prefixNonce     = []byte("nonce:")
	prefixBlock     = []byte("block:")
	prefixTx        = []byte("tx:")
	prefixLastBlock = []byte("lastBlock")
)

// Account represents a user account in the DEX.
type Account struct {
	Address    ids.ShortID       `json:"address"`
	Nonce      uint64            `json:"nonce"`
	Balances   map[ids.ID]uint64 `json:"balances"`   // token -> balance
	OpenOrders []ids.ID          `json:"openOrders"` // list of open order IDs
	LPTokens   map[ids.ID]uint64 `json:"lpTokens"`   // pool -> LP token balance
	CreatedAt  int64             `json:"createdAt"`
}

// State manages the persistent state of the DEX VM.
type State struct {
	mu sync.RWMutex
	db database.Database

	// Cached state
	accounts        map[ids.ShortID]*Account
	lastBlockID     ids.ID
	lastBlockHeight uint64
}

// New creates a new state manager.
func New(db database.Database) *State {
	return &State{
		db:       db,
		accounts: make(map[ids.ShortID]*Account),
	}
}

// Initialize initializes state from database.
func (s *State) Initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load last block
	lastBlockBytes, err := s.db.Get(prefixLastBlock)
	if err != nil && !errors.Is(err, database.ErrNotFound) {
		return fmt.Errorf("failed to load last block: %w", err)
	}
	if len(lastBlockBytes) >= 40 {
		copy(s.lastBlockID[:], lastBlockBytes[:32])
		s.lastBlockHeight = binary.BigEndian.Uint64(lastBlockBytes[32:40])
	}

	return nil
}

// GetAccount returns an account by address.
func (s *State) GetAccount(addr ids.ShortID) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check cache first
	if acc, ok := s.accounts[addr]; ok {
		return acc, nil
	}

	// Load from database
	key := append(prefixAccount, addr[:]...)
	data, err := s.db.Get(key)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, ErrAccountNotFound
		}
		return nil, err
	}

	acc, err := s.decodeAccount(data)
	if err != nil {
		return nil, err
	}

	return acc, nil
}

// GetOrCreateAccount returns an existing account or creates a new one.
func (s *State) GetOrCreateAccount(addr ids.ShortID) *Account {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check cache first
	if acc, ok := s.accounts[addr]; ok {
		return acc
	}

	// Try to load from database
	key := append(prefixAccount, addr[:]...)
	data, err := s.db.Get(key)
	if err == nil {
		acc, err := s.decodeAccount(data)
		if err == nil {
			s.accounts[addr] = acc
			return acc
		}
	}

	// Create new account
	acc := &Account{
		Address:    addr,
		Nonce:      0,
		Balances:   make(map[ids.ID]uint64),
		OpenOrders: make([]ids.ID, 0),
		LPTokens:   make(map[ids.ID]uint64),
	}
	s.accounts[addr] = acc
	return acc
}

// SaveAccount saves an account to database.
func (s *State) SaveAccount(acc *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := append(prefixAccount, acc.Address[:]...)
	data, err := s.encodeAccount(acc)
	if err != nil {
		return err
	}

	if err := s.db.Put(key, data); err != nil {
		return err
	}

	s.accounts[acc.Address] = acc
	return nil
}

// GetBalance returns the balance of a token for an account.
func (s *State) GetBalance(addr ids.ShortID, token ids.ID) (uint64, error) {
	acc, err := s.GetAccount(addr)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return 0, nil
		}
		return 0, err
	}

	return acc.Balances[token], nil
}

// Transfer transfers tokens between accounts.
func (s *State) Transfer(from, to ids.ShortID, token ids.ID, amount uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get or create accounts
	fromAcc := s.getOrCreateAccountLocked(from)
	toAcc := s.getOrCreateAccountLocked(to)

	// Check balance
	if fromAcc.Balances[token] < amount {
		return ErrInsufficientBalance
	}

	// Transfer
	fromAcc.Balances[token] -= amount
	toAcc.Balances[token] += amount

	return nil
}

// Credit adds tokens to an account.
func (s *State) Credit(addr ids.ShortID, token ids.ID, amount uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc := s.getOrCreateAccountLocked(addr)
	acc.Balances[token] += amount
	return nil
}

// Debit removes tokens from an account.
func (s *State) Debit(addr ids.ShortID, token ids.ID, amount uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc := s.getOrCreateAccountLocked(addr)
	if acc.Balances[token] < amount {
		return ErrInsufficientBalance
	}
	acc.Balances[token] -= amount
	return nil
}

// GetNonce returns the current nonce for an account.
func (s *State) GetNonce(addr ids.ShortID) (uint64, error) {
	acc, err := s.GetAccount(addr)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return 0, nil
		}
		return 0, err
	}
	return acc.Nonce, nil
}

// IncrementNonce increments the nonce for an account.
func (s *State) IncrementNonce(addr ids.ShortID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc := s.getOrCreateAccountLocked(addr)
	acc.Nonce++
	return nil
}

// AddOpenOrder adds an order ID to an account's open orders.
func (s *State) AddOpenOrder(addr ids.ShortID, orderID ids.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc := s.getOrCreateAccountLocked(addr)
	acc.OpenOrders = append(acc.OpenOrders, orderID)
	return nil
}

// RemoveOpenOrder removes an order ID from an account's open orders.
func (s *State) RemoveOpenOrder(addr ids.ShortID, orderID ids.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc := s.getOrCreateAccountLocked(addr)
	for i, id := range acc.OpenOrders {
		if id == orderID {
			acc.OpenOrders = append(acc.OpenOrders[:i], acc.OpenOrders[i+1:]...)
			break
		}
	}
	return nil
}

// GetLPBalance returns the LP token balance for a pool.
func (s *State) GetLPBalance(addr ids.ShortID, poolID ids.ID) (uint64, error) {
	acc, err := s.GetAccount(addr)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return 0, nil
		}
		return 0, err
	}
	return acc.LPTokens[poolID], nil
}

// CreditLPTokens adds LP tokens to an account.
func (s *State) CreditLPTokens(addr ids.ShortID, poolID ids.ID, amount uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc := s.getOrCreateAccountLocked(addr)
	acc.LPTokens[poolID] += amount
	return nil
}

// DebitLPTokens removes LP tokens from an account.
func (s *State) DebitLPTokens(addr ids.ShortID, poolID ids.ID, amount uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc := s.getOrCreateAccountLocked(addr)
	if acc.LPTokens[poolID] < amount {
		return ErrInsufficientBalance
	}
	acc.LPTokens[poolID] -= amount
	return nil
}

// SetLastBlock sets the last accepted block.
func (s *State) SetLastBlock(blockID ids.ID, height uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data := make([]byte, 40)
	copy(data[:32], blockID[:])
	binary.BigEndian.PutUint64(data[32:], height)

	if err := s.db.Put(prefixLastBlock, data); err != nil {
		return err
	}

	s.lastBlockID = blockID
	s.lastBlockHeight = height
	return nil
}

// GetLastBlock returns the last accepted block ID and height.
func (s *State) GetLastBlock() (ids.ID, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastBlockID, s.lastBlockHeight
}

// Commit commits all pending changes to the database.
func (s *State) Commit() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	batch := s.db.NewBatch()

	// Save all cached accounts
	for _, acc := range s.accounts {
		key := append(prefixAccount, acc.Address[:]...)
		data, err := s.encodeAccount(acc)
		if err != nil {
			return err
		}
		if err := batch.Put(key, data); err != nil {
			return err
		}
	}

	return batch.Write()
}

// Close closes the state manager.
func (s *State) Close() error {
	return s.Commit()
}

// Helper methods

func (s *State) getOrCreateAccountLocked(addr ids.ShortID) *Account {
	if acc, ok := s.accounts[addr]; ok {
		return acc
	}

	acc := &Account{
		Address:    addr,
		Nonce:      0,
		Balances:   make(map[ids.ID]uint64),
		OpenOrders: make([]ids.ID, 0),
		LPTokens:   make(map[ids.ID]uint64),
	}
	s.accounts[addr] = acc
	return acc
}

func (s *State) encodeAccount(acc *Account) ([]byte, error) {
	// Simplified encoding - in production use proper codec
	// Format: address (20) + nonce (8) + num_balances (4) + [token (32) + balance (8)]... + ...
	size := 20 + 8 + 4 + len(acc.Balances)*40 + 4 + len(acc.OpenOrders)*32 + 4 + len(acc.LPTokens)*40
	data := make([]byte, size)

	offset := 0
	copy(data[offset:], acc.Address[:])
	offset += 20

	binary.BigEndian.PutUint64(data[offset:], acc.Nonce)
	offset += 8

	binary.BigEndian.PutUint32(data[offset:], uint32(len(acc.Balances)))
	offset += 4

	for token, balance := range acc.Balances {
		copy(data[offset:], token[:])
		offset += 32
		binary.BigEndian.PutUint64(data[offset:], balance)
		offset += 8
	}

	binary.BigEndian.PutUint32(data[offset:], uint32(len(acc.OpenOrders)))
	offset += 4

	for _, orderID := range acc.OpenOrders {
		copy(data[offset:], orderID[:])
		offset += 32
	}

	binary.BigEndian.PutUint32(data[offset:], uint32(len(acc.LPTokens)))
	offset += 4

	for poolID, balance := range acc.LPTokens {
		copy(data[offset:], poolID[:])
		offset += 32
		binary.BigEndian.PutUint64(data[offset:], balance)
		offset += 8
	}

	return data[:offset], nil
}

func (s *State) decodeAccount(data []byte) (*Account, error) {
	if len(data) < 32 {
		return nil, ErrStateCorrupted
	}

	acc := &Account{
		Balances:   make(map[ids.ID]uint64),
		OpenOrders: make([]ids.ID, 0),
		LPTokens:   make(map[ids.ID]uint64),
	}

	offset := 0
	copy(acc.Address[:], data[offset:offset+20])
	offset += 20

	acc.Nonce = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	numBalances := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	for i := uint32(0); i < numBalances; i++ {
		var token ids.ID
		copy(token[:], data[offset:offset+32])
		offset += 32
		balance := binary.BigEndian.Uint64(data[offset:])
		offset += 8
		acc.Balances[token] = balance
	}

	if offset >= len(data) {
		return acc, nil
	}

	numOrders := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	for i := uint32(0); i < numOrders; i++ {
		var orderID ids.ID
		copy(orderID[:], data[offset:offset+32])
		offset += 32
		acc.OpenOrders = append(acc.OpenOrders, orderID)
	}

	if offset >= len(data) {
		return acc, nil
	}

	numLPTokens := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	for i := uint32(0); i < numLPTokens; i++ {
		var poolID ids.ID
		copy(poolID[:], data[offset:offset+32])
		offset += 32
		balance := binary.BigEndian.Uint64(data[offset:])
		offset += 8
		acc.LPTokens[poolID] = balance
	}

	return acc, nil
}
