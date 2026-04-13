// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/luxfi/ids"
)

// Transaction types
const (
	TxTypeCreateKey     = 1
	TxTypeDeleteKey     = 2
	TxTypeDistributeKey = 3
	TxTypeReshareKey    = 4
	TxTypeUpdateKeyMeta = 5
	TxTypeRevokeKey     = 6
)

var (
	ErrInvalidTxType    = errors.New("invalid transaction type")
	ErrInvalidTxData    = errors.New("invalid transaction data")
	ErrTxAlreadyExists  = errors.New("transaction already exists")
	ErrKeyNotFound      = errors.New("key not found")
	ErrKeyAlreadyExists = errors.New("key already exists")
	ErrUnauthorized     = errors.New("unauthorized operation")
)

// Transaction represents a K-Chain transaction.
type Transaction struct {
	id        ids.ID
	txType    uint8
	timestamp time.Time
	keyID     ids.ID
	payload   []byte
	signature []byte
	sender    []byte
}

// NewTransaction creates a new transaction.
func NewTransaction(txType uint8, keyID ids.ID, payload []byte, sender []byte) *Transaction {
	tx := &Transaction{
		txType:    txType,
		timestamp: time.Now(),
		keyID:     keyID,
		payload:   payload,
		sender:    sender,
	}
	// Compute ID from serialized data
	data := tx.Bytes()
	txID, _ := ids.ToID(data)
	tx.id = txID
	return tx
}

// ID returns the transaction's unique identifier.
func (tx *Transaction) ID() ids.ID {
	return tx.id
}

// Type returns the transaction type.
func (tx *Transaction) Type() uint8 {
	return tx.txType
}

// Timestamp returns the transaction timestamp.
func (tx *Transaction) Timestamp() time.Time {
	return tx.timestamp
}

// KeyID returns the key ID this transaction operates on.
func (tx *Transaction) KeyID() ids.ID {
	return tx.keyID
}

// Payload returns the transaction payload.
func (tx *Transaction) Payload() []byte {
	return tx.payload
}

// Bytes serializes the transaction to bytes.
func (tx *Transaction) Bytes() []byte {
	data := make([]byte, 0, 256)

	// Type (1 byte)
	data = append(data, tx.txType)

	// Timestamp (8 bytes)
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(tx.timestamp.Unix()))
	data = append(data, tsBytes...)

	// Key ID (32 bytes)
	data = append(data, tx.keyID[:]...)

	// Payload length + payload
	payloadLen := make([]byte, 4)
	binary.BigEndian.PutUint32(payloadLen, uint32(len(tx.payload)))
	data = append(data, payloadLen...)
	data = append(data, tx.payload...)

	// Sender length + sender
	senderLen := make([]byte, 4)
	binary.BigEndian.PutUint32(senderLen, uint32(len(tx.sender)))
	data = append(data, senderLen...)
	data = append(data, tx.sender...)

	// Signature length + signature
	sigLen := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLen, uint32(len(tx.signature)))
	data = append(data, sigLen...)
	data = append(data, tx.signature...)

	return data
}

// ParseTransaction deserializes a transaction from bytes.
func ParseTransaction(data []byte) (*Transaction, error) {
	if len(data) < 45 { // minimum: 1 + 8 + 32 + 4
		return nil, ErrInvalidTxData
	}

	tx := &Transaction{}
	offset := 0

	// Type
	tx.txType = data[offset]
	offset++

	// Timestamp
	ts := binary.BigEndian.Uint64(data[offset : offset+8])
	tx.timestamp = time.Unix(int64(ts), 0)
	offset += 8

	// Key ID
	copy(tx.keyID[:], data[offset:offset+32])
	offset += 32

	// Payload
	if offset+4 > len(data) {
		return nil, ErrInvalidTxData
	}
	payloadLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if offset+int(payloadLen) > len(data) {
		return nil, ErrInvalidTxData
	}
	tx.payload = make([]byte, payloadLen)
	copy(tx.payload, data[offset:offset+int(payloadLen)])
	offset += int(payloadLen)

	// Sender
	if offset+4 > len(data) {
		return nil, ErrInvalidTxData
	}
	senderLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if offset+int(senderLen) > len(data) {
		return nil, ErrInvalidTxData
	}
	tx.sender = make([]byte, senderLen)
	copy(tx.sender, data[offset:offset+int(senderLen)])
	offset += int(senderLen)

	// Signature
	if offset+4 > len(data) {
		return nil, ErrInvalidTxData
	}
	sigLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if offset+int(sigLen) > len(data) {
		return nil, ErrInvalidTxData
	}
	tx.signature = make([]byte, sigLen)
	copy(tx.signature, data[offset:offset+int(sigLen)])

	// Recompute ID
	txID, _ := ids.ToID(tx.Bytes())
	tx.id = txID

	return tx, nil
}

// Verify verifies the transaction is valid.
func (tx *Transaction) Verify(ctx context.Context) error {
	// Validate transaction type
	switch tx.txType {
	case TxTypeCreateKey, TxTypeDeleteKey, TxTypeDistributeKey,
		TxTypeReshareKey, TxTypeUpdateKeyMeta, TxTypeRevokeKey:
		// Valid type
	default:
		return ErrInvalidTxType
	}

	// Validate timestamp is not in the future
	if tx.timestamp.After(time.Now().Add(time.Minute)) {
		return errors.New("transaction timestamp too far in the future")
	}

	// Additional validation could include:
	// - Signature verification
	// - Sender authorization
	// - Payload format validation

	return nil
}

// Execute executes the transaction against the VM state.
func (tx *Transaction) Execute(ctx context.Context, vm *VM) error {
	switch tx.txType {
	case TxTypeCreateKey:
		return tx.executeCreateKey(ctx, vm)
	case TxTypeDeleteKey:
		return tx.executeDeleteKey(ctx, vm)
	case TxTypeDistributeKey:
		return tx.executeDistributeKey(ctx, vm)
	case TxTypeReshareKey:
		return tx.executeReshareKey(ctx, vm)
	case TxTypeUpdateKeyMeta:
		return tx.executeUpdateKeyMeta(ctx, vm)
	case TxTypeRevokeKey:
		return tx.executeRevokeKey(ctx, vm)
	default:
		return ErrInvalidTxType
	}
}

func (tx *Transaction) executeCreateKey(ctx context.Context, vm *VM) error {
	// Parse payload for key creation params
	if len(tx.payload) < 4 {
		return ErrInvalidTxData
	}

	// Key already stored via the RPC call that created the transaction
	// This just logs the creation on-chain for auditability
	vm.log.Info("key creation recorded on-chain",
		"keyID", tx.keyID,
		"txID", tx.id,
	)

	return nil
}

func (tx *Transaction) executeDeleteKey(ctx context.Context, vm *VM) error {
	// Mark key as deleted in state
	vm.log.Info("key deletion recorded on-chain",
		"keyID", tx.keyID,
		"txID", tx.id,
	)

	return nil
}

func (tx *Transaction) executeDistributeKey(ctx context.Context, vm *VM) error {
	// Record key distribution event
	vm.log.Info("key distribution recorded on-chain",
		"keyID", tx.keyID,
		"txID", tx.id,
	)

	return nil
}

func (tx *Transaction) executeReshareKey(ctx context.Context, vm *VM) error {
	// Record reshare event
	vm.log.Info("key reshare recorded on-chain",
		"keyID", tx.keyID,
		"txID", tx.id,
	)

	return nil
}

func (tx *Transaction) executeUpdateKeyMeta(ctx context.Context, vm *VM) error {
	// Record metadata update
	vm.log.Info("key metadata update recorded on-chain",
		"keyID", tx.keyID,
		"txID", tx.id,
	)

	return nil
}

func (tx *Transaction) executeRevokeKey(ctx context.Context, vm *VM) error {
	// Record key revocation
	vm.log.Info("key revocation recorded on-chain",
		"keyID", tx.keyID,
		"txID", tx.id,
	)

	return nil
}

// CreateKeyPayload represents the payload for a CreateKey transaction.
type CreateKeyPayload struct {
	Name        string
	Algorithm   string
	Threshold   int
	TotalShares int
	Tags        []string
}

// DeleteKeyPayload represents the payload for a DeleteKey transaction.
type DeleteKeyPayload struct {
	Force bool
}

// DistributeKeyPayload represents the payload for a DistributeKey transaction.
type DistributeKeyPayload struct {
	Validators []string
	Threshold  int
}

// ReshareKeyPayload represents the payload for a ReshareKey transaction.
type ReshareKeyPayload struct {
	NewValidators []string
	NewThreshold  int
}

// UpdateKeyMetaPayload represents the payload for an UpdateKeyMeta transaction.
type UpdateKeyMetaPayload struct {
	Name   string
	Tags   []string
	Status string
}

// RevokeKeyPayload represents the payload for a RevokeKey transaction.
type RevokeKeyPayload struct {
	Reason string
}
