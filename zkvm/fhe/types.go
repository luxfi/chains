// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package fhe provides Fully Homomorphic Encryption primitives for the Lux blockchain.
// It uses the native luxfi/lattice library (CKKS scheme) with threshold decryption support.
//
// This implementation uses Lux's own pure-Go lattice cryptography library,
// providing permissively-licensed FHE operations.
package fhe

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/lattice/v7/core/rlwe"
)

// EncryptedType represents the type of encrypted value
type EncryptedType uint8

const (
	// EBool represents an encrypted boolean
	EBool EncryptedType = iota
	// EUint8 represents an encrypted 8-bit unsigned integer
	EUint8
	// EUint16 represents an encrypted 16-bit unsigned integer
	EUint16
	// EUint32 represents an encrypted 32-bit unsigned integer
	EUint32
	// EUint64 represents an encrypted 64-bit unsigned integer
	EUint64
	// EUint128 represents an encrypted 128-bit unsigned integer
	EUint128
	// EUint256 represents an encrypted 256-bit unsigned integer
	EUint256
	// EAddress represents an encrypted 20-byte Ethereum address
	EAddress
)

// String returns the string representation of the encrypted type
func (t EncryptedType) String() string {
	switch t {
	case EBool:
		return "ebool"
	case EUint8:
		return "euint8"
	case EUint16:
		return "euint16"
	case EUint32:
		return "euint32"
	case EUint64:
		return "euint64"
	case EUint128:
		return "euint128"
	case EUint256:
		return "euint256"
	case EAddress:
		return "eaddress"
	default:
		return "unknown"
	}
}

// BitSize returns the bit size of the encrypted type
func (t EncryptedType) BitSize() int {
	switch t {
	case EBool:
		return 1
	case EUint8:
		return 8
	case EUint16:
		return 16
	case EUint32:
		return 32
	case EUint64:
		return 64
	case EUint128:
		return 128
	case EUint256:
		return 256
	case EAddress:
		return 160 // 20 bytes
	default:
		return 0
	}
}

// MaxValue returns the maximum value for the encrypted type
func (t EncryptedType) MaxValue() uint64 {
	switch t {
	case EBool:
		return 1
	case EUint8:
		return 255
	case EUint16:
		return 65535
	case EUint32:
		return 4294967295
	case EUint64:
		return 18446744073709551615
	default:
		return 0 // For types larger than uint64, use big.Int
	}
}

// Ciphertext wraps an RLWE ciphertext with metadata
type Ciphertext struct {
	// Type is the encrypted value type
	Type EncryptedType

	// Handle is a unique identifier for this ciphertext in the FHE store
	Handle [32]byte

	// Ct is the underlying RLWE ciphertext
	Ct *rlwe.Ciphertext

	// Level is the current multiplicative depth level
	Level int

	// Scale is the encoding scale (for CKKS)
	Scale float64
}

// NewCiphertext creates a new Ciphertext wrapper
func NewCiphertext(t EncryptedType, ct *rlwe.Ciphertext, handle [32]byte) *Ciphertext {
	return &Ciphertext{
		Type:   t,
		Handle: handle,
		Ct:     ct,
		Level:  ct.Level(),
		Scale:  ct.Scale.Float64(),
	}
}

// Serialize converts the ciphertext to bytes for storage/transmission
func (c *Ciphertext) Serialize() ([]byte, error) {
	if c.Ct == nil {
		return nil, errors.New("nil ciphertext")
	}

	ctBytes, err := c.Ct.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ciphertext: %w", err)
	}

	// Format: [type(1)] [handle(32)] [level(4)] [scale(8)] [ct_len(4)] [ct_bytes...]
	result := make([]byte, 1+32+4+8+4+len(ctBytes))
	offset := 0

	result[offset] = byte(c.Type)
	offset++

	copy(result[offset:offset+32], c.Handle[:])
	offset += 32

	binary.BigEndian.PutUint32(result[offset:], uint32(c.Level))
	offset += 4

	binary.BigEndian.PutUint64(result[offset:], uint64(c.Scale))
	offset += 8

	binary.BigEndian.PutUint32(result[offset:], uint32(len(ctBytes)))
	offset += 4

	copy(result[offset:], ctBytes)

	return result, nil
}

// Deserialize reconstructs a ciphertext from bytes
func (c *Ciphertext) Deserialize(data []byte, params rlwe.ParameterProvider) error {
	if len(data) < 49 { // minimum: 1+32+4+8+4
		return errors.New("data too short")
	}

	offset := 0

	c.Type = EncryptedType(data[offset])
	offset++

	copy(c.Handle[:], data[offset:offset+32])
	offset += 32

	c.Level = int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	c.Scale = float64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	ctLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	if len(data) < offset+ctLen {
		return errors.New("data too short for ciphertext")
	}

	c.Ct = rlwe.NewCiphertext(params.GetRLWEParameters(), 1, c.Level)
	if err := c.Ct.UnmarshalBinary(data[offset : offset+ctLen]); err != nil {
		return fmt.Errorf("failed to unmarshal ciphertext: %w", err)
	}

	return nil
}

// EncryptedInput represents an encrypted input with proof of correct encryption
type EncryptedInput struct {
	// Ciphertext is the encrypted value
	Ciphertext *Ciphertext

	// Proof is a zero-knowledge proof of correct encryption (zkPoK)
	// This proves the encryptor knows the plaintext without revealing it
	Proof []byte

	// Sender is the address of the sender (for access control)
	Sender [20]byte
}

// DecryptionRequest represents a request for threshold decryption
type DecryptionRequest struct {
	// RequestID is a unique identifier for this request
	RequestID [32]byte

	// Ciphertext is the value to decrypt
	Ciphertext *Ciphertext

	// Requester is the address authorized to receive the decryption
	Requester [20]byte

	// Callback is the contract address to call with the result
	Callback [20]byte

	// CallbackSelector is the function selector for the callback
	CallbackSelector [4]byte
}

// DecryptionShare represents a partial decryption from one threshold party
type DecryptionShare struct {
	// PartyID identifies the party that created this share
	PartyID string

	// Share is the partial decryption share
	Share []byte

	// Signature proves the share is authentic
	Signature []byte
}

// DecryptionResult represents the final decryption result
type DecryptionResult struct {
	// RequestID matches the original request
	RequestID [32]byte

	// Plaintext is the decrypted value (encoded based on Type)
	Plaintext []byte

	// Signature is the threshold signature proving correctness
	Signature []byte
}
