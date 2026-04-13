// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/luxfi/ids"
)

// TransactionType represents the type of transaction
type TransactionType uint8

const (
	TransactionTypeTransfer TransactionType = iota
	TransactionTypeMint
	TransactionTypeBurn
	TransactionTypeShield   // Convert transparent to shielded
	TransactionTypeUnshield // Convert shielded to transparent
)

// Transaction represents a confidential transaction
type Transaction struct {
	ID      ids.ID          `json:"id"`
	Type    TransactionType `json:"type"`
	Version uint8           `json:"version"`

	// Transparent inputs/outputs (for shield/unshield)
	TransparentInputs  []*TransparentInput  `json:"transparentInputs,omitempty"`
	TransparentOutputs []*TransparentOutput `json:"transparentOutputs,omitempty"`

	// Shielded components
	Nullifiers [][]byte          `json:"nullifiers"` // Spent note nullifiers
	Outputs    []*ShieldedOutput `json:"outputs"`    // New shielded outputs

	// Zero-knowledge proof
	Proof *ZKProof `json:"proof"`

	// FHE operations (optional)
	FHEData *FHEData `json:"fheData,omitempty"`

	// Transaction metadata
	Fee    uint64 `json:"fee"`
	Expiry uint64 `json:"expiry"`         // Block height
	Memo   []byte `json:"memo,omitempty"` // Encrypted memo

	// Signature for transparent components
	Signature []byte `json:"signature,omitempty"`
}

// TransparentInput represents an unshielded input
type TransparentInput struct {
	TxID      ids.ID `json:"txId"`
	OutputIdx uint32 `json:"outputIdx"`
	Amount    uint64 `json:"amount"`
	Address   []byte `json:"address"`
}

// TransparentOutput represents an unshielded output
type TransparentOutput struct {
	Amount  uint64 `json:"amount"`
	Address []byte `json:"address"`
	AssetID ids.ID `json:"assetId"`
}

// ShieldedOutput represents a confidential output
type ShieldedOutput struct {
	// Commitment to the note (amount and address)
	Commitment []byte `json:"commitment"`

	// Encrypted note ciphertext
	EncryptedNote []byte `json:"encryptedNote"`

	// Ephemeral public key for note encryption
	EphemeralPubKey []byte `json:"ephemeralPubKey"`

	// Output proof (rangeproof for amount)
	OutputProof []byte `json:"outputProof"`
}

// ZKProof represents a zero-knowledge proof
type ZKProof struct {
	ProofType    string   `json:"proofType"` // groth16, plonk, etc.
	ProofData    []byte   `json:"proofData"`
	PublicInputs [][]byte `json:"publicInputs"`
}

// FHEData represents fully homomorphic encryption data
type FHEData struct {
	// Encrypted computation inputs
	EncryptedInputs [][]byte `json:"encryptedInputs"`

	// Computation circuit
	CircuitID string `json:"circuitId"`

	// Encrypted result
	EncryptedResult []byte `json:"encryptedResult"`

	// Proof of correct computation
	ComputationProof []byte `json:"computationProof"`
}

// Note represents a shielded note (internal representation)
type Note struct {
	Value      *big.Int `json:"value"`      // Encrypted amount
	Address    []byte   `json:"address"`    // Recipient address
	AssetID    ids.ID   `json:"assetId"`    // Asset type
	Randomness []byte   `json:"randomness"` // Note randomness
	Nullifier  []byte   `json:"nullifier"`  // Computed nullifier
}

// ComputeID computes the transaction ID
func (tx *Transaction) ComputeID() ids.ID {
	h := sha256.New()

	// Include transaction type and version
	h.Write([]byte{byte(tx.Type), tx.Version})

	// Include nullifiers
	for _, nullifier := range tx.Nullifiers {
		h.Write(nullifier)
	}

	// Include output commitments
	for _, output := range tx.Outputs {
		h.Write(output.Commitment)
	}

	// Include proof
	if tx.Proof != nil {
		h.Write([]byte(tx.Proof.ProofType))
		h.Write(tx.Proof.ProofData)
	}

	// Include fee and expiry
	binary.Write(h, binary.BigEndian, tx.Fee)
	binary.Write(h, binary.BigEndian, tx.Expiry)

	return ids.ID(h.Sum(nil))
}

// HasFHEOperations returns true if the transaction includes FHE operations
func (tx *Transaction) HasFHEOperations() bool {
	return tx.FHEData != nil && len(tx.FHEData.EncryptedInputs) > 0
}

// GetNullifiers returns all nullifiers in the transaction
func (tx *Transaction) GetNullifiers() [][]byte {
	return tx.Nullifiers
}

// GetOutputCommitments returns all output commitments
func (tx *Transaction) GetOutputCommitments() [][]byte {
	commitments := make([][]byte, len(tx.Outputs))
	for i, output := range tx.Outputs {
		commitments[i] = output.Commitment
	}
	return commitments
}

// ValidateBasic performs basic validation
func (tx *Transaction) ValidateBasic() error {
	// Check transaction type
	if tx.Type > TransactionTypeUnshield {
		return errInvalidTransactionType
	}

	// Check nullifiers and outputs
	if len(tx.Nullifiers) == 0 && len(tx.TransparentInputs) == 0 {
		return errNoInputs
	}

	if len(tx.Outputs) == 0 && len(tx.TransparentOutputs) == 0 {
		return errNoOutputs
	}

	// Check proof
	if tx.Proof == nil {
		return errMissingProof
	}

	// Type-specific validation
	switch tx.Type {
	case TransactionTypeTransfer:
		// Must have shielded inputs and outputs
		if len(tx.Nullifiers) == 0 || len(tx.Outputs) == 0 {
			return errInvalidTransferTransaction
		}

	case TransactionTypeShield:
		// Must have transparent inputs and shielded outputs
		if len(tx.TransparentInputs) == 0 || len(tx.Outputs) == 0 {
			return errInvalidShieldTransaction
		}

	case TransactionTypeUnshield:
		// Must have shielded inputs and transparent outputs
		if len(tx.Nullifiers) == 0 || len(tx.TransparentOutputs) == 0 {
			return errInvalidUnshieldTransaction
		}
	}

	return nil
}

// ComputeNullifier computes a nullifier for a note
func ComputeNullifier(note *Note, spendingKey []byte) []byte {
	h := sha256.New()
	h.Write(note.Address)
	h.Write(note.Value.Bytes())
	h.Write(note.AssetID[:])
	h.Write(note.Randomness)
	h.Write(spendingKey)
	return h.Sum(nil)
}

// ComputeCommitment computes a note commitment
func ComputeCommitment(note *Note) []byte {
	h := sha256.New()
	h.Write(note.Value.Bytes())
	h.Write(note.Address)
	h.Write(note.AssetID[:])
	h.Write(note.Randomness)
	return h.Sum(nil)
}

// EncryptNote encrypts a note for the recipient using ChaCha20-Poly1305.
// chainID and txID bind the encryption key to prevent cross-chain/cross-tx reuse.
func EncryptNote(note *Note, recipientPubKey []byte, ephemeralPrivKey []byte, chainID ids.ID, txID ids.ID) ([]byte, []byte, error) {
	// Derive shared secret using ECDH
	sharedSecret, err := deriveSharedSecret(ephemeralPrivKey, recipientPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Derive encryption key from shared secret
	encryptionKey := deriveEncryptionKey(sharedSecret, chainID, txID)

	// Serialize note plaintext
	plaintext, err := serializeNote(note)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize note: %w", err)
	}

	// Encrypt using ChaCha20-Poly1305
	ciphertext, err := encryptChaCha20Poly1305(plaintext, encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Derive ephemeral public key
	ephemeralPubKey, err := derivePublicKey(ephemeralPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive ephemeral public key: %w", err)
	}

	return ciphertext, ephemeralPubKey, nil
}

// DecryptNote decrypts a note using the recipient's key and ChaCha20-Poly1305.
// chainID and txID must match the values used during encryption.
func DecryptNote(encryptedNote []byte, ephemeralPubKey []byte, recipientPrivKey []byte, chainID ids.ID, txID ids.ID) (*Note, error) {
	// Derive shared secret using ECDH
	sharedSecret, err := deriveSharedSecret(recipientPrivKey, ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Derive decryption key from shared secret
	decryptionKey := deriveEncryptionKey(sharedSecret, chainID, txID)

	// Decrypt using ChaCha20-Poly1305
	plaintext, err := decryptChaCha20Poly1305(encryptedNote, decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Deserialize note
	note, err := deserializeNote(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize note: %w", err)
	}

	return note, nil
}

// derivePublicKey derives a Curve25519 public key from private key
func derivePublicKey(privKey []byte) ([]byte, error) {
	if len(privKey) != 32 {
		return nil, errors.New("zkvm: invalid private key length")
	}
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("zkvm: X25519 base mult failed: %w", err)
	}
	return pubKey, nil
}

// deriveSharedSecret performs ECDH key exchange using Curve25519
func deriveSharedSecret(privKey, pubKey []byte) ([]byte, error) {
	if len(privKey) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}
	if len(pubKey) != 32 {
		return nil, errors.New("public key must be 32 bytes")
	}
	sharedSecret, err := curve25519.X25519(privKey, pubKey)
	if err != nil {
		return nil, fmt.Errorf("zkvm: X25519 key exchange failed: %w", err)
	}
	return sharedSecret, nil
}

// deriveEncryptionKey derives a ChaCha20-Poly1305 key from shared secret using HKDF.
// chainID and txID are bound into the salt and info to prevent cross-chain and cross-tx key reuse.
func deriveEncryptionKey(sharedSecret []byte, chainID ids.ID, txID ids.ID) []byte {
	salt := make([]byte, 0, len(chainID)+len("zkvm-v1"))
	salt = append(salt, chainID[:]...)
	salt = append(salt, []byte("zkvm-v1")...)

	info := []byte("zkvm-note-encryption-" + txID.String())

	kdf := hkdf.New(sha256.New, sharedSecret, salt, info)

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := kdf.Read(key); err != nil {
		panic(fmt.Sprintf("hkdf read failed: %v", err))
	}

	return key
}

// encryptChaCha20Poly1305 encrypts data using ChaCha20-Poly1305 AEAD
func encryptChaCha20Poly1305(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate random nonce (XChaCha20-Poly1305 uses 24-byte nonce)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptChaCha20Poly1305 decrypts data using ChaCha20-Poly1305 AEAD
func decryptChaCha20Poly1305(ciphertext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and encrypted data
	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	// Decrypt and verify authentication tag
	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption or authentication failed: %w", err)
	}

	return plaintext, nil
}

// serializeNote serializes a note to bytes
func serializeNote(note *Note) ([]byte, error) {
	// Format: [value_len(4)][value][address_len(4)][address][assetID(32)][randomness_len(4)][randomness]
	valueBytes := note.Value.Bytes()

	buf := make([]byte, 0, 4+len(valueBytes)+4+len(note.Address)+32+4+len(note.Randomness))

	// Write value
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(valueBytes)))
	buf = append(buf, lenBuf...)
	buf = append(buf, valueBytes...)

	// Write address
	binary.BigEndian.PutUint32(lenBuf, uint32(len(note.Address)))
	buf = append(buf, lenBuf...)
	buf = append(buf, note.Address...)

	// Write asset ID (fixed 32 bytes)
	buf = append(buf, note.AssetID[:]...)

	// Write randomness
	binary.BigEndian.PutUint32(lenBuf, uint32(len(note.Randomness)))
	buf = append(buf, lenBuf...)
	buf = append(buf, note.Randomness...)

	return buf, nil
}

// deserializeNote deserializes a note from bytes
func deserializeNote(data []byte) (*Note, error) {
	if len(data) < 12 { // Minimum: 4+0+4+0+32+4+0
		return nil, errors.New("data too short")
	}

	pos := 0

	// Read value
	valueLen := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	if pos+int(valueLen) > len(data) {
		return nil, errors.New("invalid value length")
	}
	valueBytes := data[pos : pos+int(valueLen)]
	value := new(big.Int).SetBytes(valueBytes)
	pos += int(valueLen)

	// Read address
	if pos+4 > len(data) {
		return nil, errors.New("data too short for address length")
	}
	addrLen := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	if pos+int(addrLen) > len(data) {
		return nil, errors.New("invalid address length")
	}
	address := make([]byte, addrLen)
	copy(address, data[pos:pos+int(addrLen)])
	pos += int(addrLen)

	// Read asset ID
	if pos+32 > len(data) {
		return nil, errors.New("data too short for asset ID")
	}
	var assetID ids.ID
	copy(assetID[:], data[pos:pos+32])
	pos += 32

	// Read randomness
	if pos+4 > len(data) {
		return nil, errors.New("data too short for randomness length")
	}
	randLen := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	if pos+int(randLen) > len(data) {
		return nil, errors.New("invalid randomness length")
	}
	randomness := make([]byte, randLen)
	copy(randomness, data[pos:pos+int(randLen)])

	return &Note{
		Value:      value,
		Address:    address,
		AssetID:    assetID,
		Randomness: randomness,
	}, nil
}

// Transaction validation errors
var (
	errInvalidTransactionType     = errors.New("invalid transaction type")
	errNoInputs                   = errors.New("transaction has no inputs")
	errNoOutputs                  = errors.New("transaction has no outputs")
	errMissingProof               = errors.New("transaction missing proof")
	errInvalidTransferTransaction = errors.New("invalid transfer transaction")
	errInvalidShieldTransaction   = errors.New("invalid shield transaction")
	errInvalidUnshieldTransaction = errors.New("invalid unshield transaction")
)
