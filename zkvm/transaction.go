// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/luxfi/ids"
)

// Note construction — deriving a nullifier, committing to a note, encrypting
// one to a recipient — is a WALLET's work and lived here, along with the only
// panic in the package. A validator holds no spending keys and builds no
// notes: it checks proofs and the spent set. What it needs of a note is the
// commitment and the nullifier the transaction already carries.

// MaxTxSize bounds a transaction on the way in, so a peer cannot make this
// node hold what it would never build.
const MaxTxSize = 1 << 20

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

	// Transaction metadata
	Fee    uint64 `json:"fee"`
	Expiry uint64 `json:"expiry"`         // Block height
	Memo   []byte `json:"memo,omitempty"` // Encrypted memo
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

// ComputeID is the transaction's identity: a hash over everything the
// transaction means. It is NOT carried on the wire — parseTransaction derives
// it — because an identity a peer supplies is an identity a peer chooses, and
// the proof cache is keyed on it: copy an accepted transaction's id, proof and
// public inputs onto a transaction spending different notes and the cache
// answers nil before anything binds the proof to what it spends.
//
// Every variable-length field is written with its length first and every list
// with its count. Concatenated raw, a byte could move from the end of one field
// to the start of the next without the hash noticing — ["ab","c"] and ["a","bc"]
// are the same bytes — and two transactions sharing an identity is what
// consensus decides between blocks with.
func (tx *Transaction) ComputeID() ids.ID {
	h := sha256.New()
	num := func(v uint64) { binary.Write(h, binary.BigEndian, v) }
	blob := func(b []byte) { num(uint64(len(b))); h.Write(b) }
	count := func(n int) { num(uint64(n)) }
	present := func(yes bool) {
		if yes {
			h.Write([]byte{1})
			return
		}
		h.Write([]byte{0})
	}

	h.Write([]byte{byte(tx.Type), tx.Version})

	count(len(tx.TransparentInputs))
	for _, in := range tx.TransparentInputs {
		h.Write(in.TxID[:])
		num(uint64(in.OutputIdx))
		num(in.Amount)
		blob(in.Address)
	}

	count(len(tx.TransparentOutputs))
	for _, out := range tx.TransparentOutputs {
		num(out.Amount)
		h.Write(out.AssetID[:])
		blob(out.Address)
	}

	count(len(tx.Nullifiers))
	for _, nullifier := range tx.Nullifiers {
		blob(nullifier)
	}

	count(len(tx.Outputs))
	for _, output := range tx.Outputs {
		blob(output.Commitment)
		blob(output.EncryptedNote)
		blob(output.EphemeralPubKey)
		blob(output.OutputProof)
	}

	present(tx.Proof != nil)
	if tx.Proof != nil {
		blob([]byte(tx.Proof.ProofType))
		blob(tx.Proof.ProofData)
		count(len(tx.Proof.PublicInputs))
		for _, input := range tx.Proof.PublicInputs {
			blob(input)
		}
	}

	num(tx.Fee)
	num(tx.Expiry)
	blob(tx.Memo)

	return ids.ID(h.Sum(nil))
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

	// A transaction names the height it stops being valid at. Without one it
	// sits in a bounded pool forever: it can never enter a block, nothing
	// evicts it, and once the pool is full of them every honest arrival paying
	// the same floor is refused.
	if tx.Expiry == 0 {
		return errNoExpiry
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

var (
	errInvalidTransactionType     = errors.New("invalid transaction type")
	errNoInputs                   = errors.New("transaction has no inputs")
	errNoOutputs                  = errors.New("transaction has no outputs")
	errMissingProof               = errors.New("transaction missing proof")
	errNoExpiry                   = errors.New("transaction names no expiry height")
	errExpired                    = errors.New("transaction has expired")
	errInvalidTransferTransaction = errors.New("invalid transfer transaction")
	errInvalidShieldTransaction   = errors.New("invalid shield transaction")
	errInvalidUnshieldTransaction = errors.New("invalid unshield transaction")
)
