// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"github.com/luxfi/log"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

var _ chain.Block = (*Block)(nil)

// Block represents a block in the ZK UTXO chain
type Block struct {
	ParentID_      ids.ID         `json:"parentId"`
	BlockHeight    uint64         `json:"height"`
	BlockTimestamp int64          `json:"timestamp"`
	Txs            []*Transaction `json:"transactions"`
	StateRoot      []byte         `json:"stateRoot"` // Merkle tree root of UTXO set

	// Aggregated proof for the block (optional)
	BlockProof *ZKProof `json:"blockProof,omitempty"`

	// Cached values
	ID_    ids.ID
	bytes  []byte
	status choices.Status
	vm     *VM
}

// ID returns the block ID
func (b *Block) ID() ids.ID {
	if b.ID_ == ids.Empty {
		b.ID_ = b.computeID()
	}
	return b.ID_
}

// computeID computes the block ID
func (b *Block) computeID() ids.ID {
	h := sha256.New()
	h.Write(b.ParentID_[:])
	binary.Write(h, binary.BigEndian, b.BlockHeight)
	binary.Write(h, binary.BigEndian, b.BlockTimestamp)

	// Include transaction IDs
	for _, tx := range b.Txs {
		txID := tx.ID
		if txID == ids.Empty {
			txID = tx.ComputeID()
		}
		h.Write(txID[:])
	}

	// Include state root
	h.Write(b.StateRoot)

	// Include block proof if present
	if b.BlockProof != nil {
		h.Write([]byte(b.BlockProof.ProofType))
		h.Write(b.BlockProof.ProofData)
	}

	return ids.ID(h.Sum(nil))
}

// ParentID returns the parent block ID
func (b *Block) ParentID() ids.ID {
	return b.ParentID_
}

// Parent is an alias for ParentID for compatibility
func (b *Block) Parent() ids.ID {
	return b.ParentID_
}

// Height returns the block height
func (b *Block) Height() uint64 {
	return b.BlockHeight
}

// Timestamp returns the block timestamp
func (b *Block) Timestamp() time.Time {
	return time.Unix(b.BlockTimestamp, 0)
}

// Status returns the block status
func (b *Block) Status() uint8 {
	return uint8(b.status)
}

// Verify verifies the block
func (b *Block) Verify(ctx context.Context) error {
	// Basic validation
	if b.BlockHeight == 0 && b.ParentID_ != ids.Empty {
		return errInvalidBlock
	}

	// Verify timestamp
	if b.BlockTimestamp > time.Now().Unix()+maxClockSkew {
		return errFutureBlock
	}

	// Block-level shape: every nullifier in the block must be distinct.
	// verifyTransaction below only sees nullifiers already spent in ACCEPTED
	// state, so without this two txs in one block — or one tx listing a nullifier
	// twice — spend the same shielded note and inflate supply. Checked before the
	// proofs because it is the cheaper gate.
	spentHere := make(map[string]struct{}, len(b.Txs))
	for _, tx := range b.Txs {
		for _, nullifier := range tx.Nullifiers {
			if _, dup := spentHere[string(nullifier)]; dup {
				return errDuplicateNullifier
			}
			spentHere[string(nullifier)] = struct{}{}
		}
	}

	// Verify each transaction
	for _, tx := range b.Txs {
		if err := tx.ValidateBasic(); err != nil {
			return err
		}

		// Verify transaction proof
		if err := b.vm.verifyTransaction(tx); err != nil {
			return err
		}
	}

	// Verify block proof if present
	if b.BlockProof != nil {
		if err := b.vm.proofVerifier.VerifyBlockProof(b); err != nil {
			return err
		}
	}

	// Verify against parent
	if b.BlockHeight > 0 {
		parent, err := b.vm.GetBlock(ctx, b.ParentID_)
		if err != nil {
			return err
		}

		parentBlock, ok := parent.(*Block)
		if !ok {
			return errors.New("invalid parent block type")
		}

		if b.BlockHeight != parentBlock.BlockHeight+1 {
			return errInvalidHeight
		}

		if b.BlockTimestamp < parentBlock.BlockTimestamp {
			return errInvalidTimestamp
		}
	}

	// Verify state root
	if !bytes.Equal(b.StateRoot, b.vm.computeStateRoot(b.Txs)) {
		return errInvalidStateRoot
	}

	return nil
}

// Accept applies the block. Everything below is staged and committed in one
// batch with the block and the tip, so a spend that cannot be recorded takes
// the whole block with it.
//
// This used to mark the block accepted and move lastAccepted before writing
// anything, then issue a Put per nullifier and per output, each returning
// early. A failure partway left some notes spent and some outputs created,
// under a tip the chain had already advanced — a shielded pool half applied,
// with no way back and no way to apply the block again.
func (b *Block) Accept(ctx context.Context) error {
	return b.vm.chain.Accept(b)
}

// Write records the block's spends and its outputs, and advances the committed
// state root. The three stores were built over this same view at Initialize,
// so what they write here commits with the block or not at all.
func (b *Block) Write(database.Database) error {
	for _, tx := range b.Txs {
		for _, nullifier := range tx.Nullifiers {
			if err := b.vm.nullifierDB.MarkNullifierSpent(nullifier, b.BlockHeight); err != nil {
				return err
			}
		}
		for i, output := range tx.Outputs {
			if err := b.vm.utxoDB.AddUTXO(&UTXO{
				TxID:        tx.ID,
				OutputIndex: uint32(i),
				Commitment:  output.Commitment,
				Ciphertext:  output.EncryptedNote,
				EphemeralPK: output.EphemeralPubKey,
				Height:      b.BlockHeight,
			}); err != nil {
				return err
			}
		}
	}
	return b.vm.stateTree.Finalize(b.StateRoot)
}

// Publish marks the block accepted and releases the transactions it carried.
// It runs after the commit, so a transaction is only dropped from the mempool
// once the block that spends it is durable.
func (b *Block) Publish() {
	b.status = choices.Accepted
	for _, tx := range b.Txs {
		b.vm.mempool.RemoveTransaction(tx.ID)
	}

	b.vm.log.Info("Block accepted",
		log.Uint64("height", b.BlockHeight),
		log.String("id", b.ID().String()),
		log.Int("txCount", len(b.Txs)),
	)
}

// Reject rejects the block
func (b *Block) Reject(ctx context.Context) error {
	b.status = choices.Rejected
	b.vm.chain.Drop(b.ID())

	// Return transactions to mempool
	for _, tx := range b.Txs {
		b.vm.mempool.AddTransaction(tx)
	}

	return nil
}

// Bytes returns the block bytes
func (b *Block) Bytes() []byte {
	if b.bytes != nil {
		return b.bytes
	}

	bytes, err := b.Marshal()
	if err != nil {
		// Log error and return nil
		return nil
	}

	b.bytes = bytes
	return bytes
}

// Genesis represents genesis data
type Genesis struct {
	Timestamp  int64          `json:"timestamp"`
	InitialTxs []*Transaction `json:"initialTransactions,omitempty"`

	// Initial setup parameters
	SetupParams *SetupParams `json:"setupParams,omitempty"`
}

// SetupParams contains trusted setup parameters
type SetupParams struct {
	// Groth16 CRS
	PowersOfTau  []byte `json:"powersOfTau,omitempty"`
	VerifyingKey []byte `json:"verifyingKey,omitempty"`

	// PLONK setup
	PlonkSRS []byte `json:"plonkSRS,omitempty"`

	// FHE parameters
	FHEPublicParams []byte `json:"fhePublicParams,omitempty"`
}

// ParseGenesis parses genesis bytes (supports both JSON and Codec formats)
func ParseGenesis(genesisBytes []byte) (*Genesis, error) {
	var genesis Genesis
	if len(genesisBytes) > 0 {
		// Try JSON first (simple genesis)
		if err := json.Unmarshal(genesisBytes, &genesis); err != nil {
			return nil, err
		}
	}

	if genesis.Timestamp == 0 {
		genesis.Timestamp = time.Now().Unix()
	}

	return &genesis, nil
}

// BlockSummary represents a lightweight block summary
type BlockSummary struct {
	ID        ids.ID `json:"id"`
	Height    uint64 `json:"height"`
	Timestamp int64  `json:"timestamp"`
	TxCount   int    `json:"txCount"`
	StateRoot []byte `json:"stateRoot"`
}

// ToSummary converts a block to a summary
func (b *Block) ToSummary() *BlockSummary {
	return &BlockSummary{
		ID:        b.ID(),
		Height:    b.BlockHeight,
		Timestamp: b.BlockTimestamp,
		TxCount:   len(b.Txs),
		StateRoot: b.StateRoot,
	}
}

const (
	maxClockSkew = 60 // seconds
)

var (
	errInvalidBlock     = errors.New("invalid block")
	errFutureBlock      = errors.New("block timestamp too far in future")
	errInvalidHeight    = errors.New("invalid block height")
	errInvalidTimestamp = errors.New("invalid block timestamp")
	errInvalidStateRoot = errors.New("invalid state root")

	// errDuplicateNullifier — the same nullifier appears twice inside one block or
	// vertex, i.e. one shielded note spent twice. Fail closed.
	errDuplicateNullifier = errors.New("nullifier spent twice in one block")
)
