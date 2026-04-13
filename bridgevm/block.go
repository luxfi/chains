// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
)

// Block represents a block in the Bridge chain
type Block struct {
	ParentID_      ids.ID           `json:"parentId"` // Field renamed to avoid method collision
	BlockHeight    uint64           `json:"height"`
	BlockTimestamp int64            `json:"timestamp"`
	BridgeRequests []*BridgeRequest `json:"bridgeRequests"`

	// MPC signatures for this block (NodeID -> signature bytes)
	MPCSignatures map[ids.NodeID][]byte `json:"mpcSignatures"`

	// Cached values
	ID_    ids.ID
	bytes  []byte
	status choices.Status
	vm     *VM
}

var (
	errInvalidBlock = errors.New("invalid block")
	errFutureBlock  = errors.New("block timestamp is in the future")

	maxClockSkew = int64(60) // 60 seconds
)

// ID returns the block ID
func (b *Block) ID() ids.ID {
	if b.ID_ == ids.Empty {
		b.ID_ = b.computeID()
	}
	return b.ID_
}

// computeID calculates the block ID
func (b *Block) computeID() ids.ID {
	h := sha256.New()

	h.Write(b.ParentID_[:])

	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, b.BlockHeight)
	h.Write(heightBytes)

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(b.BlockTimestamp))
	h.Write(timestampBytes)

	// Include bridge requests in hash
	for _, req := range b.BridgeRequests {
		h.Write(req.ID[:])
	}

	return ids.ID(h.Sum(nil))
}

// Accept marks the block as accepted
func (b *Block) Accept(ctx context.Context) error {
	b.vm.mu.Lock()
	defer b.vm.mu.Unlock()

	// Process bridge requests
	for _, req := range b.BridgeRequests {
		// Update bridge registry
		b.vm.bridgeRegistry.mu.Lock()

		completed := &CompletedBridge{
			RequestID:   req.ID,
			SourceTxID:  req.SourceTxID,
			CompletedAt: time.Now(),
		}

		// Collect MPC signatures
		if len(req.MPCSignatures) > 0 {
			completed.MPCSignature = req.MPCSignatures[0] // Use aggregated signature
		}

		b.vm.bridgeRegistry.CompletedBridges[req.ID] = completed

		// Update daily volume
		volume := b.vm.bridgeRegistry.DailyVolume[req.DestChain]
		b.vm.bridgeRegistry.DailyVolume[req.DestChain] = volume + req.Amount

		b.vm.bridgeRegistry.mu.Unlock()

		// Remove from pending
		delete(b.vm.pendingBridges, req.ID)

		b.vm.log.Info("completed bridge request",
			log.Stringer("requestID", req.ID),
			log.String("destChain", req.DestChain),
			log.Uint64("amount", req.Amount),
		)
	}

	// Update state
	b.status = choices.Accepted
	b.vm.lastAcceptedID = b.ID()

	// Remove from pending blocks
	delete(b.vm.pendingBlocks, b.ID())

	// Persist block
	return b.vm.putBlock(b)
}

// Reject marks the block as rejected
func (b *Block) Reject(ctx context.Context) error {
	b.vm.mu.Lock()
	defer b.vm.mu.Unlock()

	b.status = choices.Rejected
	delete(b.vm.pendingBlocks, b.ID())

	return nil
}

// Status returns the block's status
func (b *Block) Status() uint8 {
	return uint8(b.status)
}

// ParentID returns the parent block ID
func (b *Block) ParentID() ids.ID {
	return b.ParentID_
}

// Parent returns the parent block (for block.Block interface compatibility)
func (b *Block) Parent() ids.ID {
	return b.ParentID_
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

	// Verify each bridge request: confirmations, amounts, daily limits
	for _, req := range b.BridgeRequests {
		if req.Confirmations < b.vm.config.MinConfirmations {
			return fmt.Errorf("insufficient confirmations for request %s: %d < %d",
				req.ID, req.Confirmations, b.vm.config.MinConfirmations)
		}

		if req.Amount > b.vm.config.MaxBridgeAmount {
			return fmt.Errorf("bridge amount exceeds maximum: %d > %d",
				req.Amount, b.vm.config.MaxBridgeAmount)
		}

		b.vm.bridgeRegistry.mu.RLock()
		dailyVolume := b.vm.bridgeRegistry.DailyVolume[req.DestChain]
		b.vm.bridgeRegistry.mu.RUnlock()

		if dailyVolume+req.Amount > b.vm.config.DailyBridgeLimit {
			return fmt.Errorf("would exceed daily bridge limit for chain %s", req.DestChain)
		}
	}

	// Batch verify MPC request signatures (GPU-accelerated when available)
	if b.vm.mpcConfig != nil {
		sigErrors := batchVerifyRequestSignaturesGPU(b.BridgeRequests, b.vm.mpcConfig, b.vm.log)
		for i, err := range sigErrors {
			if err != nil {
				return fmt.Errorf("MPC signature verification failed for request %s: %w",
					b.BridgeRequests[i].ID, err)
			}
		}
	} else {
		// No MPC config: verify individually (original path)
		for _, req := range b.BridgeRequests {
			if len(req.MPCSignatures) > 0 {
				if err := b.verifyRequestMPCSignatures(req); err != nil {
					return fmt.Errorf("MPC signature verification failed for request %s: %w", req.ID, err)
				}
			}
		}
	}

	// Verify MPC block signatures using threshold ECDSA.
	// Uses GPU-accelerated batch verification when available and multiple sigs exist.
	blockHash := b.ID()
	validSignatures := batchVerifyBlockSignatures(blockHash, b.MPCSignatures, b.vm.mpcConfig, b.vm.log)

	// For threshold signature, we only need 1 valid aggregated signature
	// (the signature itself is produced by t+1 parties collaboratively)
	if len(b.MPCSignatures) > 0 && validSignatures < 1 {
		return fmt.Errorf("no valid MPC signature found")
	}

	return nil
}

// deserializeSignature deserializes signature bytes into an ecdsa.Signature
func deserializeSignature(group curve.Curve, data []byte) (*ecdsa.Signature, error) {
	if len(data) < 64 {
		return nil, errors.New("signature too short")
	}

	// Create empty signature for this curve
	sig := ecdsa.EmptySignature(group)

	// Unmarshal R point (first 33 bytes for compressed, or 65 for uncompressed)
	// For simplicity, assume first half is R, second half is S
	rLen := len(data) / 2
	if err := sig.R.UnmarshalBinary(data[:rLen]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal R: %w", err)
	}

	if err := sig.S.UnmarshalBinary(data[rLen:]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal S: %w", err)
	}

	return &sig, nil
}

// verifyRequestMPCSignatures verifies MPC threshold signatures on a bridge request
// using the CMP ECDSA protocol. The aggregated signature is verified against the
// group public key derived from Lagrange interpolation of public shares.
func (b *Block) verifyRequestMPCSignatures(req *BridgeRequest) error {
	if b.vm.mpcConfig == nil {
		return errors.New("MPC config not initialized")
	}

	// Get the group public key using Lagrange interpolation
	groupPublicKey := b.vm.mpcConfig.PublicPoint()
	if groupPublicKey == nil {
		return errors.New("failed to compute group public key")
	}

	// Compute message hash for verification (request ID serves as unique identifier)
	messageHash := computeRequestHash(req)

	// For threshold ECDSA, we verify the single aggregated signature
	// produced by t+1 parties against the combined group public key
	if len(req.MPCSignatures) == 0 {
		return errors.New("no MPC signatures present")
	}

	// The aggregated threshold signature (produced by CMP sign protocol)
	// is stored as the first entry in MPCSignatures
	aggregatedSigBytes := req.MPCSignatures[0]

	// Deserialize the ECDSA signature
	sig, err := deserializeSignature(b.vm.mpcConfig.Group, aggregatedSigBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize aggregated signature: %w", err)
	}

	// Verify the signature against the group public key
	if !sig.Verify(groupPublicKey, messageHash) {
		return errors.New("aggregated MPC signature verification failed")
	}

	return nil
}

// computeRequestHash computes a deterministic hash of a bridge request for signing
func computeRequestHash(req *BridgeRequest) []byte {
	h := sha256.New()
	h.Write(req.ID[:])
	h.Write([]byte(req.SourceChain))
	h.Write([]byte(req.DestChain))
	h.Write(req.Asset[:])

	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, req.Amount)
	h.Write(amountBytes)

	h.Write(req.Recipient)
	h.Write(req.SourceTxID[:])

	return h.Sum(nil)
}

// Height returns the block height
func (b *Block) Height() uint64 {
	return b.BlockHeight
}

// Timestamp returns the block timestamp
func (b *Block) Timestamp() time.Time {
	return time.Unix(b.BlockTimestamp, 0)
}

// Bytes returns the block bytes
func (b *Block) Bytes() []byte {
	if b.bytes != nil {
		return b.bytes
	}

	bytes, err := Codec.Marshal(codecVersion, b)
	if err != nil {
		return nil
	}

	b.bytes = bytes
	return bytes
}
