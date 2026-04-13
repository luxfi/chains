// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// Block represents a block in the IdentityVM chain
type Block struct {
	ParentID_      ids.ID          `json:"parentId"`
	BlockHeight    uint64          `json:"height"`
	BlockTimestamp int64           `json:"timestamp"`
	Credentials    []*Credential   `json:"credentials"`
	Revocations    []*RevocationEntry `json:"revocations,omitempty"`
	Identities     []*Identity     `json:"identities,omitempty"`
	StateRoot      []byte          `json:"stateRoot"`

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

	// Include credential IDs
	for _, cred := range b.Credentials {
		credID := cred.ID
		h.Write(credID[:])
	}

	// Include revocation IDs
	for _, rev := range b.Revocations {
		h.Write(rev.CredentialID[:])
	}

	// Include identity IDs
	for _, identity := range b.Identities {
		h.Write(identity.ID[:])
	}

	// Include state root
	h.Write(b.StateRoot)

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
	// Verify height
	if b.BlockHeight == 0 && b.ParentID_ != ids.Empty {
		return errors.New("invalid genesis block")
	}

	// Verify timestamp is not too far in future
	if b.BlockTimestamp > time.Now().Unix()+60 {
		return errors.New("block timestamp too far in future")
	}

	// Verify parent exists and heights are consecutive
	if b.BlockHeight > 0 {
		parent, err := b.vm.GetBlock(ctx, b.ParentID_)
		if err != nil {
			return err
		}

		if b.BlockHeight != parent.Height()+1 {
			return errors.New("non-consecutive block heights")
		}

		if b.BlockTimestamp < parent.Timestamp().Unix() {
			return errors.New("block timestamp before parent")
		}
	}

	// Verify all credentials
	for _, cred := range b.Credentials {
		if err := b.verifyCredential(cred); err != nil {
			return err
		}
	}

	return nil
}

func (b *Block) verifyCredential(cred *Credential) error {
	// Verify issuer exists
	_, err := b.vm.GetIssuer(cred.Issuer)
	if err != nil && !b.vm.config.AllowSelfIssue {
		return err
	}

	// Verify claims count
	if len(cred.Claims) > b.vm.config.MaxClaims {
		return errors.New("too many claims")
	}

	// Verify expiration is in future
	if time.Now().After(cred.ExpirationDate) {
		return errors.New("credential already expired")
	}

	return nil
}

// Accept accepts the block
func (b *Block) Accept(ctx context.Context) error {
	b.status = choices.Accepted

	b.vm.mu.Lock()
	defer b.vm.mu.Unlock()

	// Update VM state
	b.vm.lastAccepted = b
	b.vm.lastAcceptedID = b.ID()

	// Save last accepted
	id := b.ID()
	if err := b.vm.db.Put(lastAcceptedKey, id[:]); err != nil {
		return err
	}

	// Save block
	blockBytes := b.Bytes()
	if blockBytes == nil {
		return errors.New("failed to serialize block")
	}

	if err := b.vm.db.Put(id[:], blockBytes); err != nil {
		return err
	}

	// Process credentials
	for _, cred := range b.Credentials {
		b.vm.credentials[cred.ID] = cred

		// Persist credential
		credBytes, _ := json.Marshal(cred)
		credKey := append(credentialPrefix, cred.ID[:]...)
		b.vm.db.Put(credKey, credBytes)

		// Remove from pending
		for i, pending := range b.vm.pendingCreds {
			if pending.ID == cred.ID {
				b.vm.pendingCreds = append(b.vm.pendingCreds[:i], b.vm.pendingCreds[i+1:]...)
				break
			}
		}
	}

	// Process revocations
	for _, rev := range b.Revocations {
		b.vm.revocations[rev.CredentialID] = rev

		// Update credential status
		if cred, ok := b.vm.credentials[rev.CredentialID]; ok {
			cred.Status = CredentialRevoked
		}
	}

	// Process new identities
	for _, identity := range b.Identities {
		b.vm.identities[identity.ID] = identity
	}

	// Remove from pending blocks
	delete(b.vm.pendingBlocks, b.ID())

	b.vm.log.Info("Block accepted",
		log.Uint64("height", b.BlockHeight),
		log.String("id", b.ID().String()),
		log.Int("credentials", len(b.Credentials)),
	)

	return nil
}

// Reject rejects the block
func (b *Block) Reject(ctx context.Context) error {
	b.status = choices.Rejected

	b.vm.mu.Lock()
	defer b.vm.mu.Unlock()

	// Remove from pending blocks
	delete(b.vm.pendingBlocks, b.ID())

	return nil
}

// Bytes returns the block bytes
func (b *Block) Bytes() []byte {
	if b.bytes != nil {
		return b.bytes
	}

	bytes, err := json.Marshal(b)
	if err != nil {
		return nil
	}

	b.bytes = bytes
	return bytes
}
