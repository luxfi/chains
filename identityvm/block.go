// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

var _ chain.Block = (*Block)(nil)

// Block represents a block in the IdentityVM chain
type Block struct {
	ParentID_      ids.ID             `json:"parentId"`
	BlockHeight    uint64             `json:"height"`
	BlockTimestamp int64              `json:"timestamp"`
	Credentials    []*Credential      `json:"credentials"`
	Revocations    []*RevocationEntry `json:"revocations,omitempty"`
	Identities     []*Identity        `json:"identities,omitempty"`
	StateRoot      []byte             `json:"stateRoot"`

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

// computeID computes the block ID as the hash of the canonical ZAP wire.
// The wire commits to every block field, so identical logical blocks yield
// identical IDs and any field change moves the ID.
func (b *Block) computeID() ids.ID {
	return ids.ID(sha256.Sum256(b.Bytes()))
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

	// The credential must be unexpired AS OF THIS BLOCK. Comparing against the
	// wall clock would make the verdict depend on when a node happens to verify:
	// the same block is valid before the expiry and invalid after it, and a node
	// replaying history during bootstrap rejects every block whose credentials
	// have since expired. The block timestamp is the only clock every node agrees
	// on, and Verify has already bounded it against the parent and local time.
	if time.Unix(b.BlockTimestamp, 0).After(cred.ExpirationDate) {
		return errors.New("credential already expired")
	}

	return nil
}

// Accept applies the block. The store commits everything below in one batch,
// so a credential that cannot be written takes the whole block with it rather
// than leaving the chain holding half of one.
func (b *Block) Accept(ctx context.Context) error {
	return b.vm.chain.Accept(b)
}

// Write records every credential the block carries. The error a Put returns
// used to be dropped here, which meant a credential silently missing from the
// database while the chain went on believing the block had been applied.
func (b *Block) Write(db database.Database) error {
	for _, cred := range b.Credentials {
		if err := db.Put(credentialKey(cred.ID), marshalCredential(cred)); err != nil {
			return err
		}
	}
	return nil
}

// Publish makes the block's effects visible: the credentials it carries, the
// revocations it applies, the identities it introduces, and the block's own
// status. It runs after the commit, so nothing here can be believed and then
// lost — which is what setting them first did.
func (b *Block) Publish() {
	vm := b.vm

	for _, cred := range b.Credentials {
		vm.credentials[cred.ID] = cred
	}
	for _, rev := range b.Revocations {
		vm.revocations[rev.CredentialID] = rev
		if cred, ok := vm.credentials[rev.CredentialID]; ok {
			cred.Status = CredentialRevoked
		}
	}
	for _, identity := range b.Identities {
		vm.identities[identity.ID] = identity
	}

	vm.pending.Drop(b.Credentials)
	b.status = choices.Accepted

	vm.log.Info("Block accepted",
		log.Uint64("height", b.BlockHeight),
		log.String("id", b.ID().String()),
		log.Int("credentials", len(b.Credentials)),
	)
}

// Reject discards the block. It wrote nothing, so there is nothing to undo;
// its credentials stay queued for a later block.
func (b *Block) Reject(ctx context.Context) error {
	b.status = choices.Rejected
	b.vm.chain.Drop(b.ID())
	return nil
}

// Bytes returns the block bytes
func (b *Block) Bytes() []byte {
	if b.bytes != nil {
		return b.bytes
	}

	bytes, err := b.Marshal()
	if err != nil {
		return nil
	}

	b.bytes = bytes
	return bytes
}
