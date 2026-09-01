// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

var _ chain.Block = (*Block)(nil)

// maxClockSkew bounds how far ahead of this node's clock a block may be
// stamped.
const maxClockSkew = 60 // seconds

var errInvalidBlock = errors.New("identityvm: invalid block")

// Block carries every state change this chain makes.
//
// It used to carry Identities and Revocations that Verify never looked at and
// Publish applied anyway — so a peer's block naming {victim's id, attacker's
// key} took over the victim's DID, and one naming any credential revoked it.
// Nothing else produced those two lists, and Write persisted neither, so the
// takeover was invisible on disk and survived until restart.
//
// Now every list is produced by this chain, verified here, written here and
// published here — and identity, issuer and revocation state reaches consensus
// at all, which it did not when the RPC wrote it straight to the base database
// on whichever node received the call.
type Block struct {
	ParentID_      ids.ID        `json:"parentId"`
	BlockHeight    uint64        `json:"height"`
	BlockTimestamp int64         `json:"timestamp"`
	Identities     []*Identity   `json:"identities,omitempty"`
	Issuers        []*Issuer     `json:"issuers,omitempty"`
	Credentials    []*Credential `json:"credentials,omitempty"`
	Revocations    []*Revocation `json:"revocations,omitempty"`

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

// computeID is the hash of the chain's binding and the block's canonical wire.
// The binding — sha256(ChainID ‖ NetworkID) — is NOT on the wire, so the same
// bytes name a different block on a different chain: two chains with an
// identical genesis config would otherwise derive the same genesis id, and one
// chain's blocks would chain onto the other's verbatim.
func (b *Block) computeID() ids.ID {
	h := sha256.New()
	h.Write(b.vm.bind[:])
	h.Write(b.Bytes())
	return ids.ID(h.Sum(nil))
}

// ParentID returns the parent block ID
func (b *Block) ParentID() ids.ID { return b.ParentID_ }

// Parent is an alias for ParentID for compatibility
func (b *Block) Parent() ids.ID { return b.ParentID_ }

// Height returns the block height
func (b *Block) Height() uint64 { return b.BlockHeight }

// Timestamp returns the block timestamp
func (b *Block) Timestamp() time.Time { return time.Unix(b.BlockTimestamp, 0) }

// Status returns the block status
func (b *Block) Status() uint8 { return uint8(b.status) }

// Bytes returns the block's canonical encoding, computed once.
func (b *Block) Bytes() []byte {
	if b.bytes == nil {
		b.bytes = b.Marshal()
	}
	return b.bytes
}

// records is how many state changes the block carries.
func (b *Block) records() int {
	return len(b.Identities) + len(b.Issuers) + len(b.Credentials) + len(b.Revocations)
}

// Verify checks the block and every record in it.
//
// Records are checked against the state the chain holds PLUS what this block
// introduces before them, so a credential may name an identity the same block
// creates, and a second record claiming the same id is refused whichever half
// of the pair it is.
func (b *Block) Verify(ctx context.Context) error {
	if b.BlockHeight == 0 && b.ParentID_ != ids.Empty {
		return fmt.Errorf("%w: genesis has no parent", errInvalidBlock)
	}
	if n := b.records(); n == 0 || n > b.vm.config.MaxRecordsPerBlock {
		return fmt.Errorf("%w: %d records, the bound is 1..%d",
			errInvalidBlock, n, b.vm.config.MaxRecordsPerBlock)
	}
	if b.BlockTimestamp > time.Now().Unix()+maxClockSkew {
		return fmt.Errorf("%w: timestamp %d is beyond the skew allowance", errInvalidBlock, b.BlockTimestamp)
	}

	if b.BlockHeight > 0 {
		parent, err := b.vm.chain.Block(b.ParentID_, b.vm.parseBlock)
		if err != nil {
			return fmt.Errorf("identityvm: parent %s: %w", b.ParentID_, err)
		}

		// The parent must be one this chain can still build on: the accepted
		// tip, or a block verified above it. Height alone is not that check —
		// a block whose parent is an OLD accepted block satisfies
		// height == parent+1 perfectly well, and accepting it rewinds the tip
		// and leaves the height index naming an orphan as the block at that
		// height to every peer that bootstraps from it.
		tip, tipHeight := b.vm.chain.Tip()
		if parent.ID() != tip && parent.BlockHeight <= tipHeight {
			return fmt.Errorf("%w: parent %s at height %d is beneath the tip at %d",
				chain.ErrNotOnTip, parent.ID(), parent.BlockHeight, tipHeight)
		}
		if b.BlockHeight != parent.BlockHeight+1 {
			return fmt.Errorf("%w: height %d does not follow parent %d",
				errInvalidBlock, b.BlockHeight, parent.BlockHeight)
		}
		// Chain time only moves forward: it is what credential expiry is
		// judged against, so a proposer free to rewind it reopens a credential
		// the chain has already let lapse.
		if b.BlockTimestamp < parent.BlockTimestamp {
			return fmt.Errorf("%w: timestamp %d precedes parent %d",
				errInvalidBlock, b.BlockTimestamp, parent.BlockTimestamp)
		}
	}

	return b.vm.check(b)
}

// Accept applies the block. The store commits everything below in one batch,
// so a record that cannot be written takes the whole block with it rather than
// leaving the chain holding half of one.
//
// It also decides, under that same lock, whether this block still extends the
// tip — which is why nothing is asked here. Asking here read the tip, released
// it, and only then asked for the lock, so a tip that moved in between was
// answered with a reading taken before it moved.
func (b *Block) Accept(ctx context.Context) error { return b.vm.chain.Accept(b) }

// Write records every change the block makes. All four kinds land here: the
// identities and revocations used to be applied in memory only, so a restart
// lost them and the node came back disagreeing with the block it had accepted.
func (b *Block) Write(db database.Database) error {
	for _, identity := range b.Identities {
		if err := db.Put(identityKey(identity.ID), marshalIdentity(identity)); err != nil {
			return err
		}
	}
	for _, issuer := range b.Issuers {
		if err := db.Put(issuerKey(issuer.ID), marshalIssuer(issuer)); err != nil {
			return err
		}
	}
	for _, cred := range b.Credentials {
		if err := db.Put(credentialKey(cred.ID), marshalCredential(cred)); err != nil {
			return err
		}
	}
	for _, rev := range b.Revocations {
		if err := db.Put(revocationKey(rev.CredentialID), marshalRevocation(rev)); err != nil {
			return err
		}
	}
	return nil
}

// Publish makes the block's effects visible in memory. It runs after the
// commit, so nothing here can be believed and then lost.
func (b *Block) Publish() {
	vm := b.vm

	for _, identity := range b.Identities {
		vm.identities[identity.ID] = identity
	}
	for _, issuer := range b.Issuers {
		vm.issuers[issuer.ID] = issuer
	}
	for _, cred := range b.Credentials {
		vm.credentials[cred.ID] = cred
	}
	for _, rev := range b.Revocations {
		vm.revocations[rev.CredentialID] = rev
	}

	vm.pending.Drop(b.changes())
	b.status = choices.Accepted

	vm.log.Info("Block accepted",
		log.Uint64("height", b.BlockHeight),
		log.String("id", b.ID().String()),
		log.Int("records", b.records()),
	)
}

// Reject discards the block. It wrote nothing, so there is nothing to undo;
// what it carried stays queued for a later block.
func (b *Block) Reject(ctx context.Context) error {
	b.status = choices.Rejected
	b.vm.chain.Drop(b.ID())
	return nil
}

// changes is the block's records back in the shape the pool holds them.
func (b *Block) changes() []*Change {
	out := make([]*Change, 0, b.records())
	for _, v := range b.Identities {
		out = append(out, &Change{Identity: v})
	}
	for _, v := range b.Issuers {
		out = append(out, &Change{Issuer: v})
	}
	for _, v := range b.Credentials {
		out = append(out, &Change{Credential: v})
	}
	for _, v := range b.Revocations {
		out = append(out, &Change{Revocation: v})
	}
	return out
}
