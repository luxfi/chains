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

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// Block is one step of the bridge chain: the transfers it settles, and where
// it sits in the sequence.
type Block struct {
	ParentID_      ids.ID           `json:"parentId"` // Field renamed to avoid method collision
	BlockHeight    uint64           `json:"height"`
	BlockTimestamp int64            `json:"timestamp"`
	BridgeRequests []*BridgeRequest `json:"bridgeRequests"`

	// Cached values
	ID_    ids.ID
	bytes  []byte
	status choices.Status
	vm     *VM

	// spend is the bridge's state as of this block, computed when it verified.
	// A child built on it starts from here; the accepted tip has it on disk
	// instead, so Publish drops it.
	spend *spend
}

var (
	errInvalidBlock = errors.New("bridgevm: invalid block")
	errFutureBlock  = errors.New("bridgevm: block timestamp is in the future")

	// maxClockSkew is how far ahead of this node's clock a block may be
	// stamped. Chain time drives the daily cap, so a proposer that could stamp
	// freely could jump the window forward and reopen the cap at will.
	maxClockSkew = int64(60)
)

// ID returns the block ID
func (b *Block) ID() ids.ID {
	if b.ID_ == ids.Empty {
		b.ID_ = b.computeID()
	}
	return b.ID_
}

// computeID calculates the block ID.
//
// The chain this block belongs to is the first thing hashed. Without it the
// same bytes name the same block on every chain that runs this VM, so a block
// built on one is a block on the other — parent ids resolve, heights line up,
// and a testnet block is a mainnet block.
func (b *Block) computeID() ids.ID {
	h := sha256.New()

	h.Write(b.vm.chainID[:])
	h.Write(b.ParentID_[:])

	var num [8]byte
	binary.BigEndian.PutUint64(num[:], b.BlockHeight)
	h.Write(num[:])

	binary.BigEndian.PutUint64(num[:], uint64(b.BlockTimestamp))
	h.Write(num[:])

	// Each request's id is the digest of the transfer it carries (Verify
	// refuses one where it is not), so hashing the ids hashes the transfers.
	for _, req := range b.BridgeRequests {
		h.Write(req.ID[:])
	}

	return ids.ID(h.Sum(nil))
}

// Accept records the block and everything it decides, in one commit.
//
// It used to credit the daily volume, complete the requests, advance
// lastAcceptedID and hand the transfers to the release worker — which
// broadcasts on an external chain — and only then write the block. A write
// that failed left every one of those done and the block missing, including a
// release already in flight for a transfer no block records.
//
// Whether this block still extends the tip is the store's to decide, under the
// lock that commits. Asking here read the tip, released it, and only then
// asked for the lock — so a tip that moved in between was answered with a
// reading taken before it moved.
func (b *Block) Accept(ctx context.Context) error { return b.vm.chain.Accept(b) }

// Write stages what this block settles: the transfers, and the day's running
// total per destination. Both land in the same commit as the block itself, so
// the cap the chain enforces is the cap the chain remembers after a restart.
func (b *Block) Write(db database.Database) error { return b.write(db) }

// Publish completes the block's transfers and hands them to the release
// worker. It runs after the commit, so an external release is only ever
// started for a transfer the chain has durably recorded.
func (b *Block) Publish() {
	b.status = choices.Accepted

	// What this block decided is on disk now, so the in-memory answer would
	// be a second copy of it.
	b.spend = nil

	for _, req := range b.BridgeRequests {
		b.vm.mu.Lock()
		delete(b.vm.pendingBridges, req.ID)
		releaser := b.vm.releaser
		b.vm.mu.Unlock()

		b.vm.log.Info("bridgevm: transfer settled",
			log.Stringer("requestID", req.ID),
			log.Uint32("dst", req.DstChainID),
			log.Uint64("amount", req.Amount),
		)

		// Hand the confirmed transfer to the release worker (relayer nodes only).
		// Non-blocking: the attestation and EVM broadcast happen off the
		// consensus path so this never waits on network I/O. Every relayer
		// broadcasts; the on-chain nonce replay-guard collapses duplicates.
		if releaser != nil {
			releaser.enqueue(req)
		}
	}
}

// Reject marks the block as rejected. Its transfers were never removed from
// the set waiting for a block, so they are proposed again rather than lost.
func (b *Block) Reject(ctx context.Context) error {
	b.status = choices.Rejected
	b.spend = nil
	b.vm.chain.Drop(b.ID())
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

// Verify decides whether this block may become part of the chain.
//
// It answers over the state as of the block's PARENT, not as of the tip: a
// block whose parent is still in flight is the ordinary shape whenever more
// than one block is in the air, and checking it against the tip would let two
// blocks in a row each spend the whole daily cap.
func (b *Block) Verify(ctx context.Context) error {
	if b.BlockHeight == 0 {
		// Genesis is given, not verified. Accepting a second one would let a
		// peer hand this chain a new beginning.
		return fmt.Errorf("%w: height 0 is genesis", errInvalidBlock)
	}
	if len(b.BridgeRequests) == 0 {
		return fmt.Errorf("%w: carries no transfers", errInvalidBlock)
	}
	if len(b.BridgeRequests) > maxRequestsPerBlock {
		return fmt.Errorf("%w: %d transfers over the %d cap",
			errInvalidBlock, len(b.BridgeRequests), maxRequestsPerBlock)
	}

	parent, err := b.vm.chain.Block(b.ParentID_, b.vm.parseBlock)
	if err != nil {
		return fmt.Errorf("bridgevm: parent %s: %w", b.ParentID_, err)
	}
	tip, tipHeight := b.vm.chain.Tip()
	if parent.ID() != tip {
		// A parent below the accepted tip is a block the chain has already
		// built past. Building on it rewinds the chain, and the height index
		// then names an orphan as the block at that height.
		if parent.Height() <= tipHeight {
			return fmt.Errorf("%w: parent %s at height %d is beneath the tip at %d",
				errInvalidBlock, parent.ID(), parent.Height(), tipHeight)
		}
		// A parent still in flight carries the state it decided. One that
		// carries none is a block this node never checked, and guessing what
		// it spent is how a chain accepts a block it cannot account for.
		if parent.spend == nil {
			return fmt.Errorf("%w: parent %s has not been verified here",
				errInvalidBlock, parent.ID())
		}
	}
	if b.BlockHeight != parent.Height()+1 {
		return fmt.Errorf("%w: height %d does not follow parent %d",
			errInvalidBlock, b.BlockHeight, parent.Height())
	}
	// Chain time only moves forward. It drives the daily window, so a proposer
	// free to rewind it reopens a cap that has already been spent.
	if b.BlockTimestamp < parent.BlockTimestamp {
		return fmt.Errorf("%w: timestamp %d precedes parent %d",
			errInvalidBlock, b.BlockTimestamp, parent.BlockTimestamp)
	}
	if b.BlockTimestamp > time.Now().Unix()+maxClockSkew {
		return fmt.Errorf("%w: timestamp %d is more than %ds ahead",
			errFutureBlock, b.BlockTimestamp, maxClockSkew)
	}

	state := b.vm.spendAt(parent)
	day := b.BlockTimestamp / dayLength
	for _, req := range b.BridgeRequests {
		// admit records each transfer as it goes, so a block carrying the same
		// one twice fails on the second: the first has already been recorded
		// settled, in this same state.
		if err := state.admit(&b.vm.config, day, req); err != nil {
			return err
		}
	}
	b.spend = state

	// A block that verifies is one the engine may build on, so it has to be
	// findable by id — including one parsed from a peer rather than built
	// here. Tracking only self-built blocks left a follower able to verify the
	// first block of a run and unable to verify the second, which is the
	// ordinary shape whenever more than one block is in flight.
	b.vm.chain.Track(b)
	return nil
}

// Height returns the block height
func (b *Block) Height() uint64 {
	return b.BlockHeight
}

// Timestamp returns the block timestamp
func (b *Block) Timestamp() time.Time {
	return time.Unix(b.BlockTimestamp, 0)
}

// Bytes returns the block's encoding, computed once.
func (b *Block) Bytes() []byte {
	if b.bytes == nil {
		b.bytes = b.Marshal()
	}
	return b.bytes
}

var _ chain.Block = (*Block)(nil)
