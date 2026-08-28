// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/ids"
)

var (
	errBlockVerificationFailed = errors.New("quantumvm: block transaction signatures failed verification")
	errInvalidBlockHeight      = errors.New("quantumvm: invalid block height")
	errInvalidParentID         = errors.New("quantumvm: parent block not found")
	errTimeBeforeParent        = errors.New("quantumvm: block timestamp precedes its parent")
	errTimeTooFarAhead         = errors.New("quantumvm: block timestamp is beyond the skew allowance")
)

// MaxFutureSkew is how far ahead of the verifying node's clock a proposer may
// stamp a block. Chain time is what the quantum stamp window is measured
// against, so an uncapped timestamp lets one proposer expire every stamp in
// flight by jumping forward, or revive expired ones by rewinding.
const MaxFutureSkew = 60 * time.Second

// Block represents a QVM block with quantum features
type Block struct {
	id           ids.ID
	timestamp    time.Time
	height       uint64
	parentID     ids.ID
	transactions []Transaction
	vm           *VM
	bytes        []byte
}

// ID returns the block ID
func (b *Block) ID() ids.ID {
	return b.id
}

// Accept persists the block and advances the tip. Every write lands in one
// versiondb commit: the block, its height index and the last-accepted pointer
// move together or not at all. A failure anywhere rolls the whole set back, so
// a node never restarts holding a tip pointer to a block it did not store.
//
// Nothing is dropped from the mempool until the commit succeeds. Evicting
// first would lose the transactions of a block that then failed to persist.
func (b *Block) Accept(ctx context.Context) error {
	b.vm.lock.Lock()
	defer b.vm.lock.Unlock()

	if err := b.vm.commitBlock(b); err != nil {
		return err
	}

	for _, tx := range b.transactions {
		if err := b.vm.txPool.RemoveTransaction(tx.ID()); err != nil {
			b.vm.log.Error("failed to remove tx from pool", "txID", tx.ID(), "error", err)
		}
	}

	b.vm.log.Info("block accepted",
		"blockID", b.id,
		"height", b.height,
		"txCount", len(b.transactions),
	)

	return nil
}

// Reject discards the block. Its transactions are still in the mempool —
// BuildBlock copies from the queue rather than draining it, and only Accept
// removes anything — so there is nothing to give back, and nothing is lost when
// the engine drops a block it never rejects either.
func (b *Block) Reject(context.Context) error {
	b.vm.log.Debug("block rejected", "blockID", b.id, "height", b.height)
	return nil
}

// Verify decides whether the block may be built on, without changing any state.
//
// It sits on its parent in both height and time. Checking only that the parent
// EXISTS lets a proposer pick height and timestamp freely: it can name genesis
// as the parent of a height-500 block, rewind chain time to revive expired
// quantum stamps, or jump forward and expire every stamp in flight at once.
func (b *Block) Verify(ctx context.Context) error {
	b.vm.lock.RLock()
	defer b.vm.lock.RUnlock()

	// Genesis is written by the VM, never proposed.
	if b.height == 0 {
		return errInvalidBlockHeight
	}

	// blockAt, not vm.GetBlock: GetBlock takes the same read lock this
	// function already holds, and a writer arriving between the two
	// acquisitions blocks the second one forever — Go's RWMutex queues a
	// pending Lock ahead of later RLocks, so a recursive read lock is a
	// deadlock, not a no-op.
	parent, err := b.vm.blockAt(b.parentID)
	if err != nil {
		return fmt.Errorf("%w: %s", errInvalidParentID, b.parentID)
	}
	if b.height != parent.height+1 {
		return fmt.Errorf("%w: %d does not follow parent %d",
			errInvalidBlockHeight, b.height, parent.height)
	}
	if b.timestamp.Before(parent.timestamp) {
		return fmt.Errorf("%w: %d precedes %d",
			errTimeBeforeParent, b.timestamp.Unix(), parent.timestamp.Unix())
	}
	if b.timestamp.After(b.vm.clock.Time().Add(MaxFutureSkew)) {
		return fmt.Errorf("%w: %d exceeds now+%s",
			errTimeTooFarAhead, b.timestamp.Unix(), MaxFutureSkew)
	}

	if len(b.transactions) > 0 && b.vm.Config.CoronaEnabled {
		msgs := make([][]byte, len(b.transactions))
		sigs := make([]*quantum.QuantumSignature, len(b.transactions))
		for i, tx := range b.transactions {
			msgs[i] = tx.Bytes()
			sigs[i] = tx.GetQuantumSignature()
		}
		if err := b.vm.quantumSigner.ParallelVerify(msgs, sigs); err != nil {
			return fmt.Errorf("%w: %w", errBlockVerificationFailed, err)
		}
	}

	return nil
}

// Parent returns the parent block ID
func (b *Block) Parent() ids.ID {
	return b.parentID
}

// ParentID returns the parent block ID (implements consensus Block interface)
func (b *Block) ParentID() ids.ID {
	return b.parentID
}

// Height returns the block height
func (b *Block) Height() uint64 {
	return b.height
}

// Timestamp returns the block timestamp (implements block.Block interface)
func (b *Block) Timestamp() time.Time {
	return b.timestamp
}

// TimestampUnix returns the block timestamp as Unix seconds.
func (b *Block) TimestampUnix() int64 {
	return b.timestamp.Unix()
}

// Status reports 0 while the block is only proposed and 1 once it is stored.
// A stored block is an accepted one: Accept is the only writer, and it commits
// the block and the tip pointer together.
func (b *Block) Status() uint8 {
	b.vm.lock.RLock()
	defer b.vm.lock.RUnlock()
	if ok, err := b.vm.state.Has(b.id[:]); err == nil && ok {
		return 1
	}
	return 0
}

// String returns a string representation of the block
func (b *Block) String() string {
	return b.id.String()
}
