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
	errEmptyBlock              = errors.New("quantumvm: block carries no transactions")
	errForeignChain            = errors.New("quantumvm: block belongs to another chain")
	errExecute                 = errors.New("quantumvm: block transaction could not be applied")
)

// MaxFutureSkew is how far ahead of the verifying node's clock a proposer may
// stamp a block. Peers' clocks differ, and this is the allowance for that; an
// uncapped timestamp is a proposer writing chain time, which is what decides
// whether the NEXT block may be stamped at all.
const MaxFutureSkew = 60 * time.Second

// Block represents a QVM block with quantum features
type Block struct {
	id           ids.ID
	timestamp    time.Time
	height       uint64
	parentID     ids.ID
	chainID      ids.ID
	networkID    uint32
	transactions []Transaction
	vm           *VM
	bytes        []byte
}

// ID returns the block ID
func (b *Block) ID() ids.ID {
	return b.id
}

// Accept makes the block the tip: commitBlock admits it, applies it and
// persists it as one step.
//
// Nothing is dropped from the mempool until that succeeds. Evicting first would
// lose the transactions of a block that then failed to persist.
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

// Reject discards the block. Nothing ran — execution belongs to Accept — and
// its transactions are still in the mempool, because BuildBlock copies from the
// queue rather than draining it and only Accept removes anything. So there is
// nothing to undo and nothing to give back.
func (b *Block) Reject(context.Context) error {
	b.vm.log.Debug("block rejected", "blockID", b.id, "height", b.height)
	return nil
}

// apply runs the block's transactions.
//
// They ran at BUILD time. A builder that executed them applied the effects of a
// block the network may never accept, applied them a second time when it
// rebuilt, and applied nothing at all on every node that received the block
// instead of building it — which is every node but one, for every block. They
// run where the block becomes the tip, on every node, exactly once.
//
// A transaction that cannot be applied stops the block. A node that cannot
// apply an agreed block stops rather than committing a chain its state no
// longer matches.
func (b *Block) apply() error {
	for _, tx := range b.transactions {
		if err := tx.Execute(); err != nil {
			return fmt.Errorf("%w %s in block %s: %w", errExecute, tx.ID(), b.id, err)
		}
	}
	return nil
}

// onThisChain refuses a block that names another chain or another network.
//
// Nothing else in the wire is chain-specific, and genesis is a constant, so
// without this every Q-Chain in existence shares a genesis id and a block built
// on one is a well-formed block on all of them.
func (b *Block) onThisChain() error {
	if b.chainID != b.vm.blockchainID || b.networkID != b.vm.NetworkID {
		return fmt.Errorf("%w: chain %s network %d, this node serves chain %s network %d",
			errForeignChain, b.chainID, b.networkID, b.vm.blockchainID, b.vm.NetworkID)
	}
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

	if err := b.onThisChain(); err != nil {
		return err
	}

	// Genesis is written by the VM, never proposed.
	if b.height == 0 {
		return errInvalidBlockHeight
	}

	// A proposed block carries work. Refusing an empty one is also what keeps
	// the signature check below from being satisfiable by removing its
	// subject: a parser that dropped the transaction set produces a block that
	// verifies nothing, and a block that verifies nothing must not verify.
	if len(b.transactions) == 0 {
		return errEmptyBlock
	}

	if len(b.Bytes()) > MaxBlockSize {
		return fmt.Errorf("%w: %d bytes over %d", errBlockTooLarge, len(b.Bytes()), MaxBlockSize)
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

	if b.vm.Config.QuantumStampEnabled {
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
