// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// block.go is the A-Chain block: how one is named, checked, and made fact.
//
// Three properties carry everything else here, and each of them was absent:
//
//   - A block is named by its CHAIN as well as its content. The chain id does
//     not travel on the wire — a peer supplies its own — so identical bytes name
//     different blocks on different chains and no block crosses between them.
//
//   - Verify DECIDES and changes nothing. It reads committed state, runs the
//     block's transition against an overlay it throws away, and compares the
//     result to what the proposer stamped. A block that is checked and loses the
//     round has therefore moved no state and no value, and two blocks in flight
//     cannot see each other's work.
//
//   - Accept is ONE commit. The block's state transition, the block's own bytes,
//     its height entry and the tip pointer go into a single versiondb commit, so
//     the chain has all of it or none of it, and a restart reads back the tip it
//     actually reached rather than starting again from genesis.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"

	"github.com/luxfi/ai/pkg/aivm"
	"github.com/luxfi/ai/pkg/attestation"
)

// Block errors.
var (
	// ErrInvalidBlock refuses a block that does not sit correctly on the chain:
	// a bad height, a timestamp outside its bounds, an oversized encoding, or a
	// genesis block offered as a proposal.
	ErrInvalidBlock = errors.New("aivm: invalid block")

	// ErrNotOnTip refuses a block the chain will not build on: one whose parent
	// is neither the accepted tip nor a block verified above it and still in
	// flight. Accepting one rewinds the chain and leaves the height index naming
	// an orphan as canonical.
	ErrNotOnTip = errors.New("aivm: block does not extend the accepted tip")

	// ErrDetachedBlock refuses a block with no chain behind it. Such a block has
	// no parent to sit on, no state to check against, and no chain id to be
	// named by — every question Verify asks is unanswerable, and answering "no
	// objection" to all of them is how an unchecked block passes.
	ErrDetachedBlock = errors.New("aivm: block belongs to no chain")
)

// MaxBlockSize bounds the wire encoding a block may arrive as, checked BEFORE
// anything is decoded. Without it a peer chose how much memory this node
// allocated: a single 49 MB block, made of nothing but repeated provider
// registrations, parsed without complaint.
//
// It is a CONSENSUS RULE, not configuration — every node enforces the same
// number on the same block, and a bound each operator could set would let two
// honestly-configured validators reach opposite verdicts. Verify holds a
// self-built block to it too, so a proposer cannot produce one its own peers
// would refuse to parse.
const MaxBlockSize = 2 << 20 // 2 MiB

// MaxFutureSkew is how far ahead of the verifying node's clock a block's
// timestamp may be. Timestamps are monotonic — Verify refuses one below its
// parent's — so an unbounded stamp is not a one-block error: it raises the floor
// every later block must clear, and one block dated a thousand hours out stops
// the chain producing for a thousand hours. The bound is loose enough to absorb
// ordinary clock disagreement between honest validators and tight enough that
// the damage from an out-of-range one is a single rejected block.
const MaxFutureSkew = 60 * time.Second

// Block represents an AIVM block
type Block struct {
	ID_        ids.ID    `json:"id"`
	ParentID_  ids.ID    `json:"parentID"`
	Height_    uint64    `json:"height"`
	Timestamp_ time.Time `json:"timestamp"`

	// AI-specific data
	Tasks        []aivm.Task       `json:"tasks,omitempty"`
	Results      []aivm.TaskResult `json:"results,omitempty"`
	MerkleRoot   [32]byte          `json:"merkleRoot"`
	ProviderRegs []ProviderReg     `json:"providerRegs,omitempty"`

	// ImportedIntents are the committed C-Chain intents that this block turned
	// into A-Chain quorum tasks (under consensus, via the verified inbound seam).
	// Recorded so Block.Verify can deterministically re-run the same imports and
	// every validator reaches identical engine state.
	ImportedIntents []CIntent `json:"importedIntents,omitempty"`

	// ReceiptRoot is the engine's committed receipt_root as of this block — the
	// single commitment the A->C boundary exports.
	ReceiptRoot common.Hash `json:"receiptRoot"`

	bytes []byte
	vm    *VM
}

// ProviderReg represents a provider registration in a block
type ProviderReg struct {
	ProviderID     string                        `json:"providerId"`
	WalletAddress  string                        `json:"walletAddress"`
	Endpoint       string                        `json:"endpoint"`
	CPUAttestation *attestation.AttestationQuote `json:"cpuAttestation,omitempty"`
	GPUAttestation *attestation.GPUAttestation   `json:"gpuAttestation,omitempty"`
}

// blockID names a block by its canonical wire AND by the chain it belongs to.
//
// The chain id is hashed in but never encoded, so it cannot be supplied by
// whoever sent the bytes: every node names the block under ITS OWN chain. Two
// chains that share a genesis timestamp used to share a genesis id, and a block
// built on one parsed byte-identically on the other and resolved as a parent
// there.
func blockID(chainID ids.ID, wire []byte) ids.ID {
	h := sha256.New()
	h.Write(chainID[:])
	h.Write(wire)
	return ids.ID(h.Sum(nil))
}

// name encodes the block and names it, in that order, because the name is a
// function of the encoding. Every path that produces a Block — genesis, a
// proposal, a parse, a tip read back at startup — ends here, so a Block the VM
// holds always has both, and Bytes() and ID() never have to compute (and so
// never have to swallow an error).
func (blk *Block) name() error {
	wire, err := blk.Marshal()
	if err != nil {
		return err
	}
	blk.bytes = wire
	blk.ID_ = blockID(blk.chain(), wire)
	return nil
}

// chain is the id of the chain this block belongs to. A block with no VM belongs
// to none, and is named under the empty chain — Verify refuses it outright, so
// the value is never load-bearing.
func (blk *Block) chain() ids.ID {
	if blk.vm == nil {
		return ids.Empty
	}
	return blk.vm.chainID
}

// ID returns the block ID
func (blk *Block) ID() ids.ID { return blk.ID_ }

// Parent returns the parent block ID
func (blk *Block) Parent() ids.ID { return blk.ParentID_ }

// ParentID returns the parent block ID
func (blk *Block) ParentID() ids.ID { return blk.ParentID_ }

// Height returns the block height
func (blk *Block) Height() uint64 { return blk.Height_ }

// Timestamp returns the block timestamp
func (blk *Block) Timestamp() time.Time { return blk.Timestamp_ }

// Bytes returns the block's canonical wire encoding.
func (blk *Block) Bytes() []byte { return blk.bytes }

// Status reports 0 = processing, 1 = accepted.
func (blk *Block) Status() uint8 {
	vm := blk.vm
	if vm == nil {
		return 0
	}
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	if vm.lastAccepted != nil && blk.ID_ == vm.lastAccepted.ID_ {
		return 1
	}
	if ok, _ := vm.db.Has(blockKey(blk.ID_)); ok {
		return 1
	}
	return 0
}

// Verify decides whether this block can be accepted, and changes NOTHING.
//
// It checks that the block sits correctly on its parent in height and in time,
// that its encoding is one every peer will accept, and that the state transition
// it claims is the one this node computes from the same inputs. The transition
// runs against an overlay over committed state and a clone of the ledger, both
// discarded on the way out, so a block that verifies and then loses the round
// has moved no state and no value — and two blocks in flight cannot see each
// other's work, which is what let Accept(A) publish B's intent and Reject(B)
// discard A's.
//
// Verify does not decide the outcome on its own. The tip moves between this call
// and Accept, and it is Accept, holding the lock that commits, that has the last
// word.
func (blk *Block) Verify(ctx context.Context) error {
	vm := blk.vm
	if vm == nil {
		return ErrDetachedBlock
	}
	if blk.Height_ == 0 {
		return fmt.Errorf("%w: genesis is not a proposed block", ErrInvalidBlock)
	}
	if n := len(blk.bytes); n == 0 {
		return fmt.Errorf("%w: block has no encoding", ErrInvalidBlock)
	} else if n > MaxBlockSize {
		return fmt.Errorf("%w: %d bytes exceeds %d", ErrInvalidBlock, n, MaxBlockSize)
	}

	if err := blk.check(); err != nil {
		return err
	}

	// A block that verifies is one the engine may build on, so it has to be
	// findable by id — including one parsed from a peer rather than built here.
	// Tracking only self-built blocks left a follower able to verify the first
	// block of a run and unable to verify the second.
	//
	// The read lock inside check cannot be upgraded, so the checks finish under
	// it and the registration takes the write lock on its own.
	vm.mu.Lock()
	vm.track(blk)
	vm.mu.Unlock()
	return nil
}

// check is Verify's verdict, taken under the read lock. Split out so the lock is
// released before Verify takes the write lock to track the block.
func (blk *Block) check() error {
	vm := blk.vm
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	// Where the block sits. above is the run of blocks in flight between the tip
	// and this block's parent; empty means the parent IS the tip.
	above, err := vm.above(blk)
	if err != nil {
		return err
	}
	parent := vm.lastAccepted
	if n := len(above); n > 0 {
		parent = above[n-1]
	}
	if blk.Height_ != parent.Height_+1 {
		return fmt.Errorf("%w: height %d does not follow parent %d",
			ErrInvalidBlock, blk.Height_, parent.Height_)
	}
	// Chain time is the parent's, advanced. Without this a proposer picks it
	// freely: it can rewind time, or jump a thousand hours forward and leave a
	// floor no honest block can clear.
	if blk.Timestamp_.Before(parent.Timestamp_) {
		return fmt.Errorf("%w: timestamp %s precedes parent %s",
			ErrInvalidBlock, blk.Timestamp_.UTC(), parent.Timestamp_.UTC())
	}
	if blk.Timestamp_.After(vm.clock.Time().Add(MaxFutureSkew)) {
		return fmt.Errorf("%w: timestamp %s is beyond the %s skew allowance",
			ErrInvalidBlock, blk.Timestamp_.UTC(), MaxFutureSkew)
	}

	// The transition, on state this node can throw away. Any ancestor still in
	// flight is folded in first: its effects are not committed yet, and checking
	// this block against state that lacks them would refuse an honest block —
	// stalling a follower at exactly the depth consensus is working at.
	st := newOverlay(vm.qstate)
	lg := newStateLedger(st)
	for _, a := range above {
		if _, err := vm.replay(st, lg, a.ImportedIntents, a.Height_); err != nil {
			return fmt.Errorf("aivm: ancestor %s: %w", a.ID_, err)
		}
	}
	root, err := vm.replay(st, lg, blk.ImportedIntents, blk.Height_)
	if err != nil {
		return err
	}
	// The recorded root must equal the one these imports actually produce, with
	// no exemption for the zero hash. Skipping the comparison when the block
	// claims zero made the determinism check opt-out: a proposer wrote a zero
	// receipt_root and followers applied its intents without ever checking that
	// their engine state agreed.
	if root != blk.ReceiptRoot {
		return ErrReceiptRootMismatch
	}
	return nil
}

// Accept makes the block fact.
//
// Everything the block changes — its state transition, its own bytes, its height
// entry and the tip pointer — is staged through ONE view and committed ONCE, so
// the chain has the whole block or none of it. Any failure aborts the view and
// leaves the tip where it was: the block did not happen, and nothing it claimed
// survives. In-memory state advances only after the commit returns, so there is
// no window in which this node has moved past state that is not on disk.
func (blk *Block) Accept(ctx context.Context) error {
	vm := blk.vm
	if vm == nil {
		return ErrDetachedBlock
	}
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// A block extends the tip or it is not accepted. Verify reached that verdict
	// against the tip AT THAT TIME; between the two calls the chain moves, and it
	// is this hold of the lock that decides. Without it Accept commits the height
	// index and the tip pointer for a block on an abandoned branch — the chain
	// rewinds, and every peer bootstrapping from the index is served an orphan as
	// canonical.
	if vm.lastAccepted == nil {
		return fmt.Errorf("%w: chain has no tip", ErrNotOnTip)
	}
	if blk.ParentID_ != vm.lastAccepted.ID_ {
		return fmt.Errorf("%w: %s extends %s, not the tip %s",
			ErrNotOnTip, blk.ID_, blk.ParentID_, vm.lastAccepted.ID_)
	}

	if err := blk.commit(); err != nil {
		// Nothing staged reached the base, and the real ledger was never touched
		// — the transition ran against the clone. There is no cache to rebuild
		// because there is no cache that moved.
		vm.view.Abort()
		return err
	}

	vm.lastAccepted = blk
	delete(vm.flight, blk.ID_)
	vm.prune()
	vm.drop(blk.ImportedIntents)
	return nil
}

// commit stages the block's whole effect and commits it in one write. Caller
// holds vm.mu and is responsible for aborting the view on error.
func (blk *Block) commit() error {
	vm := blk.vm
	staged := NewDBState(vm.view)
	root, err := vm.replay(staged, newStateLedger(staged), blk.ImportedIntents, blk.Height_)
	if err != nil {
		return err
	}
	// Verify passed, so a mismatch here means state moved between the two calls.
	// Refuse rather than persist a state that disagrees with the block the
	// network accepted.
	if root != blk.ReceiptRoot {
		return ErrReceiptRootMismatch
	}
	if err := vm.view.Put(blockKey(blk.ID_), blk.bytes); err != nil {
		return err
	}
	if err := vm.view.Put(heightKey(blk.Height_), blk.ID_[:]); err != nil {
		return err
	}
	if err := vm.view.Put(tipKey, blk.ID_[:]); err != nil {
		return err
	}
	return vm.view.Commit()
}

// Reject drops the block. It never wrote anything — Verify runs the transition
// against an overlay it discards — so there is nothing to undo, and in
// particular nothing belonging to a SIBLING to undo, which is what the rollback
// this replaces used to take with it.
//
// The intents it carried stay buffered: rejection means this block did not land,
// not that the work was invalid, so the next proposer may carry it again.
func (blk *Block) Reject(ctx context.Context) error {
	vm := blk.vm
	if vm == nil {
		return ErrDetachedBlock
	}
	vm.mu.Lock()
	delete(vm.flight, blk.ID_)
	vm.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// Where a block sits: the tip, and the blocks in flight above it.
// ---------------------------------------------------------------------------

// above returns the blocks in flight between the accepted tip and blk's parent,
// oldest first. An empty run means the parent IS the tip.
//
// The walk is what refuses a parent this chain will not build on: an old
// accepted block, a sibling on an abandoned branch, or an id nothing knows.
// Height alone is not that check — a block whose parent is an OLD accepted block
// satisfies height == parent+1 perfectly well, and accepting it rewinds the
// chain.
//
// Each step must drop the height by exactly one, which both checks the run's own
// lineage and bounds the walk: it cannot run longer than blk's height, so no set
// of blocks a peer supplies can make it spin.
//
// Caller holds vm.mu at least for read.
func (vm *VM) above(blk *Block) ([]*Block, error) {
	if vm.lastAccepted == nil {
		return nil, fmt.Errorf("%w: chain has no tip", ErrNotOnTip)
	}
	var run []*Block
	id, height := blk.ParentID_, blk.Height_-1
	for id != vm.lastAccepted.ID_ {
		b, ok := vm.flight[id]
		if !ok {
			return nil, fmt.Errorf("%w: parent %s is neither the tip %s nor in flight",
				ErrNotOnTip, blk.ParentID_, vm.lastAccepted.ID_)
		}
		if b.Height_ != height {
			return nil, fmt.Errorf("%w: %s is at height %d under a block at height %d",
				ErrInvalidBlock, b.ID_, b.Height_, height+1)
		}
		run = append(run, b)
		id, height = b.ParentID_, height-1
	}
	slices.Reverse(run)
	return run, nil
}

// track makes a block findable by id while it is in flight, so a child can
// resolve it as a parent — whether this node built the block or parsed it from a
// peer.
//
// It also prunes, because nothing else will: the engine may abandon a block
// without ever accepting or rejecting it, so a set that only grew would leak.
// Anything at or below the accepted height is already decided or orphaned, which
// bounds this to the blocks actually in flight above the tip.
//
// Caller holds vm.mu for writing.
func (vm *VM) track(blk *Block) {
	if vm.lastAccepted == nil || blk.Height_ <= vm.lastAccepted.Height_ {
		return
	}
	vm.prune()
	vm.flight[blk.ID_] = blk
}

// prune drops every block in flight at or below the accepted height. Caller
// holds vm.mu for writing.
func (vm *VM) prune() {
	for id, b := range vm.flight {
		if b.Height_ <= vm.lastAccepted.Height_ {
			delete(vm.flight, id)
		}
	}
}
