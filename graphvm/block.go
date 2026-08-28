// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"errors"
	"time"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/consensus/engine/chain/block"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// The consensus engine requires every ChainVM to resolve a real last-accepted
// block at boot (LastAccepted -> GetBlock). This assertion guarantees *Block
// satisfies block.Block; it is what catches the Status() signature mismatch
// (the interface needs a concrete uint8, not the named choices.Status) at
// compile time so GetBlock can actually return a *Block.
var _ block.Block = (*Block)(nil)

// Block is the G-Chain's genesis block, which is the only block it has. Its
// fields are fixed at construction and it is accepted by definition, so there
// is no mutable status to keep in step with consensus.
type Block struct {
	vm *VM

	id    ids.ID
	bytes []byte
}

// ID implements the chain.Block interface
func (b *Block) ID() ids.ID { return b.id }

// Parent implements the chain.Block interface. Genesis has none.
func (b *Block) Parent() ids.ID { return ids.Empty }

// ParentID returns the parent block ID
func (b *Block) ParentID() ids.ID { return ids.Empty }

// Height implements the chain.Block interface
func (b *Block) Height() uint64 { return 0 }

// Timestamp implements the chain.Block interface
func (b *Block) Timestamp() time.Time { return genesisTimestamp }

// Status implements the block.Block interface. The interface requires a
// concrete uint8; choices.Status is `type Status uint8`, so a method returning
// the named type would NOT satisfy block.Block — which is why GetBlock could
// never have returned a *Block before this fix.
func (b *Block) Status() uint8 { return uint8(choices.Accepted) }

// Bytes implements the block.Block interface. It returns the deterministic
// canonical encoding set at construction; the block ID is the SHA-256 of
// exactly these bytes, so ParseBlock(b.Bytes()).ID() == b.ID().
func (b *Block) Bytes() []byte { return b.bytes }

// Verify implements the chain.Block interface. Genesis is the root of trust and
// nothing else can reach here — ParseBlock and GetBlock hand out no other block
// — so this asks the one question the chain answers.
func (b *Block) Verify(context.Context) error {
	if b.id != b.vm.genesis.ID() {
		return errReadOnlyChain
	}
	return nil
}

// Accept implements the chain.Block interface. Genesis is already the accepted
// frontier, so accepting it changes nothing; accepting anything else would move
// the frontier to a block GetBlock cannot return, which is the shape that
// leaves a node unable to boot.
func (b *Block) Accept(context.Context) error {
	if b.id != b.vm.genesis.ID() {
		return errReadOnlyChain
	}
	return nil
}

// Reject implements the chain.Block interface. The frontier is the only block
// there is, and rejecting it would leave the chain without one.
func (b *Block) Reject(context.Context) error {
	return errReadOnlyChain
}

// genesisTimestamp is the deterministic timestamp of the G-Chain genesis block.
// Genesis is the root of trust (accepted by definition), so a fixed,
// node-independent value is used — never time.Now(), which would make the
// genesis block ID diverge across validators and break consensus agreement.
var genesisTimestamp = time.Unix(0, 0).UTC()

// G-Chain block wire — native ZAP (fixed offsets), no reflection codec. The
// block ID is hash.ComputeHash256 of these bytes, so marshal/parse round-trips a
// byte-identical ID across nodes and restarts.
//
//	ParentID  32B   @ 0
//	Height    u64   @ 32
//	Timestamp i64   @ 40
//	Payload   bytes @ 48
const (
	gblkParentID  = 0
	gblkHeight    = 32
	gblkTimestamp = 40
	gblkPayload   = 48
	gblkSize      = 56
)

var errGBlockTrailing = errors.New("graphvm block: trailing bytes after canonical wire")

// marshalGBlock encodes a block into its canonical ZAP wire bytes.
func marshalGBlock(parentID ids.ID, height uint64, timestamp int64, payload []byte) []byte {
	b := zap.NewBuilder(zap.HeaderSize + gblkSize + len(payload) + 16)
	ob := b.StartObject(gblkSize)
	ob.SetBytesFixed(gblkParentID, parentID[:])
	ob.SetUint64(gblkHeight, height)
	ob.SetInt64(gblkTimestamp, timestamp)
	ob.SetBytes(gblkPayload, payload)
	ob.FinishAsRoot()
	return b.Finish()
}

// parseGBlock decodes canonical ZAP block wire; rejects trailing bytes.
func parseGBlock(raw []byte) (parentID ids.ID, height uint64, timestamp int64, payload []byte, err error) {
	msg, perr := zap.Parse(raw)
	if perr != nil {
		err = perr
		return
	}
	if msg.Size() != len(raw) {
		err = errGBlockTrailing
		return
	}
	o := msg.Root()
	parentID = ids.ID(o.BytesFixedSlice(gblkParentID, 32))
	height = o.Uint64(gblkHeight)
	timestamp = o.Int64(gblkTimestamp)
	payload = o.Bytes(gblkPayload)
	return
}

// newBlock builds the G-Chain genesis block (height 0) deterministically from
// the genesis config bytes. The G-Chain is a read-only query chain — it never
// builds blocks past genesis — so this is its permanent last-accepted block,
// the one GetBlock(LastAccepted()) must return during Initialize.
func newBlock(vm *VM, genesisBytes []byte) *Block {
	raw := marshalGBlock(ids.Empty, 0, genesisTimestamp.Unix(), genesisBytes)
	return &Block{
		vm:    vm,
		id:    ids.ID(hash.ComputeHash256(raw)),
		bytes: raw,
	}
}

// parseBlock decodes canonical block wire and returns the genesis block those
// bytes name. Wire that decodes but names some other block is refused: this
// chain builds nothing, so there is no other block to name, and admitting one
// would hand the engine a frontier that GetBlock reports as not found.
func parseBlock(vm *VM, raw []byte) (*Block, error) {
	if _, _, _, _, err := parseGBlock(raw); err != nil {
		return nil, err
	}
	if ids.ID(hash.ComputeHash256(raw)) != vm.genesis.ID() {
		return nil, errReadOnlyChain
	}
	return vm.genesis, nil
}
