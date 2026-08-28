// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

var _ vertex.DAGVM = (*VM)(nil)

var errNoTransactions = errors.New("zkvm: nothing to propose")

// Vertex represents a DAG vertex in the ZK UTXO chain.
// Conflict key: set of nullifiers spent in the vertex.
// Two vertices conflict iff their nullifier sets intersect.
type Vertex struct {
	id      ids.ID
	bytes   []byte
	height  uint64
	epoch   uint32
	parents []ids.ID
	txIDs   []ids.ID
	status  choices.Status
	txs     []*Transaction
	vm      *VM
}

func (v *Vertex) ID() ids.ID             { return v.id }
func (v *Vertex) Bytes() []byte          { return v.bytes }
func (v *Vertex) Height() uint64         { return v.height }
func (v *Vertex) Epoch() uint32          { return v.epoch }
func (v *Vertex) Parents() []ids.ID      { return v.parents }
func (v *Vertex) Txs() []ids.ID          { return v.txIDs }
func (v *Vertex) Status() choices.Status { return v.status }

// Verify holds a vertex to what a block is held to. It used to check the
// transactions and NOTHING ELSE — not the parents, not the height — so a vertex
// naming no parent at height 1<<40 verified, and accepting it set the store's
// height to 1<<40, pruned every block in flight, and left the linear chain
// unable to propose a child ever again.
func (v *Vertex) Verify(ctx context.Context) error {
	if uint32(len(v.txs)) > v.vm.config.MaxTxPerBlock {
		return fmt.Errorf("%w: %d transactions over the %d cap",
			errInvalidBlock, len(v.txs), v.vm.config.MaxTxPerBlock)
	}

	// A vertex extends the frontier. The store keeps one tip for both shapes,
	// so a vertex that names something else moves the chain sideways.
	tip, tipHeight := v.vm.chain.Tip()
	if len(v.parents) != 1 || v.parents[0] != tip {
		return fmt.Errorf("%w: vertex parents %v do not name the tip %s",
			ErrNotOnTip, v.parents, tip)
	}
	if v.height != tipHeight+1 {
		return fmt.Errorf("%w: height %d does not follow the tip at %d",
			errInvalidHeight, v.height, tipHeight)
	}

	// Every nullifier in the vertex must be distinct. admit only sees
	// nullifiers already spent in ACCEPTED state; BuildVertex refuses to batch
	// conflicting txs, and a vertex that arrived on the wire is held to the
	// same rule or one shielded note is spent twice.
	spentHere := make(map[string]struct{}, len(v.txs))
	for _, tx := range v.txs {
		for _, nullifier := range tx.Nullifiers {
			if _, dup := spentHere[string(nullifier)]; dup {
				return errDuplicateNullifier
			}
			spentHere[string(nullifier)] = struct{}{}
		}
	}
	for _, tx := range v.txs {
		if err := v.vm.admit(tx, v.height); err != nil {
			return err
		}
	}
	return nil
}

// Accept applies the vertex through the same store a block goes through: its
// spends and outputs are staged and committed in one batch with the vertex and
// the tip. A vertex is not a block — it has several parents and no timestamp —
// but it changes state the same way, and this is that way.
func (v *Vertex) Accept(ctx context.Context) error {
	// The tip moves between Verify and here. See Block.Accept.
	tip, _ := v.vm.chain.Tip()
	if len(v.parents) != 1 || v.parents[0] != tip {
		return fmt.Errorf("%w: vertex %s extends %v, and the tip is %s",
			ErrNotOnTip, v.id, v.parents, tip)
	}
	return v.vm.chain.Accept(v)
}

// Write records the vertex's spends and its outputs.
func (v *Vertex) Write(database.Database) error {
	for _, tx := range v.txs {
		for _, nullifier := range tx.Nullifiers {
			if err := v.vm.nullifierDB.MarkNullifierSpent(nullifier, v.height); err != nil {
				return err
			}
		}
		for i, output := range tx.Outputs {
			if err := v.vm.utxoDB.AddUTXO(&UTXO{
				TxID:        tx.ID,
				OutputIndex: uint32(i),
				Commitment:  output.Commitment,
				Ciphertext:  output.EncryptedNote,
				EphemeralPK: output.EphemeralPubKey,
				Height:      v.height,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// Publish marks the vertex accepted and releases the transactions it carried,
// once those spends are durable.
func (v *Vertex) Publish() {
	v.status = choices.Accepted
	for _, tx := range v.txs {
		v.vm.mempool.RemoveTransaction(tx.ID)
	}
}

func (v *Vertex) Reject(ctx context.Context) error {
	v.status = choices.Rejected
	for _, tx := range v.txs {
		v.vm.mempool.AddTransaction(tx)
	}
	return nil
}

// nullifierSet returns the set of nullifiers in this vertex for conflict detection.
func (v *Vertex) nullifierSet() map[string]struct{} {
	s := make(map[string]struct{})
	for _, tx := range v.txs {
		for _, n := range tx.Nullifiers {
			s[string(n)] = struct{}{}
		}
	}
	return s
}

// Conflicts returns true if this vertex and other share any nullifier.
func (v *Vertex) Conflicts(other *Vertex) bool {
	ours := v.nullifierSet()
	for _, tx := range other.txs {
		for _, n := range tx.Nullifiers {
			if _, ok := ours[string(n)]; ok {
				return true
			}
		}
	}
	return false
}

// ConflictsVertex performs the same check against the vertex.Vertex interface.
func (v *Vertex) ConflictsVertex(other vertex.Vertex) bool {
	ov, ok := other.(*Vertex)
	if !ok {
		return false
	}
	return v.Conflicts(ov)
}

// computeID binds the chain, the shape and the content. See Block.computeID.
func (v *Vertex) computeID() ids.ID {
	h := sha256.New()
	h.Write(v.vm.bind[:])
	binary.Write(h, binary.BigEndian, v.height)
	binary.Write(h, binary.BigEndian, v.epoch)
	for _, p := range v.parents {
		h.Write(p[:])
	}
	for _, tx := range v.txs {
		txID := tx.ComputeID()
		h.Write(txID[:])
	}
	return ids.ID(h.Sum(nil))
}

// BuildVertex drains the mempool, batches non-conflicting txs, and returns a vertex.
func (vm *VM) BuildVertex(ctx context.Context) (vertex.Vertex, error) {
	parent, height := vm.chain.Tip()

	candidates := vm.mempool.GetPendingTransactions(int(vm.config.MaxTxPerBlock))
	if len(candidates) == 0 {
		return nil, errNoTransactions
	}

	// Greedily batch non-conflicting txs: skip any tx whose nullifiers collide
	// with the batch. admit is the same predicate Verify runs, so nothing is
	// batched that a peer will refuse.
	usedNullifiers := make(map[string]struct{})
	var batch []*Transaction
	for _, tx := range candidates {
		if err := vm.admit(tx, height+1); err != nil {
			vm.mempool.RemoveTransaction(tx.ID)
			continue
		}
		conflict := false
		for _, n := range tx.Nullifiers {
			if _, ok := usedNullifiers[string(n)]; ok {
				conflict = true
				break
			}
		}
		if conflict {
			continue
		}
		for _, n := range tx.Nullifiers {
			usedNullifiers[string(n)] = struct{}{}
		}
		batch = append(batch, tx)
	}
	if len(batch) == 0 {
		return nil, errNoTransactions
	}

	txIDs := make([]ids.ID, len(batch))
	for i, tx := range batch {
		txIDs[i] = tx.ComputeID()
	}

	v := &Vertex{
		height:  height + 1,
		epoch:   0,
		parents: []ids.ID{parent},
		txIDs:   txIDs,
		txs:     batch,
		status:  choices.Processing,
		vm:      vm,
	}
	v.id = v.computeID()
	v.bytes = v.serialize()
	return v, nil
}

// ParseVertex deserializes a vertex from bytes.
func (vm *VM) ParseVertex(ctx context.Context, b []byte) (vertex.Vertex, error) {
	return deserializeVertex(b, vm)
}

func (v *Vertex) serialize() []byte {
	// Format: height(8) + epoch(4) + parentCount(4) + parents + txCount(4) + txBytes
	size := 8 + 4 + 4 + len(v.parents)*32 + 4
	buf := make([]byte, 0, size+len(v.txs)*64)

	b8 := make([]byte, 8)
	binary.BigEndian.PutUint64(b8, v.height)
	buf = append(buf, b8...)

	b4 := make([]byte, 4)
	binary.BigEndian.PutUint32(b4, v.epoch)
	buf = append(buf, b4...)

	binary.BigEndian.PutUint32(b4, uint32(len(v.parents)))
	buf = append(buf, b4...)
	for _, p := range v.parents {
		buf = append(buf, p[:]...)
	}

	binary.BigEndian.PutUint32(b4, uint32(len(v.txs)))
	buf = append(buf, b4...)
	for _, tx := range v.txs {
		txBytes := tx.Marshal()
		binary.BigEndian.PutUint32(b4, uint32(len(txBytes)))
		buf = append(buf, b4...)
		buf = append(buf, txBytes...)
	}

	return buf
}

func deserializeVertex(data []byte, vm *VM) (*Vertex, error) {
	if len(data) < 16 {
		return nil, errInvalidBlock
	}
	pos := 0

	height := binary.BigEndian.Uint64(data[pos:])
	pos += 8

	epoch := binary.BigEndian.Uint32(data[pos:])
	pos += 4

	// Counts are attacker-controlled: bound each by the bytes that remain before
	// allocating, or a 16-byte vertex claiming 2^32-1 parents asks for 128 GiB and
	// the node dies on an unrecoverable out-of-memory.
	parentCount := binary.BigEndian.Uint32(data[pos:])
	pos += 4
	if int(parentCount) > (len(data)-pos)/32 {
		return nil, errInvalidBlock
	}

	parents := make([]ids.ID, parentCount)
	for i := uint32(0); i < parentCount; i++ {
		copy(parents[i][:], data[pos:pos+32])
		pos += 32
	}

	if pos+4 > len(data) {
		return nil, errInvalidBlock
	}
	txCount := binary.BigEndian.Uint32(data[pos:])
	pos += 4
	// Every tx costs at least its 4-byte length prefix.
	if int(txCount) > (len(data)-pos)/4 {
		return nil, errInvalidBlock
	}

	txs := make([]*Transaction, 0, txCount)
	txIDs := make([]ids.ID, 0, txCount)
	for i := uint32(0); i < txCount; i++ {
		if pos+4 > len(data) {
			return nil, errInvalidBlock
		}
		txLen := binary.BigEndian.Uint32(data[pos:])
		pos += 4
		if pos+int(txLen) > len(data) {
			return nil, errInvalidBlock
		}
		tx, err := parseTransaction(data[pos : pos+int(txLen)])
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
		txIDs = append(txIDs, tx.ID)
		pos += int(txLen)
	}

	// Every byte handed in belongs to the vertex, or the value read is not the
	// value that was sent. Without this, arbitrary trailing bytes rode along in
	// v.bytes — which is what the store writes to disk — so one logical vertex
	// had unboundedly many encodings all mapping to the same id, and a peer
	// could park megabytes under a legitimate one.
	if pos != len(data) {
		return nil, errTrailingBytes
	}

	v := &Vertex{
		height:  height,
		epoch:   epoch,
		parents: parents,
		txIDs:   txIDs,
		txs:     txs,
		status:  choices.Unknown,
		vm:      vm,
		bytes:   data,
	}
	v.id = v.computeID()
	return v, nil
}
