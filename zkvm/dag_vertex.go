// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

var _ vertex.DAGVM = (*VM)(nil)

// Vertex represents a DAG vertex in the ZK UTXO chain.
// Conflict key: set of nullifiers spent in the vertex.
// Two vertices conflict iff their nullifier sets intersect.
type Vertex struct {
	id       ids.ID
	bytes    []byte
	height   uint64
	epoch    uint32
	parents  []ids.ID
	txIDs    []ids.ID
	status   choices.Status
	txs      []*Transaction
	vm       *VM
}

func (v *Vertex) ID() ids.ID          { return v.id }
func (v *Vertex) Bytes() []byte        { return v.bytes }
func (v *Vertex) Height() uint64       { return v.height }
func (v *Vertex) Epoch() uint32        { return v.epoch }
func (v *Vertex) Parents() []ids.ID    { return v.parents }
func (v *Vertex) Txs() []ids.ID        { return v.txIDs }
func (v *Vertex) Status() choices.Status { return v.status }

func (v *Vertex) Verify(ctx context.Context) error {
	// Every nullifier in the vertex must be distinct. verifyTransaction only sees
	// accepted state; BuildVertex already refuses to batch conflicting txs, and a
	// vertex that arrived on the wire is held to the same rule or one shielded
	// note is spent twice.
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
		if err := tx.ValidateBasic(); err != nil {
			return err
		}
		if err := v.vm.verifyTransaction(tx); err != nil {
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

func (v *Vertex) computeID() ids.ID {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, v.height)
	binary.Write(h, binary.BigEndian, v.epoch)
	for _, p := range v.parents {
		h.Write(p[:])
	}
	for _, tx := range v.txs {
		txID := tx.ID
		if txID == ids.Empty {
			txID = tx.ComputeID()
		}
		h.Write(txID[:])
	}
	return ids.ID(h.Sum(nil))
}

// BuildVertex drains the mempool, batches non-conflicting txs, and returns a vertex.
func (vm *VM) BuildVertex(ctx context.Context) (vertex.Vertex, error) {
	parent, height := vm.chain.Tip()

	candidates := vm.mempool.GetPendingTransactions(int(vm.config.MaxUTXOsPerBlock))
	if len(candidates) == 0 {
		return nil, errNoTransactions
	}

	// Greedily batch non-conflicting txs: skip any tx whose nullifiers collide with the batch.
	usedNullifiers := make(map[string]struct{})
	var batch []*Transaction
	for _, tx := range candidates {
		if err := vm.verifyTransaction(tx); err != nil {
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
		if tx.ID == ids.Empty {
			tx.ID = tx.ComputeID()
		}
		txIDs[i] = tx.ID
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
	v, err := deserializeVertex(b, vm)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Vertex) serialize() []byte {
	// Format: height(8) + epoch(4) + parentCount(4) + parents + txCount(4) + txBytes
	size := 8 + 4 + 4 + len(v.parents)*32 + 4
	for _, tx := range v.txs {
		if tx.ID == ids.Empty {
			tx.ID = tx.ComputeID()
		}
	}

	// Estimate: use codec for real txs, here store IDs + raw nullifiers for vertex identity
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
		txBytes, _ := tx.Marshal()
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
		tx, err := parseTransaction(data[pos:pos+int(txLen)])
		if err != nil {
			return nil, err
		}
		if tx.ID == ids.Empty {
			tx.ID = tx.ComputeID()
		}
		txs = append(txs, tx)
		txIDs = append(txIDs, tx.ID)
		pos += int(txLen)
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

var errNoTransactions = errInvalidBlock // reuse existing sentinel

// compile-time epoch zero for fresh chains
var _ = time.Now // avoid unused import if time were only in block.go
