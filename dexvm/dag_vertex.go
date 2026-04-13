// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/ids"
	"github.com/luxfi/chains/dexvm/orderbook"
	"github.com/luxfi/chains/dexvm/txs"
)

var _ vertex.DAGVM = (*ChainVM)(nil)

// OrderKey is the conflict key for the DEX: (base, quote, side, orderID).
// Two vertices conflict iff their OrderKey sets intersect.
type OrderKey struct {
	Symbol  string
	Side    orderbook.Side
	OrderID ids.ID
}

// DexVertex represents a DAG vertex in the DEX chain.
type DexVertex struct {
	id      ids.ID
	bytes   []byte
	height  uint64
	epoch   uint32
	parents []ids.ID
	txIDs   []ids.ID
	status  choices.Status
	rawTxs  [][]byte
	keys    []OrderKey
	vm      *ChainVM
}

func (v *DexVertex) ID() ids.ID          { return v.id }
func (v *DexVertex) Bytes() []byte        { return v.bytes }
func (v *DexVertex) Height() uint64       { return v.height }
func (v *DexVertex) Epoch() uint32        { return v.epoch }
func (v *DexVertex) Parents() []ids.ID    { return v.parents }
func (v *DexVertex) Txs() []ids.ID        { return v.txIDs }
func (v *DexVertex) Status() choices.Status { return v.status }

func (v *DexVertex) Verify(ctx context.Context) error {
	if v.vm == nil || v.vm.inner == nil {
		return errVMNotInitialized
	}
	_, err := v.vm.inner.ProcessBlock(ctx, v.height, v.vm.inner.clock.Time(), v.rawTxs)
	return err
}

func (v *DexVertex) Accept(ctx context.Context) error {
	v.status = choices.Accepted
	v.vm.lock.Lock()
	defer v.vm.lock.Unlock()
	v.vm.lastAcceptedID = v.id
	v.vm.lastAcceptedHeight = v.height
	v.vm.blocks[v.id] = &Block{
		vm:        v.vm,
		id:        v.id,
		parentID:  v.parents[0],
		height:    v.height,
		txs:       v.rawTxs,
		status:    StatusAccepted,
	}
	if v.vm.inner.db != nil {
		return v.vm.inner.db.Commit()
	}
	return nil
}

func (v *DexVertex) Reject(ctx context.Context) error {
	v.status = choices.Rejected
	if v.vm.inner.db != nil {
		v.vm.inner.db.Abort()
	}
	return nil
}

// conflictKeySet returns the set of OrderKeys for conflict detection.
func (v *DexVertex) conflictKeySet() map[OrderKey]struct{} {
	s := make(map[OrderKey]struct{}, len(v.keys))
	for _, k := range v.keys {
		s[k] = struct{}{}
	}
	return s
}

// Conflicts returns true if this vertex and other share any (symbol, side, orderID) tuple.
func (v *DexVertex) Conflicts(other *DexVertex) bool {
	ours := v.conflictKeySet()
	for _, k := range other.keys {
		if _, ok := ours[k]; ok {
			return true
		}
	}
	return false
}

// ConflictsVertex performs the same check against the vertex.Vertex interface.
func (v *DexVertex) ConflictsVertex(other vertex.Vertex) bool {
	ov, ok := other.(*DexVertex)
	if !ok {
		return false
	}
	return v.Conflicts(ov)
}

// extractOrderKeys extracts conflict keys from raw transaction bytes.
func extractOrderKeys(rawTxs [][]byte) []OrderKey {
	var keys []OrderKey
	for _, raw := range rawTxs {
		var envelope struct {
			Type    txs.TxType `json:"type"`
			OrderID ids.ID     `json:"orderId"`
			Symbol  string     `json:"symbol"`
			Side    uint8      `json:"side"`
		}
		if json.Unmarshal(raw, &envelope) != nil {
			continue
		}
		switch envelope.Type {
		case txs.TxPlaceOrder, txs.TxCancelOrder, txs.TxCommitOrder, txs.TxRevealOrder:
			keys = append(keys, OrderKey{
				Symbol:  envelope.Symbol,
				Side:    orderbook.Side(envelope.Side),
				OrderID: envelope.OrderID,
			})
		}
	}
	return keys
}

func (v *DexVertex) computeID() ids.ID {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, v.height)
	binary.Write(h, binary.BigEndian, v.epoch)
	for _, p := range v.parents {
		h.Write(p[:])
	}
	for _, raw := range v.rawTxs {
		txHash := sha256.Sum256(raw)
		h.Write(txHash[:])
	}
	return ids.ID(h.Sum(nil))
}

// BuildVertex drains pending txs and batches non-conflicting ones.
func (cvm *ChainVM) BuildVertex(ctx context.Context) (vertex.Vertex, error) {
	cvm.lock.Lock()
	defer cvm.lock.Unlock()

	if !cvm.initialized {
		return nil, errVMNotInitialized
	}
	if len(cvm.pendingTxs) == 0 {
		return nil, errNoBlocksBuilt
	}

	// Greedily batch non-conflicting txs
	usedKeys := make(map[OrderKey]struct{})
	var batch [][]byte
	var batchKeys []OrderKey
	var remaining [][]byte

	for _, raw := range cvm.pendingTxs {
		keys := extractOrderKeys([][]byte{raw})
		conflict := false
		for _, k := range keys {
			if _, ok := usedKeys[k]; ok {
				conflict = true
				break
			}
		}
		if conflict {
			remaining = append(remaining, raw)
			continue
		}
		for _, k := range keys {
			usedKeys[k] = struct{}{}
		}
		batch = append(batch, raw)
		batchKeys = append(batchKeys, keys...)
	}
	cvm.pendingTxs = remaining

	if len(batch) == 0 {
		return nil, errNoBlocksBuilt
	}

	txIDs := make([]ids.ID, len(batch))
	for i, raw := range batch {
		h := sha256.Sum256(raw)
		txIDs[i] = ids.ID(h)
	}

	parentID := cvm.lastAcceptedID
	v := &DexVertex{
		height:  cvm.lastAcceptedHeight + 1,
		epoch:   0,
		parents: []ids.ID{parentID},
		txIDs:   txIDs,
		rawTxs:  batch,
		keys:    batchKeys,
		status:  choices.Processing,
		vm:      cvm,
	}
	v.id = v.computeID()
	v.bytes = serializeDexVertex(v)
	return v, nil
}

// ParseVertex deserializes a vertex from bytes.
func (cvm *ChainVM) ParseVertex(ctx context.Context, b []byte) (vertex.Vertex, error) {
	v, err := deserializeDexVertex(b, cvm)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func serializeDexVertex(v *DexVertex) []byte {
	buf := make([]byte, 0, 256)
	b8 := make([]byte, 8)
	b4 := make([]byte, 4)

	binary.BigEndian.PutUint64(b8, v.height)
	buf = append(buf, b8...)
	binary.BigEndian.PutUint32(b4, v.epoch)
	buf = append(buf, b4...)
	binary.BigEndian.PutUint32(b4, uint32(len(v.parents)))
	buf = append(buf, b4...)
	for _, p := range v.parents {
		buf = append(buf, p[:]...)
	}
	binary.BigEndian.PutUint32(b4, uint32(len(v.rawTxs)))
	buf = append(buf, b4...)
	for _, raw := range v.rawTxs {
		binary.BigEndian.PutUint32(b4, uint32(len(raw)))
		buf = append(buf, b4...)
		buf = append(buf, raw...)
	}
	return buf
}

func deserializeDexVertex(data []byte, cvm *ChainVM) (*DexVertex, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("dex vertex data too short: %d", len(data))
	}
	pos := 0
	height := binary.BigEndian.Uint64(data[pos:])
	pos += 8
	epoch := binary.BigEndian.Uint32(data[pos:])
	pos += 4
	pc := binary.BigEndian.Uint32(data[pos:])
	pos += 4
	parents := make([]ids.ID, pc)
	for i := uint32(0); i < pc; i++ {
		if pos+32 > len(data) {
			return nil, errInvalidBlock
		}
		copy(parents[i][:], data[pos:pos+32])
		pos += 32
	}
	if pos+4 > len(data) {
		return nil, errInvalidBlock
	}
	tc := binary.BigEndian.Uint32(data[pos:])
	pos += 4
	rawTxs := make([][]byte, 0, tc)
	txIDs := make([]ids.ID, 0, tc)
	for i := uint32(0); i < tc; i++ {
		if pos+4 > len(data) {
			return nil, errInvalidBlock
		}
		tl := binary.BigEndian.Uint32(data[pos:])
		pos += 4
		if pos+int(tl) > len(data) {
			return nil, errInvalidBlock
		}
		raw := make([]byte, tl)
		copy(raw, data[pos:pos+int(tl)])
		rawTxs = append(rawTxs, raw)
		h := sha256.Sum256(raw)
		txIDs = append(txIDs, ids.ID(h))
		pos += int(tl)
	}

	v := &DexVertex{
		height:  height,
		epoch:   epoch,
		parents: parents,
		txIDs:   txIDs,
		rawTxs:  rawTxs,
		keys:    extractOrderKeys(rawTxs),
		status:  choices.Unknown,
		vm:      cvm,
		bytes:   data,
	}
	v.id = v.computeID()
	return v, nil
}
