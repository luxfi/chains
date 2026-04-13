// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/ids"
)

var _ vertex.DAGVM = (*VM)(nil)

// DestNonceKey is the conflict key for the Relay VM: (destChain, nonce).
// Two vertices conflict iff they relay to the same chain with the same nonce.
type DestNonceKey struct {
	DestChain ids.ID
	Nonce     uint64
}

// RelayVertex represents a DAG vertex in the Relay chain.
type RelayVertex struct {
	id      ids.ID
	bytes   []byte
	height  uint64
	epoch   uint32
	parents []ids.ID
	txIDs   []ids.ID
	status  choices.Status

	messages []*Message
	keys     []DestNonceKey
	vm       *VM
}

func (v *RelayVertex) ID() ids.ID          { return v.id }
func (v *RelayVertex) Bytes() []byte        { return v.bytes }
func (v *RelayVertex) Height() uint64       { return v.height }
func (v *RelayVertex) Epoch() uint32        { return v.epoch }
func (v *RelayVertex) Parents() []ids.ID    { return v.parents }
func (v *RelayVertex) Txs() []ids.ID        { return v.txIDs }
func (v *RelayVertex) Status() choices.Status { return v.status }

func (v *RelayVertex) Verify(ctx context.Context) error {
	for _, msg := range v.messages {
		if len(msg.Payload) > v.vm.config.MaxMessageSize {
			return errMessageTooLarge
		}
		if _, err := v.vm.GetChannel(msg.ChannelID); err != nil {
			return err
		}
	}
	return nil
}

func (v *RelayVertex) Accept(ctx context.Context) error {
	v.status = choices.Accepted

	v.vm.mu.Lock()
	defer v.vm.mu.Unlock()

	id := v.ID()
	if err := v.vm.db.Put(lastAcceptedKey, id[:]); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := v.vm.db.Put(id[:], b); err != nil {
		return err
	}

	// Mark messages delivered
	for _, msg := range v.messages {
		msg.State = MessageDelivered
		msgBytes, _ := json.Marshal(msg)
		msgKey := append(messagePrefix, msg.ID[:]...)
		v.vm.db.Put(msgKey, msgBytes)

		// Remove from pending
		destMsgs := v.vm.pendingMsgs[msg.DestChain]
		for i, m := range destMsgs {
			if m.ID == msg.ID {
				v.vm.pendingMsgs[msg.DestChain] = append(destMsgs[:i], destMsgs[i+1:]...)
				break
			}
		}
	}

	v.vm.lastAcceptedID = id
	delete(v.vm.pendingBlocks, id)
	return nil
}

func (v *RelayVertex) Reject(ctx context.Context) error {
	v.status = choices.Rejected
	v.vm.mu.Lock()
	delete(v.vm.pendingBlocks, v.id)
	v.vm.mu.Unlock()
	return nil
}

// conflictKeySet returns the set of DestNonceKeys for conflict detection.
func (v *RelayVertex) conflictKeySet() map[DestNonceKey]struct{} {
	s := make(map[DestNonceKey]struct{}, len(v.keys))
	for _, k := range v.keys {
		s[k] = struct{}{}
	}
	return s
}

// Conflicts returns true if this vertex and other share any (destChain, nonce) pair.
func (v *RelayVertex) Conflicts(other *RelayVertex) bool {
	ours := v.conflictKeySet()
	for _, k := range other.keys {
		if _, ok := ours[k]; ok {
			return true
		}
	}
	return false
}

// ConflictsVertex performs the same check against the vertex.Vertex interface.
func (v *RelayVertex) ConflictsVertex(other vertex.Vertex) bool {
	ov, ok := other.(*RelayVertex)
	if !ok {
		return false
	}
	return v.Conflicts(ov)
}

// extractDestNonceKeys derives conflict keys from messages.
func extractDestNonceKeys(msgs []*Message) []DestNonceKey {
	seen := make(map[DestNonceKey]struct{})
	var keys []DestNonceKey
	for _, msg := range msgs {
		k := DestNonceKey{DestChain: msg.DestChain, Nonce: msg.Sequence}
		if _, dup := seen[k]; !dup {
			seen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	return keys
}

func (v *RelayVertex) computeID() ids.ID {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, v.height)
	binary.Write(h, binary.BigEndian, v.epoch)
	for _, p := range v.parents {
		h.Write(p[:])
	}
	for _, msg := range v.messages {
		h.Write(msg.ID[:])
	}
	return ids.ID(h.Sum(nil))
}

// BuildVertex creates a vertex from pending messages, batching non-conflicting ones.
func (vm *VM) BuildVertex(ctx context.Context) (vertex.Vertex, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if vm.lastAccepted == nil {
		return nil, errors.New("no parent block")
	}

	// Collect all pending messages across destinations
	var allMsgs []*Message
	for _, msgs := range vm.pendingMsgs {
		allMsgs = append(allMsgs, msgs...)
	}
	if len(allMsgs) == 0 {
		return nil, errors.New("no pending messages")
	}

	// Greedily batch non-conflicting messages (unique destChain+nonce)
	usedKeys := make(map[DestNonceKey]struct{})
	var batch []*Message
	for _, msg := range allMsgs {
		k := DestNonceKey{DestChain: msg.DestChain, Nonce: msg.Sequence}
		if _, ok := usedKeys[k]; ok {
			continue
		}
		usedKeys[k] = struct{}{}
		batch = append(batch, msg)
	}

	keys := extractDestNonceKeys(batch)
	txIDs := make([]ids.ID, len(batch))
	for i, msg := range batch {
		txIDs[i] = msg.ID
	}

	v := &RelayVertex{
		height:   vm.lastAccepted.BlockHeight + 1,
		epoch:    0,
		parents:  []ids.ID{vm.lastAcceptedID},
		txIDs:    txIDs,
		messages: batch,
		keys:     keys,
		status:   choices.Processing,
		vm:       vm,
	}
	v.id = v.computeID()
	v.bytes, _ = json.Marshal(v)
	return v, nil
}

// ParseVertex deserializes a vertex from bytes.
func (vm *VM) ParseVertex(ctx context.Context, b []byte) (vertex.Vertex, error) {
	v := &RelayVertex{vm: vm}
	if err := json.Unmarshal(b, v); err != nil {
		return nil, err
	}
	v.keys = extractDestNonceKeys(v.messages)
	v.id = v.computeID()
	v.bytes = b
	return v, nil
}
