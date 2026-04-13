// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/ids"

	"github.com/luxfi/ai/pkg/aivm"
)

var _ vertex.DAGVM = (*VM)(nil)

// AIVertex represents a DAG vertex in the AI chain.
// Conflict key: jobID. Independent jobs commute; same job conflicts.
type AIVertex struct {
	id      ids.ID
	bytes   []byte
	height  uint64
	epoch   uint32
	parents []ids.ID
	txIDs   []ids.ID
	status  choices.Status

	tasks   []*aivm.Task
	results []*aivm.TaskResult
	jobIDs  []string
	vm      *VM
}

func (v *AIVertex) ID() ids.ID          { return v.id }
func (v *AIVertex) Bytes() []byte        { return v.bytes }
func (v *AIVertex) Height() uint64       { return v.height }
func (v *AIVertex) Epoch() uint32        { return v.epoch }
func (v *AIVertex) Parents() []ids.ID    { return v.parents }
func (v *AIVertex) Txs() []ids.ID        { return v.txIDs }
func (v *AIVertex) Status() choices.Status { return v.status }

func (v *AIVertex) Verify(ctx context.Context) error {
	for _, task := range v.tasks {
		if task.ID == "" {
			return errors.New("task missing ID")
		}
	}
	return nil
}

func (v *AIVertex) Accept(ctx context.Context) error {
	v.status = choices.Accepted

	v.vm.mu.Lock()
	defer v.vm.mu.Unlock()

	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := v.vm.db.Put(v.id[:], b); err != nil {
		return err
	}
	v.vm.lastAcceptedID = v.id
	delete(v.vm.pendingBlocks, v.id)
	return nil
}

func (v *AIVertex) Reject(ctx context.Context) error {
	v.status = choices.Rejected
	v.vm.mu.Lock()
	delete(v.vm.pendingBlocks, v.id)
	v.vm.mu.Unlock()
	return nil
}

// jobIDSet returns the set of jobIDs for conflict detection.
func (v *AIVertex) jobIDSet() map[string]struct{} {
	s := make(map[string]struct{}, len(v.jobIDs))
	for _, j := range v.jobIDs {
		s[j] = struct{}{}
	}
	return s
}

// Conflicts returns true if this vertex and other reference the same jobID.
func (v *AIVertex) Conflicts(other *AIVertex) bool {
	ours := v.jobIDSet()
	for _, j := range other.jobIDs {
		if _, ok := ours[j]; ok {
			return true
		}
	}
	return false
}

// ConflictsVertex performs the same check against the vertex.Vertex interface.
func (v *AIVertex) ConflictsVertex(other vertex.Vertex) bool {
	ov, ok := other.(*AIVertex)
	if !ok {
		return false
	}
	return v.Conflicts(ov)
}

func (v *AIVertex) computeID() ids.ID {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, v.height)
	binary.Write(h, binary.BigEndian, v.epoch)
	for _, p := range v.parents {
		h.Write(p[:])
	}
	for _, j := range v.jobIDs {
		h.Write([]byte(j))
	}
	return ids.ID(h.Sum(nil))
}

// BuildVertex creates a vertex from pending tasks/results, batching independent jobs.
func (vm *VM) BuildVertex(ctx context.Context) (vertex.Vertex, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return nil, ErrNotInitialized
	}

	parent := vm.lastAccepted
	if parent == nil {
		return nil, errors.New("no parent block")
	}

	// Collect pending tasks from core (empty providerID = all pending)
	pendingTasks := vm.core.GetPendingTasks("")
	if len(pendingTasks) == 0 {
		return nil, errors.New("no pending tasks")
	}

	// Greedily batch non-conflicting tasks (unique jobIDs)
	seen := make(map[string]struct{})
	var batch []*aivm.Task
	var jobIDs []string
	for _, task := range pendingTasks {
		if _, dup := seen[task.ID]; dup {
			continue
		}
		seen[task.ID] = struct{}{}
		batch = append(batch, task)
		jobIDs = append(jobIDs, task.ID)
	}

	txIDs := make([]ids.ID, len(batch))
	for i, task := range batch {
		h := sha256.Sum256([]byte(task.ID))
		txIDs[i] = ids.ID(h)
	}

	v := &AIVertex{
		height:  parent.Height_ + 1,
		epoch:   0,
		parents: []ids.ID{vm.lastAcceptedID},
		txIDs:   txIDs,
		tasks:   batch,
		jobIDs:  jobIDs,
		status:  choices.Processing,
		vm:      vm,
	}
	v.id = v.computeID()
	v.bytes, _ = json.Marshal(v)
	return v, nil
}

// ParseVertex deserializes a vertex from bytes.
func (vm *VM) ParseVertex(ctx context.Context, b []byte) (vertex.Vertex, error) {
	v := &AIVertex{vm: vm}
	if err := json.Unmarshal(b, v); err != nil {
		return nil, err
	}
	v.id = v.computeID()
	v.bytes = b
	return v, nil
}
