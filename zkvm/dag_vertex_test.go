// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"testing"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
)

func TestVertexConflicts_OverlappingNullifiers(t *testing.T) {
	shared := []byte("nullifier-A")

	v1 := &Vertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		txs: []*Transaction{
			{ID: ids.GenerateTestID(), Nullifiers: [][]byte{shared, []byte("n1-only")}},
		},
	}
	v2 := &Vertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		txs: []*Transaction{
			{ID: ids.GenerateTestID(), Nullifiers: [][]byte{shared, []byte("n2-only")}},
		},
	}

	if !v1.Conflicts(v2) {
		t.Fatal("expected conflict: vertices share nullifier-A")
	}
	if !v2.Conflicts(v1) {
		t.Fatal("expected conflict: symmetric check failed")
	}
}

func TestVertexConflicts_DisjointNullifiers(t *testing.T) {
	v1 := &Vertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		txs: []*Transaction{
			{ID: ids.GenerateTestID(), Nullifiers: [][]byte{[]byte("alpha")}},
		},
	}
	v2 := &Vertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		txs: []*Transaction{
			{ID: ids.GenerateTestID(), Nullifiers: [][]byte{[]byte("beta")}},
		},
	}

	if v1.Conflicts(v2) {
		t.Fatal("expected no conflict: nullifier sets are disjoint")
	}
	if v2.Conflicts(v1) {
		t.Fatal("expected no conflict: symmetric check should also be false")
	}
}

func TestVertexConflicts_MultiTx(t *testing.T) {
	v1 := &Vertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		txs: []*Transaction{
			{ID: ids.GenerateTestID(), Nullifiers: [][]byte{[]byte("a")}},
			{ID: ids.GenerateTestID(), Nullifiers: [][]byte{[]byte("b")}},
		},
	}
	v2 := &Vertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		txs: []*Transaction{
			{ID: ids.GenerateTestID(), Nullifiers: [][]byte{[]byte("b")}},
			{ID: ids.GenerateTestID(), Nullifiers: [][]byte{[]byte("c")}},
		},
	}

	if !v1.Conflicts(v2) {
		t.Fatal("expected conflict on nullifier b across multi-tx vertices")
	}
}
