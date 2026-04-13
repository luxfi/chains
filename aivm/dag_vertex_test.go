// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"testing"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
)

func TestAIVertexConflicts_SameJobID(t *testing.T) {
	v1 := &AIVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		jobIDs: []string{"job-123", "job-456"},
	}
	v2 := &AIVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		jobIDs: []string{"job-123", "job-789"},
	}

	if !v1.Conflicts(v2) {
		t.Fatal("expected conflict: both reference job-123")
	}
	if !v2.Conflicts(v1) {
		t.Fatal("expected conflict: symmetric check failed")
	}
}

func TestAIVertexConflicts_DisjointJobIDs(t *testing.T) {
	v1 := &AIVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		jobIDs: []string{"job-A"},
	}
	v2 := &AIVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		jobIDs: []string{"job-B"},
	}

	if v1.Conflicts(v2) {
		t.Fatal("expected no conflict: independent jobs commute")
	}
}
