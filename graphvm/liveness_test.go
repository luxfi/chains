// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestThisChainBuildsNoBlocks pins the design rather than the omission it looks
// like. G-Chain indexes what other chains have already agreed, so it holds no
// state of its own to agree on. A block here would carry a query result, which
// a peer recomputes from state, or a schema, which is local configuration —
// neither is something the network votes on.
//
// The other chains here had work and no way to tell consensus about it, and were
// given a latch. This one has nothing to tell, and a latch would wake a builder
// that declines. The test exists so that difference stays visible.
func TestThisChainBuildsNoBlocks(t *testing.T) {
	vm := &VM{}

	_, err := vm.BuildBlock(context.Background())
	if !errors.Is(err, errReadOnlyChain) {
		t.Fatalf("BuildBlock must decline for the stated reason, got: %v", err)
	}

	// And it reports no work, however long anyone waits.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := vm.WaitForEvent(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitForEvent reported work on a chain that builds nothing: %v", err)
	}
}
