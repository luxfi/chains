// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayvm

import (
	"testing"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
)

func TestRelayVertexConflicts_SameDestNonce(t *testing.T) {
	dest := ids.GenerateTestID()

	v1 := &RelayVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []DestNonceKey{{DestChain: dest, Nonce: 7}},
	}
	v2 := &RelayVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []DestNonceKey{{DestChain: dest, Nonce: 7}},
	}

	if !v1.Conflicts(v2) {
		t.Fatal("expected conflict: same (destChain, nonce)")
	}
	if !v2.Conflicts(v1) {
		t.Fatal("expected conflict: symmetric check failed")
	}
}

func TestRelayVertexConflicts_DifferentDests(t *testing.T) {
	v1 := &RelayVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []DestNonceKey{{DestChain: ids.GenerateTestID(), Nonce: 1}},
	}
	v2 := &RelayVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []DestNonceKey{{DestChain: ids.GenerateTestID(), Nonce: 1}},
	}

	if v1.Conflicts(v2) {
		t.Fatal("expected no conflict: different destination chains")
	}
}

func TestRelayVertexConflicts_SameDestDifferentNonce(t *testing.T) {
	dest := ids.GenerateTestID()

	v1 := &RelayVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []DestNonceKey{{DestChain: dest, Nonce: 1}},
	}
	v2 := &RelayVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []DestNonceKey{{DestChain: dest, Nonce: 2}},
	}

	if v1.Conflicts(v2) {
		t.Fatal("expected no conflict: same dest but different nonces")
	}
}
