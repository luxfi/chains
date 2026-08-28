// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/ids"
)

// parseVM is a VM with the stock config — the one production runs — and enough
// wiring to serialize and parse. Building the whole VM would test the
// constructor, not the property.
func parseVM(t *testing.T) *VM {
	t.Helper()
	vm, _ := seedVM(t)
	vm.Config = config.DefaultConfig()
	return vm
}

// TestParseAcceptsWhatWeSerialize is the property this chain could not move
// without, and the one nothing asserted.
//
// ParseBlock is the sole entry point for catch-up, gossip and Put. If it refuses
// the bytes this VM itself produces, then every node serves a block every node
// refuses, and the chain accepts nothing for as long as it runs — which is what
// happened: certAccepted=0, appliedHead=0 on every validator, on every network,
// forever, while the package's own tests stayed green because none of them ever
// sent a block through Bytes() and back.
func TestParseAcceptsWhatWeSerialize(t *testing.T) {
	vm := parseVM(t)

	blk := &Block{
		timestamp:    time.Unix(1000, 0).UTC(),
		height:       7,
		parentID:     ids.GenerateTestID(),
		chainID:      vm.blockchainID,
		networkID:    vm.NetworkID,
		transactions: []Transaction{stampedTx(1, "op")},
		vm:           vm,
	}
	blk.id = blk.computeID()

	got, err := vm.ParseBlock(context.Background(), blk.Bytes())
	if err != nil {
		t.Fatalf("ParseBlock refused bytes this VM serialized: %v\n"+
			"a block every node serves and every node refuses is a chain that cannot move", err)
	}
	if got.ID() != blk.id {
		t.Fatalf("round trip changed the block id: %s -> %s", blk.id, got.ID())
	}
	if got.Height() != 7 {
		t.Fatalf("round trip changed height: %d", got.Height())
	}
}

// TestGenesisParses: genesis is the block every node must parse, and it is
// signed by nobody — seedGenesis deliberately writes no signature, because a
// per-node signature would give each node a different genesis id. Any gate that
// demands one therefore refuses the one block the whole chain is anchored to.
func TestGenesisParses(t *testing.T) {
	vm := parseVM(t)
	if err := vm.seedGenesis(); err != nil {
		t.Fatalf("seedGenesis: %v", err)
	}
	gid := tipOf(t, vm)
	raw, err := vm.state.Get(gid[:])
	if err != nil {
		t.Fatalf("read genesis bytes: %v", err)
	}
	got, err := vm.ParseBlock(context.Background(), raw)
	if err != nil {
		t.Fatalf("ParseBlock refused GENESIS: %v", err)
	}
	if got.Height() != 0 {
		t.Fatalf("genesis height = %d, want 0", got.Height())
	}
}

// TestServeAndReceiveAgree pins the asymmetry itself.
//
// A responder answers a catch-up request with the bytes it stored; the
// requester admits the reply through ParseBlock. They are two doors into one
// format, so a check on only one of them means the fleet serves what it will
// not accept. Whatever either door does to a block, both must reach the same
// verdict.
func TestServeAndReceiveAgree(t *testing.T) {
	vm := parseVM(t)
	if err := vm.seedGenesis(); err != nil {
		t.Fatalf("seedGenesis: %v", err)
	}

	blk := &Block{
		timestamp:    time.Unix(2000, 0).UTC(),
		height:       1,
		parentID:     tipOf(t, vm),
		chainID:      vm.blockchainID,
		networkID:    vm.NetworkID,
		transactions: []Transaction{stampedTx(1, "op")},
		vm:           vm,
	}
	blk.id = blk.computeID()
	if err := blk.Accept(context.Background()); err != nil {
		t.Fatalf("accept: %v", err)
	}

	served, servErr := vm.GetBlock(context.Background(), blk.id) // responder side
	received, recvErr := vm.ParseBlock(context.Background(), blk.Bytes())
	if (servErr == nil) != (recvErr == nil) {
		t.Fatalf("the two paths disagree on identical bytes: serve=%v receive=%v\n"+
			"every node would serve this block and every node would refuse it", servErr, recvErr)
	}
	if servErr == nil && served.ID() != received.ID() {
		t.Fatalf("one block read back under two ids: %s vs %s", served.ID(), received.ID())
	}
}
