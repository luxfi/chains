// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// seedVM is the smallest VM seedGenesis needs: a store and a log. Building the
// whole VM would test the constructor, not the property under test.
func seedVM(t *testing.T) (*VM, *memdb.Database) {
	t.Helper()
	db := memdb.New()
	vm := &VM{log: log.NewNoOpLogger(), db: db}
	vm.versiondb = versiondb.New(db)
	vm.state = vm.versiondb
	return vm, db
}

// TestSeedGenesisNamesATip is the property the chain could not start without.
//
// Bootstrap asks each beacon which block it holds, and an answer naming no block
// is not counted as a responder — so if every node names nothing, the response
// floor is unreachable and the chain waits on itself for as long as it runs. The
// assertion is therefore not "a block exists" but "the VM can NAME one".
func TestSeedGenesisNamesATip(t *testing.T) {
	vm, _ := seedVM(t)

	if got := vm.getLastAcceptedID(); got != ids.Empty {
		t.Fatalf("precondition: a fresh VM should name no block, got %s", got)
	}

	if err := vm.seedGenesis(); err != nil {
		t.Fatalf("seedGenesis: %v", err)
	}

	if got := vm.getLastAcceptedID(); got == ids.Empty {
		t.Fatal("VM still names no block after seeding — every beacon reply would " +
			"be dropped and the chain could never reach its bootstrap quorum")
	}
	if got := vm.getHeight(); got != 0 {
		t.Fatalf("genesis height = %d, want 0", got)
	}
}

// genesisID is the one block every Q-Chain node must name at height 0.
//
// It is pinned rather than recomputed because the property is not "two VMs in
// this test agree" — two VMs seeded in the same second agree even with a
// wall-clock timestamp, since the wire carries Unix SECONDS, so that assertion
// passes for a build that forks in production where nodes start minutes apart.
// A constant is the only assertion that fails for every input a node could
// disagree on. If this value must change, the chain is being re-genesised and
// every node has to move together.
const genesisID = "23YdHYkgL766qjZojgBBey3RuvMfuZgtJkvgJ3yEFFVK5UcKEQ"

// TestSeedGenesisAgreesAcrossNodes is the safety half. Each node seeds alone,
// without talking to any other, so if the block were a function of anything
// local — wall-clock time above all — the nodes would name different genesis
// blocks and the repair would be a fork rather than a fix.
func TestSeedGenesisAgreesAcrossNodes(t *testing.T) {
	a, _ := seedVM(t)
	b, _ := seedVM(t)

	if err := a.seedGenesis(); err != nil {
		t.Fatalf("node a: %v", err)
	}
	if err := b.seedGenesis(); err != nil {
		t.Fatalf("node b: %v", err)
	}

	if a.getLastAcceptedID() != b.getLastAcceptedID() {
		t.Fatalf("nodes disagree on genesis: %s vs %s — this would fork the chain",
			a.getLastAcceptedID(), b.getLastAcceptedID())
	}
	if got := a.getLastAcceptedID().String(); got != genesisID {
		t.Fatalf("genesis id = %s, want %s — the block is not a constant, so nodes "+
			"that start at different times will name different genesis blocks", got, genesisID)
	}
}

// TestSeedGenesisLeavesAnExistingChainAlone: Initialize runs on every start, so
// seeding must be a no-op once a chain has a tip. Overwriting it would rewind a
// running chain to height 0 on restart.
func TestSeedGenesisLeavesAnExistingChainAlone(t *testing.T) {
	vm, _ := seedVM(t)
	if err := vm.seedGenesis(); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	first := vm.getLastAcceptedID()

	// Advance the chain, as a running node would.
	blk := &Block{timestamp: time.Unix(100, 0).UTC(), height: 7, parentID: first, vm: vm}
	blk.id = blk.computeID()
	if err := blk.Accept(context.Background()); err != nil {
		t.Fatalf("accept: %v", err)
	}

	if err := vm.seedGenesis(); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if got := vm.getLastAcceptedID(); got != blk.id {
		t.Fatalf("seeding rewound a live chain: tip %s became %s", blk.id, got)
	}
	if got := vm.getHeight(); got != 7 {
		t.Fatalf("seeding rewound height to %d, want 7", got)
	}
}

// TestSeedGenesisSurvivesRestart covers the commit. A tip held only in the
// version layer is gone at the next start, and the node is back to naming no
// block — the same deadlock, one restart later.
func TestSeedGenesisSurvivesRestart(t *testing.T) {
	vm, db := seedVM(t)
	if err := vm.seedGenesis(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	want := vm.getLastAcceptedID()

	// Restart: a new version layer over the SAME underlying store.
	restarted := &VM{log: log.NewNoOpLogger(), db: db}
	restarted.versiondb = versiondb.New(db)
	restarted.state = restarted.versiondb

	if got := restarted.getLastAcceptedID(); got != want {
		t.Fatalf("genesis did not survive restart: %s != %s (uncommitted)", got, want)
	}
}
