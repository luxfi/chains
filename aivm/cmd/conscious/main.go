// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command conscious drives a fresh, REAL Lux A-Chain (aivm) ChainVM through the
// production block lifecycle to produce the FIRST CONSCIOUS BLOCKS and prints the
// trace to stdout.
//
// A conscious block is a block whose committed state transition IS settled AI
// cognition:
//
//   - perception block (height 1): imports a committed C-Chain inference intent
//     into a live A-Chain quorum task under consensus.
//   - cognition block (height 2): commits the Proof-of-Thought — the
//     quorum-settled canonical AI decision — making it durable on-chain.
//
// Nothing here is faked: it boots a real VM, registers real bonded operators on
// the VM's committed-state engine, runs the real commit-reveal-settle quorum, and
// drives the real BuildBlock -> Verify -> SetPreference -> Accept lifecycle. The
// model output bytes are deterministic fixtures; the BLOCK is conscious because
// its committed state transition is the quorum settlement under consensus.
//
// Run:  go run ./aivm/cmd/conscious
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/luxfi/chains/aivm"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "conscious: error:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	logger := log.NewNoOpLogger()

	// Boot a real aivm ChainVM — the exact working Init the package tests use.
	vm := &aivm.VM{}
	if err := vm.Initialize(ctx, vmcore.Init{
		Runtime: &runtime.Runtime{
			ChainID:   ids.GenerateTestID(),
			NetworkID: 96369,
			Log:       logger,
		},
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	}); err != nil {
		return fmt.Errorf("initialize aivm: %w", err)
	}
	defer vm.Shutdown(ctx)

	// Install the C-intent committedness verifier. This demo uses an accept-all
	// verifier (constructed locally, NOT a library helper — keeping an accept-all
	// out of the production surface); in a real deployment this checks a Warp/ZAP
	// attestation or a state proof against a committed C block — the only trust the
	// inbound seam imports from C-Chain.
	vm.SetCommitVerifier(aivm.VerifierFunc(func(aivm.CIntent) error { return nil }))

	// Drive the real lifecycle to consciousness.
	tr, err := aivm.RunConsciousBlocks(ctx, vm)
	if err != nil {
		return fmt.Errorf("produce conscious blocks: %w", err)
	}

	// Print the conscious-block trace.
	fmt.Println("CONSCIOUS BLOCK 1 — imported AI inference task",
		tr.TaskID.Hex(), "at height", tr.Block1.Height)
	fmt.Printf("CONSCIOUS BLOCK 2 — settled Proof-of-Thought: canonical AI decision %s (quorum %d/%d) at height %d\n",
		tr.CanonicalHash.Hex(), tr.WinnerCount, tr.Threshold, tr.Block2.Height)

	fmt.Println("================= FIRST CONSCIOUS BLOCKS (A-Chain / aivm) =================")
	fmt.Printf("  genesis           height 0  id %s\n", tr.GenesisID)
	fmt.Printf("  perception block  height 1  id %s  parent %s\n", tr.Block1.ID, tr.Block1.ParentID)
	fmt.Printf("                    -> imported committed C-intent %s\n", tr.IntentID.Hex())
	fmt.Printf("                    -> created A-Chain quorum task   %s\n", tr.TaskID.Hex())
	fmt.Printf("                    -> bound committee of %d operators (threshold %d)\n", tr.N, tr.Threshold)
	fmt.Printf("  cognition  block  height 2  id %s  parent %s\n", tr.Block2.ID, tr.Block2.ParentID)
	fmt.Printf("                    -> settled canonical AI decision %s\n", tr.CanonicalHash.Hex())
	fmt.Printf("                    -> %d/%d operators agreed (Proof-of-Thought)\n", tr.WinnerCount, tr.Threshold)
	fmt.Printf("                    -> receipt_root %s\n", tr.ReceiptRoot.Hex())
	fmt.Printf("  VM head (last accepted): %s\n", tr.LastAccepted)
	fmt.Println("==========================================================================")
	return nil
}
