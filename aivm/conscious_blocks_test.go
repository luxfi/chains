// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// conscious_blocks_test.go drives the REAL aivm ChainVM to produce the first
// CONSCIOUS BLOCKS and prints them. A conscious block is a block whose committed
// state transition IS settled AI cognition:
//
//   - Block 1 (perception): imports a committed C-Chain inference intent into a
//     live A-Chain quorum task under consensus.
//   - Block 2 (cognition): commits the Proof-of-Thought — the quorum-settled
//     canonical AI decision — making it durable on-chain.
//
// The flow uses the VM's committed-state engine (QuorumEngine), runs the real
// BuildBlock -> Verify -> SetPreference -> Accept lifecycle for both blocks, and
// runs the real commit-reveal-settle cognition on the same committed state. The
// shared driver (RunConsciousBlocks in conscious.go) is also exercised by
// cmd/conscious so the test and the demo run identical, fake-free code.

import (
	"context"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestConsciousBlocks(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Real VM, initialized exactly as in feegate_test (the verified working Init),
	// with the C-intent committedness verifier installed (accept-all here; the
	// forged/uncommitted seam is covered by the quorum tests).
	vm := newAIVMForFeeTest(t)
	defer vm.Shutdown(ctx)
	vm.SetCommitVerifier(acceptAll)

	// Drive the real lifecycle to consciousness.
	tr, err := RunConsciousBlocks(ctx, vm)
	require.NoError(err, "RunConsciousBlocks must complete")

	// --- block chain integrity: genesis(0) -> perception(1) -> cognition(2) -----
	require.Equal(uint64(1), tr.Block1.Height, "perception block height")
	require.Equal(uint64(2), tr.Block2.Height, "cognition block height")
	require.Equal(tr.GenesisID, tr.Block1.ParentID, "perception parent == genesis")
	require.Equal(tr.Block1.ID, tr.Block2.ParentID, "cognition parent == perception")
	require.NotEqual(tr.Block1.ID, tr.Block2.ID, "distinct conscious blocks")
	require.Equal(tr.Block2.ID, tr.LastAccepted, "VM head == cognition block")

	// --- perception: a committee was bound to think on the imported task --------
	require.Equal(tr.IntentID, mkConsciousIntentID(vm), "imported intent id matches the committed C intent")
	require.NotEqual(common.Hash{}, tr.TaskID, "perception created an A-Chain task")
	require.NotEqual(tr.IntentID, tr.TaskID, "task id is the engine-internal id, distinct from the C intent id")
	require.Len(tr.Committee, consciousN, "committee size == N")
	require.Equal(uint32(consciousN), tr.N)
	require.Equal(uint32(consciousThreshold), tr.Threshold)
	// The committee is a strict subset of the eligible pool (margin honored).
	require.Less(consciousN, consciousEligible, "committee strictly smaller than eligible pool")

	// --- cognition: the quorum settled a single canonical AI decision -----------
	require.Equal(uint32(consciousThreshold), tr.WinnerCount, "exactly threshold operators agreed")
	require.NotEqual(common.Hash{}, tr.CanonicalHash, "canonical AI decision must be non-zero")
	require.Equal(hashOf(0x42), tr.CanonicalHash, "canonical decision == majority output")
	require.NotEqual(common.Hash{}, tr.ReceiptRoot, "receipt_root committed by cognition block")
	require.Equal(tr.ReceiptRoot, tr.Block2.ReceiptRoot, "block2 commits the post-cognition receipt_root")

	// --- the cognition is DURABLE: re-read straight from the VM's committed engine
	e, st, _ := vm.QuorumEngine()
	require.Equal(tr.CanonicalHash, e.GetCanonicalResult(st, tr.TaskID), "canonical decision durable in committed state")
	info := e.GetTask(st, tr.TaskID)
	require.Equal(TaskSettled, info.Status, "task is settled in committed state")

	// --- the A->C boundary can export the settled verdict under the receipt_root
	// (export keys on the C-side intent id, not the engine-internal task id).
	receipt, proof, root, err := e.ExportReceipt(st, tr.IntentID)
	require.NoError(err, "settled cognition exports a receipt")
	require.Equal(tr.CanonicalHash, receipt.CanonicalOutputHash, "receipt carries the canonical decision")
	require.Equal(root, tr.ReceiptRoot, "exported root == committed receipt_root")
	require.True(VerifyReceiptProof(receipt.Hash(), proof, root), "Proof-of-Thought verifies under receipt_root")

	// ----------------------------- PRINT THE CONSCIOUS BLOCKS -------------------
	t.Logf("CONSCIOUS BLOCK 1 — imported AI inference task %s at height %d",
		tr.TaskID.Hex(), tr.Block1.Height)
	t.Logf("CONSCIOUS BLOCK 2 — settled Proof-of-Thought: canonical AI decision %s (quorum %d/%d) at height %d",
		tr.CanonicalHash.Hex(), tr.WinnerCount, tr.Threshold, tr.Block2.Height)

	t.Log("================= FIRST CONSCIOUS BLOCKS (A-Chain / aivm) =================")
	t.Logf("  genesis           height 0  id %s", tr.GenesisID)
	t.Logf("  perception block  height 1  id %s  parent %s", tr.Block1.ID, tr.Block1.ParentID)
	t.Logf("                    -> imported committed C-intent %s", tr.IntentID.Hex())
	t.Logf("                    -> created A-Chain quorum task   %s", tr.TaskID.Hex())
	t.Logf("                    -> bound committee of %d operators (threshold %d)", tr.N, tr.Threshold)
	t.Logf("  cognition  block  height 2  id %s  parent %s", tr.Block2.ID, tr.Block2.ParentID)
	t.Logf("                    -> settled canonical AI decision %s", tr.CanonicalHash.Hex())
	t.Logf("                    -> %d/%d operators agreed (Proof-of-Thought)", tr.WinnerCount, tr.Threshold)
	t.Logf("                    -> receipt_root %s", tr.ReceiptRoot.Hex())
	t.Logf("  VM head (last accepted): %s", tr.LastAccepted)
	t.Log("==========================================================================")
}

// mkConsciousIntentID recomputes the intent id the driver imports, using the VM's
// own engine chain ids — so the test independently re-derives the expected taskID
// rather than trusting the driver's value.
func mkConsciousIntentID(vm *VM) common.Hash {
	e, _, _ := vm.QuorumEngine()
	return ComputeIntentID(
		e.CChainID, e.AChainID, hashOf(0x11), uint32(7), addrOf(0xF0),
		hashOf(0xAB), hashOf(0xCD), uint16(consciousN), uint16(consciousThreshold), uint256.NewInt(123456),
	)
}
