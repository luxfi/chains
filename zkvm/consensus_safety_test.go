// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// spendTx builds a shielded transfer that spends the given nullifiers.
func spendTx(nullifiers ...[]byte) *Transaction {
	tx := &Transaction{
		Type:       TransactionTypeTransfer,
		Version:    1,
		Nullifiers: nullifiers,
		Outputs: []*ShieldedOutput{
			{
				Commitment:      make([]byte, 32),
				EncryptedNote:   make([]byte, 32),
				EphemeralPubKey: make([]byte, 32),
				OutputProof:     make([]byte, 32),
			},
		},
		Proof:  &ZKProof{ProofType: "groth16", ProofData: make([]byte, 32)},
		Fee:    1,
		Expiry: 1 << 20,
	}
	tx.ID = tx.ComputeID()
	return tx
}

func nullifier(b byte) []byte {
	n := make([]byte, 32)
	n[0] = b
	return n
}

// acceptProofs makes each tx's proof verify, so a Verify failure can only come
// from a block-level rule. Without it the test VM's dummy verifying keys reject
// every tx first and the block-level gate is never reached — which is exactly the
// confound these tests must not hide behind.
func acceptProofs(vmImpl *VM, txs ...*Transaction) {
	pv := vmImpl.proofVerifier
	pv.dummyKeys = false
	for _, tx := range txs {
		pv.proofCache.Add(tx.ComputeID(), true)
	}
}

// TestComputeStateRootIsPure pins the state root as a pure function of the
// committed root plus the block's txs. Computing it must not mutate the tree,
// because Block.Verify computes it: a second Verify of the same block, or a
// Verify of the block that wins a poll after a loser was already verified, would
// otherwise see a different root and reject a valid block.
func TestComputeStateRootIsPure(t *testing.T) {
	require := require.New(t)
	vmImpl := setupTestVM(t)
	defer vmImpl.Shutdown(context.Background())

	txs := []*Transaction{spendTx(nullifier(1)), spendTx(nullifier(2))}

	first := vmImpl.computeStateRoot(txs)
	second := vmImpl.computeStateRoot(txs)
	require.Equal(first, second, "computing the root twice must give the same root")

	// Computing the root for a competing block must not disturb the root of the
	// block that actually wins.
	loser := []*Transaction{spendTx(nullifier(9))}
	vmImpl.computeStateRoot(loser)
	require.Equal(first, vmImpl.computeStateRoot(txs),
		"a rejected block's root computation must not poison later ones")
}

// TestStateRootHasOneDefinition pins the consensus root to a single hash
// function: SHA-256 over currentRoot ‖ commitments ‖ nullifiers. A second,
// hardware-conditional digest (a GPU Poseidon path with a SHA-256 fallback)
// would make the committed root depend on whether the validator has an
// accelerator, and nodes with and without one would reject each other's blocks.
func TestStateRootHasOneDefinition(t *testing.T) {
	require := require.New(t)
	vmImpl := setupTestVM(t)
	defer vmImpl.Shutdown(context.Background())

	txs := []*Transaction{spendTx(nullifier(1), nullifier(2)), spendTx(nullifier(3))}

	h := sha256.New()
	h.Write(vmImpl.root.Get())
	for _, tx := range txs {
		for _, out := range tx.Outputs {
			h.Write(out.Commitment)
		}
	}
	for _, tx := range txs {
		for _, n := range tx.Nullifiers {
			h.Write(n)
		}
	}

	require.Equal(h.Sum(nil), vmImpl.computeStateRoot(txs))
}

// TestStateRootAdvancesOnlyOnFinalize proves the root moves only when a block is
// accepted, and that after it moves the next block's root builds on the new one.
func TestStateRootAdvancesOnlyOnFinalize(t *testing.T) {
	require := require.New(t)
	vmImpl := setupTestVM(t)
	defer vmImpl.Shutdown(context.Background())

	before := append([]byte(nil), vmImpl.root.Get()...)
	txs := []*Transaction{spendTx(nullifier(4))}

	root := vmImpl.computeStateRoot(txs)
	require.Equal(before, vmImpl.root.Get(), "computing a root must not advance it")

	require.NoError(vmImpl.root.Finalize(root))
	require.Equal(root, vmImpl.root.Get())
	require.NotEqual(root, vmImpl.computeStateRoot(txs),
		"the next block folds the same txs onto the new committed root")
}

// TestBlockVerifyRejectsDuplicateNullifier proves a block cannot spend the same
// shielded note twice. Neither nullifier is spent in accepted state, so the
// per-tx nullifier check cannot see the conflict — only the block-level check
// can, and without it the note is double-spent and supply inflates.
func TestBlockVerifyRejectsDuplicateNullifier(t *testing.T) {
	require := require.New(t)
	vmImpl := setupTestVM(t)
	defer vmImpl.Shutdown(context.Background())

	reused := nullifier(7)
	require.False(spentOf(t, vmImpl.nullifierDB, reused), "precondition: not yet spent")

	first, second := spendTx(reused), spendTx(reused)
	second.Fee = 2 // distinct tx, same spent note
	second.ID = second.ComputeID()
	acceptProofs(vmImpl, first, second)

	blk := &Block{
		ParentID_:      tipOf(vmImpl),
		BlockHeight:    1,
		BlockTimestamp: 1607144400,
		Txs:            []*Transaction{first, second},
		vm:             vmImpl,
	}
	blk.StateRoot = vmImpl.computeStateRoot(blk.Txs)

	// Sanity: each tx on its own is a block this VM accepts, so the rejection
	// below is caused by the pair sharing a nullifier and nothing else.
	solo := &Block{
		ParentID_:      tipOf(vmImpl),
		BlockHeight:    1,
		BlockTimestamp: 1607144400,
		Txs:            []*Transaction{first},
		vm:             vmImpl,
	}
	solo.StateRoot = vmImpl.computeStateRoot(solo.Txs)
	require.NoError(solo.Verify(context.Background()))

	require.ErrorIs(blk.Verify(context.Background()), errDuplicateNullifier)
}

// TestBlockVerifyRejectsNullifierRepeatedInOneTx covers the same defect within a
// single transaction: the mempool's conflict map is consulted before the tx's own
// nullifiers are inserted, so [n, n] passes admission.
func TestBlockVerifyRejectsNullifierRepeatedInOneTx(t *testing.T) {
	require := require.New(t)
	vmImpl := setupTestVM(t)
	defer vmImpl.Shutdown(context.Background())

	reused := nullifier(8)
	tx := spendTx(reused, reused)
	require.NoError(vmImpl.mempool.AddTransaction(tx), "admission does not catch it")
	acceptProofs(vmImpl, tx)

	blk := &Block{
		ParentID_:      tipOf(vmImpl),
		BlockHeight:    1,
		BlockTimestamp: 1607144400,
		Txs:            []*Transaction{tx},
		vm:             vmImpl,
	}
	blk.StateRoot = vmImpl.computeStateRoot(blk.Txs)

	require.ErrorIs(blk.Verify(context.Background()), errDuplicateNullifier)
}

// TestVertexVerifyRejectsDuplicateNullifier is the DAG half of the same gate.
// BuildVertex refuses to batch conflicting txs; a vertex off the wire must be
// held to the same rule.
func TestVertexVerifyRejectsDuplicateNullifier(t *testing.T) {
	require := require.New(t)
	vmImpl := setupTestVM(t)
	defer vmImpl.Shutdown(context.Background())

	reused := nullifier(6)
	first, second := spendTx(reused), spendTx(reused)
	second.Fee = 2
	second.ID = second.ComputeID()
	acceptProofs(vmImpl, first, second)

	solo := &Vertex{height: 1, parents: []ids.ID{tipOf(vmImpl)}, txs: []*Transaction{first}, vm: vmImpl}
	require.NoError(solo.Verify(context.Background()))

	v := &Vertex{
		height:  1,
		parents: []ids.ID{tipOf(vmImpl)},
		txs:     []*Transaction{first, second},
		vm:      vmImpl,
	}

	require.ErrorIs(v.Verify(context.Background()), errDuplicateNullifier)
}

// TestDeserializeVertexBoundsParentCount proves the vertex decoder sizes its
// slices from the bytes actually present. A 16-byte vertex claiming 2^32-1
// parents asked for 128 GiB before this bound existed, which is an
// unrecoverable out-of-memory rather than a rejected message — a remote kill
// with a 16-byte payload.
func TestDeserializeVertexBoundsParentCount(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:], 1)      // height
	binary.BigEndian.PutUint32(data[8:], 0)      // epoch
	binary.BigEndian.PutUint32(data[12:], 1<<22) // parentCount: 4.2M IDs = 134 MiB
	require.Equal(0, (len(data)-16)/32, "no parent bytes are present at all")

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	v, err := deserializeVertex(data, nil)

	runtime.ReadMemStats(&after)

	require.Nil(v)
	require.ErrorIs(err, errInvalidBlock)
	require.Less(after.TotalAlloc-before.TotalAlloc, uint64(4<<20),
		"rejecting the header must not allocate the claimed parents")
}

// TestDeserializeVertexBoundsTxCount is the same bound for the tx count.
func TestDeserializeVertexBoundsTxCount(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 20)
	binary.BigEndian.PutUint64(data[0:], 1)      // height
	binary.BigEndian.PutUint32(data[8:], 0)      // epoch
	binary.BigEndian.PutUint32(data[12:], 0)     // parentCount
	binary.BigEndian.PutUint32(data[16:], 1<<24) // txCount: 16.7M pointers = 134 MiB

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	v, err := deserializeVertex(data, nil)

	runtime.ReadMemStats(&after)

	require.Nil(v)
	require.True(errors.Is(err, errInvalidBlock))
	require.Less(after.TotalAlloc-before.TotalAlloc, uint64(4<<20),
		"rejecting the header must not allocate the claimed txs")
}

// tipOf is the accepted block a test builds its next block on.
func tipOf(vm *VM) ids.ID {
	id, _ := vm.chain.Tip()
	return id
}
