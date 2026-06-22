// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// export.go is the A->C OUTBOUND seam: ExportReceipt produces, for a settled C
// intent, the canonical AInferenceReceipt and a Merkle proof that its
// receipt_hash is included under the engine's committed receipt_root. The C-side
// boundary (Blue-A's aivmbridge) admits the receipt by:
//   1. recomputing receipt_hash = keccak(DomainReceipt || receipt.Encode()),
//   2. checking VerifyReceiptProof(receipt_hash, proof, receipt_root) == true
//      against the receipt_root it tracks for A-Chain.
// No A-Chain trust is imported beyond that single 32-byte root commitment.
//
// The receipt is RECONSTRUCTED deterministically from settled on-state (the task
// record + canonical result + selected/winner sets), so export is a pure read;
// it never re-runs settlement and cannot change state. The reconstructed receipt
// is byte-identical to the one emitted at Settle (same buildReceipt over the same
// immutable settled state), so its Hash() equals the stored leaf and the proof
// verifies.

import "github.com/luxfi/geth/common"

// TaskForIntent returns the A-Chain task id that a committed C-Chain intent
// created (zero hash if the intent never created a task). The task id is the
// engine-internal id derived at createTask (computeTaskID over the requester's
// nonce + height), distinct from the C-side intent id; this mapping is the only
// way an external caller (the C boundary, an RPC client, this package's drivers)
// resolves "the intent I committed" to "the task that answers it" for the
// lifecycle calls (SelectOperators / Commit / Reveal / Settle / GetTask) that key
// on the task id. Pure read.
func (e *Engine) TaskForIntent(st QuorumState, intentID common.Hash) common.Hash {
	return st.GetState(slotHash(nsIntentTask, intentID))
}

// ExportReceipt returns the settled receipt for the given C-chain intent id and
// a proof of its inclusion under the current receipt_root. Errors if the intent
// has no settled receipt. The returned (receipt, proof, root) triple is exactly
// what the C boundary verifies.
func (e *Engine) ExportReceipt(st QuorumState, intentID common.Hash) (AInferenceReceipt, MerkleProof, common.Hash, error) {
	// Locate the receipt leaf index for this intent (stored as index+1; 0 means
	// unsettled / unknown).
	idxPlus1 := readUint64(st, slotHash(nsIntentRcpt, intentID))
	if idxPlus1 == 0 {
		return AInferenceReceipt{}, MerkleProof{}, common.Hash{}, ErrReceiptNotFound
	}
	leafIndex := uint32(idxPlus1 - 1)

	// Recover the task this intent created, then reconstruct the receipt.
	taskID := st.GetState(slotHash(nsIntentTask, intentID))
	if taskID == (common.Hash{}) {
		return AInferenceReceipt{}, MerkleProof{}, common.Hash{}, ErrReceiptNotFound
	}
	receipt, err := e.reconstructReceipt(st, taskID)
	if err != nil {
		return AInferenceReceipt{}, MerkleProof{}, common.Hash{}, err
	}

	// Build the inclusion proof over the leaf-hashed receipt list and return the
	// current root.
	leaves := allReceiptLeaves(st)
	if leafIndex >= uint32(len(leaves)) {
		return AInferenceReceipt{}, MerkleProof{}, common.Hash{}, ErrProofOutOfRange
	}
	hashed := make([]common.Hash, len(leaves))
	for i, lh := range leaves {
		hashed[i] = leafHash(lh)
	}
	proof := merkleProof(hashed, leafIndex)
	root := e.ReceiptRoot(st)
	return receipt, proof, root, nil
}

// reconstructReceipt rebuilds the canonical receipt for a settled task purely
// from on-state — identical bytes to the receipt emitted at Settle.
func (e *Engine) reconstructReceipt(st QuorumState, taskID common.Hash) (AInferenceReceipt, error) {
	task := readTask(st, taskID)
	if task.Status == TaskNone || !isSet(st.GetState(slotHash(nsSettled, taskID))) {
		return AInferenceReceipt{}, ErrTaskUnknown
	}
	feePaid := readUint(st, slotHash(nsTaskFee, taskID))
	canonical := st.GetState(slotHash(nsCanonical, taskID))
	height := readUint64(st, slotHash(nsTaskHeight, taskID))

	res := SettleResult{Status: task.Status, CanonicalHash: canonical}
	var winners []common.Address
	if task.Status == TaskSettled {
		revealers, hashes := tally(st, taskID)
		for i := range revealers {
			if hashes[i] == canonical {
				winners = append(winners, revealers[i])
			}
		}
	}
	return e.buildReceipt(st, taskID, task, res, feePaid, height, winners), nil
}
