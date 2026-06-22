// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// receipts.go defines the cross-chain AInferenceReceipt produced on settle and
// the running receipt_root the A->C boundary exports. A receipt is the durable,
// verifiable statement "task T (created from C intent I) settled to canonical
// output O under quorum N/threshold, paying fee F, at A-height H". Its canonical
// encoding is PINNED byte-for-byte (EncodeReceipt / ReceiptEncodedLen) and its
// hash is keccak(DomainReceipt || encoding) — the same on the C side, so a
// receipt minted here verifies under the receipt_root the boundary tracks.
//
// receipt_root is a keccak Merkle root over the leaf-hashed receipt_hashes of
// every settled task, in settlement order. It is updated by appendReceipt on
// each Settle and is the single 32-byte commitment the A->C boundary needs to
// admit an A-Chain receipt; an exported receipt carries a Merkle proof that its
// receipt_hash is under this root (see export.go / VerifyReceiptProof).

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// ReceiptVersion is the wire version stamped into every receipt (the u16be
// Version field). Bumping it is a wire change shared with the boundary.
const ReceiptVersion uint16 = 1

// AInferenceReceipt is the cross-chain settlement receipt. Field order here is
// presentation; the WIRE order is fixed by EncodeReceipt and MUST NOT be
// reordered.
type AInferenceReceipt struct {
	Version             uint16         `json:"version"`
	IntentID            common.Hash    `json:"intentId"`            // source C-chain intent id
	TaskID              common.Hash    `json:"taskId"`              // A-chain task id (beacon anchor)
	CChainID            common.Hash    `json:"cChainId"`
	AChainID            common.Hash    `json:"aChainId"`
	Requester           common.Address `json:"requester"`
	ModelSpecHash       common.Hash    `json:"modelSpecHash"`
	PromptHash          common.Hash    `json:"promptHash"`
	CanonicalOutputHash common.Hash    `json:"canonicalOutputHash"` // zero if Failed
	Status              uint8          `json:"status"`              // StatusCompleted / StatusFailed / ...
	N                   uint16         `json:"n"`
	Threshold           uint16         `json:"threshold"`
	WinnersRoot         common.Hash    `json:"winnersRoot"`         // merkle root over winner addresses
	OperatorsRoot       common.Hash    `json:"operatorsRoot"`       // merkle root over selected addresses
	FeePaid             *uint256.Int   `json:"feePaid"`
	SettledAtHeight     uint64         `json:"settledAtHeight"`
}

// EncodeReceipt produces the canonical fixed-width encoding (exactly
// ReceiptEncodedLen = 355 bytes) in the PINNED order:
//
//	u16be(Version) || IntentID(32) || TaskID(32) || CChainID(32) || AChainID(32) ||
//	Requester(20) || ModelSpecHash(32) || PromptHash(32) || CanonicalOutputHash(32) ||
//	u8(Status) || u16be(N) || u16be(Threshold) || WinnersRoot(32) ||
//	OperatorsRoot(32) || u256be(FeePaid,32) || u64be(SettledAtHeight)
func (r AInferenceReceipt) Encode() []byte {
	buf := make([]byte, 0, ReceiptEncodedLen)
	buf = append(buf, u16be(r.Version)...)
	buf = append(buf, r.IntentID.Bytes()...)
	buf = append(buf, r.TaskID.Bytes()...)
	buf = append(buf, r.CChainID.Bytes()...)
	buf = append(buf, r.AChainID.Bytes()...)
	buf = append(buf, r.Requester.Bytes()...)
	buf = append(buf, r.ModelSpecHash.Bytes()...)
	buf = append(buf, r.PromptHash.Bytes()...)
	buf = append(buf, r.CanonicalOutputHash.Bytes()...)
	buf = append(buf, r.Status)
	buf = append(buf, u16be(r.N)...)
	buf = append(buf, u16be(r.Threshold)...)
	buf = append(buf, r.WinnersRoot.Bytes()...)
	buf = append(buf, r.OperatorsRoot.Bytes()...)
	buf = append(buf, u256be(r.FeePaid)...)
	buf = append(buf, u64be(r.SettledAtHeight)...)
	return buf
}

// Hash is the receipt commitment: keccak256(DomainReceipt || Encode()). This is
// the leaf value (pre-leaf-hash) that goes into the receipt_root and that an
// exported proof proves membership of.
func (r AInferenceReceipt) Hash() common.Hash {
	return common.BytesToHash(crypto.Keccak256(append([]byte(DomainReceipt), r.Encode()...)))
}

// buildReceipt assembles the receipt for a just-settled task. Status maps from
// the settlement outcome (Settled->Completed, Failed->Failed). WinnersRoot is
// over the winning operators in winner-iteration order (empty on Failed);
// OperatorsRoot is over the full selected set in selection order — both
// reproducible by the boundary from the same on-chain arrays.
func (e *Engine) buildReceipt(st QuorumState, taskID common.Hash, task taskRecord, res SettleResult, feePaid *uint256.Int, height uint64, winners []common.Address) AInferenceReceipt {
	status := StatusCompleted
	if res.Status == TaskFailed {
		status = StatusFailed
	}
	intentID := st.GetState(slotHash(nsTaskIntent, taskID))
	selected := selectedOperators(st, taskID, task.N)
	return AInferenceReceipt{
		Version:             ReceiptVersion,
		IntentID:            intentID,
		TaskID:              taskID,
		CChainID:            e.CChainID,
		AChainID:            e.AChainID,
		Requester:           task.Requester,
		ModelSpecHash:       task.ModelSpecHash,
		PromptHash:          task.PromptHash,
		CanonicalOutputHash: res.CanonicalHash,
		Status:              status,
		N:                   uint16(task.N),
		Threshold:           uint16(task.Threshold),
		WinnersRoot:         rootOverAddrs(winners),
		OperatorsRoot:       rootOverAddrs(selected),
		FeePaid:             new(uint256.Int).Set(feePaid),
		SettledAtHeight:     height,
	}
}

// ---------------------------------------------------------------------------
// receipt_root accumulator: an append-only list of settled receipt_hashes whose
// keccak Merkle root is the exported commitment. We store the leaf list so a
// membership proof can be produced for any settled receipt (export.go). The root
// is recomputed over all leaves on each append — O(n) per settle, bounded by the
// number of settled tasks; the leaf list is the authoritative state and the
// cached root slot is a convenience read.
// ---------------------------------------------------------------------------

// receiptIndexCount returns how many settled receipts are in the root.
func receiptIndexCount(st QuorumState) uint32 {
	return uint32(new(uint256.Int).SetBytes(st.GetState(slotNS(nsReceiptIdx)).Bytes()).Uint64())
}

// receiptLeafAt returns the settled receipt_hash at index i.
func receiptLeafAt(st QuorumState, i uint32) common.Hash {
	return st.GetState(slotNSIdx(nsReceiptLeaf, i))
}

// allReceiptLeaves reads the full settled-receipt_hash list in settlement order.
func allReceiptLeaves(st QuorumState) []common.Hash {
	n := receiptIndexCount(st)
	out := make([]common.Hash, n)
	for i := uint32(0); i < n; i++ {
		out[i] = receiptLeafAt(st, i)
	}
	return out
}

// appendReceipt appends a settled receipt_hash to the list at index n,
// recomputes the receipt_root over all leaves, caches it, records the
// intentID -> (leaf index n) mapping so ExportReceipt can locate this receipt by
// its source intent, and returns the new root. intentID may be zero for a task
// not sourced from a C intent (no reverse mapping is then stored).
func appendReceipt(st QuorumState, intentID, receiptHash common.Hash) (root common.Hash, leafIndex uint32) {
	n := receiptIndexCount(st)
	st.SetState(slotNSIdx(nsReceiptLeaf, n), receiptHash)
	st.SetState(slotNS(nsReceiptIdx), h32(uint256.NewInt(uint64(n)+1)))
	if intentID != (common.Hash{}) {
		// store index+1 so 0 reliably means "no settled receipt for this intent"
		st.SetState(slotHash(nsIntentRcpt, intentID), h32(uint256.NewInt(uint64(n)+1)))
	}

	leaves := allReceiptLeaves(st) // includes the just-appended one
	hashed := make([]common.Hash, len(leaves))
	for i, lh := range leaves {
		hashed[i] = leafHash(lh)
	}
	root = merkleRoot(hashed)
	st.SetState(slotNS(nsReceiptRoot), root)
	return root, n
}

// ReceiptRoot returns the current committed receipt_root (zero before any
// settle).
func (e *Engine) ReceiptRoot(st QuorumState) common.Hash {
	return st.GetState(slotNS(nsReceiptRoot))
}
