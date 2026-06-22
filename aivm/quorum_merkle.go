// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// quorum_merkle.go is the ONE keccak Merkle implementation used by the engine:
//   - WinnersRoot / OperatorsRoot in a receipt (leaves = operator addresses)
//   - the running receipt_root the A->C boundary exports (leaves = receipt_hashes)
//   - membership proofs that a receipt_hash is under the exported receipt_root
//
// Pinned construction (shared with the boundary — DO NOT change without changing
// both sides):
//   - leafAddr(a) = keccak256( a.Bytes()[20] )    (operator-address leaf)
//   - leafHash(h) = keccak256( h.Bytes()[32] )    (receipt-hash leaf; the raw
//     receipt_hash is itself a keccak digest, but we hash it once more so a leaf
//     can never be confused with an internal node value)
//   - node(l, r)  = keccak256( l || r )
//   - odd level: the last node is duplicated (hashed with itself), the standard
//     Bitcoin/aiquorum convention. Deterministic on every node.
//   - empty set: the all-zero hash (a settled-but-empty root is impossible in
//     practice — a settled task always has >=1 winner — but the function is
//     total).
//
// Leaf-vs-node domain separation: a leaf is keccak(value) and a node is
// keccak(left||right); since a leaf preimage is 20 or 32 bytes and a node
// preimage is 64 bytes, and we hash leaves before combining, a second-preimage
// attack that reinterprets an internal node as a leaf is not available.

import (
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// leafAddr is the operator-address leaf hash.
func leafAddr(a common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(a.Bytes()))
}

// leafHash is the receipt-hash leaf hash (one extra keccak over the digest).
func leafHash(h common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(h.Bytes()))
}

// merkleNode combines two child hashes.
func merkleNode(l, r common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(l.Bytes(), r.Bytes()))
}

// merkleRoot folds a slice of leaf hashes into a root. Leaves must already be
// leaf-hashed (leafAddr/leafHash); this function only does the node combination.
// Odd levels duplicate the last node. Empty -> zero hash.
func merkleRoot(leaves []common.Hash) common.Hash {
	if len(leaves) == 0 {
		return common.Hash{}
	}
	level := make([]common.Hash, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		next := make([]common.Hash, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, merkleNode(level[i], level[i+1]))
			} else {
				next = append(next, merkleNode(level[i], level[i])) // duplicate odd tail
			}
		}
		level = next
	}
	return level[0]
}

// rootOverAddrs builds the Merkle root over operator addresses (WinnersRoot /
// OperatorsRoot). Addresses are leaf-hashed in the given order — the caller
// fixes the order (selection order for OperatorsRoot, winner-iteration order for
// WinnersRoot) and the boundary reproduces it from the same source, so the root
// is reproducible.
func rootOverAddrs(addrs []common.Address) common.Hash {
	leaves := make([]common.Hash, len(addrs))
	for i, a := range addrs {
		leaves[i] = leafAddr(a)
	}
	return merkleRoot(leaves)
}

// MerkleProof is an inclusion proof: the sibling hashes from leaf to root, plus
// the leaf index (to know left/right at each level). A verifier with the leaf,
// the proof, and the root can recompute the root and check equality.
type MerkleProof struct {
	Index    uint32        `json:"index"`    // leaf index in the tree
	Siblings []common.Hash `json:"siblings"` // sibling at each level, leaf->root
}

// merkleProof builds the inclusion proof for leaf index `idx` over the given
// already-leaf-hashed leaves. It mirrors merkleRoot's duplicate-odd-tail rule so
// the proof verifies against the same root.
func merkleProof(leaves []common.Hash, idx uint32) MerkleProof {
	proof := MerkleProof{Index: idx}
	level := make([]common.Hash, len(leaves))
	copy(level, leaves)
	i := int(idx)
	for len(level) > 1 {
		var sib common.Hash
		if i%2 == 0 {
			if i+1 < len(level) {
				sib = level[i+1]
			} else {
				sib = level[i] // duplicated tail: sibling is self
			}
		} else {
			sib = level[i-1]
		}
		proof.Siblings = append(proof.Siblings, sib)

		next := make([]common.Hash, 0, (len(level)+1)/2)
		for j := 0; j < len(level); j += 2 {
			if j+1 < len(level) {
				next = append(next, merkleNode(level[j], level[j+1]))
			} else {
				next = append(next, merkleNode(level[j], level[j]))
			}
		}
		level = next
		i /= 2
	}
	return proof
}

// VerifyReceiptProof checks that receiptHash is included under root at the
// proof's index. It re-applies the leaf hash (leafHash) and folds with the
// siblings, choosing left/right by the index bit at each level — exactly
// inverting merkleProof/merkleRoot. Returns true iff the recomputed root equals
// root. This is the function the A->C boundary (and anyone) uses to verify an
// exported receipt belongs to the committed receipt_root.
func VerifyReceiptProof(receiptHash common.Hash, proof MerkleProof, root common.Hash) bool {
	cur := leafHash(receiptHash)
	idx := proof.Index
	for _, sib := range proof.Siblings {
		if idx%2 == 0 {
			cur = merkleNode(cur, sib)
		} else {
			cur = merkleNode(sib, cur)
		}
		idx /= 2
	}
	return cur == root
}
