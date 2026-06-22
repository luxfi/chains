// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// quorum_wire.go pins the SHARED CROSS-CHAIN WIRE SPEC byte-for-byte. These
// encodings are the contract between A-Chain (this package) and the A<->C
// boundary (Blue-A's aivmbridge precompile on C-Chain). They MUST stay
// byte-identical on both sides or a receipt produced here will not verify under
// the receipt_root the boundary tracks, and an intent committed on C will not
// re-derive to the same intent_id here. quorum_wire_test.go asserts the exact
// bytes (length + golden keccak) so any drift is caught at build time.
//
// keccak256 is luxfi/crypto.Keccak256 — the canonical keccak in the Lux stack
// (the same primitive geth-side code uses), so a digest computed here equals one
// computed on the C side bit-for-bit.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// Domain separators (raw UTF-8 bytes, no length prefix — concatenated verbatim).
// They keep the intent-id keyspace and the receipt-hash keyspace disjoint, and
// version the wire so a future v2 cannot collide with v1.
const (
	DomainIntent  = "lux/aivmbridge/intent/v1"
	DomainReceipt = "lux/aivmbridge/receipt/v1"
)

// Receipt status codes (the AInferenceReceipt.Status byte). Pinned values shared
// with the boundary.
const (
	StatusUnknown    uint8 = 0
	StatusPending    uint8 = 1
	StatusCompleted  uint8 = 2
	StatusFailed     uint8 = 3
	StatusChallenged uint8 = 4
)

// ReceiptEncodedLen is the exact byte length of the canonical AInferenceReceipt
// encoding (see EncodeReceipt). Pinned so a drift in field widths/order is a
// compile/test failure, not a silent cross-chain mismatch.
//
//	u16(Version)2 + IntentID32 + TaskID32 + CChainID32 + AChainID32 +
//	Requester20 + ModelSpecHash32 + PromptHash32 + CanonicalOutputHash32 +
//	u8(Status)1 + u16(N)2 + u16(Threshold)2 + WinnersRoot32 + OperatorsRoot32 +
//	u256(FeePaid)32 + u64(SettledAtHeight)8
const ReceiptEncodedLen = 2 + 32 + 32 + 32 + 32 + 20 + 32 + 32 + 32 + 1 + 2 + 2 + 32 + 32 + 32 + 8 // = 355

// ComputeIntentID derives the cross-chain intent id from the COMMITTED C-Chain
// intent fields, exactly:
//
//	keccak256( DomainIntent ||
//	    c_chain_id(32) || a_chain_id(32) || c_tx_hash(32) || u32be(call_index) ||
//	    caller(20) || model_spec_hash(32) || prompt_hash(32) ||
//	    u16be(N) || u16be(threshold) || u256be(fee,32) )
//
// Every field is fixed-width in this precise order. The A-Chain importer
// recomputes this from the delivered fields and rejects the intent unless it
// equals the id the C side committed — so a forged/tampered intent (any field
// altered) yields a different id and cannot create a task.
func ComputeIntentID(cChainID, aChainID, cTxHash common.Hash, callIndex uint32, caller common.Address, modelSpecHash, promptHash common.Hash, n, threshold uint16, fee *uint256.Int) common.Hash {
	buf := make([]byte, 0, len(DomainIntent)+32*3+4+20+32*2+2+2+32)
	buf = append(buf, []byte(DomainIntent)...)
	buf = append(buf, cChainID.Bytes()...)
	buf = append(buf, aChainID.Bytes()...)
	buf = append(buf, cTxHash.Bytes()...)
	buf = append(buf, u32be(callIndex)...)
	buf = append(buf, caller.Bytes()...)
	buf = append(buf, modelSpecHash.Bytes()...)
	buf = append(buf, promptHash.Bytes()...)
	buf = append(buf, u16be(n)...)
	buf = append(buf, u16be(threshold)...)
	buf = append(buf, u256be(fee)...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

// ---------------------------------------------------------------------------
// fixed-width encoders (the only place width/endianness is decided)
// ---------------------------------------------------------------------------

func u16be(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func u32be(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func u64be(v uint64) []byte {
	return []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

// u256be returns the 32-byte big-endian encoding of a uint256 (nil -> zero).
func u256be(v *uint256.Int) []byte {
	if v == nil {
		return make([]byte, 32)
	}
	b := v.Bytes32()
	return b[:]
}

// h32 packs a uint256 into a 32-byte hash (big-endian).
func h32(v *uint256.Int) common.Hash {
	b := v.Bytes32()
	return common.BytesToHash(b[:])
}

// readUint reads a uint256 stored at a slot (zero if unset).
func readUint(st QuorumState, slot common.Hash) *uint256.Int {
	return new(uint256.Int).SetBytes(st.GetState(slot).Bytes())
}

// readUint64 reads a uint64-valued slot (low 64 bits of the stored uint256).
func readUint64(st QuorumState, slot common.Hash) uint64 {
	return readUint(st, slot).Uint64()
}

// isSet reports whether a slot holds a non-zero value.
func isSet(h common.Hash) bool { return h != (common.Hash{}) }

// oneHash is the canonical "true" flag value.
func oneHash() common.Hash {
	var w [32]byte
	w[31] = 1
	return common.BytesToHash(w[:])
}

// bytesLess is the deterministic big-endian ordering on hashes (tie-break in
// plurality, leaf ordering elsewhere). Total order, identical on every node.
func bytesLess(a, b common.Hash) bool {
	ab, bb := a.Bytes(), b.Bytes()
	for i := 0; i < len(ab); i++ {
		if ab[i] != bb[i] {
			return ab[i] < bb[i]
		}
	}
	return false
}
