// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"encoding/hex"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// quorum_wire_test.go freezes the SHARED CROSS-CHAIN WIRE SPEC as golden vectors.
// These assertions are the cross-spec drift detector: if the A-side encoders ever
// diverge from the pinned bytes (and therefore from Blue-A's aivmbridge encoders,
// which MUST produce the same bytes), the build fails here rather than silently
// minting receipts the C boundary cannot verify.

// fixed inputs used to derive the golden vectors (all deterministic).
func wireFixture() (cChain, aChain, cTx, modelSpecH, promptH common.Hash, callIdx uint32, caller common.Address, n, threshold uint16, fee *uint256.Int) {
	cChain = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	aChain = common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	cTx = common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333")
	modelSpecH = common.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444")
	promptH = common.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555")
	callIdx = 7
	caller = common.HexToAddress("0x00000000000000000000000000000000000000aa")
	n = 5
	threshold = 3
	fee = uint256.NewInt(1_000_000)
	return
}

// TestIntentIDByteSpec asserts ComputeIntentID hashes EXACTLY the pinned preimage
// (DomainIntent || c_chain || a_chain || c_tx || u32be(call_index) || caller ||
// model_spec || prompt || u16be(N) || u16be(threshold) || u256be(fee)).
func TestIntentIDByteSpec(t *testing.T) {
	require := require.New(t)
	cChain, aChain, cTx, ms, ph, callIdx, caller, n, threshold, fee := wireFixture()

	// Independently assemble the preimage by hand (NOT via the production helper)
	// and assert equality — so a change to ComputeIntentID's field order/widths is
	// caught against this hand-built reference.
	var pre []byte
	pre = append(pre, []byte(DomainIntent)...)
	pre = append(pre, cChain.Bytes()...)
	pre = append(pre, aChain.Bytes()...)
	pre = append(pre, cTx.Bytes()...)
	pre = append(pre, []byte{0, 0, 0, 7}...) // u32be(7)
	pre = append(pre, caller.Bytes()...)
	pre = append(pre, ms.Bytes()...)
	pre = append(pre, ph.Bytes()...)
	pre = append(pre, []byte{0, 5}...) // u16be(5)
	pre = append(pre, []byte{0, 3}...) // u16be(3)
	feeB := fee.Bytes32()
	pre = append(pre, feeB[:]...)

	want := common.BytesToHash(crypto.Keccak256(pre))
	got := ComputeIntentID(cChain, aChain, cTx, callIdx, caller, ms, ph, n, threshold, fee)
	require.Equal(want, got, "intent_id must hash the exact pinned preimage")

	// The preimage length is itself part of the spec: DomainIntent("lux/
	// aivmbridge/intent/v1", 24 bytes) + 3*32 + 4 + 20 + 2*32 + 2 + 2 + 32 = 244.
	require.Equal(len(DomainIntent)+32*3+4+20+32*2+2+2+32, len(pre))
	require.Equal(24, len(DomainIntent))
	require.Equal(244, len(pre))

	// Anchor so the golden value is visible in -v runs (cross-check vs aivmbridge).
	t.Logf("GOLDEN intent_id = %s", got.Hex())
}

// TestReceiptByteSpec asserts the AInferenceReceipt canonical encoding is exactly
// 355 bytes in the pinned field order, and that receipt_hash =
// keccak(DomainReceipt || encoding).
func TestReceiptByteSpec(t *testing.T) {
	require := require.New(t)
	cChain, aChain, cTx, ms, ph, callIdx, caller, n, threshold, fee := wireFixture()
	intentID := ComputeIntentID(cChain, aChain, cTx, callIdx, caller, ms, ph, n, threshold, fee)

	r := AInferenceReceipt{
		Version:             ReceiptVersion,
		IntentID:            intentID,
		TaskID:              common.HexToHash("0x6666666666666666666666666666666666666666666666666666666666666666"),
		CChainID:            cChain,
		AChainID:            aChain,
		Requester:           caller,
		ModelSpecHash:       ms,
		PromptHash:          ph,
		CanonicalOutputHash: common.HexToHash("0x7777777777777777777777777777777777777777777777777777777777777777"),
		Status:              StatusCompleted,
		N:                   n,
		Threshold:           threshold,
		WinnersRoot:         common.HexToHash("0x8888888888888888888888888888888888888888888888888888888888888888"),
		OperatorsRoot:       common.HexToHash("0x9999999999999999999999999999999999999999999999999999999999999999"),
		FeePaid:             fee,
		SettledAtHeight:     161,
	}

	enc := r.Encode()
	require.Len(enc, ReceiptEncodedLen)
	require.Equal(355, ReceiptEncodedLen, "spec length is 355 bytes")

	// Hand-assemble the same encoding and assert byte-equality (field order/width
	// regression guard).
	var ref []byte
	ref = append(ref, 0, 1) // u16be(Version=1)
	ref = append(ref, intentID.Bytes()...)
	ref = append(ref, r.TaskID.Bytes()...)
	ref = append(ref, cChain.Bytes()...)
	ref = append(ref, aChain.Bytes()...)
	ref = append(ref, caller.Bytes()...)
	ref = append(ref, ms.Bytes()...)
	ref = append(ref, ph.Bytes()...)
	ref = append(ref, r.CanonicalOutputHash.Bytes()...)
	ref = append(ref, StatusCompleted)
	ref = append(ref, 0, 5) // u16be(N)
	ref = append(ref, 0, 3) // u16be(threshold)
	ref = append(ref, r.WinnersRoot.Bytes()...)
	ref = append(ref, r.OperatorsRoot.Bytes()...)
	fb := fee.Bytes32()
	ref = append(ref, fb[:]...)
	ref = append(ref, 0, 0, 0, 0, 0, 0, 0, 161) // u64be(161)
	require.Equal(hex.EncodeToString(ref), hex.EncodeToString(enc), "receipt encoding must match the pinned byte layout")

	// receipt_hash = keccak(DomainReceipt || encoding).
	wantHash := common.BytesToHash(crypto.Keccak256(append([]byte(DomainReceipt), enc...)))
	require.Equal(wantHash, r.Hash())
	t.Logf("GOLDEN receipt_hash = %s", r.Hash().Hex())
}

// TestMerkleProofRoundTrip exercises the keccak merkle used for receipt_root +
// WinnersRoot/OperatorsRoot: every leaf in a set proves under the root, and a
// wrong leaf does not.
func TestMerkleProofRoundTrip(t *testing.T) {
	require := require.New(t)
	// build 5 receipt-hash leaves.
	raw := []common.Hash{h(1), h(2), h(3), h(4), h(5)}
	leaves := make([]common.Hash, len(raw))
	for i, x := range raw {
		leaves[i] = leafHash(x)
	}
	root := merkleRoot(leaves)
	for i, x := range raw {
		p := merkleProof(leaves, uint32(i))
		require.True(VerifyReceiptProof(x, p, root), "leaf %d must verify", i)
	}
	// a non-member must not verify under any in-range proof.
	bad := h(0xFF)
	p := merkleProof(leaves, 0)
	require.False(VerifyReceiptProof(bad, p, root), "non-member must not verify")

	// addresses root is order-sensitive and reproducible.
	addrs := []common.Address{addr(1), addr(2), addr(3)}
	r1 := rootOverAddrs(addrs)
	r2 := rootOverAddrs([]common.Address{addr(1), addr(2), addr(3)})
	require.Equal(r1, r2)
	require.NotEqual(r1, rootOverAddrs([]common.Address{addr(3), addr(2), addr(1)}), "order matters")
}
