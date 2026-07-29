// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/cmp/config"
)

// twoPartyConfig returns a CMP config carrying real secp256k1 public shares for
// two parties, which is everything the block-signature batch reads.
func twoPartyConfig(t *testing.T) (*config.Config, []party.ID) {
	t.Helper()
	group := curve.Secp256k1{}
	ids := []party.ID{"party-a", "party-b"}
	pub := make(map[party.ID]*config.Public, len(ids))
	for _, id := range ids {
		pub[id] = &config.Public{ECDSA: randomScalar(t, group).ActOnBase()}
	}
	return &config.Config{Group: group, Public: pub}, ids
}

func randomScalar(t *testing.T, group curve.Curve) curve.Scalar {
	t.Helper()
	s := group.NewScalar()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	b[0] &= 0x7f // stay below the group order
	require.NoError(t, s.UnmarshalBinary(b))
	return s
}

func entriesFor(sigLen int, partyIDs []party.ID) []sigEntry {
	out := make([]sigEntry, 0, len(partyIDs))
	for _, id := range partyIDs {
		out = append(out, sigEntry{partyID: id, sigBytes: make([]byte, sigLen)})
	}
	return out
}

// TestBatchSignsTheBlockHashItself pins the message the accelerated batch checks
// to the message the CPU path checks. The GPU layout hashed the block hash a
// second time, so the batch verified signatures over sha256(blockHash) while
// verifyBlockSig verified them over blockHash — the same signature set was valid
// on a node with an accelerator and invalid on a node without one, which splits
// accept from reject on host hardware alone.
func TestBatchSignsTheBlockHashItself(t *testing.T) {
	require := require.New(t)
	cfg, partyIDs := twoPartyConfig(t)
	blockHash := ids.GenerateTestID()

	messages, sigs, pubkeys, err := packBlockSigBatch(blockHash, entriesFor(64, partyIDs), cfg)
	require.NoError(err)
	require.Len(messages, 2*batchHashSize)
	require.Len(sigs, 2*batchSigSize)
	require.Len(pubkeys, 2*batchPKSize)

	for i := range partyIDs {
		require.Equal(blockHash[:], messages[i*batchHashSize:(i+1)*batchHashSize],
			"row %d must carry the block hash, not a rehash of it", i)
	}
}

// TestBatchRefusesRowsItCannotRepresent proves a row the layout cannot fill
// exactly is an error rather than a zero-filled row. Zero-filling left the entry
// occupying a slot in the result vector whose verdict was then trusted, so a
// signature the CPU path rejects outright could be counted valid; combined with
// the "one valid signature is enough" block rule, one spuriously-true row admits
// the block. Returning an error sends the batch to the CPU, the one authority.
func TestBatchRefusesRowsItCannotRepresent(t *testing.T) {
	require := require.New(t)
	cfg, partyIDs := twoPartyConfig(t)
	blockHash := ids.GenerateTestID()

	_, _, _, err := packBlockSigBatch(blockHash, entriesFor(32, partyIDs), cfg)
	require.Error(err, "a 32-byte signature cannot fill a 64-byte row")

	// A party with no public share in the config cannot be laid out either.
	orphan := []sigEntry{{partyID: "unknown-party", sigBytes: make([]byte, 64)}}
	require.Panics(func() { _, _, _, _ = packBlockSigBatch(blockHash, orphan, cfg) },
		"batchVerifyBlockSignatures filters unknown parties before this point")
}

// TestVerifyBlockSigIsTheOneAuthority pins the single acceptance predicate: a
// malformed signature is refused, and it is checked against the block hash.
func TestVerifyBlockSigIsTheOneAuthority(t *testing.T) {
	require := require.New(t)
	cfg, partyIDs := twoPartyConfig(t)
	blockHash := ids.GenerateTestID()

	require.False(verifyBlockSig(cfg, blockHash, sigEntry{partyID: partyIDs[0], sigBytes: nil}))
	require.False(verifyBlockSig(cfg, blockHash, sigEntry{partyID: partyIDs[0], sigBytes: make([]byte, 32)}))
	require.False(verifyBlockSig(cfg, blockHash, sigEntry{partyID: partyIDs[0], sigBytes: make([]byte, 64)}),
		"an all-zero signature is not a valid signature")
}

// TestBatchVerifyCountsNoSignatureWithoutConfig keeps the fail-closed entry
// conditions of the caller honest.
func TestBatchVerifyCountsNoSignatureWithoutConfig(t *testing.T) {
	require := require.New(t)
	cfg, partyIDs := twoPartyConfig(t)
	blockHash := ids.GenerateTestID()

	sigs := map[ids.NodeID][]byte{ids.GenerateTestNodeID(): make([]byte, 64)}
	require.Zero(batchVerifyBlockSignatures(blockHash, sigs, nil, nil),
		"no MPC config means no signature can be counted valid")
	require.Zero(batchVerifyBlockSignatures(blockHash, nil, cfg, nil),
		"no signatures means no valid signatures")
	require.Zero(batchVerifyBlockSignatures(blockHash, sigs, cfg, nil),
		"a signer with no public share in the config is not counted")
	_ = partyIDs
}
