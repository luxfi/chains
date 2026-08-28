// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// wire_test.go — the persisted/replicated encodings must round-trip exactly.
//
// These are not cosmetic checks. Every type here is either hashed into the
// state root or read back as consensus state, so a field that silently fails
// to survive the wire is a field on which two validators can disagree while
// both believing they applied the same block.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
	"github.com/luxfi/zap"
)

// sampleKeyRecord is a structurally valid registry entry: 33-byte compressed
// group key, 20-byte address, participants sorted and sized to the policy.
func sampleKeyRecord() *KeyRecord {
	pub := make([]byte, 33)
	pub[0] = 0x02
	for i := 1; i < 33; i++ {
		pub[i] = byte(i)
	}
	addr := make([]byte, 20)
	for i := range addr {
		addr[i] = byte(0xA0 + i)
	}
	return &KeyRecord{
		KeyID:          "bridge-custody",
		Kind:           KindCGGMP21,
		Policy:         quorum.MustNew(2, 3),
		Participants:   []party.ID{"p1", "p2", "p3"},
		GroupPublicKey: pub,
		Address:        addr,
		CreatedHeight:  42,
	}
}

func sampleSignature() []byte {
	sig := make([]byte, 65)
	for i := range sig {
		sig[i] = byte(i)
	}
	return sig
}

func TestWireRoundTrip_Operation_Sign(t *testing.T) {
	require := require.New(t)
	op := &Operation{
		Type:            OpTypeSign,
		CeremonyID:      "mpc/deadbeef",
		KeyID:           "key-1",
		RequestingChain: "B-Chain",
		Digest:          make([]byte, 32),
		Artifact:        sampleSignature(),
		Signers:         []party.ID{"p1", "p2"},
	}
	b := marshalOperation(op)
	msg, err := zap.Parse(b)
	require.NoError(err)
	got, err := readOperation(msg.Root())
	require.NoError(err)
	require.Equal(op, got)
}

// A keygen operation carries the key record it asks consensus to register.
// That record is the whole payload of the transition, so it must survive the
// wire byte-for-byte — including the policy, from which the degree is derived.
func TestWireRoundTrip_Operation_Keygen(t *testing.T) {
	require := require.New(t)
	rec := sampleKeyRecord()
	commit := KeyCommitDigest(rec)
	op := &Operation{
		Type:            OpTypeKeygen,
		CeremonyID:      "mpc/keygen/cafe",
		KeyID:           rec.KeyID,
		RequestingChain: "B-Chain",
		Digest:          commit[:],
		Artifact:        sampleSignature(),
		Signers:         rec.Participants,
		Key:             rec,
	}
	b := marshalOperation(op)
	msg, err := zap.Parse(b)
	require.NoError(err)
	got, err := readOperation(msg.Root())
	require.NoError(err)
	require.Equal(op, got)

	// The operation digest is what the state root is folded over: identical
	// operations must give an identical digest after a wire round trip, or two
	// validators applying the same block compute different roots.
	require.Equal(op.digest(), got.digest())
}

func TestWireRoundTrip_Block(t *testing.T) {
	require := require.New(t)
	rec := sampleKeyRecord()
	commit := KeyCommitDigest(rec)
	blk := &Block{
		ID_:            ids.ID{9}, // derived; must NOT affect wire
		ParentID_:      ids.ID{1, 2, 3},
		BlockHeight:    42,
		BlockTimestamp: 1_700_000_000,
		StateRoot:      [32]byte{7, 7, 7},
		Operations: []*Operation{
			{
				Type: OpTypeKeygen, CeremonyID: "c1", KeyID: rec.KeyID,
				Digest: commit[:], Artifact: sampleSignature(),
				Signers: rec.Participants, Key: rec,
			},
			{
				Type: OpTypeSign, CeremonyID: "c2", KeyID: rec.KeyID,
				Digest: make([]byte, 32), Artifact: sampleSignature(),
				Signers: []party.ID{"p1", "p2"},
			},
		},
	}
	b := blk.Marshal()
	var got Block
	require.NoError(parseBlockBytes(b, &got))
	require.Equal(blk.ParentID_, got.ParentID_)
	require.Equal(blk.BlockHeight, got.BlockHeight)
	require.Equal(blk.BlockTimestamp, got.BlockTimestamp)
	require.Equal(blk.StateRoot, got.StateRoot)
	require.Equal(blk.Operations, got.Operations)

	// canonical: trailing byte rejected
	require.Error(parseBlockBytes(append(b, 0), &got))

	// empty-operations block: Operations stays nil
	empty := &Block{ParentID_: ids.ID{5}, BlockHeight: 1}
	eb := empty.Marshal()
	var egot Block
	require.NoError(parseBlockBytes(eb, &egot))
	require.Nil(egot.Operations)
}

// The key record is the custody registry entry. Policy is stored as K and N and
// the degree is derived from them, so the round trip must preserve the policy
// exactly — a policy that decoded to something else is a key that needs a
// different quorum than the registry claims.
func TestWireRoundTrip_KeyRecord(t *testing.T) {
	require := require.New(t)
	rec := sampleKeyRecord()
	require.NoError(rec.Validate())

	b := marshalKeyRecord(rec)
	got, err := parseKeyRecord(b)
	require.NoError(err)
	require.Equal(rec, got)
	require.Equal(rec.Policy.String(), got.Policy.String())
	require.Equal(rec.Degree(), got.Degree())

	_, err = parseKeyRecord(append(b, 0))
	require.Error(err, "trailing bytes must be rejected")
}

func TestWireRoundTrip_CeremonyRecord(t *testing.T) {
	require := require.New(t)
	c := &CeremonyRecord{
		ID:              "mpc/abc123",
		Kind:            OpTypeSign,
		KeyID:           "bridge-custody",
		Digest:          make([]byte, 32),
		Signers:         []party.ID{"p1", "p2", "p3"},
		Artifact:        sampleSignature(),
		RequestingChain: "B-Chain",
		Height:          99,
	}
	b := marshalCeremonyRecord(c)
	got, err := parseCeremonyRecord(b)
	require.NoError(err)
	require.Equal(c, got)

	_, err = parseCeremonyRecord(append(b, 0))
	require.Error(err, "trailing bytes must be rejected")
}

func TestWireRoundTrip_CrossChainMPCRequest(t *testing.T) {
	require := require.New(t)
	r := &CrossChainMPCRequest{
		Type: "sign", RequestingChain: "B-Chain", KeyID: "key-1",
		KeyType: "secp256k1", MessageHash: []byte("h"), MessageType: "eth_sign",
	}
	b := r.Marshal()
	var got CrossChainMPCRequest
	require.NoError(parseCrossChainMPCRequest(b, &got))
	require.Equal(r, &got)
}
