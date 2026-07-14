// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// sampleCredential is a fully-populated credential exercising every wire
// field: fixed ids, times (with sub-second precision), a dynamic claims
// document, a type list, and an optional proof.
func sampleCredential() *Credential {
	return &Credential{
		ID:              ids.ID{1, 2, 3},
		Type:            []string{"VerifiableCredential", "KYCCredential"},
		Issuer:          ids.ID{4, 5, 6},
		Subject:         ids.ID{7, 8, 9},
		IssuanceDate:    time.Unix(1_700_000_000, 500).UTC(),
		ExpirationDate:  time.Unix(1_800_000_000, 0).UTC(),
		Claims:          map[string]interface{}{"name": "alice", "age": float64(30), "verified": true},
		Status:          CredentialActive,
		RevocationIndex: 7,
		Proof: &CredentialProof{
			Type:               "Ed25519Signature2020",
			Created:            "2026-07-14T00:00:00Z",
			VerificationMethod: "did:lux:abc#key-1",
			ProofPurpose:       "assertionMethod",
			ProofValue:         []byte{0xde, 0xad, 0xbe, 0xef},
			ZKProof:            []byte{0x01, 0x02},
		},
	}
}

func sampleIdentity() *Identity {
	return &Identity{
		ID:          ids.ID{10, 11, 12},
		DID:         "did:lux:0123456789abcdef",
		PublicKey:   []byte{0xaa, 0xbb, 0xcc, 0xdd},
		Controllers: []ids.ID{{13}, {14}, {15}},
		Services: []ServiceEndpoint{
			{ID: "svc-1", Type: "LinkedDomains", ServiceEndpoint: "https://example.com"},
			{ID: "svc-2", Type: "MessagingService", ServiceEndpoint: "https://msg.example.com"},
		},
		Created:  time.Unix(1_650_000_000, 0).UTC(),
		Updated:  time.Unix(1_660_000_000, 123).UTC(),
		Metadata: map[string]string{"org": "lux", "role": "issuer", "tier": "gold"},
	}
}

func sampleRevocation() *RevocationEntry {
	return &RevocationEntry{
		CredentialID: ids.ID{1, 2, 3},
		RevokedBy:    ids.ID{4, 5, 6},
		RevokedAt:    time.Unix(1_750_000_000, 0).UTC(),
		Reason:       "key compromise",
	}
}

func requireCredentialEqual(t *testing.T, want, got *Credential) {
	t.Helper()
	require.Equal(t, want.ID, got.ID)
	require.Equal(t, want.Type, got.Type)
	require.Equal(t, want.Issuer, got.Issuer)
	require.Equal(t, want.Subject, got.Subject)
	require.Equal(t, want.IssuanceDate.UnixNano(), got.IssuanceDate.UnixNano())
	require.Equal(t, want.ExpirationDate.UnixNano(), got.ExpirationDate.UnixNano())
	require.Equal(t, want.Claims, got.Claims)
	require.Equal(t, want.Status, got.Status)
	require.Equal(t, want.RevocationIndex, got.RevocationIndex)
	require.Equal(t, want.Proof, got.Proof)
}

func requireIdentityEqual(t *testing.T, want, got *Identity) {
	t.Helper()
	require.Equal(t, want.ID, got.ID)
	require.Equal(t, want.DID, got.DID)
	require.Equal(t, want.PublicKey, got.PublicKey)
	require.Equal(t, want.Controllers, got.Controllers)
	require.Equal(t, want.Services, got.Services)
	require.Equal(t, want.Created.UnixNano(), got.Created.UnixNano())
	require.Equal(t, want.Updated.UnixNano(), got.Updated.UnixNano())
	require.Equal(t, want.Metadata, got.Metadata)
}

func requireRevocationEqual(t *testing.T, want, got *RevocationEntry) {
	t.Helper()
	require.Equal(t, want.CredentialID, got.CredentialID)
	require.Equal(t, want.RevokedBy, got.RevokedBy)
	require.Equal(t, want.RevokedAt.UnixNano(), got.RevokedAt.UnixNano())
	require.Equal(t, want.Reason, got.Reason)
}

func TestWireRoundTrip_Credential(t *testing.T) {
	require := require.New(t)
	c := sampleCredential()

	got, err := parseCredential(marshalCredential(c))
	require.NoError(err)
	requireCredentialEqual(t, c, got)

	// canonical: trailing byte rejected
	_, err = parseCredential(append(marshalCredential(c), 0))
	require.Error(err)

	// no-proof credential: Proof stays nil
	c.Proof = nil
	got, err = parseCredential(marshalCredential(c))
	require.NoError(err)
	require.Nil(got.Proof)
	requireCredentialEqual(t, c, got)
}

func TestWireRoundTrip_Identity(t *testing.T) {
	require := require.New(t)
	id := sampleIdentity()

	got, err := parseIdentity(marshalIdentity(id))
	require.NoError(err)
	requireIdentityEqual(t, id, got)

	_, err = parseIdentity(append(marshalIdentity(id), 0))
	require.Error(err)

	// minimal identity: empty collections come back nil
	min := &Identity{ID: ids.ID{99}, DID: "did:lux:min", Created: time.Unix(1, 0).UTC(), Updated: time.Unix(2, 0).UTC()}
	got, err = parseIdentity(marshalIdentity(min))
	require.NoError(err)
	require.Nil(got.Controllers)
	require.Nil(got.Services)
	require.Nil(got.Metadata)
	requireIdentityEqual(t, min, got)
}

func TestWireRoundTrip_Revocation(t *testing.T) {
	require := require.New(t)
	r := sampleRevocation()

	parsed, err := parseRevocation(marshalRevocation(r))
	require.NoError(err)
	requireRevocationEqual(t, r, parsed)

	// canonical: trailing byte rejected
	_, err = parseRevocation(append(marshalRevocation(r), 0))
	require.Error(err)
}

func TestWireRoundTrip_Block(t *testing.T) {
	require := require.New(t)
	blk := &Block{
		ID_:            ids.ID{0xff}, // derived; must NOT affect wire
		ParentID_:      ids.ID{1, 2, 3},
		BlockHeight:    42,
		BlockTimestamp: 1_700_000_000,
		StateRoot:      []byte{0xca, 0xfe, 0xba, 0xbe},
		Credentials:    []*Credential{sampleCredential(), sampleCredential()},
		Revocations:    []*RevocationEntry{sampleRevocation()},
		Identities:     []*Identity{sampleIdentity()},
	}

	b, err := blk.Marshal()
	require.NoError(err)

	var got Block
	require.NoError(parseBlock(b, &got))
	require.Equal(blk.ParentID_, got.ParentID_)
	require.Equal(blk.BlockHeight, got.BlockHeight)
	require.Equal(blk.BlockTimestamp, got.BlockTimestamp)
	require.Equal(blk.StateRoot, got.StateRoot)

	require.Len(got.Credentials, 2)
	for i := range blk.Credentials {
		requireCredentialEqual(t, blk.Credentials[i], got.Credentials[i])
	}
	require.Len(got.Revocations, 1)
	requireRevocationEqual(t, blk.Revocations[0], got.Revocations[0])
	require.Len(got.Identities, 1)
	requireIdentityEqual(t, blk.Identities[0], got.Identities[0])

	// canonical: trailing byte rejected
	require.Error(parseBlock(append(b, 0), &got))

	// empty block: nested slices come back nil, StateRoot nil
	empty := &Block{ParentID_: ids.ID{5}, BlockHeight: 1, BlockTimestamp: 2}
	eb, err := empty.Marshal()
	require.NoError(err)
	var egot Block
	require.NoError(parseBlock(eb, &egot))
	require.Nil(egot.Credentials)
	require.Nil(egot.Revocations)
	require.Nil(egot.Identities)
	require.Nil(egot.StateRoot)
	require.Equal(uint64(1), egot.BlockHeight)
	require.Equal(int64(2), egot.BlockTimestamp)
}

func TestWireDeterminism_Block(t *testing.T) {
	require := require.New(t)

	build := func() *Block {
		return &Block{
			ParentID_:      ids.ID{1, 2, 3},
			BlockHeight:    42,
			BlockTimestamp: 1_700_000_000,
			StateRoot:      []byte{0xca, 0xfe},
			Credentials:    []*Credential{sampleCredential()},
			Revocations:    []*RevocationEntry{sampleRevocation()},
			Identities:     []*Identity{sampleIdentity()},
		}
	}

	b1, err := build().Marshal()
	require.NoError(err)
	b2, err := build().Marshal()
	require.NoError(err)
	require.Equal(b1, b2, "same logical block must marshal to identical bytes")

	// blockID = hash of wire, stable across independent constructions
	require.Equal(build().ID(), build().ID())
	// a changed field moves the id
	other := build()
	other.BlockHeight = 43
	require.NotEqual(build().ID(), other.ID())
}

func TestWireDeterminism_Credential(t *testing.T) {
	require := require.New(t)
	// Multi-key claims + multi-key identity metadata: Go map iteration order
	// is randomized, so identical bytes prove key-sorted canonicalization.
	c := &Credential{
		ID:     ids.ID{1},
		Type:   []string{"A", "B", "C"},
		Claims: map[string]interface{}{"z": float64(1), "a": "x", "m": true, "b": float64(2)},
		Status: CredentialActive,
	}
	require.Equal(marshalCredential(c), marshalCredential(c))

	id := sampleIdentity()
	require.Equal(marshalIdentity(id), marshalIdentity(id))
}
