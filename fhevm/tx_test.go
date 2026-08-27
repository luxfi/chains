// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/mpcvm/fhe"
	"github.com/luxfi/ids"
)

// TestSyntacticVerify_AcceptsWellFormed establishes the baseline every
// rejection test below is measured against.
func TestSyntacticVerify_AcceptsWellFormed(t *testing.T) {
	k := newTestKey(t)
	require.NoError(t, registerTx(t, k, testScheme, digestOf("ok"), 1).SyntacticVerify())
}

// TestSyntacticVerify_Rejects proves each structural rule actually refuses.
// Every case is a well-formed transaction with exactly one thing wrong, so a
// rule that stopped being enforced fails here instead of shipping.
func TestSyntacticVerify_Rejects(t *testing.T) {
	k := newTestKey(t)
	digest := digestOf("subject")
	handle := deriveHandle(digest, testScheme)

	for _, tc := range []struct {
		name string
		tx   *Transaction
		want error
	}{
		{
			name: "unknown transaction type",
			tx:   &Transaction{Type: 99, Nonce: 1},
			want: ErrInvalidTxType,
		},
		{
			name: "unknown scheme",
			tx: &Transaction{Type: TxRegisterCiphertext, Scheme: "paillier", Nonce: 1,
				Payload: mustJSON(t, RegisterPayload{Digest: digest, Size: 1})},
			want: ErrUnknownScheme,
		},
		{
			name: "nonce zero",
			tx: &Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 0,
				Subject: handle, Payload: mustJSON(t, RegisterPayload{Digest: digest, Size: 1})},
			want: ErrBadNonce,
		},
		{
			name: "undecodable payload",
			tx: &Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1,
				Subject: handle, Payload: []byte("not json")},
			want: ErrInvalidPayload,
		},
		{
			name: "register with no digest",
			tx: &Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1,
				Payload: mustJSON(t, RegisterPayload{Size: 1})},
			want: ErrInvalidPayload,
		},
		{
			name: "register with zero size",
			tx: &Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1,
				Subject: handle, Payload: mustJSON(t, RegisterPayload{Digest: digest})},
			want: ErrInvalidPayload,
		},
		{
			name: "register with negative level",
			tx: &Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1,
				Subject: handle, Payload: mustJSON(t, RegisterPayload{Digest: digest, Size: 1, Level: -1})},
			want: ErrInvalidPayload,
		},
		{
			name: "register whose subject is not the derived handle",
			tx: &Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1,
				Subject: [32]byte{0xde, 0xad}, Payload: mustJSON(t, RegisterPayload{Digest: digest, Size: 1})},
			want: ErrHandleMismatch,
		},
		{
			name: "register under a different scheme than the handle names",
			tx: &Transaction{Type: TxRegisterCiphertext, Scheme: "bfv-n13", Nonce: 1,
				Subject: handle, Payload: mustJSON(t, RegisterPayload{Digest: digest, Size: 1})},
			want: ErrHandleMismatch,
		},
		{
			name: "grant conferring nothing",
			tx: &Transaction{Type: TxGrantPermit, Nonce: 1, Subject: handle,
				Payload: mustJSON(t, GrantPayload{Grantee: k.addr, Operations: 0})},
			want: ErrInvalidPayload,
		},
		{
			name: "grant with unknown operation bits",
			tx: &Transaction{Type: TxGrantPermit, Nonce: 1, Subject: handle,
				Payload: mustJSON(t, GrantPayload{Grantee: k.addr, Operations: 1 << 20})},
			want: ErrInvalidPayload,
		},
		{
			name: "request naming no permit",
			tx: &Transaction{Type: TxRequestDecrypt, Scheme: testScheme, Nonce: 1, Subject: handle,
				Payload: mustJSON(t, RequestPayload{})},
			want: ErrInvalidPayload,
		},
		{
			name: "fulfil carrying no result",
			tx: &Transaction{Type: TxFulfillDecrypt, Nonce: 1, Subject: handle,
				Payload: mustJSON(t, FulfillPayload{})},
			want: ErrInvalidPayload,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, tc.tx.SyntacticVerify(), tc.want)
		})
	}
}

// TestSyntacticVerify_AdvanceRejectsUnusableCommittee proves an epoch proposal
// carries the whole committee check with it, so a committee that could never
// sign cannot be voted in.
func TestSyntacticVerify_AdvanceRejectsUnusableCommittee(t *testing.T) {
	good, _ := newCommittee(t, 3)
	pk := []byte("next-network-key")

	advance := func(c []fhe.CommitteeMember, threshold int, key []byte) *Transaction {
		return &Transaction{
			Type: TxAdvanceEpoch, Nonce: 1,
			Subject: committeeDigest(1, threshold, key, c),
			Payload: mustJSON(t, AdvancePayload{Epoch: 1, Committee: c, Threshold: threshold, PublicKey: key}),
		}
	}

	require.NoError(t, advance(good, 2, pk).SyntacticVerify())

	require.ErrorIs(t, advance(nil, 1, pk).SyntacticVerify(), ErrInvalidCommittee)
	require.ErrorIs(t, advance(good, 0, pk).SyntacticVerify(), ErrInvalidThreshold)
	require.ErrorIs(t, advance(good, 4, pk).SyntacticVerify(), ErrInvalidThreshold)
	require.ErrorIs(t, advance(good, 2, nil).SyntacticVerify(), ErrInvalidCommittee)

	// Out of canonical order: two members proposing the same set would hash it
	// differently and never agree, so the order is part of the value.
	shuffled := append([]fhe.CommitteeMember(nil), good...)
	shuffled[0], shuffled[2] = shuffled[2], shuffled[0]
	require.ErrorIs(t, advance(shuffled, 2, pk).SyntacticVerify(), ErrInvalidCommittee)

	// A member whose key cannot be parsed could never attest — installing it
	// would wedge the chain, because a committee that cannot speak also cannot
	// be replaced.
	unusable := append([]fhe.CommitteeMember(nil), good...)
	unusable[1].PublicKey = []byte("not-an-mldsa-65-key")
	require.ErrorIs(t, advance(unusable, 2, pk).SyntacticVerify(), ErrInvalidCommittee)

	// A proposal whose subject does not hash its own contents is refused, so
	// the signature always covers the committee actually being voted for.
	mismatched := advance(good, 2, pk)
	mismatched.Subject = [32]byte{0xff}
	require.ErrorIs(t, mismatched.SyntacticVerify(), ErrHandleMismatch)
}

// TestAuthenticate proves the payer authentication path: an unsigned, a
// tampered, and an impersonating transaction are each refused, and only a
// genuine signature by the claimed identity passes.
func TestAuthenticate(t *testing.T) {
	k := newTestKey(t)
	other := newTestKey(t)

	require.NoError(t, registerTx(t, k, testScheme, digestOf("auth"), 1).authenticate())

	unsigned := registerTx(t, k, testScheme, digestOf("auth"), 1)
	unsigned.Auth, unsigned.Sig = nil, nil
	require.ErrorIs(t, unsigned.authenticate(), ErrUnsignedTx)

	tampered := registerTx(t, k, testScheme, digestOf("auth"), 1)
	tampered.Nonce = 7
	require.ErrorIs(t, tampered.authenticate(), ErrBadSignature)

	// Signed by `other` but claiming k's address: the address is derived from
	// the attached public key, so the two cannot be made to agree.
	impersonating := registerTx(t, k, testScheme, digestOf("auth"), 1)
	other.sign(t, impersonating)
	require.ErrorIs(t, impersonating.authenticate(), ErrPayerMismatch)

	// Auth bytes that are not a public key at all.
	garbage := registerTx(t, k, testScheme, digestOf("auth"), 1)
	garbage.Auth = []byte("garbage")
	garbage.Payer = addressOf(garbage.Auth)
	require.Error(t, garbage.authenticate())
}

// TestAddressDerivationIsStable proves a payer's address and a committee
// member's address come from the same one-way derivation, so membership and
// payer identity cannot disagree.
func TestAddressDerivationIsStable(t *testing.T) {
	k := newTestKey(t)
	require.Equal(t, k.addr, addressOf(k.pub))

	members, keys := newCommittee(t, 3)
	rec := &EpochRecord{EpochInfo: fhe.EpochInfo{Committee: members}}
	for i, key := range keys {
		require.Truef(t, rec.memberOf(key.addr), "member %d must be recognised by its payer address", i)
	}
	require.False(t, rec.memberOf(newTestKey(t).addr), "a stranger is not a member")
}

// TestIdentifiersAreDeterministic proves every id F derives comes from signed
// transaction fields alone, so two validators applying one block agree — and
// that changing any input changes the id.
func TestIdentifiersAreDeterministic(t *testing.T) {
	d := digestOf("determinism")
	a, b := newTestKey(t).addr, newTestKey(t).addr

	require.Equal(t, deriveHandle(d, testScheme), deriveHandle(d, testScheme))
	require.NotEqual(t, deriveHandle(d, testScheme), deriveHandle(d, "bfv-n13"))
	require.NotEqual(t, deriveHandle(d, testScheme), deriveHandle(digestOf("other"), testScheme))

	h := deriveHandle(d, testScheme)
	require.Equal(t, derivePermitID(h, a, b, 1, 0, 1), derivePermitID(h, a, b, 1, 0, 1))
	require.NotEqual(t, derivePermitID(h, a, b, 1, 0, 1), derivePermitID(h, a, b, 1, 0, 2),
		"a grantor may re-grant the same capability without colliding")
	require.NotEqual(t, derivePermitID(h, a, b, 1, 0, 1), derivePermitID(h, b, a, 1, 0, 1))

	require.Equal(t, deriveRequestID(h, a, 3), deriveRequestID(h, a, 3))
	require.NotEqual(t, deriveRequestID(h, a, 3), deriveRequestID(h, a, 4))
	require.NotEqual(t, deriveRequestID(h, a, 3), deriveRequestID(h, b, 3))
}

// TestCommitteeDigestIsSemantic proves the value members attest describes the
// PROPOSAL, not the bytes one client happened to encode: it changes with every
// meaningful field and with the members themselves.
func TestCommitteeDigestIsSemantic(t *testing.T) {
	c, _ := newCommittee(t, 3)
	pk := []byte("network-key")
	base := committeeDigest(1, 2, pk, c)

	require.Equal(t, base, committeeDigest(1, 2, pk, c))
	require.NotEqual(t, base, committeeDigest(2, 2, pk, c), "epoch must bind")
	require.NotEqual(t, base, committeeDigest(1, 3, pk, c), "threshold must bind")
	require.NotEqual(t, base, committeeDigest(1, 2, []byte("other"), c), "network key must bind")

	fewer := c[:2]
	require.NotEqual(t, base, committeeDigest(1, 2, pk, fewer), "membership must bind")

	// Length-prefixing means a member's fields cannot be re-split across the
	// boundary to forge a colliding digest.
	shifted := append([]fhe.CommitteeMember(nil), c...)
	shifted[0].PublicKey = append(append([]byte(nil), c[0].PublicKey...), c[1].PublicKey...)
	require.NotEqual(t, base, committeeDigest(1, 2, pk, shifted))
}

// TestTallyCountsDistinctMembers proves a threshold decision counts members,
// not messages: one member repeating itself never raises a count, and votes for
// different values are counted apart.
func TestTallyCountsDistinctMembers(t *testing.T) {
	a, b := newTestKey(t).addr, newTestKey(t).addr
	x, y := [32]byte{1}, [32]byte{2}

	as := []Attestation{{Member: a, Value: x}, {Member: a, Value: x}}
	require.Equal(t, 1, tally(as, x), "a repeated member counts once")

	as = append(as, Attestation{Member: b, Value: x})
	require.Equal(t, 2, tally(as, x))

	require.Zero(t, tally(as, y), "votes for another value do not count")
	require.True(t, attested(as, a))
	require.False(t, attested(as, newTestKey(t).addr))
}

// TestEffectDistinguishesOperations proves the in-flight uniqueness key names
// the right thing: two votes by one member on one decision collide, votes by
// different members do not, and two grants by one grantor do not.
func TestEffectDistinguishesOperations(t *testing.T) {
	k := newTestKey(t)
	other := newTestKey(t)
	req := [32]byte{7}

	// One member cannot have two attestations to one request in flight, even
	// naming different results — the effect is the vote, not the value.
	v1 := fulfillTx(t, k, req, [32]byte{1}, 1)
	v2 := fulfillTx(t, k, req, [32]byte{2}, 2)
	require.Equal(t, v1.effect(), v2.effect())

	// A different member voting on the same request is a different effect.
	v3 := fulfillTx(t, other, req, [32]byte{1}, 1)
	require.NotEqual(t, v1.effect(), v3.effect())

	// Registering two different ciphertexts are different effects; registering
	// the same one twice is the same effect.
	r1 := registerTx(t, k, testScheme, digestOf("one"), 1)
	r2 := registerTx(t, k, testScheme, digestOf("two"), 2)
	r1again := registerTx(t, other, testScheme, digestOf("one"), 1)
	require.NotEqual(t, r1.effect(), r2.effect())
	require.Equal(t, r1.effect(), r1again.effect(), "the handle is the effect, whoever claims it")

	// Two grants over the same handle by the same grantor are distinct — the
	// nonce distinguishes the permits they create.
	handle := deriveHandle(digestOf("g"), testScheme)
	g1 := grantTx(t, k, handle, other.addr, fhe.PermitOpDecrypt, 0, 1)
	g2 := grantTx(t, k, handle, other.addr, fhe.PermitOpDecrypt, 0, 2)
	require.NotEqual(t, g1.effect(), g2.effect())
}

// TestTransactionIDIsContentHash proves the id is the hash of the canonical
// wire, so it changes with any field and cannot be chosen by the sender.
func TestTransactionIDIsContentHash(t *testing.T) {
	k := newTestKey(t)
	tx := registerTx(t, k, testScheme, digestOf("id"), 1)
	first := tx.ID()
	require.NotEqual(t, ids.Empty, first)
	require.Equal(t, first, tx.ID(), "ID is stable once computed")

	other := registerTx(t, k, testScheme, digestOf("id"), 2)
	require.NotEqual(t, first, other.ID())
}
