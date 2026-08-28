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

	require.NoError(t, registerTx(t, k, testScheme, digestOf("auth"), 1).authenticate(testChainID))

	unsigned := registerTx(t, k, testScheme, digestOf("auth"), 1)
	unsigned.Auth, unsigned.Sig = nil, nil
	require.ErrorIs(t, unsigned.authenticate(testChainID), ErrUnsignedTx)

	tampered := registerTx(t, k, testScheme, digestOf("auth"), 1)
	tampered.Nonce = 7
	require.ErrorIs(t, tampered.authenticate(testChainID), ErrBadSignature)

	// Signed by `other` but claiming k's address: the address is derived from
	// the attached public key, so the two cannot be made to agree.
	impersonating := registerTx(t, k, testScheme, digestOf("auth"), 1)
	other.sign(t, impersonating)
	require.ErrorIs(t, impersonating.authenticate(testChainID), ErrPayerMismatch)

	// Auth bytes that are not a public key at all.
	garbage := registerTx(t, k, testScheme, digestOf("auth"), 1)
	garbage.Auth = []byte("garbage")
	garbage.Payer = addressOf(garbage.Auth)
	require.Error(t, garbage.authenticate(testChainID))
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

	// vote() is the only writer, and it replaces rather than appends, so one
	// member holds exactly one entry however often it votes.
	var as []Attestation
	as = vote(as, a, x)
	as = vote(as, a, x)
	require.Len(t, as, 1, "a repeated member holds one entry")
	require.Equal(t, 1, tally(as, x), "and counts once")

	as = vote(as, b, x)
	require.Equal(t, 2, tally(as, x))
	require.Zero(t, tally(as, y), "votes for another value do not count")

	// Moving a vote moves it: the old value keeps nothing.
	as = vote(as, a, y)
	require.Len(t, as, 2, "still one entry per member")
	require.Equal(t, 1, tally(as, x))
	require.Equal(t, 1, tally(as, y))

	// And the count is over DISTINCT members whatever the slice holds, so a
	// record that somehow carried a duplicate could not inflate a threshold.
	require.Equal(t, 1, tally([]Attestation{{Member: a, Value: x}, {Member: a, Value: x}}, x))
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

	// An epoch advance is a vote on the DECISION, and exactly one epoch is ever
	// open, so one member's two votes are one effect however they differ. The
	// proposal must not enter the effect: if it did, a member could vote twice,
	// both votes would pass Verify against committed state, and Accept would
	// apply one and refuse the other — a block every validator certifies and no
	// validator can apply.
	cA, _ := newCommittee(t, 3)
	cB, _ := newCommittee(t, 3)
	a1 := advanceTx(t, k, 1, cA, 2, []byte("k"), 1)
	a2 := advanceTx(t, k, 1, cB, 2, []byte("k"), 2)
	require.NotEqual(t, a1.Subject, a2.Subject, "two genuinely different proposals")
	require.Equal(t, a1.effect(), a2.effect(), "but one member, one vote")

	// A different member voting on the same decision is a different effect.
	a3 := advanceTx(t, other, 1, cA, 2, []byte("k"), 1)
	require.NotEqual(t, a1.effect(), a3.effect())

	// A vote and an attestation never collide across operation kinds.
	require.NotEqual(t, a1.effect(), v1.effect())
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

// TestSyntacticVerifyRefusesEveryMalformedPayload walks each operation's payload
// rules. They are the checks that run on an UNAUTHENTICATED transaction, so
// each one is a refusal that costs nothing — and each is a field an attacker
// chooses, which is why none of them may be optional.
func TestSyntacticVerifyRefusesEveryMalformedPayload(t *testing.T) {
	digest := digestOf("subject")
	handle := deriveHandle(digest, testScheme)
	sound := RegisterPayload{Digest: digest, Type: 4, Level: 3, Size: 4096}

	for name, tc := range map[string]struct {
		tx   *Transaction
		want error
	}{
		"register: undecodable": {
			&Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1, Subject: handle,
				Payload: []byte("{not json")}, ErrInvalidPayload},
		"register: no digest": {
			&Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1,
				Subject: deriveHandle([32]byte{}, testScheme),
				Payload: mustJSON(nil, RegisterPayload{Type: 4, Level: 3, Size: 4096})}, ErrInvalidPayload},
		"register: zero size": {
			&Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1, Subject: handle,
				Payload: mustJSON(nil, RegisterPayload{Digest: digest, Type: 4, Level: 3})}, ErrInvalidPayload},
		"register: size beyond anything servable": {
			&Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1, Subject: handle,
				Payload: mustJSON(nil, RegisterPayload{Digest: digest, Type: 4, Level: 3, Size: MaxCiphertextSize + 1})}, ErrInvalidPayload},
		"register: negative level": {
			&Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1, Subject: handle,
				Payload: mustJSON(nil, RegisterPayload{Digest: digest, Type: 4, Level: -1, Size: 4096})}, ErrInvalidPayload},
		"register: subject is not the handle": {
			&Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1, Subject: [32]byte{9},
				Payload: mustJSON(nil, sound)}, ErrHandleMismatch},

		"grant: undecodable": {
			&Transaction{Type: TxGrantPermit, Nonce: 1, Payload: []byte("{")}, ErrInvalidPayload},
		"grant: confers nothing": {
			&Transaction{Type: TxGrantPermit, Nonce: 1,
				Payload: mustJSON(nil, GrantPayload{Operations: 0})}, ErrInvalidPayload},
		"grant: unknown capability bits": {
			&Transaction{Type: TxGrantPermit, Nonce: 1,
				Payload: mustJSON(nil, GrantPayload{Operations: 1 << 31})}, ErrInvalidPayload},
		"grant: negative expiry": {
			&Transaction{Type: TxGrantPermit, Nonce: 1,
				Payload: mustJSON(nil, GrantPayload{Operations: fhe.PermitOpDecrypt, Expiry: -1})}, ErrInvalidPayload},

		"revoke: undecodable": {
			&Transaction{Type: TxRevokePermit, Nonce: 1, Payload: []byte("[]")}, ErrInvalidPayload},

		"request: undecodable": {
			&Transaction{Type: TxRequestDecrypt, Scheme: testScheme, Nonce: 1, Payload: []byte("{")}, ErrInvalidPayload},
		"request: names no permit": {
			&Transaction{Type: TxRequestDecrypt, Scheme: testScheme, Nonce: 1,
				Payload: mustJSON(nil, RequestPayload{})}, ErrInvalidPayload},
		"request: negative expiry": {
			&Transaction{Type: TxRequestDecrypt, Scheme: testScheme, Nonce: 1,
				Payload: mustJSON(nil, RequestPayload{PermitID: [32]byte{1}, Expiry: -1})}, ErrInvalidPayload},

		"fulfill: undecodable": {
			&Transaction{Type: TxFulfillDecrypt, Nonce: 1, Payload: []byte("{")}, ErrInvalidPayload},
		"fulfill: no result": {
			&Transaction{Type: TxFulfillDecrypt, Nonce: 1,
				Payload: mustJSON(nil, FulfillPayload{})}, ErrInvalidPayload},

		"advance: undecodable": {
			&Transaction{Type: TxAdvanceEpoch, Nonce: 1, Payload: []byte("{")}, ErrInvalidPayload},

		"a nonce below the first one": {
			&Transaction{Type: TxRevokePermit, Nonce: 0,
				Payload: mustJSON(nil, RevokePayload{})}, ErrBadNonce},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, tc.tx.SyntacticVerify(), tc.want)
		})
	}

	// The control: the well-formed shapes all pass.
	require.NoError(t, (&Transaction{Type: TxRegisterCiphertext, Scheme: testScheme, Nonce: 1,
		Subject: handle, Payload: mustJSON(nil, sound)}).SyntacticVerify())
	require.NoError(t, (&Transaction{Type: TxRevokePermit, Nonce: 1,
		Payload: mustJSON(nil, RevokePayload{})}).SyntacticVerify())
}

// TestCommitteeOrderIsPartOfTheValue proves a committee's members must arrive
// in canonical order and without repeats. Members hash the SET to vote on it,
// so two orderings of the same members would be two different proposals and the
// committee could never agree with itself.
func TestCommitteeOrderIsPartOfTheValue(t *testing.T) {
	c, _ := newCommittee(t, 3)

	shuffled := []fhe.CommitteeMember{c[2], c[0], c[1]}
	require.ErrorIs(t, ValidateCommittee(shuffled, 2, []byte("pk")), ErrInvalidCommittee)

	repeated := []fhe.CommitteeMember{c[0], c[0], c[1]}
	require.ErrorIs(t, ValidateCommittee(repeated, 2, []byte("pk")), ErrInvalidCommittee,
		"one seat twice is not two seats")

	require.NoError(t, ValidateCommittee(c, 2, []byte("pk")), "the control")
}

// TestApplyFailsClosedOnWhatItCannotWrite proves every effect reports a failed
// write instead of returning success. These are the errors that abort a block
// whole: a validator that cannot write cannot proceed, and a transaction that
// silently did not apply would leave two validators holding different state.
func TestApplyFailsClosedOnWhatItCannotWrite(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)
	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)
	next, _ := newCommittee(t, 3)
	now := vm.clock.Time().Unix()

	require.NoError(t, vm.versdb.Close())
	for name, apply := range map[string]func() error{
		"register": func() error { return registerTx(t, owner, testScheme, digestOf("w"), 9).applyRegister(vm, now) },
		"grant": func() error {
			return grantTx(t, owner, handle, grantee.addr, fhe.PermitOpDecrypt, 0, 9).applyGrant(vm, now)
		},
		"revoke":  func() error { return revokeTx(t, owner, permitID, 9).applyRevoke(vm) },
		"request": func() error { return requestTx(t, grantee, testScheme, handle, permitID, 0, 9).applyRequest(vm, now) },
		"fulfill": func() error { return fulfillTx(t, members[0], requestID, digestOf("r"), 9).applyFulfill(vm, now) },
		"advance": func() error { return advanceTx(t, members[0], 1, next, 2, []byte("pk"), 9).applyAdvance(vm, now) },
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, apply())
		})
	}
}

// TestApplyRefusesAPayloadItCannotDecode proves each effect re-derives its
// arguments from the payload and fails closed rather than applying a zero
// value. SyntacticVerify has already accepted the payload by the time a block
// carries it, so this is the check behind the check — but a check that only
// ever runs behind another is one nobody can show still works, so it is shown
// here directly.
func TestApplyRefusesAPayloadItCannotDecode(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)
	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)
	now := vm.clock.Time().Unix()

	junk := func(typ uint8, subject [32]byte) *Transaction {
		return &Transaction{Type: typ, Scheme: testScheme, Payer: owner.addr, Subject: subject,
			Nonce: 9, Payload: []byte("{not json")}
	}
	require.Error(t, junk(TxRegisterCiphertext, handle).applyRegister(vm, now))
	require.Error(t, junk(TxGrantPermit, handle).applyGrant(vm, now))
	require.Error(t, junk(TxRequestDecrypt, handle).applyRequest(vm, now))
	require.Error(t, junk(TxFulfillDecrypt, requestID).applyFulfill(vm, now))
	require.Error(t, junk(TxAdvanceEpoch, [32]byte{}).applyAdvance(vm, now))

	// And each effect that names a record refuses when the record is not there.
	missing := [32]byte{0xaa}
	require.ErrorIs(t, revokeTx(t, owner, missing, 9).applyRevoke(vm), ErrPermitNotFound)
	require.ErrorIs(t, fulfillTx(t, members[0], missing, digestOf("r"), 9).applyFulfill(vm, now), ErrRequestNotFound)

	// A fulfilment whose epoch has been forgotten is refused rather than tallied
	// against a threshold nobody can name.
	rec, ok := vm.Decrypt(requestID)
	require.True(t, ok)
	rec.Epoch = 99
	vm.stateLock.Lock()
	require.NoError(t, vm.putDecrypt(&DecryptRecord{DecryptRequest: rec.DecryptRequest, PermitID: rec.PermitID}))
	vm.stateLock.Unlock()
	require.ErrorIs(t, fulfillTx(t, members[0], requestID, digestOf("r"), 9).applyFulfill(vm, now), ErrEpochNotFound)
}

// TestAnUnknownOperationIsRefused proves authorization fails closed on an
// operation it does not know, rather than falling through to an effect.
//
// Apply has the same default and it is UNREACHABLE: checkAuth runs first and
// refuses every type the switch below does not name, so nothing reaches it. It
// stays because the switch assigns err per case — without the default an
// unknown type would leave err nil and Apply would report the transaction
// APPLIED, which is the one answer that must never be given by accident.
func TestAnUnknownOperationIsRefused(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	vm.stateLock.Lock()
	defer vm.stateLock.Unlock()
	alien := &Transaction{Type: 99, Payer: k.addr, Nonce: 1}
	require.ErrorIs(t, alien.checkAuth(vm, 0), ErrInvalidTxType)

	applied, err := alien.Apply(vm, 0)
	require.NoError(t, err, "an unknown operation reverts; it does not halt the block")
	require.False(t, applied)
}

// TestCheckAuthRefusesWhatItCannotResolve covers the authorization decisions
// that turn on a record being there. Each is a refusal rather than a default:
// authorization that fell through when it could not find what it was asked
// about would grant on ignorance.
func TestCheckAuthRefusesWhatItCannotResolve(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)
	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)
	now := vm.clock.Time().Unix()

	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()

	// A request whose payload does not decode cannot be authorized against a
	// permit it does not name.
	malformed := &Transaction{Type: TxRequestDecrypt, Scheme: testScheme, Payer: grantee.addr,
		Subject: handle, Nonce: 2, Payload: []byte("{not json")}
	require.ErrorIs(t, malformed.checkAuth(vm, now), ErrInvalidPayload)

	// So does an epoch proposal.
	badAdvance := &Transaction{Type: TxAdvanceEpoch, Payer: members[0].addr, Nonce: 2,
		Payload: []byte("{not json")}
	require.ErrorIs(t, badAdvance.checkAuth(vm, now), ErrInvalidPayload)

	// A fulfilment for an epoch the chain has forgotten names no committee, so
	// there is nobody it could be authorized as.
	rec, ok := vm.decrypts[requestID]
	require.True(t, ok)
	held := rec.Epoch
	rec.Epoch = 99
	require.ErrorIs(t,
		fulfillTx(t, members[0], requestID, digestOf("r"), 1).checkAuth(vm, now), ErrEpochNotFound)
	rec.Epoch = held
}

// TestAdvanceReportsAWriteItCannotMake proves the epoch rotation reports a
// failed write at either of the two records it must put down — the epoch it
// closes and the epoch it opens. A rotation that half-happened would leave the
// chain with no sitting committee.
func TestAdvanceReportsAWriteItCannotMake(t *testing.T) {
	vm, _, members := newDecryptVM(t, 3, 1) // one vote decides
	next, _ := newCommittee(t, 3)
	now := vm.clock.Time().Unix()

	require.NoError(t, vm.versdb.Close())
	require.Error(t, advanceTx(t, members[0], 1, next, 2, []byte("pk"), 1).applyAdvance(vm, now),
		"a rotation that cannot be written did not happen")
}

// TestFulfilmentNeedsThePermitThatAskedForIt proves a committee cannot answer a
// request whose authorizing permit is no longer there. The permit is what makes
// the ask legitimate, so a request that outlived it authorizes nothing —
// otherwise a deleted grant would still deliver a plaintext to a callback.
func TestFulfilmentNeedsThePermitThatAskedForIt(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)
	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)
	now := vm.clock.Time().Unix()

	fulfil := fulfillTx(t, members[0], requestID, digestOf("r"), 1)

	vm.stateLock.RLock()
	require.NoError(t, fulfil.checkAuth(vm, now), "the control: with the permit there, it is authorized")
	vm.stateLock.RUnlock()

	// Point the request at a permit nothing granted.
	vm.stateLock.Lock()
	vm.decrypts[requestID].PermitID = [32]byte{0xab}
	vm.stateLock.Unlock()

	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	require.ErrorIs(t, fulfil.checkAuth(vm, now), ErrPermitNotFound)
}
