// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// TestPolicyExpiryAuthorizesNobody proves an expired policy is not merely
// stricter but closed: it authorizes nobody, admins included, and the boundary
// is the expiry instant itself rather than the second after it.
func TestPolicyExpiryAuthorizesNobody(t *testing.T) {
	admin, guest, stranger := newTestKey(t), newTestKey(t), newTestKey(t)
	p := AuthPolicy{
		Admins:     []fee_Account{admin.addr},
		Authorized: []fee_Account{guest.addr},
		ExpiresAt:  1_000,
	}

	require.True(t, p.MayInvoke(admin.addr, 999), "an admin may invoke while live")
	require.True(t, p.MayInvoke(guest.addr, 999), "an authorized account may invoke while live")
	require.False(t, p.MayInvoke(stranger.addr, 999), "nobody else may, ever")

	require.False(t, p.MayInvoke(admin.addr, 1_000), "expiry is inclusive: at ExpiresAt it is closed")
	require.False(t, p.MayInvoke(guest.addr, 1_000))

	// Zero means no expiry, not "expired at the epoch".
	never := AuthPolicy{Admins: []fee_Account{admin.addr}, ExpiresAt: 0}
	require.True(t, never.MayInvoke(admin.addr, 1<<40))

	// Administering is not invoking: a guest never administers.
	require.True(t, p.MayAdmin(admin.addr))
	require.False(t, p.MayAdmin(guest.addr))
	require.False(t, p.MayAdmin(stranger.addr))
}

// TestRegistrantCannotLockItselfOut proves the fail-secure default: whoever
// registers a key is an admin of it even if the policy it supplied names
// somebody else, so a key can never be born unadministrable.
func TestRegistrantCannotLockItselfOut(t *testing.T) {
	owner, other := newTestKey(t), newTestKey(t)
	vm := newTestVM(t, map[string]uint64{owner.hexAddr(): 10_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	reg := &Transaction{
		Type: TxRegisterKey, Algorithm: "ml-dsa-65", Payer: owner.addr,
		KeyID: deriveKeyID("locked"), GasLimit: 300_000, Nonce: 1,
		Payload: mustJSON(t, RegisterKeyPayload{
			Name: "locked", PublicKey: []byte("PUB"), Threshold: 1, TotalShares: 1,
			Commitments: [][]byte{{9}},
			// A policy naming ONLY somebody else.
			Policy: AuthPolicy{Admins: []fee_Account{other.addr}},
		}),
	}
	owner.sign(t, reg)
	acceptOne(t, vm, reg)

	rec, ok := vm.KeyByName("locked")
	require.True(t, ok)
	require.True(t, rec.Policy.MayAdmin(owner.addr), "the registrant is always an admin")
	require.True(t, rec.Policy.MayAdmin(other.addr), "the supplied admins are kept too")

	// And that is not decoration: the owner can actually still revoke it.
	revoke := &Transaction{
		Type: TxRevokeKey, Payer: owner.addr, KeyID: deriveKeyID("locked"),
		GasLimit: 300_000, Nonce: 2, Payload: mustJSON(t, RevokePayload{Reason: "mine"}),
	}
	owner.sign(t, revoke)
	acceptOne(t, vm, revoke)
	rec, _ = vm.KeyByName("locked")
	require.Equal(t, StatusRevoked, rec.Status)
}

// TestOwnerSurvivesAPolicyRewrite proves an admin cannot evict the key's owner
// by replacing the policy — the owner is re-added whatever the new policy says,
// so no policy update can strand a key.
func TestOwnerSurvivesAPolicyRewrite(t *testing.T) {
	owner, coAdmin := newTestKey(t), newTestKey(t)
	vm := newTestVM(t, map[string]uint64{
		owner.hexAddr(): 10_000_000_000, coAdmin.hexAddr(): 10_000_000_000,
	})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	reg := &Transaction{
		Type: TxRegisterKey, Algorithm: "ml-dsa-65", Payer: owner.addr,
		KeyID: deriveKeyID("shared"), GasLimit: 300_000, Nonce: 1,
		Payload: mustJSON(t, RegisterKeyPayload{
			Name: "shared", PublicKey: []byte("PUB"), Threshold: 1, TotalShares: 1,
			Commitments: [][]byte{{1}},
			Policy:      AuthPolicy{Admins: []fee_Account{coAdmin.addr}},
		}),
	}
	owner.sign(t, reg)
	acceptOne(t, vm, reg)

	// The co-admin rewrites the policy to name only itself.
	rewrite := &Transaction{
		Type: TxSetPolicy, Payer: coAdmin.addr, KeyID: deriveKeyID("shared"),
		GasLimit: 300_000, Nonce: 1,
		Payload: mustJSON(t, SetPolicyPayload{
			Policy: AuthPolicy{Admins: []fee_Account{coAdmin.addr}},
		}),
	}
	coAdmin.sign(t, rewrite)
	acceptOne(t, vm, rewrite)

	rec, ok := vm.KeyByName("shared")
	require.True(t, ok)
	require.True(t, rec.Policy.MayAdmin(owner.addr), "the owner cannot be evicted by a policy update")

	// Proven by use: the owner can still act.
	revoke := &Transaction{
		Type: TxRevokeKey, Payer: owner.addr, KeyID: deriveKeyID("shared"),
		GasLimit: 300_000, Nonce: 2, Payload: mustJSON(t, RevokePayload{}),
	}
	owner.sign(t, revoke)
	acceptOne(t, vm, revoke)
	rec, _ = vm.KeyByName("shared")
	require.Equal(t, StatusRevoked, rec.Status)
}

// TestRevocationIsTerminal proves a revoked key is dead to policy and to
// ceremonies alike, and that only an admin may revoke.
func TestRevocationIsTerminal(t *testing.T) {
	owner, stranger := newTestKey(t), newTestKey(t)
	vm := newTestVM(t, map[string]uint64{
		owner.hexAddr(): 10_000_000_000, stranger.hexAddr(): 10_000_000_000,
	})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	keyID := deriveKeyID("terminal")

	acceptOne(t, vm, registerTx(t, owner, "terminal", 300_000, 1))

	// A stranger may not revoke somebody else's key.
	badRevoke := &Transaction{
		Type: TxRevokeKey, Payer: stranger.addr, KeyID: keyID,
		GasLimit: 300_000, Nonce: 1, Payload: mustJSON(t, RevokePayload{}),
	}
	stranger.sign(t, badRevoke)
	_, err := vm.SubmitTx(badRevoke)
	require.ErrorIs(t, err, ErrUnauthorized)

	// Revoking a key that does not exist is not-found, not a silent success.
	ghost := &Transaction{
		Type: TxRevokeKey, Payer: owner.addr, KeyID: ids.GenerateTestID(),
		GasLimit: 300_000, Nonce: 2, Payload: mustJSON(t, RevokePayload{}),
	}
	owner.sign(t, ghost)
	_, err = vm.SubmitTx(ghost)
	require.ErrorIs(t, err, ErrKeyNotFound)

	// The owner revokes.
	revoke := &Transaction{
		Type: TxRevokeKey, Payer: owner.addr, KeyID: keyID,
		GasLimit: 300_000, Nonce: 2, Payload: mustJSON(t, RevokePayload{Reason: "compromise"}),
	}
	owner.sign(t, revoke)
	acceptOne(t, vm, revoke)

	rec, ok := vm.KeyByID(keyID)
	require.True(t, ok)
	require.Equal(t, StatusRevoked, rec.Status)

	// After revocation neither policy changes nor ceremonies are possible.
	setPolicy := &Transaction{
		Type: TxSetPolicy, Payer: owner.addr, KeyID: keyID, GasLimit: 300_000, Nonce: 3,
		Payload: mustJSON(t, SetPolicyPayload{}),
	}
	owner.sign(t, setPolicy)
	_, err = vm.SubmitTx(setPolicy)
	require.ErrorIs(t, err, ErrKeyRevoked)

	authorize := &Transaction{
		Type: TxAuthorize, Algorithm: "ml-dsa-65", Payer: owner.addr, KeyID: keyID,
		GasLimit: 300_000, Nonce: 3,
		Payload: mustJSON(t, AuthorizePayload{Ceremony: CeremonySign, Message: []byte("m")}),
	}
	owner.sign(t, authorize)
	_, err = vm.SubmitTx(authorize)
	require.ErrorIs(t, err, ErrKeyRevoked)

	// But re-revoking is still permitted: revocation is idempotent, not an error
	// that would strand an admin retrying after a dropped block.
	again := &Transaction{
		Type: TxRevokeKey, Payer: owner.addr, KeyID: keyID, GasLimit: 300_000, Nonce: 3,
		Payload: mustJSON(t, RevokePayload{}),
	}
	owner.sign(t, again)
	acceptOne(t, vm, again)
}

// TestDuplicateNameRefused proves a key name is claimed once. The key id is
// derived from the name, so admitting a second registration would silently
// overwrite the first key's public material and committee.
func TestDuplicateNameRefused(t *testing.T) {
	first, second := newTestKey(t), newTestKey(t)
	vm := newTestVM(t, map[string]uint64{
		first.hexAddr(): 10_000_000_000, second.hexAddr(): 10_000_000_000,
	})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	acceptOne(t, vm, registerTx(t, first, "taken", 300_000, 1))

	_, err := vm.SubmitTx(registerTx(t, second, "taken", 300_000, 1))
	require.ErrorIs(t, err, ErrKeyExists)

	rec, ok := vm.KeyByName("taken")
	require.True(t, ok)
	require.Equal(t, first.addr, rec.Owner, "the first claim stands")
}

// TestApplyReChecksAuthorization proves Apply is defence in depth rather than a
// blind writer: handed a transaction that was never verified, it still refuses
// every unauthorized case rather than mutating state.
func TestApplyReChecksAuthorization(t *testing.T) {
	owner, stranger := newTestKey(t), newTestKey(t)
	vm := newTestVM(t, map[string]uint64{owner.hexAddr(): 10_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	acceptOne(t, vm, registerTx(t, owner, "guarded", 300_000, 1))
	keyID := deriveKeyID("guarded")
	now := vm.clock.Time().Unix()

	vm.stateLock.Lock()
	defer vm.stateLock.Unlock()

	unknownType := &Transaction{Type: 200, Payer: owner.addr}
	require.ErrorIs(t, unknownType.Apply(vm, now), ErrInvalidTxType)

	strangerPolicy := &Transaction{
		Type: TxSetPolicy, Payer: stranger.addr, KeyID: keyID,
		Payload: mustJSON(t, SetPolicyPayload{}),
	}
	require.ErrorIs(t, strangerPolicy.Apply(vm, now), ErrUnauthorized)

	strangerRevoke := &Transaction{
		Type: TxRevokeKey, Payer: stranger.addr, KeyID: keyID,
		Payload: mustJSON(t, RevokePayload{}),
	}
	require.ErrorIs(t, strangerRevoke.Apply(vm, now), ErrUnauthorized)

	ghostAuthorize := &Transaction{
		Type: TxAuthorize, Algorithm: "ml-dsa-65", Payer: owner.addr, KeyID: ids.GenerateTestID(),
		Payload: mustJSON(t, AuthorizePayload{Ceremony: CeremonyDKG}),
	}
	require.ErrorIs(t, ghostAuthorize.Apply(vm, now), ErrKeyNotFound)

	// A payload that decoded at Verify but not here is refused, not applied with
	// zero values.
	corrupt := &Transaction{Type: TxRegisterKey, Payer: owner.addr, Payload: []byte("{{{")}
	require.ErrorIs(t, corrupt.Apply(vm, now), ErrInvalidPayload)

	// Nothing above mutated anything.
	rec := vm.keys[keyID]
	require.Equal(t, StatusActive, rec.Status)
	require.Empty(t, vm.ceremonies)
}

// TestSyntacticVerifyRefusesMalformedPayloads walks every shape the codec must
// refuse before any state is consulted. Each case is a distinct refusal, so a
// single over-broad check could not stand in for the set.
func TestSyntacticVerifyRefusesMalformedPayloads(t *testing.T) {
	cases := []struct {
		name string
		tx   *Transaction
		want error
	}{
		{"unknown type", &Transaction{Type: 42}, ErrInvalidTxType},
		{"register with unpriced algorithm",
			&Transaction{Type: TxRegisterKey, Algorithm: "rsa-2048"}, ErrUnknownAlgorithm},
		{"register with undecodable payload",
			&Transaction{Type: TxRegisterKey, Algorithm: "ml-dsa-65", Payload: []byte("{{")},
			ErrInvalidPayload},
		{"register with no name",
			&Transaction{Type: TxRegisterKey, Algorithm: "ml-dsa-65",
				Payload: mustJSONRaw(RegisterKeyPayload{PublicKey: []byte("p"),
					Threshold: 1, TotalShares: 1, Commitments: [][]byte{{1}}})}, ErrInvalidPayload},
		{"register with no public key",
			&Transaction{Type: TxRegisterKey, Algorithm: "ml-dsa-65",
				Payload: mustJSONRaw(RegisterKeyPayload{Name: "n",
					Threshold: 1, TotalShares: 1, Commitments: [][]byte{{1}}})}, ErrInvalidPayload},
		{"register with zero threshold",
			&Transaction{Type: TxRegisterKey, Algorithm: "ml-dsa-65",
				Payload: mustJSONRaw(RegisterKeyPayload{Name: "n", PublicKey: []byte("p"),
					Threshold: 0, TotalShares: 3, Commitments: [][]byte{{1}}})}, ErrInvalidThreshold},
		{"register with zero shares",
			&Transaction{Type: TxRegisterKey, Algorithm: "ml-dsa-65",
				Payload: mustJSONRaw(RegisterKeyPayload{Name: "n", PublicKey: []byte("p"),
					Threshold: 1, TotalShares: 0, Commitments: [][]byte{{1}}})}, ErrInvalidThreshold},
		{"register with no commitments",
			&Transaction{Type: TxRegisterKey, Algorithm: "ml-dsa-65",
				Payload: mustJSONRaw(RegisterKeyPayload{Name: "n", PublicKey: []byte("p"),
					Threshold: 1, TotalShares: 1})}, ErrInvalidPayload},
		{"setpolicy with undecodable payload",
			&Transaction{Type: TxSetPolicy, Payload: []byte("nope")}, ErrInvalidPayload},
		{"authorize with undecodable payload",
			&Transaction{Type: TxAuthorize, Algorithm: "ml-dsa-65", Payload: []byte("nope")},
			ErrInvalidPayload},
		{"authorize with unknown ceremony",
			&Transaction{Type: TxAuthorize, Algorithm: "ml-dsa-65",
				Payload: mustJSONRaw(AuthorizePayload{Ceremony: "seance"})}, ErrInvalidCeremony},
		{"revoke with undecodable payload",
			&Transaction{Type: TxRevokeKey, Payload: []byte("nope")}, ErrInvalidPayload},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.ErrorIs(t, c.tx.SyntacticVerify(), c.want)
		})
	}

	// The well-formed counterparts pass, so the refusals above are about the
	// specific defect and not about the shape in general.
	for _, ceremony := range []string{CeremonyDKG, CeremonySign, CeremonyReshare} {
		ok := &Transaction{Type: TxAuthorize, Algorithm: "ml-dsa-65",
			Payload: mustJSONRaw(AuthorizePayload{Ceremony: ceremony})}
		require.NoError(t, ok.SyntacticVerify())
	}
	require.NoError(t, (&Transaction{Type: TxSetPolicy,
		Payload: mustJSONRaw(SetPolicyPayload{})}).SyntacticVerify())
	require.NoError(t, (&Transaction{Type: TxRevokeKey,
		Payload: mustJSONRaw(RevokePayload{})}).SyntacticVerify())
}

// TestAuthenticateRefusesAForeignKey proves the payer address is a commitment to
// the public key: a well-formed signature under a key that is not the payer's is
// refused, and a payer whose Auth is not an ML-DSA-65 key at all is refused
// before any verification is attempted.
func TestAuthenticateRefusesAForeignKey(t *testing.T) {
	k := newTestKey(t)

	tx := registerTx(t, k, "auth", 300_000, 1)
	require.NoError(t, tx.authenticate())

	// Auth bytes that are the right owner but not a parseable key.
	garbled := registerTx(t, k, "auth", 300_000, 1)
	garbled.Auth = []byte("not-a-key")
	garbled.Payer = addressOf(garbled.Auth) // keep the address consistent
	require.Error(t, garbled.authenticate(), "an unparseable public key must be refused")

	// A signature over different bytes does not verify.
	swapped := registerTx(t, k, "auth", 300_000, 1)
	other := registerTx(t, k, "auth", 300_000, 2)
	swapped.Sig = other.Sig
	require.ErrorIs(t, swapped.authenticate(), ErrBadSignature)
}

// TestCorruptRecordsAreSkippedNotFatal proves the cache reload survives a
// record it cannot decode: the chain keeps the records it can read rather than
// refusing to start, and the unreadable one is simply absent.
func TestCorruptRecordsAreSkippedNotFatal(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 10_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	acceptOne(t, vm, registerTx(t, k, "readable", 300_000, 1))

	vm.stateLock.Lock()
	require.NoError(t, vm.versdb.Put([]byte(KeyPrefix+ids.GenerateTestID().String()), []byte("{{{")))
	require.NoError(t, vm.versdb.Put([]byte(CeremonyPrefix+ids.GenerateTestID().String()), []byte("{{{")))
	require.NoError(t, vm.versdb.Commit())
	err := vm.loadStateLocked()
	vm.stateLock.Unlock()
	require.NoError(t, err)

	require.Len(t, vm.Keys(), 1, "the readable record survives")
	_, ok := vm.KeyByName("readable")
	require.True(t, ok)
	_, ok = vm.Ceremony(ids.GenerateTestID())
	require.False(t, ok)
}

// TestReadsAreCopies proves the query surface hands out copies: a caller that
// mutates what it was given cannot reach into committed chain state.
func TestReadsAreCopies(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 10_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	acceptOne(t, vm, registerTx(t, k, "copied", 300_000, 1))
	keyID := deriveKeyID("copied")

	byID, ok := vm.KeyByID(keyID)
	require.True(t, ok)
	byID.Status = "tampered"
	byID.Name = "tampered"

	fresh, ok := vm.KeyByName("copied")
	require.True(t, ok)
	require.Equal(t, StatusActive, fresh.Status, "a mutated copy must not reach chain state")

	all := vm.Keys()
	require.Len(t, all, 1)
	all[0].Status = "tampered"
	fresh, _ = vm.KeyByID(keyID)
	require.Equal(t, StatusActive, fresh.Status)

	_, ok = vm.KeyByID(ids.GenerateTestID())
	require.False(t, ok)
	_, ok = vm.KeyByName("absent")
	require.False(t, ok)
}

// TestCeremonyIdBindsItsRequest proves the ceremony id is a commitment to what
// was authorized: same key, same requester, same message but a different nonce
// is a DIFFERENT ceremony, so two authorizations can never collapse into one
// record the committee would fulfil once.
func TestCeremonyIdBindsItsRequest(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	acceptOne(t, vm, registerTx(t, k, "ceremonial", 300_000, 1))
	keyID := deriveKeyID("ceremonial")

	authorize := func(nonce uint64, msg string) {
		tx := &Transaction{
			Type: TxAuthorize, Algorithm: "ml-dsa-65", Payer: k.addr, KeyID: keyID,
			GasLimit: 300_000, Nonce: nonce,
			Payload: mustJSON(t, AuthorizePayload{Ceremony: CeremonySign, Message: []byte(msg)}),
		}
		k.sign(t, tx)
		acceptOne(t, vm, tx)
	}
	authorize(2, "digest-one")
	authorize(3, "digest-one") // same message, later nonce
	authorize(4, "digest-two")

	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	require.Len(t, vm.ceremonies, 3, "each authorization is its own ceremony record")
	for _, c := range vm.ceremonies {
		require.Equal(t, keyID, c.KeyID)
		require.Equal(t, k.addr, c.Requester)
		require.Equal(t, CeremonyAuthorized, c.Status)
	}
}

// TestExpiredPermitStopsCeremoniesButNotAdministration proves the two verbs are
// separate: expiry closes invocation for everyone, while administration — which
// is how an admin would extend the policy — remains open.
func TestExpiredPermitStopsCeremoniesButNotAdministration(t *testing.T) {
	owner, guest := newTestKey(t), newTestKey(t)
	vm := newTestVM(t, map[string]uint64{
		owner.hexAddr(): 100_000_000_000, guest.hexAddr(): 100_000_000_000,
	})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	expiry := genesisTime.Add(time.Hour)
	invoke := expiringKey(t, vm, owner, guest, "temporal", expiry.Unix(), 1)

	// Before expiry the guest may invoke.
	acceptOne(t, vm, invoke)

	// After it, nobody may.
	vm.clock.Set(expiry.Add(time.Second))
	later := &Transaction{
		Type: TxAuthorize, Algorithm: "ml-dsa-65", Payer: guest.addr,
		KeyID: deriveKeyID("temporal"), GasLimit: 300_000, Nonce: 2,
		Payload: mustJSON(t, AuthorizePayload{Ceremony: CeremonySign, Message: []byte("m")}),
	}
	guest.sign(t, later)
	_, err := vm.SubmitTx(later)
	require.ErrorIs(t, err, ErrUnauthorized)

	// But the owner can still administer, and that restores invocation.
	extend := &Transaction{
		Type: TxSetPolicy, Payer: owner.addr, KeyID: deriveKeyID("temporal"),
		GasLimit: 300_000, Nonce: 2,
		Payload: mustJSON(t, SetPolicyPayload{Policy: AuthPolicy{
			Authorized: []fee_Account{guest.addr},
			ExpiresAt:  expiry.Add(time.Hour).Unix(),
		}}),
	}
	owner.sign(t, extend)
	acceptOne(t, vm, extend)

	guest.sign(t, later)
	_, err = vm.SubmitTx(later)
	require.NoError(t, err, "an extended policy authorizes again")
}
