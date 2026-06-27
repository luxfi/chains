// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

func TestTransactionRoundTrip(t *testing.T) {
	k := newTestKey(t)
	tx := registerTx(t, k, "rt-key", 150_000, 7)

	data := tx.Bytes()
	require.NotEmpty(t, data)

	parsed, err := ParseTransaction(data)
	require.NoError(t, err)
	require.Equal(t, tx.Type, parsed.Type)
	require.Equal(t, tx.Algorithm, parsed.Algorithm)
	require.Equal(t, tx.Payer, parsed.Payer)
	require.Equal(t, tx.KeyID, parsed.KeyID)
	require.Equal(t, tx.GasLimit, parsed.GasLimit)
	require.Equal(t, tx.Nonce, parsed.Nonce)
	require.Equal(t, tx.Payload, parsed.Payload)
	require.Equal(t, tx.Auth, parsed.Auth)
	require.Equal(t, tx.Sig, parsed.Sig)
	require.Equal(t, tx.ID(), parsed.ID())

	// A round-tripped, signed tx authenticates.
	require.NoError(t, parsed.authenticate())
}

func TestParseTransactionRejectsTruncated(t *testing.T) {
	k := newTestKey(t)
	tx := registerTx(t, k, "trunc", 150_000, 1)
	data := tx.Bytes()
	_, err := ParseTransaction(data[:len(data)-5])
	require.Error(t, err)
}

func TestSyntacticVerify(t *testing.T) {
	k := newTestKey(t)

	// Valid register.
	require.NoError(t, registerTx(t, k, "ok", 150_000, 1).SyntacticVerify())

	// Invalid type.
	bad := &Transaction{Type: 99}
	require.ErrorIs(t, bad.SyntacticVerify(), ErrInvalidTxType)

	// Register with bad threshold (t > n).
	payload := mustJSON(t, RegisterKeyPayload{
		Name: "bad", PublicKey: []byte("p"), Threshold: 9, TotalShares: 5,
		Commitments: [][]byte{{1}},
	})
	badThresh := &Transaction{Type: TxRegisterKey, Algorithm: "ml-dsa-65", Payload: payload}
	require.ErrorIs(t, badThresh.SyntacticVerify(), ErrInvalidThreshold)

	// Authorize with unknown ceremony type.
	cp := mustJSON(t, AuthorizePayload{Ceremony: "wat"})
	badCer := &Transaction{Type: TxAuthorize, Algorithm: "ml-dsa-65", KeyID: ids.GenerateTestID(), Payload: cp}
	require.ErrorIs(t, badCer.SyntacticVerify(), ErrInvalidCeremony)
}

func TestSetPolicyAuthorization(t *testing.T) {
	owner := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{owner.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	acceptOne(t, vm, registerTx(t, owner, "pkey", 200_000, 1))
	keyID := deriveKeyID("pkey")

	// A funded stranger cannot change the policy: rejected at admission, never charged.
	stranger := newTestKey(t)
	fundLedger(t, vm, stranger.addr, 1_000_000_000)
	sp := mustJSON(t, SetPolicyPayload{Policy: AuthPolicy{Admins: []fee_Account{stranger.addr}}})
	strangerTx := &Transaction{Type: TxSetPolicy, Payer: stranger.addr, KeyID: keyID, GasLimit: 200_000, Nonce: 1, Payload: sp}
	stranger.sign(t, strangerTx)
	_, err := vm.SubmitTx(strangerTx)
	require.ErrorIs(t, err, ErrUnauthorized)

	balAfter, _ := vm.Balance(stranger.addr)
	require.Equal(t, uint64(1_000_000_000), balAfter, "unauthorized tx must never be charged")

	// The owner (admin) CAN update the policy.
	sp2 := mustJSON(t, SetPolicyPayload{Policy: AuthPolicy{Authorized: []fee_Account{stranger.addr}}})
	ownerTx := &Transaction{Type: TxSetPolicy, Payer: owner.addr, KeyID: keyID, GasLimit: 200_000, Nonce: 2, Payload: sp2}
	owner.sign(t, ownerTx)
	acceptOne(t, vm, ownerTx)

	rec, ok := vm.KeyByName("pkey")
	require.True(t, ok)
	require.Contains(t, rec.Policy.Authorized, stranger.addr)
	require.Contains(t, rec.Policy.Admins, owner.addr, "owner must remain admin after policy update")
}

// fundLedger credits an account directly (test helper) and commits.
func fundLedger(t *testing.T, vm *VM, acct fee_Account, amount uint64) {
	t.Helper()
	vm.stateLock.Lock()
	require.NoError(t, vm.ledger.Credit(acct, amount))
	require.NoError(t, vm.versdb.Commit())
	vm.stateLock.Unlock()
}
