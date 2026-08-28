// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"context"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/chains/mpcvm/fhe"
)

// TestServicePublicParams proves the parameters F reports come from the FHE
// runtime's own threshold configuration — so a client encrypting for F and a
// node evaluating for F agree by construction — while the threshold and network
// key come from the seated epoch on chain.
func TestServicePublicParams(t *testing.T) {
	committee, _ := newCommittee(t, 3)
	vm := newTestVM(t, nil, committee, 2)
	svc := &Service{vm: vm}

	var reply fhe.GetPublicParamsReply
	require.NoError(t, svc.GetPublicParams(nil, &fhe.GetPublicParamsArgs{}, &reply))

	cfg := fhe.DefaultThresholdConfig()
	require.Equal(t, cfg.CKKSParams.LogN(), reply.LogN)
	require.Equal(t, int(cfg.CKKSParams.LogQ()+cfg.CKKSParams.LogP()), reply.LogQP)
	require.Equal(t, cfg.CKKSParams.LogDefaultScale(), reply.LogScale)

	require.Equal(t, uint64(0), reply.Epoch)
	require.Equal(t, 2, reply.Threshold)
	require.Equal(t, hex.EncodeToString([]byte("network-fhe-public-key")), reply.PublicKey)
	require.Equal(t, vm.chainID.String(), reply.ChainID)
}

// TestServiceCommittee proves the committee is readable per epoch, and that an
// epoch nobody ever seated is an error rather than an empty answer.
func TestServiceCommittee(t *testing.T) {
	committee, _ := newCommittee(t, 3)
	vm := newTestVM(t, nil, committee, 2)
	svc := &Service{vm: vm}

	var reply fhe.GetCommitteeReply
	require.NoError(t, svc.GetCommittee(nil, &fhe.GetCommitteeArgs{}, &reply))
	require.Equal(t, uint64(0), reply.Epoch)
	require.Equal(t, 2, reply.Threshold)
	require.Len(t, reply.Members, 3)
	for i, m := range reply.Members {
		require.Equal(t, committee[i].NodeID.String(), m.NodeID)
		require.Equal(t, hex.EncodeToString(committee[i].PublicKey), m.PublicKey)
		require.Equal(t, i, m.Index)
	}

	future := uint64(9)
	require.ErrorIs(t,
		svc.GetCommittee(nil, &fhe.GetCommitteeArgs{Epoch: &future}, &fhe.GetCommitteeReply{}),
		ErrEpochNotFound)
}

// TestServiceCiphertextViews proves a registered value reads back through the
// RPC surface with its digest — so a client can check a body it fetched from
// off-chain storage — and that the listing filters work.
func TestServiceCiphertextViews(t *testing.T) {
	a, b := newTestKey(t), newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(a, b), committee, 1)
	svc := &Service{vm: vm}

	digest := digestOf("value-one")
	acceptOne(t, vm, registerTx(t, a, testScheme, digest, 1))
	acceptOne(t, vm, registerTx(t, b, "bfv-n13", digestOf("value-two"), 1))

	handle := deriveHandle(digest, testScheme)
	var got GetCiphertextReply
	require.NoError(t, svc.GetCiphertext(nil, &GetCiphertextArgs{Handle: hexOf(handle)}, &got))
	require.Equal(t, hexOf(handle), got.Ciphertext.Handle)
	require.Equal(t, hexOf(digest), got.Ciphertext.Digest)
	require.Equal(t, a.addr.String(), got.Ciphertext.Owner)
	require.Equal(t, testScheme, got.Ciphertext.Scheme)
	require.Equal(t, uint32(4096), got.Ciphertext.Size)
	require.Equal(t, vm.chainID.String(), got.Ciphertext.ChainID)

	var all ListCiphertextsReply
	require.NoError(t, svc.ListCiphertexts(nil, &ListCiphertextsArgs{}, &all))
	require.Equal(t, 2, all.Total)

	var byScheme ListCiphertextsReply
	require.NoError(t, svc.ListCiphertexts(nil, &ListCiphertextsArgs{Scheme: "bfv-n13"}, &byScheme))
	require.Equal(t, 1, byScheme.Total)
	require.Equal(t, "bfv-n13", byScheme.Ciphertexts[0].Scheme)

	var byOwner ListCiphertextsReply
	require.NoError(t, svc.ListCiphertexts(nil, &ListCiphertextsArgs{Owner: a.hexAddr()}, &byOwner))
	require.Equal(t, 1, byOwner.Total)
	require.Equal(t, a.addr.String(), byOwner.Ciphertexts[0].Owner)

	require.ErrorIs(t,
		svc.GetCiphertext(nil, &GetCiphertextArgs{Handle: hexOf(digestOf("absent"))}, &GetCiphertextReply{}),
		ErrCiphertextNotFound)
}

// TestServicePermitView proves a grant reads back with the capability bits and
// expiry it was created with, and that revocation is visible.
func TestServicePermitView(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(owner, grantee), committee, 1)
	svc := &Service{vm: vm}

	ops := fhe.PermitOpDecrypt | fhe.PermitOpCompute
	handle, permitID := seedPermit(t, vm, owner, grantee, ops, 0)

	var got GetPermitReply
	require.NoError(t, svc.GetPermit(nil, &GetPermitArgs{PermitID: hexOf(permitID)}, &got))
	require.Equal(t, hexOf(permitID), got.Permit.PermitID)
	require.Equal(t, hexOf(handle), got.Permit.Handle)
	require.Equal(t, owner.addr.String(), got.Permit.Grantor)
	require.Equal(t, grantee.addr.String(), got.Permit.Grantee)
	require.Equal(t, ops, got.Permit.Operations)
	require.Equal(t, StatusActive, got.Permit.Status)

	acceptOne(t, vm, revokeTx(t, owner, permitID, 3))
	require.NoError(t, svc.GetPermit(nil, &GetPermitArgs{PermitID: hexOf(permitID)}, &got))
	require.Equal(t, StatusRevoked, got.Permit.Status)

	require.ErrorIs(t,
		svc.GetPermit(nil, &GetPermitArgs{PermitID: hexOf(digestOf("absent"))}, &GetPermitReply{}),
		ErrPermitNotFound)
}

// TestServiceDecryptView proves the request surface shows how far the committee
// has got — who attested what, against what threshold — and the final result
// handle once it completes.
func TestServiceDecryptView(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	vm, _, members := newDecryptVM(t, 3, 2, owner, grantee)
	svc := &Service{vm: vm}

	handle, permitID := seedPermit(t, vm, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, vm, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)

	var got GetDecryptReply
	require.NoError(t, svc.GetDecrypt(nil, &GetDecryptArgs{RequestID: hexOf(requestID)}, &got))
	require.Equal(t, hexOf(requestID), got.Request.RequestID)
	require.Equal(t, hexOf(handle), got.Request.Handle)
	require.Equal(t, hexOf(permitID), got.Request.PermitID)
	require.Equal(t, grantee.addr.String(), got.Request.Requester)
	require.Equal(t, fhe.RequestPending.String(), got.Request.Status)
	require.Equal(t, 2, got.Request.Threshold)
	require.Empty(t, got.Request.Attestations)
	require.Empty(t, got.Request.ResultHandle, "a pending request has no result")
	require.Equal(t, "ca11000000000000000000000000000000000000", got.Request.Callback)
	require.Equal(t, "01020304", got.Request.Selector)

	result := digestOf("answer")
	acceptOne(t, vm, fulfillTx(t, members[0], requestID, result, 1))
	require.NoError(t, svc.GetDecrypt(nil, &GetDecryptArgs{RequestID: hexOf(requestID)}, &got))
	require.Len(t, got.Request.Attestations, 1)
	require.Equal(t, members[0].addr.String(), got.Request.Attestations[0].Member)
	require.Equal(t, hexOf(result), got.Request.Attestations[0].Value)
	require.Equal(t, fhe.RequestPending.String(), got.Request.Status)

	acceptOne(t, vm, fulfillTx(t, members[1], requestID, result, 1))
	require.NoError(t, svc.GetDecrypt(nil, &GetDecryptArgs{RequestID: hexOf(requestID)}, &got))
	require.Equal(t, fhe.RequestCompleted.String(), got.Request.Status)
	require.Equal(t, hexOf(result), got.Request.ResultHandle)
	require.NotZero(t, got.Request.CompletedAt)

	require.ErrorIs(t,
		svc.GetDecrypt(nil, &GetDecryptArgs{RequestID: hexOf(digestOf("absent"))}, &GetDecryptReply{}),
		ErrRequestNotFound)
}

// TestServiceSubmitTransaction proves the one mutating endpoint takes a
// client-signed transaction as hex, parses it canonically, and enqueues it —
// and that a transaction the VM would refuse is refused here too.
func TestServiceSubmitTransaction(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	svc := &Service{vm: vm}

	tx := registerTx(t, k, testScheme, digestOf("submitted"), 1)
	var reply SubmitTransactionReply
	require.NoError(t, svc.SubmitTransaction(nil,
		&SubmitTransactionArgs{Tx: hex.EncodeToString(tx.Bytes())}, &reply))
	require.Equal(t, tx.ID().String(), reply.TxID)

	// The 0x prefix is accepted too.
	next := registerTx(t, k, testScheme, digestOf("prefixed"), 2)
	require.NoError(t, svc.SubmitTransaction(nil,
		&SubmitTransactionArgs{Tx: "0x" + hex.EncodeToString(next.Bytes())}, &reply))

	acceptQueued(t, vm)
	_, ok := vm.Ciphertext(tx.Subject)
	require.True(t, ok)

	// Not hex at all.
	require.Error(t, svc.SubmitTransaction(nil, &SubmitTransactionArgs{Tx: "zzzz"}, &reply))
	// Hex, but not a transaction.
	require.Error(t, svc.SubmitTransaction(nil, &SubmitTransactionArgs{Tx: "deadbeef"}, &reply))
	// A well-formed transaction the VM refuses (replayed nonce).
	require.ErrorIs(t, svc.SubmitTransaction(nil,
		&SubmitTransactionArgs{Tx: hex.EncodeToString(tx.Bytes())}, &reply), ErrBadNonce)
}

// TestServiceBalanceAndHealth proves the account and diagnostic surfaces report
// what consensus actually did.
func TestServiceBalanceAndHealth(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	svc := &Service{vm: vm}

	tx := registerTx(t, k, testScheme, digestOf("charged"), 1)
	spent, err := FeeFor(tx)
	require.NoError(t, err)
	acceptOne(t, vm, tx)

	var bal BalanceReply
	require.NoError(t, svc.Balance(nil, &BalanceArgs{Address: k.hexAddr()}, &bal))
	require.Equal(t, testFund-spent, bal.BalanceNLUX)
	require.Equal(t, spent, bal.BurnedNLUX)

	require.Error(t, svc.Balance(nil, &BalanceArgs{Address: "nothex"}, &bal))
	require.Error(t, svc.Balance(nil, &BalanceArgs{Address: "0011"}, &bal))

	var h HealthReply
	require.NoError(t, svc.Health(nil, &HealthArgs{}, &h))
	require.True(t, h.Healthy)
	require.Equal(t, "1", h.Details["ciphertexts"])
	require.Equal(t, "1", h.Details["height"])
}

// TestServiceFeeSchedule proves clients can compute the exact burn before
// submitting: every operation is listed, scheme-priced ones once per scheme,
// and each entry's fee is gas times the price.
func TestServiceFeeSchedule(t *testing.T) {
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, nil, committee, 1)
	svc := &Service{vm: vm}

	var reply FeeScheduleReply
	require.NoError(t, svc.FeeSchedule(nil, &FeeScheduleArgs{}, &reply))
	require.Equal(t, uint64(GasPrice), reply.GasPrice)

	seen := map[string]int{}
	for _, e := range reply.Entries {
		seen[e.Operation]++
		require.Equal(t, e.Gas*uint64(GasPrice), e.FeeNLUX, "%s/%s", e.Operation, e.Scheme)
		require.GreaterOrEqual(t, e.FeeNLUX, MinScheduledFee())
	}
	for op, name := range opNames {
		want := 1
		if usesScheme(op) {
			want = len(schemeGas)
		}
		require.Equalf(t, want, seen[name], "operation %s listed %d times", name, seen[name])
	}
}

// TestServiceRejectsMalformedIdentifiers proves the 32-byte identifier decoder
// fails closed on anything that is not exactly 32 bytes of hex, rather than
// padding or truncating into a valid-looking lookup.
func TestServiceRejectsMalformedIdentifiers(t *testing.T) {
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, nil, committee, 1)
	svc := &Service{vm: vm}

	for _, bad := range []string{"", "zz", "00", hex.EncodeToString(make([]byte, 31)), hex.EncodeToString(make([]byte, 33))} {
		require.Errorf(t, svc.GetCiphertext(nil, &GetCiphertextArgs{Handle: bad}, &GetCiphertextReply{}), "handle %q", bad)
		require.Errorf(t, svc.GetPermit(nil, &GetPermitArgs{PermitID: bad}, &GetPermitReply{}), "permit %q", bad)
		require.Errorf(t, svc.GetDecrypt(nil, &GetDecryptArgs{RequestID: bad}, &GetDecryptReply{}), "request %q", bad)
	}
}

// TestHTTPHandlerServesRPC proves the VM hands consensus a handler that
// actually routes to the registered service.
func TestHTTPHandlerServesRPC(t *testing.T) {
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, nil, committee, 1)

	h, err := vm.NewHTTPHandler(context.Background())
	require.NoError(t, err)
	require.NotNil(t, h)

	handlers, err := vm.CreateHandlers(context.Background())
	require.NoError(t, err)
	require.Contains(t, handlers, "/rpc")

	static, err := vm.CreateStaticHandlers(context.Background())
	require.NoError(t, err)
	require.Nil(t, static, "F serves nothing that does not depend on chain state")

	var _ http.Handler = h
}

// TestServiceReportsWhatItCannotAnswer covers the RPC surface's refusals: an
// address or identifier it cannot decode, and a ledger it cannot read. A read
// endpoint that answered zero on a failed read would be worse than one that
// refuses — a caller cannot tell the difference from the outside.
func TestServiceReportsWhatItCannotAnswer(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	svc := &Service{vm: vm}
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("listed"), 1))

	// A filter whose address does not decode is an error, not an empty listing:
	// an empty listing reads as "this owner has nothing".
	require.Error(t, svc.ListCiphertexts(nil,
		&ListCiphertextsArgs{Owner: "not-an-address"}, &ListCiphertextsReply{}))
	require.Error(t, svc.Balance(nil, &BalanceArgs{Address: "zz"}, &BalanceReply{}))

	// The control: the same calls with sound arguments answer.
	var listed ListCiphertextsReply
	require.NoError(t, svc.ListCiphertexts(nil, &ListCiphertextsArgs{Owner: k.hexAddr()}, &listed))
	require.Equal(t, 1, listed.Total)

	var bal BalanceReply
	require.NoError(t, svc.Balance(nil, &BalanceArgs{Address: k.hexAddr()}, &bal))
	require.Less(t, bal.BalanceNLUX, testFund, "the fee was burned")
	require.Positive(t, bal.BurnedNLUX)

	// A ledger that cannot be read is reported, on both the balance it names and
	// the supply it reports beside it.
	sound := vm.state
	vm.state = &faults{Database: sound, readFails: []byte("fee/")}
	vm.ledger = fee.NewLedger(vm.state)
	require.ErrorIs(t, svc.Balance(nil, &BalanceArgs{Address: k.hexAddr()}, &BalanceReply{}), errDisk)
	require.ErrorIs(t, svc.Health(nil, &HealthArgs{}, &HealthReply{}), errDisk)
	vm.state, vm.ledger = sound, fee.NewLedger(sound)

	// And with it sound again, health answers.
	var h HealthReply
	require.NoError(t, svc.Health(nil, &HealthArgs{}, &h))
	require.True(t, h.Healthy)
}
