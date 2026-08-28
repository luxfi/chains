// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// call drives the VM's real JSON-RPC surface end to end — over the registered
// gorilla codec, through the mux NewHTTPHandler builds, into the Service. It
// returns the decoded result and any JSON-RPC error message, so a test asserts
// what a client actually receives rather than what a Go method returns.
func call(t *testing.T, h http.Handler, method string, args, out any) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"method": "kchain." + method, "params": []any{args}, "id": 1,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *string         `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope), "body: %s", rec.Body)

	// A refused call answers 400 and carries the reason; an accepted one answers
	// 200 and carries a result. Never 200 with a silent empty body.
	if envelope.Error != nil {
		require.Equal(t, http.StatusBadRequest, rec.Code, "a refusal must not answer 200")
		require.NotEmpty(t, *envelope.Error)
		return *envelope.Error
	}
	require.Equal(t, http.StatusOK, rec.Code)
	if out != nil {
		require.NoError(t, json.Unmarshal(envelope.Result, out))
	}
	return ""
}

// TestRPCSubmitsAndReadsThroughConsensus drives the whole public surface over
// real HTTP: a client-signed transaction goes in as hex, the chain settles it in
// a block, and every read-only query then observes the committed PUBLIC record.
// Nothing here is a getter assertion — each read is checked against the effect a
// consensus block produced.
func TestRPCSubmitsAndReadsThroughConsensus(t *testing.T) {
	k := newTestKey(t)
	const fund = uint64(10_000_000_000)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): fund})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	h, err := vm.NewHTTPHandler(ctx)
	require.NoError(t, err)

	// Submit a signed RegisterKey over the wire.
	tx := registerTx(t, k, "rpc-key", 300_000, 1)
	var sub SubmitTransactionReply
	require.Empty(t, call(t, h, "SubmitTransaction",
		SubmitTransactionArgs{Tx: "0x" + hex.EncodeToString(tx.Bytes())}, &sub))
	require.Equal(t, tx.ID().String(), sub.TxID)

	// Before the block, the key does not exist: submission is not application.
	var missing GetKeyReply
	require.Contains(t, call(t, h, "GetKey", GetKeyArgs{Name: "rpc-key"}, &missing),
		ErrKeyNotFound.Error())

	blk, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))

	// By name and by id, the same record.
	var byName, byID GetKeyReply
	require.Empty(t, call(t, h, "GetKey", GetKeyArgs{Name: "rpc-key"}, &byName))
	require.Equal(t, "rpc-key", byName.Key.Name)
	require.Equal(t, StatusActive, byName.Key.Status)
	require.Equal(t, k.addr.String(), byName.Key.Owner)
	require.Empty(t, call(t, h, "GetKey", GetKeyArgs{ID: byName.Key.ID}, &byID))
	require.Equal(t, byName.Key, byID.Key, "id and name must resolve the same record")

	// The view carries the PUBLIC material and only that. Decode it back.
	pub, err := base64.StdEncoding.DecodeString(byName.Key.PublicKey)
	require.NoError(t, err)
	require.Equal(t, []byte("PUBLIC-KEY-MATERIAL-ONLY"), pub)
	require.Len(t, byName.Key.Commitments, 3)

	// The balance query reflects the burn the block performed.
	var bal BalanceReply
	require.Empty(t, call(t, h, "Balance", BalanceArgs{Address: k.hexAddr()}, &bal))
	spent := fund - bal.BalanceNLUX
	require.Positive(t, spent, "the operation must have cost something")
	require.Equal(t, spent, bal.BurnedNLUX, "what the payer lost is what the chain burned")

	// Health reports the live chain.
	var health HealthReply
	require.Empty(t, call(t, h, "Health", HealthArgs{}, &health))
	require.True(t, health.Healthy)
	require.Equal(t, "1", health.Details["keys"])
	require.Equal(t, "true", health.Details["authOnly"])
}

// TestRPCRejectsMalformedInput proves the surface fails closed on anything it
// cannot decode: bad hex, bad transaction bytes, an unparseable id, an unknown
// account, and a query for a record that does not exist.
func TestRPCRejectsMalformedInput(t *testing.T) {
	vm := newTestVM(t, nil)
	defer func() { _ = vm.Shutdown(context.Background()) }()
	h, err := vm.NewHTTPHandler(context.Background())
	require.NoError(t, err)

	require.NotEmpty(t, call(t, h, "SubmitTransaction", SubmitTransactionArgs{Tx: "zz"}, nil),
		"non-hex must be refused")
	require.NotEmpty(t, call(t, h, "SubmitTransaction", SubmitTransactionArgs{Tx: "0xdeadbeef"}, nil),
		"undecodable transaction bytes must be refused")
	require.NotEmpty(t, call(t, h, "GetKey", GetKeyArgs{ID: "not-an-id"}, nil))
	require.Contains(t, call(t, h, "GetKey", GetKeyArgs{Name: "absent"}, nil), ErrKeyNotFound.Error())
	require.NotEmpty(t, call(t, h, "GetCeremony", GetCeremonyArgs{ID: "not-an-id"}, nil))
	require.Contains(t, call(t, h, "GetCeremony",
		GetCeremonyArgs{ID: ids.GenerateTestID().String()}, nil), ErrInvalidCeremony.Error())
	require.NotEmpty(t, call(t, h, "Balance", BalanceArgs{Address: "0xnothex"}, nil))
	require.NotEmpty(t, call(t, h, "Balance", BalanceArgs{Address: "0xdead"}, nil),
		"an address of the wrong width must be refused, not zero-padded")
}

// TestRPCListAndCeremonyFilter proves ListKeys filters on what it says it
// filters on, and GetCeremony returns the record a consensus-authorized
// ceremony created.
func TestRPCListAndCeremonyFilter(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()
	h, err := vm.NewHTTPHandler(ctx)
	require.NoError(t, err)

	acceptOne(t, vm, registerTx(t, k, "dsa-key", 300_000, 1))

	kemTx := registerTx(t, k, "kem-key", 300_000, 2)
	kemTx.Algorithm = "ml-kem-768"
	k.sign(t, kemTx)
	acceptOne(t, vm, kemTx)

	// Revoke one so a status filter has something to separate.
	revoke := &Transaction{
		Type: TxRevokeKey, Payer: k.addr, KeyID: deriveKeyID("kem-key"),
		GasLimit: 300_000, Nonce: 3, Payload: mustJSON(t, RevokePayload{Reason: "rotate"}),
	}
	k.sign(t, revoke)
	acceptOne(t, vm, revoke)

	var all, byAlgo, byStatus, none ListKeysReply
	require.Empty(t, call(t, h, "ListKeys", ListKeysArgs{}, &all))
	require.Equal(t, 2, all.Total)

	require.Empty(t, call(t, h, "ListKeys", ListKeysArgs{Algorithm: "ml-kem-768"}, &byAlgo))
	require.Equal(t, 1, byAlgo.Total)
	require.Equal(t, "kem-key", byAlgo.Keys[0].Name)

	require.Empty(t, call(t, h, "ListKeys", ListKeysArgs{Status: StatusRevoked}, &byStatus))
	require.Equal(t, 1, byStatus.Total)
	require.Equal(t, "kem-key", byStatus.Keys[0].Name)

	require.Empty(t, call(t, h, "ListKeys",
		ListKeysArgs{Algorithm: "ml-dsa-65", Status: StatusRevoked}, &none))
	require.Zero(t, none.Total, "filters must compose, not fall back to a match-all")

	// Authorize a ceremony on the surviving key and read it back by id.
	authorize := &Transaction{
		Type: TxAuthorize, Algorithm: "ml-dsa-65", Payer: k.addr,
		KeyID: deriveKeyID("dsa-key"), GasLimit: 300_000, Nonce: 4,
		Payload: mustJSON(t, AuthorizePayload{Ceremony: CeremonySign, Message: []byte("digest")}),
	}
	k.sign(t, authorize)
	acceptOne(t, vm, authorize)

	var ceremonyID ids.ID
	vm.stateLock.RLock()
	for id := range vm.ceremonies {
		ceremonyID = id
	}
	vm.stateLock.RUnlock()

	var got GetCeremonyReply
	require.Empty(t, call(t, h, "GetCeremony", GetCeremonyArgs{ID: ceremonyID.String()}, &got))
	require.Equal(t, CeremonySign, got.Ceremony.Type)
	require.Equal(t, CeremonyAuthorized, got.Ceremony.Status)
	require.Equal(t, k.addr.String(), got.Ceremony.Requester)
	msg, err := base64.StdEncoding.DecodeString(got.Ceremony.Message)
	require.NoError(t, err)
	require.Equal(t, []byte("digest"), msg)
	require.Empty(t, got.Ceremony.Result, "an authorized ceremony has no result yet")
}

// TestFeeScheduleQuotesWhatTheChainCharges proves the published schedule is the
// same computation settlement uses: every quoted entry must equal FeeFor for
// that exact (operation, algorithm), and every priced algorithm must appear. A
// schedule that drifted from the charge would have clients underfunding their
// gas limits.
func TestFeeScheduleQuotesWhatTheChainCharges(t *testing.T) {
	vm := newTestVM(t, nil)
	defer func() { _ = vm.Shutdown(context.Background()) }()
	h, err := vm.NewHTTPHandler(context.Background())
	require.NoError(t, err)

	var sched FeeScheduleReply
	require.Empty(t, call(t, h, "FeeSchedule", FeeScheduleArgs{}, &sched))
	require.Equal(t, uint64(GasPrice), sched.GasPrice)

	ops := map[string]uint8{
		"registerKey": TxRegisterKey, "setPolicy": TxSetPolicy,
		"authorize": TxAuthorize, "revokeKey": TxRevokeKey,
	}
	seenAlgo := map[string]bool{}
	for _, e := range sched.Entries {
		op, ok := ops[e.Operation]
		require.Truef(t, ok, "schedule names an unknown operation %q", e.Operation)
		want, err := FeeFor(&Transaction{Type: op, Algorithm: e.Algorithm})
		require.NoError(t, err)
		require.Equalf(t, want, e.FeeNLUX, "%s/%s quoted %d but costs %d",
			e.Operation, e.Algorithm, e.FeeNLUX, want)
		require.Equal(t, e.Gas*uint64(GasPrice), e.FeeNLUX)
		if usesAlgorithm(op) {
			seenAlgo[e.Algorithm] = true
		}
	}
	for algo := range algoGas {
		require.Truef(t, seenAlgo[algo], "algorithm %q is priced but not quoted", algo)
	}
	require.Len(t, sched.Entries, 2*len(algoGas)+2)
}

// TestHandlersAreOnePath proves the VM publishes exactly one handler, and that
// NewHTTPHandler mounts that same handler — two names for one surface, not two
// surfaces.
func TestHandlersAreOnePath(t *testing.T) {
	vm := newTestVM(t, nil)
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	handlers, err := vm.CreateHandlers(ctx)
	require.NoError(t, err)
	require.Len(t, handlers, 1)
	require.Contains(t, handlers, "/rpc")

	h, err := vm.NewHTTPHandler(ctx)
	require.NoError(t, err)
	var health HealthReply
	require.Empty(t, call(t, h, "Health", HealthArgs{}, &health))
	require.True(t, health.Healthy)
}
