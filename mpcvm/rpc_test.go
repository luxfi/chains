// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// rpc_test.go — the read surface, driven end to end.
//
// Every test here goes through the real http.Handler and, where a Client method
// exists, through the real Client over a real socket. A test that called the
// rpc* methods directly would prove the projection and nothing about the
// dispatch, the encoding or the error codes a caller actually sees.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/threshold/pkg/quorum"
)

// serve puts the VM's real handler behind a real socket and returns a Client
// pointed at it.
func serve(t *testing.T, vm *VM) (*Client, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	handlers, err := vm.CreateHandlers(ctx())
	require.NoError(t, err)
	for path, h := range handlers {
		mux.Handle(path, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "B-Chain"), srv
}

// call posts one JSON-RPC request and returns the decoded response.
func call(t *testing.T, srv *httptest.Server, method string, params any) RPCResponse {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)

	resp, err := http.Post(srv.URL+"/rpc", "application/json", strings.NewReader(string(body)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var out RPCResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// -----------------------------------------------------------------------------
// Dispatch
// -----------------------------------------------------------------------------

// Ceremonies are requested BY a chain, over the transport that authenticates
// which chain. HTTP authenticates nobody, so this endpoint refuses rather than
// offering a way in that reads a chain's name out of a request body.
func TestCeremoniesAreNotReachableOverAnEndpointThatAuthenticatesNobody(t *testing.T) {
	vm := newVM(t)
	_, srv := serve(t, vm)

	for _, method := range []string{"threshold_keygen", "threshold_sign"} {
		got := call(t, srv, method, map[string]any{"keyId": "vault"})
		require.NotNil(t, got.Error, "%s must not be reachable here", method)
		require.Equal(t, RPCErrorUnauthorized, got.Error.Code)
		require.Contains(t, got.Error.Message, "authenticates no caller")
	}
}

func TestAnUnknownMethodIsNamedNotIgnored(t *testing.T) {
	vm := newVM(t)
	_, srv := serve(t, vm)

	got := call(t, srv, "threshold_doTheThing", nil)
	require.NotNil(t, got.Error)
	require.Equal(t, RPCErrorMethodNotFound, got.Error.Code)
	require.Contains(t, got.Error.Message, "threshold_doTheThing")
}

func TestOnlyAPostCarriesARequest(t *testing.T) {
	vm := newVM(t)
	_, srv := serve(t, vm)

	resp, err := http.Get(srv.URL + "/rpc")
	require.NoError(t, err)
	defer resp.Body.Close()

	var out RPCResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NotNil(t, out.Error)
	require.Equal(t, RPCErrorInvalidRequest, out.Error.Code)
}

func TestABodyThatIsNotJSONIsRefused(t *testing.T) {
	vm := newVM(t)
	_, srv := serve(t, vm)

	resp, err := http.Post(srv.URL+"/rpc", "application/json", strings.NewReader("{not json"))
	require.NoError(t, err)
	defer resp.Body.Close()

	var out RPCResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.Equal(t, RPCErrorInvalidRequest, out.Error.Code)
}

// Every read method that takes parameters refuses ones it cannot decode, with
// the code that says so.
func TestUndecodableParametersAreNamedAsSuch(t *testing.T) {
	vm := newVM(t)
	_, srv := serve(t, vm)

	for _, method := range []string{
		"mpc_getKey", "mpc_getCeremony", "threshold_getPublicKey", "threshold_getAddress",
		"threshold_getQuota", "threshold_getChainPermissions",
	} {
		got := call(t, srv, method, []int{1, 2, 3})
		require.NotNilf(t, got.Error, "%s", method)
		require.Equalf(t, RPCErrorInvalidParams, got.Error.Code, "%s", method)
	}
}

// A VM error carries its own code, and the mapping is written once so every
// method classifies the same failure the same way.
func TestAFailureIsClassifiedTheSameWayByEveryMethod(t *testing.T) {
	vm := newVM(t)
	_, srv := serve(t, vm)

	for _, method := range []string{"mpc_getKey", "threshold_getPublicKey", "threshold_getAddress"} {
		got := call(t, srv, method, map[string]string{"keyId": "nothing"})
		require.NotNilf(t, got.Error, "%s", method)
		require.Equalf(t, RPCErrorKeyNotFound, got.Error.Code, "%s", method)
	}

	got := call(t, srv, "mpc_getCeremony", map[string]string{"ceremonyId": "mpc/nothing"})
	require.Equal(t, RPCErrorCeremonyNotFound, got.Error.Code)

	got = call(t, srv, "threshold_getQuota", map[string]string{"chainId": "Nobody"})
	require.Equal(t, RPCErrorUnauthorized, got.Error.Code)

	got = call(t, srv, "threshold_getChainPermissions", map[string]string{"chainId": "Nobody"})
	require.Equal(t, RPCErrorUnauthorized, got.Error.Code)
}

func TestAnRPCErrorSaysItsCodeAndMessage(t *testing.T) {
	err := &RPCError{Code: RPCErrorKeyNotFound, Message: "no such key"}
	require.Equal(t, "RPC error -32005: no such key", err.Error())
}

// -----------------------------------------------------------------------------
// The registry, over the wire
// -----------------------------------------------------------------------------

// One projection in one place: every RPC that returns a key returns the same
// shape, so a field cannot mean one thing under mpc_getKey and another
// elsewhere.
func TestACustodyKeyReadsBackIdenticallyThroughEveryDoor(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 80)
	key.register(t, vm)
	client, _ := serve(t, vm)

	one, err := client.GetKey(ctx(), "vault")
	require.NoError(t, err)
	require.Equal(t, "vault", one.KeyID)
	require.Equal(t, KindCGGMP21, one.Kind)
	require.Equal(t, "3-of-5", one.Policy)
	require.Equal(t, 2, one.Degree, "the degree is reported so it can be checked against the policy, not inferred")
	require.Equal(t, "0x"+hex.EncodeToString(key.rec.GroupPublicKey), one.GroupPublicKey)
	require.Equal(t, "0x"+hex.EncodeToString(key.rec.Address), one.Address)
	require.Len(t, one.Participants, 5)

	all, err := client.ListKeys(ctx())
	require.NoError(t, err)
	require.Len(t, all, 1)
	require.Equal(t, *one, all[0])

	pub, err := client.GetPublicKey(ctx(), "vault")
	require.NoError(t, err)
	require.Equal(t, key.rec.GroupPublicKey, pub)

	addr, err := client.GetAddress(ctx(), "vault")
	require.NoError(t, err)
	require.Equal(t, key.rec.Address, addr)
}

// A produced signature is readable back out of replicated state, split into the
// parts a verifier wants.
func TestARecordedCeremonyReadsBackAsItsParts(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 81)
	key.register(t, vm)

	op := key.signOpOver(t, digestOf(1))
	blk := blockOver(t, vm, op)
	require.NoError(t, blk.Verify(ctx()))
	require.NoError(t, blk.Accept(ctx()))

	client, _ := serve(t, vm)
	got, err := client.GetCeremony(ctx(), op.CeremonyID)
	require.NoError(t, err)
	require.Equal(t, OpTypeSign, got.Kind)
	require.Equal(t, "vault", got.KeyID)
	require.Equal(t, "0x"+hex.EncodeToString(op.Digest), got.Digest)
	require.Equal(t, "0x"+hex.EncodeToString(op.Artifact), got.Signature)
	require.Equal(t, "0x"+hex.EncodeToString(op.Artifact[0:32]), got.R)
	require.Equal(t, "0x"+hex.EncodeToString(op.Artifact[32:64]), got.S)
	require.Equal(t, int(op.Artifact[64]), got.V)
	require.Equal(t, blk.BlockHeight, got.Height)
	require.Len(t, got.Signers, 3)

	all, err := client.ListCeremonies(ctx())
	require.NoError(t, err)
	require.Len(t, all, 2, "the keygen and the signature are both in the log")

	root, err := client.StateRoot(ctx())
	require.NoError(t, err)
	require.Equal(t, "0x"+hex.EncodeToString(mustRoot(vm)), root)
}

// An artifact that is not the 65-byte encoding is reported whole rather than
// sliced into parts that would be wrong.
func TestAnArtifactThatIsNotSixtyFiveBytesIsNotSplit(t *testing.T) {
	info := ceremonyInfoOf(&CeremonyRecord{ID: "mpc/x", Artifact: []byte{1, 2, 3}})
	require.Equal(t, "0x010203", info.Signature)
	require.Empty(t, info.R)
	require.Empty(t, info.S)
	require.Zero(t, info.V)
}

// -----------------------------------------------------------------------------
// Node information
// -----------------------------------------------------------------------------

// What the chain agrees on and what is true of THIS node are reported
// separately, because conflating them is how an operator concludes the chain is
// broken when in fact this one validator holds no share.
func TestNodeFactsAndChainFactsAreReportedSeparately(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 82)
	key.register(t, vm)
	vm.stage(key.signOpOver(t, digestOf(1)))
	client, _ := serve(t, vm)

	info, err := client.GetInfo(ctx())
	require.NoError(t, err)
	require.Equal(t, Version.String(), info.Version)
	require.Equal(t, vm.rt.NodeID.String(), info.NodeID)
	require.Equal(t, vm.rt.ChainID.String(), info.ChainID)
	require.Equal(t, string(vm.partyID), info.PartyID)
	require.Equal(t, "3-of-5", info.Policy)
	require.Equal(t, 1, info.TotalKeys, "chain fact")
	require.Equal(t, 0, info.SharesHeld, "node fact: this validator holds none")
	require.Equal(t, 1, info.StagedCeremonies, "node fact")
	require.Equal(t, "0x"+hex.EncodeToString(mustRoot(vm)), info.StateRoot)
	require.NotEmpty(t, info.AuthorizedChains)
}

// Every counter is incremented where the thing happens. A counter that is only
// reported and never written is a number that reads as evidence and is not.
func TestTheCountersReportWhatThisNodeDid(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 83)
	key.register(t, vm)
	vm.stage(key.signOpOver(t, digestOf(1)))
	client, _ := serve(t, vm)

	stats, err := client.GetStats(ctx())
	require.NoError(t, err)
	require.Zero(t, stats.TotalSignatures, "this node ran no ceremony")
	require.Zero(t, stats.TotalKeygens)
	require.Equal(t, 1, stats.StagedCeremonies)
	require.NotNil(t, stats.SignaturesByChain)

	// The counters move when a ceremony completes, not when a block lands.
	vm.stats.mu.Lock()
	vm.stats.TotalSignatures = 3
	vm.stats.TotalKeygens = 1
	vm.stats.SignaturesByChain["B-Chain"] = 3
	vm.stats.mu.Unlock()

	stats, err = client.GetStats(ctx())
	require.NoError(t, err)
	require.Equal(t, uint64(3), stats.TotalSignatures)
	require.Equal(t, uint64(1), stats.TotalKeygens)
	require.Equal(t, uint64(3), stats.SignaturesByChain["B-Chain"])
}

// The committee IS the validator set; there is no separate MPC party roster to
// drift from it.
func TestThePartyListIsTheValidatorSet(t *testing.T) {
	node := ids.GenerateTestNodeID()
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), oneValidator(node), nil)
	defer vm.Shutdown(ctx())
	_, srv := serve(t, vm)

	got := call(t, srv, "threshold_getParties", nil)
	require.Nil(t, got.Error)

	var parties []PartyInfo
	remarshal(t, got.Result, &parties)
	require.Len(t, parties, 1)
	require.Equal(t, node.String(), parties[0].PartyID)
	require.Equal(t, parties[0].PartyID, parties[0].NodeID,
		"a party id IS a node id; reporting both saves a caller a side table, it does not create one")
	require.False(t, parties[0].IsLocal, "this node is not the one validator")
}

func TestANodeWithNoValidatorStateHasNoCommitteeToReport(t *testing.T) {
	vm := newVM(t)
	_, srv := serve(t, vm)
	got := call(t, srv, "threshold_getParties", nil)
	require.NotNil(t, got.Error)
	require.Equal(t, RPCErrorInternal, got.Error.Code)
}

// -----------------------------------------------------------------------------
// Quota and permissions
// -----------------------------------------------------------------------------

func TestQuotaIsReportedAgainstWhicheverLimitApplies(t *testing.T) {
	bridge := ids.GenerateTestID()
	cfg := fmt.Sprintf(`{"policy":"3-of-5","authorizedChains":{
		"B-Chain":{"chainId":%q,"canSign":true,"dailySigningLimit":10}}}`, bridge)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, nil, cfg)
	defer vm.Shutdown(ctx())

	vm.mu.Lock()
	vm.dailySigningCount["B-Chain"] = 4
	vm.mu.Unlock()

	client, _ := serve(t, vm)
	q, err := client.GetQuota(ctx())
	require.NoError(t, err)
	require.Equal(t, "B-Chain", q.ChainID)
	require.Equal(t, uint64(10), q.DailyLimit)
	require.Equal(t, uint64(4), q.UsedToday)
	require.Equal(t, uint64(6), q.Remaining)
	require.NotZero(t, q.ResetTime)

	// Past the limit, remaining is zero rather than negative-wrapped.
	vm.mu.Lock()
	vm.dailySigningCount["B-Chain"] = 99
	vm.mu.Unlock()
	q, err = client.GetQuota(ctx())
	require.NoError(t, err)
	require.Zero(t, q.Remaining)
}

func TestPermissionsAreReadableForABoundChain(t *testing.T) {
	bridge := ids.GenerateTestID()
	cfg := fmt.Sprintf(`{"policy":"3-of-5","authorizedChains":{
		"B-Chain":{"chainId":%q,"chainName":"Bridge Chain","canSign":true,"canKeygen":true,"maxSigningSize":1024}}}`, bridge)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, nil, cfg)
	defer vm.Shutdown(ctx())
	_, srv := serve(t, vm)

	got := call(t, srv, "threshold_getChainPermissions", map[string]string{"chainId": "B-Chain"})
	require.Nil(t, got.Error)
	var perms ChainPermissions
	remarshal(t, got.Result, &perms)
	require.Equal(t, bridge.String(), perms.ChainID)
	require.True(t, perms.CanSign)
	require.Equal(t, 1024, perms.MaxSigningSize)

	got = call(t, srv, "threshold_getAuthorizedChains", nil)
	require.Nil(t, got.Error)
	var names []string
	remarshal(t, got.Result, &names)
	require.Equal(t, []string{"B-Chain"}, names)
}

// -----------------------------------------------------------------------------
// Health
// -----------------------------------------------------------------------------

func TestHealthOverRPCIsTheHealthTheEngineIsTold(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 84)
	key.register(t, vm)
	client, _ := serve(t, vm)

	got, err := client.Health(ctx())
	require.NoError(t, err)
	require.Equal(t, true, got["healthy"])
	require.Equal(t, "1", got["custodyKeys"])

	engine, err := vm.HealthCheck(ctx())
	require.NoError(t, err)
	require.Equal(t, engine.Details["stateRoot"], got["stateRoot"])
}

func TestAnUnhealthyNodeSaysSoOverRPC(t *testing.T) {
	vm := newVM(t)
	vm.state.db = &faultyIterDB{Database: vm.state.db}
	_, srv := serve(t, vm)

	got := call(t, srv, "threshold_health", nil)
	require.NotNil(t, got.Error)
	require.Equal(t, RPCErrorInternal, got.Error.Code)
}

// -----------------------------------------------------------------------------
// The client's own failure modes
// -----------------------------------------------------------------------------

func TestAClientReportsWhatWentWrongRatherThanAZeroValue(t *testing.T) {
	unreachable := NewClient("http://127.0.0.1:1", "B-Chain")
	_, err := unreachable.GetInfo(ctx())
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to send request")

	// A server that answers with something that is not a JSON-RPC envelope.
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer junk.Close()
	_, err = NewClient(junk.URL, "B-Chain").GetInfo(ctx())
	require.ErrorContains(t, err, "failed to unmarshal response")

	// A well-formed envelope whose result is not the shape the caller expects.
	wrong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"a string"}`))
	}))
	defer wrong.Close()
	_, err = NewClient(wrong.URL, "B-Chain").GetInfo(ctx())
	require.ErrorContains(t, err, "failed to unmarshal result")

	// A request that cannot be built at all.
	bad := NewClient("://not a url", "B-Chain")
	_, err = bad.GetInfo(ctx())
	require.ErrorContains(t, err, "failed to create request")
}

func TestAClientSurfacesTheServersErrorCode(t *testing.T) {
	vm := newVM(t)
	client, _ := serve(t, vm)
	_, err := client.GetKey(ctx(), "nothing")
	require.ErrorContains(t, err, fmt.Sprintf("RPC error %d", RPCErrorKeyNotFound))
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func mustRoot(vm *VM) []byte {
	root := vm.StateRoot()
	return root[:]
}

// remarshal moves a decoded interface{} result into a typed value, which is
// what a caller that used the typed client would have got directly.
func remarshal(t *testing.T, from any, into any) {
	t.Helper()
	raw, err := json.Marshal(from)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, into))
}

// A global override outranks the chain's own limit, and the quota report says
// so — an operator throttling one chain must see the number that is in force.
func TestTheQuotaReportedIsTheOneInForce(t *testing.T) {
	bridge := ids.GenerateTestID()
	cfg := fmt.Sprintf(`{"policy":"3-of-5","dailySigningQuota":{"B-Chain":3},
		"authorizedChains":{"B-Chain":{"chainId":%q,"canSign":true,"dailySigningLimit":1000}}}`, bridge)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, nil, cfg)
	defer vm.Shutdown(ctx())

	client, _ := serve(t, vm)
	q, err := client.GetQuota(ctx())
	require.NoError(t, err)
	require.Equal(t, uint64(3), q.DailyLimit, "the override is the limit, not the entry's own")
	require.Equal(t, uint64(3), q.Remaining)
}
