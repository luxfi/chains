// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newRPCRig stands up a VM with quote + swap store wired and serves
// the JSON-RPC handler over httptest.
func newRPCRig(t *testing.T) (*httptest.Server, *VM) {
	t.Helper()
	vm := &VM{
		quoteEngine: &QuoteEngine{Feed: defaultPriceFeed()},
		swapStore:   newInMemorySwapStore(),
	}
	handlers, err := vm.CreateRPCHandlers()
	if err != nil {
		t.Fatalf("CreateRPCHandlers: %v", err)
	}
	mux := http.NewServeMux()
	for path, h := range handlers {
		mux.Handle(path, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, vm
}

// callRPC invokes one method against the rig and unmarshals the
// result into out.
func callRPC(t *testing.T, url, method string, params any, out any) (rpcCode int, rpcMessage string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  method,
		"params":  params,
	})
	resp, err := http.Post(url+"/rpc", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error != nil {
		return env.Error.Code, env.Error.Message
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
	}
	return 0, ""
}

func TestRPC_EstimateFee(t *testing.T) {
	srv, _ := newRPCRig(t)

	var reply EstimateFeeReply
	code, msg := callRPC(t, srv.URL, "bridge_estimateFee", EstimateFeeArgs{
		SourceChain: "ETHEREUM_SEPOLIA",
		DestChain:   "LUX_TESTNET",
		SourceAsset: "ETH",
		DestAsset:   "LUX",
		Amount:      "1",
	}, &reply)
	if code != 0 {
		t.Fatalf("rpc error: %d %s", code, msg)
	}
	if reply.NetAmount != "1400" {
		t.Errorf("NetAmount = %q, want 1400 (1 ETH @ $3500 / $2.50)", reply.NetAmount)
	}
	if reply.FeeAmount != "0" {
		t.Errorf("FeeAmount = %q, want 0 for non-Lux source", reply.FeeAmount)
	}
}

func TestRPC_EstimateFee_LuxExit(t *testing.T) {
	srv, _ := newRPCRig(t)

	var reply EstimateFeeReply
	code, msg := callRPC(t, srv.URL, "bridge_estimateFee", EstimateFeeArgs{
		SourceChain: "LUX_TESTNET",
		DestChain:   "ETHEREUM_SEPOLIA",
		SourceAsset: "LUX",
		DestAsset:   "ETH",
		Amount:      "1000",
	}, &reply)
	if code != 0 {
		t.Fatalf("rpc error: %d %s", code, msg)
	}
	if reply.FeeAmount == "" || reply.FeeAmount == "0" {
		t.Errorf("Lux-exit FeeAmount = %q, want > 0", reply.FeeAmount)
	}
}

func TestRPC_EstimateFee_UnknownAsset(t *testing.T) {
	srv, _ := newRPCRig(t)
	var reply EstimateFeeReply
	code, msg := callRPC(t, srv.URL, "bridge_estimateFee", EstimateFeeArgs{
		SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
		SourceAsset: "UNOBTAINIUM", DestAsset: "LUX", Amount: "1",
	}, &reply)
	if code == 0 {
		t.Fatalf("expected error, got success")
	}
	if !strings.Contains(msg, "price unknown") && !strings.Contains(msg, "UNOBTAINIUM") {
		t.Errorf("expected price-unknown error, got %q", msg)
	}
}

func TestRPC_SubmitRequest_ThenGetStatus(t *testing.T) {
	srv, _ := newRPCRig(t)

	var sub SubmitRequestReply
	code, msg := callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
		SourceChain: "ETHEREUM_SEPOLIA",
		DestChain:   "LUX_TESTNET",
		SourceAsset: "ETH",
		DestAsset:   "LUX",
		Amount:      "1",
		Recipient:   "0xa28fAE14eB42e7A5C36Ad2D774a2b7Eb293c4473",
		Sender:      "0xa28fAE14eB42e7A5C36Ad2D774a2b7Eb293c4473",
	}, &sub)
	if code != 0 {
		t.Fatalf("submit rpc error: %d %s", code, msg)
	}
	if !strings.HasPrefix(sub.RequestID, "req_") {
		t.Errorf("RequestID = %q, want req_ prefix", sub.RequestID)
	}
	if sub.Status != StatusPending {
		t.Errorf("Status = %q, want pending", sub.Status)
	}
	if sub.NetAmount != "1400" {
		t.Errorf("NetAmount snapshot = %q, want 1400", sub.NetAmount)
	}

	var get GetStatusReply
	code, msg = callRPC(t, srv.URL, "bridge_getStatus", GetStatusArgs{RequestID: sub.RequestID}, &get)
	if code != 0 {
		t.Fatalf("getStatus rpc error: %d %s", code, msg)
	}
	if get.RequestID != sub.RequestID {
		t.Errorf("getStatus returned id=%q want %q", get.RequestID, sub.RequestID)
	}
}

func TestRPC_GetStatus_NotFound(t *testing.T) {
	srv, _ := newRPCRig(t)
	var get GetStatusReply
	code, msg := callRPC(t, srv.URL, "bridge_getStatus", GetStatusArgs{RequestID: "req_nope"}, &get)
	if code == 0 {
		t.Fatalf("expected error, got success")
	}
	if !strings.Contains(msg, "not found") {
		t.Errorf("error = %q, want 'not found'", msg)
	}
}

func TestRPC_CancelRequest(t *testing.T) {
	srv, _ := newRPCRig(t)
	// Submit then cancel.
	var sub SubmitRequestReply
	_, _ = callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
		SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
		SourceAsset: "ETH", DestAsset: "LUX", Amount: "1",
		Recipient: "0xabc", Sender: "0xabc",
	}, &sub)

	var cancel CancelRequestReply
	code, msg := callRPC(t, srv.URL, "bridge_cancelRequest", CancelRequestArgs{RequestID: sub.RequestID}, &cancel)
	if code != 0 {
		t.Fatalf("cancel rpc error: %d %s", code, msg)
	}
	if !cancel.Success {
		t.Errorf("cancel.Success = false, want true")
	}

	// Confirm idempotent: second cancel still returns success.
	code, msg = callRPC(t, srv.URL, "bridge_cancelRequest", CancelRequestArgs{RequestID: sub.RequestID}, &cancel)
	if code != 0 || !cancel.Success {
		t.Errorf("idempotent cancel failed: code=%d msg=%q success=%v", code, msg, cancel.Success)
	}
}

func TestRPC_Health(t *testing.T) {
	srv, _ := newRPCRig(t)
	var reply HealthReply
	code, msg := callRPC(t, srv.URL, "bridge_health", nil, &reply)
	if code != 0 {
		t.Fatalf("health rpc error: %d %s", code, msg)
	}
	if reply.Status != "healthy" {
		t.Errorf("Status = %q, want healthy", reply.Status)
	}
}

// =============================================================================
// Discovery RPC tests
// =============================================================================

// configureVMForDiscovery sets minimal config + registry state on the
// rig's VM so the discovery methods have non-empty data to surface.
// Centralized so test cases stay focused on the assertion, not setup.
func configureVMForDiscovery(vm *VM) {
	vm.config.MPCThreshold = 67
	vm.config.MPCTotalParties = 100
	vm.config.MinConfirmations = 6
	vm.config.SupportedChains = []string{"ETHEREUM_SEPOLIA", "LUX_TESTNET", "BTC_TESTNET"}
}

func TestRPC_GetInfo(t *testing.T) {
	srv, vm := newRPCRig(t)
	configureVMForDiscovery(vm)

	var reply GetBridgeInfoReply
	code, msg := callRPC(t, srv.URL, "bridge_getInfo", nil, &reply)
	if code != 0 {
		t.Fatalf("rpc error: %d %s", code, msg)
	}
	if reply.Version == "" {
		t.Error("Version should be non-empty")
	}
	if reply.ChainID != "B" {
		t.Errorf("ChainID = %q, want B", reply.ChainID)
	}
	if reply.Threshold != 67 {
		t.Errorf("Threshold = %d, want 67", reply.Threshold)
	}
	if reply.TotalParties != 100 {
		t.Errorf("TotalParties = %d, want 100", reply.TotalParties)
	}
	if len(reply.SupportedChains) != 3 {
		t.Errorf("SupportedChains len = %d, want 3", len(reply.SupportedChains))
	}
	// MPCReady is false because mpcKeyManager is nil in the rig — that
	// is the correct state ("MPC pending"), not an error.
	if reply.MPCReady {
		t.Error("MPCReady should be false without mpcKeyManager")
	}
	if reply.TotalBridged != "0" {
		t.Errorf("TotalBridged = %q, want 0", reply.TotalBridged)
	}
	if reply.TotalFees != "0" {
		t.Errorf("TotalFees = %q, want 0", reply.TotalFees)
	}
}

func TestRPC_GetSupportedChains(t *testing.T) {
	srv, vm := newRPCRig(t)
	configureVMForDiscovery(vm)

	var reply GetSupportedChainsReply
	code, msg := callRPC(t, srv.URL, "bridge_getSupportedChains", nil, &reply)
	if code != 0 {
		t.Fatalf("rpc error: %d %s", code, msg)
	}
	if len(reply.Chains) != 3 {
		t.Fatalf("Chains len = %d, want 3", len(reply.Chains))
	}
	for _, c := range reply.Chains {
		if c.ChainID == "" {
			t.Error("ChainID empty in result")
		}
		if !c.Enabled {
			t.Errorf("chain %s not Enabled, want true", c.ChainID)
		}
		if c.Confirmations != 6 {
			t.Errorf("chain %s Confirmations = %d, want 6", c.ChainID, c.Confirmations)
		}
	}
}

func TestRPC_GetChainConfig(t *testing.T) {
	srv, vm := newRPCRig(t)
	configureVMForDiscovery(vm)

	// happy path: lowercase input matches case-insensitively
	var reply GetChainConfigReply
	code, msg := callRPC(t, srv.URL, "bridge_getChainConfig",
		GetChainConfigArgs{ChainID: "ethereum_sepolia"}, &reply)
	if code != 0 {
		t.Fatalf("rpc error: %d %s", code, msg)
	}
	if !strings.EqualFold(reply.ChainID, "ETHEREUM_SEPOLIA") {
		t.Errorf("ChainID = %q, want ETHEREUM_SEPOLIA (case-insensitive match)", reply.ChainID)
	}
	if !reply.Enabled {
		t.Error("Enabled = false, want true")
	}

	// unknown chain: error surfaces the requested id so daemons can log it
	code, msg = callRPC(t, srv.URL, "bridge_getChainConfig",
		GetChainConfigArgs{ChainID: "UNOBTAINIUM_CHAIN"}, &reply)
	if code == 0 {
		t.Fatal("expected error for unknown chain, got success")
	}
	if !strings.Contains(msg, "UNOBTAINIUM_CHAIN") {
		t.Errorf("error %q should name the missing chain", msg)
	}

	// empty chainId: explicit invalid-params surface
	code, msg = callRPC(t, srv.URL, "bridge_getChainConfig",
		GetChainConfigArgs{ChainID: ""}, &reply)
	if code == 0 {
		t.Fatal("expected error for empty chainId")
	}
	if !strings.Contains(msg, "chainId required") {
		t.Errorf("error %q should say chainId required", msg)
	}
}

func TestRPC_GetSignature_NotYetAvailable(t *testing.T) {
	srv, _ := newRPCRig(t)

	// Submit a swap so it exists in the store, but with no signature.
	var sub SubmitRequestReply
	_, _ = callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
		SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
		SourceAsset: "ETH", DestAsset: "LUX", Amount: "1",
		Recipient: "0xabc", Sender: "0xabc",
	}, &sub)

	var reply GetSignatureReply
	code, msg := callRPC(t, srv.URL, "bridge_getSignature",
		GetSignatureArgs{RequestID: sub.RequestID}, &reply)
	if code == 0 {
		t.Fatal("expected error (signature not yet available), got success")
	}
	if !strings.Contains(msg, "not yet available") {
		t.Errorf("error %q should say 'not yet available'", msg)
	}
}

func TestRPC_GetSignature_AfterSign(t *testing.T) {
	srv, vm := newRPCRig(t)

	// Submit
	var sub SubmitRequestReply
	_, _ = callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
		SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
		SourceAsset: "ETH", DestAsset: "LUX", Amount: "1",
		Recipient: "0xabc", Sender: "0xabc",
	}, &sub)

	// Simulate the MPC quorum populating the signature via Patch.
	const sig = "deadbeefcafe1234"
	if _, err := vm.swapStore.Patch(sub.RequestID, func(r *BridgeRequestRecord) {
		r.Signature = sig
		r.Status = StatusSigned
	}); err != nil {
		t.Fatalf("Patch: %v", err)
	}

	var reply GetSignatureReply
	code, msg := callRPC(t, srv.URL, "bridge_getSignature",
		GetSignatureArgs{RequestID: sub.RequestID}, &reply)
	if code != 0 {
		t.Fatalf("rpc error: %d %s", code, msg)
	}
	if reply.Signature != sig {
		t.Errorf("Signature = %q, want %q", reply.Signature, sig)
	}
	if reply.SessionID != sub.RequestID {
		t.Errorf("SessionID = %q, want %q", reply.SessionID, sub.RequestID)
	}
}

func TestRPC_GetSignature_NotFound(t *testing.T) {
	srv, _ := newRPCRig(t)
	var reply GetSignatureReply
	code, msg := callRPC(t, srv.URL, "bridge_getSignature",
		GetSignatureArgs{RequestID: "req_does_not_exist"}, &reply)
	if code == 0 {
		t.Fatal("expected error for missing swap")
	}
	if !strings.Contains(msg, "not found") {
		t.Errorf("error %q should say 'not found'", msg)
	}
}
