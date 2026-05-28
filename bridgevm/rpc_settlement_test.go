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
