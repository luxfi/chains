// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// newRPCRig serves the JSON-RPC handler over httptest, against a VM brought up
// the way the node brings one up. A rig that hand-assembles a VM answers for a
// state no node is ever in.
func newRPCRig(t *testing.T) (*httptest.Server, *VM) {
	t.Helper()
	vm := boot(t)
	handlers, err := vm.CreateRPCHandlers()
	require.NoError(t, err)
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
	return postRPC(t, url, body, out)
}

func postRPC(t *testing.T, url string, body []byte, out any) (int, string) {
	t.Helper()
	resp, err := http.Post(url+"/rpc", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
	if env.Error != nil {
		return env.Error.Code, env.Error.Message
	}
	if out != nil && len(env.Result) > 0 {
		require.NoError(t, json.Unmarshal(env.Result, out))
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
	require.Zero(t, code, msg)
	require.NotEmpty(t, reply.FeeAmount)
	require.NotEmpty(t, reply.NetAmount)
	require.Positive(t, reply.EstimatedTime)
}

func TestRPC_EstimateFee_LuxExit(t *testing.T) {
	srv, _ := newRPCRig(t)

	var reply EstimateFeeReply
	code, msg := callRPC(t, srv.URL, "bridge_estimateFee", EstimateFeeArgs{
		SourceChain: "LUX_TESTNET",
		DestChain:   "ETHEREUM_SEPOLIA",
		SourceAsset: "LUX",
		DestAsset:   "ETH",
		Amount:      "100",
	}, &reply)
	require.Zero(t, code, msg)
	require.NotEqual(t, "0", reply.FeeAmount, "a Lux exit charges a service fee")
}

func TestRPC_EstimateFee_UnknownAsset(t *testing.T) {
	srv, _ := newRPCRig(t)
	var reply EstimateFeeReply
	code, _ := callRPC(t, srv.URL, "bridge_estimateFee", EstimateFeeArgs{
		SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
		SourceAsset: "NOSUCHASSET", DestAsset: "LUX", Amount: "1",
	}, &reply)
	require.NotZero(t, code, "an unknown asset must not quote")
}

func TestRPC_EstimateFee_BadAmount(t *testing.T) {
	srv, _ := newRPCRig(t)
	var reply EstimateFeeReply
	for _, amount := range []string{"", "-1", "0", "not-a-number"} {
		code, _ := callRPC(t, srv.URL, "bridge_estimateFee", EstimateFeeArgs{
			SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
			SourceAsset: "ETH", DestAsset: "LUX", Amount: amount,
		}, &reply)
		require.NotZero(t, code, "amount %q must be refused", amount)
	}
}

func TestRPC_SubmitRequest_ThenGetStatus(t *testing.T) {
	srv, _ := newRPCRig(t)

	var sub SubmitRequestReply
	code, msg := callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
		SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
		SourceAsset: "ETH", DestAsset: "LUX", Amount: "2",
		Recipient: "0xrecipient", Sender: "0xsender",
	}, &sub)
	require.Zero(t, code, msg)
	require.NotEmpty(t, sub.RequestID)
	require.Equal(t, StatusPending, sub.Status)

	var status GetStatusReply
	code, msg = callRPC(t, srv.URL, "bridge_getStatus", GetStatusArgs{RequestID: sub.RequestID}, &status)
	require.Zero(t, code, msg)
	require.Equal(t, sub.RequestID, status.RequestID)
	require.Equal(t, sub.FeeAmount, status.FeeAmount)
}

func TestRPC_SubmitRequest_MissingFields(t *testing.T) {
	srv, _ := newRPCRig(t)
	var sub SubmitRequestReply
	code, _ := callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
		DestChain: "LUX_TESTNET", Amount: "1", Recipient: "0xabc",
	}, &sub)
	require.NotZero(t, code, "a request naming no source chain must be refused")
}

func TestRPC_GetStatus_NotFound(t *testing.T) {
	srv, _ := newRPCRig(t)
	var reply GetStatusReply
	code, msg := callRPC(t, srv.URL, "bridge_getStatus", GetStatusArgs{RequestID: "req_nope"}, &reply)
	require.NotZero(t, code)
	require.Contains(t, msg, "not found")
}

func TestRPC_CancelRequest(t *testing.T) {
	srv, _ := newRPCRig(t)

	var sub SubmitRequestReply
	_, _ = callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
		SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
		SourceAsset: "ETH", DestAsset: "LUX", Amount: "1",
		Recipient: "0xabc", Sender: "0xabc",
	}, &sub)

	var cancel CancelRequestReply
	code, msg := callRPC(t, srv.URL, "bridge_cancelRequest", CancelRequestArgs{RequestID: sub.RequestID}, &cancel)
	require.Zero(t, code, msg)
	require.True(t, cancel.Success)

	// Cancelling a terminal swap again is a no-op success, so retries are safe.
	code, msg = callRPC(t, srv.URL, "bridge_cancelRequest", CancelRequestArgs{RequestID: sub.RequestID}, &cancel)
	require.Zero(t, code, msg)
	require.True(t, cancel.Success)

	code, _ = callRPC(t, srv.URL, "bridge_cancelRequest", CancelRequestArgs{RequestID: "req_nope"}, &cancel)
	require.NotZero(t, code)
}

func TestRPC_Health(t *testing.T) {
	srv, _ := newRPCRig(t)
	var reply HealthReply
	code, msg := callRPC(t, srv.URL, "bridge_health", nil, &reply)
	require.Zero(t, code, msg)
	require.Equal(t, "healthy", reply.Status)
	require.False(t, reply.MPCReady, "no custody group key until M-Chain keygen lands")
}

// =============================================================================
// Discovery RPC
// =============================================================================

func TestRPC_GetInfo(t *testing.T) {
	srv, vm := newRPCRig(t)

	var reply GetBridgeInfoReply
	code, msg := callRPC(t, srv.URL, "bridge_getInfo", nil, &reply)
	require.Zero(t, code, msg)
	require.NotEmpty(t, reply.Version)
	require.Equal(t, "B", reply.ChainID)
	require.Len(t, reply.SupportedChains, 2)
	// MPCReady is false because mpcConfig is nil in the rig (M-Chain keygen
	// not completed) — the correct "MPC pending" state, not an error.
	require.False(t, reply.MPCReady)
	require.Equal(t, "0", reply.TotalBridged)
	require.Equal(t, "0", reply.TotalFees)
	require.Zero(t, reply.Height)

	// The threshold reported here is the signer set's, not a configured number
	// beside it: one question, one answer.
	require.NoError(t, registerSigner(vm, ids.GenerateTestNodeID()))
	require.NoError(t, registerSigner(vm, ids.GenerateTestNodeID()))
	require.NoError(t, registerSigner(vm, ids.GenerateTestNodeID()))
	require.NoError(t, registerSigner(vm, ids.GenerateTestNodeID()))
	code, msg = callRPC(t, srv.URL, "bridge_getInfo", nil, &reply)
	require.Zero(t, code, msg)
	require.Equal(t, 4, reply.TotalParties)
	require.Equal(t, vm.GetSignerSetInfo().Threshold, reply.Threshold)
}

// TestRPC_GetInfoReportsWhatMoved reads the same durable counter the daily cap
// is enforced against, so the number a dashboard shows is the number the chain
// acts on.
func TestRPC_GetInfoReportsWhatMoved(t *testing.T) {
	srv, vm := newRPCRig(t)
	pend(vm, requestFor(1, 4_242))
	blk := buildAndAccept(t, vm)

	var reply GetBridgeInfoReply
	code, msg := callRPC(t, srv.URL, "bridge_getInfo", nil, &reply)
	require.Zero(t, code, msg)
	require.Equal(t, "4242", reply.TotalBridged)
	require.Equal(t, uint64(1), reply.Height)
	require.Equal(t, blk.BlockHeight, reply.Height)
}

func TestRPC_GetSupportedChains(t *testing.T) {
	srv, vm := newRPCRig(t)

	var reply GetSupportedChainsReply
	code, msg := callRPC(t, srv.URL, "bridge_getSupportedChains", nil, &reply)
	require.Zero(t, code, msg)
	require.Len(t, reply.Chains, len(vm.config.ExternalChains))
	for i, c := range reply.Chains {
		require.Equal(t, strconv.FormatUint(vm.config.ExternalChains[i].ChainID, 10), c.ChainID)
		require.Equal(t, vm.config.ExternalChains[i].Name, c.ChainName)
		require.True(t, c.Enabled)
		require.Equal(t, int(vm.config.MinConfirmations), c.Confirmations)
	}
}

// The chains this bridge says it serves are the chains it can actually route
// to. A separate list declared beside the routing table could name a chain
// with no client behind it.
func TestRPC_SupportedChainsAreTheRoutableOnes(t *testing.T) {
	srv, vm := newRPCRig(t)
	var reply GetSupportedChainsReply
	code, msg := callRPC(t, srv.URL, "bridge_getSupportedChains", nil, &reply)
	require.Zero(t, code, msg)

	for _, c := range reply.Chains {
		id, err := strconv.ParseUint(c.ChainID, 10, 32)
		require.NoError(t, err)
		found := false
		for _, cfg := range vm.config.ExternalChains {
			found = found || cfg.ChainID == id
		}
		require.True(t, found, "chain %s is advertised but not one the release path routes by", c.ChainID)
	}
}

func TestRPC_GetChainConfig(t *testing.T) {
	srv, _ := newRPCRig(t)

	// By name, case-insensitively.
	var reply GetChainConfigReply
	code, msg := callRPC(t, srv.URL, "bridge_getChainConfig",
		GetChainConfigArgs{ChainID: "ZOO-TESTNET"}, &reply)
	require.Zero(t, code, msg)
	require.Equal(t, "zoo-testnet", reply.ChainName)
	require.True(t, reply.Enabled)

	// And by the numeric id the transfers actually carry.
	code, msg = callRPC(t, srv.URL, "bridge_getChainConfig",
		GetChainConfigArgs{ChainID: strconv.FormatUint(uint64(dstChain), 10)}, &reply)
	require.Zero(t, code, msg)
	require.Equal(t, "zoo-testnet", reply.ChainName)

	// Unknown chain: the error names the requested id so daemons can log it.
	code, msg = callRPC(t, srv.URL, "bridge_getChainConfig",
		GetChainConfigArgs{ChainID: "UNOBTAINIUM_CHAIN"}, &reply)
	require.NotZero(t, code)
	require.Contains(t, msg, "UNOBTAINIUM_CHAIN")

	code, msg = callRPC(t, srv.URL, "bridge_getChainConfig",
		GetChainConfigArgs{ChainID: ""}, &reply)
	require.NotZero(t, code)
	require.Contains(t, msg, "chainId required")
}

// The KMS path a relayer key lives at is not something an unauthenticated
// surface answers with.
func TestRPC_ChainConfigNamesNoSecretLocation(t *testing.T) {
	srv, vm := newRPCRig(t)
	vm.config.ExternalChains[0].GasKeyKMSPath = "kms://bridge/relayer/lux"

	resp, err := http.Post(srv.URL+"/rpc", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"bridge_getSupportedChains"}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	require.NoError(t, err)
	require.NotContains(t, buf.String(), "kms://")
}

func TestRPC_GetSignature(t *testing.T) {
	srv, vm := newRPCRig(t)

	var sub SubmitRequestReply
	_, _ = callRPC(t, srv.URL, "bridge_submitRequest", SubmitRequestArgs{
		SourceChain: "ETHEREUM_SEPOLIA", DestChain: "LUX_TESTNET",
		SourceAsset: "ETH", DestAsset: "LUX", Amount: "1",
		Recipient: "0xabc", Sender: "0xabc",
	}, &sub)

	// Still signing: a caller can poll without confusing this with "no such
	// swap".
	var reply GetSignatureReply
	code, msg := callRPC(t, srv.URL, "bridge_getSignature", GetSignatureArgs{RequestID: sub.RequestID}, &reply)
	require.NotZero(t, code)
	require.Contains(t, msg, "not yet available")

	const sig = "deadbeefcafe1234"
	_, err := vm.swapStore.Patch(sub.RequestID, func(r *BridgeRequestRecord) {
		r.Signature = sig
		r.Status = StatusSigned
	})
	require.NoError(t, err)

	code, msg = callRPC(t, srv.URL, "bridge_getSignature", GetSignatureArgs{RequestID: sub.RequestID}, &reply)
	require.Zero(t, code, msg)
	require.Equal(t, sig, reply.Signature)
	require.Equal(t, sub.RequestID, reply.SessionID)

	code, msg = callRPC(t, srv.URL, "bridge_getSignature", GetSignatureArgs{RequestID: "req_does_not_exist"}, &reply)
	require.NotZero(t, code)
	require.Contains(t, msg, "not found")
}

func TestRPC_GetMPCPublicKey(t *testing.T) {
	srv, _ := newRPCRig(t)
	var reply GetMPCPublicKeyReply
	code, msg := callRPC(t, srv.URL, "bridge_getMPCPublicKey", nil, &reply)
	require.NotZero(t, code, "a chain with no group key must say so rather than answer with nothing")
	require.Contains(t, msg, "not yet established")
}

// =============================================================================
// Signer-set RPC
// =============================================================================

func TestRPC_SignerSetLifecycle(t *testing.T) {
	srv, _ := newRPCRig(t)
	node := ids.GenerateTestNodeID()
	bond := strconv.FormatUint(minValidatorBond, 10)

	var reg RegisterValidatorReply
	code, msg := callRPC(t, srv.URL, "bridge_registerValidator",
		RegisterValidatorArgs{NodeID: node.String(), BondAmount: bond, MPCPubKey: "0xpub"}, &reg)
	require.Zero(t, code, msg)
	require.True(t, reg.Registered)

	var has HasSignerReply
	code, msg = callRPC(t, srv.URL, "bridge_hasSigner", HasSignerArgs{NodeID: node.String()}, &has)
	require.Zero(t, code, msg)
	require.True(t, has.IsSigner)

	var info GetSignerSetInfoReply
	code, msg = callRPC(t, srv.URL, "bridge_getSignerSetInfo", nil, &info)
	require.Zero(t, code, msg)
	require.Equal(t, 1, info.TotalSigners)
	require.Equal(t, node.String(), info.Signers[0].NodeID)
	require.Equal(t, minValidatorBond, info.Signers[0].BondAmount)

	var epoch GetCurrentEpochReply
	code, msg = callRPC(t, srv.URL, "bridge_getCurrentEpoch", nil, &epoch)
	require.Zero(t, code, msg)
	require.Zero(t, epoch.Epoch)
	require.Equal(t, 1, epoch.TotalSigners)

	// A second validator lands on the set, then gets waitlisted once it freezes.
	waiting := ids.GenerateTestNodeID()
	code, msg = callRPC(t, srv.URL, "bridge_registerValidator",
		RegisterValidatorArgs{NodeID: waiting.String(), BondAmount: bond}, &reg)
	require.Zero(t, code, msg)

	var slash SlashSignerReply
	code, msg = callRPC(t, srv.URL, "bridge_slashSigner",
		SlashSignerArgs{NodeID: node.String(), Reason: "equivocation", SlashPercent: 10, Evidence: "0x01"}, &slash)
	require.Zero(t, code, msg)
	require.True(t, slash.Success)
	require.True(t, slash.RemovedFromSet, "a bond below the requirement is not a bond")

	var replace ReplaceSignerReply
	code, msg = callRPC(t, srv.URL, "bridge_replaceSigner",
		ReplaceSignerArgs{NodeID: waiting.String()}, &replace)
	require.Zero(t, code, msg)
	require.True(t, replace.Success)
	require.Equal(t, uint64(2), replace.NewEpoch)

	var wl GetWaitlistReply
	code, msg = callRPC(t, srv.URL, "bridge_getWaitlist", nil, &wl)
	require.Zero(t, code, msg)
	require.Zero(t, wl.WaitlistSize)
}

func TestRPC_SignerMethodsRefuseABadNodeID(t *testing.T) {
	srv, _ := newRPCRig(t)
	for _, method := range []string{"bridge_hasSigner", "bridge_replaceSigner", "bridge_slashSigner", "bridge_registerValidator"} {
		code, _ := callRPC(t, srv.URL, method, map[string]any{"nodeId": "not-a-node-id", "slashPercent": 5}, nil)
		require.NotZero(t, code, "%s accepted a malformed node id", method)
	}
	code, _ := callRPC(t, srv.URL, "bridge_replaceSigner",
		map[string]any{"nodeId": ids.GenerateTestNodeID().String(), "replacementNodeId": "not-a-node-id"}, nil)
	require.NotZero(t, code)
}

// =============================================================================
// The envelope itself
// =============================================================================

func TestRPC_UnknownMethod(t *testing.T) {
	srv, _ := newRPCRig(t)
	code, msg := callRPC(t, srv.URL, "bridge_doWhateverIWant", nil, nil)
	require.Equal(t, -32601, code)
	require.Contains(t, msg, "method not found")
}

func TestRPC_MalformedParamsAndBody(t *testing.T) {
	srv, _ := newRPCRig(t)

	// Every method that takes arguments must refuse arguments it cannot read.
	for _, method := range []string{
		"bridge_registerValidator", "bridge_replaceSigner", "bridge_hasSigner",
		"bridge_slashSigner", "bridge_estimateFee", "bridge_submitRequest",
		"bridge_getStatus", "bridge_cancelRequest", "bridge_getChainConfig",
		"bridge_getSignature",
	} {
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":"not-an-object"}`)
		code, _ := postRPC(t, srv.URL, body, nil)
		require.Equal(t, -32602, code, "%s accepted params it cannot decode", method)
	}

	code, _ := postRPC(t, srv.URL, []byte(`{not json`), nil)
	require.Equal(t, -32700, code)
}

func TestRPC_DottedMethodNamesAreTheSameMethods(t *testing.T) {
	srv, _ := newRPCRig(t)
	for _, method := range []string{
		"bridge.getSignerSetInfo", "bridge.getWaitlist", "bridge.getCurrentEpoch",
		"bridge.health", "bridge.getInfo", "bridge.getSupportedChains",
	} {
		code, msg := callRPC(t, srv.URL, method, nil, nil)
		require.Zero(t, code, "%s: %s", method, msg)
	}
}

func TestRPC_OnlyPostIsAnswered(t *testing.T) {
	srv, _ := newRPCRig(t)
	resp, err := http.Get(srv.URL + "/rpc")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// A Service with no VM behind it answers with an error rather than a panic.
func TestRPC_ServiceWithoutAVM(t *testing.T) {
	s := &Service{}
	require.Error(t, s.EstimateFee(nil, &EstimateFeeArgs{Amount: "1"}, &EstimateFeeReply{}))
	require.Error(t, s.SubmitRequest(nil, &SubmitRequestArgs{}, &SubmitRequestReply{}))
	require.Error(t, s.GetStatus(nil, &GetStatusArgs{}, &GetStatusReply{}))
	require.Error(t, s.CancelRequest(nil, &CancelRequestArgs{}, &CancelRequestReply{}))
	require.Error(t, s.GetBridgeInfo(nil, &GetBridgeInfoArgs{}, &GetBridgeInfoReply{}))
	require.Error(t, s.GetSupportedChains(nil, &GetSupportedChainsArgs{}, &GetSupportedChainsReply{}))
	require.Error(t, s.GetChainConfig(nil, &GetChainConfigArgs{ChainID: "x"}, &GetChainConfigReply{}))
	require.Error(t, s.GetSignature(nil, &GetSignatureArgs{}, &GetSignatureReply{}))
	require.Error(t, s.GetMPCPublicKey(nil, &GetMPCPublicKeyArgs{}, &GetMPCPublicKeyReply{}))

	var health HealthReply
	require.NoError(t, s.Health(nil, &HealthArgs{}, &health))
	require.Equal(t, "no vm", health.Status)
}

func TestHexEncode(t *testing.T) {
	require.Equal(t, "", hexEncode(nil))
	require.Equal(t, "00ff1a", hexEncode([]byte{0x00, 0xff, 0x1a}))
}

// registerSigner adds one signer with a bond that meets the requirement.
func registerSigner(vm *VM, node ids.NodeID) error {
	_, err := vm.RegisterValidator(&RegisterValidatorInput{
		NodeID:     node.String(),
		BondAmount: strconv.FormatUint(minValidatorBond, 10),
	})
	return err
}
