// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// evmclient_depth_test.go — where a lock's depth comes from.
//
// A client is configured with many validator RPCs and refuses to start unless
// every one of them is on the configured chain. That is a statement about the
// set. The number a release then rests on — how deep the source lock is — was
// read from one member of it, so an endpoint that answered correctly at startup
// and differently afterwards decided the release on its own.
package bridgevm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/ids"
)

// depthServer is an endpoint on chain id that puts every transaction in block
// txBlock and reports head as its own height. headErr makes it refuse to say
// where it has got to.
func depthServer(t *testing.T, id, txBlock, head uint64, headErr bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "eth_chainId":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x%x"}`, req.ID, id)
		case "eth_getTransactionReceipt":
			rcpt := &types.Receipt{
				Status:            types.ReceiptStatusSuccessful,
				CumulativeGasUsed: 21000,
				GasUsed:           21000,
				Logs:              []*types.Log{},
				BlockNumber:       new(big.Int).SetUint64(txBlock),
			}
			enc, err := json.Marshal(rcpt)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, enc)
		case "eth_blockNumber":
			if headErr {
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"unavailable"}}`, req.ID)
				return
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x%x"}`, req.ID, head)
		default:
			http.Error(w, "unexpected method "+req.Method, http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func depthClient(t *testing.T, id uint64, urls ...string) *evmChainClient {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("gas key: %v", err)
	}
	c, err := newEVMChainClient(context.Background(), ExternalChainConfig{
		Name:          "lux-c",
		ChainID:       id,
		RPCEndpoints:  urls,
		Gateway:       "0x0000000000000000000000000000000000000001",
		CustodySigner: "0x0000000000000000000000000000000000000002",
	}, key, nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return c
}

// TestDepthIsTheLeastAdvancedEndpointsAnswer.
//
// Depth gates the release, so the endpoint that reports the largest one decides
// it. Read from a single endpoint, that is whichever endpoint the client
// happens to read from, and a lock 1 block deep can be presented as 101. Read
// from all of them, the smallest answer wins: an endpoint can then withhold a
// release it should not have had a say in, and cannot manufacture one.
func TestDepthIsTheLeastAdvancedEndpointsAnswer(t *testing.T) {
	const (
		id      = 96369
		txBlock = 100
	)
	ahead := depthServer(t, id, txBlock, 200, false)  // 101 deep
	behind := depthServer(t, id, txBlock, 100, false) // 1 deep

	for _, order := range [][]string{{ahead.URL, behind.URL}, {behind.URL, ahead.URL}} {
		c := depthClient(t, id, order...)
		got, err := c.GetConfirmations(context.Background(), ids.ID(common.HexToHash("0x01")))
		if err != nil {
			t.Fatalf("confirmations: %v", err)
		}
		if got != 1 {
			t.Fatalf("depth = %d, want 1: one endpoint has the lock 101 blocks deep and one "+
				"has it 1 deep, and a release must rest on the smaller", got)
		}
	}
}

// TestDepthRefusesWhenAnEndpointCannotAnswer: an endpoint that does not say
// where it has got to has not agreed the lock is deep — silently reading past
// it would let whoever silences the honest endpoints choose who answers.
func TestDepthRefusesWhenAnEndpointCannotAnswer(t *testing.T) {
	const (
		id      = 96369
		txBlock = 100
	)
	ahead := depthServer(t, id, txBlock, 200, false)
	mute := depthServer(t, id, txBlock, 200, true)

	c := depthClient(t, id, ahead.URL, mute.URL)
	if _, err := c.GetConfirmations(context.Background(), ids.ID(common.HexToHash("0x01"))); err == nil {
		t.Fatal("an endpoint that could not report its head was read past")
	}
}

// The positive control: endpoints that agree return the depth they agree on.
func TestDepthOfAgreeingEndpoints(t *testing.T) {
	const (
		id      = 96369
		txBlock = 100
	)
	a := depthServer(t, id, txBlock, 109, false)
	b := depthServer(t, id, txBlock, 109, false)

	c := depthClient(t, id, a.URL, b.URL)
	got, err := c.GetConfirmations(context.Background(), ids.ID(common.HexToHash("0x01")))
	if err != nil {
		t.Fatalf("confirmations: %v", err)
	}
	if got != 10 {
		t.Fatalf("depth = %d, want 10", got)
	}
}

// A client with no endpoint cannot report a depth, and must not report the seed
// the loop starts from — that seed is the maximum, so it clears every minimum a
// release is gated on. Reached only by constructing the client directly, which
// is the point: the refusal belongs in the function that answers, not only in
// the constructor that happens to guard it today.
func TestDepthRefusesWithNoEndpoints(t *testing.T) {
	c := &evmChainClient{name: "lux"}
	got, err := c.GetConfirmations(context.Background(), ids.ID{1})
	if err == nil {
		t.Fatalf("a client with no endpoints answered depth %d with no error", got)
	}
	if got != 0 {
		t.Errorf("depth %d returned alongside an error; it must be 0", got)
	}
}
