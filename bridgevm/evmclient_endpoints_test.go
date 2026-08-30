package bridgevm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luxfi/crypto"
)

// A signed release is broadcast to every configured endpoint — RPCEndpoints
// says so on its own field, and broadcastRelease loops over all of them. Only
// endpoints[0] used to be asked what chain it was on, so every endpoint after
// the first received a signed transaction without anyone establishing where it
// would land.
//
// What these tests pin is narrow and worth stating exactly: each endpoint
// answers with the configured chain id. A fork reports the id of the chain it
// left and still passes — distinguishing that needs a commitment to the
// genesis, which is a different check that this path does not make.

// chainIDServer answers eth_chainId with the id it is given and nothing else.
func chainIDServer(t *testing.T, id uint64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method != "eth_chainId" {
			http.Error(w, "unexpected method "+req.Method, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x%x"}`, req.ID, id)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func endpointCfg(name string, id uint64, urls ...string) ExternalChainConfig {
	return ExternalChainConfig{
		Name:          name,
		ChainID:       id,
		RPCEndpoints:  urls,
		Gateway:       "0x1111111111111111111111111111111111111111",
		CustodySigner: "0x2222222222222222222222222222222222222222",
	}
}

func TestEverySecondaryEndpointIsAskedWhatChainItIsOn(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("gas key: %v", err)
	}
	const want = 96369

	good := chainIDServer(t, want)
	// A second endpoint on a different network. Before every endpoint was
	// verified, this was dialled, never questioned, and then handed a signed
	// release by broadcastRelease.
	wrong := chainIDServer(t, want+1)

	_, err = newEVMChainClient(context.Background(),
		endpointCfg("lux-c", want, good.URL, wrong.URL), key, nil)
	if err == nil {
		t.Fatal("a secondary endpoint on another chain was accepted; releases would be broadcast to it")
	}
	// Named, so an operator reading the log knows which of N endpoints to fix
	// rather than being told only that one of them disagreed.
	if !strings.Contains(err.Error(), wrong.URL) {
		t.Fatalf("refusal does not name the offending endpoint %q: %v", wrong.URL, err)
	}
}

// The positive control. Without it the test above would pass just as well
// against a constructor that refused every configuration it was handed.
func TestAllEndpointsAgreeingIsAccepted(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("gas key: %v", err)
	}
	const want = 96369
	a, b := chainIDServer(t, want), chainIDServer(t, want)

	if _, err := newEVMChainClient(context.Background(),
		endpointCfg("lux-c", want, a.URL, b.URL), key, nil); err != nil {
		t.Fatalf("two endpoints both on the configured chain were refused: %v", err)
	}
}
