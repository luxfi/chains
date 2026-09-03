package bridgevm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
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

// chainIDServer answers eth_chainId with the id it is given, and serves a
// genesis header whose parentHash carries `mark` — enough to give block 0 a
// hash that differs per mark while staying a well-formed header.
func chainIDServer(t *testing.T, id uint64, mark ...byte) *httptest.Server {
	t.Helper()
	var parent common.Hash
	if len(mark) > 0 {
		parent[0] = mark[0]
	}
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
		case "eth_getBlockByNumber":
			h := &types.Header{
				ParentHash: parent,
				Number:     new(big.Int),
				Difficulty: new(big.Int),
				GasLimit:   8_000_000,
				Time:       1,
				Extra:      []byte{},
			}
			enc, err := json.Marshal(h)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, enc)
		default:
			http.Error(w, "unexpected method "+req.Method, http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// genesisOf is what the server above will report as block 0's hash.
func genesisOf(mark byte) common.Hash {
	var parent common.Hash
	parent[0] = mark
	return (&types.Header{
		ParentHash: parent,
		Number:     new(big.Int),
		Difficulty: new(big.Int),
		GasLimit:   8_000_000,
		Time:       1,
		Extra:      []byte{},
	}).Hash()
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

// A fork answers eth_chainId with the id of the chain it left, so the id check
// above cannot see it. This is the case the genesis commitment exists for, and
// the reason a chain id is not an identity.
func TestAForkIsRefusedAlthoughItsChainIDIsRight(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("gas key: %v", err)
	}
	const want = 96369
	real, fork := chainIDServer(t, want, 1), chainIDServer(t, want, 2)

	cfg := endpointCfg("lux-c", want, real.URL, fork.URL)
	cfg.Genesis = genesisOf(1).Hex()

	_, err = newEVMChainClient(context.Background(), cfg, key, nil)
	if err == nil {
		t.Fatal("an endpoint on a fork was accepted; it reports the right chain id, so only the genesis separates them")
	}
	// Named, and named for the right reason: a block-0 fetch that simply failed
	// would also mention this endpoint, so the assertion has to reach the
	// comparison rather than settle for the URL appearing somewhere.
	if !strings.Contains(err.Error(), fork.URL) || !strings.Contains(err.Error(), "but genesis") {
		t.Fatalf("refusal is not a genesis mismatch naming %q: %v", fork.URL, err)
	}

	// And the same configuration without the commitment accepts the fork —
	// which is what makes the commitment the thing doing the work here, rather
	// than some other difference between the two servers.
	cfg.Genesis = ""
	if _, err := newEVMChainClient(context.Background(), cfg, key, nil); err != nil {
		t.Fatalf("without a genesis the fork should pass the id check: %v", err)
	}
}

// A mistyped hash must be refused at startup rather than zero-padded into a
// hash no chain can match.
func TestAMalformedGenesisIsRefusedByName(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("gas key: %v", err)
	}
	const want = 96369
	srv := chainIDServer(t, want, 1)

	for _, bad := range []string{"0xdeadbeef", "not-a-hash", genesisOf(1).Hex() + "00"} {
		cfg := endpointCfg("lux-c", want, srv.URL)
		cfg.Genesis = bad
		if _, err := newEVMChainClient(context.Background(), cfg, key, nil); err == nil {
			t.Fatalf("genesis %q was accepted", bad)
		}
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
	a, b := chainIDServer(t, want, 1), chainIDServer(t, want, 1)

	cfg := endpointCfg("lux-c", want, a.URL, b.URL)
	cfg.Genesis = genesisOf(1).Hex()

	if _, err := newEVMChainClient(context.Background(), cfg, key, nil); err != nil {
		t.Fatalf("two endpoints both on the configured chain were refused: %v", err)
	}
}
