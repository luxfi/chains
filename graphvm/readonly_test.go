// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// A chain that builds no block must admit no block. Before this, ParseBlock
// accepted 56 bytes of well-formed ZAP naming any height and any parent, Verify
// passed it, and Accept moved lastAccepted to it — after which
// GetBlock(LastAccepted()) answered "not found" and the node could not boot.
// One unauthenticated block off the wire, one permanently unstartable node.
func TestForgedBlockIsRefusedAtEveryDoor(t *testing.T) {
	ctx := context.Background()
	vm := initVM(t, []byte(`{"schemaVersion":"1"}`))

	genesis, err := vm.LastAccepted(ctx)
	require.NoError(t, err)

	for _, forged := range [][]byte{
		marshalGBlock(ids.ID{0xFF}, 9_999_999, 1<<40, []byte("attacker")),
		marshalGBlock(ids.Empty, 1, genesisTimestamp.Unix(), nil),
		marshalGBlock(ids.Empty, 0, genesisTimestamp.Unix(), []byte("other genesis")),
		marshalGBlock(ids.Empty, 0, genesisTimestamp.Unix()+1, []byte(`{"schemaVersion":"1"}`)),
	} {
		_, err := vm.ParseBlock(ctx, forged)
		require.ErrorIs(t, err, errReadOnlyChain, "ParseBlock admitted %x", forged)
	}

	// The frontier has not moved, and it still resolves.
	now, err := vm.LastAccepted(ctx)
	require.NoError(t, err)
	require.Equal(t, genesis, now)
	blk, err := vm.GetBlock(ctx, now)
	require.NoError(t, err)
	require.Equal(t, genesis, blk.ID())
}

// The refusal is the ONE predicate: admission, assembly, preference and
// consensus all answer with it, so none can drift from the others.
func TestOnePredicateServesEveryDoor(t *testing.T) {
	ctx := context.Background()
	vm := initVM(t, nil)

	_, err := vm.BuildBlock(ctx)
	require.ErrorIs(t, err, errReadOnlyChain)

	_, err = vm.ParseBlock(ctx, marshalGBlock(ids.Empty, 1, 0, nil))
	require.ErrorIs(t, err, errReadOnlyChain)

	require.ErrorIs(t, vm.SetPreference(ctx, ids.GenerateTestID()), errReadOnlyChain)
	require.NoError(t, vm.SetPreference(ctx, vm.genesis.ID()))

	// A block that did NOT come from this VM cannot be verified or accepted
	// into it, even though it is a well-formed *Block.
	other := initVM(t, []byte("different genesis"))
	require.ErrorIs(t, (&Block{vm: vm, id: other.genesis.ID()}).Verify(ctx), errReadOnlyChain)
	require.ErrorIs(t, (&Block{vm: vm, id: other.genesis.ID()}).Accept(ctx), errReadOnlyChain)

	// Genesis itself verifies and accepts, and rejecting it never does.
	require.NoError(t, vm.genesis.Verify(ctx))
	require.NoError(t, vm.genesis.Accept(ctx))
	require.ErrorIs(t, vm.genesis.Reject(ctx), errReadOnlyChain)
}

// Malformed wire is reported as malformed wire, not as a policy refusal: the
// two are different answers and a caller acts on them differently.
func TestMalformedWireIsRefusedAsWire(t *testing.T) {
	ctx := context.Background()
	vm := initVM(t, nil)

	_, err := vm.ParseBlock(ctx, nil)
	require.Error(t, err)
	require.NotErrorIs(t, err, errReadOnlyChain)

	trailing := append(append([]byte(nil), vm.genesis.Bytes()...), 0xFF)
	_, err = vm.ParseBlock(ctx, trailing)
	require.ErrorIs(t, err, errGBlockTrailing)
}

func TestGenesisBlockShape(t *testing.T) {
	ctx := context.Background()
	vm := initVM(t, []byte(`{"schemaVersion":"1"}`))
	b := vm.genesis

	require.Equal(t, uint64(0), b.Height())
	require.Equal(t, ids.Empty, b.Parent())
	require.Equal(t, ids.Empty, b.ParentID())
	require.Equal(t, genesisTimestamp, b.Timestamp())
	require.Equal(t, uint8(3), b.Status()) // choices.Accepted
	require.NotEmpty(t, b.Bytes())

	// Height 0 is the only height; the ID index and the block agree.
	at0, err := vm.GetBlockIDAtHeight(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, b.ID(), at0)
	_, err = vm.GetBlockIDAtHeight(ctx, 1)
	require.ErrorIs(t, err, database.ErrNotFound)
	_, err = vm.GetBlock(ctx, ids.GenerateTestID())
	require.ErrorIs(t, err, database.ErrNotFound)
}

func TestVMLifecycle(t *testing.T) {
	ctx := context.Background()
	vm := initVM(t, nil)

	require.NoError(t, vm.SetState(ctx, 0))
	v, err := vm.Version(ctx)
	require.NoError(t, err)
	require.Equal(t, Version.String(), v)

	h, err := vm.HealthCheck(ctx)
	require.NoError(t, err)
	require.True(t, h.Healthy)
	require.Equal(t, Version.String(), h.Details["version"])

	require.NoError(t, vm.Connected(ctx, ids.EmptyNodeID, nil))
	require.NoError(t, vm.Disconnected(ctx, ids.EmptyNodeID))
	require.ErrorIs(t, vm.Request(ctx, ids.EmptyNodeID, 0, genesisTimestamp, nil), errNoAppProtocol)
	require.NoError(t, vm.RequestFailed(ctx, ids.EmptyNodeID, 0, nil))
	require.NoError(t, vm.Response(ctx, ids.EmptyNodeID, 0, nil))
	require.NoError(t, vm.Gossip(ctx, ids.EmptyNodeID, nil))
	require.NoError(t, vm.CrossChainRequest(ctx, ids.Empty, 0, genesisTimestamp, nil))
	require.NoError(t, vm.CrossChainRequestFailed(ctx, ids.Empty, 0, nil))
	require.NoError(t, vm.CrossChainResponse(ctx, ids.Empty, 0, nil))

	require.NoError(t, vm.Shutdown(ctx))
	require.NoError(t, (&VM{}).Shutdown(ctx))
}

func TestInitializeRefusesBadConfig(t *testing.T) {
	boot := func(config []byte) error {
		return (&VM{}).Initialize(context.Background(), vmcore.Init{
			Runtime: &runtime.Runtime{NetworkID: 1},
			DB:      memdb.New(),
			Config:  config,
		})
	}

	require.ErrorContains(t, boot([]byte(`{`)), "failed to parse config")

	// subtle.ConstantTimeCompare reports EQUAL for two zero-length slices, so a
	// configured "" matches the token in `Authorization: Bearer `. Auth on,
	// everyone in. The chain refuses to boot rather than serve that.
	require.ErrorIs(t, boot([]byte(`{"requireAuth":true,"apiKeys":[""]}`)), errEmptyAPIKey)
	require.ErrorIs(t, boot([]byte(`{"requireAuth":true,"apiKeys":["good",""]}`)), errEmptyAPIKey)
	require.ErrorIs(t, boot([]byte(`{"requireAuth":true}`)), errEmptyAPIKey)
	require.ErrorIs(t, boot([]byte(`{"requireAuth":true,"apiKeys":[]}`)), errEmptyAPIKey)

	require.NoError(t, boot([]byte(`{"requireAuth":true,"apiKeys":["k"]}`)))
	require.NoError(t, boot([]byte(`{"requireAuth":false,"apiKeys":[""]}`)))
	require.NoError(t, boot(nil))
}

// post drives a handler at the path the node mounts it on: the node matches
// /v1/chain/<chainID>+key EXACTLY and then hands the handler the full path, so a
// handler that dispatches on r.URL.Path answers nothing.
func post(t *testing.T, h http.Handler, auth, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/chain/chain/graphql", strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestGraphQLEndpointServesTheExecutor(t *testing.T) {
	vm := initVM(t, nil)
	require.NoError(t, vm.db.Put([]byte("account:0x1"), []byte(`{"address":"0x1","balance":"7"}`)))

	handlers, err := vm.CreateHandlers(context.Background())
	require.NoError(t, err)
	require.Len(t, handlers, 1)
	h := handlers["/graphql"]
	require.NotNil(t, h)

	// The endpoint answers the query rather than a placeholder. It used to
	// reply {"data":null,"errors":["GraphQL endpoint ready"]} to everything.
	rec := post(t, h, "", `{"query":"{ account(address: \"0x1\") }"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp GraphQLResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Empty(t, resp.Errors)
	acct := resp.Data.(map[string]interface{})["account"].(map[string]interface{})
	require.Equal(t, "7", acct["balance"])

	// A GraphQL error is a 200 carrying errors; the request was understood.
	rec = post(t, h, "", `{"query":"{ nope }"}`)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "unknown field")

	// A malformed request is a 400, and a GET is a 405 — never a silent 200.
	rec = post(t, h, "", `not json`)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graphql", nil))
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	// A body larger than the cap is refused before it is parsed.
	rec = post(t, h, "", `{"query":"`+strings.Repeat("a", maxRequestBytes)+`"}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestNewHTTPHandlerMountsTheSameRoute(t *testing.T) {
	vm := initVM(t, nil)
	h, err := vm.NewHTTPHandler(context.Background())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ chainInfo }"}`)))
	require.Equal(t, http.StatusOK, rec.Code)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/elsewhere", bytes.NewReader(nil)))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestAuthAdmitsOnlyAConfiguredKey(t *testing.T) {
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime: &runtime.Runtime{NetworkID: 1},
		DB:      memdb.New(),
		Config:  []byte(`{"requireAuth":true,"apiKeys":["secret","second"]}`),
	}))

	handlers, err := vm.CreateHandlers(context.Background())
	require.NoError(t, err)
	h := handlers["/graphql"]

	body := `{"query":"{ chainInfo }"}`
	for _, auth := range []string{"", "Bearer ", "Bearer wrong", "wrong", "Bearer secretx", "Bearer secre"} {
		require.Equal(t, http.StatusUnauthorized, post(t, h, auth, body).Code, "auth %q was admitted", auth)
	}
	// Surrounding whitespace in a header value is whitespace, not a key.
	for _, auth := range []string{"Bearer secret", "secret", "Bearer second", " second ", "Bearer  secret "} {
		require.Equal(t, http.StatusOK, post(t, h, auth, body).Code, "auth %q was refused", auth)
	}
}

func TestUnauthenticatedChainNeedsNoKey(t *testing.T) {
	vm := initVM(t, nil)
	handlers, err := vm.CreateHandlers(context.Background())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, post(t, handlers["/graphql"], "", `{"query":"{ chainInfo }"}`).Code)
}

// This chain never has work to report, however long anyone waits. The other
// chains here had work and no way to say so, and were given a latch; a latch
// here would wake a builder that declines.
func TestWaitForEventReportsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&VM{}).WaitForEvent(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

// A chain that builds no block charges for none: every fee this policy is asked
// to validate is refused, whatever it pays and in whatever asset.
func TestFeePolicyRefusesEveryUserTransaction(t *testing.T) {
	vm := initVM(t, nil)
	require.Equal(t, vm.feePolicy, vm.FeePolicy())

	for _, paid := range []uint64{0, 1, 1 << 62} {
		for _, asset := range []ids.ID{ids.Empty, vm.feePolicy.FeeAssetID(), ids.GenerateTestID()} {
			require.ErrorIs(t, vm.feePolicy.ValidateFee(paid, asset), fee.ErrChainAcceptsNoUserTxs)
		}
	}
	require.Zero(t, vm.feePolicy.MinTxFee())
}
