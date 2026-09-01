// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

// call drives one endpoint at the path the node mounts it on. The node matches
// /v1/chain/<chainID>+key EXACTLY and hands the handler the full path, so a
// handler that dispatches on r.URL.Path recognises nothing — which is what a
// mux behind a single key does.
func call(t *testing.T, vm *VM, verb, route, query string, body string) *httptest.ResponseRecorder {
	t.Helper()
	h, ok := vm.endpoints()[route]
	require.True(t, ok, "no endpoint at %s", route)

	url := "/v1/chain/24C9zm36x43T7LqcaKF1ikHxSeuQeTXnstzi5Gwh2apo18rXNE" + route
	if query != "" {
		url += "?" + query
	}
	r := httptest.NewRequest(verb, url, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestEveryEndpointAnswersAtItsMountedPath(t *testing.T) {
	vm := newVM(t)
	for route, h := range vm.endpoints() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/chain/chain"+route, nil))
		require.NotEqual(t, http.StatusNotFound, rec.Code,
			"GET %s: the handler dispatches on the request path instead of answering at its mount", route)
	}
	require.Len(t, vm.endpoints(), 9)
}

func TestSendTransactionEndpoint(t *testing.T) {
	vm := newVM(t)

	require.Equal(t, http.StatusBadRequest, call(t, vm, http.MethodPost, "/sendTransaction", "", "not json").Code)

	tx := spendTx(nullifier(1))
	tx.Fee = 1 << 40
	tx.ID = ids.GenerateTestID() // the sender's choice, and it is ignored
	body, err := json.Marshal(tx)
	require.NoError(t, err)

	rec := call(t, vm, http.MethodPost, "/sendTransaction", "", string(body))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), tx.ComputeID().String())
	require.Equal(t, 1, vm.mempool.Size())

	// The same transaction again is the transaction the pool already holds.
	require.Equal(t, http.StatusOK, call(t, vm, http.MethodPost, "/sendTransaction", "", string(body)).Code)
	require.Equal(t, 1, vm.mempool.Size())

	// A DIFFERENT transaction spending the same note is refused.
	rival := spendTx(nullifier(1))
	rival.Fee = 1 << 40
	rival.Memo = []byte("different")
	rivalBody, err := json.Marshal(rival)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, call(t, vm, http.MethodPost, "/sendTransaction", "", string(rivalBody)).Code)
}

func TestGetTransactionEndpoint(t *testing.T) {
	vm := newVM(t)

	require.Equal(t, http.StatusBadRequest, call(t, vm, http.MethodGet, "/getTransaction", "txID=nonsense", "").Code)
	require.Equal(t, http.StatusNotFound,
		call(t, vm, http.MethodGet, "/getTransaction", "txID="+ids.GenerateTestID().String(), "").Code)

	tx := spendTx(nullifier(1))
	require.NoError(t, vm.mempool.AddTransaction(tx))
	rec := call(t, vm, http.MethodGet, "/getTransaction", "txID="+tx.ID.String(), "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "pending")
}

func TestBlockEndpoints(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	require.Equal(t, http.StatusBadRequest, call(t, vm, http.MethodGet, "/getBlock", "blockID=nonsense", "").Code)
	require.Equal(t, http.StatusNotFound,
		call(t, vm, http.MethodGet, "/getBlock", "blockID="+ids.GenerateTestID().String(), "").Code)

	blk := build(t, vm, spendTx(nullifier(1)))
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))

	rec := call(t, vm, http.MethodGet, "/getBlock", "blockID="+blk.ID().String(), "")
	require.Equal(t, http.StatusOK, rec.Code)
	var summary BlockSummary
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &summary))
	require.Equal(t, blk.ID(), summary.ID)
	require.EqualValues(t, 1, summary.Height)

	rec = call(t, vm, http.MethodGet, "/getLatestBlock", "", "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), blk.ID().String())
}

// The latest block is whatever the tip names. A tip that names nothing this
// node holds is a failure to report, not a block to invent.
func TestLatestBlockReportsAnUnresolvableTip(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	tx := spendTx(nullifier(1))
	acceptProofs(vm, tx)
	require.NoError(t, vm.mempool.AddTransaction(tx))
	built, err := vm.BuildVertex(ctx)
	require.NoError(t, err)
	require.NoError(t, built.Verify(ctx))
	require.NoError(t, built.Accept(ctx))

	// The tip is a vertex, which is a decision this chain makes but not a
	// block the caller can be handed.
	require.Equal(t, http.StatusNotFound, call(t, vm, http.MethodGet, "/getLatestBlock", "", "").Code)
}

func TestUTXOEndpoints(t *testing.T) {
	vm := newVM(t)

	require.Equal(t, http.StatusBadRequest, call(t, vm, http.MethodGet, "/getUTXO", "", "").Code)
	require.Equal(t, http.StatusNotFound, call(t, vm, http.MethodGet, "/getUTXO", "commitment=absent", "").Code)

	require.NoError(t, vm.utxoDB.AddUTXO(&UTXO{
		TxID: ids.ID{1}, Commitment: []byte("c"), Ciphertext: []byte("note"), Height: 3,
	}))

	rec := call(t, vm, http.MethodGet, "/getUTXO", "commitment=c", "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "bm90ZQ==") // base64("note")

	rec = call(t, vm, http.MethodGet, "/getUTXOCount", "", "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"count":1`)
}

func TestNullifierEndpointReportsAFailedRead(t *testing.T) {
	vm := newVM(t)

	require.Equal(t, http.StatusBadRequest, call(t, vm, http.MethodGet, "/isNullifierSpent", "", "").Code)

	rec := call(t, vm, http.MethodGet, "/isNullifierSpent", "nullifier=n", "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"isSpent":false`)

	require.NoError(t, vm.nullifierDB.MarkNullifierSpent([]byte("n"), 7))
	rec = call(t, vm, http.MethodGet, "/isNullifierSpent", "nullifier=n", "")
	require.Contains(t, rec.Body.String(), `"isSpent":true`)
	require.Contains(t, rec.Body.String(), `"height":7`)

	// A set that cannot be READ is a failure, not an unspent note.
	vm.nullifierDB.spent = map[string]uint64{}
	vm.nullifierDB.db = &brokenDB{Database: vm.nullifierDB.db, err: errors.New("disk gone")}
	require.Equal(t, http.StatusInternalServerError,
		call(t, vm, http.MethodGet, "/isNullifierSpent", "nullifier=n", "").Code)
}

func TestStatusEndpoints(t *testing.T) {
	vm := newVM(t)

	rec := call(t, vm, http.MethodGet, "/getStatus", "", "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "utxoCount")

	rec = call(t, vm, http.MethodGet, "/getProofStats", "", "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "cacheHits")
}

func TestEndpointsRefuseTheWrongMethod(t *testing.T) {
	vm := newVM(t)
	require.Equal(t, http.StatusMethodNotAllowed,
		call(t, vm, http.MethodGet, "/sendTransaction", "", "").Code)
	require.Equal(t, http.StatusMethodNotAllowed,
		call(t, vm, http.MethodPost, "/getStatus", "", "").Code)
}

// The same routes are reachable by path through NewHTTPHandler.
func TestHTTPHandlerMountsEveryRoute(t *testing.T) {
	vm := newVM(t)
	mux, err := vm.NewHTTPHandler(context.Background())
	require.NoError(t, err)

	for route := range vm.endpoints() {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, route, nil))
		require.NotEqual(t, http.StatusNotFound, rec.Code, route)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/elsewhere", nil))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

var _ database.Database = (*brokenDB)(nil)
