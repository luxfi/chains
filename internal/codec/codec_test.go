// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package codec

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/rpc/v2"
	"github.com/stretchr/testify/require"
)

// call builds the JSON-RPC request a client would send for the named method.
func call(t *testing.T, method, params string) *http.Request {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":` + params + `}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// TestMethod pins the spelling a client may use. Every name here is one
// quantumvm serves; a change to this table is a change to the wire.
func TestMethod(t *testing.T) {
	for _, test := range []struct {
		wire, method string
	}{
		{"quantumvm.getBlock", "quantumvm.GetBlock"},
		{"quantumvm.generateCoronaKey", "quantumvm.GenerateCoronaKey"},
		{"quantumvm.verifyQuantumSignature", "quantumvm.VerifyQuantumSignature"},
		{"quantumvm.getPendingTransactions", "quantumvm.GetPendingTransactions"},
		{"quantumvm.getHealth", "quantumvm.GetHealth"},
		{"quantumvm.getConfig", "quantumvm.GetConfig"},
	} {
		t.Run(test.wire, func(t *testing.T) {
			method, err := New().NewRequest(call(t, test.wire, "[{}]")).Method()
			require.NoError(t, err)
			require.Equal(t, test.method, method)
		})
	}
}

// TestMethodRaised refuses the spelling of the Go method itself, so a service
// answers to one name and not two.
func TestMethodRaised(t *testing.T) {
	method, err := New().NewRequest(call(t, "quantumvm.GetBlock", "[{}]")).Method()
	require.ErrorIs(t, err, errUppercaseMethod)
	require.EqualError(t, err, "method must start with a non-uppercase letter")
	require.Equal(t, "quantumvm.GetBlock", method)
}

// TestMethodWhole passes a name carrying no dot through untouched — the server
// rejects it, and the codec does not invent a class for it.
func TestMethodWhole(t *testing.T) {
	method, err := New().NewRequest(call(t, "getBlock", "[{}]")).Method()
	require.NoError(t, err)
	require.Equal(t, "getBlock", method)
}

// TestReadRequest reports one message for arguments of the wrong shape.
func TestReadRequest(t *testing.T) {
	request := New().NewRequest(call(t, "quantumvm.getBlock", `["not-an-object"]`))
	_, err := request.Method()
	require.NoError(t, err)
	require.ErrorIs(t, request.ReadRequest(&Args{}), errInvalidArg)
}

type Args struct {
	Height uint64 `json:"height"`
}

type Reply struct {
	Height uint64 `json:"height"`
}

// service stands in for quantumvm's: an exported Go method, recording that it
// ran.
type service struct{ ran string }

func (s *service) GetBlock(_ *http.Request, a *Args, r *Reply) error {
	s.ran = "GetBlock"
	r.Height = a.Height
	return nil
}

// TestServe drives the whole path a client takes: a lower-case name on the
// wire reaches the exported Go method and its answer comes back.
func TestServe(t *testing.T) {
	server := rpc.NewServer()
	server.RegisterCodec(New(), "application/json")
	served := &service{}
	require.NoError(t, server.RegisterService(served, "quantumvm"))

	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, call(t, "quantumvm.getBlock", `[{"height":7}]`))

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "GetBlock", served.ran)

	var answer struct {
		Result Reply            `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &answer))
	require.Nil(t, answer.Error)
	require.Equal(t, uint64(7), answer.Result.Height)
}
