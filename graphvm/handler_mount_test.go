// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The node mounts each CreateHandlers key at /v1/chain/<chainID>+key and matches
// that path EXACTLY, then hands the handler the request on the path it arrived
// on. A handler that dispatches on r.URL.Path is therefore unreachable.
func TestHandlersAnswerAtTheMountedPath(t *testing.T) {
	const base = "/v1/chain/24C9zm36x43T7LqcaKF1ikHxSeuQeTXnstzi5Gwh2apo18rXNE"

	handlers, err := (&VM{}).CreateHandlers(context.Background())
	if err != nil {
		t.Fatalf("CreateHandlers: %v", err)
	}
	if len(handlers) == 0 {
		t.Fatal("CreateHandlers returned no handlers")
	}

	for endpoint, h := range handlers {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, base+endpoint, nil))
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s%s: 404 — the handler dispatches on the request path instead of answering at its mount",
				base, endpoint)
		}
	}
}
