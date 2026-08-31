// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The node mounts each CreateHandlers key at /v1/bc/<chainID>+key and matches
// that path EXACTLY, then hands the handler the request on the path it arrived
// on. So a handler that dispatches on r.URL.Path is unreachable: no request can
// ever carry the bare path it looks for, and no path below the mount is routed
// at all. This asserts the only property that makes an endpoint reachable —
// the handler answers at the path the node delivers.
func TestHandlersAnswerAtTheMountedPath(t *testing.T) {
	const base = "/v1/bc/2NXHomv4gbu8i6JTqALHvcbdeb8gb8r7jzbxqXvqZRd1UzorhF"

	handlers, err := (&VM{}).CreateHandlers(context.Background())
	if err != nil {
		t.Fatalf("CreateHandlers: %v", err)
	}
	if len(handlers) == 0 {
		t.Fatal("CreateHandlers returned no handlers")
	}

	for endpoint, h := range handlers {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, base+endpoint, nil))
			if rec.Code == http.StatusNotFound {
				t.Errorf("%s %s%s: 404 — the handler dispatches on the request path instead of answering at its mount",
					method, base, endpoint)
			}
		}
	}
}
