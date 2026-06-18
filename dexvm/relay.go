// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/rpc"
)

// ZAP CLOB method names. These are FROZEN and MUST stay byte-identical with the
// d-chain gateway (github.com/luxfi/dex/pkg/api/zap_server.go) and the EVM
// precompile (github.com/luxfi/precompile/dex/engine_zap.go). The proxy never
// interprets order semantics — it forwards these frames verbatim to the single
// source-of-truth matcher.
const (
	ZAPMethodEnsureMarket = "clob_ensure_market"
	ZAPMethodPlace        = "clob_place"
	ZAPMethodCancel       = "clob_cancel"
	ZAPMethodSubmit       = "clob_submit"
)

// FillWireSize is one fill in a clob_submit response: price[8]+size[8]+side[1].
// FROZEN — must equal dex/pkg/api.FillWireSize and the precompile's fillWireSize.
const FillWireSize = 17

// ErrRelayNotConfigured is returned when an order relay is attempted but no
// d-chain ZAP endpoint is configured. The proxy is inert on the relay leg until
// the venue operator points dex-zap-endpoint at a d-chain gateway.
var ErrRelayNotConfigured = errors.New("dexvm: d-chain ZAP endpoint not configured")

// zapConn is the connection contract the relay uses. Production uses
// *rpc.ZAPConn; the interface lets the VM test harness drive the relay without
// a live socket (and keeps the proxy a clean leaf over luxfi/rpc).
type zapConn interface {
	Call(ctx context.Context, method string, payload []byte) ([]byte, error)
	Close() error
}

// zapDialer establishes a zapConn to addr. Overridable in tests; defaults to
// the canonical rpc.ZAPDial (pinned luxfi/rpc v1.1.0).
var zapDialer = func(ctx context.Context, addr string) (zapConn, error) {
	return rpc.ZAPDial(ctx, addr)
}

// RelayClient forwards byte-identical clob_* frames to the d-chain's ZAP
// gateway. It is PURE TRANSPORT to the single source-of-truth matcher: it holds
// NO order/pool/book state, performs NO matching, and never mints. This is the
// ORDER RELAY leg (NOT atomic, NOT consensus) of the two-primitive proxy; value
// settlement is the separate atomic SharedMemory import/export leg (atomic.go).
type RelayClient struct {
	addr    string
	timeout time.Duration

	mu   sync.Mutex
	conn zapConn
}

// NewRelayClient creates a relay targeting the d-chain ZAP endpoint (e.g.
// "127.0.0.1:9100"). An empty addr yields a relay that returns
// ErrRelayNotConfigured on every call — the inert relay leg.
func NewRelayClient(addr string, timeout time.Duration) *RelayClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &RelayClient{addr: addr, timeout: timeout}
}

// Configured reports whether a d-chain endpoint is set.
func (r *RelayClient) Configured() bool { return r != nil && r.addr != "" }

func (r *RelayClient) dial(ctx context.Context) (zapConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		return r.conn, nil
	}
	c, err := zapDialer(ctx, r.addr)
	if err != nil {
		return nil, fmt.Errorf("dexvm relay dial %s: %w", r.addr, err)
	}
	r.conn = c
	return c, nil
}

// Relay forwards an opaque clob_* frame to the d-chain and returns the raw
// response bytes verbatim. The proxy does not interpret the payload beyond
// routing it to the configured matcher.
func (r *RelayClient) Relay(ctx context.Context, method string, payload []byte) ([]byte, error) {
	if !r.Configured() {
		return nil, ErrRelayNotConfigured
	}
	cctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	c, err := r.dial(cctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.Call(cctx, method, payload)
	if err != nil {
		// A failed call invalidates the cached connection so the next relay
		// redials rather than reusing a broken socket.
		r.mu.Lock()
		if r.conn == c {
			_ = r.conn.Close()
			r.conn = nil
		}
		r.mu.Unlock()
		return nil, fmt.Errorf("dexvm relay %s: %w", method, err)
	}
	return resp, nil
}

// Close closes the cached connection, if any.
func (r *RelayClient) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		err := r.conn.Close()
		r.conn = nil
		return err
	}
	return nil
}

// Fill is one execution returned by the d-chain matcher: price + size + the
// taker side this submit took with. The proxy derives the settlement delta
// ONLY from these server-returned fills — never from a client-supplied amount.
type Fill struct {
	Price float64
	Size  float64
	Side  uint8
}

// DecodeFills parses a clob_submit response: count[4] then count×(price[8] +
// size[8] + side[1]). Every field is range-checked so a backend that lies (or a
// MITM on the socket) cannot inject a structurally invalid fill into settlement:
// price/size must be finite and strictly positive, and side MUST be a valid CLOB
// side (0=BUY, 1=SELL). A side byte outside {0,1} is malformed wire exactly like
// a NaN price — rejecting it here keeps a Fill value always well-formed, so no
// downstream consumer ever sees an impossible side. (Cross-fill side CONSISTENCY
// — "a single submit takes exactly one side" — is a settlement-policy invariant
// enforced in settleFromFills, not a per-fill wire property; the two checks own
// different invariants and do not overlap.)
func DecodeFills(data []byte) ([]Fill, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("fills response too short: %d", len(data))
	}
	n := int(binary.BigEndian.Uint32(data[0:4]))
	if 4+n*FillWireSize > len(data) {
		return nil, fmt.Errorf("fills response truncated: count=%d len=%d", n, len(data))
	}
	fills := make([]Fill, 0, n)
	off := 4
	for i := 0; i < n; i++ {
		p := float64FromBits(data[off : off+8])
		s := float64FromBits(data[off+8 : off+16])
		side := data[off+16]
		off += FillWireSize
		if !isFinitePositive(p) {
			return nil, fmt.Errorf("fill %d: invalid price %v", i, p)
		}
		if !isFinitePositive(s) {
			return nil, fmt.Errorf("fill %d: invalid size %v", i, s)
		}
		if side > 1 {
			return nil, fmt.Errorf("fill %d: invalid side %d (must be 0=BUY or 1=SELL)", i, side)
		}
		fills = append(fills, Fill{Price: p, Size: s, Side: side})
	}
	return fills, nil
}
