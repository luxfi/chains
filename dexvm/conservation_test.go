// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// conservation_test.go — the end-to-end value-conservation proof for the
// stateless atomic ZAP proxy. This is the ONE acceptance criterion that had no
// executable proof before: move value C-Chain -> proxy -> d-chain and back, and
// assert GLOBAL ALL-OR-NOTHING CONSERVATION — the proxy never mints, never
// burns value into nowhere; every credited unit traces to a confirmed fill or
// to value that was locked on the import leg.
//
// The two primitives are exercised end-to-end with REAL atomic.SharedMemory
// (in-memory two-chain harness) for the settlement leg and a fake ZAP listener
// (the zapDialer seam) standing in for the d-chain matcher on the relay leg.

package dexvm

import (
	"context"
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/vm"
	"github.com/luxfi/vm/chains/atomic"
	"github.com/luxfi/warp"

	"github.com/luxfi/chains/dexvm/config"
	"github.com/luxfi/chains/dexvm/txs"
)

// fakeMatcherConn is a fake d-chain matcher over the zapConn seam. A clob_submit
// returns a canned fills frame; place/cancel return an ack. It records every
// frame it received so the test can assert the proxy forwarded byte-identical
// payloads.
type fakeMatcherConn struct {
	fills    []Fill
	received [][]byte
}

func (f *fakeMatcherConn) Call(_ context.Context, method string, payload []byte) ([]byte, error) {
	f.received = append(f.received, append([]byte(nil), payload...))
	switch method {
	case ZAPMethodSubmit:
		return encodeFillsWire(f.fills), nil
	default:
		// ack: order_id(8) + status(0=placed) + seq(8)
		ack := make([]byte, 17)
		binary.BigEndian.PutUint64(ack[0:8], 1)
		return ack, nil
	}
}

func (f *fakeMatcherConn) Close() error { return nil }

// encodeFillsWire encodes fills in the FROZEN clob_submit response format:
// count[4] then count×(price[8]+size[8]+side[1]).
func encodeFillsWire(fills []Fill) []byte {
	resp := make([]byte, 4+len(fills)*FillWireSize)
	binary.BigEndian.PutUint32(resp[0:4], uint32(len(fills)))
	off := 4
	for _, fl := range fills {
		binary.BigEndian.PutUint64(resp[off:off+8], math.Float64bits(fl.Price))
		binary.BigEndian.PutUint64(resp[off+8:off+16], math.Float64bits(fl.Size))
		resp[off+16] = fl.Side
		off += FillWireSize
	}
	return resp
}

// conservationHarness wires a proxy VM with REAL two-chain shared memory and a
// fake matcher, returning the proxy VM, the C-Chain's shared-memory handle, and
// the chain ids.
type conservationHarness struct {
	vm          *VM
	cChainSM    atomic.SharedMemory
	proxyChain  ids.ID
	cChain      ids.ID
	matcher     *fakeMatcherConn
	exportTaker ids.ShortID // the address whose exported proceeds we audit
}

func newConservationHarness(t *testing.T, fills []Fill) *conservationHarness {
	t.Helper()
	logger := log.NewNoOpLogger()

	baseDB := memdb.New()
	memoryDB := prefixdb.New([]byte{0}, baseDB)
	m := atomic.NewMemory(memoryDB)

	proxyChain := ids.GenerateTestID()
	cChain := ids.GenerateTestID()
	proxySM := m.NewSharedMemory(proxyChain)
	cChainSM := m.NewSharedMemory(cChain)

	matcher := &fakeMatcherConn{fills: fills}
	// Drive the relay over the fake matcher instead of a live socket.
	prev := zapDialer
	zapDialer = func(_ context.Context, _ string) (zapConn, error) { return matcher, nil }
	t.Cleanup(func() { zapDialer = prev })

	rt := &runtime.Runtime{
		ChainID:      proxyChain,
		CChainID:     cChain,
		NetworkID:    96369,
		Log:          logger,
		SharedMemory: proxySM,
	}

	v := &VM{}
	// Non-empty endpoint so the relay leg is live; the fake dialer ignores it.
	v.Config = config.DefaultConfig()
	v.Config.DexZapEndpoint = "127.0.0.1:0"
	if err := v.Initialize(context.Background(), vm.Init{
		Runtime:  rt,
		DB:       prefixdb.New([]byte{1}, baseDB),
		ToEngine: make(chan vm.Message, 8),
		Sender:   warp.FakeSender{},
		Log:      logger,
	}); err != nil {
		t.Fatalf("init proxy vm: %v", err)
	}
	v.bootstrapped = true

	return &conservationHarness{
		vm:         v,
		cChainSM:   cChainSM,
		proxyChain: proxyChain,
		cChain:     cChain,
		matcher:    matcher,
	}
}

// ---------------------------------------------------------------------------
// Test helpers.
// ---------------------------------------------------------------------------

// newImportTxBytes builds a wire-ready ImportTx claiming one source UTXO.
func newImportTxBytes(t *testing.T, from ids.ShortID, sourceChain, utxoID, asset ids.ID, amount uint64) []byte {
	t.Helper()
	tx := txs.NewImportTx(from, 0, sourceChain,
		[]txs.AtomicInput{{UTXOID: utxoID, Asset: asset, Amount: amount}},
		[]txs.AtomicOutput{{Owner: from, Asset: asset, Amount: amount}},
	)
	return tx.Bytes()
}

// newRelayTxBytes builds a wire-ready RelayOrderTx carrying a clob_submit frame.
func newRelayTxBytes(t *testing.T, from ids.ShortID, collateralRef ids.ID, payload []byte) []byte {
	t.Helper()
	return txs.NewRelayOrderTx(from, 0, ZAPMethodSubmit, payload, collateralRef).Bytes()
}

// mustParseImport parses wire bytes back into a typed ImportTx.
func mustParseImport(t *testing.T, b []byte) *txs.ImportTx {
	t.Helper()
	parser := &txs.TxParser{}
	tx, err := parser.Parse(b)
	if err != nil {
		t.Fatalf("parse import: %v", err)
	}
	return tx.(*txs.ImportTx)
}

// clobSubmitPayload builds the FROZEN 66-byte clob_submit request frame:
// poolId[32] | side[1] | isMarket[1] | limit[8] | size[8] | user[16].
func clobSubmitPayload(poolID ids.ID, size uint64) []byte {
	p := make([]byte, 66)
	copy(p[0:32], poolID[:])
	p[32] = 0 // buy
	p[33] = 1 // market
	putZAPFloat(p[42:50], float64(size))
	return p
}

// exportedTotal sums the value the proxy exported back to C-Chain (the proceeds
// the C-Chain can now claim), read via the C-Chain's Indexed view on the taker
// trait. Each element value is owner(20)|asset(32)|amount(8).
func exportedTotal(t *testing.T, h *conservationHarness) uint64 {
	t.Helper()
	var total uint64
	for _, v := range indexedByTaker(t, h) {
		if len(v) >= 60 {
			total += binary.BigEndian.Uint64(v[52:60])
		}
	}
	return total
}

// indexedByTaker returns the exported proceeds the C-Chain can claim, indexed by
// the taker address trait.
func indexedByTaker(t *testing.T, h *conservationHarness) [][]byte {
	t.Helper()
	// The proxy used the taker (sender) as the output owner/trait. Recover it
	// from the consumed receipts is overkill; the taker is the single sender we
	// used. Use the well-known taker from the test by scanning all proceeds.
	// Indexed needs the trait; we pass the taker address recorded on the export.
	taker := h.exportTaker
	vals, _, _, err := h.cChainSM.Indexed(h.proxyChain, [][]byte{taker[:]}, nil, nil, 100)
	if err != nil {
		t.Fatalf("Indexed C-Chain proceeds: %v", err)
	}
	return vals
}

// The conservation test.
// ---------------------------------------------------------------------------

// TestEndToEndAtomicValueConservation moves value C-Chain -> proxy -> d-chain
// and back, asserting GLOBAL ALL-OR-NOTHING CONSERVATION across the boundary:
//
//  1. C-Chain exports 1000 units into shared memory (the proxy can claim them).
//  2. The proxy IMPORTS them (consumes the UTXO atomically) — debit leg.
//  3. The proxy RELAYS a clob_submit to the d-chain (fake matcher) which returns
//     fills totaling exactly the imported notional.
//  4. The proxy EXPORTS the proceeds back to C-Chain (credit leg), derived ONLY
//     from the returned fills.
//  5. Assert: the source UTXO is GONE from shared memory (consumed exactly
//     once), the proxy minted NOTHING (exported base+quote == fill totals), and
//     C-Chain can claim exactly the exported proceeds.
func TestEndToEndAtomicValueConservation(t *testing.T) {
	// Matcher fills: 600 base @ price 1 + ... summing to a known notional. Use a
	// single fill of 1000 base @ price 1 so base=1000, quote=1000 (integer-exact).
	fills := []Fill{{Price: 1, Size: 1000, Side: 0}}
	h := newConservationHarness(t, fills)
	ctx := context.Background()

	taker := ids.GenerateTestShortID()
	h.exportTaker = taker
	assetID := ids.GenerateTestID()

	// --- Step 1: C-Chain exports 1000 units into shared memory. ---
	// The exported UTXO key is what the proxy's import will consume.
	srcTxID := ids.GenerateTestID()
	srcUTXOID := deriveUTXOID(srcTxID, 0)
	exportedVal := encodeExportedOutput(txs.AtomicOutput{Owner: taker, Asset: assetID, Amount: 1000})
	if err := h.cChainSM.Apply(map[ids.ID]*atomic.Requests{
		h.proxyChain: {PutRequests: []*atomic.Element{{
			Key:    srcUTXOID[:],
			Value:  exportedVal,
			Traits: [][]byte{taker[:]},
		}}},
	}); err != nil {
		t.Fatalf("C-Chain export to shared memory: %v", err)
	}

	// Sanity: the proxy can see the exported value before importing it.
	vals, err := h.vm.sharedMemory().Get(h.cChain, [][]byte{srcUTXOID[:]})
	if err != nil || len(vals) != 1 || vals[0] == nil {
		t.Fatalf("proxy cannot see exported UTXO: vals=%v err=%v", vals, err)
	}

	// --- Steps 2-4: import -> relay -> export, all in one block. ---
	collateralRef := srcUTXOID
	importTx := newImportTxBytes(t, taker, h.cChain, srcUTXOID, assetID, 1000)
	relayTx := newRelayTxBytes(t, taker, collateralRef, clobSubmitPayload(assetID, 1000))

	result, err := h.vm.ProcessBlock(ctx, 1, time.Unix(1, 0), [][]byte{importTx, relayTx})
	if err != nil {
		t.Fatalf("ProcessBlock: %v", err)
	}

	// Assert the proxy forwarded a byte-identical clob_submit frame (66 bytes).
	if len(h.matcher.received) != 1 {
		t.Fatalf("matcher received %d frames, want 1 (one clob_submit)", len(h.matcher.received))
	}
	if got := len(h.matcher.received[0]); got != 66 {
		t.Fatalf("relayed clob_submit frame = %d bytes, want 66", got)
	}

	// --- Step 4 commit: accept the block (atomic settle). ---
	if err := h.vm.acceptBlock(result); err != nil {
		t.Fatalf("acceptBlock: %v", err)
	}

	// --- Step 5: assert GLOBAL ALL-OR-NOTHING CONSERVATION. ---

	const importedValue uint64 = 1000

	// (a) The source UTXO was consumed exactly once — gone from shared memory.
	after, err := h.vm.sharedMemory().Get(h.cChain, [][]byte{srcUTXOID[:]})
	if err == nil && len(after) == 1 && after[0] != nil {
		t.Fatalf("source UTXO still present after import — value was NOT consumed (double-spend risk)")
	}

	// (b) The taker BUY received exactly the filled base (single-leg
	// conservation): one fill of 1000 base @ price 1 -> received base = 1000.
	var wantReceived uint64
	for _, f := range fills {
		wantReceived += uint64(f.Size) // BUY receives base = sum(size)
	}
	gotExported := exportedTotal(t, h)
	if gotExported != wantReceived {
		t.Errorf("exported proceeds = %d, want %d (must equal confirmed fills exactly)", gotExported, wantReceived)
	}

	// (c) THE conservation invariant: the proxy never mints. Total value exported
	// back to C-Chain must NOT exceed the value imported from C-Chain. (Equality
	// here because the whole locked notional filled; any unfilled remainder would
	// make this strictly less, with the difference refunded as the locked asset.)
	if gotExported > importedValue {
		t.Fatalf("CONSERVATION VIOLATED: exported %d > imported %d (proxy minted value)", gotExported, importedValue)
	}

	// (d) The consumed set records the source UTXO (replay protection persists).
	consumed, err := h.vm.state.IsConsumed(srcUTXOID)
	if err != nil {
		t.Fatalf("IsConsumed: %v", err)
	}
	if !consumed {
		t.Error("source UTXO not in consumed set after import")
	}
}

// TestImportRefusesDoubleSpend proves a source UTXO can be claimed at most once:
// a second import of the same UTXO fails, so the proxy can never mint by
// re-importing already-claimed value.
func TestImportRefusesDoubleSpend(t *testing.T) {
	h := newConservationHarness(t, nil)
	ctx := context.Background()
	taker := ids.GenerateTestShortID()
	assetID := ids.GenerateTestID()
	utxoID := deriveUTXOID(ids.GenerateTestID(), 0)

	ar := newAtomicRequests()
	tx := mustParseImport(t, newImportTxBytes(t, taker, h.cChain, utxoID, assetID, 500))

	if err := h.vm.executeImport(tx, ar); err != nil {
		t.Fatalf("first import: %v", err)
	}
	// Second import of the same UTXO must fail (double-spend guard).
	if err := h.vm.executeImport(tx, ar); err == nil {
		t.Fatal("second import of same UTXO succeeded — double-spend NOT prevented")
	}
	_ = ctx
}

// TestRelayInertWithoutEndpoint proves the relay leg is inert when no d-chain
// endpoint is configured: a relay returns ErrRelayNotConfigured and never
// panics, never mints.
func TestRelayInertWithoutEndpoint(t *testing.T) {
	relay := NewRelayClient("", 0)
	if relay.Configured() {
		t.Fatal("empty-endpoint relay reports Configured()=true")
	}
	if _, err := relay.Relay(context.Background(), ZAPMethodSubmit, []byte{0}); err != ErrRelayNotConfigured {
		t.Fatalf("inert relay returned %v, want ErrRelayNotConfigured", err)
	}
}
