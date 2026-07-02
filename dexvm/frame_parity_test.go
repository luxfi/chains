// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"bytes"
	"testing"

	"github.com/luxfi/dex/pkg/zapwire"
	"github.com/luxfi/ids"

	"github.com/luxfi/chains/dexvm/txs"
)

// frame_parity_test.go is the CROSS-MODULE oracle: it pins the proxy's exact-integer
// ZAP frames BYTE-IDENTICAL to dex v1.14.0's frozen zapwire codec (the venue's own
// source of truth). An interop mismatch is the whole failure mode of the wire change
// — the proxy must produce/consume the SAME bytes the d-chain gateway speaks — so we
// assert it against the canonical package directly, not a re-declared copy.
//
// zapwire is a PURE-GO stdlib leaf (no cgo/GPU matcher), so the proxy can import it
// in a test even under CGO_ENABLED=0. The production proxy re-declares the frozen
// constants (relay.go / vm.go) to stay a clean leaf over luxfi/rpc; this test is the
// guard that the re-declaration never drifts from the canonical frame.

// TestFrameParity_Constants pins the wire constants to zapwire's.
func TestFrameParity_Constants(t *testing.T) {
	if PriceScale != zapwire.PriceScale {
		t.Fatalf("PriceScale %d != zapwire.PriceScale %d — the fixed-point grid diverged", PriceScale, zapwire.PriceScale)
	}
	if FillWireSize != zapwire.FillWireSize {
		t.Fatalf("FillWireSize %d != zapwire.FillWireSize %d — the fill frame diverged", FillWireSize, zapwire.FillWireSize)
	}
	if ZAPMethodSubmit == "" || ZAPMethodPlace == "" {
		t.Fatalf("empty ZAP method names")
	}
}

// TestFrameParity_PlaceFrame proves encodeCLOBPlace emits the EXACT bytes
// zapwire.EncodePlace does for the same order, and that the venue's DecodePlace reads
// back the exact-integer fixed-point price and base-unit size.
func TestFrameParity_PlaceFrame(t *testing.T) {
	var pool [32]byte
	for i := range pool {
		pool[i] = byte(i + 1)
	}
	const humanPrice = uint64(10)
	const size = uint64(5)

	from := ids.ShortID{0xAB, 0xCD, 0xEF, 0x01, 0x02}
	tx := txs.NewPlaceOrderTx(from, 0, pool, zapwire.SideSell, humanPrice, size)
	maker := tx.Sender()

	got := encodeCLOBPlace(tx)
	// The venue reads the price field as the fixed-point ×PriceScale PriceInt grid
	// value, so the proxy scales the whole human price onto it: humanPrice*PriceScale.
	want := zapwire.EncodePlace(pool, zapwire.SideSell, humanPrice*PriceScale, size, string(maker[:16]))
	if !bytes.Equal(got, want) {
		t.Fatalf("place frame != zapwire.EncodePlace\n got=%x\nwant=%x", got, want)
	}

	// The venue's own decoder reads back exact integers (no float on the wire).
	dPool, dSide, dPrice, dSize, _, err := zapwire.DecodePlace(got)
	if err != nil {
		t.Fatalf("zapwire.DecodePlace(proxy frame): %v", err)
	}
	if dPool != pool || dSide != zapwire.SideSell {
		t.Fatalf("decoded pool/side mismatch: side=%d", dSide)
	}
	if dPrice != humanPrice*PriceScale {
		t.Fatalf("decoded price=%d, want %d (fixed-point ×PriceScale)", dPrice, humanPrice*PriceScale)
	}
	if dSize != size {
		t.Fatalf("decoded size=%d, want %d (atomic base units)", dSize, size)
	}
}

// TestFrameParity_SubmitFrame proves the 66-byte submit frame the proxy's test
// harness builds (clobSubmitPayload) is byte-identical to zapwire.EncodeSubmit for a
// market order — the exact-integer frame the 0x9999 EVM surface and the native venue
// both speak.
func TestFrameParity_SubmitFrame(t *testing.T) {
	var pool [32]byte
	for i := range pool {
		pool[i] = byte(0x40 + i)
	}
	const size = uint64(1234)

	got := clobSubmitPayload(ids.ID(pool), size)
	// clobSubmitPayload builds a market BUY with limit 0 and empty user, size in base
	// units — the same fields, byte-for-byte, as the venue's EncodeSubmit.
	want := zapwire.EncodeSubmit(pool, zapwire.SideBuy, true, 0, size, "")
	if !bytes.Equal(got, want) {
		t.Fatalf("submit frame != zapwire.EncodeSubmit\n got=%x\nwant=%x", got, want)
	}

	_, dSide, dMarket, dLimit, dSize, _, err := zapwire.DecodeSubmit(got)
	if err != nil {
		t.Fatalf("zapwire.DecodeSubmit(proxy frame): %v", err)
	}
	if dSide != zapwire.SideBuy || !dMarket || dLimit != 0 || dSize != size {
		t.Fatalf("decoded submit mismatch: side=%d market=%v limit=%d size=%d", dSide, dMarket, dLimit, dSize)
	}
}

// TestFrameParity_FillWire proves the fill response wire round-trips byte-identically
// between the proxy's DecodeFills and the venue's zapwire.EncodeFills/DecodeFills:
// price is fixed-point ×PriceScale, size is atomic base units, both EXACT uint64s.
func TestFrameParity_FillWire(t *testing.T) {
	// A stream with a fractional-flooring price to exercise the fixed-point grid.
	proxyFills := []Fill{
		{Price: fp(2), Size: 100, Side: zapwire.SideBuy},
		{Price: fp(1.5), Size: 4, Side: zapwire.SideSell},
	}

	// (a) proxy-encoded wire decodes identically under the venue's codec.
	wire := encodeFillsWire(proxyFills)
	venueFills, err := zapwire.DecodeFills(wire)
	if err != nil {
		t.Fatalf("zapwire.DecodeFills(proxy wire): %v", err)
	}
	if len(venueFills) != len(proxyFills) {
		t.Fatalf("fill count %d != %d", len(venueFills), len(proxyFills))
	}
	for i, f := range proxyFills {
		if venueFills[i].Price != f.Price || venueFills[i].Size != f.Size || venueFills[i].TakerSide != f.Side {
			t.Fatalf("fill %d mismatch: venue=%+v proxy=%+v", i, venueFills[i], f)
		}
	}

	// (b) venue-encoded wire decodes identically under the proxy's DecodeFills — the
	// real direction: the venue returns fills, the proxy consumes them.
	venueWire := zapwire.EncodeFills([]zapwire.Fill{
		{Price: fp(2), Size: 100, TakerSide: zapwire.SideBuy},
		{Price: fp(1.5), Size: 4, TakerSide: zapwire.SideSell},
	})
	if !bytes.Equal(venueWire, wire) {
		t.Fatalf("fill wire not byte-identical\n proxy=%x\n venue=%x", wire, venueWire)
	}
	back, err := DecodeFills(venueWire)
	if err != nil {
		t.Fatalf("proxy DecodeFills(venue wire): %v", err)
	}
	for i, f := range proxyFills {
		if back[i].Price != f.Price || back[i].Size != f.Size || back[i].Side != f.Side {
			t.Fatalf("proxy round-trip fill %d mismatch: %+v vs %+v", i, back[i], f)
		}
	}
}
