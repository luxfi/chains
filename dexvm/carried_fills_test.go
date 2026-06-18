// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// carried_fills_test.go — executable spec for the carried-fills wire format (the
// RED #9 block/vertex format change). It pins:
//   - the codec round-trips byte-exactly (proposer encode -> validator decode);
//   - malformed/hostile sections are rejected at the boundary (no panic, no
//     impossible Fill into settlement);
//   - the BLOCK bytes carry fills through Bytes() -> parseBlock and the block id
//     commits to them (tamper detection);
//   - the VERTEX bytes carry fills through serialize -> deserialize and the vertex
//     id commits to them.

package dexvm

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// TestCarriedFills_CodecRoundTrip proves encode/decode is an exact inverse for a
// representative entry set (multiple txIndexes, multiple fills, a zero-fill entry).
func TestCarriedFills_CodecRoundTrip(t *testing.T) {
	in := []carriedFill{
		{txIndex: 1, fills: []Fill{{Price: 2, Size: 50, Side: 0}, {Price: 2, Size: 50, Side: 0}}},
		{txIndex: 3, fills: nil}, // explicit zero-fill (a failed/empty submit)
		{txIndex: 7, fills: []Fill{{Price: 1.5, Size: 4, Side: 1}}},
	}
	enc := encodeCarriedFills(in, nil)
	out, sig, consumed, err := decodeCarriedFills(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if consumed != len(enc) {
		t.Fatalf("consumed %d != section len %d", consumed, len(enc))
	}
	if sig != nil {
		t.Fatalf("expected empty reserved signature, got %d bytes", len(sig))
	}
	if len(out) != len(in) {
		t.Fatalf("entry count: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].txIndex != in[i].txIndex || len(out[i].fills) != len(in[i].fills) {
			t.Fatalf("entry %d mismatch: got %+v want %+v", i, out[i], in[i])
		}
		for j := range in[i].fills {
			if out[i].fills[j] != in[i].fills[j] {
				t.Fatalf("entry %d fill %d: got %+v want %+v", i, j, out[i].fills[j], in[i].fills[j])
			}
		}
	}

	// fillsForTx resolves entries; an absent txIndex returns (nil,false).
	if f, ok := fillsForTx(out, 1); !ok || len(f) != 2 {
		t.Fatalf("fillsForTx(1): ok=%v len=%d, want ok=true len=2", ok, len(f))
	}
	if f, ok := fillsForTx(out, 3); !ok || len(f) != 0 {
		t.Fatalf("fillsForTx(3) explicit zero-fill: ok=%v len=%d, want ok=true len=0", ok, len(f))
	}
	if _, ok := fillsForTx(out, 99); ok {
		t.Fatalf("fillsForTx(99): want absent, got present")
	}
}

// TestCarriedFills_ReservedSignatureRoundTrips proves the reserved fill-attestation
// field survives the codec (the trustless-path upgrade carries data here without a
// further wire-format change).
func TestCarriedFills_ReservedSignatureRoundTrips(t *testing.T) {
	sigIn := []byte("reserved-d-chain-fill-attestation-bytes")
	enc := encodeCarriedFills([]carriedFill{{txIndex: 0, fills: []Fill{{Price: 1, Size: 1, Side: 0}}}}, sigIn)
	_, sigOut, consumed, err := decodeCarriedFills(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if consumed != len(enc) {
		t.Fatalf("consumed %d != len %d", consumed, len(enc))
	}
	if string(sigOut) != string(sigIn) {
		t.Fatalf("reserved signature round-trip: got %q want %q", sigOut, sigIn)
	}
}

// TestCarriedFills_RejectsMalformed proves the decoder rejects hostile/truncated
// sections at the boundary (the SAME positivity/side invariant DecodeFills enforces
// on the ZAP wire) — so no impossible Fill ever reaches settlement and no
// over-allocation is possible.
func TestCarriedFills_RejectsMalformed(t *testing.T) {
	good := encodeCarriedFills([]carriedFill{{txIndex: 0, fills: []Fill{{Price: 1, Size: 1, Side: 0}}}}, nil)

	t.Run("truncated_header", func(t *testing.T) {
		if _, _, _, err := decodeCarriedFills([]byte{0, 0}); err == nil {
			t.Fatal("accepted a 2-byte section (need >=4 for the entry count)")
		}
	})
	t.Run("invalid_side", func(t *testing.T) {
		bad := make([]byte, len(good))
		copy(bad, good)
		// side byte = entryCount[4] + txIndex[4] + fillCount[4] + price[8] + size[8].
		bad[4+4+4+8+8] = 7
		if _, _, _, err := decodeCarriedFills(bad); err == nil {
			t.Fatal("accepted a fill with side byte 7 (must be 0 or 1)")
		}
	})
	t.Run("nonpositive_size", func(t *testing.T) {
		bad := make([]byte, len(good))
		copy(bad, good)
		binary.BigEndian.PutUint64(bad[4+4+4+8:4+4+4+16], 0) // size = 0.0
		if _, _, _, err := decodeCarriedFills(bad); err == nil {
			t.Fatal("accepted a fill with size 0 (must be finite and strictly positive)")
		}
	})
	t.Run("overlarge_entry_count", func(t *testing.T) {
		bad := make([]byte, 4)
		binary.BigEndian.PutUint32(bad, maxCarriedFillEntries+1)
		if _, _, _, err := decodeCarriedFills(bad); err == nil {
			t.Fatal("accepted an entry count above the bound (over-allocation guard)")
		}
	})
	t.Run("missing_signature_length", func(t *testing.T) {
		// A valid entry section but cut off before the sigLen field.
		bad := good[:len(good)-4]
		if _, _, _, err := decodeCarriedFills(bad); err == nil {
			t.Fatal("accepted a section missing the signature length")
		}
	})
}

// TestBlock_CarriedFillsRoundTripAndIDBinding proves a BLOCK serializes its carried
// fills and that parseBlock recovers them, and that the block id (hash of bytes)
// commits to the fills — a peer cannot swap the proposer's fills while keeping the
// same id.
func TestBlock_CarriedFillsRoundTripAndIDBinding(t *testing.T) {
	cvm := NewChainVM(log.NewNoOpLogger())

	var parent ids.ID
	b := &Block{
		vm:        cvm,
		parentID:  parent,
		height:    5,
		timestamp: time.Unix(1_700_000_000, 0),
		txs:       [][]byte{[]byte("tx-a"), []byte("tx-bb")},
		carriedFills: []carriedFill{
			{txIndex: 1, fills: []Fill{{Price: 2, Size: 50, Side: 0}}},
		},
	}
	wire := b.Bytes()

	parsed, err := parseBlock(cvm, wire)
	if err != nil {
		t.Fatalf("parseBlock: %v", err)
	}
	if parsed.height != b.height || !parsed.timestamp.Equal(b.timestamp) || len(parsed.txs) != len(b.txs) {
		t.Fatalf("header/txs round-trip mismatch: got h=%d ts=%v ntx=%d", parsed.height, parsed.timestamp, len(parsed.txs))
	}
	if len(parsed.carriedFills) != 1 || parsed.carriedFills[0].txIndex != 1 ||
		len(parsed.carriedFills[0].fills) != 1 || parsed.carriedFills[0].fills[0] != b.carriedFills[0].fills[0] {
		t.Fatalf("carried fills not preserved through block round-trip: %+v", parsed.carriedFills)
	}

	// ID binding: change ONE carried fill and the block id (hash of bytes) must
	// differ — the fills are committed, not malleable.
	b2 := *b
	b2.carriedFills = []carriedFill{{txIndex: 1, fills: []Fill{{Price: 2, Size: 999, Side: 0}}}}
	p1, _ := parseBlock(cvm, b.Bytes())
	p2, _ := parseBlock(cvm, b2.Bytes())
	if p1.id == p2.id {
		t.Fatalf("block id does NOT commit to carried fills: different fills produced the same id %x", p1.id[:8])
	}
}

// TestVertex_CarriedFillsRoundTripAndIDBinding proves a VERTEX serializes its
// carried fills, deserialize recovers them, and the vertex id commits to them.
func TestVertex_CarriedFillsRoundTripAndIDBinding(t *testing.T) {
	cvm := NewChainVM(log.NewNoOpLogger())

	v := &DexVertex{
		height:    3,
		epoch:     0,
		timestamp: time.Unix(1_650_000_000, 7),
		parents:   []ids.ID{{0x01}},
		rawTxs:    [][]byte{[]byte("raw-tx-1")},
		carriedFills: []carriedFill{
			{txIndex: 0, fills: []Fill{{Price: 3, Size: 9, Side: 1}}},
		},
		vm: cvm,
	}
	v.id = v.computeID()
	wire := serializeDexVertex(v)

	parsed, err := deserializeDexVertex(wire, cvm)
	if err != nil {
		t.Fatalf("deserializeDexVertex: %v", err)
	}
	if len(parsed.carriedFills) != 1 || parsed.carriedFills[0].fills[0] != v.carriedFills[0].fills[0] {
		t.Fatalf("carried fills not preserved through vertex round-trip: %+v", parsed.carriedFills)
	}
	// The recomputed id (deserialize calls computeID) must match the original — the
	// fills are part of the committed id.
	if parsed.id != v.id {
		t.Fatalf("vertex id mismatch after round-trip: got %x want %x", parsed.id[:8], v.id[:8])
	}

	// Tamper: a vertex identical except for one carried fill must have a different id.
	tampered := &DexVertex{
		height:       v.height,
		epoch:        v.epoch,
		timestamp:    v.timestamp,
		parents:      v.parents,
		rawTxs:       v.rawTxs,
		carriedFills: []carriedFill{{txIndex: 0, fills: []Fill{{Price: 3, Size: 9999, Side: 1}}}},
	}
	if tampered.computeID() == v.id {
		t.Fatalf("vertex id does NOT commit to carried fills: different fills produced the same id %x", v.id[:8])
	}
}
