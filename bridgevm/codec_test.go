// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"bytes"
	"testing"
	"time"

	"github.com/luxfi/ids"
)

func TestBridgeRequest_RoundTrip(t *testing.T) {
	orig := &BridgeRequest{
		ID:            ids.ID{0x01, 0x02, 0x03},
		SourceChain:   "ethereum",
		DestChain:     "lux-c-chain",
		Asset:         ids.ID{0xAA, 0xBB},
		Amount:        1_000_000_000,
		Recipient:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
		SourceTxID:    ids.ID{0xCC, 0xDD},
		Confirmations: 12,
		Status:        "pending",
		MPCSignatures: [][]byte{
			{0x11, 0x22, 0x33},
			{0x44, 0x55, 0x66, 0x77, 0x88},
		},
		CreatedAt: time.Unix(1717545600, 12345),
	}

	encoded, err := marshalBridgeRequest(orig)
	if err != nil {
		t.Fatalf("marshalBridgeRequest: %v", err)
	}

	decoded := &BridgeRequest{}
	off, err := unmarshalBridgeRequest(encoded, 0, decoded)
	if err != nil {
		t.Fatalf("unmarshalBridgeRequest: %v", err)
	}
	if off != len(encoded) {
		t.Errorf("trailing bytes: off=%d len=%d", off, len(encoded))
	}

	if decoded.ID != orig.ID {
		t.Errorf("ID: got %v, want %v", decoded.ID, orig.ID)
	}
	if decoded.SourceChain != orig.SourceChain {
		t.Errorf("SourceChain: got %q, want %q", decoded.SourceChain, orig.SourceChain)
	}
	if decoded.DestChain != orig.DestChain {
		t.Errorf("DestChain: got %q, want %q", decoded.DestChain, orig.DestChain)
	}
	if decoded.Asset != orig.Asset {
		t.Errorf("Asset: got %v, want %v", decoded.Asset, orig.Asset)
	}
	if decoded.Amount != orig.Amount {
		t.Errorf("Amount: got %d, want %d", decoded.Amount, orig.Amount)
	}
	if !bytes.Equal(decoded.Recipient, orig.Recipient) {
		t.Errorf("Recipient: got %x, want %x", decoded.Recipient, orig.Recipient)
	}
	if decoded.SourceTxID != orig.SourceTxID {
		t.Errorf("SourceTxID: got %v, want %v", decoded.SourceTxID, orig.SourceTxID)
	}
	if decoded.Confirmations != orig.Confirmations {
		t.Errorf("Confirmations: got %d, want %d", decoded.Confirmations, orig.Confirmations)
	}
	if decoded.Status != orig.Status {
		t.Errorf("Status: got %q, want %q", decoded.Status, orig.Status)
	}
	if len(decoded.MPCSignatures) != len(orig.MPCSignatures) {
		t.Fatalf("MPCSignatures len: got %d, want %d", len(decoded.MPCSignatures), len(orig.MPCSignatures))
	}
	for i := range orig.MPCSignatures {
		if !bytes.Equal(decoded.MPCSignatures[i], orig.MPCSignatures[i]) {
			t.Errorf("MPCSignatures[%d]: got %x, want %x", i, decoded.MPCSignatures[i], orig.MPCSignatures[i])
		}
	}
	if !decoded.CreatedAt.Equal(orig.CreatedAt) {
		t.Errorf("CreatedAt: got %v, want %v", decoded.CreatedAt, orig.CreatedAt)
	}
}

func TestBlock_RoundTrip(t *testing.T) {
	nodeA := ids.NodeID{0x0A}
	nodeB := ids.NodeID{0x0B}
	nodeC := ids.NodeID{0x0C}

	orig := &Block{
		ParentID_:      ids.ID{0xFF, 0xEE},
		BlockHeight:    42,
		BlockTimestamp: 1717545600,
		BridgeRequests: []*BridgeRequest{
			{
				ID:            ids.ID{0x01},
				SourceChain:   "eth",
				DestChain:     "lux",
				Asset:         ids.ID{0x02},
				Amount:        100,
				Recipient:     []byte{0xAB},
				SourceTxID:    ids.ID{0x03},
				Confirmations: 6,
				Status:        "completed",
				MPCSignatures: [][]byte{{0x99}},
				CreatedAt:     time.Unix(1717545500, 0),
			},
			{
				ID:            ids.ID{0x04},
				SourceChain:   "btc",
				DestChain:     "lux",
				Asset:         ids.ID{0x05},
				Amount:        200,
				Recipient:     []byte{0xCD, 0xEF},
				SourceTxID:    ids.ID{0x06},
				Confirmations: 3,
				Status:        "pending",
				MPCSignatures: nil,
				CreatedAt:     time.Unix(1717545550, 0),
			},
		},
		MPCSignatures: map[ids.NodeID][]byte{
			nodeA: {0xA1, 0xA2},
			nodeB: {0xB1},
			nodeC: {0xC1, 0xC2, 0xC3},
		},
	}

	encoded, err := marshalBlock(orig)
	if err != nil {
		t.Fatalf("marshalBlock: %v", err)
	}

	decoded := &Block{}
	if err := unmarshalBlock(encoded, decoded); err != nil {
		t.Fatalf("unmarshalBlock: %v", err)
	}

	if decoded.ParentID_ != orig.ParentID_ {
		t.Errorf("ParentID_: got %v, want %v", decoded.ParentID_, orig.ParentID_)
	}
	if decoded.BlockHeight != orig.BlockHeight {
		t.Errorf("BlockHeight: got %d, want %d", decoded.BlockHeight, orig.BlockHeight)
	}
	if decoded.BlockTimestamp != orig.BlockTimestamp {
		t.Errorf("BlockTimestamp: got %d, want %d", decoded.BlockTimestamp, orig.BlockTimestamp)
	}
	if len(decoded.BridgeRequests) != len(orig.BridgeRequests) {
		t.Fatalf("BridgeRequests len: got %d, want %d", len(decoded.BridgeRequests), len(orig.BridgeRequests))
	}
	for i, want := range orig.BridgeRequests {
		got := decoded.BridgeRequests[i]
		if got.ID != want.ID || got.SourceChain != want.SourceChain || got.Amount != want.Amount {
			t.Errorf("BridgeRequests[%d]: got %+v, want %+v", i, got, want)
		}
	}
	if len(decoded.MPCSignatures) != len(orig.MPCSignatures) {
		t.Fatalf("MPCSignatures len: got %d, want %d", len(decoded.MPCSignatures), len(orig.MPCSignatures))
	}
	for nid, want := range orig.MPCSignatures {
		got, ok := decoded.MPCSignatures[nid]
		if !ok {
			t.Errorf("MPCSignatures[%s]: missing", nid)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("MPCSignatures[%s]: got %x, want %x", nid, got, want)
		}
	}
}

func TestBlock_Deterministic(t *testing.T) {
	// Encoding two semantically-identical blocks must yield byte-identical
	// output, even when MPCSignatures is populated in different insertion
	// orders. Map iteration order in Go is non-deterministic; marshalBlock
	// must sort by NodeID before serializing.
	build := func(order []ids.NodeID) *Block {
		b := &Block{
			ParentID_:      ids.ID{0xFF},
			BlockHeight:    1,
			BlockTimestamp: 1,
			MPCSignatures:  make(map[ids.NodeID][]byte, len(order)),
		}
		// Use the NodeID byte as the signature so the values are deterministic
		// regardless of insertion order.
		for _, nid := range order {
			b.MPCSignatures[nid] = []byte{nid[0]}
		}
		return b
	}

	a := build([]ids.NodeID{{0x03}, {0x01}, {0x02}})
	b := build([]ids.NodeID{{0x01}, {0x02}, {0x03}})

	encA, err := marshalBlock(a)
	if err != nil {
		t.Fatalf("marshalBlock(a): %v", err)
	}
	encB, err := marshalBlock(b)
	if err != nil {
		t.Fatalf("marshalBlock(b): %v", err)
	}
	if !bytes.Equal(encA, encB) {
		t.Errorf("non-deterministic encoding: %x vs %x", encA, encB)
	}
}

func TestBlock_RejectsShortBuffer(t *testing.T) {
	if err := unmarshalBlock(nil, &Block{}); err == nil {
		t.Errorf("expected error for empty buffer")
	}
	if err := unmarshalBlock([]byte{0x00}, &Block{}); err == nil {
		t.Errorf("expected error for short buffer")
	}
}

func TestBlock_RejectsTrailingBytes(t *testing.T) {
	enc, err := marshalBlock(&Block{})
	if err != nil {
		t.Fatalf("marshalBlock: %v", err)
	}
	enc = append(enc, 0xAB)
	if err := unmarshalBlock(enc, &Block{}); err == nil {
		t.Errorf("expected error for trailing bytes")
	}
}

func TestBlock_RejectsNil(t *testing.T) {
	if _, err := marshalBlock(nil); err == nil {
		t.Errorf("expected error for nil block")
	}
	if err := unmarshalBlock([]byte{0x00}, nil); err == nil {
		t.Errorf("expected error for nil block receiver")
	}
}

func TestBridgeRequest_RejectsNil(t *testing.T) {
	if _, err := marshalBridgeRequest(nil); err == nil {
		t.Errorf("expected error for nil request")
	}
	if _, err := unmarshalBridgeRequest([]byte{0x00}, 0, nil); err == nil {
		t.Errorf("expected error for nil request receiver")
	}
}
