// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"bytes"
	"testing"

	"github.com/luxfi/ids"
)

// TestGBlockWireRoundTrip proves the native-ZAP block wire round-trips every
// field byte-for-byte (parentID, height, timestamp, payload).
func TestGBlockWireRoundTrip(t *testing.T) {
	parentID := ids.ID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	const height = uint64(0xDEADBEEF)
	const ts = int64(1_700_000_000)
	payload := []byte("graph-block-payload")

	raw := marshalGBlock(parentID, height, ts, payload)
	gotParent, gotHeight, gotTS, gotPayload, err := parseGBlock(raw)
	if err != nil {
		t.Fatalf("parseGBlock: %v", err)
	}
	if gotParent != parentID {
		t.Errorf("parentID: got %x, want %x", gotParent, parentID)
	}
	if gotHeight != height {
		t.Errorf("height: got %d, want %d", gotHeight, height)
	}
	if gotTS != ts {
		t.Errorf("timestamp: got %d, want %d", gotTS, ts)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload: got %q, want %q", gotPayload, payload)
	}

	// empty payload (genesis-like) round-trips too.
	raw0 := marshalGBlock(ids.Empty, 0, 0, nil)
	p0, h0, t0, pay0, err := parseGBlock(raw0)
	if err != nil {
		t.Fatalf("parseGBlock(empty): %v", err)
	}
	if p0 != ids.Empty || h0 != 0 || t0 != 0 || len(pay0) != 0 {
		t.Errorf("empty block mismatch: %x %d %d %q", p0, h0, t0, pay0)
	}
}

// TestGBlockWireDeterminism proves the same logical block always serializes to
// identical bytes (so blockID = hash(wire) is stable across nodes/restarts).
func TestGBlockWireDeterminism(t *testing.T) {
	parentID := ids.ID{0xAB}
	a := marshalGBlock(parentID, 42, 99, []byte("x"))
	b := marshalGBlock(parentID, 42, 99, []byte("x"))
	if !bytes.Equal(a, b) {
		t.Fatalf("non-deterministic block wire:\n a=%x\n b=%x", a, b)
	}
	// a field change must change the bytes.
	c := marshalGBlock(parentID, 43, 99, []byte("x"))
	if bytes.Equal(a, c) {
		t.Fatal("height change did not change wire bytes")
	}
}

// TestGBlockWireTrailingRejected proves canonical framing: a trailing byte is
// refused.
func TestGBlockWireTrailingRejected(t *testing.T) {
	raw := marshalGBlock(ids.ID{0x01}, 1, 1, []byte("y"))
	tampered := append(append([]byte(nil), raw...), 0xFF)
	if _, _, _, _, err := parseGBlock(tampered); err == nil {
		t.Fatal("trailing byte accepted; want rejection")
	}
}
