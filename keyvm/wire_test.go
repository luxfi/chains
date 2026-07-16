// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// sampleTx is a fully-populated transaction whose every field is non-empty, so
// the canonical round-trip exercises every offset.
func sampleTx() *Transaction {
	tx := &Transaction{
		Type:      TxRegisterKey,
		Algorithm: "ml-dsa-65",
		KeyID:     ids.ID{9, 8, 7, 6, 5, 4, 3, 2, 1},
		GasLimit:  21000,
		Nonce:     42,
		Payload:   []byte("register-key-payload"),
		Auth:      []byte("payer-public-key-bytes"),
		Sig:       []byte("payer-signature-bytes"),
	}
	copy(tx.Payer[:], []byte("payer-address-20byte"))
	return tx
}

// TestWireCanonicalRoundTrip proves Bytes()→ParseTransaction is a faithful,
// idempotent round-trip and that the id is the content hash of the canonical
// wire (id == sha256(Bytes())).
func TestWireCanonicalRoundTrip(t *testing.T) {
	tx := sampleTx()
	data := tx.Bytes()

	parsed, err := ParseTransaction(data)
	if err != nil {
		t.Fatalf("ParseTransaction(canonical) failed: %v", err)
	}

	if got := parsed.Bytes(); string(got) != string(data) {
		t.Fatalf("re-serialization not canonical: parsed.Bytes() != input\n in =%x\n out=%x", data, got)
	}
	if want := ids.ID(sha256.Sum256(data)); parsed.ID() != want {
		t.Fatalf("id != sha256(Bytes()): got %s want %s", parsed.ID(), want)
	}

	// Field fidelity across the seam.
	if parsed.Type != tx.Type || parsed.Algorithm != tx.Algorithm ||
		parsed.GasLimit != tx.GasLimit || parsed.Nonce != tx.Nonce ||
		parsed.Payer != tx.Payer || parsed.KeyID != tx.KeyID ||
		string(parsed.Payload) != string(tx.Payload) ||
		string(parsed.Auth) != string(tx.Auth) || string(parsed.Sig) != string(tx.Sig) {
		t.Fatalf("field mismatch after round-trip:\n in =%+v\n out=%+v", tx, parsed)
	}
}

// TestWireRejectsNonCanonical is the M1 regression guard: zap follows the root
// offset and ignores unreferenced padding inside a message's declared size, so a
// twin buffer can decode to identical fields yet hash differently. The canonical
// gate must reject any input that is not already byte-equal to its re-serialized
// form — exactly one byte-string authenticates per logical tx (no id-malleability).
func TestWireRejectsNonCanonical(t *testing.T) {
	tx := sampleTx()
	data := tx.Bytes()

	// Split the two concatenated zap messages (signing ‖ sig).
	n, err := zapLen(data)
	if err != nil {
		t.Fatalf("zapLen: %v", err)
	}

	// Craft a non-canonical twin: append 8 unreferenced bytes to the trailing
	// (sig) message and bump its declared size field so the old
	// n+gm.Size()==len(data) trailing-bytes check still passes. The root offset
	// does not reference the padding, so the fields decode identically.
	sig := append([]byte(nil), data[n:]...)
	sig = append(sig, make([]byte, 8)...)
	binary.LittleEndian.PutUint32(sig[12:16], uint32(len(sig)))
	twin := append(append([]byte(nil), data[:n]...), sig...)

	if string(twin) == string(data) {
		t.Fatal("twin construction failed to differ from canonical")
	}

	// Sanity: the twin's trailing sub-message still self-reports the padded size
	// (so a naive size==len check would accept it) — the property M1 closes.
	if got := int(binary.LittleEndian.Uint32(twin[n+12 : n+16])); got != len(sig) {
		t.Fatalf("twin size field not bumped: got %d want %d", got, len(sig))
	}

	if _, err := ParseTransaction(twin); err == nil {
		t.Fatal("ParseTransaction accepted a non-canonical (padded) twin — id-malleability not closed")
	}
}

// TestWireParseRejectsTruncated confirms the parser fails closed on a short buffer.
func TestWireParseRejectsTruncated(t *testing.T) {
	data := sampleTx().Bytes()
	for _, cut := range []int{0, 4, zap.HeaderSize, len(data) - 1} {
		if _, err := ParseTransaction(data[:cut]); err == nil {
			t.Fatalf("ParseTransaction accepted truncated buffer of len %d", cut)
		}
	}
}
