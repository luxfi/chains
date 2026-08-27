// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

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
		Type:     TxRegisterCiphertext,
		Scheme:   "ckks-n14",
		Subject:  [32]byte{9, 8, 7, 6, 5, 4, 3, 2, 1},
		GasLimit: 81000,
		Nonce:    42,
		Payload:  []byte("register-ciphertext-payload"),
		Auth:     []byte("payer-public-key-bytes"),
		Sig:      []byte("payer-signature-bytes"),
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
	if parsed.Type != tx.Type || parsed.Scheme != tx.Scheme ||
		parsed.GasLimit != tx.GasLimit || parsed.Nonce != tx.Nonce ||
		parsed.Payer != tx.Payer || parsed.Subject != tx.Subject ||
		string(parsed.Payload) != string(tx.Payload) ||
		string(parsed.Auth) != string(tx.Auth) || string(parsed.Sig) != string(tx.Sig) {
		t.Fatalf("field mismatch after round-trip:\n in =%+v\n out=%+v", tx, parsed)
	}
}

// TestWireSigningBytesArePrefix proves the payer's signature covers a genuine
// byte-prefix of the full wire, so what is authenticated and what is
// transmitted cannot come apart.
func TestWireSigningBytesArePrefix(t *testing.T) {
	tx := sampleTx()
	signing := tx.SigningBytes()
	full := tx.Bytes()
	if len(signing) > len(full) || string(full[:len(signing)]) != string(signing) {
		t.Fatal("SigningBytes() is not a prefix of Bytes()")
	}
	n, err := zapLen(full)
	if err != nil {
		t.Fatalf("zapLen: %v", err)
	}
	if n != len(signing) {
		t.Fatalf("zapLen = %d, want the signing length %d", n, len(signing))
	}
}

// TestWireSigningBytesBindEveryField proves the signed preimage changes when
// ANY semantically-meaningful field changes — including Subject, which names
// the object the operation acts on. A field the signature did not cover could
// be swapped in flight.
func TestWireSigningBytesBindEveryField(t *testing.T) {
	base := string(sampleTx().SigningBytes())
	for name, mutate := range map[string]func(*Transaction){
		"Type":     func(tx *Transaction) { tx.Type = TxGrantPermit },
		"Scheme":   func(tx *Transaction) { tx.Scheme = "bfv-n13" },
		"Payer":    func(tx *Transaction) { tx.Payer[0] ^= 0xff },
		"Subject":  func(tx *Transaction) { tx.Subject[0] ^= 0xff },
		"GasLimit": func(tx *Transaction) { tx.GasLimit++ },
		"Nonce":    func(tx *Transaction) { tx.Nonce++ },
		"Payload":  func(tx *Transaction) { tx.Payload = append(tx.Payload, 'x') },
	} {
		tx := sampleTx()
		mutate(tx)
		if string(tx.SigningBytes()) == base {
			t.Fatalf("changing %s left the signed preimage unchanged", name)
		}
	}
	// Auth and Sig are deliberately EXCLUDED from the preimage: the signature
	// cannot cover itself.
	tx := sampleTx()
	tx.Auth = []byte("a-different-public-key")
	tx.Sig = []byte("a-different-signature")
	if string(tx.SigningBytes()) != base {
		t.Fatal("Auth/Sig must not appear in the signed preimage")
	}
}

// TestWireRejectsNonCanonical proves the canonical gate: zap follows the root
// offset and ignores unreferenced padding inside a message's declared size, so
// a twin buffer can decode to identical fields yet hash differently. Parse must
// reject any input that is not already byte-equal to its re-serialized form —
// exactly one byte-string authenticates per logical tx (no id-malleability).
func TestWireRejectsNonCanonical(t *testing.T) {
	tx := sampleTx()
	data := tx.Bytes()

	// Split the two concatenated zap messages (signing ‖ sig).
	n, err := zapLen(data)
	if err != nil {
		t.Fatalf("zapLen: %v", err)
	}

	// Craft a non-canonical twin: append 8 unreferenced bytes to the trailing
	// (sig) message and bump its declared size field so a naive
	// n+gm.Size()==len(data) trailing-bytes check still passes. The root offset
	// does not reference the padding, so the fields decode identically.
	sig := append([]byte(nil), data[n:]...)
	sig = append(sig, make([]byte, 8)...)
	binary.LittleEndian.PutUint32(sig[12:16], uint32(len(sig)))
	twin := append(append([]byte(nil), data[:n]...), sig...)

	if string(twin) == string(data) {
		t.Fatal("twin construction failed to differ from canonical")
	}
	if got := int(binary.LittleEndian.Uint32(twin[n+12 : n+16])); got != len(sig) {
		t.Fatalf("twin size field not bumped: got %d want %d", got, len(sig))
	}
	if _, err := ParseTransaction(twin); err == nil {
		t.Fatal("ParseTransaction accepted a non-canonical (padded) twin — id-malleability not closed")
	}
}

// TestWireParseRejectsTruncated confirms the parser fails closed on a short
// buffer rather than reading past the end.
func TestWireParseRejectsTruncated(t *testing.T) {
	data := sampleTx().Bytes()
	for _, cut := range []int{0, 4, zap.HeaderSize, len(data) - 1} {
		if _, err := ParseTransaction(data[:cut]); err == nil {
			t.Fatalf("ParseTransaction accepted truncated buffer of len %d", cut)
		}
	}
}

// TestWireParseRejectsTrailing confirms bytes appended after a complete
// transaction are refused rather than ignored.
func TestWireParseRejectsTrailing(t *testing.T) {
	data := append(sampleTx().Bytes(), 0xde, 0xad)
	if _, err := ParseTransaction(data); err == nil {
		t.Fatal("ParseTransaction accepted trailing bytes")
	}
}

// TestBlockWireRoundTrip proves a block serializes and re-parses with its
// transactions intact and its id unchanged.
func TestBlockWireRoundTrip(t *testing.T) {
	a := sampleTx()
	b := sampleTx()
	b.Nonce = 43
	b.Payload = []byte("second")
	blk := &Block{
		parentID:     ids.ID{1, 2, 3},
		height:       7,
		timestamp:    timeAt(1_700_000_000),
		transactions: []*Transaction{a, b},
	}
	blk.id = blk.computeID()

	parsed, err := parseBlock(nil, blk.Bytes())
	if err != nil {
		t.Fatalf("parseBlock: %v", err)
	}
	if parsed.id != blk.id {
		t.Fatalf("block id changed across the wire: %s != %s", parsed.id, blk.id)
	}
	if parsed.height != blk.height || parsed.parentID != blk.parentID ||
		!parsed.timestamp.Equal(blk.timestamp) {
		t.Fatalf("header mismatch:\n in =%+v\n out=%+v", blk, parsed)
	}
	if len(parsed.transactions) != 2 {
		t.Fatalf("got %d transactions, want 2", len(parsed.transactions))
	}
	for i, tx := range parsed.transactions {
		if tx.ID() != blk.transactions[i].ID() {
			t.Fatalf("transaction %d id changed across the wire", i)
		}
	}
}

// TestBlockWireRejectsTrailing confirms a block with appended bytes is refused.
func TestBlockWireRejectsTrailing(t *testing.T) {
	blk := &Block{parentID: ids.ID{1}, height: 1, timestamp: timeAt(1)}
	if _, err := parseBlock(nil, append(blk.Bytes(), 0xff)); err == nil {
		t.Fatal("parseBlock accepted trailing bytes")
	}
}
