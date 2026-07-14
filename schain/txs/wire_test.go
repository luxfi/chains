// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// wire_test.go — the native-ZAP wire-codec proof for every S-Chain tx type. Each
// test builds a tx, serializes it through the ZAP codec, parses it back, and
// asserts EVERY field survives byte-for-byte, that the wire is stable through a
// round trip (parsed.Bytes() == orig.Bytes()), that the TxID is a deterministic
// pure function of the fields, and that the parser rejects trailing bytes. This
// is the >1-validator safety property: the same logical tx always yields the
// same wire and therefore the same content-addressed id on every node.
package txs

import (
	"bytes"
	"errors"
	"testing"

	"github.com/luxfi/ids"
)

// TestPutManifestWireRoundTrip proves a PutManifestTx round-trips through the ZAP
// codec with every field intact and a stable wire/id.
func TestPutManifestWireRoundTrip(t *testing.T) {
	orig := NewPutManifestTx(
		"bucket-A",
		"path/to/object.bin",
		[]string{"3,01f2a", "3,02b7c", "4,0099"},
		1<<40, // 1 TiB — exercises the full int64 range, not a small value
		"9bec6f3c1e5d4a2b8f0e7c6d5a4b3c2d",
	)

	parser := &TxParser{}
	parsed, err := parser.Parse(orig.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Type() != TxPutManifest {
		t.Fatalf("parsed type = %v, want TxPutManifest", parsed.Type())
	}
	pm, ok := parsed.(*PutManifestTx)
	if !ok {
		t.Fatalf("parsed concrete type = %T, want *PutManifestTx", parsed)
	}

	if pm.Bucket != orig.Bucket {
		t.Errorf("Bucket = %q, want %q", pm.Bucket, orig.Bucket)
	}
	if pm.Object != orig.Object {
		t.Errorf("Object = %q, want %q", pm.Object, orig.Object)
	}
	if len(pm.FileIDs) != len(orig.FileIDs) {
		t.Fatalf("FileIDs len = %d, want %d", len(pm.FileIDs), len(orig.FileIDs))
	}
	for i := range orig.FileIDs {
		if pm.FileIDs[i] != orig.FileIDs[i] {
			t.Errorf("FileIDs[%d] = %q, want %q", i, pm.FileIDs[i], orig.FileIDs[i])
		}
	}
	if pm.Size != orig.Size {
		t.Errorf("Size = %d, want %d", pm.Size, orig.Size)
	}
	if pm.ETag != orig.ETag {
		t.Errorf("ETag = %q, want %q", pm.ETag, orig.ETag)
	}
	if pm.ID() != orig.ID() {
		t.Errorf("TxID = %s, want %s", pm.ID(), orig.ID())
	}
	if !bytes.Equal(pm.Bytes(), orig.Bytes()) {
		t.Errorf("wire not stable through round trip")
	}
}

// TestPutManifestSingleFile proves the smallest legal manifest (one file blob)
// round-trips — the boundary Verify requires (ErrNoFileIDs below it).
func TestPutManifestSingleFile(t *testing.T) {
	orig := NewPutManifestTx("b", "o", []string{"1,0"}, 0, "")
	parsed, err := (&TxParser{}).Parse(orig.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	pm := parsed.(*PutManifestTx)
	if len(pm.FileIDs) != 1 || pm.FileIDs[0] != "1,0" {
		t.Fatalf("FileIDs = %v, want [1,0]", pm.FileIDs)
	}
	if pm.Bucket != "b" || pm.Object != "o" || pm.Size != 0 || pm.ETag != "" {
		t.Fatalf("field mismatch: %+v", pm)
	}
	if pm.ID() != orig.ID() || !bytes.Equal(pm.Bytes(), orig.Bytes()) {
		t.Fatalf("id/wire not stable")
	}
}

// TestPutManifestDeterministicID proves the id is a pure function of the fields:
// two independently-built PutManifestTxs with identical fields share wire+id, and
// changing any field moves the id.
func TestPutManifestDeterministicID(t *testing.T) {
	mk := func() *PutManifestTx {
		return NewPutManifestTx("b", "o", []string{"1,0", "2,1"}, 42, "etag")
	}
	a, b := mk(), mk()
	if a.ID() != b.ID() {
		t.Fatalf("identical PutManifest have different ids: %s != %s", a.ID(), b.ID())
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("identical PutManifest have different wire bytes")
	}
	cases := map[string]*PutManifestTx{
		"bucket":  NewPutManifestTx("b2", "o", []string{"1,0", "2,1"}, 42, "etag"),
		"object":  NewPutManifestTx("b", "o2", []string{"1,0", "2,1"}, 42, "etag"),
		"fileIds": NewPutManifestTx("b", "o", []string{"1,0", "2,2"}, 42, "etag"),
		"filecnt": NewPutManifestTx("b", "o", []string{"1,0"}, 42, "etag"),
		"size":    NewPutManifestTx("b", "o", []string{"1,0", "2,1"}, 43, "etag"),
		"etag":    NewPutManifestTx("b", "o", []string{"1,0", "2,1"}, 42, "etag2"),
	}
	for name, tx := range cases {
		if tx.ID() == a.ID() {
			t.Errorf("changing %s did not change the id", name)
		}
	}
}

// TestAllocateWireRoundTripSigned proves a fully-authorized AllocateTx — the
// proposer-stamped Epoch/Nonce/Fingerprint plus the ML-DSA pinned-writer
// authorization — round-trips with EVERY field intact. The existing
// allocate_test only covers the unsigned intent; this covers the signed image
// that actually travels in the block and whose TxID must cover the auth.
func TestAllocateWireRoundTripSigned(t *testing.T) {
	fingerprint := ids.ID{0xfe, 0xed, 0xfa, 0xce, 0x01, 0x02, 0x03, 0x04, 0x05}
	signer := ids.NodeID{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44}
	pub := bytes.Repeat([]byte{0x9c}, 1952) // ML-DSA-65 public key size
	sig := bytes.Repeat([]byte{0x7e}, 3309) // ML-DSA-65 signature size

	orig := NewAllocateTx("bucket-A/band-3", 64).WithAuthorization(
		7,           // epoch
		131,         // nonce
		fingerprint, // set commitment
		signer,      // HRW owner NodeID
		0x42,        // ML-DSA-65 scheme byte
		pub,
		sig,
	)

	parsed, err := (&TxParser{}).Parse(orig.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Type() != TxAllocate {
		t.Fatalf("parsed type = %v, want TxAllocate", parsed.Type())
	}
	at, ok := parsed.(*AllocateTx)
	if !ok {
		t.Fatalf("parsed concrete type = %T, want *AllocateTx", parsed)
	}

	if at.Range != orig.Range {
		t.Errorf("Range = %q, want %q", at.Range, orig.Range)
	}
	if at.Count != orig.Count {
		t.Errorf("Count = %d, want %d", at.Count, orig.Count)
	}
	if at.Epoch != orig.Epoch {
		t.Errorf("Epoch = %d, want %d", at.Epoch, orig.Epoch)
	}
	if at.Nonce != orig.Nonce {
		t.Errorf("Nonce = %d, want %d", at.Nonce, orig.Nonce)
	}
	if at.Fingerprint != orig.Fingerprint {
		t.Errorf("Fingerprint = %s, want %s", at.Fingerprint, orig.Fingerprint)
	}
	if at.Signer != orig.Signer {
		t.Errorf("Signer = %s, want %s", at.Signer, orig.Signer)
	}
	if at.SignerScheme != orig.SignerScheme {
		t.Errorf("SignerScheme = %d, want %d", at.SignerScheme, orig.SignerScheme)
	}
	if !bytes.Equal(at.SignerPubKey, orig.SignerPubKey) {
		t.Errorf("SignerPubKey mismatch (len %d vs %d)", len(at.SignerPubKey), len(orig.SignerPubKey))
	}
	if !bytes.Equal(at.Sig, orig.Sig) {
		t.Errorf("Sig mismatch (len %d vs %d)", len(at.Sig), len(orig.Sig))
	}
	if !at.IsSigned() {
		t.Errorf("IsSigned() = false, want true")
	}
	if at.ID() != orig.ID() {
		t.Errorf("TxID = %s, want %s", at.ID(), orig.ID())
	}
	if !bytes.Equal(at.Bytes(), orig.Bytes()) {
		t.Errorf("wire not stable through round trip")
	}
	// SigningBytes is derived purely from the signed fields — it must survive the
	// round trip too (the block's signature verifies against exactly these bytes).
	if !bytes.Equal(at.SigningBytes(), orig.SigningBytes()) {
		t.Errorf("SigningBytes not stable through round trip")
	}
}

// TestAllocateWireRoundTripUnsigned proves the mempool intent (no auth stamped)
// round-trips: the zero Fingerprint/Signer and nil pubkey/sig come back intact
// and the tx reports itself unsigned.
func TestAllocateWireRoundTripUnsigned(t *testing.T) {
	orig := NewAllocateTx("r/1", 1)
	parsed, err := (&TxParser{}).Parse(orig.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	at := parsed.(*AllocateTx)
	if at.Range != "r/1" || at.Count != 1 {
		t.Fatalf("Range/Count mismatch: %+v", at)
	}
	if at.Epoch != 0 || at.Nonce != 0 {
		t.Errorf("Epoch/Nonce = %d/%d, want 0/0", at.Epoch, at.Nonce)
	}
	if at.Fingerprint != (ids.ID{}) {
		t.Errorf("Fingerprint = %s, want zero", at.Fingerprint)
	}
	if at.Signer != (ids.NodeID{}) {
		t.Errorf("Signer = %s, want zero", at.Signer)
	}
	if at.SignerScheme != 0 || at.SignerPubKey != nil || at.Sig != nil {
		t.Errorf("auth fields non-empty on unsigned intent: scheme=%d pub=%v sig=%v", at.SignerScheme, at.SignerPubKey, at.Sig)
	}
	if at.IsSigned() {
		t.Errorf("IsSigned() = true, want false")
	}
	if at.ID() != orig.ID() || !bytes.Equal(at.Bytes(), orig.Bytes()) {
		t.Errorf("id/wire not stable")
	}
}

// TestAllocateDeterministicSignedID proves a signed AllocateTx's id is a pure
// function of ALL its fields — two identical signed txs share wire+id, and moving
// any authorization field moves the id.
func TestAllocateDeterministicSignedID(t *testing.T) {
	fp := ids.ID{0x01}
	nid := ids.NodeID{0x02}
	pub := []byte{0x03, 0x04}
	sig := []byte{0x05, 0x06}
	mk := func() *AllocateTx {
		return NewAllocateTx("r", 9).WithAuthorization(5, 6, fp, nid, 0x42, pub, sig)
	}
	a, b := mk(), mk()
	if a.ID() != b.ID() {
		t.Fatalf("identical signed AllocateTx have different ids: %s != %s", a.ID(), b.ID())
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("identical signed AllocateTx have different wire bytes")
	}
	cases := map[string]*AllocateTx{
		"epoch":  NewAllocateTx("r", 9).WithAuthorization(6, 6, fp, nid, 0x42, pub, sig),
		"nonce":  NewAllocateTx("r", 9).WithAuthorization(5, 7, fp, nid, 0x42, pub, sig),
		"finger": NewAllocateTx("r", 9).WithAuthorization(5, 6, ids.ID{0x09}, nid, 0x42, pub, sig),
		"signer": NewAllocateTx("r", 9).WithAuthorization(5, 6, fp, ids.NodeID{0x09}, 0x42, pub, sig),
		"scheme": NewAllocateTx("r", 9).WithAuthorization(5, 6, fp, nid, 0x43, pub, sig),
		"pubkey": NewAllocateTx("r", 9).WithAuthorization(5, 6, fp, nid, 0x42, []byte{0x03, 0x05}, sig),
		"sig":    NewAllocateTx("r", 9).WithAuthorization(5, 6, fp, nid, 0x42, pub, []byte{0x05, 0x07}),
	}
	for name, tx := range cases {
		if tx.ID() == a.ID() {
			t.Errorf("changing %s did not change the id", name)
		}
	}
}

// TestParseTrailingBytes proves the codec is canonical: a well-formed wire object
// with any extra byte appended is rejected, not silently accepted.
func TestParseTrailingBytes(t *testing.T) {
	for _, tx := range []Tx{
		NewPutManifestTx("b", "o", []string{"1,0"}, 1, "e"),
		NewAllocateTx("r", 1),
	} {
		bad := append(append([]byte(nil), tx.Bytes()...), 0x00)
		if _, err := (&TxParser{}).Parse(bad); !errors.Is(err, ErrTrailingBytes) {
			t.Errorf("%s: trailing byte err = %v, want ErrTrailingBytes", tx.Type(), err)
		}
	}
}

// TestParseInvalidType proves an unknown leading type byte is rejected and an
// empty input does not panic.
func TestParseInvalidType(t *testing.T) {
	if _, err := (&TxParser{}).Parse(nil); !errors.Is(err, ErrInvalidTxType) {
		t.Errorf("empty input err = %v, want ErrInvalidTxType", err)
	}
	if _, err := (&TxParser{}).Parse([]byte{0xff}); !errors.Is(err, ErrInvalidTxType) {
		t.Errorf("unknown type byte err = %v, want ErrInvalidTxType", err)
	}
}
