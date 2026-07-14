// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package txs

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/ids"
)

// fill helpers producing distinct non-zero fixed-width values so a field
// swapped for another is caught by equality.
func id32(seed byte) ids.ID {
	var x ids.ID
	for i := range x {
		x[i] = seed + byte(i)
	}
	return x
}

func short20(seed byte) ids.ShortID {
	var x ids.ShortID
	for i := range x {
		x[i] = seed + byte(i)
	}
	return x
}

func arr32(seed byte) [32]byte {
	var x [32]byte
	for i := range x {
		x[i] = seed + byte(i)
	}
	return x
}

// nonzeroBase returns a BaseTx with EVERY field non-zero (TxID/bytes excluded —
// those are derived on the wire, not encoded).
func nonzeroBase(t TxType) BaseTx {
	return BaseTx{
		TxType:    t,
		From:      short20(0x10),
		Nonce:     0x1122334455667788,
		GasPrice:  4242,
		GasLimit:  777777,
		CreatedAt: 1_700_000_000_123_456_789,
		Signature: []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02},
	}
}

// normalize clears the derived identity fields so two logically-equal txs compare
// equal regardless of whether they came from a constructor or a parse.
func normalize(b *BaseTx) {
	b.TxID = ids.Empty
	b.bytes = nil
}

// sampleTxs returns one fully-populated instance of every concrete tx type,
// each with non-zero values in EVERY field (including slices / nested orders).
func sampleTxs() []Tx {
	imp := &ImportTx{
		BaseTx:      nonzeroBase(TxImport),
		SourceChain: id32(0x20),
		ImportedInputs: []AtomicInput{
			{UTXOID: id32(0x30), Asset: id32(0x40), Amount: 1_000},
			{UTXOID: id32(0x31), Asset: id32(0x40), Amount: 2_500},
		},
		Outputs: []AtomicOutput{
			{Rail: RailSwap, Owner: short20(0x50), Asset: id32(0x40), Amount: 900, Spent: 0},
			{Rail: RailSwap, Owner: short20(0x51), Asset: id32(0x40), Amount: 600, Spent: 1500},
		},
	}

	exp := &ExportTx{
		BaseTx:           nonzeroBase(TxExport),
		DestinationChain: id32(0x60),
		FillRef:          id32(0x70),
		ExportedOutputs: []AtomicOutput{
			{Rail: RailLP, Owner: short20(0x80), Asset: id32(0x90), Amount: 3_333, Spent: 4_444},
		},
	}

	relay := &RelayOrderTx{
		BaseTx:        nonzeroBase(TxRelayOrder),
		Method:        "clob_submit",
		Payload:       []byte("opaque-clob-frame-bytes"),
		CollateralRef: id32(0xA0),
		AssetOut:      id32(0xB0),
		PriceLimit:    987_654,
		LimitIsUpper:  true,
	}

	place := &PlaceOrderTx{
		BaseTx:        nonzeroBase(TxPlaceOrder),
		PoolID:        arr32(0xC0),
		Side:          1,
		Price:         55_555,
		Size:          66_666,
		CollateralRef: id32(0xD0),
	}

	cancel := &CancelOrderTx{
		BaseTx:  nonzeroBase(TxCancelOrder),
		PoolID:  arr32(0xE0),
		OrderID: 0x0102030405060708,
	}

	return []Tx{imp, exp, relay, place, cancel}
}

// TestRoundTripAllTypes marshals each concrete tx to native ZAP wire, parses it
// back through the canonical TxParser, and asserts every field survives.
func TestRoundTripAllTypes(t *testing.T) {
	parser := &TxParser{}
	for _, orig := range sampleTxs() {
		orig := orig
		t.Run(orig.Type().String(), func(t *testing.T) {
			// Marshal via the exported codec (the same path finalize uses).
			wire, err := marshalAny(orig)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if wire[0] != byte(orig.Type()) {
				t.Fatalf("discriminator byte = %d, want %d", wire[0], orig.Type())
			}

			parsed, err := parser.Parse(wire)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if parsed.Type() != orig.Type() {
				t.Fatalf("parsed type = %v, want %v", parsed.Type(), orig.Type())
			}

			// Parsed TxID must be the checksum of the wire, and Bytes() the wire.
			if parsed.ID() != ids.Checksum256(wire) {
				t.Fatalf("parsed TxID mismatch")
			}
			if !bytes.Equal(parsed.Bytes(), wire) {
				t.Fatalf("parsed Bytes() != wire")
			}

			// Deep field equality after clearing derived identity fields.
			assertFieldsEqual(t, orig, parsed)
		})
	}
}

// TestDeterminism marshals each tx twice and requires byte-identical output, and
// requires a re-marshal of the PARSED tx to reproduce the exact wire (TxID is a
// pure function of the wire).
func TestDeterminism(t *testing.T) {
	parser := &TxParser{}
	for _, orig := range sampleTxs() {
		orig := orig
		t.Run(orig.Type().String(), func(t *testing.T) {
			w1, err := marshalAny(orig)
			if err != nil {
				t.Fatalf("marshal 1: %v", err)
			}
			w2, err := marshalAny(orig)
			if err != nil {
				t.Fatalf("marshal 2: %v", err)
			}
			if !bytes.Equal(w1, w2) {
				t.Fatalf("non-deterministic marshal:\n a=%x\n b=%x", w1, w2)
			}

			parsed, err := parser.Parse(w1)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			w3, err := marshalAny(parsed)
			if err != nil {
				t.Fatalf("re-marshal parsed: %v", err)
			}
			if !bytes.Equal(w1, w3) {
				t.Fatalf("re-marshal of parsed tx diverged:\n orig=%x\n re  =%x", w1, w3)
			}
			if parsed.ID() != ids.Checksum256(w1) {
				t.Fatalf("TxID not a pure function of wire")
			}
		})
	}
}

// TestConstructorRoundTrip drives the PUBLIC constructor path (New*Tx) to prove
// a freshly built tx is wire-ready and parses back to an equal tx with the same
// TxID/Bytes.
func TestConstructorRoundTrip(t *testing.T) {
	parser := &TxParser{}
	from := short20(0x11)

	built := []Tx{
		NewImportTx(from, 7, id32(0x21),
			[]AtomicInput{{UTXOID: id32(0x22), Asset: id32(0x23), Amount: 10}},
			[]AtomicOutput{{Owner: from, Asset: id32(0x23), Amount: 9}}),
		NewExportTx(from, 8, id32(0x24),
			[]AtomicOutput{{Rail: RailLP, Owner: from, Asset: id32(0x25), Amount: 5, Spent: 3}}, id32(0x26)),
		NewRelayOrderTx(from, 9, "clob_place", []byte("frame"), id32(0x27)),
		NewPlaceOrderTx(from, 10, arr32(0x28), 0, 100, 200),
		NewCancelOrderTx(from, 11, arr32(0x29), 42),
	}

	for _, orig := range built {
		orig := orig
		t.Run(orig.Type().String(), func(t *testing.T) {
			parsed, err := parser.Parse(orig.Bytes())
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if parsed.ID() != orig.ID() {
				t.Fatalf("TxID mismatch: parsed=%s orig=%s", parsed.ID(), orig.ID())
			}
			if !bytes.Equal(parsed.Bytes(), orig.Bytes()) {
				t.Fatalf("Bytes() mismatch")
			}
			assertFieldsEqual(t, orig, parsed)
		})
	}
}

// TestRelaySignatureBindsThroughWire proves the ZAP wire preserves the relay
// signature semantics end to end: a signed relay verifies, and any tamper of a
// signature-covered field (From) is rejected at admission.
func TestRelaySignatureBindsThroughWire(t *testing.T) {
	key, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	relay := NewRelayOrderTx(ids.ShortEmpty, 3, "clob_submit", []byte("frame"), id32(0x33))
	if err := relay.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if relay.From != ids.ShortID(key.EVMAddress()) {
		t.Fatalf("Sign did not stamp From to signer address")
	}
	if err := relay.Verify(); err != nil {
		t.Fatalf("signed relay should verify: %v", err)
	}

	// Round-trip the signed relay and re-verify off the wire.
	parsed, err := (&TxParser{}).Parse(relay.Bytes())
	if err != nil {
		t.Fatalf("parse signed relay: %v", err)
	}
	if err := parsed.Verify(); err != nil {
		t.Fatalf("parsed signed relay should verify: %v", err)
	}

	// Tamper the signature-covered From: verify must reject (ErrInvalidSignature).
	spoofed := parsed.(*RelayOrderTx)
	spoofed.From = short20(0x99)
	if err := spoofed.Verify(); err != ErrInvalidSignature {
		t.Fatalf("spoofed From must be ErrInvalidSignature, got %v", err)
	}
}

// TestTrailingBytesRejected asserts the parser rejects a wire with extra bytes
// appended after the canonical ZAP message.
func TestTrailingBytesRejected(t *testing.T) {
	wire, err := marshalAny(sampleTxs()[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	corrupt := append(append([]byte(nil), wire...), 0xFF, 0xFF)
	if _, err := (&TxParser{}).Parse(corrupt); err == nil {
		t.Fatalf("expected trailing-bytes rejection, got nil")
	}
}

// marshalAny dispatches Marshal on a Tx interface value (the generic Marshal[T]
// needs a concrete *T; the test carries Tx, so switch to the concrete type).
func marshalAny(tx Tx) ([]byte, error) {
	switch v := tx.(type) {
	case *ImportTx:
		return Marshal(v, TxImport)
	case *ExportTx:
		return Marshal(v, TxExport)
	case *RelayOrderTx:
		return Marshal(v, TxRelayOrder)
	case *PlaceOrderTx:
		return Marshal(v, TxPlaceOrder)
	case *CancelOrderTx:
		return Marshal(v, TxCancelOrder)
	default:
		return nil, ErrInvalidTxType
	}
}

// assertFieldsEqual compares two txs of the same concrete type for full field
// equality, ignoring the derived TxID/bytes.
func assertFieldsEqual(t *testing.T, orig, parsed Tx) {
	t.Helper()
	switch o := orig.(type) {
	case *ImportTx:
		p := parsed.(*ImportTx)
		oc, pc := *o, *p
		normalize(&oc.BaseTx)
		normalize(&pc.BaseTx)
		if !reflect.DeepEqual(oc, pc) {
			t.Fatalf("ImportTx mismatch:\n orig=%+v\n got =%+v", oc, pc)
		}
	case *ExportTx:
		p := parsed.(*ExportTx)
		oc, pc := *o, *p
		normalize(&oc.BaseTx)
		normalize(&pc.BaseTx)
		if !reflect.DeepEqual(oc, pc) {
			t.Fatalf("ExportTx mismatch:\n orig=%+v\n got =%+v", oc, pc)
		}
	case *RelayOrderTx:
		p := parsed.(*RelayOrderTx)
		oc, pc := *o, *p
		normalize(&oc.BaseTx)
		normalize(&pc.BaseTx)
		if !reflect.DeepEqual(oc, pc) {
			t.Fatalf("RelayOrderTx mismatch:\n orig=%+v\n got =%+v", oc, pc)
		}
	case *PlaceOrderTx:
		p := parsed.(*PlaceOrderTx)
		oc, pc := *o, *p
		normalize(&oc.BaseTx)
		normalize(&pc.BaseTx)
		if !reflect.DeepEqual(oc, pc) {
			t.Fatalf("PlaceOrderTx mismatch:\n orig=%+v\n got =%+v", oc, pc)
		}
	case *CancelOrderTx:
		p := parsed.(*CancelOrderTx)
		oc, pc := *o, *p
		normalize(&oc.BaseTx)
		normalize(&pc.BaseTx)
		if !reflect.DeepEqual(oc, pc) {
			t.Fatalf("CancelOrderTx mismatch:\n orig=%+v\n got =%+v", oc, pc)
		}
	default:
		t.Fatalf("unknown tx type %T", orig)
	}
}

// BenchmarkMarshalImport / BenchmarkParseImport give a rough ns/op for the
// native path (compare against the historical json path in the report).
func BenchmarkMarshalImport(b *testing.B) {
	tx := sampleTxs()[0].(*ImportTx)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Marshal(tx, TxImport); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseImport(b *testing.B) {
	wire, err := Marshal(sampleTxs()[0].(*ImportTx), TxImport)
	if err != nil {
		b.Fatal(err)
	}
	parser := &TxParser{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parser.Parse(wire); err != nil {
			b.Fatal(err)
		}
	}
}
