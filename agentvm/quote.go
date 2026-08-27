// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

// quote.go verifies a hardware attestation quote. It is the only place in the
// chain where a guarantee rests on something other than an operator's bond.
//
// A quote carries the vendor's report bytes VERBATIM — exactly the span the
// hardware signature covers — and nothing beside them. The two facts the chain
// needs, the binding and the launch measurement, are read out of those bytes at
// the vendor's own offsets. Carrying them as separate fields would let an
// operator present a report that says one thing and fields that say another; the
// report is the only source.
//
// Verification is three checks, all of which must pass:
//
//  1. the attesting key's digest is one the chain has admitted (RootSet). The
//     vendor certificate chain that proves a key belongs to genuine hardware is
//     validated when the key is admitted, which is a governance act; on-chain the
//     admitted digest is what a quote is checked against. An empty root set
//     admits nothing, so hardware attestation is refused until a root exists.
//  2. the signature verifies over the report under that key, on the curve and
//     with the hash the vendor actually signs with.
//  3. the report's binding field equals the run being attested.
//
// Both supported layouts are fixed by their vendor specifications:
//
//	SEV-SNP  ATTESTATION_REPORT: the signature covers bytes [0, 0x2A0). REPORT_DATA
//	         is 64 bytes at 0x050 and MEASUREMENT is 48 bytes at 0x090. The key is
//	         the VCEK, ECDSA P-384 over SHA-384.
//	TDX      the signed span is the 48-byte quote header followed by the 584-byte
//	         TD quote body. MRTD is 48 bytes at 0x088 within the body and REPORTDATA
//	         is 64 bytes at 0x208, so at 184 and 568 from the start of the span. The
//	         key is the attestation key, ECDSA P-256 over SHA-256.
//
// Signature and key ride in the one encoding every verifier wants: r||s big-endian
// at the curve's field width, and an uncompressed SEC1 point. A device that emits
// another encoding normalises at its own edge, off-chain, before the quote reaches
// consensus.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// QuoteKind names an attestation report layout.
type QuoteKind uint8

const (
	// QuoteNone is the absence of a quote — the zero value.
	QuoteNone QuoteKind = 0
	// QuoteSEVSNP is an AMD SEV-SNP ATTESTATION_REPORT.
	QuoteSEVSNP QuoteKind = 1
	// QuoteTDX is an Intel TDX quote header followed by its TD quote body.
	QuoteTDX QuoteKind = 2

	quoteKindCount = 3
)

// String names the quote kind.
func (k QuoteKind) String() string {
	switch k {
	case QuoteNone:
		return "none"
	case QuoteSEVSNP:
		return "sev-snp"
	case QuoteTDX:
		return "tdx"
	default:
		return "unknown"
	}
}

// layout is where a vendor's report keeps the two facts the chain reads, and how
// the hardware signs it. One row per supported report; nothing else in the
// package knows a vendor offset.
type layout struct {
	length      int // exact length of the signed span
	binding     int // offset of the 64-byte report-data field
	measurement int // offset of the measurement field
	measureLen  int // length of the measurement field
	field       int // curve field width in bytes; signature is 2*field
	point       int // uncompressed SEC1 point length: 1 + 2*field
	digest      func([]byte) []byte
	curve       func() elliptic.Curve
}

var layouts = [quoteKindCount]layout{
	QuoteSEVSNP: {
		length:      0x2A0,
		binding:     0x050,
		measurement: 0x090,
		measureLen:  48,
		field:       48,
		point:       97,
		digest:      func(b []byte) []byte { h := sha512.Sum384(b); return h[:] },
		curve:       elliptic.P384,
	},
	QuoteTDX: {
		length:      48 + 584,
		binding:     48 + 0x208,
		measurement: 48 + 0x088,
		measureLen:  48,
		field:       32,
		point:       65,
		digest:      func(b []byte) []byte { h := sha256.Sum256(b); return h[:] },
		curve:       elliptic.P256,
	},
}

// Quote is a hardware attestation report and the signature over it.
type Quote struct {
	Kind      QuoteKind `json:"kind"`
	Report    []byte    `json:"report"`    // the vendor's signed span, verbatim
	Key       []byte    `json:"key"`       // attesting public key, uncompressed SEC1 point
	Signature []byte    `json:"signature"` // r||s, big-endian, at the curve's field width
}

// KeyDigest is how an attesting key is named on-chain: keccak over the
// uncompressed point. Admission stores this; a quote is checked against it.
func KeyDigest(key []byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(key))
}

// Present reports whether a quote was supplied at all.
func (q Quote) Present() bool { return q.Kind != QuoteNone }

// Measurement is the launch measurement the report states, read at the vendor's
// offset. Zero for a quote whose kind or length is not one this build knows —
// callers reach it only after Verify has accepted the quote.
func (q Quote) Measurement() common.Hash {
	l, ok := q.layout()
	if !ok {
		return common.Hash{}
	}
	return common.BytesToHash(crypto.Keccak256(q.Report[l.measurement : l.measurement+l.measureLen]))
}

// Binding is what the report says it was produced for: the low 32 bytes of the
// 64-byte report-data field, which is where a run's claim is placed when the
// quote is requested.
func (q Quote) Binding() common.Hash {
	l, ok := q.layout()
	if !ok {
		return common.Hash{}
	}
	return common.BytesToHash(q.Report[l.binding+32 : l.binding+64])
}

// Digest identifies the quote for the purpose of binding it into a signed claim.
func (q Quote) Digest() common.Hash {
	if !q.Present() {
		return common.Hash{}
	}
	return common.BytesToHash(crypto.Keccak256(
		[]byte(DomainQuote), []byte{byte(q.Kind)}, q.Report, q.Key, q.Signature,
	))
}

// layout returns the vendor layout for this quote, and whether the quote's shape
// matches it. Every length is checked here so the readers above can slice without
// a bounds concern.
func (q Quote) layout() (layout, bool) {
	if q.Kind == QuoteNone || q.Kind >= quoteKindCount {
		return layout{}, false
	}
	l := layouts[q.Kind]
	if len(q.Report) != l.length || len(q.Key) != l.point || len(q.Signature) != 2*l.field {
		return layout{}, false
	}
	return l, true
}

// Verify accepts the quote only if its shape matches a layout this build knows,
// its key has been admitted, its signature verifies, and its report was produced
// for this exact claim. Every failure is a refusal; there is no partial success.
func (q Quote) Verify(claim common.Hash, trust Trust) error {
	l, ok := q.layout()
	if !ok {
		return ErrQuoteMalformed
	}
	if trust == nil || !trust.Attests(KeyDigest(q.Key)) {
		return ErrQuoteKeyNotAdmitted
	}
	if q.Key[0] != 4 {
		return ErrQuoteMalformed
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(l.curve(), q.Key)
	if err != nil {
		return ErrQuoteMalformed
	}
	r := new(big.Int).SetBytes(q.Signature[:l.field])
	s := new(big.Int).SetBytes(q.Signature[l.field:])
	if !ecdsa.Verify(pub, l.digest(q.Report), r, s) {
		return ErrQuoteSignature
	}
	if q.Binding() != claim {
		return ErrQuoteBinding
	}
	return nil
}
