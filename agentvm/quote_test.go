// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// newQuote builds a real attestation quote: a report laid out at the vendor's own
// offsets, signed on the vendor's curve with the vendor's hash. Nothing here is a
// stand-in — the verifier under test runs the same ECDSA verification it would
// run against silicon.
func newQuote(t *testing.T, kind QuoteKind, binding common.Hash) (Quote, *ecdsa.PrivateKey) {
	t.Helper()
	l := layouts[kind]

	report := make([]byte, l.length)
	// Fill the report with a recognisable pattern so a verifier that reads the
	// wrong offset gets the wrong answer rather than a plausible zero.
	for i := range report {
		report[i] = byte(i)
	}
	// The binding sits in the low 32 bytes of the 64-byte report-data field.
	copy(report[l.binding:l.binding+32], make([]byte, 32))
	copy(report[l.binding+32:l.binding+64], binding.Bytes())

	priv, err := ecdsa.GenerateKey(l.curve(), rand.Reader)
	require.NoError(t, err)
	r, s, err := ecdsa.Sign(rand.Reader, priv, l.digest(report))
	require.NoError(t, err)

	sig := make([]byte, 2*l.field)
	r.FillBytes(sig[:l.field])
	s.FillBytes(sig[l.field:])

	key, err := priv.PublicKey.Bytes()
	require.NoError(t, err)
	return Quote{Kind: kind, Report: report, Key: key, Signature: sig}, priv
}

// admits is a Trust that believes exactly one attesting key and one state root.
type admits struct {
	key  common.Hash
	root common.Hash
}

func (a admits) Attests(d common.Hash) bool { return d == a.key }
func (a admits) Pins(d common.Hash) bool    { return d == a.root }

func TestQuoteVerifiesOnBothLayouts(t *testing.T) {
	for _, kind := range []QuoteKind{QuoteSEVSNP, QuoteTDX} {
		binding := h(0x42)
		q, _ := newQuote(t, kind, binding)
		trust := admits{key: KeyDigest(q.Key)}

		require.NoError(t, q.Verify(binding, trust), "%s quote must verify", kind)
		require.Equal(t, binding, q.Binding(), "%s binding read at the vendor offset", kind)
		require.NotEqual(t, common.Hash{}, q.Measurement())
	}
}

func TestQuoteCurvesAndWidthsAreTheVendors(t *testing.T) {
	require.Equal(t, elliptic.P384(), layouts[QuoteSEVSNP].curve(), "SEV-SNP signs on P-384")
	require.Equal(t, elliptic.P256(), layouts[QuoteTDX].curve(), "TDX signs on P-256")
	require.Equal(t, 0x2A0, layouts[QuoteSEVSNP].length, "SEV-SNP signs bytes [0,0x2A0)")
	require.Equal(t, 0x050, layouts[QuoteSEVSNP].binding, "REPORT_DATA is at 0x050")
	require.Equal(t, 0x090, layouts[QuoteSEVSNP].measurement, "MEASUREMENT is at 0x090")
	require.Equal(t, 48+584, layouts[QuoteTDX].length, "TDX signs header plus body")
	require.Equal(t, 48+0x208, layouts[QuoteTDX].binding, "REPORTDATA is at 0x208 in the body")
	require.Equal(t, 48+0x088, layouts[QuoteTDX].measurement, "MRTD is at 0x088 in the body")
}

func TestQuoteRefusesAKeyNobodyAdmitted(t *testing.T) {
	binding := h(0x42)
	q, _ := newQuote(t, QuoteSEVSNP, binding)
	require.ErrorIs(t, q.Verify(binding, admits{key: h(0xFF)}), ErrQuoteKeyNotAdmitted)
	require.ErrorIs(t, q.Verify(binding, no{}), ErrQuoteKeyNotAdmitted)
	require.ErrorIs(t, q.Verify(binding, nil), ErrQuoteKeyNotAdmitted)
}

// TestQuoteRefusesAnotherRunsReport is the check that stops a valid quote for one
// run being presented for another. It is why the binding is read out of the
// signed report rather than carried beside it.
func TestQuoteRefusesAnotherRunsReport(t *testing.T) {
	q, _ := newQuote(t, QuoteSEVSNP, h(0x42))
	trust := admits{key: KeyDigest(q.Key)}
	require.NoError(t, q.Verify(h(0x42), trust))
	require.ErrorIs(t, q.Verify(h(0x43), trust), ErrQuoteBinding)
}

// TestQuoteRefusesATamperedReport: because the binding lives in the signed span,
// editing it breaks the signature rather than changing what the quote says.
func TestQuoteRefusesATamperedReport(t *testing.T) {
	q, _ := newQuote(t, QuoteSEVSNP, h(0x42))
	trust := admits{key: KeyDigest(q.Key)}

	tampered := q
	tampered.Report = append([]byte(nil), q.Report...)
	copy(tampered.Report[layouts[QuoteSEVSNP].binding+32:], h(0x43).Bytes())
	require.ErrorIs(t, tampered.Verify(h(0x43), trust), ErrQuoteSignature,
		"editing the binding must break the signature, not redirect the quote")

	// Editing the measurement is the same story.
	tampered = q
	tampered.Report = append([]byte(nil), q.Report...)
	tampered.Report[layouts[QuoteSEVSNP].measurement] ^= 0xFF
	require.ErrorIs(t, tampered.Verify(h(0x42), trust), ErrQuoteSignature)
}

// TestQuoteRefusesAnotherKeysSignature: substituting a key that IS admitted for
// the one that signed does not help, because the signature is checked under the
// key presented.
func TestQuoteRefusesAnotherKeysSignature(t *testing.T) {
	q, _ := newQuote(t, QuoteSEVSNP, h(0x42))
	other, _ := newQuote(t, QuoteSEVSNP, h(0x42))

	swapped := q
	swapped.Key = other.Key
	require.ErrorIs(t, swapped.Verify(h(0x42), admits{key: KeyDigest(other.Key)}), ErrQuoteSignature)
}

func TestQuoteRefusesMalformedShapes(t *testing.T) {
	good, _ := newQuote(t, QuoteSEVSNP, h(0x42))
	trust := admits{key: KeyDigest(good.Key)}

	cases := map[string]func(Quote) Quote{
		"no quote at all":  func(q Quote) Quote { return Quote{} },
		"unknown kind":     func(q Quote) Quote { q.Kind = QuoteKind(9); return q },
		"short report":     func(q Quote) Quote { q.Report = q.Report[:len(q.Report)-1]; return q },
		"long report":      func(q Quote) Quote { q.Report = append(q.Report, 0); return q },
		"short signature":  func(q Quote) Quote { q.Signature = q.Signature[:8]; return q },
		"short key":        func(q Quote) Quote { q.Key = q.Key[:8]; return q },
		"compressed point": func(q Quote) Quote { k := append([]byte(nil), q.Key...); k[0] = 2; q.Key = k; return q },
		"tdx sized as snp": func(q Quote) Quote { q.Kind = QuoteTDX; return q },
	}
	for name, mangle := range cases {
		bad := mangle(good)
		err := bad.Verify(h(0x42), trust)
		require.Error(t, err, name)
		require.NotErrorIs(t, err, ErrQuoteBinding, "%s must fail before the binding read", name)
	}
}

// TestQuoteDigestBindsEveryPart: the digest an operator signs over must change
// when any part of the quote does, or a signature would carry between quotes.
func TestQuoteDigestBindsEveryPart(t *testing.T) {
	q, _ := newQuote(t, QuoteSEVSNP, h(0x42))
	base := q.Digest()
	require.NotEqual(t, common.Hash{}, base)
	require.Equal(t, common.Hash{}, Quote{}.Digest(), "no quote digests to zero")

	alt := q
	alt.Report = append([]byte(nil), q.Report...)
	alt.Report[0] ^= 1
	require.NotEqual(t, base, alt.Digest())

	alt = q
	alt.Signature = append([]byte(nil), q.Signature...)
	alt.Signature[0] ^= 1
	require.NotEqual(t, base, alt.Digest())
}

// TestMemoryEncryptedNeedsTheQuoteToo: encrypted memory is a hardware statement,
// so it costs the same verification hardware attestation does.
func TestMemoryEncryptedNeedsTheQuoteToo(t *testing.T) {
	claim := h(0x42)
	q, _ := newQuote(t, QuoteSEVSNP, claim)
	trust := admits{key: KeyDigest(q.Key)}

	ev := Evidence{Witness: Witness{Serves: MechanismTEE}, Quote: q}
	require.NoError(t, ev.Proves(Require(MemoryEncrypted, AttestHardware), claim, outputHandle(), common.Address{}, trust))

	ev.Quote = Quote{}
	require.ErrorIs(t,
		ev.Proves(Require(MemoryEncrypted), claim, outputHandle(), common.Address{}, trust),
		ErrQuoteMalformed)
}
