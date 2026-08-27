// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package confidential

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

// bench is a device under test control: it answers with whatever report it was
// given, so a device that binds the wrong run can be exercised without one.
type bench struct {
	bind common.Hash
	err  error
	asks []common.Hash
}

func (b *bench) Kind() agentvm.QuoteKind { return agentvm.QuoteSEVSNP }

func (b *bench) Quote(binding common.Hash) (agentvm.Quote, error) {
	b.asks = append(b.asks, binding)
	if b.err != nil {
		return agentvm.Quote{}, b.err
	}
	return quote(b.bind), nil
}

// quote builds a report of the shape agentvm.Quote reads: the signed span at
// its exact length, the binding in the low half of REPORT_DATA, a key that
// parses as an uncompressed P-384 point, and a signature at the field width.
// Nothing here verifies, and nothing in this package verifies; the chain does.
func quote(bind common.Hash) agentvm.Quote {
	report := make([]byte, span)
	for i := range report {
		report[i] = byte(i)
	}
	copy(report[0x050+32:0x050+64], bind[:])

	key := make([]byte, point)
	key[0] = 4
	for i := 1; i < point; i++ {
		key[i] = byte(i * 3)
	}
	sig := make([]byte, 2*width)
	for i := range sig {
		sig[i] = byte(i * 5)
	}
	return agentvm.Quote{Kind: agentvm.QuoteSEVSNP, Report: report, Key: key, Signature: sig}
}

func TestAttest(t *testing.T) {
	claim := common.HexToHash("0xa1b2c3")
	dev := &bench{bind: claim}
	a, err := New(dev)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ev, err := a.Attest(t.Context(), claim, agentvm.Handle{}, runner.Result{}, agentvm.Evidence{})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if !ev.Quote.Present() {
		t.Fatal("evidence carries no quote")
	}
	if got := ev.Quote.Binding(); got != claim {
		t.Errorf("quote binds %s, want %s", got, claim)
	}
	if len(dev.asks) != 1 || dev.asks[0] != claim {
		t.Errorf("device was asked for %v, want one quote over %s", dev.asks, claim)
	}
}

func TestAttestRefusesWrongBinding(t *testing.T) {
	claim := common.HexToHash("0xa1b2c3")
	// The device answers with a report produced for a different run. Accepting
	// it would build evidence the chain refuses with no way to say why.
	a, err := New(&bench{bind: common.HexToHash("0xdeadbeef")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ev, err := a.Attest(t.Context(), claim, agentvm.Handle{}, runner.Result{}, agentvm.Evidence{})
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("Attest = %v, want ErrBinding", err)
	}
	if ev.Quote.Present() {
		t.Error("a refused quote was written into the evidence anyway")
	}
}

func TestAttestRefusesMalformedQuote(t *testing.T) {
	// A report of the wrong length has no readable binding, so it cannot bind
	// this run and is refused for the same reason a mismatched one is.
	claim := common.HexToHash("0x01")
	short := quote(claim)
	short.Report = short.Report[:span-1]

	a, err := New(fixed{q: short})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Attest(t.Context(), claim, agentvm.Handle{}, runner.Result{}, agentvm.Evidence{}); !errors.Is(err, ErrBinding) {
		t.Fatalf("Attest of a malformed quote = %v, want ErrBinding", err)
	}
}

// fixed answers with one quote, whatever it is asked.
type fixed struct{ q agentvm.Quote }

func (f fixed) Kind() agentvm.QuoteKind                  { return agentvm.QuoteSEVSNP }
func (f fixed) Quote(common.Hash) (agentvm.Quote, error) { return f.q, nil }

func TestAttestPropagatesDeviceError(t *testing.T) {
	boom := errors.New("firmware busy")
	a, err := New(&bench{err: boom})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Attest(t.Context(), common.Hash{}, agentvm.Handle{}, runner.Result{}, agentvm.Evidence{}); !errors.Is(err, boom) {
		t.Fatalf("Attest = %v, want the device error", err)
	}
}

func TestAttestHonoursContext(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	stop()
	a, _ := New(&bench{})
	if _, err := a.Attest(ctx, common.Hash{}, agentvm.Handle{}, runner.Result{}, agentvm.Evidence{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Attest on a cancelled context = %v, want Canceled", err)
	}
}

func TestNewRefusesNoDevice(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrDevice) {
		t.Fatalf("New(nil) = %v, want ErrDevice", err)
	}
}

func TestGrants(t *testing.T) {
	a, err := New(&bench{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := agentvm.Require(agentvm.MemoryEncrypted, agentvm.AttestHardware)
	if got := a.Grants(); got != want {
		t.Errorf("Grants = %d, want %d", got, want)
	}
	// What it grants is what the TEE mechanism provides, which is the only
	// place in the chain those two properties come from.
	if !agentvm.Grants(agentvm.MechanismTEE).Contains(a.Grants()) {
		t.Error("the tee mechanism does not provide what this attestor grants")
	}
}

func TestElement(t *testing.T) {
	// One, written the way AMD writes it: least significant byte first.
	one := make([]byte, slot)
	one[0] = 1
	got, err := element(one)
	if err != nil {
		t.Fatalf("element: %v", err)
	}
	want := make([]byte, width)
	want[width-1] = 1
	if string(got) != string(want) {
		t.Errorf("element(1 little-endian) = %x, want %x", got, want)
	}

	// A full permutation: a big-endian value written backwards into the slot
	// must come back out as itself.
	be := make([]byte, width)
	for i := range be {
		be[i] = byte(i + 1)
	}
	le := make([]byte, slot)
	for i := 0; i < width; i++ {
		le[i] = be[width-1-i]
	}
	got, err = element(le)
	if err != nil {
		t.Fatalf("element: %v", err)
	}
	if string(got) != string(be) {
		t.Errorf("element = %x, want %x", got, be)
	}
}

func TestElementRefusesOverflow(t *testing.T) {
	// A byte above the field width means the value does not fit in P-384.
	// Taking the low 48 anyway would hand the verifier a different number.
	le := make([]byte, slot)
	le[width] = 1
	if _, err := element(le); !errors.Is(err, ErrReport) {
		t.Fatalf("element over the field = %v, want ErrReport", err)
	}
	if _, err := element(make([]byte, slot-1)); !errors.Is(err, ErrReport) {
		t.Fatalf("element of a short slot = %v, want ErrReport", err)
	}
}

// response builds a guest response holding one report: the msg_report_resp
// header, then the ATTESTATION_REPORT at offset 32.
func response(bind common.Hash, size uint32) []byte {
	buf := make([]byte, 4000)
	binary.LittleEndian.PutUint32(buf[0:4], 0)
	binary.LittleEndian.PutUint32(buf[4:8], size)
	report := buf[head:]
	for i := 0; i < span; i++ {
		report[i] = byte(i)
	}
	copy(report[0x050+32:0x050+64], bind[:])
	// r = 2, s = 3, each little-endian in its own 72-byte slot.
	report[slotR] = 2
	report[slotS] = 3
	return buf
}

func vcek() []byte {
	key := make([]byte, point)
	key[0] = 4
	for i := 1; i < point; i++ {
		key[i] = byte(i)
	}
	return key
}

func TestParse(t *testing.T) {
	bind := common.HexToHash("0x5150")
	q, err := parse(response(bind, 0x4A0), vcek())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if q.Kind != agentvm.QuoteSEVSNP {
		t.Errorf("kind = %v, want sev-snp", q.Kind)
	}
	if len(q.Report) != span {
		t.Errorf("report = %d bytes, want %d", len(q.Report), span)
	}
	if len(q.Signature) != 2*width {
		t.Fatalf("signature = %d bytes, want %d", len(q.Signature), 2*width)
	}
	if q.Signature[width-1] != 2 || q.Signature[2*width-1] != 3 {
		t.Errorf("signature = %x, want r=2 and s=3 big-endian", q.Signature)
	}
	for i := 0; i < width-1; i++ {
		if q.Signature[i] != 0 || q.Signature[width+i] != 0 {
			t.Fatalf("signature has a non-zero leading byte at %d: %x", i, q.Signature)
		}
	}
	// The binding this package writes and the binding the chain reads are the
	// same bytes at the same offset.
	if got := q.Binding(); got != bind {
		t.Errorf("Binding = %s, want %s", got, bind)
	}
}

func TestParseRefusals(t *testing.T) {
	bind := common.HexToHash("0x01")

	failed := response(bind, 0x4A0)
	binary.LittleEndian.PutUint32(failed[0:4], 22)
	if _, err := parse(failed, vcek()); !errors.Is(err, ErrReport) {
		t.Errorf("parse of a non-zero status = %v, want ErrReport", err)
	}

	if _, err := parse(response(bind, least-1), vcek()); !errors.Is(err, ErrReport) {
		t.Errorf("parse of a short report = %v, want ErrReport", err)
	}

	if _, err := parse(response(bind, 4000), vcek()); !errors.Is(err, ErrReport) {
		t.Errorf("parse of a report longer than its buffer = %v, want ErrReport", err)
	}

	if _, err := parse(make([]byte, 8), vcek()); !errors.Is(err, ErrReport) {
		t.Errorf("parse of a truncated response = %v, want ErrReport", err)
	}

	over := response(bind, 0x4A0)
	over[head+slotR+width] = 1
	if _, err := parse(over, vcek()); !errors.Is(err, ErrReport) {
		t.Errorf("parse of a signature over the field = %v, want ErrReport", err)
	}
}

func TestParseRefusesBadKey(t *testing.T) {
	bind := common.HexToHash("0x01")
	if _, err := parse(response(bind, 0x4A0), make([]byte, point)); !errors.Is(err, ErrKey) {
		t.Errorf("parse with a key that is not a point = %v, want ErrKey", err)
	}
	if _, err := parse(response(bind, 0x4A0), vcek()[:point-1]); !errors.Is(err, ErrKey) {
		t.Errorf("parse with a short key = %v, want ErrKey", err)
	}
}

func TestNewGuestRefusesBadKey(t *testing.T) {
	// The VCEK is supplied, so its shape is checked before anything opens a
	// device. This is the one guest path that runs on every machine.
	if _, err := NewGuest(nil); !errors.Is(err, ErrKey) {
		t.Fatalf("NewGuest(nil) = %v, want ErrKey", err)
	}
	if _, err := NewGuest(make([]byte, point)); !errors.Is(err, ErrKey) {
		t.Fatalf("NewGuest with a zero leading byte = %v, want ErrKey", err)
	}
}
