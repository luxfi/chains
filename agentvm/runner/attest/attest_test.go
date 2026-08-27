// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package attest

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
	"github.com/luxfi/chains/agentvm/runner/confidential"
)

// operator signs with a secp256k1 key, which is what an operator on this chain
// holds and what the chain recovers an address from.
type operator struct{ key *ecdsa.PrivateKey }

func (o operator) Sign(digest common.Hash) ([]byte, error) {
	return crypto.Sign(digest.Bytes(), o.key)
}

func hold(t *testing.T) (operator, common.Address) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// The address of a key on this chain: keccak over the uncompressed public
	// point, low 20 bytes. Written out rather than taken from a helper, so it
	// is visibly the same derivation agentvm/evidence.go recovers to.
	pub := crypto.FromECDSAPub(&key.PublicKey)
	return operator{key: key}, common.BytesToAddress(crypto.Keccak256(pub[1:])[12:])
}

// signer reports the address the evidence signature recovers to, by the path
// agentvm/evidence.go uses: ecrecover over the attestation digest, then keccak
// over the public key.
func signer(t *testing.T, ev agentvm.Evidence, claim common.Hash, out agentvm.Handle) common.Address {
	t.Helper()
	if len(ev.Signature) != 65 {
		t.Fatalf("signature is %d bytes, want 65", len(ev.Signature))
	}
	pub, err := crypto.Ecrecover(ev.Attestation(claim, out).Bytes(), ev.Signature)
	if err != nil {
		t.Fatalf("Ecrecover: %v", err)
	}
	return common.BytesToAddress(crypto.Keccak256(pub[1:])[12:])
}

// nothing is a chain that has admitted no attesting key and no state root. It
// is what a fresh chain looks like, and software attestation does not consult
// it, which is the difference between the two attestations.
type nothing struct{}

func (nothing) Attests(common.Hash) bool { return false }
func (nothing) Pins(common.Hash) bool    { return false }

var (
	claim = common.HexToHash("0x1234abcd")
	out   = agentvm.Handle{Digest: common.HexToHash("0xbeef"), Size: 3, Bucket: "runs", Key: "one"}
)

// ran is what a gVisor run reports about itself.
func ran() runner.Result {
	return runner.Result{
		Output:   []byte("42"),
		Observed: agentvm.Witness{Serves: agentvm.MechanismGVisor, Digest: common.HexToHash("0xaa")},
		Filter:   common.HexToHash("0xbb"),
		Kernel:   common.HexToHash("0xcc"),
		Root:     common.HexToHash("0xdd"),
	}
}

func TestAttest(t *testing.T) {
	op, addr := hold(t)
	a := New(op, agentvm.PlacementLocal)

	ev, err := a.Attest(t.Context(), claim, out, ran(), agentvm.Evidence{})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}

	r := ran()
	if ev.Witness != r.Observed {
		t.Errorf("witness = %+v, want the run's observation %+v", ev.Witness, r.Observed)
	}
	if ev.Filter != r.Filter || ev.Kernel != r.Kernel || ev.Root != r.Root {
		t.Errorf("evidence lost the run's measurements: %+v", ev)
	}
	if ev.Placement != agentvm.PlacementLocal {
		t.Errorf("placement = %v, want local", ev.Placement)
	}
	if got := signer(t, ev, claim, out); got != addr {
		t.Errorf("signature recovers to %s, want the operator %s", got, addr)
	}

	// The chain's own predicate, over the same evidence: this is what the
	// signature is for.
	if err := ev.Proves(agentvm.Require(agentvm.AttestSoftware), claim, out, addr, nothing{}); err != nil {
		t.Errorf("evidence does not prove attest.software: %v", err)
	}
	if err := ev.Proves(agentvm.Require(agentvm.AttestSoftware), claim, out, common.Address{}, nothing{}); err == nil {
		t.Error("evidence proved attest.software for an operator that did not sign it")
	}
}

func TestAttestCoversEveryField(t *testing.T) {
	op, addr := hold(t)
	ev, err := New(op, agentvm.PlacementLocal).Attest(t.Context(), claim, out, ran(), agentvm.Evidence{})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	// One field changed after the fact, and the signature no longer names the
	// operator. That is what "signs last" buys.
	ev.Filter = common.HexToHash("0xffff")
	if got := signer(t, ev, claim, out); got == addr {
		t.Error("the signature survived a change to the filter digest")
	}
}

func TestGrants(t *testing.T) {
	op, _ := hold(t)
	want := agentvm.Require(agentvm.AttestSoftware)
	if got := New(op, agentvm.PlacementLocal).Grants(); got != want {
		t.Errorf("Grants = %d, want %d", got, want)
	}
}

func TestAttestWithoutKey(t *testing.T) {
	if _, err := New(nil, agentvm.PlacementLocal).Attest(t.Context(), claim, out, ran(), agentvm.Evidence{}); !errors.Is(err, ErrKey) {
		t.Fatalf("Attest without a key = %v, want ErrKey", err)
	}
}

func TestAttestUnknownPlacement(t *testing.T) {
	op, _ := hold(t)
	a := New(op, agentvm.Placement(200))
	if _, err := a.Attest(t.Context(), claim, out, ran(), agentvm.Evidence{}); !errors.Is(err, ErrPlacement) {
		t.Fatalf("Attest with an unknown placement = %v, want ErrPlacement", err)
	}
}

func TestAttestHonoursContext(t *testing.T) {
	op, _ := hold(t)
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := New(op, agentvm.PlacementLocal).Attest(ctx, claim, out, ran(), agentvm.Evidence{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Attest on a cancelled context = %v, want Canceled", err)
	}
}

// device answers with a report bound to whatever it is asked for, shaped the way
// agentvm.Quote reads a SEV-SNP report.
type device struct{}

func (device) Kind() agentvm.QuoteKind { return agentvm.QuoteSEVSNP }

func (device) Quote(bind common.Hash) (agentvm.Quote, error) { return report(bind), nil }

func report(bind common.Hash) agentvm.Quote {
	body := make([]byte, 0x2A0)
	for i := range body {
		body[i] = byte(i)
	}
	copy(body[0x050+32:0x050+64], bind[:])
	key := make([]byte, 97)
	key[0] = 4
	sig := make([]byte, 96)
	return agentvm.Quote{Kind: agentvm.QuoteSEVSNP, Report: body, Key: key, Signature: sig}
}

func hardware(t *testing.T) runner.Attestor {
	t.Helper()
	a, err := confidential.New(device{})
	if err != nil {
		t.Fatalf("confidential.New: %v", err)
	}
	return a
}

func TestChain(t *testing.T) {
	op, addr := hold(t)
	c := Chain(hardware(t), New(op, agentvm.PlacementCluster))

	ev, err := c.Attest(t.Context(), claim, out, ran(), agentvm.Evidence{})
	if err != nil {
		t.Fatalf("Chain Attest: %v", err)
	}
	if !ev.Quote.Present() {
		t.Fatal("the chained evidence carries no quote")
	}
	if ev.Quote.Binding() != claim {
		t.Errorf("quote binds %s, want %s", ev.Quote.Binding(), claim)
	}
	if ev.Placement != agentvm.PlacementCluster {
		t.Errorf("placement = %v, want cluster", ev.Placement)
	}
	if got := signer(t, ev, claim, out); got != addr {
		t.Errorf("signature recovers to %s, want the operator %s", got, addr)
	}

	// The signature came after the quote, so replacing the quote breaks it.
	tampered := ev
	tampered.Quote = report(common.HexToHash("0x99"))
	if got := signer(t, tampered, claim, out); got == addr {
		t.Error("the signature survived a replaced quote")
	}
}

func TestChainRefusesSigningFirst(t *testing.T) {
	op, _ := hold(t)
	// The signing attestor first, the hardware attestor after it: the quote
	// lands on evidence that has already been signed.
	c := Chain(New(op, agentvm.PlacementCluster), hardware(t))

	ev, err := c.Attest(t.Context(), claim, out, ran(), agentvm.Evidence{})
	if !errors.Is(err, ErrOrder) {
		t.Fatalf("Chain Attest = %v, want ErrOrder", err)
	}
	if ev.Quote.Present() || len(ev.Signature) != 0 {
		t.Error("a refused chain returned partial evidence")
	}
}

func TestChainGrants(t *testing.T) {
	op, _ := hold(t)
	c := Chain(hardware(t), New(op, agentvm.PlacementCluster))
	want := agentvm.Require(agentvm.MemoryEncrypted, agentvm.AttestHardware, agentvm.AttestSoftware)
	if got := c.Grants(); got != want {
		t.Errorf("Grants = %d, want the union %d", got, want)
	}
}

// broken refuses every run.
type broken struct{ err error }

func (b broken) Grants() agentvm.Properties { return 0 }

func (b broken) Attest(context.Context, common.Hash, agentvm.Handle, runner.Result, agentvm.Evidence) (agentvm.Evidence, error) {
	return agentvm.Evidence{}, b.err
}

func TestChainPropagatesError(t *testing.T) {
	op, _ := hold(t)
	boom := errors.New("device busy")
	c := Chain(broken{err: boom}, New(op, agentvm.PlacementCluster))

	ev, err := c.Attest(t.Context(), claim, out, ran(), agentvm.Evidence{})
	if !errors.Is(err, boom) {
		t.Fatalf("Chain Attest = %v, want the attestor's error", err)
	}
	if len(ev.Signature) != 0 {
		t.Error("a chain that failed still signed")
	}
}

func TestChainOfNothing(t *testing.T) {
	c := Chain()
	if got := c.Grants(); got != 0 {
		t.Errorf("Grants of an empty chain = %d, want 0", got)
	}
	ev, err := c.Attest(t.Context(), claim, out, ran(), agentvm.Evidence{})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if ev.Quote.Present() || len(ev.Signature) != 0 || ev.Witness != (agentvm.Witness{}) || ev.Filter != (common.Hash{}) {
		t.Errorf("an empty chain wrote evidence: %+v", ev)
	}
}

func TestChainSkipsAbsentAttestors(t *testing.T) {
	op, addr := hold(t)
	// A mechanism that is not available on this host is nil rather than a
	// runner that lies about itself, and the same is true of an attestor.
	c := Chain(nil, hardware(t), nil, New(op, agentvm.PlacementCluster), nil)
	ev, err := c.Attest(t.Context(), claim, out, ran(), agentvm.Evidence{})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if got := signer(t, ev, claim, out); got != addr {
		t.Errorf("signature recovers to %s, want %s", got, addr)
	}
}
