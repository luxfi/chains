// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/luxfi/ids"
)

func sampleSecurity() *SecurityRequest {
	return &SecurityRequest{
		SrcChainID: 96369,
		DstChainID: 36963,
		Nonce:      1,
		Security:   ids.ID(bytes.Repeat([]byte{0xAB}, 32)),
		Quantity:   new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)),
		Holder:     bytes.Repeat([]byte{0x11}, 20),
		Identity:   bytes.Repeat([]byte{0x22}, 20),
		Acquired:   1_700_000_000,
	}
}

// The reason this message exists rather than a widened BridgeTransfer: a
// position of any real size overflows the uint64 the fungible path carries.
func TestAPositionLargerThanAUint64Crosses(t *testing.T) {
	r := sampleSecurity()
	// A billion shares at eighteen decimals — far past uint64, and an ordinary
	// size for a register.
	r.Quantity = new(big.Int).Mul(big.NewInt(1_000_000_000), big.NewInt(1e18))

	sc, err := r.crossing()
	if err != nil {
		t.Fatalf("crossing: %v", err)
	}
	if got := new(big.Int).SetBytes(sc.Quantity[:]); got.Cmp(r.Quantity) != 0 {
		t.Fatalf("quantity did not survive: got %s want %s", got, r.Quantity)
	}
	if r.Quantity.IsUint64() {
		t.Fatal("control: this test's quantity fits a uint64, so it proves nothing")
	}
}

// A short identity is a malformed request, not an absence. Reading it as
// absence would let a truncated field pass for "this holder had none".
func TestAShortIdentityIsRefusedRatherThanTreatedAsAbsent(t *testing.T) {
	r := sampleSecurity()
	r.Identity = bytes.Repeat([]byte{0x22}, 19)

	if _, err := r.crossing(); err == nil {
		t.Fatal("a 19-byte identity was accepted")
	}

	// Whereas none at all is honest, and travels as zero.
	r.Identity = nil
	sc, err := r.crossing()
	if err != nil {
		t.Fatalf("an absent identity should cross: %v", err)
	}
	if sc.Identity != ([20]byte{}) {
		t.Fatal("an absent identity did not travel as zero")
	}
}

// Everything the digest commits to is validated before a signature can exist,
// because an attestation over a malformed crossing authorises an arrival nobody
// can make sense of.
func TestAMalformedCrossingNeverReachesASignature(t *testing.T) {
	for name, break_ := range map[string]func(*SecurityRequest){
		"no destination":  func(r *SecurityRequest) { r.DstChainID = 0 },
		"short holder":    func(r *SecurityRequest) { r.Holder = bytes.Repeat([]byte{1}, 19) },
		"no holder":       func(r *SecurityRequest) { r.Holder = nil },
		"nil quantity":    func(r *SecurityRequest) { r.Quantity = nil },
		"zero quantity":   func(r *SecurityRequest) { r.Quantity = big.NewInt(0) },
		"negative amount": func(r *SecurityRequest) { r.Quantity = big.NewInt(-1) },
		"over uint256": func(r *SecurityRequest) {
			r.Quantity = new(big.Int).Lsh(big.NewInt(1), 256)
		},
	} {
		r := sampleSecurity()
		break_(r)
		if _, err := r.crossing(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	// Control: the unbroken request crosses, so the refusals above are the
	// breakage and not a mapping that refuses everything.
	if _, err := sampleSecurity().crossing(); err != nil {
		t.Fatalf("control: a well-formed crossing was refused: %v", err)
	}
}

// The route and the nonce are part of what one attestation authorises, so two
// requests that differ only in those must not produce the same digest.
func TestEachCrossingIsItsOwn(t *testing.T) {
	base, err := sampleSecurity().crossing()
	if err != nil {
		t.Fatalf("crossing: %v", err)
	}
	for name, mutate := range map[string]func(*SecurityRequest){
		"nonce":       func(r *SecurityRequest) { r.Nonce++ },
		"destination": func(r *SecurityRequest) { r.DstChainID++ },
		"source":      func(r *SecurityRequest) { r.SrcChainID++ },
		"holder":      func(r *SecurityRequest) { r.Holder[19] ^= 1 },
		"identity":    func(r *SecurityRequest) { r.Identity[19] ^= 1 },
		"acquired":    func(r *SecurityRequest) { r.Acquired++ },
		"quantity":    func(r *SecurityRequest) { r.Quantity = big.NewInt(1) },
	} {
		r := sampleSecurity()
		mutate(r)
		other, err := r.crossing()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if other.Digest() == base.Digest() {
			t.Fatalf("%s does not change the digest, so one attestation covers both", name)
		}
	}
}
