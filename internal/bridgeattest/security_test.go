// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgeattest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/luxfi/crypto/secp256k1"
)

func katCrossing() SecurityCrossing {
	var security [32]byte
	copy(security[:], bytes.Repeat([]byte{0xAB}, 32))
	var quantity [32]byte
	// 1000 units at eighteen decimals — past what a uint64 Amount could hold,
	// which is one of the reasons this message exists.
	new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)).FillBytes(quantity[:])
	var holder, identity [20]byte
	copy(holder[:], bytes.Repeat([]byte{0x11}, 20))
	copy(identity[:], bytes.Repeat([]byte{0x22}, 20))
	return SecurityCrossing{
		SrcChainID: 96369,
		DstChainID: 36963,
		Security:   security,
		Quantity:   quantity,
		Holder:     holder,
		Identity:   identity,
		Acquired:   1_700_000_000,
		Nonce:      1,
	}
}

// The preimage, built here by hand rather than by calling the method under
// test. A digest test that computes the digest the same way the code does
// proves the code agrees with itself.
func TestSecurityDigestIsTheStatedPreimage(t *testing.T) {
	sc := katCrossing()

	h := sha256.New()
	h.Write([]byte("LUX_SECURITY_CROSSING_v1"))
	var b [8]byte
	binary.BigEndian.PutUint32(b[:4], 96369)
	h.Write(b[:4])
	binary.BigEndian.PutUint32(b[:4], 36963)
	h.Write(b[:4])
	h.Write(sc.Security[:])
	h.Write(sc.Quantity[:])
	h.Write(sc.Holder[:])
	h.Write(sc.Identity[:])
	binary.BigEndian.PutUint64(b[:], 1_700_000_000)
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], 1)
	h.Write(b[:])

	if got, want := sc.Digest(), h.Sum(nil); !bytes.Equal(got[:], want) {
		t.Fatalf("digest drift:\n got %x\nwant %x", got, want)
	}
	t.Logf("security crossing KAT digest: %s", hex.EncodeToString(func() []byte { d := sc.Digest(); return d[:] }()))
}

// The property the separate tag exists for. A fungible transfer and a security
// crossing that agree on every field they share must still produce different
// digests, or an attestation authorising one would authorise the other — and a
// security would arrive somewhere having run no register at all.
func TestAFungibleAttestationCannotBeReplayedAsASecurityOne(t *testing.T) {
	sc := katCrossing()

	var amount [32]byte
	binary.BigEndian.PutUint64(amount[24:], 1_000_000)
	bt := BridgeTransfer{
		SrcChainID: sc.SrcChainID,
		DstChainID: sc.DstChainID,
		Asset:      sc.Security,
		Amount:     1_000_000,
		Recipient:  sc.Holder,
		Nonce:      sc.Nonce,
	}
	twin := sc
	twin.Quantity = amount
	twin.Identity = [20]byte{}
	twin.Acquired = 0

	if bt.Digest() == twin.Digest() {
		t.Fatal("a transfer and a crossing over the same facts produced one digest")
	}

	// And the verifiers refuse each other's signatures outright.
	key, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	d := bt.Digest()
	sig, err := secp256k1.Sign(d[:], key.Bytes())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub := key.PublicKey().CompressedBytes()
	if !VerifyBridgeAttestation(pub, bt, sig) {
		t.Fatal("control: the transfer signature does not verify as a transfer")
	}
	if VerifySecurityAttestation(pub, twin, sig) {
		t.Fatal("a transfer signature authorised a security crossing")
	}
}

func TestSecurityVerifyRoundTrip(t *testing.T) {
	sc := katCrossing()
	d := sc.Digest()

	key, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sig, err := secp256k1.Sign(d[:], key.Bytes())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub := key.PublicKey().CompressedBytes()

	a := &SecurityAttestation{Crossing: sc, Digest: d, Signature: sig, GroupPubKey: pub}
	if !a.VerifyAgainst(pub) {
		t.Fatal("a well-formed attestation did not verify")
	}

	// Every field is bound: change any one and the signature stops meaning it.
	for name, mutate := range map[string]func(*SecurityCrossing){
		"quantity": func(c *SecurityCrossing) { c.Quantity[31] ^= 1 },
		"holder":   func(c *SecurityCrossing) { c.Holder[19] ^= 1 },
		"identity": func(c *SecurityCrossing) { c.Identity[19] ^= 1 },
		"acquired": func(c *SecurityCrossing) { c.Acquired++ },
		"nonce":    func(c *SecurityCrossing) { c.Nonce++ },
		"route":    func(c *SecurityCrossing) { c.DstChainID++ },
		"security": func(c *SecurityCrossing) { c.Security[31] ^= 1 },
	} {
		moved := sc
		mutate(&moved)
		bad := &SecurityAttestation{Crossing: moved, Digest: moved.Digest(), Signature: sig, GroupPubKey: pub}
		if bad.VerifyAgainst(pub) {
			t.Fatalf("%s is not bound by the signature", name)
		}
	}
}

// The defect the fungible verifier already carries a comment about: reading the
// key off the struct being verified answers "was this signed by whoever signed
// it", which an attacker's own key satisfies.
func TestAnAttackersOwnKeyIsNotEvidence(t *testing.T) {
	sc := katCrossing()
	d := sc.Digest()

	theirs, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sig, err := secp256k1.Sign(d[:], theirs.Bytes())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	forged := &SecurityAttestation{
		Crossing: sc, Digest: d, Signature: sig,
		GroupPubKey: theirs.PublicKey().CompressedBytes(),
	}

	ours, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if forged.VerifyAgainst(ours.PublicKey().CompressedBytes()) {
		t.Fatal("an attestation signed by a stranger verified against the group key")
	}
	if forged.VerifyAgainst(nil) {
		t.Fatal("a nil expected key was treated as permission")
	}
}
