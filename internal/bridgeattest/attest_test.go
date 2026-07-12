// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgeattest

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/crypto/secp256k1"
)

// katTransfer is the frozen known-answer vector. The SAME vector is asserted on
// the M-Chain (mpcvm) Go side and in the Solidity BridgeGateway.t.sol. If any of
// the three surfaces changes the domain tag, field order, encoding, or widths,
// exactly one of these three tests goes red — that is the interop tripwire.
//
//	srcChainId = 200201 (Zoo EVM)
//	dstChainId = 96368  (Lux testnet C-Chain)
//	asset      = keccak256("ZOO")
//	amount     = 1000000
//	recipient  = 0x00..01 (20 bytes)
//	nonce      = 1
func katTransfer(t *testing.T) BridgeTransfer {
	t.Helper()
	var asset [32]byte
	copy(asset[:], crypto.Keccak256([]byte("ZOO")))
	// Pin the asset id itself so a keccak/import swap can't silently move it.
	const wantAsset = "f60aa5d51208599eb8dddd34b5e5f7732da8b35de3e71da60731c16e9a9d3c87"
	if got := hex.EncodeToString(asset[:]); got != wantAsset {
		t.Fatalf("asset keccak256(\"ZOO\") drift: got %s want %s", got, wantAsset)
	}
	var recipient [20]byte
	recipient[19] = 1
	return BridgeTransfer{
		SrcChainID: 200201,
		DstChainID: 96368,
		Asset:      asset,
		Amount:     1000000,
		Recipient:  recipient,
		Nonce:      1,
	}
}

func TestDigestKAT(t *testing.T) {
	// Frozen digest. Recomputed independently (python sha256 over the exact
	// preimage) and cross-checked by the Solidity test's sha256(abi.encodePacked).
	const wantDigest = "d5a83a92c81687688de10f0da371d85a95fba02c9e3462563e3413d16264bcfa"
	got := katTransfer(t).Digest()
	if hex.EncodeToString(got[:]) != wantDigest {
		t.Fatalf("digest KAT drift: got %x want %s", got, wantDigest)
	}
}

func TestVerifyRoundTrip(t *testing.T) {
	bt := katTransfer(t)
	digest := bt.Digest()

	key, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sig, err := secp256k1.Sign(digest[:], key.Bytes())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("sig len = %d, want 65 (r||s||v)", len(sig))
	}
	pub := key.PublicKey().CompressedBytes()
	if len(pub) != 33 {
		t.Fatalf("compressed pubkey len = %d, want 33", len(pub))
	}

	att := &Attestation{Transfer: bt, Digest: digest, Signature: sig, GroupPubKey: pub}

	if !att.Verify() {
		t.Fatal("valid attestation failed to verify")
	}
	// r||s (drop v) must also verify.
	if !VerifyBridgeAttestation(pub, bt, sig[:64]) {
		t.Fatal("r||s form failed to verify")
	}
}

func TestVerifyWrongSignerRejected(t *testing.T) {
	bt := katTransfer(t)
	digest := bt.Digest()

	signer, _ := secp256k1.NewPrivateKey()
	sig, _ := secp256k1.Sign(digest[:], signer.Bytes())

	// A different group key must not verify the signature.
	other, _ := secp256k1.NewPrivateKey()
	if VerifyBridgeAttestation(other.PublicKey().CompressedBytes(), bt, sig) {
		t.Fatal("signature verified under the wrong group key")
	}
}

func TestVerifyTamperRejected(t *testing.T) {
	bt := katTransfer(t)
	digest := bt.Digest()
	key, _ := secp256k1.NewPrivateKey()
	sig, _ := secp256k1.Sign(digest[:], key.Bytes())
	pub := key.PublicKey().CompressedBytes()

	// Mutating any bound field must invalidate the signature (digest changes).
	for name, mut := range map[string]func(*BridgeTransfer){
		"amount":    func(x *BridgeTransfer) { x.Amount++ },
		"nonce":     func(x *BridgeTransfer) { x.Nonce++ },
		"recipient": func(x *BridgeTransfer) { x.Recipient[0] ^= 0xff },
		"srcChain":  func(x *BridgeTransfer) { x.SrcChainID++ },
		"dstChain":  func(x *BridgeTransfer) { x.DstChainID++ },
		"asset":     func(x *BridgeTransfer) { x.Asset[0] ^= 0xff },
	} {
		tampered := bt
		mut(&tampered)
		if VerifyBridgeAttestation(pub, tampered, sig) {
			t.Fatalf("tampered field %q still verified", name)
		}
	}
}

// TestAttestationSelfConsistency guards the self-reported digest field: an
// attestation whose Digest does not match its Transfer must be rejected even if
// the signature is otherwise valid over the real digest.
func TestAttestationSelfConsistency(t *testing.T) {
	bt := katTransfer(t)
	digest := bt.Digest()
	key, _ := secp256k1.NewPrivateKey()
	sig, _ := secp256k1.Sign(digest[:], key.Bytes())

	var wrong [32]byte
	copy(wrong[:], bytes.Repeat([]byte{0xab}, 32))
	att := &Attestation{Transfer: bt, Digest: wrong, Signature: sig, GroupPubKey: key.PublicKey().CompressedBytes()}
	if att.Verify() {
		t.Fatal("attestation with mismatched self-reported digest verified")
	}
}
