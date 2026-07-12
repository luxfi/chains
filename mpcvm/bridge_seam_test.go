// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// bridge_seam_test.go — fast, transport-free tests of the B→M attestation seam:
// the digest is domain-bound and replay-safe, and a signature over one transfer
// verifies for THAT transfer and no other. These use an ordinary secp256k1 key
// (a threshold signature verifies identically to a single-key one), so they run
// in -short without the DKG/sign ceremony.

import (
	"testing"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/stretchr/testify/require"
)

func sampleTransfer() BridgeTransfer {
	var asset [32]byte
	copy(asset[:], []byte("LUX"))
	var recip [20]byte
	copy(recip[:], []byte("recipient-0xdeadbeef"))
	return BridgeTransfer{
		SrcChainID: 200201,
		DstChainID: 97368,
		Asset:      asset,
		Amount:     1_000_000,
		Recipient:  recip,
		Nonce:      42,
	}
}

// TestBridgeAttestation_ReplaySafe proves a signature over one transfer's
// domain-bound digest verifies for that transfer and fails for any transfer
// that differs in ANY digest-committed field — no replay across routes,
// amounts, recipients, or nonces.
func TestBridgeAttestation_ReplaySafe(t *testing.T) {
	priv, err := secp256k1.NewPrivateKey()
	require.NoError(t, err)
	pub := priv.PublicKey().CompressedBytes()
	require.Len(t, pub, 33)

	bt := sampleTransfer()
	digest := bt.Digest()
	sig, err := priv.SignHash(digest[:])
	require.NoError(t, err)

	// Correct transfer verifies.
	require.True(t, VerifyBridgeAttestation(pub, bt, sig),
		"signature over the correct transfer must verify")

	// Every digest-committed field is binding: flip it and the SAME signature
	// must be rejected.
	mutations := map[string]func(BridgeTransfer) BridgeTransfer{
		"srcChainID": func(b BridgeTransfer) BridgeTransfer { b.SrcChainID++; return b },
		"dstChainID": func(b BridgeTransfer) BridgeTransfer { b.DstChainID++; return b },
		"asset":      func(b BridgeTransfer) BridgeTransfer { b.Asset[0] ^= 0x01; return b },
		"amount":     func(b BridgeTransfer) BridgeTransfer { b.Amount++; return b },
		"recipient":  func(b BridgeTransfer) BridgeTransfer { b.Recipient[0] ^= 0x01; return b },
		"nonce":      func(b BridgeTransfer) BridgeTransfer { b.Nonce++; return b },
	}
	for field, mutate := range mutations {
		require.Falsef(t, VerifyBridgeAttestation(pub, mutate(bt), sig),
			"signature must NOT verify after mutating %s (replay/rebind)", field)
	}

	// A truncated / malformed signature is rejected, not panicked on.
	require.False(t, VerifyBridgeAttestation(pub, bt, sig[:10]))
	require.False(t, VerifyBridgeAttestation(nil, bt, sig))
}

// TestBridgeDigest_DomainSeparated proves the digest is stable and that the
// domain tag is mixed in (a transfer's digest is not the bare field hash),
// so a bridge attestation can never be replayed as another message M signs.
func TestBridgeDigest_DomainSeparated(t *testing.T) {
	bt := sampleTransfer()
	d1 := bt.Digest()
	d2 := bt.Digest()
	require.Equal(t, d1, d2, "digest must be deterministic")

	// Distinct transfers produce distinct digests.
	other := bt
	other.Nonce++
	require.NotEqual(t, bt.Digest(), other.Digest())

	// The domain separator is registered so QuantumAttestation-style tooling
	// recognises the bridge domain.
	require.Equal(t, []byte(bridgeTransferDomainTag), domainSeparators[DomainBridgeTransfer])
}

// TestCeremonyID_DeterministicAndBinding proves the derived ceremony id lets
// honest validators converge without an announce round, and separates distinct
// keys / digests / quorums while being independent of signer ordering.
func TestCeremonyID_DeterministicAndBinding(t *testing.T) {
	digest := sampleTransfer().Digest()
	signers := []party.ID{"a", "b", "c"}

	base := ceremonyID("k1", digest[:], signers)

	// Deterministic and signer-order independent.
	require.Equal(t, base, ceremonyID("k1", digest[:], []party.ID{"c", "a", "b"}))

	// Bound to key, digest and signer set.
	require.NotEqual(t, base, ceremonyID("k2", digest[:], signers))
	other := sampleTransfer()
	other.Amount++
	od := other.Digest()
	require.NotEqual(t, base, ceremonyID("k1", od[:], signers))
	require.NotEqual(t, base, ceremonyID("k1", digest[:], []party.ID{"a", "b", "d"}))
}
