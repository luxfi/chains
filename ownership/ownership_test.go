// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ownership

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/crypto/secp256k1"
)

// genesisCollection is the live Lux Genesis ERC-721 on Ethereum mainnet. It
// appears here only as realistic test data — this package pins no collection,
// because which collection entitles is the attester's concern, asserted once at
// the place that reads Ethereum.
var genesisCollection = [20]byte{
	0x31, 0xe0, 0xF9, 0x19, 0xC6, 0x7c, 0xeD, 0xd2, 0xBc, 0x3E,
	0x29, 0x43, 0x40, 0xDc, 0x90, 0x07, 0x35, 0x81, 0x03, 0x11,
}

// The frozen vectors for fixture(). A diff here means previously issued
// attestations stop verifying: treat it as a wire-format break, never as a test
// that needs updating.
const (
	KATRoot    = "804cd348581c8049872c0333b54a078db5bdbde2a73af3a7730a86186af5e3e2"
	KATPayload = "549b7eb0720a1b37b7905f76a5287daf21379ad42e54504a00042c379f7057ef"
)

// fixture is the canonical claim the KAT vectors pin. Every field is non-zero
// and distinct so a field-order regression cannot pass by symmetry.
func fixture() Claim {
	c := Claim{Chain: 1, Collection: genesisCollection, Token: 7, Block: 25443474}
	for i := range c.Owner {
		c.Owner[i] = byte(0xA0 + i)
	}
	for i := range c.Node {
		c.Node[i] = byte(0x10 + i)
	}
	return c
}

// TestKAT freezes the wire format. The digest layout, field order and domain tag
// are consumed by the M-Chain VM and by every node's chain manager; if this test
// changes, previously issued attestations stop verifying, so a diff here is a
// flag-day and must be treated as one.
func TestKAT(t *testing.T) {
	require.Equal(t, "LUX:QuantumAttest:nft/ownership:v1", DomainTag,
		"the domain tag is frozen; mpcvm registers this exact byte string")
	require.Equal(t, "nft/ownership", Domain)

	c := fixture()
	root := c.Root()
	subject := c.Subject()
	payload := Payload(subject, root, 42)

	require.Equal(t, "101112131415161718191a1b1c1d1e1f20212223000000000000000000000000",
		hex.EncodeToString(subject[:]), "Subject is the 20 NodeID bytes, left-aligned in 32")
	require.Equal(t, KATRoot, hex.EncodeToString(root[:]),
		"the commitment layout is frozen")
	require.Equal(t, KATPayload, hex.EncodeToString(payload[:]),
		"the signed payload is frozen")
}

// TestEveryFieldIsBound tamps each field in turn and requires the commitment to
// move. A field absent from the digest would be a field an attester could not
// actually constrain — the collection could be swapped, or the token, or the
// node, under a signature that still verified.
func TestEveryFieldIsBound(t *testing.T) {
	base := fixture().Root()

	mutate := map[string]func(*Claim){
		"chain":      func(c *Claim) { c.Chain = 137 },
		"collection": func(c *Claim) { c.Collection[19] ^= 0xff },
		"token":      func(c *Claim) { c.Token = 8 },
		"owner":      func(c *Claim) { c.Owner[0] ^= 0xff },
		"node":       func(c *Claim) { c.Node[0] ^= 0xff },
		"block":      func(c *Claim) { c.Block++ },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			c := fixture()
			m(&c)
			require.NotEqual(t, base, c.Root(), "%s is not bound into the commitment", name)
		})
	}
}

// TestPayloadBindsEpoch proves the epoch is part of what is signed, so an
// attestation cannot be replayed into a different epoch.
func TestPayloadBindsEpoch(t *testing.T) {
	c := fixture()
	require.NotEqual(t,
		Payload(c.Subject(), c.Root(), 1),
		Payload(c.Subject(), c.Root(), 2),
		"epoch must be bound into the signed payload")
}

// sign produces a real secp256k1 signature over a claim's payload, standing in
// for an M-Chain threshold ceremony. A threshold ECDSA signature verifies
// exactly like a single-key one, which is why the gate needs no live M-Chain to
// be tested.
func sign(t *testing.T, key *secp256k1.PrivateKey, c Claim, epoch uint64) *Attestation {
	t.Helper()
	payload := Payload(c.Subject(), c.Root(), epoch)
	sig, err := key.SignHash(payload[:])
	require.NoError(t, err)
	return &Attestation{
		Claim:     c,
		Epoch:     epoch,
		Signers:   3,
		Quorum:    3,
		Signature: sig,
		GroupKey:  key.PublicKey().CompressedBytes(),
	}
}

// TestOwnershipAuthorizes is the positive half of the gate's contract: a node
// named by an authentic, quorum-signed claim IS authorized.
func TestOwnershipAuthorizes(t *testing.T) {
	key, err := secp256k1.NewPrivateKey()
	require.NoError(t, err)
	c := fixture()

	a := sign(t, key, c, 42)
	require.NoError(t, a.Authorizes(c.Node),
		"an authentic attestation bound to this node authorizes it")

	// A 65-byte recoverable signature and its 64-byte r||s prefix must both be
	// accepted, since M-Chain artifacts carry the recovery id.
	if len(a.Signature) == 65 {
		short := *a
		short.Signature = a.Signature[:64]
		require.NoError(t, short.Authorizes(c.Node), "r||s must verify as well as r||s||v")
	}
}

// TestAbsenceRefuses is the negative half, and the one that matters: every way an
// entitlement can be missing, borrowed, forged or weakened must refuse.
func TestAbsenceRefuses(t *testing.T) {
	key, err := secp256k1.NewPrivateKey()
	require.NoError(t, err)
	other, err := secp256k1.NewPrivateKey()
	require.NoError(t, err)
	c := fixture()
	var absent *Attestation

	t.Run("no attestation at all", func(t *testing.T) {
		require.Error(t, absent.Authorizes(c.Node))
	})

	t.Run("attestation for a different node is not borrowable", func(t *testing.T) {
		a := sign(t, key, c, 42)
		peer := c.Node
		peer[0] ^= 0xff
		require.ErrorIs(t, a.Authorizes(peer), ErrWrongNode,
			"a node must not activate on a peer's entitlement")
	})

	t.Run("signed by the wrong key", func(t *testing.T) {
		a := sign(t, key, c, 42)
		a.GroupKey = other.PublicKey().CompressedBytes()
		require.ErrorIs(t, a.Authorizes(c.Node), ErrBadSignature)
	})

	t.Run("no group key", func(t *testing.T) {
		a := sign(t, key, c, 42)
		a.GroupKey = nil
		require.ErrorIs(t, a.Authorizes(c.Node), ErrNoKey)
	})

	t.Run("below quorum", func(t *testing.T) {
		a := sign(t, key, c, 42)
		a.Signers = a.Quorum - 1
		require.ErrorIs(t, a.Authorizes(c.Node), ErrNoQuorum)
	})

	t.Run("quorum claimed as zero", func(t *testing.T) {
		a := sign(t, key, c, 42)
		a.Quorum = 0
		a.Signers = 0
		require.ErrorIs(t, a.Authorizes(c.Node), ErrNoQuorum,
			"a zero threshold must never read as satisfied")
	})

	t.Run("epoch replayed", func(t *testing.T) {
		a := sign(t, key, c, 42)
		a.Epoch = 43
		require.ErrorIs(t, a.Authorizes(c.Node), ErrBadSignature)
	})

	t.Run("malformed signature", func(t *testing.T) {
		a := sign(t, key, c, 42)
		a.Signature = a.Signature[:32]
		require.ErrorIs(t, a.Authorizes(c.Node), ErrBadSignature)
	})

	// Every claim field: re-point an authentic signature at a mutated claim and
	// require refusal. This is what stops a holder of one token from activating
	// on a claim about another token, collection or chain.
	for name, m := range map[string]func(*Claim){
		"collection swapped": func(c *Claim) { c.Collection[0] ^= 0xff },
		"token swapped":      func(c *Claim) { c.Token = 8 },
		"chain swapped":      func(c *Claim) { c.Chain = 137 },
		"owner swapped":      func(c *Claim) { c.Owner[0] ^= 0xff },
		"block swapped":      func(c *Claim) { c.Block++ },
	} {
		t.Run(name, func(t *testing.T) {
			a := sign(t, key, c, 42)
			m(&a.Claim)
			require.ErrorIs(t, a.Authorizes(a.Claim.Node), ErrBadSignature,
				"a signature must not survive a %s", name)
		})
	}
}
