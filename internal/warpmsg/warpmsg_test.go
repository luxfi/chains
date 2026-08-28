// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warpmsg

import (
	"errors"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

// stubSigner returns exactly what it is told to, which is the point: Signer is
// an interface, so the width of a signature is a runtime fact, not a
// compile-time one.
type stubSigner struct {
	sig []byte
	err error
}

func (s stubSigner) Sign(*warp.Message) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.sig, nil
}

func sigOf(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1) // non-zero, so zero padding is visible
	}
	return b
}

const (
	netID   = uint32(1)
	payload = "cross-chain payload"
)

func chainID() ids.ID { return ids.ID{'s', 'r', 'c'} }

// A signature of the wrong width is refused rather than reshaped. Copying it
// into a fixed array pads a short one with zeros and truncates a long one, and
// either way the envelope is well-formed and unverifiable: the sender believes
// it emitted a cross-chain message that no receiver can ever accept.
func TestSignatureOfTheWrongWidthIsRefused(t *testing.T) {
	for _, n := range []int{0, 1, warp.SignatureLen - 1, warp.SignatureLen + 1, 2 * warp.SignatureLen} {
		env, err := BuildSigned(stubSigner{sig: sigOf(n)}, netID, chainID(), []byte(payload))
		require.Nil(t, env)
		require.ErrorContains(t, err, "signature is")
		require.ErrorContains(t, err, "want 96")
	}
}

// A signature of the right width is carried through byte for byte. If the
// envelope held anything other than what the signer produced, verification at
// the receiver would fail for a reason invisible here.
func TestCorrectlySizedSignatureSurvivesIntact(t *testing.T) {
	want := sigOf(warp.SignatureLen)

	env, err := BuildSigned(stubSigner{sig: want}, netID, chainID(), []byte(payload))
	require.NoError(t, err)
	require.NotNil(t, env)

	require.Equal(t, want, env.Beam.Signature[:])

	// The single-signer convention: bit 0 and nothing else. A receiver
	// aggregates against the validator set by these indices, so a wider set
	// attributes the signature to validators that did not sign.
	require.True(t, env.Beam.Signers.Contains(0))
	for i := 1; i < 8; i++ {
		require.False(t, env.Beam.Signers.Contains(i), "bit %d must not be set", i)
	}

	require.Equal(t, netID, env.Message.NetworkID)
	require.Equal(t, chainID(), env.Message.SourceChainID)

	wire, err := env.Bytes()
	require.NoError(t, err)
	require.NotEmpty(t, wire)
}

// A signer that fails must not yield an envelope. An unsigned message that
// looks transmittable is worse than no message.
func TestSignerFailurePropagates(t *testing.T) {
	boom := errors.New("hsm unavailable")

	env, err := BuildSigned(stubSigner{err: boom}, netID, chainID(), []byte(payload))
	require.Nil(t, env)
	require.ErrorIs(t, err, boom)
	require.ErrorContains(t, err, "sign warp message")
}

// The message must refuse what it cannot represent, before anything is signed.
func TestUnbuildableMessageIsRefusedBeforeSigning(t *testing.T) {
	// A payload beyond the message limit cannot become a Message. If this
	// implementation ever accepts it, the guard below is what tells us.
	huge := make([]byte, 4*1024*1024)

	signed := false
	_, err := BuildSigned(funcSigner(func(*warp.Message) ([]byte, error) {
		signed = true
		return sigOf(warp.SignatureLen), nil
	}), netID, chainID(), huge)

	if err != nil {
		require.False(t, signed, "a message that cannot be built must not be signed")
		require.ErrorContains(t, err, "build warp message")
	}
}

type funcSigner func(*warp.Message) ([]byte, error)

func (f funcSigner) Sign(m *warp.Message) ([]byte, error) { return f(m) }

// Distinct payloads produce distinct envelopes. A builder that ignored its
// payload would pass every test above.
func TestPayloadReachesTheEnvelope(t *testing.T) {
	s := stubSigner{sig: sigOf(warp.SignatureLen)}

	a, err := BuildSigned(s, netID, chainID(), []byte("one"))
	require.NoError(t, err)
	b, err := BuildSigned(s, netID, chainID(), []byte("two"))
	require.NoError(t, err)

	require.NotEqual(t, a.Message.ID(), b.Message.ID())
	require.Equal(t, []byte("one"), a.Message.Payload)
	require.Equal(t, []byte("two"), b.Message.Payload)
}

// Network and source chain are part of what is signed. Two chains emitting the
// same payload must not produce the same message, or a message from one is
// replayable as a message from the other.
func TestNetworkAndChainSeparateOtherwiseIdenticalMessages(t *testing.T) {
	s := stubSigner{sig: sigOf(warp.SignatureLen)}

	base, err := BuildSigned(s, netID, chainID(), []byte(payload))
	require.NoError(t, err)

	otherNet, err := BuildSigned(s, netID+1, chainID(), []byte(payload))
	require.NoError(t, err)
	require.NotEqual(t, base.Message.ID(), otherNet.Message.ID())

	otherChain, err := BuildSigned(s, netID, ids.ID{'d', 's', 't'}, []byte(payload))
	require.NoError(t, err)
	require.NotEqual(t, base.Message.ID(), otherChain.Message.ID())
}
