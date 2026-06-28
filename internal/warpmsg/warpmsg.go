// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package warpmsg is the single, canonical place in chains that builds,
// signs, and wraps a single-signer Warp message.
//
// Every VM that emits a cross-chain Warp message — bridgevm reshare gossip,
// zkvm FHE task callbacks, thresholdvm decryption fulfillments — calls
// BuildSigned. The build→sign→wrap sequence lives here and nowhere else, so
// there is exactly one way to turn (networkID, sourceChainID, payload) into a
// transmittable signed Warp envelope.
package warpmsg

import (
	"fmt"

	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

// BuildSigned builds a Warp content Message for (networkID, sourceChainID,
// payload), signs it with the node's BLS key over the Beam domain, and wraps
// the signature into a single-signer Envelope.
//
// The signer is the local node's warp.Signer (BLS); it signs
// BeamSigningBytes(message.ID()). The resulting signature is placed at
// validator bit index 0 — the single-signer convention every chains VM uses
// before the receiver aggregates and verifies the Beam BitSetSignature
// against the canonical validator set (warp.VerifyEnvelope). The returned
// Envelope is therefore the complete, transmittable, verifiable signed
// message: env.Bytes() for the wire, env.Message for the authenticated
// content.
func BuildSigned(signer warp.Signer, networkID uint32, sourceChainID ids.ID, payload []byte) (*warp.Envelope, error) {
	msg, err := warp.NewMessage(networkID, sourceChainID, payload)
	if err != nil {
		return nil, fmt.Errorf("build warp message: %w", err)
	}

	sigBytes, err := signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("sign warp message: %w", err)
	}

	var sig [warp.SignatureLen]byte
	copy(sig[:], sigBytes)

	signers := warp.NewBitSet()
	signers.Add(0)

	env, err := warp.NewEnvelope(msg, warp.NewBitSetSignature(signers, sig), nil, nil)
	if err != nil {
		return nil, fmt.Errorf("wrap warp envelope: %w", err)
	}
	return env, nil
}
