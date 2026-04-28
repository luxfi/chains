// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package cggmp21 declares the M-Chain CGGMP21 protocol surface.
//
// This package contains interfaces only. The concrete implementation
// (key generation, pre-signing, signing, verification, identifiable
// abort) lives in chains/mchain/protocol/cggmp21/. The substrate
// imports this package; M-Chain implements it.
package cggmp21

import (
	"context"

	"github.com/luxfi/chains/thresholdvm/types"
)

// Verifier validates a CGGMP21 share payload. It is registered into
// the M-Chain LaneRegistry as the LaneMChainCGGMP21 verifier.
type Verifier interface {
	// VerifyShare checks that the per-round payload is a well-formed
	// CGGMP21 commitment / signature share. It does not produce or
	// hold any secret material.
	VerifyShare(subject [32]byte, share types.Share, payload []byte) error

	// VerifyFinal checks that the aggregated proof is a valid
	// secp256k1 ECDSA signature under the group public key encoded in
	// the proof.
	VerifyFinal(subject [32]byte, proof types.Proof) error
}

// Driver runs the protocol on a participant's behalf. Only validators
// selected into the ceremony's participant set instantiate a Driver;
// everyone else only verifies.
type Driver interface {
	// Round1 emits the participant's round-1 payload (commitments).
	Round1(ctx context.Context, ceremony types.CeremonyID) ([]byte, error)

	// Round2 emits the participant's round-2 payload (encrypted
	// shares), given the round-1 commitments from the rest of the
	// participant set.
	Round2(ctx context.Context, ceremony types.CeremonyID, round1 [][]byte) ([]byte, error)

	// Finalize aggregates all round-2 payloads into the final proof.
	// Returns ErrIdentifiableAbort if a participant is detected
	// cheating; the abort proof identifies the cheater.
	Finalize(ctx context.Context, ceremony types.CeremonyID, round2 [][]byte) (types.Proof, error)
}
