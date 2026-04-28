// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package frost declares the M-Chain FROST protocol surface.
//
// FROST is a 2-round Schnorr threshold scheme over Ed25519. This
// package is interface-only; the implementation lives in
// chains/mchain/protocol/frost/.
package frost

import (
	"context"

	"github.com/luxfi/chains/thresholdvm/types"
)

// Verifier validates FROST share payloads. Registered as the
// LaneMChainFROST verifier in the M-Chain LaneRegistry.
type Verifier interface {
	VerifyShare(subject [32]byte, share types.Share, payload []byte) error
	VerifyFinal(subject [32]byte, proof types.Proof) error
}

// Driver runs FROST on a selected participant's behalf.
type Driver interface {
	// Round1 emits the participant's nonce commitments (D_i, E_i).
	Round1(ctx context.Context, ceremony types.CeremonyID) ([]byte, error)
	// Round2 emits the signature share z_i.
	Round2(ctx context.Context, ceremony types.CeremonyID, round1 [][]byte) ([]byte, error)
	// Finalize aggregates {z_i} into the single Ed25519 (R, z).
	Finalize(ctx context.Context, ceremony types.CeremonyID, round2 [][]byte) (types.Proof, error)
}
