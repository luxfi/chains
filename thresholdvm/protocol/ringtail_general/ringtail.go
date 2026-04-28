// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ringtail_general declares the M-Chain general-purpose
// Ringtail (Ring-LWE) threshold protocol surface.
//
// This is **not** consensus-Ringtail. Consensus uses Ringtail at
// fixed parameters as the post-quantum cert lane (Q-Chain runs that
// ceremony, see LP-073). General-purpose Ringtail is for app-level
// threshold signing under a different parameter set; it lives on
// M-Chain.
//
// Interface-only; implementation in chains/mchain/protocol/ringtail/.
package ringtail_general

import (
	"context"

	"github.com/luxfi/chains/thresholdvm/types"
)

// Verifier validates Ringtail-general share payloads. Registered as
// the LaneMChainRingtailGen verifier in the M-Chain LaneRegistry.
type Verifier interface {
	VerifyShare(subject [32]byte, share types.Share, payload []byte) error
	VerifyFinal(subject [32]byte, proof types.Proof) error
}

// Driver runs the 2-round lattice protocol for a selected participant.
type Driver interface {
	Round1(ctx context.Context, ceremony types.CeremonyID) ([]byte, error)
	Round2(ctx context.Context, ceremony types.CeremonyID, round1 [][]byte) ([]byte, error)
	Finalize(ctx context.Context, ceremony types.CeremonyID, round2 [][]byte) (types.Proof, error)
}
