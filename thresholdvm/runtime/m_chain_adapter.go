// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package runtime defines the adapter contracts the host chains
// (M-Chain and F-Chain) implement to plug into the ThresholdVM
// substrate.
//
// The substrate calls into adapters; adapters never call into the
// substrate. This is the orthogonality boundary at the type level:
// MChainAdapter exposes only MPC hooks, FChainAdapter exposes only
// FHE hooks. A chain that implements both interfaces is a
// configuration error.
package runtime

import (
	"context"

	"github.com/luxfi/chains/thresholdvm/cert"
	"github.com/luxfi/chains/thresholdvm/types"
)

// MChainAdapter is the contract M-Chain implements. The substrate
// drives ceremonies by calling these hooks; M-Chain provides the
// validator-set selection, persistence, and cert-emission.
type MChainAdapter interface {
	// Selector returns the M-Chain participant selector. Stake-weighted
	// VRF over P-Chain stake delegated to M-Chain.
	Selector() types.Selector

	// Registry returns the M-Chain LaneRegistry. Must be owned by
	// OwnerMChain and have verifiers for LaneMChainCGGMP21,
	// LaneMChainFROST, LaneMChainRingtailGen registered.
	Registry() *cert.LaneRegistry

	// CeremonyRoot returns mchain_ceremony_root at the current epoch.
	// Bound into certificate_subject by Quasar 3.0.
	CeremonyRoot(ctx context.Context, epoch uint64) ([32]byte, error)

	// OnDKG is called by the substrate when a new DKG ceremony enters
	// StateRegistered. M-Chain persists the participant set and
	// allocates the payload arena.
	OnDKG(ctx context.Context, ceremony types.Ceremony, set *types.ParticipantSet) error

	// OnSign is called for a signing ceremony. Same shape as OnDKG;
	// distinguished only by Ceremony.Kind.
	OnSign(ctx context.Context, ceremony types.Ceremony, set *types.ParticipantSet) error

	// OnReshare is called for an LSS resharing ceremony (LP-077). The
	// new participant set replaces the old one atomically at
	// finalize.
	OnReshare(ctx context.Context, ceremony types.Ceremony, oldSet, newSet *types.ParticipantSet) error

	// OnFinalize emits the finalized cert artifact onto Quasar 3.0's
	// CertLane and advances mchain_ceremony_root. If the ceremony's
	// kind is KindTFHEKeygen, the proof is also handed off to F-Chain
	// via the cross-chain envelope.
	OnFinalize(ctx context.Context, ceremony types.Ceremony, proof types.Proof) error
}
