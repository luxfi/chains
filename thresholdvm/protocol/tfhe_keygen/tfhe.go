// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package tfhe_keygen declares the cross-chain TFHE bootstrap-key
// generation surface.
//
// The ceremony **runs on M-Chain** (it is an MPC ceremony of FROST
// shape over the TFHE secret-key polynomial), but its **output is
// consumed by F-Chain** as the new bootstrap key. The handoff is
// represented in the substrate as a single Ceremony with kind
// KindTFHEKeygen and Lane=LaneMChainFROST at finalize, then ingested
// on F-Chain via Lane=LaneFChainBootstrap that wraps the upstream
// artifact.
//
// Interface-only; implementations split between
// chains/mchain/protocol/tfhe_keygen/ (the producer) and
// chains/fchain/protocol/tfhe_bootstrap/ (the consumer).
package tfhe_keygen

import (
	"context"

	"github.com/luxfi/chains/thresholdvm/types"
)

// Producer is implemented by M-Chain. It runs the MPC ceremony that
// produces a TFHE evaluation key.
type Producer interface {
	Round1(ctx context.Context, ceremony types.CeremonyID) ([]byte, error)
	Round2(ctx context.Context, ceremony types.CeremonyID, round1 [][]byte) ([]byte, error)
	// Finalize emits a Proof whose Payload is the serialized TFHE
	// evaluation key plus bootstrap material.
	Finalize(ctx context.Context, ceremony types.CeremonyID, round2 [][]byte) (types.Proof, error)
}

// Consumer is implemented by F-Chain. It accepts the M-Chain proof,
// re-verifies under the M-Chain ceremony root, and binds the new key
// into fchain_fhe_root.
type Consumer interface {
	// Ingest verifies the upstream proof and installs the bootstrap
	// key for use by F-Chain's FHE compute pipeline (LP-013).
	Ingest(ctx context.Context, mchainSubject [32]byte, proof types.Proof) error
	// VerifyHandoff is the per-share verifier on F-Chain's
	// LaneFChainBootstrap. It validates that a F-Chain bootstrap
	// share correctly references an M-Chain TFHE-keygen ceremony.
	VerifyHandoff(subject [32]byte, share types.Share, payload []byte) error
}
