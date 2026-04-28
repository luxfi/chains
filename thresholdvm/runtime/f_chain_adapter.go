// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package runtime

import (
	"context"

	"github.com/luxfi/chains/thresholdvm/cert"
	"github.com/luxfi/chains/thresholdvm/types"
)

// FChainAdapter is the contract F-Chain implements. Same state
// machine as M-Chain, different hooks: F-Chain consumes upstream MPC
// outputs and emits FHE compute attestations.
type FChainAdapter interface {
	// Selector returns the F-Chain participant selector. Stake-weighted
	// over P-Chain stake delegated to F-Chain. GPU operators
	// self-select by delegating here rather than to M-Chain.
	Selector() types.Selector

	// Registry returns the F-Chain LaneRegistry. Must be owned by
	// OwnerFChain and have verifiers for LaneFChainTFHE,
	// LaneFChainBootstrap registered.
	Registry() *cert.LaneRegistry

	// FHERoot returns fchain_fhe_root at the current epoch. Bound
	// into certificate_subject alongside mchain_ceremony_root.
	FHERoot(ctx context.Context, epoch uint64) ([32]byte, error)

	// OnBootstrapHandoff is called by the substrate when M-Chain
	// finalizes a KindTFHEKeygen ceremony and hands off the bootstrap
	// key. F-Chain re-verifies under the M-Chain ceremony root and
	// installs the key.
	OnBootstrapHandoff(ctx context.Context, mchainSubject [32]byte, proof types.Proof) error

	// OnEval is called for a TFHE compute ceremony. The participant
	// set is the F-Chain GPU operators selected by VRF.
	OnEval(ctx context.Context, ceremony types.Ceremony, set *types.ParticipantSet) error

	// OnFinalize emits the finalized cert artifact onto Quasar 3.0's
	// CertLane and advances fchain_fhe_root.
	OnFinalize(ctx context.Context, ceremony types.Ceremony, proof types.Proof) error
}
