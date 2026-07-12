// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

// attest.go — the two runtime dependencies the EVM release path needs, defined
// as clean interface boundaries so the concrete transports (Warp to M-Chain,
// KMS for the relayer key) are injected, never hard-wired here.
//
//   AttestationClient : B -> M. B hands M a domain-bound BridgeTransfer; M
//                        returns a threshold-signed attestation. The concrete
//                        impl issues a Warp CrossChainMPCRequest to M-Chain
//                        (mpcvm). The cryptographer owns M; this is the seam we
//                        agreed on (see internal/bridgeattest — one definition of
//                        the digest, shared by both chains and the on-chain
//                        gateway).
//
//   KeyProvider       : resolves the gas-paying relayer key from a KMS path.
//                        This is the ONLY way a private key enters the VM — never
//                        from genesis, config JSON, env, or logs. The relayer key
//                        pays for release-tx inclusion; it does NOT authorise the
//                        mint (the MPC threshold signature in calldata does).

import (
	"context"
	"crypto/ecdsa"

	"github.com/luxfi/chains/internal/bridgeattest"
)

// AttestationClient is B's boundary to M-Chain. Given a canonical transfer, it
// returns M's self-describing threshold attestation (signature + group key). B
// verifies the attestation locally (bridgeattest.Attestation.Verify) before it
// broadcasts, so a faulty or malicious M-response is caught before any EVM tx.
type AttestationClient interface {
	AttestBridgeTransfer(ctx context.Context, transfer bridgeattest.BridgeTransfer) (*bridgeattest.Attestation, error)
}

// KeyProvider resolves a gas-paying relayer key from a KMS path. Production
// wiring supplies a luxfi/kms-backed resolver; tests inject a local key. A nil
// KeyProvider with configured external chains is a hard error at enable time —
// there is no plaintext-key fallback (fail secure).
type KeyProvider func(ctx context.Context, kmsPath string) (*ecdsa.PrivateKey, error)
