// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// service.go carves the (currently single, overloaded) threshold VM into
// three orthogonal SERVICE surfaces — ThresholdService, MPCService, FHEService
// — per LP-134 / LP-7050. This is the "separate what the primitive IS from
// where it is APPLIED" decomposition (Hammock-driven composition, not
// inheritance).
//
// It changes NO behavior and NO genesis: the interfaces are carved directly
// from the methods *VM already implements, and *VM is asserted to satisfy all
// three at the bottom of this file (the compatibility bridge). The physical
// VM split — moving each surface's implementation onto its own package
// (github.com/luxfi/chains/mpcvm implementing MPCService, .../fhevm
// implementing FHEService) behind these exact interfaces — is the follow-up;
// until then the one *VM backs all three surfaces and the M-Chain / F-Chain
// runtime adapters (runtime/{m,f}_chain_adapter.go) delegate to it.
//
// Layering mirrors the primitive-library stack that already exists upstream
// (github.com/luxfi/threshold is consumed by github.com/luxfi/mpc; FHE ⊥ MPC):
//
//   - ThresholdService — PURE threshold primitives: DKG, committee lifecycle
//     (keygen / refresh / reshare), key/committee lookup. The substrate the
//     other two consume. Owns no custody, no bridge business logic, no FHE.
//   - MPCService — threshold SIGNING, bridge-custody attestation. CONSUMES
//     ThresholdService committees to produce signatures/attestations over
//     cross-chain subjects. This is M-Chain's surface (LP-7100).
//   - FHEService — confidential compute / encrypted state. CONSUMES
//     ThresholdService key/decryption committees; owns FHE jobs and
//     threshold-decrypt. This is F-Chain's surface (LP-8200).
//
// thresholdvm itself remains a LIBRARY: there is no T-Chain, no teleportvm.
package thresholdvm

import "github.com/luxfi/threshold/pkg/party"

// ThresholdService is the pure threshold-primitive surface — the substrate
// M-Chain (MPC) and F-Chain (FHE) both consume. It is distributed key
// generation, committee formation and rotation (resharing), and lookup of the
// artifacts those ceremonies produce. It deliberately excludes signing-for-
// custody (MPCService) and FHE execution (FHEService).
type ThresholdService interface {
	// InitializeMPC establishes the threshold party set for the substrate.
	InitializeMPC(partyIDs []party.ID) error

	// StartKeygen runs a distributed key-generation ceremony for keyID of the
	// given keyType, attributed to requestedBy.
	StartKeygen(keyID, keyType, requestedBy string) (*KeygenSession, error)

	// StartKeygenWithProtocol runs DKG under an explicit protocol
	// (e.g. CGGMP21 / FROST / Corona-general) with an explicit (t, n).
	StartKeygenWithProtocol(keyID, protocol, requestedBy string, threshold, totalParties int) (*KeygenSession, error)

	// RefreshKey re-randomizes the shares of an existing key without changing
	// its public key (proactive-security refresh).
	RefreshKey(keyID, requestedBy string) (*KeygenSession, error)

	// ReshareKey rotates the signer committee for keyID to a new party set
	// (LSS resharing), preserving the public key.
	ReshareKey(keyID string, newPartyIDs []party.ID, requestedBy string) (*KeygenSession, error)

	// GetPublicKey returns the group public key for keyID.
	GetPublicKey(keyID string) ([]byte, error)

	// GetAddress returns the chain address derived from keyID's public key.
	GetAddress(keyID string) ([]byte, error)
}

// MPCService is the M-Chain surface: threshold signing and bridge-custody
// attestation. It CONSUMES ThresholdService committees to sign / attest over
// cross-chain subjects. Owns no FHE.
type MPCService interface {
	ThresholdService

	// RequestSignature asks the custody committee for keyID to threshold-sign
	// messageHash on behalf of requestingChain.
	RequestSignature(requestingChain, keyID string, messageHash []byte, messageType string) (*SigningSession, error)

	// GetSignature returns the (possibly in-progress) signing session.
	GetSignature(sessionID string) (*SigningSession, error)

	// AttestOracleCommit produces a threshold attestation over an oracle
	// read/write commitment for requestingChain.
	AttestOracleCommit(requestingChain string, requestID [32]byte, kind uint8, commitRoot [32]byte, epoch uint64) (*QuantumAttestation, error)

	// AttestSessionComplete attests that a bridge/custody session finished with
	// the given output/oracle/receipts roots.
	AttestSessionComplete(requestingChain string, sessionID [32]byte, outputHash, oracleRoot, receiptsRoot [32]byte, epoch uint64) (*QuantumAttestation, error)

	// AttestEpochBeacon produces the per-epoch beacon attestation.
	AttestEpochBeacon(requestingChain string, epoch uint64, previousRef [32]byte) (*QuantumAttestation, error)

	// VerifyAttestation verifies a QuantumAttestation this service produced.
	VerifyAttestation(attestation *QuantumAttestation) error
}

// FHEService is the F-Chain surface: confidential compute over encrypted
// state. It CONSUMES ThresholdService key/decryption committees; it owns FHE
// jobs and threshold-decrypt. The FHE execution primitives live in the fhe/
// subpackage (fhe.FHEAccelerator); this interface is the chain-facing surface
// the physical fhevm package will implement in the follow-up split. Kept
// minimal and honest: today the single *VM exposes the ThresholdService
// substrate that F-Chain's FHE runtime consumes, so FHEService embeds it and
// the FHE-execution methods are added as the fhevm package is carved out.
type FHEService interface {
	ThresholdService
}

// Compatibility bridge: the single overloaded *VM satisfies all three service
// surfaces today. When the physical split lands, mpcvm.VM will satisfy
// MPCService and fhevm.VM will satisfy FHEService, each backed only by the
// substrate it needs — these assertions move to those packages and *VM here
// narrows to ThresholdService (the library substrate).
var (
	_ ThresholdService = (*VM)(nil)
	_ MPCService       = (*VM)(nil)
	_ FHEService       = (*VM)(nil)
)
