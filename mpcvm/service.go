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
//   - ThresholdService — PURE threshold primitives: DKG, committee formation,
//     key/committee lookup. The substrate the other two consume. Owns no
//     custody, no bridge business logic, no FHE.
//   - MPCService — threshold SIGNING, bridge-custody attestation. CONSUMES
//     ThresholdService committees to produce signatures/attestations over
//     cross-chain subjects. This is M-Chain's surface (LP-7100).
//   - FHEService — confidential compute / encrypted state. CONSUMES
//     ThresholdService key/decryption committees; owns FHE jobs and
//     threshold-decrypt. This is F-Chain's surface (LP-8200).
//
// mpcvm itself remains a LIBRARY: there is no T-Chain, no teleportvm.
package mpcvm

import (
	"context"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
)

// ThresholdService is the pure threshold-primitive surface — the substrate
// M-Chain (MPC) and F-Chain (FHE) both consume. It is distributed key
// generation, committee formation, and lookup of the artifacts those ceremonies
// produce. It deliberately excludes signing-for-custody (MPCService) and FHE
// execution (FHEService).
//
// Every ceremony method takes a context and returns the COMPLETED ceremony's
// operation: a ceremony either finished (and its verifiable artifact is in
// hand) or it failed. There is no third "in progress" state to poll, because a
// handle to an unfinished ceremony is a handle to state that only one node has.
type ThresholdService interface {
	// StartKeygen runs a distributed key-generation ceremony for keyID under
	// the chain's default policy, attributed to requestedBy.
	StartKeygen(ctx context.Context, keyID, requestedBy string) (*Operation, error)

	// StartKeygenWithPolicy runs DKG under an explicit k-of-n policy. The
	// polynomial degree is derived from the policy, never passed alongside it.
	StartKeygenWithPolicy(ctx context.Context, keyID string, policy quorum.Policy, requestedBy string) (*Operation, error)

	// Policy returns the chain's default signing policy.
	Policy() quorum.Policy

	// Committee returns the ceremony party set at a P-Chain height: this
	// chain's validators. Joining the signing ring is joining the validator
	// set — there is no separate operator registry.
	Committee(ctx context.Context, height uint64) ([]party.ID, error)

	// Key returns one custody key's replicated public record; Keys returns all
	// of them.
	Key(keyID string) (*KeyRecord, error)
	Keys() ([]*KeyRecord, error)

	// PublicKey returns the compressed group public key for keyID.
	PublicKey(keyID string) ([]byte, error)

	// Address returns the external-chain custody address derived from keyID's
	// group public key.
	Address(keyID string) ([]byte, error)
}

// MPCService is the M-Chain surface: threshold signing and bridge-custody
// attestation. It CONSUMES ThresholdService committees to sign / attest over
// cross-chain subjects. Owns no FHE.
type MPCService interface {
	ThresholdService

	// RequestSignature asks the custody committee for keyID to threshold-sign
	// messageHash on behalf of requestingChain. It returns when the ceremony
	// has produced a signature that verifies under the registered group key.
	RequestSignature(ctx context.Context, requestingChain, keyID string, messageHash []byte) (*Operation, error)

	// Ceremony returns one recorded ceremony — the replicated, durable evidence
	// that a signature was produced, including the signature. Ceremonies
	// returns the whole log.
	Ceremony(id string) (*CeremonyRecord, error)
	Ceremonies() ([]*CeremonyRecord, error)

	// StateRoot is the value two validators compare to know whether they agree
	// about custody.
	StateRoot() [32]byte

	// RequestBridgeRelease is the B→M seam: a bridge release request in, a
	// threshold-signed self-describing attestation out.
	RequestBridgeRelease(ctx context.Context, req BridgeReleaseRequest) (*BridgeTransferAttestation, error)

	// AttestOracleCommit produces a threshold attestation over an oracle
	// read/write commitment for requestingChain.
	AttestOracleCommit(ctx context.Context, requestingChain, keyID string, requestID [32]byte, kind uint8, commitRoot [32]byte, epoch uint64) (*QuantumAttestation, error)

	// AttestSessionComplete attests that a bridge/custody session finished with
	// the given output/oracle/receipts roots.
	AttestSessionComplete(ctx context.Context, requestingChain, keyID string, sessionID [32]byte, outputHash, oracleRoot, receiptsRoot [32]byte, epoch uint64) (*QuantumAttestation, error)

	// AttestEpochBeacon produces the per-epoch beacon attestation.
	AttestEpochBeacon(ctx context.Context, requestingChain, keyID string, epoch uint64, previousRef [32]byte) (*QuantumAttestation, error)

	// VerifyAttestation verifies a QuantumAttestation against this node's
	// custody registry.
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
