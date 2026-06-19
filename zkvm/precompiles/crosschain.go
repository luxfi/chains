// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package precompiles

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/ids"
)

// CrossChainZKVerifierAddr is deployed on every EVM chain to route
// ZK verification requests to Z-Chain via Warp messaging.
const CrossChainZKVerifierAddr = 0x0F20

// Verifier type identifiers used in cross-chain routing.
const (
	VerifierTypeGroth16 = 0x01
	VerifierTypePLONK   = 0x02
	VerifierTypeSTARK   = 0x03
	VerifierTypeHalo2   = 0x04
	VerifierTypeNova    = 0x05
)

// CrossChainZKVerifier routes ZK verification from any EVM chain to Z-Chain.
//
// Input format:
//
//	verifier_type (1 byte)
//	proof_data    (remaining bytes — forwarded to Z-Chain verifier)
//
// The routing works via Warp messaging:
//  1. Caller on C-Chain (or any subnet EVM) invokes this precompile
//  2. Precompile constructs a Warp message addressed to Z-Chain
//  3. Z-Chain receives the message and invokes the appropriate verifier
//  4. Result is returned via Warp response
//
// Gas: base 100K (includes Warp relay overhead).
//
// StrictPQ, when set, makes this router refuse the classical
// (quantum-breakable) verifier types Groth16 and PLONK: on a strict-PQ
// chain only the post-quantum STARK/FRI path (VerifierTypeSTARK) may be
// routed. This mirrors the registration-time gate in
// RegisterZKPrecompiles — a strict-PQ chain wires this router with
// StrictPQ=true so it cannot relay a classical proof to Z-Chain.
type CrossChainZKVerifier struct {
	ZChainID ids.ID
	StrictPQ bool
}

func (v *CrossChainZKVerifier) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 100_000
	}

	// Base relay cost + verifier-specific cost
	base := uint64(100_000)
	switch input[0] {
	case VerifierTypeGroth16:
		return base + groth16Gas
	case VerifierTypePLONK:
		return base + plonkGas
	case VerifierTypeSTARK:
		return base + starkGas
	case VerifierTypeHalo2:
		return base + halo2Gas
	case VerifierTypeNova:
		return base + novaGas
	default:
		return base
	}
}

func (v *CrossChainZKVerifier) Run(input []byte) ([]byte, error) {
	if len(input) < 2 {
		return resultInvalid, errInputTooShort
	}

	verifierType := input[0]
	proofData := input[1:]

	// Strict-PQ chains refuse the classical pairing-based paths: only the
	// quantum-safe STARK/FRI rollup path may be routed.
	if v.StrictPQ && (verifierType == VerifierTypeGroth16 || verifierType == VerifierTypePLONK) {
		return resultInvalid, errClassicalForbiddenStrictPQ
	}

	// Validate verifier type
	switch verifierType {
	case VerifierTypeGroth16, VerifierTypePLONK, VerifierTypeSTARK:
		// supported — route to Z-Chain. STARK is the strict-PQ
		// (quantum-safe) rollup-proof path; Groth16/PLONK are the
		// classical pairing-based paths kept for non-strict-PQ chains.
	case VerifierTypeHalo2, VerifierTypeNova:
		return resultInvalid, errNotImplemented
	default:
		return resultInvalid, fmt.Errorf("unknown verifier type: 0x%02x", verifierType)
	}

	// Construct Warp message payload:
	// target_precompile_addr(1) | proof_data
	var targetAddr byte
	switch verifierType {
	case VerifierTypeGroth16:
		targetAddr = Groth16VerifierAddr
	case VerifierTypePLONK:
		targetAddr = PLONKVerifierAddr
	case VerifierTypeSTARK:
		targetAddr = STARKVerifierAddr
	}

	msg := encodeWarpPayload(v.ZChainID, targetAddr, proofData)

	// In production, this payload is submitted as a Warp unsigned message
	// to the Z-Chain, which executes the precompile and returns the result
	// via a Warp response. The EVM integration layer handles the async
	// Warp send/receive. Here we return the encoded message for the
	// runtime to dispatch.
	return msg, nil
}

// encodeWarpPayload encodes a cross-chain ZK verification request.
//
// Format:
//
//	z_chain_id    (32 bytes)
//	target_addr   (1 byte)
//	payload_len   (4 bytes, big-endian)
//	payload       (payload_len bytes)
func encodeWarpPayload(zChainID ids.ID, targetAddr byte, payload []byte) []byte {
	buf := make([]byte, 32+1+4+len(payload))
	copy(buf[0:32], zChainID[:])
	buf[32] = targetAddr
	binary.BigEndian.PutUint32(buf[33:37], uint32(len(payload)))
	copy(buf[37:], payload)
	return buf
}

// DecodeWarpPayload decodes a cross-chain ZK verification request.
func DecodeWarpPayload(data []byte) (zChainID ids.ID, targetAddr byte, payload []byte, err error) {
	if len(data) < 37 {
		return ids.ID{}, 0, nil, errors.New("warp payload too short")
	}
	copy(zChainID[:], data[0:32])
	targetAddr = data[32]
	payloadLen := binary.BigEndian.Uint32(data[33:37])
	if uint32(len(data)) < 37+payloadLen {
		return ids.ID{}, 0, nil, errors.New("warp payload truncated")
	}
	payload = data[37 : 37+payloadLen]
	return zChainID, targetAddr, payload, nil
}
