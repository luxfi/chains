// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package bridgeattest is the ONE canonical definition of the bridge-transfer
// attestation seam between B-Chain (bridgevm) and M-Chain (mpcvm).
//
// M threshold-signs a domain-bound bridge-transfer digest; B (and every EVM
// gateway holding the group key's address) verifies that signature before it
// mints/releases. M owns the signature; B owns what the message authorises. The
// signature is a standard secp256k1 ECDSA signature, so anyone holding the group
// key verifies it with zero interaction — no callback to M.
//
// This package is deliberately dependency-free (stdlib + luxfi/crypto/secp256k1
// only). It is a value seam, not a place: the digest is a pure function of the
// transfer's field values, so it lives in one small package that both the
// M-Chain VM and the B-Chain VM import — never duplicated, never able to drift.
//
// The digest layout, field order, domain tag, and signature encoding are FROZEN.
// The on-chain Solidity BridgeGateway (chains/bridgevm/contracts) recomputes the
// exact same sha256 preimage; the KAT vector in attest_test.go pins the bytes so
// any drift on any of the three surfaces (M Go, B Go, Solidity) trips a test.
package bridgeattest

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/luxfi/crypto/secp256k1"
)

// DomainTag is the domain-separation tag hashed into every bridge-transfer
// digest, so a bridge attestation can never be replayed as any other message M
// signs (oracle writes, session-complete, epoch beacons, ...). It is written raw
// (no length prefix) as the first bytes of the preimage.
const DomainTag = "LUX_BRIDGE_TRANSFER_v1"

// BridgeTransfer is the domain-bound message B commits to on lock and M signs as
// its attestation. Field layout is FROZEN so the digest is canonical across
// validators and across the B/M/Solidity boundary.
//
// One attestation over one BridgeTransfer authorises exactly one mint — of that
// amount, of that asset, to that recipient, on that route (src->dst), at that
// nonce — and nothing else.
type BridgeTransfer struct {
	SrcChainID uint32   `json:"srcChainId"` // source EVM chain id
	DstChainID uint32   `json:"dstChainId"` // destination EVM chain id
	Asset      [32]byte `json:"asset"`      // canonical cross-chain asset id
	Amount     uint64   `json:"amount"`     // units locked on src == minted on dst
	Recipient  [20]byte `json:"recipient"`  // destination recipient (20-byte account)
	Nonce      uint64   `json:"nonce"`      // per-route monotonic nonce (replay guard)
}

// Digest is the canonical, domain-separated signing preimage for a transfer.
//
//	sha256(
//	  "LUX_BRIDGE_TRANSFER_v1"   // 22-byte ASCII tag, raw
//	  || uint32_BE(SrcChainID)   // 4
//	  || uint32_BE(DstChainID)   // 4
//	  || Asset[32]               // 32
//	  || uint64_BE(Amount)       // 8
//	  || Recipient[20]           // 20
//	  || uint64_BE(Nonce)        // 8
//	)
//
// abi.encodePacked(bytes(DomainTag), uint32, uint32, bytes32, uint256(u64),
// bytes20, uint64) on the Solidity side produces the identical preimage.
func (bt BridgeTransfer) Digest() [32]byte {
	h := sha256.New()
	h.Write([]byte(DomainTag))
	var b [8]byte
	binary.BigEndian.PutUint32(b[:4], bt.SrcChainID)
	h.Write(b[:4])
	binary.BigEndian.PutUint32(b[:4], bt.DstChainID)
	h.Write(b[:4])
	h.Write(bt.Asset[:])
	binary.BigEndian.PutUint64(b[:], bt.Amount)
	h.Write(b[:])
	h.Write(bt.Recipient[:])
	binary.BigEndian.PutUint64(b[:], bt.Nonce)
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Attestation is M's threshold signature over a transfer, plus the context B
// needs to verify it. Self-describing so B (or a relayer) can verify without
// re-querying M.
type Attestation struct {
	Transfer    BridgeTransfer `json:"transfer"`
	Digest      [32]byte       `json:"digest"`
	Signature   []byte         `json:"signature"`   // secp256k1 r(32)||s(32)||v(1)
	GroupPubKey []byte         `json:"groupPubKey"` // 33-byte compressed group key
	Signers     []string       `json:"signers"`     // party ids of the T+1 quorum
	KeyID       string         `json:"keyId"`
	CreatedAt   int64          `json:"createdAt"`
}

// Verify returns true iff the attestation's signature is a valid threshold
// signature by the group key over THIS transfer's domain-bound digest, and the
// self-reported digest matches the recomputed one. Defense in depth: B calls
// this before it broadcasts a release, even though the on-chain gateway also
// verifies.
func (a *Attestation) Verify() bool {
	if a == nil {
		return false
	}
	if a.Digest != a.Transfer.Digest() {
		return false
	}
	return VerifyBridgeAttestation(a.GroupPubKey, a.Transfer, a.Signature)
}

// VerifyBridgeAttestation returns true iff sig is a valid ECDSA signature by
// groupPubKey over the transfer's domain-bound digest. Accepts r||s (64) or
// r||s||v (65). A threshold ECDSA signature verifies exactly like a single-key
// one, so there is no interaction with M.
func VerifyBridgeAttestation(groupPubKey []byte, bt BridgeTransfer, sig []byte) bool {
	if len(sig) == 65 {
		sig = sig[:64] // drop recovery id; VerifySignature wants r||s
	}
	if len(sig) != 64 || len(groupPubKey) == 0 {
		return false
	}
	d := bt.Digest()
	return secp256k1.VerifySignature(groupPubKey, d[:], sig)
}
