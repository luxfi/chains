// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgeattest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/luxfi/crypto/secp256k1"
)

// security.go — the attested message for a security crossing.
//
// A fungible transfer says move N units of an asset to an account. A security
// crossing cannot be said that way. The destination has to run the register
// before the position exists there: whether the recipient is verified, which
// claims their identity carries, what act this is (an arrival is not a mint),
// and whose clock the position brings with it. None of that fits BridgeTransfer,
// whose field layout is frozen and whose Amount is a uint64 — too small to hold
// an eighteen-decimal position above about 18.4 tokens.
//
// So this is a sibling message with its own domain tag rather than a widening
// of that one. Two consequences, both wanted: the frozen digest stays frozen,
// and a fungible attestation can never be replayed as a security one, because
// the tag they commit to differs in the first bytes of the preimage.

// SecurityDomainTag separates a security crossing from every other message M
// signs. Written raw, as the first bytes of the preimage, exactly as DomainTag
// is.
const SecurityDomainTag = "LUX_SECURITY_CROSSING_v1"

// SecurityCrossing is the domain-bound message B commits to when a security
// leaves one register, and M threshold-signs as its attestation. Field layout is
// FROZEN, for the same reason BridgeTransfer's is: the digest has to be
// identical across validators and across the B/M/Solidity boundary.
//
// One attestation authorises exactly one arrival — of that quantity, of that
// security, to that holder, on that route, at that nonce — and nothing else.
type SecurityCrossing struct {
	SrcChainID uint32 `json:"srcChainId"` // source EVM chain id
	DstChainID uint32 `json:"dstChainId"` // destination EVM chain id

	// Security is the canonical cross-chain id of the security itself, not the
	// token contract on either side. The same paper has a different address on
	// every register it appears on.
	Security [32]byte `json:"security"`

	// Quantity is 32 bytes big-endian, holding the full uint256 the token
	// moves. A security's smallest unit is the register's business and an
	// eighteen-decimal position overflows a uint64 at about 18.4 tokens, so a
	// crossing that could not carry more than that would be a crossing for
	// nothing.
	Quantity [32]byte `json:"quantity"`

	// Holder is the account the position lands on.
	Holder [20]byte `json:"holder"`

	// Identity is the holder's ONCHAINID on the SOURCE register.
	//
	// It travels because the register's clocks belong to the person and not to
	// the key: a holding period that starts again on arrival is a holding
	// period a crossing can wash off, and the destination cannot ask the source
	// register anything. Zero where the source had no identity registered — an
	// honest absence, which the destination weighs as it likes rather than
	// reading as an identity of zero.
	Identity [20]byte `json:"identity"`

	// Acquired is when the holder first received on the SOURCE register, in
	// seconds. The destination anchors the arriving position's clock to it
	// rather than to now, so a §144 holding period or a Reg CF year is served
	// once by the holder and not once per chain they visit. Zero means the
	// source had no anchor to send.
	Acquired uint64 `json:"acquired"`

	// Nonce is the per-route monotonic replay guard.
	Nonce uint64 `json:"nonce"`
}

// Digest is the canonical, domain-separated signing preimage for a crossing.
//
//	sha256(
//	  "LUX_SECURITY_CROSSING_v1"  // 24-byte ASCII tag, raw
//	  || uint32_BE(SrcChainID)    // 4
//	  || uint32_BE(DstChainID)    // 4
//	  || Security[32]             // 32
//	  || Quantity[32]             // 32, big-endian uint256
//	  || Holder[20]               // 20
//	  || Identity[20]             // 20
//	  || uint64_BE(Acquired)      // 8
//	  || uint64_BE(Nonce)         // 8
//	)
//
// abi.encodePacked(bytes(SecurityDomainTag), uint32, uint32, bytes32, uint256,
// bytes20, bytes20, uint64, uint64) on the Solidity side produces the identical
// preimage.
func (sc SecurityCrossing) Digest() [32]byte {
	h := sha256.New()
	h.Write([]byte(SecurityDomainTag))
	var b [8]byte
	binary.BigEndian.PutUint32(b[:4], sc.SrcChainID)
	h.Write(b[:4])
	binary.BigEndian.PutUint32(b[:4], sc.DstChainID)
	h.Write(b[:4])
	h.Write(sc.Security[:])
	h.Write(sc.Quantity[:])
	h.Write(sc.Holder[:])
	h.Write(sc.Identity[:])
	binary.BigEndian.PutUint64(b[:], sc.Acquired)
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], sc.Nonce)
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SecurityAttestation is M's threshold signature over a crossing, plus the
// context B needs to verify it without re-querying M.
type SecurityAttestation struct {
	Crossing    SecurityCrossing `json:"crossing"`
	Digest      [32]byte         `json:"digest"`
	Signature   []byte           `json:"signature"`   // secp256k1 r||s||v
	GroupPubKey []byte           `json:"groupPubKey"` // 33-byte compressed group key
	Signers     []string         `json:"signers"`     // party ids of the T+1 quorum
	KeyID       string           `json:"keyId"`
	// CeremonyID is this attestation's entry in M-Chain's replicated ceremony
	// log — the handle that turns "B was handed a signature" into "B can point
	// at the consensus record that produced it".
	CeremonyID string `json:"ceremonyId"`
	CreatedAt  int64  `json:"createdAt"`
}

// VerifyAgainst returns true iff the signature is a valid threshold signature,
// by the EXPECTED group key, over this crossing's domain-bound digest.
//
// The expected key is an argument because it is the whole check — reading the
// key off the struct being verified answers "was this signed by whoever signed
// it", which every attestation satisfies, including one an attacker minted with
// its own key. See VerifyAgainst on Attestation, where that was a real defect.
func (a *SecurityAttestation) VerifyAgainst(expectedGroupKey []byte) bool {
	if a == nil || len(expectedGroupKey) == 0 {
		return false
	}
	if a.Digest != a.Crossing.Digest() {
		return false
	}
	if len(a.GroupPubKey) != 0 && !bytes.Equal(a.GroupPubKey, expectedGroupKey) {
		return false
	}
	return VerifySecurityAttestation(expectedGroupKey, a.Crossing, a.Signature)
}

// VerifySecurityAttestation returns true iff sig is a valid ECDSA signature by
// groupPubKey over the crossing's domain-bound digest. Accepts r||s (64) or
// r||s||v (65). A threshold signature verifies exactly like a single-key one, so
// there is no interaction with M.
func VerifySecurityAttestation(groupPubKey []byte, sc SecurityCrossing, sig []byte) bool {
	if len(sig) == 65 {
		sig = sig[:64]
	}
	if len(sig) != 64 || len(groupPubKey) == 0 {
		return false
	}
	d := sc.Digest()
	return secp256k1.VerifySignature(groupPubKey, d[:], sig)
}
