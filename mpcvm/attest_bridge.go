// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// attest_bridge.go — the bridge attestation domain on the M-Chain.
//
// This is the seam between M (mpcvm) and B (bridgevm): M threshold-signs a
// domain-bound bridge-transfer message; B verifies that signature inline before
// it mints/releases. M owns the signature; B owns what the message means. The
// signature is a standard secp256k1 ECDSA signature, so B (or any chain holding
// the group key) verifies it with zero interaction — no callback to M.
//
// Mirrors AttestOracleCommit (vm.go): a domain-separated payload → a threshold
// signature → an attestation record. The BridgeTransfer digest binds both chain
// IDs, the asset, the amount, the recipient and a nonce, so one attestation
// authorises exactly one mint — of that amount, to that recipient, on that
// route — and nothing else.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/threshold/pkg/party"
)

// bridgeTransferDomainTag is the domain-separation tag hashed into every bridge
// transfer digest, so a bridge attestation can never be replayed as any other
// message M signs (oracle writes, session-complete, epoch beacons, ...).
const bridgeTransferDomainTag = "LUX_BRIDGE_TRANSFER_v1"

// DomainBridgeTransfer registers the bridge domain with the attestation domain
// registry so QuantumAttestation-style tooling recognises it.
const DomainBridgeTransfer AttestationDomain = "bridge/transfer"

func init() {
	// Additive registration; does not touch existing domains.
	domainSeparators[DomainBridgeTransfer] = []byte(bridgeTransferDomainTag)
}

// BridgeTransfer is the domain-bound message B commits to on lock and M signs as
// its attestation. Field layout is fixed so the digest is canonical across
// validators and across the B/M boundary.
type BridgeTransfer struct {
	SrcChainID uint32   `json:"srcChainId"` // source network id
	DstChainID uint32   `json:"dstChainId"` // destination network id
	Asset      [32]byte `json:"asset"`      // canonical asset id
	Amount     uint64   `json:"amount"`     // units locked on source == minted on dest
	Recipient  [20]byte `json:"recipient"`  // destination recipient (20-byte account)
	Nonce      uint64   `json:"nonce"`      // per-route monotonic nonce (replay guard)
}

// Digest is the canonical, domain-separated signing preimage for a transfer.
func (bt BridgeTransfer) Digest() [32]byte {
	h := sha256.New()
	h.Write([]byte(bridgeTransferDomainTag))
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

// BridgeTransferAttestation is M's threshold signature over a transfer, plus the
// context B needs to verify it. Self-describing so B (or a relayer) can verify
// without re-querying M.
type BridgeTransferAttestation struct {
	Transfer    BridgeTransfer `json:"transfer"`
	Digest      [32]byte       `json:"digest"`
	Signature   []byte         `json:"signature"`   // secp256k1 r(32)‖s(32)‖v(1)
	GroupPubKey []byte         `json:"groupPubKey"` // 33-byte compressed group key
	Signers     []party.ID     `json:"signers"`     // the quorum that signed
	KeyID       string         `json:"keyId"`
	// CeremonyID is this attestation's entry in M-Chain's replicated ceremony
	// log — the audit handle that turns "B was handed a signature" into "B can
	// point at the consensus record that produced it".
	CeremonyID string `json:"ceremonyId"`
	CreatedAt  int64  `json:"createdAt"`
}

// BridgeReleaseRequest is the clean, self-contained request B hands M to
// authorise a cross-chain release. It carries exactly the fields that bind the
// release (both chain ids, asset, amount, recipient, per-route nonce) plus the
// M-Chain routing context (which authorised chain is asking, and which custody
// key must sign). Everything the digest commits to travels here; nothing else
// can be minted from the resulting attestation.
type BridgeReleaseRequest struct {
	RequestingChain string `json:"requestingChain"` // authorised chain id in M's permission table (e.g. "B-Chain")
	// KeyID names the custody key that must sign. It is REQUIRED: there is no
	// "active key" for a request to fall back to, because a fallback means the
	// chain, not the requester, chose which vault to spend from — and a key
	// rotation would silently redirect releases to a different custody address.
	KeyID      string   `json:"keyId"`
	SrcChainID uint32   `json:"srcChainId"`
	DstChainID uint32   `json:"dstChainId"`
	Asset      [32]byte `json:"asset"`
	Amount     uint64   `json:"amount"`
	Recipient  [20]byte `json:"recipient"`
	Nonce      uint64   `json:"nonce"`
}

// RequestBridgeRelease is THE B→M seam: B calls this with a release request and
// gets back a threshold-signed, self-describing attestation. M computes the
// domain-bound digest, threshold-signs it across the committee, and returns the
// signature plus the group key and quorum B needs to verify — no callback to M.
// B's gate on the return value is VerifyBridgeAttestation.
//
// The signature is a standard secp256k1 ECDSA signature over the domain-bound
// digest, so a destination-chain gateway contract verifies it exactly like a
// single-key signature (ecrecover to the custody address).
func (vm *VM) RequestBridgeRelease(ctx context.Context, req BridgeReleaseRequest) (*BridgeTransferAttestation, error) {
	return vm.AttestBridgeTransfer(ctx, req.RequestingChain, req.KeyID, BridgeTransfer{
		SrcChainID: req.SrcChainID,
		DstChainID: req.DstChainID,
		Asset:      req.Asset,
		Amount:     req.Amount,
		Recipient:  req.Recipient,
		Nonce:      req.Nonce,
	})
}

// AttestBridgeTransfer produces a threshold attestation over a bridge transfer:
// compute the domain-bound digest, run the ceremony across the committee, and
// return the self-describing attestation B verifies.
//
// The ceremony is complete when this returns — the signature is in the returned
// operation, and the same signature is recorded in the replicated ceremony log
// under op.CeremonyID once the block carrying it is accepted. B can therefore
// verify immediately (VerifyBridgeAttestation, no interaction) and audit later
// (Ceremony(id), against consensus state).
func (vm *VM) AttestBridgeTransfer(
	ctx context.Context,
	requestingChain string,
	keyID string,
	bt BridgeTransfer,
) (*BridgeTransferAttestation, error) {
	digest := bt.Digest()

	op, err := vm.RequestSignature(ctx, requestingChain, keyID, digest[:])
	if err != nil {
		return nil, fmt.Errorf("mpcvm: bridge attestation for %s: %w", keyID, err)
	}
	// The group key travels with the attestation so B verifies without a
	// round-trip to M. Failing to read it is fatal, not something to paper over
	// with a nil key: an attestation nobody can verify is worse than an error.
	pub, err := vm.PublicKey(keyID)
	if err != nil {
		return nil, err
	}

	return &BridgeTransferAttestation{
		Transfer:    bt,
		Digest:      digest,
		Signature:   op.Artifact,
		GroupPubKey: pub,
		Signers:     op.Signers,
		KeyID:       keyID,
		CeremonyID:  op.CeremonyID,
		CreatedAt:   time.Now().Unix(),
	}, nil
}

// VerifyBridgeAttestation is B's gate: it returns true iff sig is a valid
// threshold signature by the group key over THIS transfer's domain-bound
// digest. Accepts r‖s (64) or r‖s‖v (65). No interaction with M — a threshold
// ECDSA signature verifies exactly like a single-key one.
func VerifyBridgeAttestation(groupPubKey []byte, bt BridgeTransfer, sig []byte) bool {
	if len(sig) == 65 {
		sig = sig[:64] // drop recovery id; VerifySignature wants r‖s
	}
	if len(sig) != 64 || len(groupPubKey) == 0 {
		return false
	}
	d := bt.Digest()
	return secp256k1.VerifySignature(groupPubKey, d[:], sig)
}
