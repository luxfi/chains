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
	Signers     []party.ID     `json:"signers"`     // the T+1 quorum that signed
	KeyID       string         `json:"keyId"`
	CreatedAt   int64          `json:"createdAt"`
}

// BridgeReleaseRequest is the clean, self-contained request B hands M to
// authorise a cross-chain release. It carries exactly the fields that bind the
// release (both chain ids, asset, amount, recipient, per-route nonce) plus the
// M-Chain routing context (which authorised chain is asking, and which custody
// key must sign). Everything the digest commits to travels here; nothing else
// can be minted from the resulting attestation.
type BridgeReleaseRequest struct {
	RequestingChain string   `json:"requestingChain"` // authorised chain id in M's permission table (e.g. "B-Chain")
	KeyID           string   `json:"keyId"`           // custody key to sign with; empty => M's active custody key
	SrcChainID      uint32   `json:"srcChainId"`
	DstChainID      uint32   `json:"dstChainId"`
	Asset           [32]byte `json:"asset"`
	Amount          uint64   `json:"amount"`
	Recipient       [20]byte `json:"recipient"`
	Nonce           uint64   `json:"nonce"`
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
func (vm *VM) RequestBridgeRelease(req BridgeReleaseRequest) (*BridgeTransferAttestation, error) {
	keyID := req.KeyID
	if keyID == "" {
		vm.mu.RLock()
		keyID = vm.activeKeyID
		vm.mu.RUnlock()
	}
	bt := BridgeTransfer{
		SrcChainID: req.SrcChainID,
		DstChainID: req.DstChainID,
		Asset:      req.Asset,
		Amount:     req.Amount,
		Recipient:  req.Recipient,
		Nonce:      req.Nonce,
	}
	return vm.AttestBridgeTransfer(req.RequestingChain, keyID, bt)
}

// AttestBridgeTransfer produces a threshold attestation over a bridge transfer.
// It mirrors AttestOracleCommit: compute the domain-bound digest, request a
// threshold signature from the committee, and return the self-describing
// attestation B verifies. The signing itself runs through the native transport
// (executor + MessageRouter) once the VM's signing path is bound to a
// per-session router; the digest and verification below are transport-agnostic
// and are what B consumes.
func (vm *VM) AttestBridgeTransfer(
	requestingChain string,
	keyID string,
	bt BridgeTransfer,
) (*BridgeTransferAttestation, error) {
	digest := bt.Digest()

	session, err := vm.RequestSignature(requestingChain, keyID, digest[:], "raw")
	if err != nil {
		return nil, fmt.Errorf("mpcvm: request bridge attestation: %w", err)
	}

	// Wait for the threshold signature to complete.
	ctx, cancel := context.WithTimeout(context.Background(), vm.config.SessionTimeout)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("mpcvm: bridge attestation timed out")
		case <-time.After(100 * time.Millisecond):
			s, err := vm.GetSignature(session.SessionID)
			if err != nil {
				continue
			}
			if s.Status == "failed" {
				return nil, fmt.Errorf("mpcvm: bridge attestation signing failed: %s", s.Error)
			}
			if s.Status != "completed" {
				continue
			}
			pub, err := vm.GetPublicKey(keyID)
			if err != nil {
				pub = nil
			}
			return &BridgeTransferAttestation{
				Transfer:    bt,
				Digest:      digest,
				Signature:   packSig(s.Signature),
				GroupPubKey: pub,
				Signers:     s.SignerParties,
				KeyID:       keyID,
				CreatedAt:   time.Now().Unix(),
			}, nil
		}
	}
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

// packSig flattens a session signature into r(32)‖s(32)‖v(1).
func packSig(sig *ecdsaSignature) []byte {
	if sig == nil {
		return nil
	}
	out := make([]byte, 0, 65)
	out = append(out, leftPad(sig.R, 32)...)
	out = append(out, leftPad(sig.S, 32)...)
	out = append(out, sig.V)
	return out
}

// leftPad left-pads b to n bytes (big-endian scalar normalisation).
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}
