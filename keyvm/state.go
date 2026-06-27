// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"github.com/luxfi/chains/fee"
	"github.com/luxfi/ids"
)

// ZERO-SECRET INVARIANT (the K-Chain's reason to exist).
//
// K-Chain is an AUTHORIZATION and COORDINATION plane for distributed keys. It
// can NEVER hold, store, reconstruct, or transmit secret key material or
// threshold shares — even a fully compromised K validator must yield NOTHING
// usable to reconstruct a key. The shares live OFF-K, on the MPC/threshold
// committee. K records only PUBLIC artifacts and policy, and it triggers
// (authorizes + coordinates) ceremonies the committee actually performs.
//
// This invariant is enforced STRUCTURALLY, not by discipline: the only types K
// persists are the three below, and every field of them is public by
// construction (public keys, public VSS commitments, public committee node
// IDs, public policy, public addresses, public timestamps). There is no field
// whose type or name can carry a private key or a share. authonly_test.go
// proves this two ways: (1) a reflection walk of these types rejects any
// secret-typed or secret-named field, and (2) a scan of the package source
// rejects any call that could generate, parse, reconstruct, or sign with a
// secret. Together they make holding-a-secret and reconstructing-a-secret
// structurally impossible in this package, not merely unimplemented.

// Key lifecycle states.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// Ceremony types K may authorize on the committee. K authorizes and records the
// PUBLIC result; it performs none of the secret-bearing computation.
const (
	CeremonyDKG     = "dkg"     // distributed key generation (result: public key + commitments)
	CeremonySign    = "sign"    // threshold signing (result: aggregate signature)
	CeremonyReshare = "reshare" // proactive resharing (result: new commitments/committee)
)

// Ceremony lifecycle states.
const (
	CeremonyAuthorized = "authorized" // K authorized it; committee may proceed
	CeremonyFulfilled  = "fulfilled"  // committee returned a public result
	CeremonyRejected   = "rejected"   // policy denied or committee failed
)

// AuthPolicy is the access-control rule set for a key: who may administer it and
// who may invoke ceremonies on it, under what temporal/rate conditions. It is
// pure PUBLIC policy — addresses and limits, never secrets.
type AuthPolicy struct {
	// Admins may change this policy and revoke the key.
	Admins []fee.Account `json:"admins"`
	// Authorized may request ceremonies (sign/dkg/reshare) on this key.
	Authorized []fee.Account `json:"authorized"`
	// MaxOpsPerEpoch bounds authorized ceremonies per epoch (0 = unlimited).
	MaxOpsPerEpoch uint32 `json:"maxOpsPerEpoch"`
	// RequireQuorum is the minimum committee acknowledgement K records before a
	// ceremony is considered fulfillable (informational on K; enforced by the
	// committee). 0 means "use the key's threshold".
	RequireQuorum uint32 `json:"requireQuorum"`
	// ExpiresAt is a unix timestamp after which no ceremony is authorized; 0 = no expiry.
	ExpiresAt int64 `json:"expiresAt"`
}

// MayAdmin reports whether a may administer (set policy / revoke) the key.
func (p AuthPolicy) MayAdmin(a fee.Account) bool {
	for _, adm := range p.Admins {
		if adm == a {
			return true
		}
	}
	return false
}

// MayInvoke reports whether a may request a ceremony at time now. An expired
// policy authorizes no one (fail closed); admins may always invoke.
func (p AuthPolicy) MayInvoke(a fee.Account, now int64) bool {
	if p.ExpiresAt != 0 && now >= p.ExpiresAt {
		return false
	}
	if p.MayAdmin(a) {
		return true
	}
	for _, auth := range p.Authorized {
		if auth == a {
			return true
		}
	}
	return false
}

// KeyRecord is the ONLY per-key state K stores. Every field is PUBLIC. There is
// deliberately no PrivateKey, no Share, no Seed — K holds the public key and the
// VSS COMMITMENTS (public curve points that let anyone verify a share without
// learning it), the committee that holds the shares off-K, and the policy.
type KeyRecord struct {
	ID          ids.ID       `json:"id"`
	Name        string       `json:"name"`
	Algorithm   string       `json:"algorithm"`
	PublicKey   []byte       `json:"publicKey"`   // PUBLIC key bytes
	Threshold   uint32       `json:"threshold"`   // t in t-of-n
	TotalShares uint32       `json:"totalShares"` // n in t-of-n
	Commitments [][]byte     `json:"commitments"` // PUBLIC VSS commitments, NOT shares
	Committee   []ids.NodeID `json:"committee"`   // off-K share holders (public IDs)
	Policy      AuthPolicy   `json:"policy"`
	Owner       fee.Account  `json:"owner"`
	Status      string       `json:"status"`
	CreatedAt   int64        `json:"createdAt"`
	UpdatedAt   int64        `json:"updatedAt"`
}

// CeremonyRecord is K's record of an authorized DKG/sign/reshare ceremony. K
// stores the authorization decision and the ceremony's PUBLIC inputs/outputs
// (the digest to be signed; the resulting aggregate signature or public key).
// It never stores shares or partial secrets.
type CeremonyRecord struct {
	ID        ids.ID      `json:"id"`
	KeyID     ids.ID      `json:"keyId"`
	Type      string      `json:"type"`
	Requester fee.Account `json:"requester"`
	Message   []byte      `json:"message"` // PUBLIC digest to sign (sign ceremonies)
	Result    []byte      `json:"result"`  // PUBLIC result (signature / new public key)
	Status    string      `json:"status"`
	CreatedAt int64       `json:"createdAt"`
}
