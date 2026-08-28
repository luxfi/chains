// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
)

// Keys on this chain are ML-DSA-65. An identity outlives the credentials
// issued against it, and a signature that a quantum computer can forge is a
// signature over an identity someone else then controls — so the classical
// choice is the one that expires.
const KeyMode = mldsa.MLDSA65

// didPrefix is the method this chain answers to. A DID is DERIVED from the
// identity's id rather than stored beside it: a stored one is a second name
// that can disagree with the first.
const didPrefix = "did:lux:"

var (
	errUnknownIdentity   = errors.New("identityvm: unknown identity")
	errUnknownCredential = errors.New("identityvm: unknown credential")
	errUnknownIssuer     = errors.New("identityvm: unknown issuer")
	errCredentialRevoked = errors.New("identityvm: credential revoked")
	errCredentialExpired = errors.New("identityvm: credential expired")
	errNotIssuer         = errors.New("identityvm: not an authorized issuer")
	errNotAuthorized     = errors.New("identityvm: signature does not authorize this")
	errExists            = errors.New("identityvm: already recorded")
	errWrongID           = errors.New("identityvm: id does not name this record")
	errTooManyClaims     = errors.New("identityvm: too many claims")
	errNoKey             = errors.New("identityvm: public key is not an ML-DSA-65 key")
)

// Identity is a decentralized identifier: a public key, and what the chain
// records about it.
//
// It carries no Controllers, no Services and no Updated: nothing wrote them,
// and this chain has no update path for a DID document, so a field that can
// only ever be empty is not a field. Adding one means adding the update
// transaction that fills it, verified like everything else here.
type Identity struct {
	ID        ids.ID            `json:"id"`
	PublicKey []byte            `json:"publicKey"`
	Created   time.Time         `json:"created"`
	Metadata  map[string]string `json:"metadata,omitempty"`

	// Signature is by PublicKey over signable(), so registering a key means
	// holding it.
	Signature []byte `json:"signature"`
}

// DID is the identifier this identity answers to, derived from its id.
func (i *Identity) DID() string { return didPrefix + i.ID.String() }

// identityFrom parses a DID back to the id it names.
func identityFrom(did string) (ids.ID, error) {
	if !strings.HasPrefix(did, didPrefix) {
		return ids.Empty, fmt.Errorf("%w: %q is not a %s identifier", errUnknownIdentity, did, didPrefix)
	}
	return ids.FromString(strings.TrimPrefix(did, didPrefix))
}

// Issuer is a party the chain lets issue credentials.
type Issuer struct {
	ID         ids.ID    `json:"id"`
	Name       string    `json:"name"`
	PublicKey  []byte    `json:"publicKey"`
	Types      []string  `json:"types"`
	TrustLevel int       `json:"trustLevel"`
	CreatedAt  time.Time `json:"createdAt"`

	Signature []byte `json:"signature"`
}

// Credential is a verifiable claim an issuer makes about a subject.
//
// It carries no Status: whether a credential is revoked is what the revocation
// set says, and whether it is expired is what its expiry and the clock say.
// A stored status is a third answer that has to be kept in step with both, and
// keeping it in step is what had GetCredential writing under a read lock.
type Credential struct {
	ID             ids.ID                 `json:"id"`
	Type           []string               `json:"type"`
	Issuer         ids.ID                 `json:"issuer"`
	Subject        ids.ID                 `json:"subject"`
	IssuanceDate   time.Time              `json:"issuanceDate"`
	ExpirationDate time.Time              `json:"expirationDate"`
	Claims         map[string]interface{} `json:"claims"`

	// Signature is by the ISSUER's key over signable(). Without it, issuing is
	// naming an issuer, which anyone can do.
	Signature []byte `json:"signature"`
}

// Revocation withdraws a credential. One credential has at most one.
type Revocation struct {
	CredentialID ids.ID    `json:"credentialId"`
	RevokedBy    ids.ID    `json:"revokedBy"`
	RevokedAt    time.Time `json:"revokedAt"`
	Reason       string    `json:"reason,omitempty"`

	// Signature is by RevokedBy's key over signable(). RevokedBy used to be a
	// bare id compared against the credential's issuer and subject, both of
	// which GetCredential publishes — so revoking someone's credential was
	// pasting their id into the request.
	Signature []byte `json:"signature"`
}

// A record's identity is a hash over what it says, so an id a peer supplies is
// an id it can be held to.
func identityID(publicKey []byte) ids.ID {
	return tag("identityvm/identity", publicKey)
}

func issuerID(publicKey []byte) ids.ID {
	return tag("identityvm/issuer", publicKey)
}

func tag(domain string, b []byte) ids.ID {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(b)
	return ids.ID(h.Sum(nil))
}

// verify checks a record's signature against a public key, with the chain's
// binding as the signing context — so a signature made for one chain does not
// authorize anything on another.
func verify(publicKey, message, signature, bind []byte) error {
	pub, err := mldsa.PublicKeyFromBytes(publicKey, KeyMode)
	if err != nil {
		return fmt.Errorf("%w: %w", errNoKey, err)
	}
	if !pub.VerifySignatureCtx(message, signature, bind) {
		return errNotAuthorized
	}
	return nil
}
