// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/luxfi/ids"
)

// Service provides RPC access to the IdentityVM.
//
// A mutating call SUBMITS a signed record. It does not create one: the caller
// holds the key, so the caller signs, and the chain checks. The service used
// to build the record itself from a public key the caller named — which is why
// registering an issuer, and revoking anyone's credential, took nothing but
// the request.
type Service struct {
	vm *VM
}

// ======== submissions ========

// SubmitIdentityArgs registers a DID: a public key and a signature by it.
type SubmitIdentityArgs struct {
	PublicKey string            `json:"publicKey"` // base64
	Signature string            `json:"signature"` // base64
	Created   int64             `json:"created"`   // UnixNano
	Metadata  map[string]string `json:"metadata,omitempty"`
	Fee       uint64            `json:"fee"`
}

// SubmitReply names what was accepted into the queue.
type SubmitReply struct {
	ID string `json:"id"`
}

// SubmitIdentity queues a new identity.
func (s *Service) SubmitIdentity(r *http.Request, args *SubmitIdentityArgs, reply *SubmitReply) error {
	if err := s.vm.gateUserTx(args.Fee); err != nil {
		return err
	}
	publicKey, signature, err := decodePair(args.PublicKey, args.Signature)
	if err != nil {
		return err
	}

	identity := &Identity{
		PublicKey: publicKey,
		Created:   time.Unix(0, args.Created).UTC(),
		Metadata:  args.Metadata,
		Signature: signature,
	}
	identity.ID = identityID(publicKey)

	if err := s.vm.Submit(&Change{Identity: identity}); err != nil {
		return err
	}
	reply.ID = identity.ID.String()
	return nil
}

// SubmitIssuerArgs registers an issuer.
type SubmitIssuerArgs struct {
	Name       string   `json:"name"`
	PublicKey  string   `json:"publicKey"` // base64
	Signature  string   `json:"signature"` // base64
	Types      []string `json:"types,omitempty"`
	TrustLevel int      `json:"trustLevel"`
	CreatedAt  int64    `json:"createdAt"` // UnixNano
	Fee        uint64   `json:"fee"`
}

// SubmitIssuer queues a new issuer.
func (s *Service) SubmitIssuer(r *http.Request, args *SubmitIssuerArgs, reply *SubmitReply) error {
	if err := s.vm.gateUserTx(args.Fee); err != nil {
		return err
	}
	publicKey, signature, err := decodePair(args.PublicKey, args.Signature)
	if err != nil {
		return err
	}

	issuer := &Issuer{
		Name:       args.Name,
		PublicKey:  publicKey,
		Types:      args.Types,
		TrustLevel: args.TrustLevel,
		CreatedAt:  time.Unix(0, args.CreatedAt).UTC(),
		Signature:  signature,
	}
	issuer.ID = issuerID(publicKey)

	if err := s.vm.Submit(&Change{Issuer: issuer}); err != nil {
		return err
	}
	reply.ID = issuer.ID.String()
	return nil
}

// SubmitCredentialArgs issues a credential, signed by its issuer.
type SubmitCredentialArgs struct {
	Type       []string               `json:"type,omitempty"`
	Issuer     string                 `json:"issuer"`
	Subject    string                 `json:"subject"`
	Issuance   int64                  `json:"issuance"`   // UnixNano
	Expiration int64                  `json:"expiration"` // UnixNano; 0 means the chain's default
	Claims     map[string]interface{} `json:"claims,omitempty"`
	Signature  string                 `json:"signature"` // base64
	Fee        uint64                 `json:"fee"`
}

// SubmitCredential queues a new credential.
func (s *Service) SubmitCredential(r *http.Request, args *SubmitCredentialArgs, reply *SubmitReply) error {
	if err := s.vm.gateUserTx(args.Fee); err != nil {
		return err
	}
	issuer, err := ids.FromString(args.Issuer)
	if err != nil {
		return err
	}
	subject, err := ids.FromString(args.Subject)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(args.Signature)
	if err != nil {
		return err
	}

	cred := &Credential{
		Type:           args.Type,
		Issuer:         issuer,
		Subject:        subject,
		IssuanceDate:   time.Unix(0, args.Issuance).UTC(),
		ExpirationDate: s.vm.expiry(args.Issuance, args.Expiration),
		Claims:         args.Claims,
		Signature:      signature,
	}
	cred.ID = tag("identityvm/credential", cred.signable())

	if err := s.vm.Submit(&Change{Credential: cred}); err != nil {
		return err
	}
	reply.ID = cred.ID.String()
	return nil
}

// expiry is when a credential lapses: what the issuer named, or the chain's
// default measured from issuance. A caller-supplied lifetime used to be added
// to the wall clock without a sign check, so a NEGATIVE one produced a
// credential that was already expired — admitted, queued, put into every block
// this node proposed, and refused by every node including this one.
func (vm *VM) expiry(issuance, expiration int64) time.Time {
	if expiration > 0 {
		return time.Unix(0, expiration).UTC()
	}
	return time.Unix(0, issuance).UTC().Add(time.Duration(vm.config.CredentialTTL) * time.Second)
}

// SubmitRevocationArgs withdraws a credential, signed by its issuer or its
// subject.
type SubmitRevocationArgs struct {
	CredentialID string `json:"credentialId"`
	RevokedBy    string `json:"revokedBy"`
	RevokedAt    int64  `json:"revokedAt"` // UnixNano
	Reason       string `json:"reason,omitempty"`
	Signature    string `json:"signature"` // base64
	Fee          uint64 `json:"fee"`
}

// SubmitRevocation queues a revocation.
func (s *Service) SubmitRevocation(r *http.Request, args *SubmitRevocationArgs, reply *SubmitReply) error {
	if err := s.vm.gateUserTx(args.Fee); err != nil {
		return err
	}
	credID, err := ids.FromString(args.CredentialID)
	if err != nil {
		return err
	}
	revoker, err := ids.FromString(args.RevokedBy)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(args.Signature)
	if err != nil {
		return err
	}

	rev := &Revocation{
		CredentialID: credID,
		RevokedBy:    revoker,
		RevokedAt:    time.Unix(0, args.RevokedAt).UTC(),
		Reason:       args.Reason,
		Signature:    signature,
	}

	if err := s.vm.Submit(&Change{Revocation: rev}); err != nil {
		return err
	}
	reply.ID = credID.String()
	return nil
}

// ======== queries ========

// IDArgs names a record by id.
type IDArgs struct {
	ID string `json:"id"`
}

// IdentityReply represents an identity in RPC responses.
type IdentityReply struct {
	ID        string            `json:"id"`
	DID       string            `json:"did"`
	PublicKey string            `json:"publicKey"`
	Created   string            `json:"created"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// GetIdentity returns an identity by id.
func (s *Service) GetIdentity(r *http.Request, args *IDArgs, reply *IdentityReply) error {
	id, err := ids.FromString(args.ID)
	if err != nil {
		return err
	}
	identity, err := s.vm.Identity(id)
	if err != nil {
		return err
	}
	*reply = describeIdentity(identity)
	return nil
}

// ResolveArgs names an identity by DID.
type ResolveArgs struct {
	DID string `json:"did"`
}

// ResolveIdentity returns the identity a DID names.
func (s *Service) ResolveIdentity(r *http.Request, args *ResolveArgs, reply *IdentityReply) error {
	identity, err := s.vm.Resolve(args.DID)
	if err != nil {
		return err
	}
	*reply = describeIdentity(identity)
	return nil
}

// CredentialReply represents a credential in RPC responses.
type CredentialReply struct {
	ID         string                 `json:"id"`
	Type       []string               `json:"type,omitempty"`
	Issuer     string                 `json:"issuer"`
	Subject    string                 `json:"subject"`
	Issuance   string                 `json:"issuance"`
	Expiration string                 `json:"expiration"`
	Claims     map[string]interface{} `json:"claims,omitempty"`
	Status     string                 `json:"status"`
}

// GetCredential returns a credential and its status.
func (s *Service) GetCredential(r *http.Request, args *IDArgs, reply *CredentialReply) error {
	id, err := ids.FromString(args.ID)
	if err != nil {
		return err
	}
	cred, status, err := s.vm.Credential(id)
	if err != nil {
		return err
	}
	*reply = CredentialReply{
		ID:         cred.ID.String(),
		Type:       cred.Type,
		Issuer:     cred.Issuer.String(),
		Subject:    cred.Subject.String(),
		Issuance:   cred.IssuanceDate.Format(time.RFC3339),
		Expiration: cred.ExpirationDate.Format(time.RFC3339),
		Claims:     cred.Claims,
		Status:     status,
	}
	return nil
}

// VerifyReply reports whether a credential is usable now.
type VerifyReply struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

// VerifyCredential reports whether a credential is recorded, unrevoked and
// unexpired. A refusal is an ANSWER, not an error: the caller asked a question
// and "no, because it is revoked" is the answer to it.
func (s *Service) VerifyCredential(r *http.Request, args *IDArgs, reply *VerifyReply) error {
	id, err := ids.FromString(args.ID)
	if err != nil {
		return err
	}
	if err := s.vm.Verify(id); err != nil {
		reply.Valid, reply.Reason = false, err.Error()
		return nil
	}
	reply.Valid = true
	return nil
}

// ProofArgs asks for a selective-disclosure artifact.
type ProofArgs struct {
	ID         string `json:"id"`
	Disclosure string `json:"disclosure"` // base64
}

// ProofReply carries the artifact.
type ProofReply struct {
	CredentialID     string `json:"credentialId"`
	IssuerDID        string `json:"issuerDid"`
	SubjectDID       string `json:"subjectDid"`
	CredType         string `json:"credType,omitempty"`
	ClaimsCommitment string `json:"claimsCommitment"`
	IssuedAt         string `json:"issuedAt"`
	ExpiresAt        string `json:"expiresAt"`
}

// CreateProof builds a selective-disclosure artifact for a credential.
func (s *Service) CreateProof(r *http.Request, args *ProofArgs, reply *ProofReply) error {
	id, err := ids.FromString(args.ID)
	if err != nil {
		return err
	}
	disclosure, err := base64.StdEncoding.DecodeString(args.Disclosure)
	if err != nil {
		return err
	}
	proof, err := s.vm.Proof(id, disclosure)
	if err != nil {
		return err
	}
	*reply = ProofReply{
		CredentialID:     proof.CredentialID.String(),
		IssuerDID:        proof.IssuerDID,
		SubjectDID:       proof.SubjectDID,
		CredType:         proof.CredType,
		ClaimsCommitment: base64.StdEncoding.EncodeToString(proof.ClaimsCommitment[:]),
		IssuedAt:         proof.IssuedAt.Format(time.RFC3339),
		ExpiresAt:        proof.ExpiresAt.Format(time.RFC3339),
	}
	return nil
}

// IssuerReply represents an issuer in RPC responses.
type IssuerReply struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	PublicKey  string   `json:"publicKey"`
	Types      []string `json:"types,omitempty"`
	TrustLevel int      `json:"trustLevel"`
	CreatedAt  string   `json:"createdAt"`
}

// GetIssuer returns an issuer by id.
func (s *Service) GetIssuer(r *http.Request, args *IDArgs, reply *IssuerReply) error {
	id, err := ids.FromString(args.ID)
	if err != nil {
		return err
	}
	issuer, err := s.vm.Issuer(id)
	if err != nil {
		return err
	}
	*reply = describeIssuer(issuer)
	return nil
}

// EmptyArgs is a call that names nothing.
type EmptyArgs struct{}

// ListIssuersReply carries every issuer the chain holds, in id order.
type ListIssuersReply struct {
	Issuers []IssuerReply `json:"issuers"`
}

// ListIssuers returns every issuer, in id order.
func (s *Service) ListIssuers(r *http.Request, args *EmptyArgs, reply *ListIssuersReply) error {
	for _, issuer := range s.vm.Issuers() {
		reply.Issuers = append(reply.Issuers, describeIssuer(issuer))
	}
	return nil
}

// HealthReply reports what the chain holds.
type HealthReply struct {
	Healthy bool              `json:"healthy"`
	Details map[string]string `json:"details"`
}

// Health reports what the chain holds, which is always an answer.
func (s *Service) Health(r *http.Request, args *EmptyArgs, reply *HealthReply) error {
	health, _ := s.vm.HealthCheck(r.Context())
	reply.Healthy, reply.Details = health.Healthy, health.Details
	return nil
}

// ======== helpers ========

func decodePair(publicKey, signature string) ([]byte, []byte, error) {
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, nil, err
	}
	return pub, sig, nil
}

func describeIdentity(i *Identity) IdentityReply {
	return IdentityReply{
		ID:        i.ID.String(),
		DID:       i.DID(),
		PublicKey: base64.StdEncoding.EncodeToString(i.PublicKey),
		Created:   i.Created.Format(time.RFC3339),
		Metadata:  i.Metadata,
	}
}

func describeIssuer(s *Issuer) IssuerReply {
	return IssuerReply{
		ID:         s.ID.String(),
		Name:       s.Name,
		PublicKey:  base64.StdEncoding.EncodeToString(s.PublicKey),
		Types:      s.Types,
		TrustLevel: s.TrustLevel,
		CreatedAt:  s.CreatedAt.Format(time.RFC3339),
	}
}
