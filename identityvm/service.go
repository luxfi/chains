// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/luxfi/ids"
)

// Service provides RPC access to the IdentityVM
type Service struct {
	vm *VM
}

// ======== Identity API ========

// CreateIdentityArgs are arguments for CreateIdentity
type CreateIdentityArgs struct {
	PublicKey string            `json:"publicKey"` // Base64-encoded
	Metadata  map[string]string `json:"metadata"`
}

// CreateIdentityReply is the reply for CreateIdentity
type CreateIdentityReply struct {
	ID  string `json:"id"`
	DID string `json:"did"`
}

// CreateIdentity creates a new decentralized identity
func (s *Service) CreateIdentity(r *http.Request, args *CreateIdentityArgs, reply *CreateIdentityReply) error {
	publicKey, err := base64.StdEncoding.DecodeString(args.PublicKey)
	if err != nil {
		return err
	}

	identity, err := s.vm.CreateIdentity(publicKey, args.Metadata)
	if err != nil {
		return err
	}

	reply.ID = identity.ID.String()
	reply.DID = identity.DID
	return nil
}

// GetIdentityArgs are arguments for GetIdentity
type GetIdentityArgs struct {
	ID string `json:"id"`
}

// IdentityReply represents an identity in RPC responses
type IdentityReply struct {
	ID        string            `json:"id"`
	DID       string            `json:"did"`
	PublicKey string            `json:"publicKey"`
	Created   string            `json:"created"`
	Updated   string            `json:"updated"`
	Metadata  map[string]string `json:"metadata"`
	Services  []ServiceEndpoint `json:"services"`
}

// GetIdentityReply is the reply for GetIdentity
type GetIdentityReply struct {
	Identity IdentityReply `json:"identity"`
}

// GetIdentity returns an identity by ID
func (s *Service) GetIdentity(r *http.Request, args *GetIdentityArgs, reply *GetIdentityReply) error {
	identityID, err := ids.FromString(args.ID)
	if err != nil {
		return err
	}

	identity, err := s.vm.GetIdentity(identityID)
	if err != nil {
		return err
	}

	reply.Identity = IdentityReply{
		ID:        identity.ID.String(),
		DID:       identity.DID,
		PublicKey: base64.StdEncoding.EncodeToString(identity.PublicKey),
		Created:   identity.Created.Format(time.RFC3339),
		Updated:   identity.Updated.Format(time.RFC3339),
		Metadata:  identity.Metadata,
		Services:  identity.Services,
	}

	return nil
}

// ResolveIdentityArgs are arguments for ResolveIdentity
type ResolveIdentityArgs struct {
	DID string `json:"did"`
}

// ResolveIdentityReply is the reply for ResolveIdentity
type ResolveIdentityReply struct {
	Identity IdentityReply `json:"identity"`
}

// ResolveIdentity resolves an identity by DID
func (s *Service) ResolveIdentity(r *http.Request, args *ResolveIdentityArgs, reply *ResolveIdentityReply) error {
	identity, err := s.vm.ResolveIdentity(args.DID)
	if err != nil {
		return err
	}

	reply.Identity = IdentityReply{
		ID:        identity.ID.String(),
		DID:       identity.DID,
		PublicKey: base64.StdEncoding.EncodeToString(identity.PublicKey),
		Created:   identity.Created.Format(time.RFC3339),
		Updated:   identity.Updated.Format(time.RFC3339),
		Metadata:  identity.Metadata,
		Services:  identity.Services,
	}

	return nil
}

// ======== Credential API ========

// IssueCredentialArgs are arguments for IssueCredential
type IssueCredentialArgs struct {
	IssuerID   string                 `json:"issuerId"`
	SubjectID  string                 `json:"subjectId"`
	Type       []string               `json:"type"`
	Claims     map[string]interface{} `json:"claims"`
	TTLSeconds int64                  `json:"ttlSeconds"` // Optional, uses default if 0
}

// IssueCredentialReply is the reply for IssueCredential
type IssueCredentialReply struct {
	CredentialID   string `json:"credentialId"`
	ExpirationDate string `json:"expirationDate"`
}

// IssueCredential issues a new verifiable credential
func (s *Service) IssueCredential(r *http.Request, args *IssueCredentialArgs, reply *IssueCredentialReply) error {
	issuerID, err := ids.FromString(args.IssuerID)
	if err != nil {
		return err
	}

	subjectID, err := ids.FromString(args.SubjectID)
	if err != nil {
		return err
	}

	ttl := time.Duration(args.TTLSeconds) * time.Second

	cred, err := s.vm.IssueCredential(issuerID, subjectID, args.Type, args.Claims, ttl)
	if err != nil {
		return err
	}

	reply.CredentialID = cred.ID.String()
	reply.ExpirationDate = cred.ExpirationDate.Format(time.RFC3339)
	return nil
}

// GetCredentialArgs are arguments for GetCredential
type GetCredentialArgs struct {
	CredentialID string `json:"credentialId"`
}

// CredentialReply represents a credential in RPC responses
type CredentialReply struct {
	ID             string                 `json:"id"`
	Type           []string               `json:"type"`
	Issuer         string                 `json:"issuer"`
	Subject        string                 `json:"subject"`
	IssuanceDate   string                 `json:"issuanceDate"`
	ExpirationDate string                 `json:"expirationDate"`
	Claims         map[string]interface{} `json:"claims"`
	Status         string                 `json:"status"`
}

// GetCredentialReply is the reply for GetCredential
type GetCredentialReply struct {
	Credential CredentialReply `json:"credential"`
}

// GetCredential returns a credential by ID
func (s *Service) GetCredential(r *http.Request, args *GetCredentialArgs, reply *GetCredentialReply) error {
	credID, err := ids.FromString(args.CredentialID)
	if err != nil {
		return err
	}

	cred, err := s.vm.GetCredential(credID)
	if err != nil {
		return err
	}

	reply.Credential = CredentialReply{
		ID:             cred.ID.String(),
		Type:           cred.Type,
		Issuer:         cred.Issuer.String(),
		Subject:        cred.Subject.String(),
		IssuanceDate:   cred.IssuanceDate.Format(time.RFC3339),
		ExpirationDate: cred.ExpirationDate.Format(time.RFC3339),
		Claims:         cred.Claims,
		Status:         cred.Status,
	}

	return nil
}

// VerifyCredentialArgs are arguments for VerifyCredential
type VerifyCredentialArgs struct {
	CredentialID string `json:"credentialId"`
}

// VerifyCredentialReply is the reply for VerifyCredential
type VerifyCredentialReply struct {
	Valid   bool   `json:"valid"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// VerifyCredential verifies a credential
func (s *Service) VerifyCredential(r *http.Request, args *VerifyCredentialArgs, reply *VerifyCredentialReply) error {
	credID, err := ids.FromString(args.CredentialID)
	if err != nil {
		return err
	}

	valid, err := s.vm.VerifyCredential(credID)
	if err != nil {
		reply.Valid = false
		reply.Message = err.Error()

		// Determine status based on error
		switch err {
		case errCredentialRevoked:
			reply.Status = CredentialRevoked
		case errCredentialExpired:
			reply.Status = CredentialExpired
		default:
			reply.Status = "invalid"
		}
		return nil
	}

	reply.Valid = valid
	reply.Status = CredentialActive
	return nil
}

// RevokeCredentialArgs are arguments for RevokeCredential
type RevokeCredentialArgs struct {
	CredentialID string `json:"credentialId"`
	RevokerID    string `json:"revokerId"`
	Reason       string `json:"reason"`
}

// RevokeCredentialReply is the reply for RevokeCredential
type RevokeCredentialReply struct {
	Success bool `json:"success"`
}

// RevokeCredential revokes a credential
func (s *Service) RevokeCredential(r *http.Request, args *RevokeCredentialArgs, reply *RevokeCredentialReply) error {
	credID, err := ids.FromString(args.CredentialID)
	if err != nil {
		return err
	}

	revokerID, err := ids.FromString(args.RevokerID)
	if err != nil {
		return err
	}

	if err := s.vm.RevokeCredential(credID, revokerID, args.Reason); err != nil {
		return err
	}

	reply.Success = true
	return nil
}

// CreateProofArgs are arguments for CreateProof
type CreateProofArgs struct {
	CredentialID        string   `json:"credentialId"`
	ZKProof             string   `json:"zkProof,omitempty"` // Base64-encoded
	SelectiveDisclosure []string `json:"selectiveDisclosure,omitempty"`
}

// CreateProofReply is the reply for CreateProof
type CreateProofReply struct {
	CredentialID     string `json:"credentialId"`
	IssuerDID        string `json:"issuerDid"`
	SubjectDID       string `json:"subjectDid"`
	CredType         string `json:"credentialType"`
	ClaimsCommitment string `json:"claimsCommitment"` // Base64-encoded
	IssuedAt         int64  `json:"issuedAt"`
	ExpiresAt        int64  `json:"expiresAt"`
}

// CreateProof creates a credential proof artifact
func (s *Service) CreateProof(r *http.Request, args *CreateProofArgs, reply *CreateProofReply) error {
	credID, err := ids.FromString(args.CredentialID)
	if err != nil {
		return err
	}

	var zkProof []byte
	if args.ZKProof != "" {
		zkProof, err = base64.StdEncoding.DecodeString(args.ZKProof)
		if err != nil {
			return err
		}
	}

	proof, err := s.vm.CreateCredentialProof(credID, zkProof, args.SelectiveDisclosure)
	if err != nil {
		return err
	}

	reply.CredentialID = proof.CredentialID.String()
	reply.IssuerDID = proof.IssuerDID
	reply.SubjectDID = proof.SubjectDID
	reply.CredType = proof.CredType
	reply.ClaimsCommitment = base64.StdEncoding.EncodeToString(proof.ClaimsCommitment[:])
	reply.IssuedAt = proof.IssuedAt.Unix()
	reply.ExpiresAt = proof.ExpiresAt.Unix()
	return nil
}

// ======== Issuer API ========

// RegisterIssuerArgs are arguments for RegisterIssuer
type RegisterIssuerArgs struct {
	Name       string   `json:"name"`
	PublicKey  string   `json:"publicKey"` // Base64-encoded
	Types      []string `json:"types"`
	TrustLevel int      `json:"trustLevel"`
}

// RegisterIssuerReply is the reply for RegisterIssuer
type RegisterIssuerReply struct {
	IssuerID string `json:"issuerId"`
}

// RegisterIssuer registers a new credential issuer
func (s *Service) RegisterIssuer(r *http.Request, args *RegisterIssuerArgs, reply *RegisterIssuerReply) error {
	publicKey, err := base64.StdEncoding.DecodeString(args.PublicKey)
	if err != nil {
		return err
	}

	issuer, err := s.vm.RegisterIssuer(args.Name, publicKey, args.Types, args.TrustLevel)
	if err != nil {
		return err
	}

	reply.IssuerID = issuer.ID.String()
	return nil
}

// GetIssuerArgs are arguments for GetIssuer
type GetIssuerArgs struct {
	IssuerID string `json:"issuerId"`
}

// IssuerReply represents an issuer in RPC responses
type IssuerReply struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	PublicKey  string   `json:"publicKey"`
	Types      []string `json:"types"`
	TrustLevel int      `json:"trustLevel"`
	CreatedAt  string   `json:"createdAt"`
	Status     string   `json:"status"`
}

// GetIssuerReply is the reply for GetIssuer
type GetIssuerReply struct {
	Issuer IssuerReply `json:"issuer"`
}

// GetIssuer returns an issuer by ID
func (s *Service) GetIssuer(r *http.Request, args *GetIssuerArgs, reply *GetIssuerReply) error {
	issuerID, err := ids.FromString(args.IssuerID)
	if err != nil {
		return err
	}

	issuer, err := s.vm.GetIssuer(issuerID)
	if err != nil {
		return err
	}

	reply.Issuer = IssuerReply{
		ID:         issuer.ID.String(),
		Name:       issuer.Name,
		PublicKey:  base64.StdEncoding.EncodeToString(issuer.PublicKey),
		Types:      issuer.Types,
		TrustLevel: issuer.TrustLevel,
		CreatedAt:  issuer.CreatedAt.Format(time.RFC3339),
		Status:     issuer.Status,
	}

	return nil
}

// ListIssuersArgs are arguments for ListIssuers
type ListIssuersArgs struct {
	Type   string `json:"type,omitempty"`   // Filter by credential type
	Status string `json:"status,omitempty"` // Filter by status
}

// ListIssuersReply is the reply for ListIssuers
type ListIssuersReply struct {
	Issuers []IssuerReply `json:"issuers"`
}

// ListIssuers lists all issuers
func (s *Service) ListIssuers(r *http.Request, args *ListIssuersArgs, reply *ListIssuersReply) error {
	s.vm.mu.RLock()
	defer s.vm.mu.RUnlock()

	reply.Issuers = make([]IssuerReply, 0, len(s.vm.issuers))

	for _, issuer := range s.vm.issuers {
		// Apply filters
		if args.Status != "" && issuer.Status != args.Status {
			continue
		}

		if args.Type != "" {
			found := false
			for _, t := range issuer.Types {
				if t == args.Type {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		reply.Issuers = append(reply.Issuers, IssuerReply{
			ID:         issuer.ID.String(),
			Name:       issuer.Name,
			PublicKey:  base64.StdEncoding.EncodeToString(issuer.PublicKey),
			Types:      issuer.Types,
			TrustLevel: issuer.TrustLevel,
			CreatedAt:  issuer.CreatedAt.Format(time.RFC3339),
			Status:     issuer.Status,
		})
	}

	return nil
}

// ======== Health Check ========

// HealthArgs are arguments for Health
type HealthArgs struct{}

// HealthReply is the reply for Health
type HealthReply struct {
	Healthy     bool `json:"healthy"`
	Identities  int  `json:"identities"`
	Credentials int  `json:"credentials"`
	Issuers     int  `json:"issuers"`
}

// Health returns health status
func (s *Service) Health(r *http.Request, args *HealthArgs, reply *HealthReply) error {
	health, err := s.vm.HealthCheck(context.Background())
	if err != nil {
		return err
	}

	s.vm.mu.RLock()
	defer s.vm.mu.RUnlock()

	reply.Healthy = health.Healthy
	reply.Identities = len(s.vm.identities)
	reply.Credentials = len(s.vm.credentials)
	reply.Issuers = len(s.vm.issuers)
	return nil
}
