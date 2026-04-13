// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/luxfi/ids"
)

// Service provides JSON-RPC endpoints for the K-Chain VM.
type Service struct {
	vm *VM
}

// ======== Key Management API ========

// ListKeysArgs contains arguments for ListKeys.
type ListKeysArgs struct {
	Offset    int    `json:"offset"`
	Limit     int    `json:"limit"`
	Algorithm string `json:"algorithm"`
	Status    string `json:"status"`
}

// ListKeysReply contains the response for ListKeys.
type ListKeysReply struct {
	Keys  []KeyMetadataReply `json:"keys"`
	Total int                `json:"total"`
}

// KeyMetadataReply is the JSON representation of KeyMetadata.
type KeyMetadataReply struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Algorithm   string   `json:"algorithm"`
	KeyType     string   `json:"keyType"`
	PublicKey   string   `json:"publicKey"`
	Threshold   int      `json:"threshold"`
	TotalShares int      `json:"totalShares"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
	Status      string   `json:"status"`
	Tags        []string `json:"tags"`
}

// ListKeys lists all keys.
func (s *Service) ListKeys(r *http.Request, args *ListKeysArgs, reply *ListKeysReply) error {
	keys, err := s.vm.ListKeys(r.Context())
	if err != nil {
		return err
	}

	reply.Keys = make([]KeyMetadataReply, 0, len(keys))
	for _, meta := range keys {
		// Apply filters
		if args.Algorithm != "" && meta.Algorithm != args.Algorithm {
			continue
		}
		if args.Status != "" && meta.Status != args.Status {
			continue
		}

		reply.Keys = append(reply.Keys, KeyMetadataReply{
			ID:          meta.ID.String(),
			Name:        meta.Name,
			Algorithm:   meta.Algorithm,
			KeyType:     meta.KeyType,
			PublicKey:   base64.StdEncoding.EncodeToString(meta.PublicKey),
			Threshold:   meta.Threshold,
			TotalShares: meta.TotalShares,
			CreatedAt:   meta.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:   meta.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			Status:      meta.Status,
			Tags:        meta.Tags,
		})
	}

	// Apply pagination
	start := args.Offset
	if start > len(reply.Keys) {
		start = len(reply.Keys)
	}
	end := start + args.Limit
	if args.Limit == 0 || end > len(reply.Keys) {
		end = len(reply.Keys)
	}

	reply.Total = len(reply.Keys)
	reply.Keys = reply.Keys[start:end]

	return nil
}

// GetKeyByIDArgs contains arguments for GetKeyByID.
type GetKeyByIDArgs struct {
	ID string `json:"id"`
}

// GetKeyByIDReply contains the response for GetKeyByID.
type GetKeyByIDReply struct {
	KeyMetadataReply
}

// GetKeyByID retrieves a key by ID.
func (s *Service) GetKeyByID(r *http.Request, args *GetKeyByIDArgs, reply *GetKeyByIDReply) error {
	keyID, err := ids.FromString(args.ID)
	if err != nil {
		return err
	}

	meta, err := s.vm.GetKey(r.Context(), keyID)
	if err != nil {
		return err
	}

	reply.ID = meta.ID.String()
	reply.Name = meta.Name
	reply.Algorithm = meta.Algorithm
	reply.KeyType = meta.KeyType
	reply.PublicKey = base64.StdEncoding.EncodeToString(meta.PublicKey)
	reply.Threshold = meta.Threshold
	reply.TotalShares = meta.TotalShares
	reply.CreatedAt = meta.CreatedAt.Format("2006-01-02T15:04:05Z07:00")
	reply.UpdatedAt = meta.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")
	reply.Status = meta.Status
	reply.Tags = meta.Tags

	return nil
}

// GetKeyByNameArgs contains arguments for GetKeyByName.
type GetKeyByNameArgs struct {
	Name string `json:"name"`
}

// GetKeyByNameReply contains the response for GetKeyByName.
type GetKeyByNameReply struct {
	KeyMetadataReply
}

// GetKeyByName retrieves a key by name.
func (s *Service) GetKeyByName(r *http.Request, args *GetKeyByNameArgs, reply *GetKeyByNameReply) error {
	meta, err := s.vm.GetKeyByName(r.Context(), args.Name)
	if err != nil {
		return err
	}

	reply.ID = meta.ID.String()
	reply.Name = meta.Name
	reply.Algorithm = meta.Algorithm
	reply.KeyType = meta.KeyType
	reply.PublicKey = base64.StdEncoding.EncodeToString(meta.PublicKey)
	reply.Threshold = meta.Threshold
	reply.TotalShares = meta.TotalShares
	reply.CreatedAt = meta.CreatedAt.Format("2006-01-02T15:04:05Z07:00")
	reply.UpdatedAt = meta.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")
	reply.Status = meta.Status
	reply.Tags = meta.Tags

	return nil
}

// CreateKeyArgs contains arguments for CreateKey.
type CreateKeyArgs struct {
	Name        string   `json:"name"`
	Algorithm   string   `json:"algorithm"`
	Threshold   int      `json:"threshold"`
	TotalShares int      `json:"totalShares"`
	Tags        []string `json:"tags"`
}

// CreateKeyReply contains the response for CreateKey.
type CreateKeyReply struct {
	Key       KeyMetadataReply `json:"key"`
	PublicKey string           `json:"publicKey"`
	ShareIDs  []string         `json:"shareIds"`
}

// CreateKey creates a new distributed key.
func (s *Service) CreateKey(r *http.Request, args *CreateKeyArgs, reply *CreateKeyReply) error {
	// Use defaults if not specified
	threshold := args.Threshold
	if threshold == 0 {
		threshold = s.vm.Config.DefaultThreshold
	}
	totalShares := args.TotalShares
	if totalShares == 0 {
		totalShares = s.vm.Config.DefaultTotalShares
	}
	algorithm := args.Algorithm
	if algorithm == "" {
		algorithm = "ml-kem-768"
	}

	meta, err := s.vm.CreateKey(r.Context(), args.Name, algorithm, threshold, totalShares)
	if err != nil {
		return err
	}

	reply.Key = KeyMetadataReply{
		ID:          meta.ID.String(),
		Name:        meta.Name,
		Algorithm:   meta.Algorithm,
		KeyType:     meta.KeyType,
		Threshold:   meta.Threshold,
		TotalShares: meta.TotalShares,
		CreatedAt:   meta.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   meta.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		Status:      meta.Status,
		Tags:        meta.Tags,
	}
	reply.PublicKey = base64.StdEncoding.EncodeToString(meta.PublicKey)
	reply.ShareIDs = []string{} // Shares are distributed separately

	return nil
}

// DeleteKeyArgs contains arguments for DeleteKey.
type DeleteKeyArgs struct {
	ID    string `json:"id"`
	Force bool   `json:"force"`
}

// DeleteKeyReply contains the response for DeleteKey.
type DeleteKeyReply struct {
	Success       bool     `json:"success"`
	DeletedShares []string `json:"deletedShares"`
}

// DeleteKey deletes a key.
func (s *Service) DeleteKey(r *http.Request, args *DeleteKeyArgs, reply *DeleteKeyReply) error {
	keyID, err := ids.FromString(args.ID)
	if err != nil {
		return err
	}

	if err := s.vm.DeleteKey(r.Context(), keyID); err != nil {
		return err
	}

	reply.Success = true
	return nil
}

// ======== Cryptographic Operations ========

// EncryptArgs contains arguments for Encrypt.
type EncryptArgs struct {
	KeyID     string `json:"keyId"`
	Plaintext string `json:"plaintext"` // Base64-encoded
}

// EncryptReply contains the response for Encrypt.
type EncryptReply struct {
	Ciphertext string `json:"ciphertext"` // Base64-encoded
	Nonce      string `json:"nonce"`
	Tag        string `json:"tag"`
}

// Encrypt encrypts data.
func (s *Service) Encrypt(r *http.Request, args *EncryptArgs, reply *EncryptReply) error {
	keyID, err := ids.FromString(args.KeyID)
	if err != nil {
		return err
	}

	plaintext, err := base64.StdEncoding.DecodeString(args.Plaintext)
	if err != nil {
		return err
	}

	ciphertext, nonce, err := s.vm.Encrypt(r.Context(), keyID, plaintext)
	if err != nil {
		return err
	}

	reply.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	reply.Nonce = base64.StdEncoding.EncodeToString(nonce)

	return nil
}

// ======== Health Check ========

// HealthArgs contains arguments for Health.
type HealthArgs struct{}

// HealthReply contains the response for Health.
type HealthReply struct {
	Healthy    bool             `json:"healthy"`
	Version    string           `json:"version"`
	Validators map[string]bool  `json:"validators"`
	Latency    map[string]int64 `json:"latency"`
}

// Health checks service health.
func (s *Service) Health(r *http.Request, args *HealthArgs, reply *HealthReply) error {
	health, err := s.vm.HealthCheck(context.Background())
	if err != nil {
		return err
	}

	reply.Healthy = health.Healthy
	reply.Version = health.Details["version"]
	reply.Validators = make(map[string]bool)
	reply.Latency = make(map[string]int64)

	// Check validator connectivity with TCP dial
	// Only check validators that are in the configured allowlist
	timeout := s.vm.Config.ValidatorTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Limit concurrent health checks to prevent resource exhaustion
	const maxConcurrent = 10
	semaphore := make(chan struct{}, maxConcurrent)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, v := range s.vm.Config.Validators {
		// Validate address format (host:port)
		host, port, err := net.SplitHostPort(v)
		if err != nil {
			// Invalid format - skip this validator
			mu.Lock()
			reply.Validators[v] = false
			reply.Latency[v] = -2 // Invalid format
			mu.Unlock()
			continue
		}

		// Basic validation: ensure host and port are not empty
		if host == "" || port == "" {
			mu.Lock()
			reply.Validators[v] = false
			reply.Latency[v] = -2
			mu.Unlock()
			continue
		}

		wg.Add(1)
		go func(validator string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			start := time.Now()
			conn, err := net.DialTimeout("tcp", validator, timeout)
			if err != nil {
				mu.Lock()
				reply.Validators[validator] = false
				reply.Latency[validator] = -1 // Unreachable
				mu.Unlock()
				return
			}
			latency := time.Since(start).Milliseconds()
			conn.Close()

			mu.Lock()
			reply.Validators[validator] = true
			reply.Latency[validator] = latency
			mu.Unlock()
		}(v)
	}

	wg.Wait()
	return nil
}

// ======== Algorithm Information ========

// ListAlgorithmsArgs contains arguments for ListAlgorithms.
type ListAlgorithmsArgs struct{}

// AlgorithmInfo describes a supported algorithm.
type AlgorithmInfo struct {
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	SecurityLevel    int      `json:"securityLevel"`
	KeySize          int      `json:"keySize"`
	SignatureSize    int      `json:"signatureSize"`
	PostQuantum      bool     `json:"postQuantum"`
	ThresholdSupport bool     `json:"thresholdSupport"`
	Description      string   `json:"description"`
	Standards        []string `json:"standards"`
}

// ListAlgorithmsReply contains the response for ListAlgorithms.
type ListAlgorithmsReply struct {
	Algorithms []AlgorithmInfo `json:"algorithms"`
}

// ListAlgorithms lists supported algorithms.
func (s *Service) ListAlgorithms(r *http.Request, args *ListAlgorithmsArgs, reply *ListAlgorithmsReply) error {
	reply.Algorithms = []AlgorithmInfo{
		{
			Name:             "ml-kem-768",
			Type:             "key-exchange",
			SecurityLevel:    192,
			KeySize:          2400,
			PostQuantum:      true,
			ThresholdSupport: false,
			Description:      "ML-KEM-768 post-quantum key encapsulation",
			Standards:        []string{"NIST FIPS 203"},
		},
		{
			Name:             "ml-kem-512",
			Type:             "key-exchange",
			SecurityLevel:    128,
			KeySize:          1632,
			PostQuantum:      true,
			ThresholdSupport: false,
			Description:      "ML-KEM-512 post-quantum key encapsulation",
			Standards:        []string{"NIST FIPS 203"},
		},
		{
			Name:             "ml-kem-1024",
			Type:             "key-exchange",
			SecurityLevel:    256,
			KeySize:          3168,
			PostQuantum:      true,
			ThresholdSupport: false,
			Description:      "ML-KEM-1024 post-quantum key encapsulation",
			Standards:        []string{"NIST FIPS 203"},
		},
		{
			Name:             "ml-dsa-65",
			Type:             "signing",
			SecurityLevel:    192,
			SignatureSize:    3309,
			PostQuantum:      true,
			ThresholdSupport: false,
			Description:      "ML-DSA-65 post-quantum digital signature",
			Standards:        []string{"NIST FIPS 204"},
		},
		{
			Name:             "ml-dsa-44",
			Type:             "signing",
			SecurityLevel:    128,
			SignatureSize:    2420,
			PostQuantum:      true,
			ThresholdSupport: false,
			Description:      "ML-DSA-44 post-quantum digital signature",
			Standards:        []string{"NIST FIPS 204"},
		},
		{
			Name:             "ml-dsa-87",
			Type:             "signing",
			SecurityLevel:    256,
			SignatureSize:    4627,
			PostQuantum:      true,
			ThresholdSupport: false,
			Description:      "ML-DSA-87 post-quantum digital signature",
			Standards:        []string{"NIST FIPS 204"},
		},
		{
			Name:             "bls-threshold",
			Type:             "signing",
			SecurityLevel:    128,
			SignatureSize:    96,
			PostQuantum:      false,
			ThresholdSupport: true,
			Description:      "BLS12-381 threshold signatures",
			Standards:        []string{"IETF BLS Signature"},
		},
		{
			Name:             "secp256k1",
			Type:             "signing",
			SecurityLevel:    128,
			SignatureSize:    64,
			PostQuantum:      false,
			ThresholdSupport: false,
			Description:      "ECDSA on secp256k1 (Ethereum compatible)",
			Standards:        []string{"SEC 2"},
		},
	}

	return nil
}
