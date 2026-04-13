// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

var (
	ErrNotInitialized    = errors.New("FHE service not initialized")
	ErrInvalidHandle     = errors.New("invalid ciphertext handle")
	ErrInvalidPermit     = errors.New("invalid permit")
	ErrRequestInProgress = errors.New("request already in progress")
	ErrBatchTooLarge     = errors.New("batch size exceeds maximum")
	ErrEpochNotReady     = errors.New("epoch not ready")
	ErrUnauthorized      = errors.New("caller not authorized")
	ErrAuthRequired      = errors.New("authentication required")
)

// Authenticator verifies RPC caller identity
type Authenticator interface {
	// GetCallerAddress extracts the authenticated caller address from context
	GetCallerAddress(ctx context.Context) ([20]byte, error)
}

const (
	MaxBatchSize = 100
)

// FHEService provides the RPC interface for FHE operations
type FHEService struct {
	registry    *Registry
	integration *ThresholdFHEIntegration
	logger      log.Logger
	chainID     ids.ID
	auth        Authenticator
}

// FHEServiceOption configures an FHEService
type FHEServiceOption func(*FHEService)

// WithAuthenticator sets the authenticator for RPC caller verification
func WithAuthenticator(auth Authenticator) FHEServiceOption {
	return func(s *FHEService) {
		s.auth = auth
	}
}

// NewFHEService creates a new FHE RPC service
func NewFHEService(registry *Registry, integration *ThresholdFHEIntegration, logger log.Logger, chainID ids.ID, opts ...FHEServiceOption) *FHEService {
	s := &FHEService{
		registry:    registry,
		integration: integration,
		logger:      logger,
		chainID:     chainID,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.auth == nil {
		logger.Warn("FHEService created without authenticator - RPC methods will not verify caller identity")
	}

	return s
}

// ========================
// Params RPCs
// ========================

// GetPublicParamsArgs contains no arguments
type GetPublicParamsArgs struct{}

// GetPublicParamsReply contains FHE public parameters
type GetPublicParamsReply struct {
	Epoch     uint64 `json:"epoch"`
	LogN      int    `json:"logN"`
	LogQP     int    `json:"logQP"` // Total bits for Q*P
	LogScale  int    `json:"logScale"`
	Threshold int    `json:"threshold"`
	PublicKey string `json:"publicKey"` // hex-encoded
	ChainID   string `json:"chainId"`
}

// GetPublicParams returns the current FHE public parameters
func (s *FHEService) GetPublicParams(_ context.Context, _ *GetPublicParamsArgs, reply *GetPublicParamsReply) error {
	if s.registry == nil {
		return ErrNotInitialized
	}

	epoch := s.registry.GetCurrentEpoch()
	epochInfo, err := s.registry.GetEpoch(epoch)
	if err != nil {
		return fmt.Errorf("failed to get epoch info: %w", err)
	}

	config := DefaultThresholdConfig()

	reply.Epoch = epoch
	reply.LogN = config.CKKSParams.LogN()
	reply.LogQP = int(config.CKKSParams.LogQ() + config.CKKSParams.LogP())
	reply.LogScale = config.CKKSParams.LogDefaultScale()
	reply.Threshold = epochInfo.Threshold
	reply.PublicKey = hex.EncodeToString(epochInfo.PublicKey)
	reply.ChainID = s.chainID.String()

	return nil
}

// GetCommitteeArgs contains no arguments
type GetCommitteeArgs struct {
	Epoch *uint64 `json:"epoch,omitempty"`
}

// CommitteeMemberInfo represents a committee member
type CommitteeMemberInfo struct {
	NodeID    string `json:"nodeId"`
	PublicKey string `json:"publicKey"`
	Weight    uint64 `json:"weight"`
	Index     int    `json:"index"`
}

// GetCommitteeReply contains the current committee
type GetCommitteeReply struct {
	Epoch     uint64                `json:"epoch"`
	Threshold int                   `json:"threshold"`
	Members   []CommitteeMemberInfo `json:"members"`
}

// GetCommittee returns the current threshold committee
func (s *FHEService) GetCommittee(_ context.Context, args *GetCommitteeArgs, reply *GetCommitteeReply) error {
	if s.registry == nil {
		return ErrNotInitialized
	}

	epoch := s.registry.GetCurrentEpoch()
	if args.Epoch != nil {
		epoch = *args.Epoch
	}

	epochInfo, err := s.registry.GetEpoch(epoch)
	if err != nil {
		return fmt.Errorf("failed to get epoch info: %w", err)
	}

	reply.Epoch = epoch
	reply.Threshold = epochInfo.Threshold
	reply.Members = make([]CommitteeMemberInfo, len(epochInfo.Committee))

	for i, member := range epochInfo.Committee {
		reply.Members[i] = CommitteeMemberInfo{
			NodeID:    member.NodeID.String(),
			PublicKey: hex.EncodeToString(member.PublicKey),
			Weight:    member.Weight,
			Index:     member.Index,
		}
	}

	return nil
}

// ========================
// Ciphertext RPCs
// ========================

// RegisterCiphertextArgs contains the ciphertext to register
type RegisterCiphertextArgs struct {
	Handle  string `json:"handle"` // hex-encoded 32 bytes
	Owner   string `json:"owner"`  // hex-encoded 20 bytes
	Type    uint8  `json:"type"`
	Level   int    `json:"level"`
	Size    uint32 `json:"size"`
	ChainID string `json:"chainId,omitempty"`
}

// RegisterCiphertextReply contains the registration result
type RegisterCiphertextReply struct {
	Handle       string `json:"handle"`
	Epoch        uint64 `json:"epoch"`
	RegisteredAt int64  `json:"registeredAt"`
}

// RegisterCiphertext registers a new ciphertext
func (s *FHEService) RegisterCiphertext(ctx context.Context, args *RegisterCiphertextArgs, reply *RegisterCiphertextReply) error {
	if s.registry == nil {
		return ErrNotInitialized
	}

	handleBytes, err := hex.DecodeString(args.Handle)
	if err != nil || len(handleBytes) != 32 {
		return ErrInvalidHandle
	}

	ownerBytes, err := hex.DecodeString(args.Owner)
	if err != nil || len(ownerBytes) != 20 {
		return fmt.Errorf("invalid owner address")
	}

	var handle [32]byte
	var owner [20]byte
	copy(handle[:], handleBytes)
	copy(owner[:], ownerBytes)

	// Verify caller is the owner being registered
	if s.auth != nil {
		caller, err := s.auth.GetCallerAddress(ctx)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrAuthRequired, err)
		}
		if caller != owner {
			return fmt.Errorf("%w: caller is not the ciphertext owner", ErrUnauthorized)
		}
	}

	chainID := s.chainID
	if args.ChainID != "" {
		chainID, err = ids.FromString(args.ChainID)
		if err != nil {
			return fmt.Errorf("invalid chain ID: %w", err)
		}
	}

	meta := &CiphertextMeta{
		Handle:  handle,
		Owner:   owner,
		Type:    args.Type,
		Level:   args.Level,
		Size:    args.Size,
		ChainID: chainID,
	}

	if err := s.registry.RegisterCiphertext(meta); err != nil {
		return fmt.Errorf("failed to register ciphertext: %w", err)
	}

	reply.Handle = args.Handle
	reply.Epoch = meta.Epoch
	reply.RegisteredAt = meta.RegisteredAt

	return nil
}

// GetCiphertextMetaArgs contains the handle to query
type GetCiphertextMetaArgs struct {
	Handle string `json:"handle"` // hex-encoded 32 bytes
}

// GetCiphertextMetaReply contains ciphertext metadata
type GetCiphertextMetaReply struct {
	Handle       string `json:"handle"`
	Owner        string `json:"owner"`
	Type         uint8  `json:"type"`
	Level        int    `json:"level"`
	Epoch        uint64 `json:"epoch"`
	RegisteredAt int64  `json:"registeredAt"`
	Size         uint32 `json:"size"`
	ChainID      string `json:"chainId"`
}

// GetCiphertextMeta retrieves ciphertext metadata
func (s *FHEService) GetCiphertextMeta(_ context.Context, args *GetCiphertextMetaArgs, reply *GetCiphertextMetaReply) error {
	if s.registry == nil {
		return ErrNotInitialized
	}

	handleBytes, err := hex.DecodeString(args.Handle)
	if err != nil || len(handleBytes) != 32 {
		return ErrInvalidHandle
	}

	var handle [32]byte
	copy(handle[:], handleBytes)

	meta, err := s.registry.GetCiphertextMeta(handle)
	if err != nil {
		return err
	}

	reply.Handle = hex.EncodeToString(meta.Handle[:])
	reply.Owner = hex.EncodeToString(meta.Owner[:])
	reply.Type = meta.Type
	reply.Level = meta.Level
	reply.Epoch = meta.Epoch
	reply.RegisteredAt = meta.RegisteredAt
	reply.Size = meta.Size
	reply.ChainID = meta.ChainID.String()

	return nil
}

// ========================
// Decrypt RPCs
// ========================

// RequestDecryptArgs contains the decrypt request parameters
type RequestDecryptArgs struct {
	CiphertextHandle string `json:"ciphertextHandle"` // hex-encoded 32 bytes
	PermitID         string `json:"permitId"`         // hex-encoded 32 bytes
	Callback         string `json:"callback"`         // hex-encoded 20 bytes
	CallbackSelector string `json:"callbackSelector"` // hex-encoded 4 bytes
	SourceChain      string `json:"sourceChain,omitempty"`
	Expiry           int64  `json:"expiry,omitempty"` // Unix timestamp
	GasLimit         uint32 `json:"gasLimit,omitempty"`
}

// RequestDecryptReply contains the request ID
type RequestDecryptReply struct {
	RequestID string `json:"requestId"`
	Epoch     uint64 `json:"epoch"`
	Status    string `json:"status"`
}

// RequestDecrypt submits a threshold decryption request
func (s *FHEService) RequestDecrypt(_ context.Context, args *RequestDecryptArgs, reply *RequestDecryptReply) error {
	if s.registry == nil {
		return ErrNotInitialized
	}

	// Parse inputs
	handleBytes, err := hex.DecodeString(args.CiphertextHandle)
	if err != nil || len(handleBytes) != 32 {
		return ErrInvalidHandle
	}

	permitBytes, err := hex.DecodeString(args.PermitID)
	if err != nil || len(permitBytes) != 32 {
		return ErrInvalidPermit
	}

	callbackBytes, err := hex.DecodeString(args.Callback)
	if err != nil || len(callbackBytes) != 20 {
		return fmt.Errorf("invalid callback address")
	}

	selectorBytes, err := hex.DecodeString(args.CallbackSelector)
	if err != nil || len(selectorBytes) != 4 {
		return fmt.Errorf("invalid callback selector")
	}

	var handle, permit [32]byte
	var callback [20]byte
	var selector [4]byte
	copy(handle[:], handleBytes)
	copy(permit[:], permitBytes)
	copy(callback[:], callbackBytes)
	copy(selector[:], selectorBytes)

	// Verify ciphertext exists
	_, err = s.registry.GetCiphertextMeta(handle)
	if err != nil {
		return fmt.Errorf("ciphertext not found: %w", err)
	}

	// Verify permit
	if err := s.registry.VerifyPermit(permit, handle, callback, PermitOpDecrypt); err != nil {
		return fmt.Errorf("permit verification failed: %w", err)
	}

	// Generate request ID
	epoch := s.registry.GetCurrentEpoch()
	requestData := append(handle[:], permit[:]...)
	requestData = append(requestData, callback[:]...)
	requestData = append(requestData, []byte(fmt.Sprintf("%d%d", epoch, time.Now().UnixNano()))...)
	requestID := sha256.Sum256(requestData)

	// Parse source chain
	sourceChain := s.chainID
	if args.SourceChain != "" {
		sourceChain, err = ids.FromString(args.SourceChain)
		if err != nil {
			return fmt.Errorf("invalid source chain: %w", err)
		}
	}

	// Set default expiry (1 hour)
	expiry := args.Expiry
	if expiry == 0 {
		expiry = time.Now().Add(time.Hour).Unix()
	}

	// Create decrypt request
	req := &DecryptRequest{
		RequestID:        requestID,
		CiphertextHandle: handle,
		Requester:        callback, // Callback address is the requester
		Callback:         callback,
		CallbackSelector: selector,
		SourceChain:      sourceChain,
		Expiry:           expiry,
	}

	if err := s.registry.CreateDecryptRequest(req); err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	reply.RequestID = hex.EncodeToString(requestID[:])
	reply.Epoch = epoch
	reply.Status = RequestPending.String()

	s.logger.Info("Decrypt request created",
		log.String("requestID", reply.RequestID),
		log.Uint64("epoch", epoch),
	)

	return nil
}

// GetDecryptResultArgs contains the request ID to query
type GetDecryptResultArgs struct {
	RequestID string `json:"requestId"` // hex-encoded 32 bytes
}

// GetDecryptResultReply contains the decryption result
type GetDecryptResultReply struct {
	RequestID    string `json:"requestId"`
	Status       string `json:"status"`
	ResultHandle string `json:"resultHandle,omitempty"`
	Plaintext    string `json:"plaintext,omitempty"` // hex-encoded
	Error        string `json:"error,omitempty"`
	CreatedAt    int64  `json:"createdAt"`
	CompletedAt  int64  `json:"completedAt,omitempty"`
}

// GetDecryptResult retrieves the result of a decrypt request
func (s *FHEService) GetDecryptResult(_ context.Context, args *GetDecryptResultArgs, reply *GetDecryptResultReply) error {
	if s.registry == nil {
		return ErrNotInitialized
	}

	requestBytes, err := hex.DecodeString(args.RequestID)
	if err != nil || len(requestBytes) != 32 {
		return fmt.Errorf("invalid request ID")
	}

	var requestID [32]byte
	copy(requestID[:], requestBytes)

	req, err := s.registry.GetDecryptRequest(requestID)
	if err != nil {
		return err
	}

	reply.RequestID = args.RequestID
	reply.Status = req.Status.String()
	reply.CreatedAt = req.CreatedAt
	reply.CompletedAt = req.CompletedAt
	reply.Error = req.Error

	if req.Status == RequestCompleted {
		reply.ResultHandle = hex.EncodeToString(req.ResultHandle[:])
	}

	return nil
}

// RequestDecryptBatchArgs contains multiple decrypt requests
type RequestDecryptBatchArgs struct {
	Requests []RequestDecryptArgs `json:"requests"`
}

// RequestDecryptBatchReply contains multiple request IDs
type RequestDecryptBatchReply struct {
	RequestIDs []string `json:"requestIds"`
	Epoch      uint64   `json:"epoch"`
}

// RequestDecryptBatch submits multiple decrypt requests
func (s *FHEService) RequestDecryptBatch(ctx context.Context, args *RequestDecryptBatchArgs, reply *RequestDecryptBatchReply) error {
	if len(args.Requests) > MaxBatchSize {
		return ErrBatchTooLarge
	}

	reply.RequestIDs = make([]string, len(args.Requests))
	reply.Epoch = s.registry.GetCurrentEpoch()

	for i, req := range args.Requests {
		var singleReply RequestDecryptReply
		if err := s.RequestDecrypt(ctx, &req, &singleReply); err != nil {
			return fmt.Errorf("request %d failed: %w", i, err)
		}
		reply.RequestIDs[i] = singleReply.RequestID
	}

	return nil
}

// GetDecryptBatchResultArgs contains multiple request IDs
type GetDecryptBatchResultArgs struct {
	RequestIDs []string `json:"requestIds"`
}

// GetDecryptBatchResultReply contains multiple results
type GetDecryptBatchResultReply struct {
	Results []GetDecryptResultReply `json:"results"`
}

// GetDecryptBatchResult retrieves multiple decrypt results
func (s *FHEService) GetDecryptBatchResult(ctx context.Context, args *GetDecryptBatchResultArgs, reply *GetDecryptBatchResultReply) error {
	if len(args.RequestIDs) > MaxBatchSize {
		return ErrBatchTooLarge
	}
	reply.Results = make([]GetDecryptResultReply, len(args.RequestIDs))

	for i, reqID := range args.RequestIDs {
		var singleReply GetDecryptResultReply
		if err := s.GetDecryptResult(ctx, &GetDecryptResultArgs{RequestID: reqID}, &singleReply); err != nil {
			singleReply.RequestID = reqID
			singleReply.Error = err.Error()
		}
		reply.Results[i] = singleReply
	}

	return nil
}

// ========================
// Receipt/Status RPCs
// ========================

// GetRequestReceiptArgs contains the request ID
type GetRequestReceiptArgs struct {
	RequestID string `json:"requestId"`
}

// GetRequestReceiptReply contains the Warp receipt info
type GetRequestReceiptReply struct {
	RequestID     string `json:"requestId"`
	Status        string `json:"status"`
	WarpMessageID string `json:"warpMessageId,omitempty"`
	TxID          string `json:"txId,omitempty"`
	Epoch         uint64 `json:"epoch"`
	SourceChain   string `json:"sourceChain"`
	CreatedAt     int64  `json:"createdAt"`
	ProcessedAt   int64  `json:"processedAt,omitempty"`
}

// GetRequestReceipt retrieves Warp receipt info for a request
func (s *FHEService) GetRequestReceipt(_ context.Context, args *GetRequestReceiptArgs, reply *GetRequestReceiptReply) error {
	if s.registry == nil {
		return ErrNotInitialized
	}

	requestBytes, err := hex.DecodeString(args.RequestID)
	if err != nil || len(requestBytes) != 32 {
		return fmt.Errorf("invalid request ID")
	}

	var requestID [32]byte
	copy(requestID[:], requestBytes)

	req, err := s.registry.GetDecryptRequest(requestID)
	if err != nil {
		return err
	}

	reply.RequestID = args.RequestID
	reply.Status = req.Status.String()
	reply.Epoch = req.Epoch
	reply.SourceChain = req.SourceChain.String()
	reply.CreatedAt = req.CreatedAt
	reply.ProcessedAt = req.CompletedAt

	// WarpMessageID and TxID would be populated by the actual processing
	// For now, derive a pseudo ID from the request
	if req.Status == RequestCompleted || req.Status == RequestFailed {
		warpID := sha256.Sum256(append([]byte("warp:"), requestID[:]...))
		reply.WarpMessageID = hex.EncodeToString(warpID[:])
	}

	return nil
}

// ========================
// Permit RPCs
// ========================

// CreatePermitArgs contains permit creation parameters
type CreatePermitArgs struct {
	Handle      string `json:"handle"`                // hex-encoded 32 bytes
	Grantee     string `json:"grantee"`               // hex-encoded 20 bytes
	Grantor     string `json:"grantor"`               // hex-encoded 20 bytes
	Operations  uint32 `json:"operations"`            // bitmask
	Expiry      int64  `json:"expiry"`                // Unix timestamp
	Attestation string `json:"attestation,omitempty"` // hex-encoded
	ChainID     string `json:"chainId,omitempty"`
}

// CreatePermitReply contains the permit ID
type CreatePermitReply struct {
	PermitID  string `json:"permitId"`
	CreatedAt int64  `json:"createdAt"`
}

// CreatePermit creates a new access permit
func (s *FHEService) CreatePermit(ctx context.Context, args *CreatePermitArgs, reply *CreatePermitReply) error {
	if s.registry == nil {
		return ErrNotInitialized
	}

	handleBytes, err := hex.DecodeString(args.Handle)
	if err != nil || len(handleBytes) != 32 {
		return ErrInvalidHandle
	}

	granteeBytes, err := hex.DecodeString(args.Grantee)
	if err != nil || len(granteeBytes) != 20 {
		return fmt.Errorf("invalid grantee address")
	}

	grantorBytes, err := hex.DecodeString(args.Grantor)
	if err != nil || len(grantorBytes) != 20 {
		return fmt.Errorf("invalid grantor address")
	}

	var handle [32]byte
	var grantee, grantor [20]byte
	copy(handle[:], handleBytes)
	copy(grantee[:], granteeBytes)
	copy(grantor[:], grantorBytes)

	// Verify caller is the grantor
	if s.auth != nil {
		caller, err := s.auth.GetCallerAddress(ctx)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrAuthRequired, err)
		}
		if caller != grantor {
			return fmt.Errorf("%w: caller not authorized to create permits for grantor", ErrUnauthorized)
		}
	}

	// Verify grantor owns the ciphertext
	meta, err := s.registry.GetCiphertextMeta(handle)
	if err != nil {
		return fmt.Errorf("ciphertext not found: %w", err)
	}
	if meta.Owner != grantor {
		return fmt.Errorf("grantor is not the ciphertext owner")
	}

	// Generate permit ID
	permitData := append(handle[:], grantee[:]...)
	permitData = append(permitData, grantor[:]...)
	permitData = append(permitData, []byte(fmt.Sprintf("%d%d", args.Operations, time.Now().UnixNano()))...)
	permitID := sha256.Sum256(permitData)

	chainID := s.chainID
	if args.ChainID != "" {
		chainID, err = ids.FromString(args.ChainID)
		if err != nil {
			return fmt.Errorf("invalid chain ID: %w", err)
		}
	}

	var attestation []byte
	if args.Attestation != "" {
		attestation, err = hex.DecodeString(args.Attestation)
		if err != nil {
			return fmt.Errorf("invalid attestation: %w", err)
		}
	}

	permit := &Permit{
		PermitID:    permitID,
		Handle:      handle,
		Grantee:     grantee,
		Grantor:     grantor,
		Operations:  args.Operations,
		Expiry:      args.Expiry,
		Attestation: attestation,
		ChainID:     chainID,
	}

	if err := s.registry.CreatePermit(permit); err != nil {
		return fmt.Errorf("failed to create permit: %w", err)
	}

	reply.PermitID = hex.EncodeToString(permitID[:])
	reply.CreatedAt = permit.CreatedAt

	return nil
}

// VerifyPermitArgs contains permit verification parameters
type VerifyPermitArgs struct {
	PermitID  string `json:"permitId"`  // hex-encoded 32 bytes
	Handle    string `json:"handle"`    // hex-encoded 32 bytes
	Grantee   string `json:"grantee"`   // hex-encoded 20 bytes
	Operation uint32 `json:"operation"` // operation to check
}

// VerifyPermitReply contains verification result
type VerifyPermitReply struct {
	Valid  bool   `json:"valid"`
	Error  string `json:"error,omitempty"`
	Expiry int64  `json:"expiry,omitempty"`
}

// VerifyPermit verifies a permit is valid for an operation
func (s *FHEService) VerifyPermit(_ context.Context, args *VerifyPermitArgs, reply *VerifyPermitReply) error {
	if s.registry == nil {
		return ErrNotInitialized
	}

	permitBytes, err := hex.DecodeString(args.PermitID)
	if err != nil || len(permitBytes) != 32 {
		reply.Valid = false
		reply.Error = "invalid permit ID format"
		return nil
	}

	handleBytes, err := hex.DecodeString(args.Handle)
	if err != nil || len(handleBytes) != 32 {
		reply.Valid = false
		reply.Error = "invalid handle format"
		return nil
	}

	granteeBytes, err := hex.DecodeString(args.Grantee)
	if err != nil || len(granteeBytes) != 20 {
		reply.Valid = false
		reply.Error = "invalid grantee format"
		return nil
	}

	var permitID, handle [32]byte
	var grantee [20]byte
	copy(permitID[:], permitBytes)
	copy(handle[:], handleBytes)
	copy(grantee[:], granteeBytes)

	err = s.registry.VerifyPermit(permitID, handle, grantee, args.Operation)
	if err != nil {
		reply.Valid = false
		reply.Error = err.Error()
		return nil
	}

	// Get expiry for valid permits
	permit, _ := s.registry.GetPermit(permitID)
	if permit != nil {
		reply.Expiry = permit.Expiry
	}

	reply.Valid = true
	return nil
}
