// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/multiparty"
	mpckks "github.com/luxfi/lattice/v7/multiparty/mpckks"
	"github.com/luxfi/lattice/v7/schemes/ckks"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/platformvm/warp"
	"github.com/luxfi/node/vms/platformvm/warp/payload"
)

var (
	ErrDecryptionFailed   = errors.New("threshold decryption failed")
	ErrInsufficientShares = errors.New("insufficient decryption shares")
	ErrRequestNotFound    = errors.New("decryption request not found")
	ErrAlreadyFulfilled   = errors.New("request already fulfilled")
	ErrCiphertextNotFound = errors.New("ciphertext not found in storage")
	// Note: ErrRequestExpired is defined in warp_payloads.go
)

// DecryptionRequest represents a pending decryption request from C-Chain
type DecryptionRequest struct {
	RequestID        common.Hash
	CiphertextHash   common.Hash
	DecryptionType   uint8
	Requester        common.Address
	SourceChainID    ids.ID
	CallbackAddress  common.Address
	CallbackSelector uint32
	HasCallback      bool
	Timestamp        time.Time
	Fulfilled        bool
	Result           []byte
}

// CiphertextStorage interface for accessing FHE ciphertext storage
type CiphertextStorage interface {
	Get(handle common.Hash) ([]byte, error)
	Put(handle common.Hash, data []byte) error
	Delete(handle common.Hash) error
}

// Relayer coordinates threshold decryption between C-Chain and F-Chain (FHE compute per LP-134; legacy: T-Chain)
type Relayer struct {
	logger          log.Logger
	decryptor       *ThresholdDecryptor
	storage         CiphertextStorage
	networkID       uint32
	chainID         ids.ID
	zChainID        ids.ID
	signer          warp.Signer
	pendingRequests map[common.Hash]*DecryptionRequest
	requestTimeout  time.Duration
	mu              sync.RWMutex

	// Channels
	requestChan  chan *DecryptionRequest
	resultChan   chan *DecryptionResult
	shutdownChan chan struct{}

	// Message handler callback for sending signed messages
	onMessage func(context.Context, *warp.Message) error
}

// DecryptionResult contains the result of a threshold decryption
type DecryptionResult struct {
	RequestID common.Hash
	Plaintext []byte
	Error     error
}

// NewRelayer creates a new decryption relayer
func NewRelayer(
	logger log.Logger,
	decryptor *ThresholdDecryptor,
	storage CiphertextStorage,
	networkID uint32,
	chainID ids.ID,
	zChainID ids.ID,
	signer warp.Signer,
	onMessage func(context.Context, *warp.Message) error,
) *Relayer {
	return &Relayer{
		logger:          logger,
		decryptor:       decryptor,
		storage:         storage,
		networkID:       networkID,
		chainID:         chainID,
		zChainID:        zChainID,
		signer:          signer,
		pendingRequests: make(map[common.Hash]*DecryptionRequest),
		requestTimeout:  30 * time.Second,
		requestChan:     make(chan *DecryptionRequest, 100),
		resultChan:      make(chan *DecryptionResult, 100),
		shutdownChan:    make(chan struct{}),
		onMessage:       onMessage,
	}
}

// Start begins processing decryption requests
func (r *Relayer) Start(ctx context.Context) error {
	r.logger.Info("Starting FHE decryption relayer")

	go r.processRequests(ctx)
	go r.processResults(ctx)
	go r.cleanupExpired(ctx)

	return nil
}

// Stop shuts down the relayer
func (r *Relayer) Stop() error {
	close(r.shutdownChan)
	return nil
}

// SubmitRequest adds a new decryption request from C-Chain
func (r *Relayer) SubmitRequest(_ context.Context, req *DecryptionRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.pendingRequests[req.RequestID]; exists {
		return fmt.Errorf("request %s already exists", req.RequestID.Hex())
	}

	req.Timestamp = time.Now()
	r.pendingRequests[req.RequestID] = req

	r.logger.Debug("Received decryption request",
		"requestID", req.RequestID.Hex(),
		"hash", req.CiphertextHash.Hex(),
		"type", req.DecryptionType,
	)

	// Queue for processing
	select {
	case r.requestChan <- req:
	default:
		r.logger.Warn("Request queue full, dropping request", "requestID", req.RequestID.Hex())
		delete(r.pendingRequests, req.RequestID)
		return errors.New("request queue full")
	}

	return nil
}

// GetResult retrieves the result of a decryption request
func (r *Relayer) GetResult(requestID common.Hash) ([]byte, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	req, exists := r.pendingRequests[requestID]
	if !exists {
		return nil, false, ErrRequestNotFound
	}

	if !req.Fulfilled {
		return nil, false, nil
	}

	return req.Result, true, nil
}

// processRequests handles incoming decryption requests
func (r *Relayer) processRequests(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.shutdownChan:
			return
		case req := <-r.requestChan:
			r.handleRequest(ctx, req)
		}
	}
}

// handleRequest processes a single decryption request
func (r *Relayer) handleRequest(ctx context.Context, req *DecryptionRequest) {
	r.logger.Debug("Processing decryption request", "requestID", req.RequestID.Hex())

	// Fetch ciphertext from Z-Chain storage
	ciphertext, err := r.fetchCiphertext(ctx, req.CiphertextHash)
	if err != nil {
		r.logger.Error("Failed to fetch ciphertext", "error", err)
		r.resultChan <- &DecryptionResult{
			RequestID: req.RequestID,
			Error:     fmt.Errorf("fetch ciphertext: %w", err),
		}
		return
	}

	// Create decryption session
	sessionID := fmt.Sprintf("decrypt-%s", req.RequestID.Hex())

	// Initiate threshold decryption
	plaintext, err := r.decryptor.Decrypt(ctx, sessionID, ciphertext)
	if err != nil {
		r.logger.Error("Threshold decryption failed", "error", err)
		r.resultChan <- &DecryptionResult{
			RequestID: req.RequestID,
			Error:     fmt.Errorf("threshold decrypt: %w", err),
		}
		return
	}

	// Send result
	r.resultChan <- &DecryptionResult{
		RequestID: req.RequestID,
		Plaintext: plaintext,
	}
}

// processResults handles completed decryptions
func (r *Relayer) processResults(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.shutdownChan:
			return
		case result := <-r.resultChan:
			r.handleResult(ctx, result)
		}
	}
}

// handleResult processes a decryption result
func (r *Relayer) handleResult(ctx context.Context, result *DecryptionResult) {
	r.mu.Lock()
	req, exists := r.pendingRequests[result.RequestID]
	if !exists {
		r.mu.Unlock()
		r.logger.Warn("Result for unknown request", "requestID", result.RequestID.Hex())
		return
	}

	if req.Fulfilled {
		r.mu.Unlock()
		r.logger.Warn("Request already fulfilled", "requestID", result.RequestID.Hex())
		return
	}

	if result.Error != nil {
		r.logger.Error("Decryption failed",
			"requestID", result.RequestID.Hex(),
			"error", result.Error,
		)
		// Keep request pending for retry or manual intervention
		r.mu.Unlock()
		return
	}

	req.Fulfilled = true
	req.Result = result.Plaintext
	r.mu.Unlock()

	r.logger.Debug("Decryption completed",
		"requestID", result.RequestID.Hex(),
		"resultLen", len(result.Plaintext),
	)

	// Send fulfillment back to C-Chain via Warp
	if err := r.sendFulfillment(ctx, req); err != nil {
		r.logger.Error("Failed to send fulfillment", "error", err)
	}
}

// sendFulfillment sends the decryption result back to C-Chain
func (r *Relayer) sendFulfillment(ctx context.Context, req *DecryptionRequest) error {
	// Encode fulfillment call using proper ABI encoding
	data := encodeFulfillmentCall(req.RequestID, req.Result)

	// Gateway address for FHE fulfillment (precompile address)
	gatewayAddr := common.HexToAddress("0x0200000000000000000000000000000000000083").Bytes()

	// Create addressed call payload
	addressedCall, err := payload.NewAddressedCall(gatewayAddr, data)
	if err != nil {
		return fmt.Errorf("create addressed call: %w", err)
	}

	// Create unsigned warp message
	unsignedMsg, err := warp.NewUnsignedMessage(
		r.networkID,
		r.chainID,
		addressedCall.Bytes(),
	)
	if err != nil {
		return fmt.Errorf("create unsigned message: %w", err)
	}

	// Sign the message
	sigBytes, err := r.signer.Sign(unsignedMsg)
	if err != nil {
		return fmt.Errorf("sign warp message: %w", err)
	}

	// Convert signature bytes to fixed-size array
	var sig [96]byte
	copy(sig[:], sigBytes)

	// Create BitSetSignature
	bitSetSig := &warp.BitSetSignature{
		Signers:   []byte{0x01},
		Signature: sig,
	}

	// Create final signed message
	msg, err := warp.NewMessage(unsignedMsg, bitSetSig)
	if err != nil {
		return fmt.Errorf("create warp message: %w", err)
	}

	// Send via message handler
	if r.onMessage != nil {
		if err := r.onMessage(ctx, msg); err != nil {
			return fmt.Errorf("send warp message: %w", err)
		}
	}

	r.logger.Info("Sent decryption fulfillment",
		"requestID", req.RequestID.Hex(),
		"sourceChain", req.SourceChainID,
	)

	return nil
}

// encodeFulfillmentCall creates ABI-encoded call data for fulfillDecryption(bytes32,bytes)
func encodeFulfillmentCall(requestID common.Hash, result []byte) []byte {
	// Function selector: keccak256("fulfillDecryption(bytes32,bytes)")[:4]
	selector := []byte{0x8a, 0x6d, 0x3a, 0xf9}

	// Calculate padded result length (32-byte aligned)
	paddedLen := ((len(result) + 31) / 32) * 32

	// Total size: 4 (selector) + 32 (requestID) + 32 (offset) + 32 (length) + paddedLen
	data := make([]byte, 4+32+32+32+paddedLen)

	// Copy selector
	copy(data[0:4], selector)

	// Copy requestID (bytes32)
	copy(data[4:36], requestID.Bytes())

	// Offset to bytes data (0x40 = 64, pointing past requestID and offset)
	binary.BigEndian.PutUint64(data[60:68], 64)

	// Length of result bytes
	binary.BigEndian.PutUint64(data[92:100], uint64(len(result)))

	// Copy result data
	copy(data[100:], result)

	return data
}

// fetchCiphertext retrieves ciphertext from storage
func (r *Relayer) fetchCiphertext(_ context.Context, handle common.Hash) ([]byte, error) {
	if r.storage == nil {
		return nil, errors.New("ciphertext storage not configured")
	}

	data, err := r.storage.Get(handle)
	if err != nil {
		return nil, fmt.Errorf("get from storage: %w", err)
	}

	if len(data) == 0 {
		return nil, ErrCiphertextNotFound
	}

	return data, nil
}

// cleanupExpired removes expired pending requests
func (r *Relayer) cleanupExpired(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.shutdownChan:
			return
		case <-ticker.C:
			r.doCleanup()
		}
	}
}

func (r *Relayer) doCleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	expired := make([]common.Hash, 0)

	for id, req := range r.pendingRequests {
		if now.Sub(req.Timestamp) > r.requestTimeout && !req.Fulfilled {
			expired = append(expired, id)
		}
	}

	for _, id := range expired {
		delete(r.pendingRequests, id)
		r.logger.Debug("Cleaned up expired request", "requestID", id.Hex())
	}
}

// ThresholdDecryptor performs threshold CKKS decryption using the E2S multiparty protocol
type ThresholdDecryptor struct {
	logger       log.Logger
	params       ckks.Parameters
	threshold    int
	totalParties int
	partyID      int
	logBound     uint
	secretKey    *rlwe.SecretKey
	e2sProtocol  mpckks.EncToShareProtocol

	// Active decryption sessions
	sessions   map[string]*decryptorSession
	sessionsMu sync.RWMutex

	// Callback for broadcasting shares to other validators
	broadcastShare func(sessionID string, share []byte) error
}

type decryptorSession struct {
	sessionID      string
	ciphertext     *rlwe.Ciphertext
	publicShares   []multiparty.KeySwitchShare
	ownSecretShare *multiparty.AdditiveShareBigint
	shareCount     int
	complete       bool
	result         []byte
	participants   map[int]bool
	completedChan  chan struct{}
}

// NewThresholdDecryptor creates a new threshold decryptor
func NewThresholdDecryptor(
	logger log.Logger,
	params ckks.Parameters,
	threshold, totalParties, partyID int,
	logBound uint,
	broadcastShare func(sessionID string, share []byte) error,
) (*ThresholdDecryptor, error) {
	e2sProtocol, err := mpckks.NewEncToShareProtocol(params, params.Xe())
	if err != nil {
		return nil, fmt.Errorf("create E2S protocol: %w", err)
	}

	return &ThresholdDecryptor{
		logger:         logger,
		params:         params,
		threshold:      threshold,
		totalParties:   totalParties,
		partyID:        partyID,
		logBound:       logBound,
		e2sProtocol:    e2sProtocol,
		sessions:       make(map[string]*decryptorSession),
		broadcastShare: broadcastShare,
	}, nil
}

// SetSecretKey sets this party's secret key
func (d *ThresholdDecryptor) SetSecretKey(sk *rlwe.SecretKey) {
	d.secretKey = sk
}

// Decrypt performs threshold decryption of the ciphertext
func (d *ThresholdDecryptor) Decrypt(ctx context.Context, sessionID string, ciphertextBytes []byte) ([]byte, error) {
	if d.secretKey == nil {
		return nil, errors.New("secret key not initialized")
	}

	// Parse ciphertext
	ct := rlwe.NewCiphertext(d.params.Parameters, 1, d.params.MaxLevel())
	if err := ct.UnmarshalBinary(ciphertextBytes); err != nil {
		return nil, fmt.Errorf("unmarshal ciphertext: %w", err)
	}

	// Allocate shares
	publicShare := d.e2sProtocol.AllocateShare(ct.Level())
	secretShare := mpckks.NewAdditiveShare(d.params, d.params.LogMaxSlots())

	// Generate E2S share
	if err := d.e2sProtocol.GenShare(
		d.secretKey,
		d.logBound,
		ct,
		&secretShare,
		&publicShare,
	); err != nil {
		return nil, fmt.Errorf("generate share: %w", err)
	}

	// Create session
	session := &decryptorSession{
		sessionID:      sessionID,
		ciphertext:     ct,
		publicShares:   make([]multiparty.KeySwitchShare, 0, d.threshold),
		ownSecretShare: &secretShare,
		shareCount:     0,
		complete:       false,
		participants:   make(map[int]bool),
		completedChan:  make(chan struct{}),
	}

	d.sessionsMu.Lock()
	d.sessions[sessionID] = session
	d.sessionsMu.Unlock()

	// Serialize and broadcast our public share
	shareBytes, err := publicShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal share: %w", err)
	}

	if d.broadcastShare != nil {
		if err := d.broadcastShare(sessionID, shareBytes); err != nil {
			d.logger.Warn("Failed to broadcast share", "error", err)
		}
	}

	// Add our own share
	if err := d.AddShare(sessionID, d.partyID, shareBytes); err != nil {
		return nil, fmt.Errorf("add own share: %w", err)
	}

	// Wait for threshold shares with timeout
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-session.completedChan:
		return session.result, nil
	case <-time.After(30 * time.Second):
		return nil, ErrInsufficientShares
	}
}

// AddShare adds a decryption share from another party
func (d *ThresholdDecryptor) AddShare(sessionID string, partyID int, shareBytes []byte) error {
	d.sessionsMu.Lock()
	defer d.sessionsMu.Unlock()

	session, exists := d.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	if session.complete {
		return nil
	}

	if session.participants[partyID] {
		return nil // Already have this party's share
	}

	// Deserialize share
	share := d.e2sProtocol.AllocateShare(session.ciphertext.Level())
	if err := share.UnmarshalBinary(shareBytes); err != nil {
		return fmt.Errorf("unmarshal share: %w", err)
	}

	session.publicShares = append(session.publicShares, share)
	session.shareCount++
	session.participants[partyID] = true

	d.logger.Debug("Added decryption share",
		"sessionID", sessionID,
		"partyID", partyID,
		"count", session.shareCount,
		"threshold", d.threshold,
	)

	// Check if we have enough shares
	if session.shareCount >= d.threshold {
		result, err := d.completeDecryption(session)
		if err != nil {
			return fmt.Errorf("complete decryption: %w", err)
		}
		session.result = result
		session.complete = true
		close(session.completedChan)
	}

	return nil
}

// completeDecryption finishes decryption when threshold is reached
func (d *ThresholdDecryptor) completeDecryption(session *decryptorSession) ([]byte, error) {
	d.logger.Info("Threshold reached, completing decryption",
		"sessionID", session.sessionID,
		"shares", session.shareCount,
	)

	// Aggregate all public shares
	aggregatedShare := d.e2sProtocol.AllocateShare(session.ciphertext.Level())
	for i, share := range session.publicShares {
		if i == 0 {
			aggregatedShare = share
		} else {
			d.e2sProtocol.AggregateShares(aggregatedShare, share, &aggregatedShare)
		}
	}

	// Allocate output for recovered values
	recoveredShare := mpckks.NewAdditiveShare(d.params, d.params.LogMaxSlots())

	// Recover the plaintext using GetShare
	d.e2sProtocol.GetShare(session.ownSecretShare, aggregatedShare, session.ciphertext, &recoveredShare)

	// Convert recovered bigint values to float64
	values := make([]complex128, len(recoveredShare.Value))
	scale := new(big.Float).SetPrec(256).SetFloat64(math.Pow(2, float64(d.params.DefaultScale().Log2())))

	for i, v := range recoveredShare.Value {
		if v == nil {
			continue
		}
		fv := new(big.Float).SetPrec(256).SetInt(v)
		fv.Quo(fv, scale)
		realVal, _ := fv.Float64()
		values[i] = complex(realVal, 0)
	}

	// Convert to bytes
	result := encodeComplexValues(values[:8])

	d.logger.Info("Decryption completed",
		"sessionID", session.sessionID,
		"resultLen", len(result),
	)

	return result, nil
}

// encodeComplexValues converts complex values to bytes for output
func encodeComplexValues(values []complex128) []byte {
	result := make([]byte, len(values)*16) // 8 bytes real + 8 bytes imag per value
	for i, v := range values {
		realBits := math.Float64bits(real(v))
		binary.LittleEndian.PutUint64(result[i*16:i*16+8], realBits)
		imagBits := math.Float64bits(imag(v))
		binary.LittleEndian.PutUint64(result[i*16+8:i*16+16], imagBits)
	}
	return result
}

// InMemoryCiphertextStorage is a simple in-memory implementation of CiphertextStorage
type InMemoryCiphertextStorage struct {
	data map[common.Hash][]byte
	mu   sync.RWMutex
}

// NewInMemoryCiphertextStorage creates a new in-memory storage
func NewInMemoryCiphertextStorage() *InMemoryCiphertextStorage {
	return &InMemoryCiphertextStorage{
		data: make(map[common.Hash][]byte),
	}
}

// Get retrieves ciphertext by handle
func (s *InMemoryCiphertextStorage) Get(handle common.Hash) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, exists := s.data[handle]
	if !exists {
		return nil, ErrCiphertextNotFound
	}
	return data, nil
}

// Put stores ciphertext
func (s *InMemoryCiphertextStorage) Put(handle common.Hash, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[handle] = data
	return nil
}

// Delete removes ciphertext
func (s *InMemoryCiphertextStorage) Delete(handle common.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, handle)
	return nil
}
