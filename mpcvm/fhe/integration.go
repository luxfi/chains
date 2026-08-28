// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/multiparty"
	mpckks "github.com/luxfi/lattice/v7/multiparty/mpckks"
	"github.com/luxfi/lattice/v7/schemes/ckks"
	"github.com/luxfi/log"
)

// ThresholdConfig contains configuration for threshold FHE decryption
type ThresholdConfig struct {
	// Threshold is the minimum number of parties required (e.g., 67)
	Threshold int
	// TotalParties is the total number of parties (e.g., 100)
	TotalParties int
	// CKKSParams are the CKKS scheme parameters
	CKKSParams ckks.Parameters
	// LogBound is the bit length of masks for E2S protocol security
	LogBound uint
}

// DefaultThresholdConfig returns the default 67-of-100 configuration
func DefaultThresholdConfig() ThresholdConfig {
	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	return ThresholdConfig{
		Threshold:    67,
		TotalParties: 100,
		CKKSParams:   params,
		LogBound:     128,
	}
}

// checkThreshold rejects a (threshold, total) pair that is not a quorum.
// Both decryption paths finalize a session on shareCount >= threshold, so the
// pair is the only thing standing between a ciphertext and its plaintext:
// a threshold below 1 finalizes on the first share to arrive, a threshold of 1
// over more than one party lets any single party decrypt alone -- which is the
// one property a t-of-n scheme exists to deny -- and a threshold above the
// party count can never be met, so every request hangs until it expires.
func checkThreshold(threshold, total int) error {
	if total < 1 {
		return fmt.Errorf("%w: committee of %d parties", ErrInvalidThreshold, total)
	}
	least := 2
	if total == 1 {
		least = 1
	}
	if threshold < least || threshold > total {
		return fmt.Errorf("%w: %d of %d parties, want %d to %d", ErrInvalidThreshold, threshold, total, least, total)
	}
	return nil
}

// parseCiphertext deserializes ciphertext bytes that arrived from off this
// chain. rlwe's decoder sizes its allocations from lengths it reads out of the
// input, so a crafted payload reaches make() with a length out of range and
// panics instead of returning an error -- sixteen bytes are enough. Both
// callers run on a goroutine that services cross-chain requests and neither
// recovers, so that panic ends the process. Every other malformed input already
// comes back as an error here; this makes the crafted one do the same.
func parseCiphertext(params ckks.Parameters, data []byte) (ct *rlwe.Ciphertext, err error) {
	defer func() {
		if r := recover(); r != nil {
			ct, err = nil, fmt.Errorf("unmarshal ciphertext: %v", r)
		}
	}()

	ct = rlwe.NewCiphertext(params.Parameters, 1, params.MaxLevel())
	if err := ct.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("unmarshal ciphertext: %w", err)
	}
	return ct, nil
}

// ThresholdFHEIntegration integrates threshold FHE with ThresholdVM
type ThresholdFHEIntegration struct {
	logger  log.Logger
	config  ThresholdConfig
	service *FHEDecryptionService

	// CKKS multiparty components
	params      ckks.Parameters
	encoder     *ckks.Encoder
	e2sProtocol mpckks.EncToShareProtocol

	// This party's identity and secret key share
	partyID   int
	secretKey *rlwe.SecretKey

	// Session management
	sessions   map[string]*DecryptionSession
	sessionsMu sync.RWMutex

	// Network key (combined public key from all validators)
	networkKey *rlwe.PublicKey
}

// DecryptionSession tracks an ongoing threshold decryption
type DecryptionSession struct {
	ID         string
	RequestID  common.Hash
	Ciphertext *rlwe.Ciphertext

	// E2S protocol shares from each party
	PublicShares    []multiparty.KeySwitchShare
	SecretShares    []multiparty.AdditiveShareBigint
	OwnSecretShare  *multiparty.AdditiveShareBigint
	OwnPublicShare  *multiparty.KeySwitchShare
	AggregatedShare *multiparty.KeySwitchShare

	ShareCount   int
	Complete     bool
	Result       []byte
	Participants map[ids.NodeID]bool
}

// NewThresholdFHEIntegration creates a new integration instance
func NewThresholdFHEIntegration(logger log.Logger, config ThresholdConfig, partyID int) (*ThresholdFHEIntegration, error) {
	if err := checkThreshold(config.Threshold, config.TotalParties); err != nil {
		return nil, err
	}

	service := NewFHEDecryptionService(logger)

	// Create E2S protocol
	e2sProtocol, err := mpckks.NewEncToShareProtocol(config.CKKSParams, config.CKKSParams.Xe())
	if err != nil {
		return nil, fmt.Errorf("create E2S protocol: %w", err)
	}

	// Create encoder
	encoder := ckks.NewEncoder(config.CKKSParams)

	return &ThresholdFHEIntegration{
		logger:      logger,
		config:      config,
		service:     service,
		params:      config.CKKSParams,
		encoder:     encoder,
		e2sProtocol: e2sProtocol,
		partyID:     partyID,
		sessions:    make(map[string]*DecryptionSession),
	}, nil
}

// Start begins the FHE integration service
func (i *ThresholdFHEIntegration) Start(ctx context.Context) error {
	return i.service.Start(ctx)
}

// Stop shuts down the FHE integration
func (i *ThresholdFHEIntegration) Stop() error {
	return i.service.Stop()
}

// SetSecretKey sets this party's secret key share
func (i *ThresholdFHEIntegration) SetSecretKey(sk *rlwe.SecretKey) {
	i.secretKey = sk
}

// InitiateDecryption starts a new threshold decryption session
func (i *ThresholdFHEIntegration) InitiateDecryption(
	sessionID string,
	requestID common.Hash,
	ciphertextBytes []byte,
) error {
	i.sessionsMu.Lock()
	defer i.sessionsMu.Unlock()

	if _, exists := i.sessions[sessionID]; exists {
		return fmt.Errorf("session %s already exists", sessionID)
	}

	// Deserialize ciphertext
	ct, err := parseCiphertext(i.params, ciphertextBytes)
	if err != nil {
		return err
	}

	i.sessions[sessionID] = &DecryptionSession{
		ID:           sessionID,
		RequestID:    requestID,
		Ciphertext:   ct,
		PublicShares: make([]multiparty.KeySwitchShare, 0, i.config.Threshold),
		SecretShares: make([]multiparty.AdditiveShareBigint, 0, i.config.Threshold),
		ShareCount:   0,
		Complete:     false,
		Participants: make(map[ids.NodeID]bool),
	}

	i.logger.Info("Initiated decryption session",
		"sessionID", sessionID,
		"requestID", requestID.Hex(),
	)

	return nil
}

// GenerateShare generates this party's decryption share for a session
func (i *ThresholdFHEIntegration) GenerateShare(sessionID string) (publicShareBytes []byte, err error) {
	i.sessionsMu.Lock()
	defer i.sessionsMu.Unlock()

	session, exists := i.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	if i.secretKey == nil {
		return nil, fmt.Errorf("secret key not initialized")
	}

	// Allocate shares
	publicShare := i.e2sProtocol.AllocateShare(session.Ciphertext.Level())
	secretShare := mpckks.NewAdditiveShare(i.params, i.params.LogMaxSlots())

	// Generate E2S share
	if err := i.e2sProtocol.GenShare(
		i.secretKey,
		i.config.LogBound,
		session.Ciphertext,
		&secretShare,
		&publicShare,
	); err != nil {
		return nil, fmt.Errorf("generate share: %w", err)
	}

	// Store our shares for later use in recovery
	session.OwnSecretShare = &secretShare
	session.OwnPublicShare = &publicShare

	// Serialize public share for broadcast
	publicShareBytes, err = publicShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal public share: %w", err)
	}

	return publicShareBytes, nil
}

// ContributeShare adds a decryption share from a validator
func (i *ThresholdFHEIntegration) ContributeShare(
	sessionID string,
	nodeID ids.NodeID,
	publicShareBytes []byte,
) (bool, error) {
	i.sessionsMu.Lock()
	defer i.sessionsMu.Unlock()

	session, exists := i.sessions[sessionID]
	if !exists {
		return false, fmt.Errorf("session %s not found", sessionID)
	}

	if session.Complete {
		return true, nil
	}

	if session.Participants[nodeID] {
		return false, fmt.Errorf("node %s already contributed", nodeID)
	}

	// Deserialize public share
	publicShare := i.e2sProtocol.AllocateShare(session.Ciphertext.Level())
	if err := publicShare.UnmarshalBinary(publicShareBytes); err != nil {
		return false, fmt.Errorf("unmarshal public share: %w", err)
	}

	session.PublicShares = append(session.PublicShares, publicShare)
	session.ShareCount++
	session.Participants[nodeID] = true

	i.logger.Debug("Received decryption share",
		"sessionID", sessionID,
		"nodeID", nodeID,
		"count", session.ShareCount,
		"threshold", i.config.Threshold,
	)

	// Check if we have enough shares
	if session.ShareCount >= i.config.Threshold {
		i.completeDecryption(session)
		return true, nil
	}

	return false, nil
}

// completeDecryption finishes decryption when threshold is reached
func (i *ThresholdFHEIntegration) completeDecryption(session *DecryptionSession) {
	i.logger.Info("Threshold reached, completing decryption",
		"sessionID", session.ID,
		"shares", session.ShareCount,
	)

	// Aggregate all public shares
	aggregatedShare := i.e2sProtocol.AllocateShare(session.Ciphertext.Level())
	for j, share := range session.PublicShares {
		if j == 0 {
			aggregatedShare = share
		} else {
			i.e2sProtocol.AggregateShares(aggregatedShare, share, &aggregatedShare)
		}
	}

	// Allocate output for recovered values
	recoveredShare := mpckks.NewAdditiveShare(i.params, i.params.LogMaxSlots())

	// Recover the plaintext using GetShare
	// Pass our own secret share to subtract it from the aggregated result
	i.e2sProtocol.GetShare(session.OwnSecretShare, aggregatedShare, session.Ciphertext, &recoveredShare)

	// Convert recovered bigint values to complex128
	values := make([]complex128, len(recoveredShare.Value))
	scale := new(big.Float).SetPrec(256).SetFloat64(math.Pow(2, float64(i.params.DefaultScale().Log2())))

	// Every entry is allocated by multiparty.NewAdditiveShareBigint, which
	// fills the slice with new(big.Int); GetShare only writes into them. There
	// is no nil to skip.
	for idx, v := range recoveredShare.Value {
		fv := new(big.Float).SetPrec(256).SetInt(v)
		fv.Quo(fv, scale)
		realVal, _ := fv.Float64()
		values[idx] = complex(realVal, 0)
	}

	// Convert complex values to bytes
	session.Result = encodeComplexValuesToBytes(values[:8])
	session.Complete = true

	i.logger.Info("Decryption completed",
		"sessionID", session.ID,
		"requestID", session.RequestID.Hex(),
		"resultLen", len(session.Result),
	)
}

// GetSessionResult retrieves the result of a completed session
func (i *ThresholdFHEIntegration) GetSessionResult(sessionID string) ([]byte, bool, error) {
	i.sessionsMu.RLock()
	defer i.sessionsMu.RUnlock()

	session, exists := i.sessions[sessionID]
	if !exists {
		return nil, false, fmt.Errorf("session %s not found", sessionID)
	}

	return session.Result, session.Complete, nil
}

// CleanupSession removes a completed session
func (i *ThresholdFHEIntegration) CleanupSession(sessionID string) {
	i.sessionsMu.Lock()
	defer i.sessionsMu.Unlock()
	delete(i.sessions, sessionID)
}

// SetNetworkKey sets the combined public key for the network
func (i *ThresholdFHEIntegration) SetNetworkKey(pk *rlwe.PublicKey) {
	i.networkKey = pk
}

// GetNetworkKey returns the network's combined public key
func (i *ThresholdFHEIntegration) GetNetworkKey() *rlwe.PublicKey {
	return i.networkKey
}

// encodeComplexValuesToBytes converts complex values to a byte representation
func encodeComplexValuesToBytes(values []complex128) []byte {
	// Each complex value takes 16 bytes (8 for real, 8 for imag)
	result := make([]byte, len(values)*16)

	for i, v := range values {
		// Convert real part to float64 bits
		realBits := math.Float64bits(real(v))
		binary.LittleEndian.PutUint64(result[i*16:i*16+8], realBits)

		// Convert imaginary part to float64 bits
		imagBits := math.Float64bits(imag(v))
		binary.LittleEndian.PutUint64(result[i*16+8:i*16+16], imagBits)
	}

	return result
}

// decodeComplexValuesFromBytes decodes bytes back to complex values
func decodeComplexValuesFromBytes(data []byte) []complex128 {
	if len(data)%16 != 0 {
		return nil
	}

	count := len(data) / 16
	values := make([]complex128, count)

	for i := 0; i < count; i++ {
		realBits := binary.LittleEndian.Uint64(data[i*16 : i*16+8])
		imagBits := binary.LittleEndian.Uint64(data[i*16+8 : i*16+16])
		values[i] = complex(math.Float64frombits(realBits), math.Float64frombits(imagBits))
	}

	return values
}
