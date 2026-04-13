// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/multiparty"
	"github.com/luxfi/lattice/v7/multiparty/mpckks"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/schemes/ckks"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

// ThresholdDecryptor manages threshold FHE decryption using luxfi/lattice.
// It implements t-out-of-n threshold access structure where at least t parties
// must participate to decrypt a ciphertext.
type ThresholdDecryptor struct {
	params ckks.Parameters

	// Threshold configuration
	threshold    int // t: minimum parties required
	totalParties int // n: total parties in the network

	// Protocol instances
	thresholdizer multiparty.Thresholdizer
	e2sProtocol   mpckks.EncToShareProtocol

	// Party state
	partyID     multiparty.ShamirPublicPoint
	secretShare *rlwe.SecretKey
	shamirShare *multiparty.ShamirSecretShare

	// Active decryption sessions
	sessions   map[[32]byte]*DecryptionSession
	sessionsMu sync.RWMutex

	// Combiner cache (one per unique set of active parties)
	combiners   map[string]*multiparty.Combiner
	combinersMu sync.RWMutex
}

// ThresholdConfig contains configuration for threshold decryption
type ThresholdConfig struct {
	// Threshold is the minimum number of parties required (t)
	Threshold int

	// TotalParties is the total number of parties (n)
	TotalParties int

	// PartyID is this node's unique identifier
	PartyID uint64

	// NoiseFlooding is the noise parameter for security
	NoiseFlooding float64
}

// DefaultThresholdConfig returns default threshold configuration
func DefaultThresholdConfig() ThresholdConfig {
	return ThresholdConfig{
		Threshold:     67, // 67-of-100 (2/3 majority)
		TotalParties:  100,
		PartyID:       1,
		NoiseFlooding: 1 << 30, // Standard noise flooding
	}
}

// DecryptionSession represents an active threshold decryption request
type DecryptionSession struct {
	// RequestID is the unique identifier for this decryption request
	RequestID [32]byte

	// Ciphertext being decrypted
	Ciphertext *Ciphertext

	// Shares collected from parties
	PublicShares  map[uint64]*multiparty.KeySwitchShare
	SecretShares  map[uint64]*multiparty.AdditiveShareBigint
	ActiveParties []multiparty.ShamirPublicPoint
	SharesMu      sync.RWMutex

	// Result when decryption is complete
	Result    []complex128
	Completed bool
	Error     error

	// Callbacks
	Callback func(result []complex128, err error)
}

// NewThresholdDecryptor creates a new threshold decryptor instance
func NewThresholdDecryptor(params ckks.Parameters, config ThresholdConfig) (*ThresholdDecryptor, error) {
	if config.Threshold < 1 {
		return nil, errors.New("threshold must be at least 1")
	}
	if config.Threshold > config.TotalParties {
		return nil, errors.New("threshold cannot exceed total parties")
	}

	// Initialize thresholdizer
	thresholdizer := multiparty.NewThresholdizer(params)

	// Initialize E2S (encryption-to-shares) protocol
	noise := ring.DiscreteGaussian{
		Sigma: config.NoiseFlooding,
		Bound: 6 * config.NoiseFlooding,
	}
	e2sProtocol, err := mpckks.NewEncToShareProtocol(params, noise)
	if err != nil {
		return nil, fmt.Errorf("failed to create E2S protocol: %w", err)
	}

	return &ThresholdDecryptor{
		params:        params,
		threshold:     config.Threshold,
		totalParties:  config.TotalParties,
		thresholdizer: thresholdizer,
		e2sProtocol:   e2sProtocol,
		partyID:       multiparty.ShamirPublicPoint(config.PartyID),
		sessions:      make(map[[32]byte]*DecryptionSession),
		combiners:     make(map[string]*multiparty.Combiner),
	}, nil
}

// SetKeyShare sets the party's secret key share (from distributed keygen)
func (td *ThresholdDecryptor) SetKeyShare(sk *rlwe.SecretKey) {
	td.secretShare = sk
}

// SetShamirShare sets the party's Shamir secret share
func (td *ThresholdDecryptor) SetShamirShare(share *multiparty.ShamirSecretShare) {
	td.shamirShare = share
}

// RequestDecryption initiates a threshold decryption request
func (td *ThresholdDecryptor) RequestDecryption(
	ctx context.Context,
	ct *Ciphertext,
	callback func(result []complex128, err error),
) ([32]byte, error) {
	if td.secretShare == nil {
		return [32]byte{}, errors.New("secret share not set")
	}
	if ct == nil || ct.Ct == nil {
		return [32]byte{}, errors.New("nil ciphertext")
	}

	// Generate request ID
	requestID := sha256.Sum256(append(ct.Handle[:], byte(len(td.sessions))))

	session := &DecryptionSession{
		RequestID:     requestID,
		Ciphertext:    ct,
		PublicShares:  make(map[uint64]*multiparty.KeySwitchShare),
		SecretShares:  make(map[uint64]*multiparty.AdditiveShareBigint),
		ActiveParties: make([]multiparty.ShamirPublicPoint, 0, td.threshold),
		Callback:      callback,
	}

	td.sessionsMu.Lock()
	td.sessions[requestID] = session
	td.sessionsMu.Unlock()

	// Generate our own share
	if err := td.generateShare(session); err != nil {
		return [32]byte{}, fmt.Errorf("failed to generate share: %w", err)
	}

	return requestID, nil
}

// generateShare generates this party's decryption share
func (td *ThresholdDecryptor) generateShare(session *DecryptionSession) error {
	level := session.Ciphertext.Ct.Level()

	// Allocate share storage
	publicShare := td.e2sProtocol.AllocateShare(level)
	secretShare := mpckks.NewAdditiveShare(td.params, td.params.MaxSlots())

	// Generate the share using E2S protocol
	logBound := uint(td.params.LogDefaultScale()) + 10
	if err := td.e2sProtocol.GenShare(
		td.secretShare,
		logBound,
		session.Ciphertext.Ct,
		&secretShare,
		&publicShare,
	); err != nil {
		return fmt.Errorf("failed to generate E2S share: %w", err)
	}

	// Store our share
	session.SharesMu.Lock()
	session.PublicShares[uint64(td.partyID)] = &publicShare
	session.SecretShares[uint64(td.partyID)] = &secretShare
	session.ActiveParties = append(session.ActiveParties, td.partyID)
	session.SharesMu.Unlock()

	return nil
}

// SubmitShare processes a decryption share from another party
func (td *ThresholdDecryptor) SubmitShare(
	requestID [32]byte,
	partyID uint64,
	publicShare *multiparty.KeySwitchShare,
	secretShare *multiparty.AdditiveShareBigint,
) error {
	td.sessionsMu.RLock()
	session, exists := td.sessions[requestID]
	td.sessionsMu.RUnlock()

	if !exists {
		return errors.New("session not found")
	}

	session.SharesMu.Lock()
	defer session.SharesMu.Unlock()

	if session.Completed {
		return errors.New("session already completed")
	}

	// Store the share
	session.PublicShares[partyID] = publicShare
	session.SecretShares[partyID] = secretShare
	session.ActiveParties = append(session.ActiveParties, multiparty.ShamirPublicPoint(partyID))

	// Check if we have enough shares
	if len(session.PublicShares) >= td.threshold {
		go td.completeDecryption(session)
	}

	return nil
}

// completeDecryption combines shares and decrypts
func (td *ThresholdDecryptor) completeDecryption(session *DecryptionSession) {
	session.SharesMu.Lock()
	if session.Completed {
		session.SharesMu.Unlock()
		return
	}
	session.Completed = true
	session.SharesMu.Unlock()

	// Aggregate public shares
	aggregatedShare := td.e2sProtocol.AllocateShare(session.Ciphertext.Ct.Level())

	first := true
	for _, share := range session.PublicShares {
		if first {
			aggregatedShare.Value.Copy(share.Value)
			first = false
		} else {
			td.params.RingQ().AtLevel(aggregatedShare.Value.Level()).Add(
				aggregatedShare.Value,
				share.Value,
				aggregatedShare.Value,
			)
		}
	}

	// Get combiner for this set of parties
	combiner := td.getCombiner(session.ActiveParties)

	// Convert threshold shares to additive shares
	combinedSK := rlwe.NewSecretKey(td.params.Parameters)
	if err := combiner.GenAdditiveShare(
		session.ActiveParties,
		td.partyID,
		*td.shamirShare,
		combinedSK,
	); err != nil {
		session.Error = fmt.Errorf("failed to combine shares: %w", err)
		if session.Callback != nil {
			session.Callback(nil, session.Error)
		}
		return
	}

	// Get the final decrypted share
	ourSecretShare := session.SecretShares[uint64(td.partyID)]
	resultShare := mpckks.NewAdditiveShare(td.params, td.params.MaxSlots())

	td.e2sProtocol.GetShare(
		ourSecretShare,
		aggregatedShare,
		session.Ciphertext.Ct,
		&resultShare,
	)

	// Aggregate all secret shares to get the plaintext
	slots := session.Ciphertext.Ct.Slots()
	result := make([]complex128, slots)

	for i := 0; i < slots; i++ {
		sum := new(big.Int)
		for _, share := range session.SecretShares {
			sum.Add(sum, share.Value[i])
		}
		// Convert back to complex value using scale
		scale := session.Ciphertext.Scale
		fVal, _ := new(big.Float).SetInt(sum).Float64()
		result[i] = complex(fVal/scale, 0)
	}

	session.Result = result

	if session.Callback != nil {
		session.Callback(result, nil)
	}
}

// getCombiner returns or creates a combiner for the given party set
func (td *ThresholdDecryptor) getCombiner(parties []multiparty.ShamirPublicPoint) *multiparty.Combiner {
	// Create a key from party IDs
	key := fmt.Sprintf("%v", parties)

	td.combinersMu.RLock()
	combiner, exists := td.combiners[key]
	td.combinersMu.RUnlock()

	if exists {
		return combiner
	}

	// Create new combiner
	td.combinersMu.Lock()
	defer td.combinersMu.Unlock()

	// Double-check after acquiring write lock
	if combiner, exists = td.combiners[key]; exists {
		return combiner
	}

	newCombiner := multiparty.NewCombiner(td.params, td.partyID, parties, td.threshold)
	td.combiners[key] = &newCombiner

	return &newCombiner
}

// GetSession returns the status of a decryption session
func (td *ThresholdDecryptor) GetSession(requestID [32]byte) (*DecryptionSession, error) {
	td.sessionsMu.RLock()
	defer td.sessionsMu.RUnlock()

	session, exists := td.sessions[requestID]
	if !exists {
		return nil, errors.New("session not found")
	}

	return session, nil
}

// CleanupSession removes a completed session
func (td *ThresholdDecryptor) CleanupSession(requestID [32]byte) {
	td.sessionsMu.Lock()
	defer td.sessionsMu.Unlock()
	delete(td.sessions, requestID)
}

// ThresholdKeyGen generates distributed key shares for threshold FHE
type ThresholdKeyGen struct {
	params        ckks.Parameters
	thresholdizer multiparty.Thresholdizer
	threshold     int
	totalParties  int
}

// NewThresholdKeyGen creates a new threshold key generator
func NewThresholdKeyGen(params ckks.Parameters, threshold, totalParties int) *ThresholdKeyGen {
	return &ThresholdKeyGen{
		params:        params,
		thresholdizer: multiparty.NewThresholdizer(params),
		threshold:     threshold,
		totalParties:  totalParties,
	}
}

// GenerateShares generates Shamir secret shares for all parties
func (tkg *ThresholdKeyGen) GenerateShares(secretKey *rlwe.SecretKey) (map[uint64]*multiparty.ShamirSecretShare, error) {
	// Generate Shamir polynomial with secret as constant term
	shamirPoly, err := tkg.thresholdizer.GenShamirPolynomial(tkg.threshold, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Shamir polynomial: %w", err)
	}

	// Generate share for each party
	shares := make(map[uint64]*multiparty.ShamirSecretShare)
	for i := 1; i <= tkg.totalParties; i++ {
		partyPoint := multiparty.ShamirPublicPoint(i)
		share := tkg.thresholdizer.AllocateThresholdSecretShare()
		tkg.thresholdizer.GenShamirSecretShare(partyPoint, shamirPoly, &share)
		shares[uint64(i)] = &share
	}

	return shares, nil
}

// DistributedKeyGen represents a distributed key generation protocol session
type DistributedKeyGen struct {
	params       ckks.Parameters
	threshold    int
	totalParties int
	partyID      multiparty.ShamirPublicPoint

	// CRS for public key generation
	crs multiparty.CRS

	// Generated shares
	localSecretShare *rlwe.SecretKey
	localShamirShare *multiparty.ShamirSecretShare
	publicKey        *rlwe.PublicKey
}

// NewDistributedKeyGen creates a new distributed key generation session
func NewDistributedKeyGen(params ckks.Parameters, threshold, totalParties int, partyID uint64, crs []byte) (*DistributedKeyGen, error) {
	dkg := &DistributedKeyGen{
		params:       params,
		threshold:    threshold,
		totalParties: totalParties,
		partyID:      multiparty.ShamirPublicPoint(partyID),
	}

	// Initialize CRS from seed using keyed PRNG
	var err error
	dkg.crs, err = sampling.NewKeyedPRNG(crs)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRS: %w", err)
	}

	return dkg, nil
}

// GenerateLocalKey generates this party's local secret key contribution
func (dkg *DistributedKeyGen) GenerateLocalKey() (*rlwe.SecretKey, error) {
	keyGen := rlwe.NewKeyGenerator(dkg.params.Parameters)
	dkg.localSecretShare = keyGen.GenSecretKeyNew()
	return dkg.localSecretShare, nil
}

// GetLocalSecretShare returns the local secret key share
func (dkg *DistributedKeyGen) GetLocalSecretShare() *rlwe.SecretKey {
	return dkg.localSecretShare
}

// GetLocalShamirShare returns the local Shamir share
func (dkg *DistributedKeyGen) GetLocalShamirShare() *multiparty.ShamirSecretShare {
	return dkg.localShamirShare
}
