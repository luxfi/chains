// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/luxfi/lattice/v7/circuits/ckks/comparison"
	"github.com/luxfi/lattice/v7/circuits/ckks/minimax"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/multiparty"
	"github.com/luxfi/lattice/v7/schemes/ckks"
	"github.com/luxfi/log"
)

// Config holds FHE processor configuration
type Config struct {
	// LogN is the ring degree (log2). Higher = more security but slower.
	// Recommended: 14 (16384 slots) for 128-bit security
	LogN int `json:"logN"`

	// LogQ is the ciphertext modulus chain (bits per level)
	LogQ []int `json:"logQ"`

	// LogP is the special modulus for key-switching
	LogP []int `json:"logP"`

	// LogDefaultScale is the default encoding scale
	LogDefaultScale int `json:"logDefaultScale"`

	// Threshold is t in t-out-of-n threshold scheme
	Threshold int `json:"threshold"`

	// MaxOperations is the maximum multiplicative depth before refresh needed
	MaxOperations int `json:"maxOperations"`
}

// DefaultConfig returns a default FHE configuration for DeFi applications
// 128-bit security, suitable for financial computations
func DefaultConfig() Config {
	return Config{
		LogN:            14,                                    // 2^14 = 16384 slots
		LogQ:            []int{55, 45, 45, 45, 45, 45, 45, 45}, // 8 levels
		LogP:            []int{61, 61},                         // Key-switching modulus
		LogDefaultScale: 45,                                    // 45-bit precision
		Threshold:       67,                                    // 67-of-100 threshold (2/3)
		MaxOperations:   6,                                     // 6 mults before bootstrap
	}
}

// Processor is the main FHE computation engine
type Processor struct {
	config Config
	log    log.Logger

	// CKKS parameters and components
	params    ckks.Parameters
	encoder   *ckks.Encoder
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor // Only for testing - production uses threshold
	evaluator *ckks.Evaluator

	// Comparison evaluator for lt, gt, eq operations
	comparator *comparison.Evaluator

	// Keys
	publicKey *rlwe.PublicKey
	secretKey *rlwe.SecretKey // Only for keygen - shares distributed to M-Chain (MPC) per LP-134
	evalKeys  *rlwe.MemEvaluationKeySet

	// Threshold components
	thresholdizer *multiparty.Thresholdizer
	threshold     int
	parties       []multiparty.ShamirPublicPoint

	// Ciphertext store (handle -> ciphertext)
	store   map[[32]byte]*Ciphertext
	storeMu sync.RWMutex

	// Statistics
	opCount   uint64
	opCountMu sync.Mutex
}

// NewProcessor creates a new FHE processor with the given configuration
func NewProcessor(config Config, logger log.Logger) (*Processor, error) {
	// Create CKKS parameters
	paramsLit := ckks.ParametersLiteral{
		LogN:            config.LogN,
		LogQ:            config.LogQ,
		LogP:            config.LogP,
		LogDefaultScale: config.LogDefaultScale,
	}

	params, err := ckks.NewParametersFromLiteral(paramsLit)
	if err != nil {
		return nil, fmt.Errorf("failed to create CKKS parameters: %w", err)
	}

	p := &Processor{
		config:    config,
		log:       logger,
		params:    params,
		encoder:   ckks.NewEncoder(params),
		threshold: config.Threshold,
		store:     make(map[[32]byte]*Ciphertext),
	}

	// Initialize thresholdizer for t-out-of-n shares
	p.thresholdizer = new(multiparty.Thresholdizer)
	*p.thresholdizer = multiparty.NewThresholdizer(params)

	if !logger.IsZero() {
		logger.Info("FHE processor initialized",
			log.Int("logN", config.LogN),
			log.Int("levels", len(config.LogQ)),
			log.Int("threshold", config.Threshold),
		)
	}

	return p, nil
}

// GenerateKeys generates a new FHE key pair.
// The secret key should be split into threshold shares after generation.
func (p *Processor) GenerateKeys() error {
	kgen := rlwe.NewKeyGenerator(p.params.Parameters)

	// Generate secret and public keys
	p.secretKey, p.publicKey = kgen.GenKeyPairNew()

	// Generate evaluation keys (relinearization + Galois for rotations)
	rlk := kgen.GenRelinearizationKeyNew(p.secretKey)

	// Generate Galois keys for rotations (needed for comparisons)
	galEls := p.params.GaloisElements(nil) // All automorphisms
	gks := kgen.GenGaloisKeysNew(galEls, p.secretKey)

	p.evalKeys = rlwe.NewMemEvaluationKeySet(rlk, gks...)

	// Create evaluator with keys
	p.evaluator = ckks.NewEvaluator(p.params, p.evalKeys)
	p.encryptor = rlwe.NewEncryptor(p.params.Parameters, p.publicKey)
	p.decryptor = rlwe.NewDecryptor(p.params.Parameters, p.secretKey)

	// Create comparison evaluator
	minimaxEval := minimax.NewEvaluator(p.params, p.evaluator, nil)
	p.comparator = comparison.NewEvaluator(p.params, minimaxEval)

	if !p.log.IsZero() {
		p.log.Info("FHE keys generated",
			log.Int("galoisKeys", len(gks)),
		)
	}

	return nil
}

// GenerateThresholdShares splits the secret key into threshold shares
// These shares should be distributed to M-Chain signers (per LP-134; legacy: T-Chain)
func (p *Processor) GenerateThresholdShares(partyPoints []multiparty.ShamirPublicPoint) ([]multiparty.ShamirSecretShare, error) {
	if p.secretKey == nil {
		return nil, errors.New("secret key not generated")
	}

	if len(partyPoints) < p.threshold {
		return nil, fmt.Errorf("need at least %d parties for threshold %d", p.threshold, p.threshold)
	}

	// Generate Shamir polynomial with secret key as constant term
	shamirPoly, err := p.thresholdizer.GenShamirPolynomial(p.threshold, p.secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Shamir polynomial: %w", err)
	}

	// Generate shares for each party
	shares := make([]multiparty.ShamirSecretShare, len(partyPoints))
	for i, point := range partyPoints {
		shares[i] = p.thresholdizer.AllocateThresholdSecretShare()
		p.thresholdizer.GenShamirSecretShare(point, shamirPoly, &shares[i])
	}

	p.parties = partyPoints

	if !p.log.IsZero() {
		p.log.Info("threshold shares generated",
			log.Int("parties", len(partyPoints)),
			log.Int("threshold", p.threshold),
		)
	}

	// Clear the secret key after distribution (security)
	// p.secretKey = nil

	return shares, nil
}

// Encrypt encrypts a value and returns a handle
func (p *Processor) Encrypt(value interface{}, t EncryptedType) (*Ciphertext, error) {
	if p.encryptor == nil {
		return nil, errors.New("encryptor not initialized")
	}

	// Convert value to float64 slice for CKKS encoding
	values, err := p.valueToFloat64Slice(value, t)
	if err != nil {
		return nil, fmt.Errorf("failed to convert value: %w", err)
	}

	// Create plaintext and encode
	pt := ckks.NewPlaintext(p.params, p.params.MaxLevel())
	if err := p.encoder.Encode(values, pt); err != nil {
		return nil, fmt.Errorf("failed to encode: %w", err)
	}

	// Encrypt
	ct := rlwe.NewCiphertext(p.params.Parameters, 1, p.params.MaxLevel())
	if err := p.encryptor.Encrypt(pt, ct); err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	// Generate handle
	handle := p.generateHandle(ct)

	// Create wrapped ciphertext
	ciphertext := NewCiphertext(t, ct, handle)

	// Store for later retrieval
	p.storeMu.Lock()
	p.store[handle] = ciphertext
	p.storeMu.Unlock()

	p.incrementOpCount()

	return ciphertext, nil
}

// EncryptUint64 encrypts a uint64 value
func (p *Processor) EncryptUint64(value uint64, t EncryptedType) (*Ciphertext, error) {
	return p.Encrypt(value, t)
}

// EncryptBool encrypts a boolean value
func (p *Processor) EncryptBool(value bool) (*Ciphertext, error) {
	v := uint64(0)
	if value {
		v = 1
	}
	return p.Encrypt(v, EBool)
}

// Decrypt decrypts a ciphertext (for testing only - use threshold decryption otherwise)
func (p *Processor) Decrypt(ct *Ciphertext) (interface{}, error) {
	if p.decryptor == nil {
		return nil, errors.New("decryptor not initialized (use threshold decryption)")
	}

	// Decrypt
	pt := ckks.NewPlaintext(p.params, ct.Ct.Level())
	p.decryptor.Decrypt(ct.Ct, pt)

	// Decode
	values := make([]float64, p.params.MaxSlots())
	if err := p.encoder.Decode(pt, values); err != nil {
		return nil, fmt.Errorf("failed to decode: %w", err)
	}

	// Convert based on type
	return p.float64ToValue(values[0], ct.Type)
}

// GetCiphertext retrieves a ciphertext by handle
func (p *Processor) GetCiphertext(handle [32]byte) (*Ciphertext, error) {
	p.storeMu.RLock()
	defer p.storeMu.RUnlock()

	ct, ok := p.store[handle]
	if !ok {
		return nil, errors.New("ciphertext not found")
	}
	return ct, nil
}

// StoreCiphertext stores a ciphertext and returns its handle
func (p *Processor) StoreCiphertext(ct *Ciphertext) [32]byte {
	p.storeMu.Lock()
	defer p.storeMu.Unlock()

	p.store[ct.Handle] = ct
	return ct.Handle
}

// GetPublicKey returns the public key for external encryption
func (p *Processor) GetPublicKey() *rlwe.PublicKey {
	return p.publicKey
}

// GetParams returns the CKKS parameters
func (p *Processor) GetParams() ckks.Parameters {
	return p.params
}

// GetEncoder returns the encoder for external use
func (p *Processor) GetEncoder() *ckks.Encoder {
	return p.encoder
}

// OpCount returns the number of operations performed
func (p *Processor) OpCount() uint64 {
	p.opCountMu.Lock()
	defer p.opCountMu.Unlock()
	return p.opCount
}

// Helper functions

func (p *Processor) valueToFloat64Slice(value interface{}, t EncryptedType) ([]float64, error) {
	slots := p.params.MaxSlots()
	result := make([]float64, slots)

	var v float64
	switch val := value.(type) {
	case bool:
		if val {
			v = 1.0
		}
	case uint8:
		v = float64(val)
	case uint16:
		v = float64(val)
	case uint32:
		v = float64(val)
	case uint64:
		v = float64(val)
	case int:
		v = float64(val)
	case int64:
		v = float64(val)
	case float64:
		v = val
	case *big.Int:
		v, _ = new(big.Float).SetInt(val).Float64()
	default:
		return nil, fmt.Errorf("unsupported value type: %T", value)
	}

	// Fill first slot with value (SIMD: could pack multiple values)
	result[0] = v

	return result, nil
}

func (p *Processor) float64ToValue(v float64, t EncryptedType) (interface{}, error) {
	switch t {
	case EBool:
		return v >= 0.5, nil
	case EUint8:
		return uint8(v + 0.5), nil
	case EUint16:
		return uint16(v + 0.5), nil
	case EUint32:
		return uint32(v + 0.5), nil
	case EUint64:
		return uint64(v + 0.5), nil
	case EUint128, EUint256:
		return new(big.Int).SetUint64(uint64(v + 0.5)), nil
	default:
		return nil, fmt.Errorf("unsupported type: %s", t)
	}
}

func (p *Processor) generateHandle(ct *rlwe.Ciphertext) [32]byte {
	// Generate random bytes and hash with ciphertext data
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)

	ctBytes, _ := ct.MarshalBinary()
	combined := append(randomBytes, ctBytes[:min(32, len(ctBytes))]...)

	return sha256.Sum256(combined)
}

func (p *Processor) incrementOpCount() {
	p.opCountMu.Lock()
	p.opCount++
	p.opCountMu.Unlock()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
