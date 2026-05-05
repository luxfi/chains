// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantum

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/cache"
)

var (
	ErrInvalidQuantumSignature   = errors.New("invalid quantum signature")
	ErrInvalidRingtailKey        = errors.New("invalid ringtail key")
	ErrQuantumStampExpired       = errors.New("quantum stamp expired")
	ErrQuantumVerificationFailed = errors.New("quantum verification failed")
	ErrUnsupportedAlgorithm      = errors.New("unsupported quantum algorithm")
)

// Algorithm versions
const (
	AlgorithmMLDSA44 uint32 = 1 // NIST Level 2 (128-bit security)
	AlgorithmMLDSA65 uint32 = 2 // NIST Level 3 (192-bit security)
	AlgorithmMLDSA87 uint32 = 3 // NIST Level 5 (256-bit security)
)

// QuantumSigner handles quantum signature operations using ML-DSA (Dilithium)
type QuantumSigner struct {
	log              log.Logger
	algorithmVersion uint32
	mldsaMode        mldsa.Mode
	stampWindow      time.Duration
	sigCache         *cache.LRU[ids.ID, *QuantumSignature]
	mu               sync.RWMutex
}

// QuantumSignature represents a quantum-resistant signature
type QuantumSignature struct {
	Algorithm    uint32
	Timestamp    time.Time
	PublicKey    []byte
	Signature    []byte
	RingtailKey  []byte
	QuantumStamp []byte
}

// MLDSAValidatorKey is the per-validator ML-DSA identity key used by the Q-Chain
// (chains/quantumvm) to attest individual round digests. It is NOT the Ringtail
// threshold share -- that lives in luxfi/threshold/protocols/ringtail and feeds
// the Q-witness aggregation in consensus/protocol/quasar.
type MLDSAValidatorKey struct {
	Version    uint32
	PublicKey  []byte
	PrivateKey []byte
	Nonce      []byte
	mldsaPriv  *mldsa.PrivateKey
}

// NewQuantumSigner creates a new quantum signer with real ML-DSA
// algorithmVersion: 1=MLDSA44, 2=MLDSA65, 3=MLDSA87
// keySize is ignored (determined by algorithm)
func NewQuantumSigner(log log.Logger, algorithmVersion uint32, keySize int, stampWindow time.Duration, cacheSize int) *QuantumSigner {
	var mode mldsa.Mode
	switch algorithmVersion {
	case AlgorithmMLDSA44:
		mode = mldsa.MLDSA44
	case AlgorithmMLDSA65:
		mode = mldsa.MLDSA65
	case AlgorithmMLDSA87:
		mode = mldsa.MLDSA87
	default:
		mode = mldsa.MLDSA65 // Default to NIST Level 3
		algorithmVersion = AlgorithmMLDSA65
	}

	return &QuantumSigner{
		log:              log,
		algorithmVersion: algorithmVersion,
		mldsaMode:        mode,
		stampWindow:      stampWindow,
		sigCache:         &cache.LRU[ids.ID, *QuantumSignature]{Size: cacheSize},
	}
}

// GenerateRingtailKey generates a new ML-DSA validator identity key.
// The "Ringtail" name is preserved on the public method for wire/RPC
// compatibility (qvm.generateRingtailKey); the underlying type is
// MLDSAValidatorKey, which is the per-validator ML-DSA identity, not a
// Ringtail threshold share.
func (qs *QuantumSigner) GenerateRingtailKey() (*MLDSAValidatorKey, error) {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	// Generate real ML-DSA key pair using circl
	mldsaPriv, err := mldsa.GenerateKey(rand.Reader, qs.mldsaMode)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA key: %w", err)
	}

	// Generate nonce for quantum stamp
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return &MLDSAValidatorKey{
		Version:    qs.algorithmVersion,
		PublicKey:  mldsaPriv.PublicKey.Bytes(),
		PrivateKey: mldsaPriv.Bytes(),
		Nonce:      nonce,
		mldsaPriv:  mldsaPriv,
	}, nil
}

// Sign creates a quantum signature for the given message using ML-DSA
func (qs *QuantumSigner) Sign(message []byte, key *MLDSAValidatorKey) (*QuantumSignature, error) {
	if key == nil {
		return nil, ErrInvalidRingtailKey
	}

	// Restore ML-DSA key if not cached
	var mldsaPriv *mldsa.PrivateKey
	if key.mldsaPriv != nil {
		mldsaPriv = key.mldsaPriv
	} else {
		var err error
		mldsaPriv, err = mldsa.PrivateKeyFromBytes(qs.mldsaMode, key.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to restore ML-DSA key: %w", err)
		}
	}

	// Generate quantum stamp
	stamp, err := qs.generateQuantumStamp(message, key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate quantum stamp: %w", err)
	}

	// Create message to sign: message || stamp
	data := make([]byte, len(message)+len(stamp))
	copy(data, message)
	copy(data[len(message):], stamp)

	// Sign with ML-DSA (real post-quantum signature!)
	signature, err := mldsaPriv.Sign(rand.Reader, data, nil)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA signing failed: %w", err)
	}

	sig := &QuantumSignature{
		Algorithm:    qs.algorithmVersion,
		Timestamp:    time.Now(),
		PublicKey:    key.PublicKey,
		Signature:    signature,
		RingtailKey:  key.PublicKey,
		QuantumStamp: stamp,
	}

	// Cache the signature
	sigID := qs.computeSignatureID(sig)
	qs.sigCache.Put(sigID, sig)

	return sig, nil
}

// Verify verifies a quantum signature using ML-DSA
func (qs *QuantumSigner) Verify(message []byte, sig *QuantumSignature) error {
	if sig == nil {
		return ErrInvalidQuantumSignature
	}

	// Verify algorithm version
	if sig.Algorithm != qs.algorithmVersion {
		return ErrUnsupportedAlgorithm
	}

	// Verify timestamp
	if time.Since(sig.Timestamp) > qs.stampWindow {
		return ErrQuantumStampExpired
	}

	// Restore public key
	pubKey, err := mldsa.PublicKeyFromBytes(sig.PublicKey, qs.mldsaMode)
	if err != nil {
		return fmt.Errorf("invalid ML-DSA public key: %w", err)
	}

	// Recreate the signed message: message || stamp
	data := make([]byte, len(message)+len(sig.QuantumStamp))
	copy(data, message)
	copy(data[len(message):], sig.QuantumStamp)

	// Verify with ML-DSA (real post-quantum verification!)
	if !pubKey.VerifySignature(data, sig.Signature) {
		return ErrQuantumVerificationFailed
	}

	return nil
}

// generateQuantumStamp generates a quantum stamp for message authentication
func (qs *QuantumSigner) generateQuantumStamp(message []byte, key *MLDSAValidatorKey) ([]byte, error) {
	// Combine message, key nonce, and timestamp
	timestamp := time.Now().UnixNano()
	data := make([]byte, len(message)+len(key.Nonce)+8)
	copy(data, message)
	copy(data[len(message):], key.Nonce)
	binary.BigEndian.PutUint64(data[len(message)+len(key.Nonce):], uint64(timestamp))

	// Generate quantum stamp using SHA-512
	hash := sha512.Sum512(data)

	// Add quantum noise
	noise := make([]byte, 32)
	if _, err := rand.Read(noise); err != nil {
		return nil, err
	}

	stamp := make([]byte, len(hash)+len(noise))
	copy(stamp, hash[:])
	copy(stamp[len(hash):], noise)

	return stamp, nil
}

// computeSignatureID computes a unique ID for a signature
func (qs *QuantumSigner) computeSignatureID(sig *QuantumSignature) ids.ID {
	data := make([]byte, 0, len(sig.Signature)+len(sig.PublicKey)+8)
	data = append(data, sig.Signature...)
	data = append(data, sig.PublicKey...)
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(sig.Timestamp.Unix()))
	data = append(data, timestampBytes...)

	id, _ := ids.ToID(data)
	return id
}

// ParallelVerify verifies multiple signatures in parallel.
// When GPU is available and batch size exceeds threshold, uses
// accel DilithiumVerifyBatch for hardware-accelerated verification.
func (qs *QuantumSigner) ParallelVerify(messages [][]byte, signatures []*QuantumSignature) error {
	return qs.ParallelVerifyWithThreshold(messages, signatures, accel.DilithiumBatchThreshold)
}

// ParallelVerifyWithThreshold verifies signatures using GPU batch path when
// accel.Available() and len >= threshold, otherwise falls back to CPU goroutines.
func (qs *QuantumSigner) ParallelVerifyWithThreshold(messages [][]byte, signatures []*QuantumSignature, gpuThreshold int) error {
	if len(messages) != len(signatures) {
		return errors.New("message and signature count mismatch")
	}
	if len(messages) == 0 {
		return nil
	}

	// GPU batch path
	if accel.Available() && len(messages) >= gpuThreshold {
		if err := qs.gpuBatchVerify(messages, signatures); err == nil {
			return nil
		}
		// GPU failed (OOM, unsupported, etc.) -- fall through to CPU
		qs.log.Debug("GPU batch verify unavailable, falling back to CPU", "count", len(messages))
	}

	// CPU parallel path
	return qs.cpuParallelVerify(messages, signatures)
}

// gpuBatchVerify runs DilithiumVerifyBatch on GPU via accel session.
func (qs *QuantumSigner) gpuBatchVerify(messages [][]byte, signatures []*QuantumSignature) error {
	n := len(messages)

	sess, err := accel.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	latticeOps := sess.Lattice()

	// Determine fixed sizes for this ML-DSA mode
	sigSize := mldsa.GetSignatureSize(qs.mldsaMode)
	pkSize := mldsa.GetPublicKeySize(qs.mldsaMode)

	// Find max message length (messages include appended quantum stamp)
	maxMsgLen := 0
	for i := 0; i < n; i++ {
		fullLen := len(messages[i]) + len(signatures[i].QuantumStamp)
		if fullLen > maxMsgLen {
			maxMsgLen = fullLen
		}
	}

	// Pack into flat byte arrays for tensor creation
	msgBuf := make([]uint8, n*maxMsgLen)
	sigBuf := make([]uint8, n*sigSize)
	pkBuf := make([]uint8, n*pkSize)

	for i := 0; i < n; i++ {
		sig := signatures[i]
		if sig == nil || len(sig.Signature) == 0 {
			return fmt.Errorf("signature %d: nil or empty", i)
		}

		// Reconstruct signed data: message || stamp
		fullMsg := make([]byte, len(messages[i])+len(sig.QuantumStamp))
		copy(fullMsg, messages[i])
		copy(fullMsg[len(messages[i]):], sig.QuantumStamp)
		copy(msgBuf[i*maxMsgLen:], fullMsg)

		// Copy signature bytes (pad if shorter)
		copy(sigBuf[i*sigSize:], sig.Signature)

		// Copy public key bytes
		copy(pkBuf[i*pkSize:], sig.PublicKey)
	}

	// Create tensors
	msgTensor, err := accel.NewTensorWithData[uint8](sess, []int{n, maxMsgLen}, msgBuf)
	if err != nil {
		return fmt.Errorf("create msg tensor: %w", err)
	}
	defer msgTensor.Close()

	sigTensor, err := accel.NewTensorWithData[uint8](sess, []int{n, sigSize}, sigBuf)
	if err != nil {
		return fmt.Errorf("create sig tensor: %w", err)
	}
	defer sigTensor.Close()

	pkTensor, err := accel.NewTensorWithData[uint8](sess, []int{n, pkSize}, pkBuf)
	if err != nil {
		return fmt.Errorf("create pk tensor: %w", err)
	}
	defer pkTensor.Close()

	resultTensor, err := accel.NewTensor[uint8](sess, []int{n})
	if err != nil {
		return fmt.Errorf("create result tensor: %w", err)
	}
	defer resultTensor.Close()

	// Run batch verification on GPU
	if err := latticeOps.DilithiumVerifyBatch(
		msgTensor.Untyped(),
		sigTensor.Untyped(),
		pkTensor.Untyped(),
		resultTensor.Untyped(),
	); err != nil {
		return fmt.Errorf("DilithiumVerifyBatch: %w", err)
	}

	// Read results back
	results, err := resultTensor.ToSlice()
	if err != nil {
		return fmt.Errorf("read results: %w", err)
	}

	for i, r := range results {
		if r == 0 {
			return fmt.Errorf("signature %d verification failed", i)
		}
	}

	return nil
}

// cpuParallelVerify is the original goroutine-per-signature fallback.
func (qs *QuantumSigner) cpuParallelVerify(messages [][]byte, signatures []*QuantumSignature) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(messages))

	for i := range messages {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := qs.Verify(messages[idx], signatures[idx]); err != nil {
				errChan <- fmt.Errorf("signature %d verification failed: %w", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// GetSignatureSize returns the signature size for the current algorithm
func (qs *QuantumSigner) GetSignatureSize() int {
	return mldsa.GetSignatureSize(qs.mldsaMode)
}

// GetPublicKeySize returns the public key size for the current algorithm
func (qs *QuantumSigner) GetPublicKeySize() int {
	return mldsa.GetPublicKeySize(qs.mldsaMode)
}

// GetMode returns the ML-DSA mode being used
func (qs *QuantumSigner) GetMode() mldsa.Mode {
	return qs.mldsaMode
}
