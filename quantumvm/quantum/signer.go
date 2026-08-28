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
	"github.com/luxfi/log"
)

var (
	ErrInvalidQuantumSignature   = errors.New("invalid quantum signature")
	ErrInvalidCoronaKey          = errors.New("invalid corona key")
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
	mu               sync.RWMutex
}

// QuantumSignature represents a quantum-resistant signature
type QuantumSignature struct {
	Algorithm    uint32
	Timestamp    time.Time
	PublicKey    []byte
	Signature    []byte
	CoronaKey    []byte
	QuantumStamp []byte
}

// MLDSAValidatorKey is the per-validator ML-DSA identity key used by the Q-Chain
// (chains/quantumvm) to attest individual round digests. It is NOT the Corona
// threshold share -- that lives in luxfi/threshold/protocols/corona and feeds
// the Q-witness aggregation in consensus/protocol/quasar.
type MLDSAValidatorKey struct {
	Version    uint32
	PublicKey  []byte
	PrivateKey []byte
	Nonce      []byte

	parse     sync.Once
	mldsaPriv *mldsa.PrivateKey
	parseErr  error
}

// signer returns the ML-DSA key for this identity. A key that arrives as bytes
// is parsed on first use and reused for every signature after that; a key that
// was just generated already holds its parsed form.
func (k *MLDSAValidatorKey) signer(mode mldsa.Mode) (*mldsa.PrivateKey, error) {
	k.parse.Do(func() {
		if k.mldsaPriv == nil {
			k.mldsaPriv, k.parseErr = mldsa.PrivateKeyFromBytes(mode, k.PrivateKey)
		}
	})
	return k.mldsaPriv, k.parseErr
}

// NewQuantumSigner creates a new quantum signer with real ML-DSA.
// algorithmVersion: 1=MLDSA44, 2=MLDSA65, 3=MLDSA87 — the parameter set
// determines every key and signature width, so there is nothing else to size.
//
// A version that does not exist is refused. Falling through to ML-DSA-65
// instead meant an operator who asked for something else got a chain signing
// under a parameter set nobody chose, and never heard about it — and it made
// the signer disagree with the config about what "unset" means.
func NewQuantumSigner(log log.Logger, algorithmVersion uint32, stampWindow time.Duration) (*QuantumSigner, error) {
	var mode mldsa.Mode
	switch algorithmVersion {
	case AlgorithmMLDSA44:
		mode = mldsa.MLDSA44
	case AlgorithmMLDSA65:
		mode = mldsa.MLDSA65
	case AlgorithmMLDSA87:
		mode = mldsa.MLDSA87
	default:
		return nil, fmt.Errorf("%w: %d (1=ML-DSA-44, 2=ML-DSA-65, 3=ML-DSA-87)",
			ErrUnsupportedAlgorithm, algorithmVersion)
	}

	return &QuantumSigner{
		log:              log,
		algorithmVersion: algorithmVersion,
		mldsaMode:        mode,
		stampWindow:      stampWindow,
	}, nil
}

// GenerateCoronaKey generates a new ML-DSA validator identity key.
// The "Corona" name is preserved on the public method for wire/RPC
// compatibility (qvm.generateCoronaKey); the underlying type is
// MLDSAValidatorKey, which is the per-validator ML-DSA identity, not a
// Corona threshold share.
func (qs *QuantumSigner) GenerateCoronaKey() (*MLDSAValidatorKey, error) {
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
		return nil, ErrInvalidCoronaKey
	}

	mldsaPriv, err := key.signer(qs.mldsaMode)
	if err != nil {
		return nil, fmt.Errorf("failed to restore ML-DSA key: %w", err)
	}

	// One reading of the clock: the stamp is derived from it, the signature
	// covers it, and it is what the signature reports. Two readings would be
	// two different times for one signature.
	stamped := time.Now()

	stamp, err := generateQuantumStamp(message, key, stamped)
	if err != nil {
		return nil, fmt.Errorf("failed to generate quantum stamp: %w", err)
	}

	// Sign with ML-DSA (real post-quantum signature!)
	signature, err := mldsaPriv.Sign(rand.Reader, signedData(message, stamp, stamped), nil)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA signing failed: %w", err)
	}

	return &QuantumSignature{
		Algorithm:    qs.algorithmVersion,
		Timestamp:    stamped,
		PublicKey:    key.PublicKey,
		Signature:    signature,
		CoronaKey:    key.PublicKey,
		QuantumStamp: stamp,
	}, nil
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

	// The stamp is fresh in both directions. Only one side was checked, and
	// time.Since goes NEGATIVE for a future date, so any timestamp ahead of now
	// compared as arbitrarily fresh and never expired at all.
	age := time.Since(sig.Timestamp)
	if age > qs.stampWindow || age < -qs.stampWindow {
		return ErrQuantumStampExpired
	}

	// Restore public key
	pubKey, err := mldsa.PublicKeyFromBytes(sig.PublicKey, qs.mldsaMode)
	if err != nil {
		return fmt.Errorf("invalid ML-DSA public key: %w", err)
	}

	// Verify with ML-DSA (real post-quantum verification!)
	if !pubKey.VerifySignature(signedData(message, sig.QuantumStamp, sig.Timestamp), sig.Signature) {
		return ErrQuantumVerificationFailed
	}

	return nil
}

// signedData is what the ML-DSA signature covers: the message, the stamp, and
// the TIME the stamp was made.
//
// The time was a plain field on the signature and nothing signed it, so the
// freshness check ran against a number the holder could rewrite: an expired
// stamp revived by setting its Timestamp to now, and the same edit forward
// produced one that never expired. A field a verifier trusts has to be a field
// the signature covers.
func signedData(message, stamp []byte, stamped time.Time) []byte {
	data := make([]byte, len(message)+len(stamp)+8)
	copy(data, message)
	copy(data[len(message):], stamp)
	binary.BigEndian.PutUint64(data[len(message)+len(stamp):], uint64(stamped.UnixNano()))
	return data
}

// generateQuantumStamp generates a quantum stamp for message authentication
func generateQuantumStamp(message []byte, key *MLDSAValidatorKey, stamped time.Time) ([]byte, error) {
	// Combine message, key nonce, and timestamp
	data := make([]byte, len(message)+len(key.Nonce)+8)
	copy(data, message)
	copy(data[len(message):], key.Nonce)
	binary.BigEndian.PutUint64(data[len(message)+len(key.Nonce):], uint64(stamped.UnixNano()))

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

// packBatch lays the batch out as three flat row-major buffers, one row per
// signature, for tensor creation.
//
// Every copy is bounded at BOTH ends, and every input is measured before it is
// copied. Slicing only the low end let row i run off the end of itself into row
// i+1: an oversized signature or public key overwrote the NEXT entry's row, so a
// caller supplying a matching over-long pair made row i+1 verify under a key of
// its own choosing. ML-DSA widths are fixed by the parameter set, so anything
// off-width is refused rather than padded.
func (qs *QuantumSigner) packBatch(messages [][]byte, signatures []*QuantumSignature) (msgBuf, sigBuf, pkBuf []uint8, maxMsgLen int, err error) {
	n := len(messages)
	sigSize := mldsa.GetSignatureSize(qs.mldsaMode)
	pkSize := mldsa.GetPublicKeySize(qs.mldsaMode)

	full := make([][]byte, n)
	for i := 0; i < n; i++ {
		sig := signatures[i]
		if sig == nil {
			return nil, nil, nil, 0, fmt.Errorf("signature %d: nil", i)
		}
		if len(sig.Signature) != sigSize {
			return nil, nil, nil, 0, fmt.Errorf("signature %d: %d bytes, ML-DSA takes %d",
				i, len(sig.Signature), sigSize)
		}
		if len(sig.PublicKey) != pkSize {
			return nil, nil, nil, 0, fmt.Errorf("public key %d: %d bytes, ML-DSA takes %d",
				i, len(sig.PublicKey), pkSize)
		}
		// The signed data is what Sign covered: message || stamp || stamp time.
		full[i] = signedData(messages[i], sig.QuantumStamp, sig.Timestamp)
		if len(full[i]) > maxMsgLen {
			maxMsgLen = len(full[i])
		}
	}

	msgBuf = make([]uint8, n*maxMsgLen)
	sigBuf = make([]uint8, n*sigSize)
	pkBuf = make([]uint8, n*pkSize)
	for i := 0; i < n; i++ {
		copy(msgBuf[i*maxMsgLen:(i+1)*maxMsgLen], full[i])
		copy(sigBuf[i*sigSize:(i+1)*sigSize], signatures[i].Signature)
		copy(pkBuf[i*pkSize:(i+1)*pkSize], signatures[i].PublicKey)
	}
	return msgBuf, sigBuf, pkBuf, maxMsgLen, nil
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

	msgBuf, sigBuf, pkBuf, maxMsgLen, err := qs.packBatch(messages, signatures)
	if err != nil {
		return err
	}
	sigSize := mldsa.GetSignatureSize(qs.mldsaMode)
	pkSize := mldsa.GetPublicKeySize(qs.mldsaMode)

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
