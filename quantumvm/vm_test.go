// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"fmt"
	"testing"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/stretchr/testify/require"
)

func TestFactory(t *testing.T) {
	require := require.New(t)

	// Create factory with default config
	factory := &Factory{
		Config: config.DefaultConfig(),
	}

	// Create VM instance
	logger := log.NoLog{}
	vm, err := factory.New(logger)
	require.NoError(err)
	require.NotNil(vm)

	// Verify it's a QVM instance
	qvm, ok := vm.(*VM)
	require.True(ok)
	require.NotNil(qvm)
	require.Equal(config.DefaultConfig().TxFee, qvm.Config.TxFee)
}

func TestQuantumSigner(t *testing.T) {
	require := require.New(t)

	// Create quantum signer with ML-DSA-44 (NIST Level 2)
	// algorithmVersion: 1=MLDSA44, 2=MLDSA65, 3=MLDSA87
	logger := log.NoLog{}
	signer := quantum.NewQuantumSigner(
		logger,
		quantum.AlgorithmMLDSA44, // ML-DSA-44 (NIST Level 2)
		0,                        // key size ignored (determined by algorithm)
		30*time.Second,           // stamp window
		100,                      // cache size
	)
	require.NotNil(signer)

	// Generate Ringtail key (now using real ML-DSA)
	key, err := signer.GenerateRingtailKey()
	require.NoError(err)
	require.NotNil(key)
	// ML-DSA-44 key sizes: public=1312, private=2560
	require.Equal(signer.GetPublicKeySize(), len(key.PublicKey))
	require.True(len(key.PrivateKey) > 0)

	// Sign a message
	message := []byte("test message for quantum signature")
	sig, err := signer.Sign(message, key)
	require.NoError(err)
	require.NotNil(sig)

	// Verify the signature
	err = signer.Verify(message, sig)
	require.NoError(err)

	// Verify with wrong message should fail
	wrongMessage := []byte("wrong message")
	err = signer.Verify(wrongMessage, sig)
	require.Error(err)
}

func TestParallelVerification(t *testing.T) {
	require := require.New(t)

	// Create quantum signer with ML-DSA-44
	logger := log.NoLog{}
	signer := quantum.NewQuantumSigner(
		logger,
		quantum.AlgorithmMLDSA44, // ML-DSA-44 (NIST Level 2)
		0,                        // key size ignored
		30*time.Second,           // stamp window
		100,                      // cache size
	)

	// Generate multiple keys and signatures
	numSigs := 10
	messages := make([][]byte, numSigs)
	signatures := make([]*quantum.QuantumSignature, numSigs)

	for i := 0; i < numSigs; i++ {
		key, err := signer.GenerateRingtailKey()
		require.NoError(err)

		message := []byte(string(rune('a'+i)) + " test message")
		messages[i] = message

		sig, err := signer.Sign(message, key)
		require.NoError(err)
		signatures[i] = sig
	}

	// Verify all signatures in parallel
	err := signer.ParallelVerify(messages, signatures)
	require.NoError(err)

	// Corrupt one signature and verify should fail
	signatures[5].Signature[0] ^= 0xFF
	err = signer.ParallelVerify(messages, signatures)
	require.Error(err)
}

func TestConfigValidation(t *testing.T) {
	require := require.New(t)

	// Test default config
	cfg := config.DefaultConfig()
	require.NoError(cfg.Validate())

	// Test config with invalid values gets corrected
	cfg.MaxParallelTxs = -1
	cfg.ParallelBatchSize = 0
	cfg.QuantumSigCacheSize = -100
	cfg.RingtailKeySize = 256

	require.NoError(cfg.Validate())

	// Values should be corrected
	require.Greater(cfg.MaxParallelTxs, 0)
	require.Greater(cfg.ParallelBatchSize, 0)
	require.Greater(cfg.QuantumSigCacheSize, 0)
	require.GreaterOrEqual(cfg.RingtailKeySize, 1024)
}

func TestGPUBatchVerifyFallback(t *testing.T) {
	require := require.New(t)

	// Create quantum signer
	logger := log.NoLog{}
	signer := quantum.NewQuantumSigner(
		logger,
		quantum.AlgorithmMLDSA44,
		0,
		30*time.Second,
		100,
	)

	// Generate enough signatures to exceed GPU batch threshold
	numSigs := 16
	messages := make([][]byte, numSigs)
	signatures := make([]*quantum.QuantumSignature, numSigs)

	for i := 0; i < numSigs; i++ {
		key, err := signer.GenerateRingtailKey()
		require.NoError(err)

		message := []byte(fmt.Sprintf("batch test message %d", i))
		messages[i] = message

		sig, err := signer.Sign(message, key)
		require.NoError(err)
		signatures[i] = sig
	}

	// ParallelVerifyWithThreshold exercises GPU path if available,
	// falls back to CPU goroutines otherwise.
	err := signer.ParallelVerifyWithThreshold(messages, signatures, 8)
	require.NoError(err)

	// Corrupt one and verify batch fails
	signatures[7].Signature[0] ^= 0xFF
	err = signer.ParallelVerifyWithThreshold(messages, signatures, 8)
	require.Error(err)
}

func TestQuasarNTTMethods(t *testing.T) {
	require := require.New(t)

	logger := log.NoLog{}
	cfg := QuasarConfig{
		ValidatorID: "test-validator",
		Threshold:   2,
		TotalNodes:  3,
		Logger:      logger,
	}

	q, err := NewQuasar(cfg)
	require.NoError(err)

	// Create polynomial coefficients (256 elements in Z_q)
	coeffs := make([]uint64, 256)
	for i := range coeffs {
		coeffs[i] = uint64(i * 7 % 8380417) // values mod q
	}

	// Forward NTT should produce 256-element output
	nttDomain, err := q.NTTForwardRingtail(coeffs)
	require.NoError(err)
	require.Len(nttDomain, 256)

	// NTT output should differ from input (it's a transform)
	differ := false
	for i := range coeffs {
		if coeffs[i] != nttDomain[i] {
			differ = true
			break
		}
	}
	require.True(differ, "NTT output should differ from input")

	// Inverse NTT should produce valid output
	recovered, err := q.NTTInverseRingtail(nttDomain)
	require.NoError(err)
	require.Len(recovered, 256)

	// Batch NTT should handle multiple polynomials
	polys := [][]uint64{coeffs, nttDomain}
	batchResult, err := q.BatchNTTForwardRingtail(polys)
	require.NoError(err)
	require.Len(batchResult, 2)
}

func TestGPUAccelAvailable(t *testing.T) {
	logger := log.NoLog{}
	cfg := QuasarConfig{
		ValidatorID: "test",
		Threshold:   2,
		TotalNodes:  3,
		Logger:      logger,
	}
	q, err := NewQuasar(cfg)
	require.NoError(t, err)

	// Just check it doesn't panic -- actual value depends on hardware
	_ = q.GPUAccelAvailable()
}

func TestQuantumStampExpiration(t *testing.T) {
	require := require.New(t)

	// Create quantum signer with short stamp window
	logger := log.NoLog{}
	signer := quantum.NewQuantumSigner(
		logger,
		1,                    // algorithm version
		1024,                 // key size
		100*time.Millisecond, // very short stamp window
		100,                  // cache size
	)

	// Generate key and sign message
	key, err := signer.GenerateRingtailKey()
	require.NoError(err)

	message := []byte("test message")
	sig, err := signer.Sign(message, key)
	require.NoError(err)

	// Immediate verification should work
	err = signer.Verify(message, sig)
	require.NoError(err)

	// Wait for stamp to expire
	time.Sleep(200 * time.Millisecond)

	// Verification should fail due to expired stamp
	err = signer.Verify(message, sig)
	require.Error(err)
	require.Equal(quantum.ErrQuantumStampExpired, err)
}
