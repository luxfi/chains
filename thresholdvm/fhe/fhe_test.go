//go:build cgo

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/schemes/ckks"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/platformvm/warp"
	"github.com/stretchr/testify/require"
)

func TestDefaultThresholdConfig(t *testing.T) {
	require := require.New(t)

	config := DefaultThresholdConfig()
	require.Equal(67, config.Threshold)
	require.Equal(100, config.TotalParties)
	require.NotNil(config.CKKSParams)
}

func TestThresholdFHEIntegrationInit(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	config := DefaultThresholdConfig()

	integration, err := NewThresholdFHEIntegration(logger, config, 1)
	require.NoError(err)
	require.NotNil(integration)
}

func TestThresholdFHEIntegrationStartStop(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	config := DefaultThresholdConfig()

	integration, err := NewThresholdFHEIntegration(logger, config, 1)
	require.NoError(err)

	ctx := context.Background()
	err = integration.Start(ctx)
	require.NoError(err)

	err = integration.Stop()
	require.NoError(err)
}

func TestThresholdFHEIntegrationSessionManagement(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	config := DefaultThresholdConfig()

	integration, err := NewThresholdFHEIntegration(logger, config, 1)
	require.NoError(err)

	// Generate a test ciphertext
	params := config.CKKSParams
	encoder := ckks.NewEncoder(params)
	encryptor := ckks.NewEncryptor(params, nil)
	kgen := rlwe.NewKeyGenerator(params.Parameters)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	encryptor = ckks.NewEncryptor(params, pk)

	// Set the secret key
	integration.SetSecretKey(sk)

	// Encode and encrypt a value
	values := make([]complex128, params.MaxSlots())
	values[0] = complex(42.0, 0)
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(values, pt)

	ct, err := encryptor.EncryptNew(pt)
	require.NoError(err)

	ctBytes, err := ct.MarshalBinary()
	require.NoError(err)

	// Initiate decryption session
	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err = integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	// Duplicate session should fail
	err = integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.Error(err)

	// Generate share
	shareBytes, err := integration.GenerateShare(sessionID)
	require.NoError(err)
	require.NotEmpty(shareBytes)

	// Session not found
	_, err = integration.GenerateShare("nonexistent")
	require.Error(err)

	// Cleanup
	integration.CleanupSession(sessionID)

	// Session should be gone
	_, _, err = integration.GetSessionResult(sessionID)
	require.Error(err)
}

func TestThresholdFHEIntegrationNetworkKey(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	config := DefaultThresholdConfig()

	integration, err := NewThresholdFHEIntegration(logger, config, 1)
	require.NoError(err)

	// Initially nil
	require.Nil(integration.GetNetworkKey())

	// Set and get
	kgen := rlwe.NewKeyGenerator(config.CKKSParams.Parameters)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)

	integration.SetNetworkKey(pk)
	require.NotNil(integration.GetNetworkKey())
}

func TestInMemoryCiphertextStorage(t *testing.T) {
	require := require.New(t)

	storage := NewInMemoryCiphertextStorage()
	require.NotNil(storage)

	handle := common.HexToHash("0x1234567890abcdef")
	data := []byte("test ciphertext data")

	// Get non-existent
	_, err := storage.Get(handle)
	require.Error(err)
	require.Equal(ErrCiphertextNotFound, err)

	// Put
	err = storage.Put(handle, data)
	require.NoError(err)

	// Get
	retrieved, err := storage.Get(handle)
	require.NoError(err)
	require.Equal(data, retrieved)

	// Delete
	err = storage.Delete(handle)
	require.NoError(err)

	// Get after delete
	_, err = storage.Get(handle)
	require.Error(err)
}

func TestThresholdDecryptorInit(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	params, err := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	require.NoError(err)

	decryptor, err := NewThresholdDecryptor(
		logger,
		params,
		67,  // threshold
		100, // totalParties
		1,   // partyID
		128, // logBound
		nil, // broadcastShare
	)
	require.NoError(err)
	require.NotNil(decryptor)
}

func TestThresholdDecryptorWithSecretKey(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	params, err := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	require.NoError(err)

	decryptor, err := NewThresholdDecryptor(
		logger,
		params,
		67, 100, 1, 128,
		nil,
	)
	require.NoError(err)

	// Generate and set secret key
	kgen := rlwe.NewKeyGenerator(params.Parameters)
	sk := kgen.GenSecretKeyNew()
	decryptor.SetSecretKey(sk)
}

func TestRelayerInit(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	params, err := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	require.NoError(err)

	decryptor, err := NewThresholdDecryptor(
		logger, params, 67, 100, 1, 128, nil,
	)
	require.NoError(err)

	storage := NewInMemoryCiphertextStorage()

	relayer := NewRelayer(
		logger,
		decryptor,
		storage,
		1,                    // networkID
		ids.GenerateTestID(), // chainID
		ids.GenerateTestID(), // zChainID
		nil,                  // signer
		nil,                  // onMessage
	)
	require.NotNil(relayer)
}

func TestRelayerStartStop(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	params, err := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	require.NoError(err)

	decryptor, err := NewThresholdDecryptor(
		logger, params, 67, 100, 1, 128, nil,
	)
	require.NoError(err)

	storage := NewInMemoryCiphertextStorage()

	relayer := NewRelayer(
		logger, decryptor, storage,
		1, ids.GenerateTestID(), ids.GenerateTestID(),
		nil, nil,
	)

	ctx := context.Background()
	err = relayer.Start(ctx)
	require.NoError(err)

	err = relayer.Stop()
	require.NoError(err)
}

func TestRelayerSubmitRequest(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	params, err := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	require.NoError(err)

	decryptor, err := NewThresholdDecryptor(
		logger, params, 67, 100, 1, 128, nil,
	)
	require.NoError(err)

	storage := NewInMemoryCiphertextStorage()

	relayer := NewRelayer(
		logger, decryptor, storage,
		1, ids.GenerateTestID(), ids.GenerateTestID(),
		nil, nil,
	)

	ctx := context.Background()
	_ = relayer.Start(ctx)
	defer relayer.Stop()

	req := &DecryptionRequest{
		RequestID:      common.HexToHash("0x1234"),
		CiphertextHash: common.HexToHash("0x5678"),
		DecryptionType: 1,
		SourceChainID:  ids.GenerateTestID(),
	}

	err = relayer.SubmitRequest(ctx, req)
	require.NoError(err)

	// Duplicate should fail
	err = relayer.SubmitRequest(ctx, req)
	require.Error(err)
}

func TestRelayerGetResult(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	params, err := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	require.NoError(err)

	decryptor, err := NewThresholdDecryptor(
		logger, params, 67, 100, 1, 128, nil,
	)
	require.NoError(err)

	storage := NewInMemoryCiphertextStorage()

	relayer := NewRelayer(
		logger, decryptor, storage,
		1, ids.GenerateTestID(), ids.GenerateTestID(),
		nil, nil,
	)

	ctx := context.Background()
	_ = relayer.Start(ctx)
	defer relayer.Stop()

	// Request not found
	_, _, err = relayer.GetResult(common.HexToHash("0xnonexistent"))
	require.Error(err)
	require.Equal(ErrRequestNotFound, err)

	// Submit request
	req := &DecryptionRequest{
		RequestID:      common.HexToHash("0x1234"),
		CiphertextHash: common.HexToHash("0x5678"),
	}
	_ = relayer.SubmitRequest(ctx, req)

	// Not fulfilled yet
	_, fulfilled, err := relayer.GetResult(req.RequestID)
	require.NoError(err)
	require.False(fulfilled)
}

func TestWarpHandler(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	params, err := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	require.NoError(err)

	decryptor, err := NewThresholdDecryptor(
		logger, params, 67, 100, 1, 128, nil,
	)
	require.NoError(err)

	storage := NewInMemoryCiphertextStorage()

	relayer := NewRelayer(
		logger, decryptor, storage,
		1, ids.GenerateTestID(), ids.GenerateTestID(),
		nil, nil,
	)

	handler := NewWarpHandler(logger, relayer)
	require.NotNil(handler)

	// Nil message
	err = handler.HandleMessage(context.Background(), nil)
	require.Error(err)

	// Invalid payload (too short)
	msg := &warp.Message{
		UnsignedMessage: warp.UnsignedMessage{
			Payload: []byte{0x01, 0x02},
		},
	}
	err = handler.HandleMessage(context.Background(), msg)
	require.Error(err)
	require.Equal(ErrInvalidPayload, err)
}

func TestFHEDecryptionService(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	service := NewFHEDecryptionService(logger)
	require.NotNil(service)

	ctx := context.Background()
	err := service.Start(ctx)
	require.NoError(err)

	// Cannot start twice
	err = service.Start(ctx)
	require.Error(err)

	err = service.Stop()
	require.NoError(err)

	// Stop is idempotent
	err = service.Stop()
	require.NoError(err)
}

func TestFHEDecryptionServiceHandlerRegistration(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	service := NewFHEDecryptionService(logger)

	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	decryptor, _ := NewThresholdDecryptor(logger, params, 67, 100, 1, 128, nil)
	storage := NewInMemoryCiphertextStorage()
	relayer := NewRelayer(logger, decryptor, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
	handler := NewWarpHandler(logger, relayer)

	chainID := ids.GenerateTestID()
	service.RegisterHandler(chainID, handler)

	retrieved, ok := service.GetHandler(chainID)
	require.True(ok)
	require.Equal(handler, retrieved)

	// Non-existent handler
	_, ok = service.GetHandler(ids.GenerateTestID())
	require.False(ok)
}

func TestEncodeFulfillmentCall(t *testing.T) {
	require := require.New(t)

	requestID := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	result := []byte("decryption result")

	data := encodeFulfillmentCall(requestID, result)
	require.NotEmpty(data)

	// Check selector
	require.Equal(byte(0x8a), data[0])
	require.Equal(byte(0x6d), data[1])
	require.Equal(byte(0x3a), data[2])
	require.Equal(byte(0xf9), data[3])

	// Check request ID is in the data
	require.Equal(requestID.Bytes(), data[4:36])
}

func TestComplexValueEncoding(t *testing.T) {
	require := require.New(t)

	original := []complex128{
		complex(1.5, 2.5),
		complex(3.14159, 0),
		complex(0, -1.0),
		complex(42.0, 42.0),
	}

	encoded := encodeComplexValuesToBytes(original)
	require.Equal(len(original)*16, len(encoded))

	decoded := decodeComplexValuesFromBytes(encoded)
	require.Equal(len(original), len(decoded))

	for i := range original {
		require.InDelta(real(original[i]), real(decoded[i]), 1e-10)
		require.InDelta(imag(original[i]), imag(decoded[i]), 1e-10)
	}
}

func TestComplexValueEncodingEmpty(t *testing.T) {
	require := require.New(t)

	encoded := encodeComplexValuesToBytes([]complex128{})
	require.Empty(encoded)

	decoded := decodeComplexValuesFromBytes([]byte{})
	require.Empty(decoded)

	// Invalid length
	decoded = decodeComplexValuesFromBytes([]byte{1, 2, 3})
	require.Nil(decoded)
}

func TestRelayerCleanup(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	decryptor, _ := NewThresholdDecryptor(logger, params, 67, 100, 1, 128, nil)
	storage := NewInMemoryCiphertextStorage()

	relayer := NewRelayer(
		logger, decryptor, storage,
		1, ids.GenerateTestID(), ids.GenerateTestID(),
		nil, nil,
	)

	// Set a very short timeout for testing
	relayer.requestTimeout = 10 * time.Millisecond

	ctx := context.Background()
	_ = relayer.Start(ctx)
	defer relayer.Stop()

	// Submit request
	req := &DecryptionRequest{
		RequestID:      common.HexToHash("0x1234"),
		CiphertextHash: common.HexToHash("0x5678"),
	}
	_ = relayer.SubmitRequest(ctx, req)

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)
	relayer.doCleanup()

	// Request should be cleaned up
	_, _, err := relayer.GetResult(req.RequestID)
	require.Equal(ErrRequestNotFound, err)
}

func TestRelayerFetchCiphertextNoStorage(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()

	// Create relayer without storage
	relayer := NewRelayer(
		logger, nil, nil, // nil storage
		1, ids.GenerateTestID(), ids.GenerateTestID(),
		nil, nil,
	)

	ctx := context.Background()
	_ = relayer.Start(ctx)
	defer relayer.Stop()

	// Fetch should fail with no storage
	_, err := relayer.fetchCiphertext(ctx, common.HexToHash("0x1234"))
	require.Error(err)
	require.Contains(err.Error(), "storage not configured")
}

func TestRelayerFetchCiphertextNotFound(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	storage := NewInMemoryCiphertextStorage()

	relayer := NewRelayer(
		logger, nil, storage,
		1, ids.GenerateTestID(), ids.GenerateTestID(),
		nil, nil,
	)

	ctx := context.Background()
	_ = relayer.Start(ctx)
	defer relayer.Stop()

	// Fetch non-existent ciphertext
	_, err := relayer.fetchCiphertext(ctx, common.HexToHash("0x1234"))
	require.ErrorIs(err, ErrCiphertextNotFound)
}

func TestRelayerFetchCiphertextSuccess(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	storage := NewInMemoryCiphertextStorage()

	// Store a ciphertext
	handle := common.HexToHash("0x1234")
	ctData := []byte("test-ciphertext-data")
	require.NoError(storage.Put(handle, ctData))

	relayer := NewRelayer(
		logger, nil, storage,
		1, ids.GenerateTestID(), ids.GenerateTestID(),
		nil, nil,
	)

	ctx := context.Background()
	_ = relayer.Start(ctx)
	defer relayer.Stop()

	// Fetch existing ciphertext
	result, err := relayer.fetchCiphertext(ctx, handle)
	require.NoError(err)
	require.Equal(ctData, result)
}

func TestRelayerGetResultFulfilled(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	storage := NewInMemoryCiphertextStorage()

	relayer := NewRelayer(
		logger, nil, storage,
		1, ids.GenerateTestID(), ids.GenerateTestID(),
		nil, nil,
	)

	ctx := context.Background()
	_ = relayer.Start(ctx)
	defer relayer.Stop()

	// Submit request
	reqID := common.HexToHash("0x1234")
	req := &DecryptionRequest{
		RequestID:      reqID,
		CiphertextHash: common.HexToHash("0x5678"),
	}
	_ = relayer.SubmitRequest(ctx, req)

	// Manually mark as fulfilled
	relayer.mu.Lock()
	relayer.pendingRequests[reqID].Fulfilled = true
	relayer.pendingRequests[reqID].Result = []byte("decrypted-data")
	relayer.mu.Unlock()

	// Get result
	result, fulfilled, err := relayer.GetResult(reqID)
	require.NoError(err)
	require.True(fulfilled)
	require.Equal([]byte("decrypted-data"), result)
}

func TestContributeShareSessionNotFound(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	config := DefaultThresholdConfig()

	integration, err := NewThresholdFHEIntegration(logger, config, 1)
	require.NoError(err)

	// Try to contribute to non-existent session
	_, err = integration.ContributeShare("non-existent", ids.GenerateTestNodeID(), []byte("share"))
	require.Error(err)
	require.Contains(err.Error(), "not found")
}

func TestContributeShareAlreadyComplete(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	// Use very low threshold for easier testing
	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	config := ThresholdConfig{
		Threshold:    1,
		TotalParties: 2,
		CKKSParams:   params,
		LogBound:     128,
	}

	integration, err := NewThresholdFHEIntegration(logger, config, 1)
	require.NoError(err)

	// Generate test ciphertext
	encoder := ckks.NewEncoder(params)
	kgen := rlwe.NewKeyGenerator(params.Parameters)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	encryptor := ckks.NewEncryptor(params, pk)

	integration.SetSecretKey(sk)

	values := make([]complex128, params.MaxSlots())
	values[0] = complex(42.0, 0)
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(values, pt)
	ct, _ := encryptor.EncryptNew(pt)
	ctBytes, _ := ct.MarshalBinary()

	// Create session
	sessionID := "test-session"
	requestID := common.HexToHash("0x1234")
	err = integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	// Generate a share
	shareBytes, err := integration.GenerateShare(sessionID)
	require.NoError(err)

	// Contribute share - threshold is 1 so this should complete
	nodeID := ids.GenerateTestNodeID()
	complete, err := integration.ContributeShare(sessionID, nodeID, shareBytes)
	require.NoError(err)
	require.True(complete)

	// Try to contribute again - should return true (already complete)
	complete, err = integration.ContributeShare(sessionID, ids.GenerateTestNodeID(), shareBytes)
	require.NoError(err)
	require.True(complete)
}

func TestContributeShareDuplicateNode(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	config := ThresholdConfig{
		Threshold:    2, // Need 2 shares
		TotalParties: 3,
		CKKSParams:   params,
		LogBound:     128,
	}

	integration, err := NewThresholdFHEIntegration(logger, config, 1)
	require.NoError(err)

	// Generate test ciphertext
	encoder := ckks.NewEncoder(params)
	kgen := rlwe.NewKeyGenerator(params.Parameters)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	encryptor := ckks.NewEncryptor(params, pk)

	integration.SetSecretKey(sk)

	values := make([]complex128, params.MaxSlots())
	values[0] = complex(42.0, 0)
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(values, pt)
	ct, _ := encryptor.EncryptNew(pt)
	ctBytes, _ := ct.MarshalBinary()

	// Create session
	sessionID := "test-session"
	requestID := common.HexToHash("0x1234")
	err = integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	// Generate a share
	shareBytes, err := integration.GenerateShare(sessionID)
	require.NoError(err)

	// Contribute first share
	nodeID := ids.GenerateTestNodeID()
	complete, err := integration.ContributeShare(sessionID, nodeID, shareBytes)
	require.NoError(err)
	require.False(complete) // threshold is 2, only 1 share

	// Try to contribute again from same node - should fail
	_, err = integration.ContributeShare(sessionID, nodeID, shareBytes)
	require.Error(err)
	require.Contains(err.Error(), "already contributed")
}

// TestContributeShareInvalidShare is skipped because the underlying lattice library
// panics on invalid share data rather than returning an error gracefully.

func TestGetSessionResultNotComplete(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	config := DefaultThresholdConfig()

	integration, err := NewThresholdFHEIntegration(logger, config, 1)
	require.NoError(err)

	// Generate test ciphertext
	params := config.CKKSParams
	encoder := ckks.NewEncoder(params)
	kgen := rlwe.NewKeyGenerator(params.Parameters)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	encryptor := ckks.NewEncryptor(params, pk)

	integration.SetSecretKey(sk)

	values := make([]complex128, params.MaxSlots())
	values[0] = complex(42.0, 0)
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(values, pt)
	ct, _ := encryptor.EncryptNew(pt)
	ctBytes, _ := ct.MarshalBinary()

	// Create session
	sessionID := "test-session"
	requestID := common.HexToHash("0x1234")
	err = integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	// Get result - should not be complete
	result, complete, err := integration.GetSessionResult(sessionID)
	require.NoError(err)
	require.False(complete)
	require.Nil(result)
}

func TestGenerateShareNoSecretKey(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	config := DefaultThresholdConfig()

	integration, err := NewThresholdFHEIntegration(logger, config, 1)
	require.NoError(err)

	// Don't set secret key
	// Generate test ciphertext with temp key
	params := config.CKKSParams
	encoder := ckks.NewEncoder(params)
	kgen := rlwe.NewKeyGenerator(params.Parameters)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	encryptor := ckks.NewEncryptor(params, pk)

	values := make([]complex128, params.MaxSlots())
	values[0] = complex(42.0, 0)
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(values, pt)
	ct, _ := encryptor.EncryptNew(pt)
	ctBytes, _ := ct.MarshalBinary()

	// Create session
	sessionID := "test-session"
	requestID := common.HexToHash("0x1234")
	err = integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	// Try to generate share without secret key
	_, err = integration.GenerateShare(sessionID)
	require.Error(err)
	require.Contains(err.Error(), "secret key not initialized")
}

// TestInitiateDecryptionInvalidCiphertext is skipped because the underlying lattice library
// panics on invalid ciphertext data rather than returning an error gracefully.

func BenchmarkThresholdDecryptorGenShare(b *testing.B) {
	logger := log.Noop()
	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)

	decryptor, _ := NewThresholdDecryptor(logger, params, 67, 100, 1, 128, nil)

	kgen := rlwe.NewKeyGenerator(params.Parameters)
	sk := kgen.GenSecretKeyNew()
	decryptor.SetSecretKey(sk)

	// Create test ciphertext
	encoder := ckks.NewEncoder(params)
	pk := kgen.GenPublicKeyNew(sk)
	encryptor := ckks.NewEncryptor(params, pk)

	values := make([]complex128, params.MaxSlots())
	values[0] = complex(42.0, 0)
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(values, pt)
	ct, _ := encryptor.EncryptNew(pt)
	ctBytes, _ := ct.MarshalBinary()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, _ = decryptor.Decrypt(ctx, "bench-session", ctBytes)
		cancel()
	}
}
