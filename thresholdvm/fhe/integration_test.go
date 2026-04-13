//go:build cgo

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/schemes/ckks"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

// newTestIntegration creates a ThresholdFHEIntegration for testing with optional custom config
func newTestIntegration(t *testing.T, config *ThresholdConfig) *ThresholdFHEIntegration {
	t.Helper()
	logger := log.Noop()

	if config == nil {
		defaultConfig := DefaultThresholdConfig()
		config = &defaultConfig
	}

	integration, err := NewThresholdFHEIntegration(logger, *config, 1)
	require.NoError(t, err)
	require.NotNil(t, integration)

	return integration
}

// newTestCiphertext generates a test ciphertext and returns the bytes along with the secret key
func newTestCiphertext(t *testing.T, params ckks.Parameters) ([]byte, *rlwe.SecretKey) {
	t.Helper()

	encoder := ckks.NewEncoder(params)
	kgen := rlwe.NewKeyGenerator(params.Parameters)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	encryptor := ckks.NewEncryptor(params, pk)

	values := make([]complex128, params.MaxSlots())
	values[0] = complex(42.0, 0)
	values[1] = complex(3.14159, 2.71828)

	pt := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(values, pt)

	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	ctBytes, err := ct.MarshalBinary()
	require.NoError(t, err)

	return ctBytes, sk
}

// --- DefaultThresholdConfig Tests ---

func TestDefaultThresholdConfigValues(t *testing.T) {
	require := require.New(t)

	config := DefaultThresholdConfig()

	require.Equal(67, config.Threshold, "default threshold should be 67")
	require.Equal(100, config.TotalParties, "default total parties should be 100")
	require.Equal(uint(128), config.LogBound, "default log bound should be 128")
	require.NotNil(config.CKKSParams, "CKKS params should not be nil")
}

func TestDefaultThresholdConfigCKKSParams(t *testing.T) {
	require := require.New(t)

	config := DefaultThresholdConfig()

	// Verify CKKS params are valid
	require.Greater(config.CKKSParams.MaxLevel(), 0)
	require.Greater(config.CKKSParams.MaxSlots(), 0)
}

// --- NewThresholdFHEIntegration Tests ---

func TestNewThresholdFHEIntegrationValid(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	config := DefaultThresholdConfig()

	integration, err := NewThresholdFHEIntegration(logger, config, 1)
	require.NoError(err)
	require.NotNil(integration)
	require.Equal(1, integration.partyID)
}

func TestNewThresholdFHEIntegrationDifferentPartyIDs(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	config := DefaultThresholdConfig()

	for _, partyID := range []int{0, 1, 50, 99} {
		integration, err := NewThresholdFHEIntegration(logger, config, partyID)
		require.NoError(err)
		require.NotNil(integration)
		require.Equal(partyID, integration.partyID)
	}
}

func TestNewThresholdFHEIntegrationCustomConfig(t *testing.T) {
	require := require.New(t)

	logger := log.Noop()
	params, err := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	require.NoError(err)

	config := ThresholdConfig{
		Threshold:    3,
		TotalParties: 5,
		CKKSParams:   params,
		LogBound:     64,
	}

	integration, err := NewThresholdFHEIntegration(logger, config, 2)
	require.NoError(err)
	require.NotNil(integration)
	require.Equal(3, integration.config.Threshold)
	require.Equal(5, integration.config.TotalParties)
	require.Equal(uint(64), integration.config.LogBound)
}

// --- Start/Stop Lifecycle Tests ---

func TestIntegrationStartStop(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	ctx := context.Background()
	err := integration.Start(ctx)
	require.NoError(err)

	err = integration.Stop()
	require.NoError(err)
}

func TestThresholdFHEIntegrationMultipleStartStop(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	ctx := context.Background()

	// First start/stop
	err := integration.Start(ctx)
	require.NoError(err)
	err = integration.Stop()
	require.NoError(err)

	// Second start/stop should also work
	err = integration.Start(ctx)
	require.NoError(err)
	err = integration.Stop()
	require.NoError(err)
}

func TestThresholdFHEIntegrationStopWithoutStart(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	// Stop without start should be safe
	err := integration.Stop()
	require.NoError(err)
}

// --- Key Management Tests ---

func TestSetSecretKey(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	require.Nil(integration.secretKey)

	kgen := rlwe.NewKeyGenerator(integration.params.Parameters)
	sk := kgen.GenSecretKeyNew()

	integration.SetSecretKey(sk)
	require.NotNil(integration.secretKey)
	require.Equal(sk, integration.secretKey)
}

func TestSetSecretKeyOverwrite(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	kgen := rlwe.NewKeyGenerator(integration.params.Parameters)
	sk1 := kgen.GenSecretKeyNew()
	sk2 := kgen.GenSecretKeyNew()

	integration.SetSecretKey(sk1)
	require.Equal(sk1, integration.secretKey)

	integration.SetSecretKey(sk2)
	require.Equal(sk2, integration.secretKey)
}

func TestSetNetworkKey(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	require.Nil(integration.GetNetworkKey())

	kgen := rlwe.NewKeyGenerator(integration.params.Parameters)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)

	integration.SetNetworkKey(pk)
	require.NotNil(integration.GetNetworkKey())
	require.Equal(pk, integration.GetNetworkKey())
}

func TestGetNetworkKeyInitiallyNil(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	require.Nil(integration.GetNetworkKey())
}

func TestSetNetworkKeyOverwrite(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	kgen := rlwe.NewKeyGenerator(integration.params.Parameters)
	sk1 := kgen.GenSecretKeyNew()
	pk1 := kgen.GenPublicKeyNew(sk1)
	sk2 := kgen.GenSecretKeyNew()
	pk2 := kgen.GenPublicKeyNew(sk2)

	integration.SetNetworkKey(pk1)
	require.Equal(pk1, integration.GetNetworkKey())

	integration.SetNetworkKey(pk2)
	require.Equal(pk2, integration.GetNetworkKey())
}

// --- InitiateDecryption Tests ---

func TestInitiateDecryptionSuccess(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)
	ctBytes, _ := newTestCiphertext(t, integration.params)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	// Verify session exists
	integration.sessionsMu.RLock()
	session, exists := integration.sessions[sessionID]
	integration.sessionsMu.RUnlock()

	require.True(exists)
	require.Equal(sessionID, session.ID)
	require.Equal(requestID, session.RequestID)
	require.NotNil(session.Ciphertext)
	require.False(session.Complete)
	require.Equal(0, session.ShareCount)
}

func TestInitiateDecryptionDuplicateSession(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)
	ctBytes, _ := newTestCiphertext(t, integration.params)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	// Duplicate should fail
	err = integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.Error(err)
	require.Contains(err.Error(), "already exists")
}

func TestInitiateDecryptionMultipleSessions(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)
	ctBytes, _ := newTestCiphertext(t, integration.params)

	for i := 0; i < 5; i++ {
		sessionID := common.Hash{byte(i)}.Hex()
		requestID := common.Hash{byte(i + 100)}

		err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
		require.NoError(err)
	}

	integration.sessionsMu.RLock()
	require.Equal(5, len(integration.sessions))
	integration.sessionsMu.RUnlock()
}

func TestInitiateDecryptionInvalidCiphertextBytes(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	// Invalid ciphertext bytes should fail
	err := integration.InitiateDecryption(sessionID, requestID, []byte("invalid"))
	require.Error(err)
	require.Contains(err.Error(), "unmarshal ciphertext")
}

// --- GenerateShare Tests ---

func TestGenerateShareSuccess(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)
	ctBytes, sk := newTestCiphertext(t, integration.params)

	integration.SetSecretKey(sk)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	shareBytes, err := integration.GenerateShare(sessionID)
	require.NoError(err)
	require.NotEmpty(shareBytes)

	// Verify own shares are stored
	integration.sessionsMu.RLock()
	session := integration.sessions[sessionID]
	integration.sessionsMu.RUnlock()

	require.NotNil(session.OwnSecretShare)
	require.NotNil(session.OwnPublicShare)
}

func TestGenerateShareSessionNotFound(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	_, err := integration.GenerateShare("nonexistent-session")
	require.Error(err)
	require.Contains(err.Error(), "not found")
}

func TestGenerateShareSecretKeyNotSet(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)
	ctBytes, _ := newTestCiphertext(t, integration.params)

	// Don't set secret key

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	_, err = integration.GenerateShare(sessionID)
	require.Error(err)
	require.Contains(err.Error(), "secret key not initialized")
}

func TestGenerateShareMultipleTimes(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)
	ctBytes, sk := newTestCiphertext(t, integration.params)

	integration.SetSecretKey(sk)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	// Generate share multiple times - should succeed each time
	share1, err := integration.GenerateShare(sessionID)
	require.NoError(err)
	require.NotEmpty(share1)

	share2, err := integration.GenerateShare(sessionID)
	require.NoError(err)
	require.NotEmpty(share2)
}

// --- ContributeShare Tests ---

func TestContributeShareSuccess(t *testing.T) {
	require := require.New(t)

	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	config := ThresholdConfig{
		Threshold:    1, // Low threshold for testing
		TotalParties: 3,
		CKKSParams:   params,
		LogBound:     128,
	}

	integration := newTestIntegration(t, &config)
	ctBytes, sk := newTestCiphertext(t, integration.params)

	integration.SetSecretKey(sk)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	shareBytes, err := integration.GenerateShare(sessionID)
	require.NoError(err)

	nodeID := ids.GenerateTestNodeID()
	complete, err := integration.ContributeShare(sessionID, nodeID, shareBytes)
	require.NoError(err)
	require.True(complete) // threshold is 1
}

func TestContributeShareInvalidSession(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	_, err := integration.ContributeShare("nonexistent", ids.GenerateTestNodeID(), []byte("share"))
	require.Error(err)
	require.Contains(err.Error(), "not found")
}

func TestContributeShareDuplicateParticipant(t *testing.T) {
	require := require.New(t)

	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	config := ThresholdConfig{
		Threshold:    2, // Need 2 shares
		TotalParties: 3,
		CKKSParams:   params,
		LogBound:     128,
	}

	integration := newTestIntegration(t, &config)
	ctBytes, sk := newTestCiphertext(t, integration.params)

	integration.SetSecretKey(sk)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	shareBytes, err := integration.GenerateShare(sessionID)
	require.NoError(err)

	nodeID := ids.GenerateTestNodeID()

	// First contribution
	complete, err := integration.ContributeShare(sessionID, nodeID, shareBytes)
	require.NoError(err)
	require.False(complete)

	// Duplicate from same node
	_, err = integration.ContributeShare(sessionID, nodeID, shareBytes)
	require.Error(err)
	require.Contains(err.Error(), "already contributed")
}

func TestContributeShareSessionAlreadyComplete(t *testing.T) {
	require := require.New(t)

	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	config := ThresholdConfig{
		Threshold:    1, // Completes with 1 share
		TotalParties: 3,
		CKKSParams:   params,
		LogBound:     128,
	}

	integration := newTestIntegration(t, &config)
	ctBytes, sk := newTestCiphertext(t, integration.params)

	integration.SetSecretKey(sk)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	shareBytes, err := integration.GenerateShare(sessionID)
	require.NoError(err)

	// Complete the session
	nodeID1 := ids.GenerateTestNodeID()
	complete, err := integration.ContributeShare(sessionID, nodeID1, shareBytes)
	require.NoError(err)
	require.True(complete)

	// Try to contribute to already complete session
	nodeID2 := ids.GenerateTestNodeID()
	complete, err = integration.ContributeShare(sessionID, nodeID2, shareBytes)
	require.NoError(err)
	require.True(complete) // returns true because already complete
}

func TestContributeShareInsufficientShares(t *testing.T) {
	require := require.New(t)

	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	config := ThresholdConfig{
		Threshold:    3, // Need 3 shares
		TotalParties: 5,
		CKKSParams:   params,
		LogBound:     128,
	}

	integration := newTestIntegration(t, &config)
	ctBytes, sk := newTestCiphertext(t, integration.params)

	integration.SetSecretKey(sk)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	shareBytes, err := integration.GenerateShare(sessionID)
	require.NoError(err)

	// Only contribute 2 shares when threshold is 3
	for i := 0; i < 2; i++ {
		nodeID := ids.GenerateTestNodeID()
		complete, err := integration.ContributeShare(sessionID, nodeID, shareBytes)
		require.NoError(err)
		require.False(complete)
	}

	// Verify not complete
	result, complete, err := integration.GetSessionResult(sessionID)
	require.NoError(err)
	require.False(complete)
	require.Nil(result)
}

func TestContributeShareThresholdReached(t *testing.T) {
	require := require.New(t)

	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	config := ThresholdConfig{
		Threshold:    2, // Need 2 shares
		TotalParties: 3,
		CKKSParams:   params,
		LogBound:     128,
	}

	integration := newTestIntegration(t, &config)
	ctBytes, sk := newTestCiphertext(t, integration.params)

	integration.SetSecretKey(sk)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	shareBytes, err := integration.GenerateShare(sessionID)
	require.NoError(err)

	// First share
	nodeID1 := ids.GenerateTestNodeID()
	complete, err := integration.ContributeShare(sessionID, nodeID1, shareBytes)
	require.NoError(err)
	require.False(complete)

	// Second share - should complete
	nodeID2 := ids.GenerateTestNodeID()
	complete, err = integration.ContributeShare(sessionID, nodeID2, shareBytes)
	require.NoError(err)
	require.True(complete)

	// Verify session is complete
	result, isComplete, err := integration.GetSessionResult(sessionID)
	require.NoError(err)
	require.True(isComplete)
	require.NotEmpty(result)
}

// --- GetSessionResult Tests ---

func TestGetSessionResultSuccess(t *testing.T) {
	require := require.New(t)

	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	config := ThresholdConfig{
		Threshold:    1,
		TotalParties: 2,
		CKKSParams:   params,
		LogBound:     128,
	}

	integration := newTestIntegration(t, &config)
	ctBytes, sk := newTestCiphertext(t, integration.params)

	integration.SetSecretKey(sk)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	shareBytes, err := integration.GenerateShare(sessionID)
	require.NoError(err)

	nodeID := ids.GenerateTestNodeID()
	_, err = integration.ContributeShare(sessionID, nodeID, shareBytes)
	require.NoError(err)

	result, complete, err := integration.GetSessionResult(sessionID)
	require.NoError(err)
	require.True(complete)
	require.NotEmpty(result)
}

func TestGetSessionResultNotFound(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)

	_, _, err := integration.GetSessionResult("nonexistent")
	require.Error(err)
	require.Contains(err.Error(), "not found")
}

func TestGetSessionResultIncomplete(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)
	ctBytes, _ := newTestCiphertext(t, integration.params)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	result, complete, err := integration.GetSessionResult(sessionID)
	require.NoError(err)
	require.False(complete)
	require.Nil(result)
}

// --- CleanupSession Tests ---

func TestCleanupSessionSuccess(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)
	ctBytes, _ := newTestCiphertext(t, integration.params)

	sessionID := "test-session-1"
	requestID := common.HexToHash("0x1234")

	err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	// Verify session exists
	integration.sessionsMu.RLock()
	_, exists := integration.sessions[sessionID]
	integration.sessionsMu.RUnlock()
	require.True(exists)

	// Cleanup
	integration.CleanupSession(sessionID)

	// Verify session is gone
	integration.sessionsMu.RLock()
	_, exists = integration.sessions[sessionID]
	integration.sessionsMu.RUnlock()
	require.False(exists)
}

func TestCleanupSessionNonexistent(t *testing.T) {
	integration := newTestIntegration(t, nil)

	// Should not panic
	integration.CleanupSession("nonexistent")
}

func TestCleanupSessionMultiple(t *testing.T) {
	require := require.New(t)

	integration := newTestIntegration(t, nil)
	ctBytes, _ := newTestCiphertext(t, integration.params)

	// Create multiple sessions
	for i := 0; i < 5; i++ {
		sessionID := common.Hash{byte(i)}.Hex()
		requestID := common.Hash{byte(i + 100)}
		err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
		require.NoError(err)
	}

	integration.sessionsMu.RLock()
	require.Equal(5, len(integration.sessions))
	integration.sessionsMu.RUnlock()

	// Cleanup some
	integration.CleanupSession(common.Hash{0}.Hex())
	integration.CleanupSession(common.Hash{2}.Hex())

	integration.sessionsMu.RLock()
	require.Equal(3, len(integration.sessions))
	integration.sessionsMu.RUnlock()
}

// --- Encoding Helper Tests ---

func TestEncodeComplexValuesToBytesBasic(t *testing.T) {
	require := require.New(t)

	values := []complex128{
		complex(1.0, 2.0),
		complex(3.0, 4.0),
	}

	encoded := encodeComplexValuesToBytes(values)
	require.Equal(32, len(encoded)) // 2 values * 16 bytes each
}

func TestDecodeComplexValuesFromBytesBasic(t *testing.T) {
	require := require.New(t)

	original := []complex128{
		complex(1.5, 2.5),
		complex(3.14159, 2.71828),
		complex(-1.0, -2.0),
		complex(0, 0),
	}

	encoded := encodeComplexValuesToBytes(original)
	decoded := decodeComplexValuesFromBytes(encoded)

	require.Equal(len(original), len(decoded))

	for i := range original {
		require.InDelta(real(original[i]), real(decoded[i]), 1e-10)
		require.InDelta(imag(original[i]), imag(decoded[i]), 1e-10)
	}
}

func TestEncodeDecodeComplexValuesRoundTrip(t *testing.T) {
	require := require.New(t)

	testCases := [][]complex128{
		{complex(0, 0)},
		{complex(1, 0), complex(0, 1)},
		{complex(42.5, -17.3), complex(0, 0), complex(-100, 100)},
		{complex(1e10, 1e-10), complex(-1e10, -1e-10)},
	}

	for _, original := range testCases {
		encoded := encodeComplexValuesToBytes(original)
		decoded := decodeComplexValuesFromBytes(encoded)

		require.Equal(len(original), len(decoded))
		for i := range original {
			require.InDelta(real(original[i]), real(decoded[i]), 1e-10)
			require.InDelta(imag(original[i]), imag(decoded[i]), 1e-10)
		}
	}
}

func TestEncodeComplexValuesEmpty(t *testing.T) {
	require := require.New(t)

	encoded := encodeComplexValuesToBytes([]complex128{})
	require.Empty(encoded)
}

func TestDecodeComplexValuesEmpty(t *testing.T) {
	require := require.New(t)

	decoded := decodeComplexValuesFromBytes([]byte{})
	require.Empty(decoded)
}

func TestDecodeComplexValuesInvalidLength(t *testing.T) {
	require := require.New(t)

	// Not divisible by 16
	decoded := decodeComplexValuesFromBytes([]byte{1, 2, 3, 4, 5})
	require.Nil(decoded)

	decoded = decodeComplexValuesFromBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	require.Nil(decoded)
}

func TestEncodeComplexValuesSpecialFloats(t *testing.T) {
	require := require.New(t)

	// Test with very small and very large values
	original := []complex128{
		complex(1e-300, 1e-300),
		complex(1e300, 1e300),
		complex(-1e-300, -1e-300),
		complex(-1e300, -1e300),
	}

	encoded := encodeComplexValuesToBytes(original)
	decoded := decodeComplexValuesFromBytes(encoded)

	require.Equal(len(original), len(decoded))
	for i := range original {
		require.Equal(real(original[i]), real(decoded[i]))
		require.Equal(imag(original[i]), imag(decoded[i]))
	}
}

// --- Integration Flow Tests ---

func TestFullDecryptionFlow(t *testing.T) {
	require := require.New(t)

	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	config := ThresholdConfig{
		Threshold:    2,
		TotalParties: 3,
		CKKSParams:   params,
		LogBound:     128,
	}

	integration := newTestIntegration(t, &config)
	ctBytes, sk := newTestCiphertext(t, integration.params)

	// Setup
	integration.SetSecretKey(sk)

	ctx := context.Background()
	err := integration.Start(ctx)
	require.NoError(err)
	defer integration.Stop()

	// Initiate decryption
	sessionID := "full-flow-session"
	requestID := common.HexToHash("0xabcd")
	err = integration.InitiateDecryption(sessionID, requestID, ctBytes)
	require.NoError(err)

	// Generate share
	shareBytes, err := integration.GenerateShare(sessionID)
	require.NoError(err)

	// Contribute shares until threshold
	node1 := ids.GenerateTestNodeID()
	complete, err := integration.ContributeShare(sessionID, node1, shareBytes)
	require.NoError(err)
	require.False(complete)

	node2 := ids.GenerateTestNodeID()
	complete, err = integration.ContributeShare(sessionID, node2, shareBytes)
	require.NoError(err)
	require.True(complete)

	// Get result
	result, isComplete, err := integration.GetSessionResult(sessionID)
	require.NoError(err)
	require.True(isComplete)
	require.NotEmpty(result)

	// Cleanup
	integration.CleanupSession(sessionID)

	// Verify cleanup
	_, _, err = integration.GetSessionResult(sessionID)
	require.Error(err)
}

func TestMultipleSessionsParallel(t *testing.T) {
	require := require.New(t)

	params, _ := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	config := ThresholdConfig{
		Threshold:    1,
		TotalParties: 2,
		CKKSParams:   params,
		LogBound:     128,
	}

	integration := newTestIntegration(t, &config)
	ctBytes, sk := newTestCiphertext(t, integration.params)

	integration.SetSecretKey(sk)

	// Create multiple sessions
	sessionIDs := []string{"session-1", "session-2", "session-3"}
	for i, sessionID := range sessionIDs {
		requestID := common.Hash{byte(i)}
		err := integration.InitiateDecryption(sessionID, requestID, ctBytes)
		require.NoError(err)
	}

	// Complete each session
	for _, sessionID := range sessionIDs {
		shareBytes, err := integration.GenerateShare(sessionID)
		require.NoError(err)

		nodeID := ids.GenerateTestNodeID()
		complete, err := integration.ContributeShare(sessionID, nodeID, shareBytes)
		require.NoError(err)
		require.True(complete)
	}

	// Verify all completed
	for _, sessionID := range sessionIDs {
		result, complete, err := integration.GetSessionResult(sessionID)
		require.NoError(err)
		require.True(complete)
		require.NotEmpty(result)
	}
}

// --- Benchmark Tests ---

func BenchmarkInitiateDecryption(b *testing.B) {
	logger := log.Noop()
	config := DefaultThresholdConfig()
	integration, _ := NewThresholdFHEIntegration(logger, config, 1)

	// Generate test ciphertext
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionID := common.Hash{byte(i % 256), byte(i / 256)}.Hex()
		requestID := common.Hash{byte(i)}
		_ = integration.InitiateDecryption(sessionID, requestID, ctBytes)
	}
}

func BenchmarkGenerateShare(b *testing.B) {
	logger := log.Noop()
	config := DefaultThresholdConfig()
	integration, _ := NewThresholdFHEIntegration(logger, config, 1)

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

	// Create a single session
	sessionID := "bench-session"
	requestID := common.HexToHash("0x1234")
	_ = integration.InitiateDecryption(sessionID, requestID, ctBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = integration.GenerateShare(sessionID)
	}
}

func BenchmarkEncodeComplexValues(b *testing.B) {
	values := make([]complex128, 8)
	for i := range values {
		values[i] = complex(float64(i), float64(i)*2)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = encodeComplexValuesToBytes(values)
	}
}

func BenchmarkDecodeComplexValues(b *testing.B) {
	values := make([]complex128, 8)
	for i := range values {
		values[i] = complex(float64(i), float64(i)*2)
	}
	encoded := encodeComplexValuesToBytes(values)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = decodeComplexValuesFromBytes(encoded)
	}
}
