// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/schemes/ckks"
	"github.com/luxfi/log"
	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

// mockSigner implements warp.Signer for testing
type mockSigner struct {
	signFunc func(*warp.Message) ([]byte, error)
}

func (m *mockSigner) Sign(msg *warp.Message) ([]byte, error) {
	if m.signFunc != nil {
		return m.signFunc(msg)
	}
	return make([]byte, 96), nil
}

// TestNewRelayer tests Relayer creation with various configurations
func TestNewRelayer(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	t.Run("valid config", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		signer := &mockSigner{}
		chainID := ids.GenerateTestID()
		zChainID := ids.GenerateTestID()

		relayer := NewRelayer(logger, nil, storage, 1, chainID, zChainID, signer, nil)
		require.NotNil(relayer)
		require.NotNil(relayer.pendingRequests)
		require.NotNil(relayer.requestChan)
		require.NotNil(relayer.resultChan)
		require.NotNil(relayer.shutdownChan)
		require.Equal(30*time.Second, relayer.requestTimeout)
	})

	t.Run("nil storage", func(t *testing.T) {
		chainID := ids.GenerateTestID()
		zChainID := ids.GenerateTestID()

		relayer := NewRelayer(logger, nil, nil, 1, chainID, zChainID, nil, nil)
		require.NotNil(relayer)
		require.Nil(relayer.storage)
	})

	t.Run("nil decryptor", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		chainID := ids.GenerateTestID()
		zChainID := ids.GenerateTestID()

		relayer := NewRelayer(logger, nil, storage, 1, chainID, zChainID, nil, nil)
		require.NotNil(relayer)
		require.Nil(relayer.decryptor)
	})

	t.Run("with onMessage callback", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		chainID := ids.GenerateTestID()
		zChainID := ids.GenerateTestID()

		onMessage := func(_ context.Context, _ *warp.Envelope) error {
			return nil
		}

		relayer := NewRelayer(logger, nil, storage, 1, chainID, zChainID, nil, onMessage)
		require.NotNil(relayer)
		require.NotNil(relayer.onMessage)
	})
}

// TestRelayerStartStopLifecycle tests the Start/Stop lifecycle
func TestRelayerStartStopLifecycle(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	t.Run("start and stop", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		err := relayer.Start(context.Background())
		require.NoError(err)

		// Give goroutines time to start
		time.Sleep(10 * time.Millisecond)

		err = relayer.Stop()
		require.NoError(err)
	})

	t.Run("start with canceled context", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		ctx, cancel := context.WithCancel(context.Background())
		err := relayer.Start(ctx)
		require.NoError(err)

		// Cancel context
		cancel()

		// Goroutines should exit gracefully
		time.Sleep(50 * time.Millisecond)

		err = relayer.Stop()
		require.NoError(err)
	})

	t.Run("double stop", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		err := relayer.Start(context.Background())
		require.NoError(err)

		time.Sleep(10 * time.Millisecond)

		err = relayer.Stop()
		require.NoError(err)

		// Second stop should panic (closing closed channel) - use recover
		require.Panics(func() {
			relayer.Stop()
		})
	})
}

// TestSubmitRequest tests request submission
func TestSubmitRequest(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	t.Run("valid request", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
		require.NoError(relayer.Start(context.Background()))
		defer relayer.Stop()

		req := &DecryptionRequest{
			RequestID:      common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			CiphertextHash: common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
			DecryptionType: 1,
			Requester:      common.HexToAddress("0x1234567890123456789012345678901234567890"),
			SourceChainID:  ids.GenerateTestID(),
		}

		err := relayer.SubmitRequest(context.Background(), req)
		require.NoError(err)

		// Verify request was added
		relayer.mu.RLock()
		_, exists := relayer.pendingRequests[req.RequestID]
		relayer.mu.RUnlock()
		require.True(exists)
	})

	t.Run("duplicate request", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
		require.NoError(relayer.Start(context.Background()))
		defer relayer.Stop()

		req := &DecryptionRequest{
			RequestID:      common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			CiphertextHash: common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
			DecryptionType: 1,
		}

		err := relayer.SubmitRequest(context.Background(), req)
		require.NoError(err)

		// Submit same request again
		err = relayer.SubmitRequest(context.Background(), req)
		require.Error(err)
		require.Contains(err.Error(), "already exists")
	})

	t.Run("request with callback", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
		require.NoError(relayer.Start(context.Background()))
		defer relayer.Stop()

		req := &DecryptionRequest{
			RequestID:        common.HexToHash("0x2234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			CiphertextHash:   common.HexToHash("0xbbcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
			DecryptionType:   2,
			HasCallback:      true,
			CallbackAddress:  common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12"),
			CallbackSelector: 0x12345678,
		}

		err := relayer.SubmitRequest(context.Background(), req)
		require.NoError(err)

		relayer.mu.RLock()
		storedReq := relayer.pendingRequests[req.RequestID]
		relayer.mu.RUnlock()

		require.True(storedReq.HasCallback)
		require.Equal(req.CallbackAddress, storedReq.CallbackAddress)
		require.Equal(req.CallbackSelector, storedReq.CallbackSelector)
	})

	t.Run("nil request", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
		require.NoError(relayer.Start(context.Background()))
		defer relayer.Stop()

		// This will panic due to nil pointer dereference
		require.Panics(func() {
			relayer.SubmitRequest(context.Background(), nil)
		})
	})

	t.Run("queue full", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
		// Don't start the relayer so requests aren't consumed

		// Fill the queue (capacity is 100)
		for i := 0; i < 100; i++ {
			req := &DecryptionRequest{
				RequestID: common.BigToHash(common.Big1.Add(common.Big1, common.Big1.SetUint64(uint64(i)))),
			}
			relayer.mu.Lock()
			select {
			case relayer.requestChan <- req:
			default:
			}
			relayer.mu.Unlock()
		}

		// Submit one more request - queue should be full
		req := &DecryptionRequest{
			RequestID: common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00"),
		}
		err := relayer.SubmitRequest(context.Background(), req)
		require.Error(err)
		require.Contains(err.Error(), "queue full")
	})
}

// TestGetResult tests result retrieval
func TestGetResult(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	t.Run("existing fulfilled result", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		reqID := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		expectedResult := []byte("decrypted data")

		relayer.mu.Lock()
		relayer.pendingRequests[reqID] = &DecryptionRequest{
			RequestID: reqID,
			Fulfilled: true,
			Result:    expectedResult,
		}
		relayer.mu.Unlock()

		result, fulfilled, err := relayer.GetResult(reqID)
		require.NoError(err)
		require.True(fulfilled)
		require.Equal(expectedResult, result)
	})

	t.Run("existing pending result", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		reqID := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

		relayer.mu.Lock()
		relayer.pendingRequests[reqID] = &DecryptionRequest{
			RequestID: reqID,
			Fulfilled: false,
		}
		relayer.mu.Unlock()

		result, fulfilled, err := relayer.GetResult(reqID)
		require.NoError(err)
		require.False(fulfilled)
		require.Nil(result)
	})

	t.Run("non-existent request", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		reqID := common.HexToHash("0xdead567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

		result, fulfilled, err := relayer.GetResult(reqID)
		require.ErrorIs(err, ErrRequestNotFound)
		require.False(fulfilled)
		require.Nil(result)
	})
}

// TestInMemoryCiphertextStorageOperations tests the in-memory ciphertext storage
func TestInMemoryCiphertextStorageOperations(t *testing.T) {
	require := require.New(t)

	t.Run("store and get", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		require.NotNil(storage)

		handle := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		data := []byte("ciphertext data here")

		err := storage.Put(handle, data)
		require.NoError(err)

		retrieved, err := storage.Get(handle)
		require.NoError(err)
		require.Equal(data, retrieved)
	})

	t.Run("get non-existent", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()

		handle := common.HexToHash("0xdead567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

		_, err := storage.Get(handle)
		require.ErrorIs(err, ErrCiphertextNotFound)
	})

	t.Run("delete existing", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()

		handle := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		data := []byte("ciphertext data")

		err := storage.Put(handle, data)
		require.NoError(err)

		err = storage.Delete(handle)
		require.NoError(err)

		_, err = storage.Get(handle)
		require.ErrorIs(err, ErrCiphertextNotFound)
	})

	t.Run("delete non-existent", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()

		handle := common.HexToHash("0xdead567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

		// Delete of non-existent should not error
		err := storage.Delete(handle)
		require.NoError(err)
	})

	t.Run("overwrite existing", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()

		handle := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		data1 := []byte("first data")
		data2 := []byte("second data - different")

		err := storage.Put(handle, data1)
		require.NoError(err)

		err = storage.Put(handle, data2)
		require.NoError(err)

		retrieved, err := storage.Get(handle)
		require.NoError(err)
		require.Equal(data2, retrieved)
	})

	t.Run("concurrent access", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()

		var wg sync.WaitGroup
		numGoroutines := 100

		// Concurrent writes
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				handle := common.BigToHash(new(big.Int).SetUint64(uint64(idx)))
				data := []byte{byte(idx)}
				storage.Put(handle, data)
			}(i)
		}
		wg.Wait()

		// Verify all writes
		for i := 0; i < numGoroutines; i++ {
			handle := common.BigToHash(new(big.Int).SetUint64(uint64(i)))
			data, err := storage.Get(handle)
			require.NoError(err)
			require.Equal([]byte{byte(i)}, data)
		}

		// Concurrent reads
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				handle := common.BigToHash(new(big.Int).SetUint64(uint64(idx)))
				_, _ = storage.Get(handle)
			}(i)
		}
		wg.Wait()
	})
}

// TestDoCleanup tests expired request cleanup
func TestDoCleanup(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	t.Run("cleanup expired requests", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
		relayer.requestTimeout = 100 * time.Millisecond

		// Add an old unfulfilled request
		reqID1 := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
		relayer.mu.Lock()
		relayer.pendingRequests[reqID1] = &DecryptionRequest{
			RequestID: reqID1,
			Timestamp: time.Now().Add(-200 * time.Millisecond), // Older than timeout
			Fulfilled: false,
		}
		relayer.mu.Unlock()

		// Add a recent unfulfilled request
		reqID2 := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
		relayer.mu.Lock()
		relayer.pendingRequests[reqID2] = &DecryptionRequest{
			RequestID: reqID2,
			Timestamp: time.Now(), // Recent
			Fulfilled: false,
		}
		relayer.mu.Unlock()

		// Run cleanup
		relayer.doCleanup()

		// Expired request should be removed
		relayer.mu.RLock()
		_, exists1 := relayer.pendingRequests[reqID1]
		_, exists2 := relayer.pendingRequests[reqID2]
		relayer.mu.RUnlock()

		require.False(exists1, "expired request should be removed")
		require.True(exists2, "recent request should remain")
	})

	t.Run("fulfilled requests not cleaned", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
		relayer.requestTimeout = 100 * time.Millisecond

		// Add an old but fulfilled request
		reqID := common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333")
		relayer.mu.Lock()
		relayer.pendingRequests[reqID] = &DecryptionRequest{
			RequestID: reqID,
			Timestamp: time.Now().Add(-200 * time.Millisecond), // Older than timeout
			Fulfilled: true,                                    // But fulfilled
		}
		relayer.mu.Unlock()

		// Run cleanup
		relayer.doCleanup()

		// Fulfilled request should remain
		relayer.mu.RLock()
		_, exists := relayer.pendingRequests[reqID]
		relayer.mu.RUnlock()

		require.True(exists, "fulfilled request should not be cleaned")
	})

	t.Run("no requests to cleanup", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		// Run cleanup on empty pending requests
		relayer.doCleanup()

		relayer.mu.RLock()
		count := len(relayer.pendingRequests)
		relayer.mu.RUnlock()

		require.Equal(0, count)
	})
}

// TestCleanupExpired tests the cleanupExpired goroutine
func TestCleanupExpired(t *testing.T) {
	logger := log.Noop()

	t.Run("cleanup stops on context cancel", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan struct{})
		go func() {
			relayer.cleanupExpired(ctx)
			close(done)
		}()

		cancel()

		select {
		case <-done:
			// Success
		case <-time.After(time.Second):
			t.Fatal("cleanupExpired did not stop on context cancel")
		}
	})

	t.Run("cleanup stops on shutdown", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		done := make(chan struct{})
		go func() {
			relayer.cleanupExpired(context.Background())
			close(done)
		}()

		close(relayer.shutdownChan)

		select {
		case <-done:
			// Success
		case <-time.After(time.Second):
			t.Fatal("cleanupExpired did not stop on shutdown")
		}
	})
}

// TestFetchCiphertext tests ciphertext fetching
func TestFetchCiphertext(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	t.Run("fetch existing ciphertext", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		handle := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		expectedData := []byte("encrypted data here")

		err := storage.Put(handle, expectedData)
		require.NoError(err)

		data, err := relayer.fetchCiphertext(context.Background(), handle)
		require.NoError(err)
		require.Equal(expectedData, data)
	})

	t.Run("fetch non-existent ciphertext", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		handle := common.HexToHash("0xdead567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

		_, err := relayer.fetchCiphertext(context.Background(), handle)
		require.Error(err)
	})

	t.Run("fetch with nil storage", func(t *testing.T) {
		relayer := NewRelayer(logger, nil, nil, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		handle := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

		_, err := relayer.fetchCiphertext(context.Background(), handle)
		require.Error(err)
		require.Contains(err.Error(), "not configured")
	})

	t.Run("fetch empty data", func(t *testing.T) {
		storage := NewInMemoryCiphertextStorage()
		relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)

		handle := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

		// Store empty data
		err := storage.Put(handle, []byte{})
		require.NoError(err)

		_, err = relayer.fetchCiphertext(context.Background(), handle)
		require.ErrorIs(err, ErrCiphertextNotFound)
	})
}

// TestEncodeFulfillmentCallABI tests ABI encoding for fulfillment
func TestEncodeFulfillmentCallABI(t *testing.T) {
	require := require.New(t)

	t.Run("encode standard result", func(t *testing.T) {
		requestID := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		result := []byte("decrypted plaintext")

		data := encodeFulfillmentCall(requestID, result)

		// Verify data is not empty
		require.NotEmpty(data)

		// Verify selector (first 4 bytes)
		require.Equal([]byte{0x8a, 0x6d, 0x3a, 0xf9}, data[0:4])

		// Verify requestID (bytes 4-36)
		require.Equal(requestID.Bytes(), data[4:36])

		// Verify minimum length for encoded data
		require.GreaterOrEqual(len(data), 36+32) // selector + requestID + at least offset
	})

	t.Run("encode empty result", func(t *testing.T) {
		requestID := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		result := []byte{}

		data := encodeFulfillmentCall(requestID, result)

		// Should still have valid structure
		require.NotEmpty(data)
		// Verify selector
		require.Equal([]byte{0x8a, 0x6d, 0x3a, 0xf9}, data[0:4])
	})

	t.Run("encode large result", func(t *testing.T) {
		requestID := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		result := make([]byte, 1000) // Large result
		for i := range result {
			result[i] = byte(i % 256)
		}

		data := encodeFulfillmentCall(requestID, result)

		// Verify has minimum structure
		require.NotEmpty(data)
		require.GreaterOrEqual(len(data), 4+32+len(result)) // at least selector + requestID + result
	})
}

// TestEncodeComplexValues tests complex value encoding
func TestEncodeComplexValues(t *testing.T) {
	require := require.New(t)

	t.Run("encode basic values", func(t *testing.T) {
		values := []complex128{
			complex(1.0, 0.0),
			complex(2.5, 0.0),
			complex(0.0, 3.0),
		}

		result := encodeComplexValues(values)
		require.Equal(len(values)*16, len(result))
	})

	t.Run("encode empty values", func(t *testing.T) {
		values := []complex128{}

		result := encodeComplexValues(values)
		require.Equal(0, len(result))
	})

	t.Run("encode single value", func(t *testing.T) {
		values := []complex128{complex(42.0, 17.0)}

		result := encodeComplexValues(values)
		require.Equal(16, len(result))
	})
}

// TestDecryptionRequestStruct tests DecryptionRequest struct fields
func TestDecryptionRequestStruct(t *testing.T) {
	require := require.New(t)

	req := &DecryptionRequest{
		RequestID:        common.HexToHash("0x1234"),
		CiphertextHash:   common.HexToHash("0xabcd"),
		DecryptionType:   1,
		Requester:        common.HexToAddress("0x1234567890123456789012345678901234567890"),
		SourceChainID:    ids.GenerateTestID(),
		CallbackAddress:  common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12"),
		CallbackSelector: 0x12345678,
		HasCallback:      true,
		Timestamp:        time.Now(),
		Fulfilled:        false,
		Result:           nil,
	}

	require.NotEqual(common.Hash{}, req.RequestID)
	require.NotEqual(common.Hash{}, req.CiphertextHash)
	require.Equal(uint8(1), req.DecryptionType)
	require.True(req.HasCallback)
	require.False(req.Fulfilled)
}

// TestDecryptionResultStruct tests DecryptionResult struct fields
func TestDecryptionResultStruct(t *testing.T) {
	require := require.New(t)

	t.Run("successful result", func(t *testing.T) {
		result := &DecryptionResult{
			RequestID: common.HexToHash("0x1234"),
			Plaintext: []byte("decrypted data"),
			Error:     nil,
		}

		require.NotNil(result.Plaintext)
		require.Nil(result.Error)
	})

	t.Run("error result", func(t *testing.T) {
		result := &DecryptionResult{
			RequestID: common.HexToHash("0x1234"),
			Plaintext: nil,
			Error:     ErrDecryptionFailed,
		}

		require.Nil(result.Plaintext)
		require.ErrorIs(result.Error, ErrDecryptionFailed)
	})
}

// TestRelayerConcurrentAccess tests concurrent access patterns
func TestRelayerConcurrentAccess(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	storage := NewInMemoryCiphertextStorage()
	relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
	require.NoError(relayer.Start(context.Background()))
	defer relayer.Stop()

	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent request submissions
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Use new big.Int to avoid race on shared common.Big1
			req := &DecryptionRequest{
				RequestID: common.BigToHash(new(big.Int).SetUint64(uint64(idx))),
			}
			relayer.SubmitRequest(context.Background(), req)
		}(i)
	}

	// Concurrent result queries
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Use new big.Int to avoid race on shared common.Big1
			reqID := common.BigToHash(new(big.Int).SetUint64(uint64(idx)))
			relayer.GetResult(reqID)
		}(i)
	}

	wg.Wait()
}

// TestErrorConstants tests error constant values
func TestErrorConstants(t *testing.T) {
	require := require.New(t)

	require.NotNil(ErrDecryptionFailed)
	require.NotNil(ErrInsufficientShares)
	require.NotNil(ErrRequestNotFound)
	require.NotNil(ErrRequestExpired)
	require.NotNil(ErrAlreadyFulfilled)
	require.NotNil(ErrCiphertextNotFound)

	// Verify they are distinct
	require.NotEqual(ErrDecryptionFailed, ErrInsufficientShares)
	require.NotEqual(ErrRequestNotFound, ErrRequestExpired)
	require.NotEqual(ErrAlreadyFulfilled, ErrCiphertextNotFound)
}

// TestCiphertextStorageInterface verifies InMemoryCiphertextStorage implements CiphertextStorage
func TestCiphertextStorageInterface(t *testing.T) {
	require := require.New(t)

	var _ CiphertextStorage = (*InMemoryCiphertextStorage)(nil)

	storage := NewInMemoryCiphertextStorage()
	var iface CiphertextStorage = storage
	require.NotNil(iface)
}

// TestRelayerNetworkIDAndChainIDs tests network and chain ID handling
func TestRelayerNetworkIDAndChainIDs(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	storage := NewInMemoryCiphertextStorage()
	networkID := uint32(12345)
	chainID := ids.GenerateTestID()
	zChainID := ids.GenerateTestID()

	relayer := NewRelayer(logger, nil, storage, networkID, chainID, zChainID, nil, nil)

	require.Equal(networkID, relayer.networkID)
	require.Equal(chainID, relayer.chainID)
	require.Equal(zChainID, relayer.zChainID)
}

// ---------------------------------------------------------------------------
// Threshold decryptor: what the quorum actually gates
// ---------------------------------------------------------------------------

// testParams is the CKKS parameter set every decryptor test shares, so a share
// produced in one test body deserializes in another.
func testParams(t testing.TB) ckks.Parameters {
	t.Helper()
	p, err := ckks.NewParametersFromLiteral(ckks.ExampleParameters128BitLogN14LogQP438)
	require.NoError(t, err)
	return p
}

// encrypt returns a ciphertext holding values and the secret key that opens it.
func encrypt(t testing.TB, p ckks.Parameters, values []complex128) ([]byte, *rlwe.SecretKey) {
	t.Helper()
	kgen := rlwe.NewKeyGenerator(p.Parameters)
	sk := kgen.GenSecretKeyNew()

	slots := make([]complex128, p.MaxSlots())
	copy(slots, values)
	pt := ckks.NewPlaintext(p, p.MaxLevel())
	require.NoError(t, ckks.NewEncoder(p).Encode(slots, pt))

	ct, err := ckks.NewEncryptor(p, kgen.GenPublicKeyNew(sk)).EncryptNew(pt)
	require.NoError(t, err)
	b, err := ct.MarshalBinary()
	require.NoError(t, err)
	return b, sk
}

// oneShare runs a single-party decryptor far enough to emit one well-formed
// E2S share for ciphertext ct, and returns those bytes.
func oneShare(t testing.TB, p ckks.Parameters, ct []byte, sk *rlwe.SecretKey) []byte {
	t.Helper()
	var out []byte
	d, err := NewThresholdDecryptor(log.Noop(), p, 1, 1, 0, 128, func(_ string, s []byte) error {
		out = append([]byte(nil), s...)
		return nil
	})
	require.NoError(t, err)
	d.SetSecretKey(sk)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = d.Decrypt(ctx, "emit", ct)
	require.NoError(t, err)
	require.NotEmpty(t, out)
	return out
}

// TestNewThresholdDecryptorRejectsNonQuorum holds the property that a t-of-n
// decryptor is refused whenever t is not a quorum over n. Every completion test
// in both decryption paths is `shares >= threshold`, so an unchecked threshold
// is the whole access control: t=0 finalizes on the first share to arrive and
// t=1 over a hundred parties lets any single one of them decrypt alone, which
// is the one thing a threshold scheme exists to prevent. t>n can never be met,
// so requests hang until they expire rather than failing at configuration time.
func TestNewThresholdDecryptorRejectsNonQuorum(t *testing.T) {
	p := testParams(t)
	for _, bad := range []struct{ threshold, total int }{
		{0, 100}, {1, 100}, {101, 100}, {67, 0}, {0, 0}, {-5, -5}, {2, 1},
	} {
		d, err := NewThresholdDecryptor(log.Noop(), p, bad.threshold, bad.total, 0, 128, nil)
		require.ErrorIs(t, err, ErrInvalidThreshold, "%d of %d", bad.threshold, bad.total)
		require.Nil(t, d)
	}

	// A lone party is the degenerate case: there is no quorum to break.
	d, err := NewThresholdDecryptor(log.Noop(), p, 1, 1, 0, 128, nil)
	require.NoError(t, err)
	require.NotNil(t, d)

	// And the smallest real quorum, plus the configured default.
	for _, ok := range []struct{ threshold, total int }{{2, 2}, {2, 3}, {67, 100}} {
		d, err := NewThresholdDecryptor(log.Noop(), p, ok.threshold, ok.total, 0, 128, nil)
		require.NoError(t, err, "%d of %d", ok.threshold, ok.total)
		require.NotNil(t, d)
	}
}

// TestNewThresholdFHEIntegrationRejectsNonQuorum holds the same property on the
// other decryption path. ContributeShare completes on
// ShareCount >= config.Threshold, so a ThresholdConfig with Threshold 0 is the
// same total break as a decryptor with threshold 0, reached through a different
// constructor.
func TestNewThresholdFHEIntegrationRejectsNonQuorum(t *testing.T) {
	p := testParams(t)
	for _, bad := range []struct{ threshold, total int }{{0, 100}, {1, 100}, {101, 100}, {5, 0}} {
		i, err := NewThresholdFHEIntegration(log.Noop(), ThresholdConfig{
			Threshold: bad.threshold, TotalParties: bad.total, CKKSParams: p, LogBound: 128,
		}, 0)
		require.ErrorIs(t, err, ErrInvalidThreshold, "%d of %d", bad.threshold, bad.total)
		require.Nil(t, i)
	}
}

// TestNewThresholdDecryptorRejectsUnusableParameters holds that a parameter set
// the E2S protocol cannot be built over is refused at construction rather than
// at the first decryption, when a request is already in flight.
func TestNewThresholdDecryptorRejectsUnusableParameters(t *testing.T) {
	d, err := NewThresholdDecryptor(log.Noop(), ckks.Parameters{}, 1, 1, 0, 128, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "E2S protocol")
	require.Nil(t, d)
}

// TestAddShareCountsPartiesNotSubmissions holds that a party's second share is
// ignored. Counting submissions instead of parties would let one validator
// reach any threshold by resubmitting, which is the cheapest possible attack on
// a t-of-n scheme: no key material, no peers, one message repeated.
//
// The decryptor is 3-of-5 and the same party id submits three times from inside
// the broadcast callback, before Decrypt adds its own share. Two distinct
// parties are seen, so the session stops at two and the context deadline is
// what ends the wait.
func TestAddShareCountsPartiesNotSubmissions(t *testing.T) {
	p := testParams(t)
	ct, sk := encrypt(t, p, []complex128{complex(42, 0)})
	foreign := oneShare(t, p, ct, sk)

	var d *ThresholdDecryptor
	d, err := NewThresholdDecryptor(log.Noop(), p, 3, 5, 0, 128, func(sessionID string, _ []byte) error {
		for i := 0; i < 3; i++ {
			require.NoError(t, d.AddShare(sessionID, 4, foreign))
		}
		return nil
	})
	require.NoError(t, err)
	d.SetSecretKey(sk)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = d.Decrypt(ctx, "repeat", ct)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	d.sessionsMu.RLock()
	session := d.sessions["repeat"]
	d.sessionsMu.RUnlock()
	require.Equal(t, 2, session.shareCount, "one party submitting three times must count once")
	require.False(t, session.complete)
}

// TestContributeShareCountsNodesNotSubmissions is the same property on the
// integration path, which dedupes on NodeID instead of an int party id.
//
// The two paths disagree on what a repeat submission means: AddShare returns
// nil, ContributeShare returns an error. Both refuse to count it, which is the
// property that matters; the divergence is in the report, not in the fix.
func TestContributeShareCountsNodesNotSubmissions(t *testing.T) {
	p := testParams(t)
	integration, err := NewThresholdFHEIntegration(log.Noop(), ThresholdConfig{
		Threshold: 3, TotalParties: 5, CKKSParams: p, LogBound: 128,
	}, 0)
	require.NoError(t, err)

	ct, sk := encrypt(t, p, []complex128{complex(42, 0)})
	integration.SetSecretKey(sk)
	require.NoError(t, integration.InitiateDecryption("s", common.HexToHash("0x1"), ct))

	share, err := integration.GenerateShare("s")
	require.NoError(t, err)

	node := ids.GenerateTestNodeID()
	complete, err := integration.ContributeShare("s", node, share)
	require.NoError(t, err)
	require.False(t, complete)

	for i := 0; i < 3; i++ {
		complete, err = integration.ContributeShare("s", node, share)
		require.Error(t, err, "a repeat submission must not be counted")
		require.False(t, complete)
	}

	integration.sessionsMu.RLock()
	count := integration.sessions["s"].ShareCount
	integration.sessionsMu.RUnlock()
	require.Equal(t, 1, count)
}

// TestAddShareAcceptsForeignSharesUnderInventedPartyIDs is the finding this
// package most needs on record: shares are counted, never verified.
//
// AddShare (relayer.go:556) deserializes the bytes and nothing else. It does
// not check that the share was produced by the claimed party, that the claimed
// party is in the committee, or that the share was produced for this session's
// ciphertext -- and partyID is an int the caller chooses. So one share, made by
// an unrelated key for an unrelated ciphertext, replayed under two party ids
// that generated nothing, carries a 3-of-5 session to completion.
//
// Deleting the deserialization check would not fail this test. Only adding a
// real check would, which is the point.
func TestAddShareAcceptsForeignSharesUnderInventedPartyIDs(t *testing.T) {
	p := testParams(t)

	// A share for a completely unrelated ciphertext under an unrelated key.
	other, otherKey := encrypt(t, p, []complex128{complex(1, 0)})
	foreign := oneShare(t, p, other, otherKey)

	// The session under attack decrypts a different ciphertext.
	target, targetKey := encrypt(t, p, []complex128{complex(42, 0)})

	var d *ThresholdDecryptor
	d, err := NewThresholdDecryptor(log.Noop(), p, 3, 5, 0, 128, func(sessionID string, _ []byte) error {
		require.NoError(t, d.AddShare(sessionID, 7, foreign))
		require.NoError(t, d.AddShare(sessionID, 8, foreign))
		return nil
	})
	require.NoError(t, err)
	d.SetSecretKey(targetKey)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := d.Decrypt(ctx, "victim", target)
	require.NoError(t, err, "the session finalized on two forged shares and one real one")
	require.NotEmpty(t, result)

	d.sessionsMu.RLock()
	session := d.sessions["victim"]
	d.sessionsMu.RUnlock()
	require.True(t, session.complete)
	require.Equal(t, 3, session.shareCount)
}

// TestContributeShareAcceptsForeignShares is the same absence of verification on
// the integration path (integration.go:231): a share generated for one session
// is accepted into another, for a different ciphertext, from a node id that
// generated nothing.
func TestContributeShareAcceptsForeignShares(t *testing.T) {
	p := testParams(t)
	integration, err := NewThresholdFHEIntegration(log.Noop(), ThresholdConfig{
		Threshold: 2, TotalParties: 5, CKKSParams: p, LogBound: 128,
	}, 0)
	require.NoError(t, err)

	first, key := encrypt(t, p, []complex128{complex(1, 0)})
	second, _ := encrypt(t, p, []complex128{complex(42, 0)})
	integration.SetSecretKey(key)

	require.NoError(t, integration.InitiateDecryption("first", common.HexToHash("0x1"), first))
	require.NoError(t, integration.InitiateDecryption("second", common.HexToHash("0x2"), second))

	// A share made for session "first" and its ciphertext.
	foreign, err := integration.GenerateShare("first")
	require.NoError(t, err)

	// Session "second" needs its own share for OwnSecretShare, then accepts the
	// foreign one from a node that contributed nothing to it.
	own, err := integration.GenerateShare("second")
	require.NoError(t, err)
	complete, err := integration.ContributeShare("second", ids.GenerateTestNodeID(), own)
	require.NoError(t, err)
	require.False(t, complete)

	complete, err = integration.ContributeShare("second", ids.GenerateTestNodeID(), foreign)
	require.NoError(t, err, "a share bound to no session is accepted by any session")
	require.True(t, complete)
}

// TestDecryptReturnsCoefficientShareNotPlaintext records what the threshold
// decryptor actually hands back today, so the gap is visible rather than
// assumed away.
//
// relayer.go:607 recovers a coefficient-domain additive share and
// relayer.go:610-624 reads its entries as if they were CKKS slot values;
// ckks.Encoder.Decode is never called, and the other parties' additive shares
// are never collected, so no reconstruction sum is ever formed. Encrypt the
// ramp slot[i] = i over 8192 slots and the first entry comes back 4095.5 -- the
// mean of 0..8191, which is coefficient 0 of the encoding. Slot 0 holds 0.
// Two runs over the identical ciphertext and key also disagree, because the
// value carries fresh smudging noise rather than a decrypted message.
//
// integration.go:280-297 is the same code on the other path. This test fails as
// soon as either the decode or the cross-party sum lands, which is intended.
func TestDecryptReturnsCoefficientShareNotPlaintext(t *testing.T) {
	p := testParams(t)
	ramp := make([]complex128, p.MaxSlots())
	for i := range ramp {
		ramp[i] = complex(float64(i), 0)
	}
	ct, sk := encrypt(t, p, ramp)

	run := func() []float64 {
		d, err := NewThresholdDecryptor(log.Noop(), p, 1, 1, 0, 128, nil)
		require.NoError(t, err)
		d.SetSecretKey(sk)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := d.Decrypt(ctx, "ramp", ct)
		require.NoError(t, err)
		require.Len(t, out, 8*16)
		values := make([]float64, len(out)/16)
		for i := range values {
			values[i] = math.Float64frombits(binary.LittleEndian.Uint64(out[i*16 : i*16+8]))
		}
		return values
	}

	first := run()
	require.InDelta(t, 4095.5, first[0], 0.5, "entry 0 is the encoding's coefficient 0, the mean of the ramp")
	require.Greater(t, math.Abs(first[0]-real(ramp[0])), 1.0, "entry 0 is not slot 0")

	require.NotEqual(t, first, run(), "a decryption is a function of the ciphertext and the key")
}

// TestDecryptRequiresSecretKey holds that a decryptor with no key share refuses
// rather than registering a session that can never produce a share.
func TestDecryptRequiresSecretKey(t *testing.T) {
	p := testParams(t)
	d, err := NewThresholdDecryptor(log.Noop(), p, 2, 3, 0, 128, nil)
	require.NoError(t, err)

	ct, _ := encrypt(t, p, []complex128{complex(1, 0)})
	_, err = d.Decrypt(context.Background(), "s", ct)
	require.Error(t, err)
	require.Contains(t, err.Error(), "secret key")

	d.sessionsMu.RLock()
	_, exists := d.sessions["s"]
	d.sessionsMu.RUnlock()
	require.False(t, exists, "a refused request must not leave a session behind")
}

// malformed is the set of byte strings a peer can put where a ciphertext
// belongs. The last two matter most: rlwe's decoder reads element and vector
// lengths straight out of the input and hands them to make(), so a crafted
// sixteen bytes reaches "makeslice: len out of range" -- a panic, on the
// goroutine that services cross-chain decryption requests, with nothing above
// it to recover. Both entry points must return an error for every one of these.
var malformed = [][]byte{
	nil,
	{},
	[]byte("invalid"),
	[]byte("not a ciphertext"),
	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
}

// TestDecryptRejectsMalformedCiphertext holds that bytes that are not a
// ciphertext are refused -- not survived, refused -- before a session exists,
// so a malformed cross-chain request neither ends the process nor parks a
// session in the map until it restarts.
func TestDecryptRejectsMalformedCiphertext(t *testing.T) {
	p := testParams(t)
	d, err := NewThresholdDecryptor(log.Noop(), p, 2, 3, 0, 128, nil)
	require.NoError(t, err)
	d.SetSecretKey(rlwe.NewKeyGenerator(p.Parameters).GenSecretKeyNew())

	for i, bad := range malformed {
		_, err = d.Decrypt(context.Background(), "s", bad)
		require.ErrorContains(t, err, "unmarshal ciphertext", "input %d", i)

		d.sessionsMu.RLock()
		_, exists := d.sessions["s"]
		d.sessionsMu.RUnlock()
		require.False(t, exists, "input %d", i)
	}
}

// TestInitiateDecryptionRejectsMalformedCiphertext holds the same refusal on
// the integration path, which deserializes the same untrusted bytes.
func TestInitiateDecryptionRejectsMalformedCiphertext(t *testing.T) {
	p := testParams(t)
	integration, err := NewThresholdFHEIntegration(log.Noop(), ThresholdConfig{
		Threshold: 2, TotalParties: 3, CKKSParams: p, LogBound: 128,
	}, 0)
	require.NoError(t, err)

	for i, bad := range malformed {
		require.ErrorContains(t,
			integration.InitiateDecryption("s", common.HexToHash("0x1"), bad),
			"unmarshal ciphertext", "input %d", i)

		integration.sessionsMu.RLock()
		_, exists := integration.sessions["s"]
		integration.sessionsMu.RUnlock()
		require.False(t, exists, "input %d", i)
	}
}

// TestDecryptSurvivesBroadcastFailure holds that a validator whose gossip fails
// still participates locally. Returning the broadcast error instead would mean
// a single unreachable peer aborts this node's contribution to every session.
func TestDecryptSurvivesBroadcastFailure(t *testing.T) {
	p := testParams(t)
	ct, sk := encrypt(t, p, []complex128{complex(7, 0)})

	d, err := NewThresholdDecryptor(log.Noop(), p, 1, 1, 0, 128, func(string, []byte) error {
		return errors.New("no peers reachable")
	})
	require.NoError(t, err)
	d.SetSecretKey(sk)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := d.Decrypt(ctx, "s", ct)
	require.NoError(t, err)
	require.NotEmpty(t, out)
}

// TestDecryptGivesUpWithoutQuorum holds that a session that never reaches its
// threshold ends in ErrInsufficientShares rather than blocking a relayer
// goroutine forever. The wait is the decryptor's own 30 second bound, so this
// test costs that long and is the only place that bound is observed.
func TestDecryptGivesUpWithoutQuorum(t *testing.T) {
	t.Parallel()

	p := testParams(t)
	ct, sk := encrypt(t, p, []complex128{complex(7, 0)})
	d, err := NewThresholdDecryptor(log.Noop(), p, 2, 3, 0, 128, nil)
	require.NoError(t, err)
	d.SetSecretKey(sk)

	start := time.Now()
	_, err = d.Decrypt(context.Background(), "lonely", ct)
	require.ErrorIs(t, err, ErrInsufficientShares)
	require.Greater(t, time.Since(start), 29*time.Second)
}

// TestAddShareRejectsUnknownSessionAndMalformedShare holds the two refusals
// AddShare owes its caller: a share for a session this node never opened, and
// bytes that are not a share at all.
func TestAddShareRejectsUnknownSessionAndMalformedShare(t *testing.T) {
	p := testParams(t)
	ct, sk := encrypt(t, p, []complex128{complex(7, 0)})

	var d *ThresholdDecryptor
	d, err := NewThresholdDecryptor(log.Noop(), p, 3, 5, 0, 128, func(sessionID string, _ []byte) error {
		require.ErrorContains(t, d.AddShare(sessionID, 2, []byte("junk")), "unmarshal share")
		return nil
	})
	require.NoError(t, err)
	d.SetSecretKey(sk)

	require.ErrorContains(t, d.AddShare("never-opened", 1, []byte{}), "not found")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = d.Decrypt(ctx, "s", ct)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	d.sessionsMu.RLock()
	count := d.sessions["s"].shareCount
	d.sessionsMu.RUnlock()
	require.Equal(t, 1, count, "the malformed share must not be counted")
}

// TestAddShareIgnoresSharesAfterCompletion holds that a share arriving late --
// after the quorum already closed the session -- is dropped rather than
// re-running the aggregation over a result that has already been reported.
func TestAddShareIgnoresSharesAfterCompletion(t *testing.T) {
	p := testParams(t)
	ct, sk := encrypt(t, p, []complex128{complex(7, 0)})
	late := oneShare(t, p, ct, sk)

	d, err := NewThresholdDecryptor(log.Noop(), p, 1, 1, 0, 128, nil)
	require.NoError(t, err)
	d.SetSecretKey(sk)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	first, err := d.Decrypt(ctx, "s", ct)
	require.NoError(t, err)

	require.NoError(t, d.AddShare("s", 99, late))

	d.sessionsMu.RLock()
	session := d.sessions["s"]
	d.sessionsMu.RUnlock()
	require.Equal(t, 1, session.shareCount)
	require.Equal(t, first, session.result, "a completed session's result must not move")
}

// ---------------------------------------------------------------------------
// Relayer: request in, fulfillment out
// ---------------------------------------------------------------------------

// singleParty is a decryptor that finishes on its own share, so a relayer test
// observes the request pipeline rather than a quorum forming.
func singleParty(t testing.TB, p ckks.Parameters, sk *rlwe.SecretKey) *ThresholdDecryptor {
	t.Helper()
	d, err := NewThresholdDecryptor(log.Noop(), p, 1, 1, 0, 128, nil)
	require.NoError(t, err)
	d.SetSecretKey(sk)
	return d
}

// TestRelayerFulfillsRequestOverWarp holds the whole C-Chain round trip: a
// submitted request is decrypted, recorded as fulfilled, and answered with one
// signed Warp envelope carrying the fulfillDecryption call for that request id.
// Each half is load-bearing -- a result recorded but never sent leaves the
// calling contract waiting forever, and an envelope sent for the wrong request
// id fulfills the wrong caller.
func TestRelayerFulfillsRequestOverWarp(t *testing.T) {
	p := testParams(t)
	ct, sk := encrypt(t, p, []complex128{complex(42, 0)})

	handle := common.HexToHash("0x0badc0de")
	storage := NewInMemoryCiphertextStorage()
	require.NoError(t, storage.Put(handle, ct))

	sent := make(chan *warp.Envelope, 1)
	r := NewRelayer(log.Noop(), singleParty(t, p, sk), storage, 1,
		ids.GenerateTestID(), ids.GenerateTestID(), &mockSigner{},
		func(_ context.Context, env *warp.Envelope) error {
			sent <- env
			return nil
		})
	require.NoError(t, r.Start(context.Background()))
	defer r.Stop()

	requestID := common.HexToHash("0xfeed")
	require.NoError(t, r.SubmitRequest(context.Background(), &DecryptionRequest{
		RequestID:      requestID,
		CiphertextHash: handle,
		SourceChainID:  ids.GenerateTestID(),
	}))

	select {
	case env := <-sent:
		require.NotNil(t, env)
		// The addressed call wraps the ABI call; the request id is at a fixed
		// offset from the selector inside it.
		require.Contains(t, string(env.Message.Payload), string(requestID.Bytes()))
	case <-time.After(30 * time.Second):
		t.Fatal("no fulfillment was sent")
	}

	result, fulfilled, err := r.GetResult(requestID)
	require.NoError(t, err)
	require.True(t, fulfilled)
	require.NotEmpty(t, result)
}

// TestRelayerLeavesFailedRequestPending holds that a request whose ciphertext
// cannot be fetched stays pending and unfulfilled. Marking it fulfilled with an
// empty result would answer the calling contract with a plaintext of nothing.
func TestRelayerLeavesFailedRequestPending(t *testing.T) {
	p := testParams(t)
	_, sk := encrypt(t, p, []complex128{complex(42, 0)})

	r := NewRelayer(log.Noop(), singleParty(t, p, sk), NewInMemoryCiphertextStorage(), 1,
		ids.GenerateTestID(), ids.GenerateTestID(), &mockSigner{},
		func(context.Context, *warp.Envelope) error {
			t.Error("a failed decryption must not send a fulfillment")
			return nil
		})
	require.NoError(t, r.Start(context.Background()))
	defer r.Stop()

	requestID := common.HexToHash("0xdead")
	require.NoError(t, r.SubmitRequest(context.Background(), &DecryptionRequest{
		RequestID:      requestID,
		CiphertextHash: common.HexToHash("0xnothinghere"),
	}))

	require.Eventually(t, func() bool {
		_, fulfilled, err := r.GetResult(requestID)
		return err == nil && !fulfilled
	}, 5*time.Second, 10*time.Millisecond)

	// Still pending after the pipeline has certainly drained.
	time.Sleep(100 * time.Millisecond)
	_, fulfilled, err := r.GetResult(requestID)
	require.NoError(t, err)
	require.False(t, fulfilled)
}

// TestRelayerReportsUndecryptableCiphertext holds that stored bytes that are
// not a ciphertext leave the request pending instead of ending the results
// goroutine. The bytes come from storage, which is written by peers.
func TestRelayerReportsUndecryptableCiphertext(t *testing.T) {
	p := testParams(t)
	_, sk := encrypt(t, p, []complex128{complex(42, 0)})

	handle := common.HexToHash("0x1")
	storage := NewInMemoryCiphertextStorage()
	require.NoError(t, storage.Put(handle, []byte("not a ciphertext")))

	r := NewRelayer(log.Noop(), singleParty(t, p, sk), storage, 1,
		ids.GenerateTestID(), ids.GenerateTestID(), &mockSigner{}, nil)
	require.NoError(t, r.Start(context.Background()))
	defer r.Stop()

	requestID := common.HexToHash("0xbeef")
	require.NoError(t, r.SubmitRequest(context.Background(), &DecryptionRequest{
		RequestID:      requestID,
		CiphertextHash: handle,
	}))

	time.Sleep(200 * time.Millisecond)
	_, fulfilled, err := r.GetResult(requestID)
	require.NoError(t, err)
	require.False(t, fulfilled)
}

// TestHandleResultDropsResultsWithNoLiveRequest holds the two cases where a
// result has nowhere to go: no such request, and a request already answered.
// Sending a second fulfillment for a request the gateway has already settled is
// a replay, so the second one has to be dropped here.
func TestHandleResultDropsResultsWithNoLiveRequest(t *testing.T) {
	sends := 0
	r := NewRelayer(log.Noop(), nil, NewInMemoryCiphertextStorage(), 1,
		ids.GenerateTestID(), ids.GenerateTestID(), &mockSigner{},
		func(context.Context, *warp.Envelope) error {
			sends++
			return nil
		})

	// Unknown request.
	r.handleResult(context.Background(), &DecryptionResult{
		RequestID: common.HexToHash("0x1"),
		Plaintext: []byte("x"),
	})

	// Already fulfilled.
	known := common.HexToHash("0x2")
	r.mu.Lock()
	r.pendingRequests[known] = &DecryptionRequest{RequestID: known, Fulfilled: true, Result: []byte("first")}
	r.mu.Unlock()
	r.handleResult(context.Background(), &DecryptionResult{RequestID: known, Plaintext: []byte("second")})

	result, fulfilled, err := r.GetResult(known)
	require.NoError(t, err)
	require.True(t, fulfilled)
	require.Equal(t, []byte("first"), result, "an answered request keeps its first result")
	require.Zero(t, sends)
}

// TestSendFulfillmentSurfacesSigningAndTransportFailures holds that a
// fulfillment that could not be signed or could not be handed to the network is
// reported as an error. Swallowing either makes a lost cross-chain answer look
// like a delivered one.
func TestSendFulfillmentSurfacesSigningAndTransportFailures(t *testing.T) {
	req := &DecryptionRequest{RequestID: common.HexToHash("0x1"), Result: []byte("plaintext")}

	newRelayer := func(signer warp.Signer, onMessage func(context.Context, *warp.Envelope) error) *Relayer {
		return NewRelayer(log.Noop(), nil, NewInMemoryCiphertextStorage(), 1,
			ids.GenerateTestID(), ids.GenerateTestID(), signer, onMessage)
	}

	failing := &mockSigner{signFunc: func(*warp.Message) ([]byte, error) {
		return nil, errors.New("bls key unavailable")
	}}
	require.ErrorContains(t,
		newRelayer(failing, nil).sendFulfillment(context.Background(), req),
		"build signed warp message")

	short := &mockSigner{signFunc: func(*warp.Message) ([]byte, error) { return []byte{1, 2, 3}, nil }}
	require.ErrorContains(t,
		newRelayer(short, nil).sendFulfillment(context.Background(), req),
		"build signed warp message")

	require.ErrorContains(t,
		newRelayer(&mockSigner{}, func(context.Context, *warp.Envelope) error {
			return errors.New("peer unreachable")
		}).sendFulfillment(context.Background(), req),
		"send warp message")

	// No transport configured is not a failure: the envelope is built and the
	// node simply has nowhere to hand it.
	require.NoError(t, newRelayer(&mockSigner{}, nil).sendFulfillment(context.Background(), req))
}

// TestFulfillmentCallEncodesAsSolidityBytes holds the ABI layout of
// fulfillDecryption(bytes32,bytes). The three words after the selector are the
// request id, the offset to the byte array, and its length; a wrong offset or
// length makes the gateway read a different span of the call data and settle
// the request with whatever it finds there.
func TestFulfillmentCallEncodesAsSolidityBytes(t *testing.T) {
	requestID := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

	for _, result := range [][]byte{{}, []byte("plaintext"), make([]byte, 64), make([]byte, 65)} {
		data := encodeFulfillmentCall(requestID, result)

		padded := ((len(result) + 31) / 32) * 32
		require.Len(t, data, 4+32+32+32+padded)
		require.Equal(t, []byte{0x8a, 0x6d, 0x3a, 0xf9}, data[0:4])
		require.Equal(t, requestID.Bytes(), data[4:36])

		// Head word 2 is the offset from the start of the arguments to the
		// length word, which is exactly two words in.
		require.Equal(t, uint64(64), binary.BigEndian.Uint64(data[60:68]))
		require.Zero(t, binary.BigEndian.Uint64(data[36:44]), "the offset word's high half must be zero")

		require.Equal(t, uint64(len(result)), binary.BigEndian.Uint64(data[92:100]))
		require.Equal(t, result, data[100:100+len(result)])
	}
}

// TestDecryptRefusesAnOversizedMask holds that a decryptor configured with a
// mask wider than the ciphertext's modulus fails the request rather than
// emitting a share the other parties cannot combine.
func TestDecryptRefusesAnOversizedMask(t *testing.T) {
	p := testParams(t)
	ct, sk := encrypt(t, p, []complex128{complex(1, 0)})

	d, err := NewThresholdDecryptor(log.Noop(), p, 2, 3, 0, 100_000, nil)
	require.NoError(t, err)
	d.SetSecretKey(sk)

	_, err = d.Decrypt(context.Background(), "s", ct)
	require.ErrorContains(t, err, "generate share")
}

// TestFulfillmentFailureLeavesTheResultRecorded holds that a fulfillment the
// node could not send does not undo the decryption. The result stays readable
// through GetResult, which is what an operator retries from; discarding it
// would mean re-running the whole quorum to answer the same request.
func TestFulfillmentFailureLeavesTheResultRecorded(t *testing.T) {
	failing := &mockSigner{signFunc: func(*warp.Message) ([]byte, error) {
		return nil, errors.New("bls key unavailable")
	}}
	r := NewRelayer(log.Noop(), nil, NewInMemoryCiphertextStorage(), 1,
		ids.GenerateTestID(), ids.GenerateTestID(), failing, nil)

	requestID := common.HexToHash("0x1")
	r.mu.Lock()
	r.pendingRequests[requestID] = &DecryptionRequest{RequestID: requestID}
	r.mu.Unlock()

	r.handleResult(context.Background(), &DecryptionResult{
		RequestID: requestID,
		Plaintext: []byte("plaintext"),
	})

	result, fulfilled, err := r.GetResult(requestID)
	require.NoError(t, err)
	require.True(t, fulfilled)
	require.Equal(t, []byte("plaintext"), result)
}

// TestExpiredRequestsAreSweptOnTheTimer holds that the relayer's periodic sweep
// actually runs, not just that doCleanup works when called by hand: an unanswered
// request that is never swept holds its slot in pendingRequests for the life of
// the process, and the queue behind it is bounded at 100. The sweep interval is
// a fixed minute inside cleanupExpired, so this test waits one.
func TestExpiredRequestsAreSweptOnTheTimer(t *testing.T) {
	t.Parallel()

	r := NewRelayer(log.Noop(), nil, NewInMemoryCiphertextStorage(), 1,
		ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
	r.requestTimeout = time.Millisecond

	requestID := common.HexToHash("0x1")
	r.mu.Lock()
	r.pendingRequests[requestID] = &DecryptionRequest{
		RequestID: requestID,
		Timestamp: time.Now().Add(-time.Hour),
	}
	r.mu.Unlock()

	require.NoError(t, r.Start(context.Background()))
	defer r.Stop()

	require.Eventually(t, func() bool {
		_, _, err := r.GetResult(requestID)
		return errors.Is(err, ErrRequestNotFound)
	}, 90*time.Second, time.Second, "the periodic sweep never removed the expired request")
}
