// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/platformvm/warp"
	"github.com/stretchr/testify/require"
)

// mockSigner implements warp.Signer for testing
type mockSigner struct {
	signFunc func(*warp.UnsignedMessage) ([]byte, error)
}

func (m *mockSigner) Sign(msg *warp.UnsignedMessage) ([]byte, error) {
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

		onMessage := func(_ context.Context, _ *warp.Message) error {
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
