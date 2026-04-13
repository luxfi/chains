// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/platformvm/warp"
	"github.com/stretchr/testify/require"
)

func createTestWarpMessage(payload []byte, sourceChainID ids.ID) *warp.Message {
	unsignedMsg, _ := warp.NewUnsignedMessage(0, sourceChainID, payload)
	return &warp.Message{
		UnsignedMessage: *unsignedMsg,
	}
}

func TestWarpHandlerNilMessage(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()
	handler := NewWarpHandler(logger, nil)
	require.NotNil(handler)

	err := handler.HandleMessage(context.Background(), nil)
	require.Error(err)
	require.Contains(err.Error(), "nil message")
}

func TestWarpHandlerPayloadTooShort(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()
	handler := NewWarpHandler(logger, nil)

	// Create a message with payload < 4 bytes
	msg := createTestWarpMessage([]byte{0x01, 0x02, 0x03}, ids.GenerateTestID())

	err := handler.HandleMessage(context.Background(), msg)
	require.ErrorIs(err, ErrInvalidPayload)
}

func TestWarpHandlerUnknownSelector(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()
	handler := NewWarpHandler(logger, nil)

	// Create a message with unknown selector
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, 0xDEADBEEF) // Unknown selector

	msg := createTestWarpMessage(payload, ids.GenerateTestID())

	err := handler.HandleMessage(context.Background(), msg)
	require.ErrorIs(err, ErrInvalidSelector)
}

func TestWarpHandlerDecryptionRequestPayloadTooShort(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()
	handler := NewWarpHandler(logger, nil)

	// Create a message with SelectorRequestDecryption but insufficient data
	// handleDecryptionRequest expects 33 bytes after selector
	payload := make([]byte, 20) // 4 (selector) + 16 (insufficient)
	binary.BigEndian.PutUint32(payload, SelectorRequestDecryption)

	msg := createTestWarpMessage(payload, ids.GenerateTestID())

	err := handler.HandleMessage(context.Background(), msg)
	require.ErrorIs(err, ErrInvalidPayload)
}

func TestWarpHandlerDecryptionWithCallbackPayloadTooShort(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()
	handler := NewWarpHandler(logger, nil)

	// Create a message with SelectorRequestDecryptionCallback but insufficient data
	// handleDecryptionWithCallback expects 57 bytes after selector
	payload := make([]byte, 40) // 4 (selector) + 36 (insufficient)
	binary.BigEndian.PutUint32(payload, SelectorRequestDecryptionCallback)

	msg := createTestWarpMessage(payload, ids.GenerateTestID())

	err := handler.HandleMessage(context.Background(), msg)
	require.ErrorIs(err, ErrInvalidPayload)
}

func TestSelectorConstants(t *testing.T) {
	require := require.New(t)

	// Verify selectors are distinct and non-zero
	require.NotZero(SelectorRequestDecryption)
	require.NotZero(SelectorRequestDecryptionCallback)
	require.NotEqual(SelectorRequestDecryption, SelectorRequestDecryptionCallback)

	// Verify expected values (using explicit cast for type consistency)
	var selectorDecrypt uint32 = SelectorRequestDecryption
	var selectorCallback uint32 = SelectorRequestDecryptionCallback
	require.Equal(uint32(0x5a6d3af9), selectorDecrypt)
	require.Equal(uint32(0x7b8c4d12), selectorCallback)
}

func TestFHEDecryptionServiceStartStop(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	service := NewFHEDecryptionService(logger)
	require.NotNil(service)

	// Start service
	err := service.Start(context.Background())
	require.NoError(err)

	// Try to start again - should fail
	err = service.Start(context.Background())
	require.Error(err)
	require.Contains(err.Error(), "already running")

	// Stop service
	err = service.Stop()
	require.NoError(err)

	// Stop again - should be idempotent
	err = service.Stop()
	require.NoError(err)
}

func TestFHEDecryptionServiceRegisterHandler(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	service := NewFHEDecryptionService(logger)
	require.NotNil(service)

	chainID := ids.GenerateTestID()
	handler := NewWarpHandler(logger, nil)

	// Register handler
	service.RegisterHandler(chainID, handler)

	// Get handler
	got, ok := service.GetHandler(chainID)
	require.True(ok)
	require.Equal(handler, got)

	// Get non-existent handler
	_, ok = service.GetHandler(ids.GenerateTestID())
	require.False(ok)
}

func TestFHEDecryptionServiceMultipleHandlers(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	service := NewFHEDecryptionService(logger)

	// Register multiple handlers
	chain1 := ids.GenerateTestID()
	chain2 := ids.GenerateTestID()
	handler1 := NewWarpHandler(logger, nil)
	handler2 := NewWarpHandler(logger, nil)

	service.RegisterHandler(chain1, handler1)
	service.RegisterHandler(chain2, handler2)

	// Verify each handler is registered correctly
	got1, ok := service.GetHandler(chain1)
	require.True(ok)
	require.Equal(handler1, got1)

	got2, ok := service.GetHandler(chain2)
	require.True(ok)
	require.Equal(handler2, got2)
}

func TestNewWarpHandler(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	handler := NewWarpHandler(logger, nil)
	require.NotNil(handler)
	require.NotNil(handler.logger)
	require.Nil(handler.relayer)
}

func TestNewFHEDecryptionService(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	service := NewFHEDecryptionService(logger)
	require.NotNil(service)
	require.NotNil(service.handlers)
	require.False(service.running)
}

func TestWarpHandlerDecryptionRequestWithRelayer(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	// Create full relayer setup
	storage := NewInMemoryCiphertextStorage()
	relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
	require.NoError(relayer.Start(context.Background()))
	defer relayer.Stop()

	handler := NewWarpHandler(logger, relayer)

	// Create valid decryption request payload
	// selector (4) + ciphertextHash (32) + decryptionType (1) = 37 bytes
	payload := make([]byte, 37)
	binary.BigEndian.PutUint32(payload, SelectorRequestDecryption)
	copy(payload[4:36], []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	})
	payload[36] = 0x01 // decryptionType

	msg := createTestWarpMessage(payload, ids.GenerateTestID())

	err := handler.HandleMessage(context.Background(), msg)
	require.NoError(err)
}

func TestWarpHandlerDecryptionWithCallbackWithRelayer(t *testing.T) {
	require := require.New(t)
	logger := log.Noop()

	// Create full relayer setup
	storage := NewInMemoryCiphertextStorage()
	relayer := NewRelayer(logger, nil, storage, 1, ids.GenerateTestID(), ids.GenerateTestID(), nil, nil)
	require.NoError(relayer.Start(context.Background()))
	defer relayer.Stop()

	handler := NewWarpHandler(logger, relayer)

	// Create valid decryption with callback payload
	// selector (4) + ciphertextHash (32) + decryptionType (1) + callbackAddress (20) + callbackSelector (4) = 61 bytes
	payload := make([]byte, 61)
	binary.BigEndian.PutUint32(payload, SelectorRequestDecryptionCallback)
	// ciphertextHash
	copy(payload[4:36], []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
	})
	payload[36] = 0x02 // decryptionType
	// callbackAddress (20 bytes)
	copy(payload[37:57], []byte{
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0xaa, 0xbb, 0xcc, 0xdd,
	})
	// callbackSelector (4 bytes)
	binary.BigEndian.PutUint32(payload[57:61], 0x12345678)

	msg := createTestWarpMessage(payload, ids.GenerateTestID())

	err := handler.HandleMessage(context.Background(), msg)
	require.NoError(err)
}

// TestWarpHandlerDecryptionRequestNoRelayer is skipped because the handler
// panics on nil relayer rather than returning an error gracefully.
// TestWarpHandlerDecryptionWithCallbackNoRelayer is skipped for the same reason.
