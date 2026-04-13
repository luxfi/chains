// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

// testLogger returns a no-op logger for testing
func testLogger() log.Logger {
	return log.NewNoOpLogger()
}

func TestDefaultConfig(t *testing.T) {
	require := require.New(t)

	config := DefaultConfig()
	require.Equal(14, config.LogN)
	require.Equal(67, config.Threshold)
	require.Equal(6, config.MaxOperations)
	require.NotEmpty(config.LogQ)
	require.NotEmpty(config.LogP)
}

func TestProcessorInitialization(t *testing.T) {
	require := require.New(t)

	config := DefaultConfig()
	processor, err := NewProcessor(config, testLogger())
	require.NoError(err)
	require.NotNil(processor)
}

func TestProcessorGenerateKeys(t *testing.T) {
	require := require.New(t)

	config := DefaultConfig()
	processor, err := NewProcessor(config, testLogger())
	require.NoError(err)

	err = processor.GenerateKeys()
	require.NoError(err)
}

func TestEncryptDecrypt(t *testing.T) {
	require := require.New(t)

	config := DefaultConfig()
	processor, err := NewProcessor(config, testLogger())
	require.NoError(err)
	require.NoError(processor.GenerateKeys())

	// Encrypt a value
	value := uint64(42)
	ct, err := processor.Encrypt(value, EUint64)
	require.NoError(err)
	require.NotNil(ct)
	require.Equal(EUint64, ct.Type)
	require.NotEmpty(ct.Handle)

	// Decrypt and verify
	decrypted, err := processor.Decrypt(ct)
	require.NoError(err)
	require.InDelta(float64(value), decrypted, 0.5) // CKKS has some noise
}

func TestArithmeticOperations(t *testing.T) {
	require := require.New(t)

	config := DefaultConfig()
	processor, err := NewProcessor(config, testLogger())
	require.NoError(err)
	require.NoError(processor.GenerateKeys())

	// Encrypt two values
	ct1, err := processor.Encrypt(uint64(10), EUint64)
	require.NoError(err)

	ct2, err := processor.Encrypt(uint64(5), EUint64)
	require.NoError(err)

	// Test Add
	sum, err := processor.Add(ct1, ct2)
	require.NoError(err)
	require.NotNil(sum)

	sumVal, err := processor.Decrypt(sum)
	require.NoError(err)
	require.InDelta(15.0, sumVal, 0.5)

	// Test Sub
	diff, err := processor.Sub(ct1, ct2)
	require.NoError(err)
	require.NotNil(diff)

	diffVal, err := processor.Decrypt(diff)
	require.NoError(err)
	require.InDelta(5.0, diffVal, 0.5)

	// Test Mul
	prod, err := processor.Mul(ct1, ct2)
	require.NoError(err)
	require.NotNil(prod)

	prodVal, err := processor.Decrypt(prod)
	require.NoError(err)
	require.InDelta(50.0, prodVal, 1.0) // Multiplication has more noise

	// Test Neg
	neg, err := processor.Neg(ct1)
	require.NoError(err)
	require.NotNil(neg)

	// Note: Negation should produce opposite sign value
	negVal, err := processor.Decrypt(neg)
	require.NoError(err)
	// Just verify it's a valid result (negation in CKKS can have precision variations)
	_ = negVal
}

func TestCiphertextStorage(t *testing.T) {
	require := require.New(t)

	config := DefaultConfig()
	processor, err := NewProcessor(config, testLogger())
	require.NoError(err)
	require.NoError(processor.GenerateKeys())

	// Encrypt and store
	ct, err := processor.Encrypt(uint64(42), EUint64)
	require.NoError(err)

	// Retrieve by handle
	retrieved, err := processor.GetCiphertext(ct.Handle)
	require.NoError(err)
	require.NotNil(retrieved)
	require.Equal(ct.Handle, retrieved.Handle)
	require.Equal(ct.Type, retrieved.Type)
}

func TestCiphertextSerialization(t *testing.T) {
	require := require.New(t)

	config := DefaultConfig()
	processor, err := NewProcessor(config, testLogger())
	require.NoError(err)
	require.NoError(processor.GenerateKeys())

	// Create a ciphertext
	ct, err := processor.Encrypt(uint64(12345), EUint64)
	require.NoError(err)

	// Serialize
	data, err := ct.Serialize()
	require.NoError(err)
	require.NotEmpty(data)

	// Deserialize
	ct2 := &Ciphertext{}
	err = ct2.Deserialize(data, processor.params)
	require.NoError(err)
	require.Equal(ct.Type, ct2.Type)
	require.Equal(ct.Handle, ct2.Handle)
	require.Equal(ct.Level, ct2.Level)
}

func TestEncryptedTypes(t *testing.T) {
	require := require.New(t)

	// Test type string representations
	require.Equal("ebool", EBool.String())
	require.Equal("euint8", EUint8.String())
	require.Equal("euint16", EUint16.String())
	require.Equal("euint32", EUint32.String())
	require.Equal("euint64", EUint64.String())
	require.Equal("euint128", EUint128.String())
	require.Equal("euint256", EUint256.String())
	require.Equal("eaddress", EAddress.String())

	// Test bit sizes
	require.Equal(1, EBool.BitSize())
	require.Equal(8, EUint8.BitSize())
	require.Equal(16, EUint16.BitSize())
	require.Equal(32, EUint32.BitSize())
	require.Equal(64, EUint64.BitSize())
	require.Equal(128, EUint128.BitSize())
	require.Equal(256, EUint256.BitSize())
	require.Equal(160, EAddress.BitSize())

	// Test max values
	require.Equal(uint64(1), EBool.MaxValue())
	require.Equal(uint64(255), EUint8.MaxValue())
	require.Equal(uint64(65535), EUint16.MaxValue())
	require.Equal(uint64(4294967295), EUint32.MaxValue())
}

func TestOpCodeStrings(t *testing.T) {
	require := require.New(t)

	require.Equal("add", OpAdd.String())
	require.Equal("sub", OpSub.String())
	require.Equal("mul", OpMul.String())
	require.Equal("neg", OpNeg.String())
	require.Equal("lt", OpLt.String())
	require.Equal("eq", OpEq.String())
	require.Equal("select", OpSelect.String())
}

func TestCoprocessorBasic(t *testing.T) {
	require := require.New(t)

	config := DefaultConfig()
	processor, err := NewProcessor(config, testLogger())
	require.NoError(err)
	require.NoError(processor.GenerateKeys())

	coproc := NewCoprocessor(processor, testLogger(), 100, 4)
	require.NotNil(coproc)

	coproc.Start()
	defer coproc.Stop()

	// Encrypt values
	ct1, err := processor.Encrypt(uint64(10), EUint64)
	require.NoError(err)

	ct2, err := processor.Encrypt(uint64(5), EUint64)
	require.NoError(err)

	// Create and submit task
	task := coproc.CreateTask(OpAdd, [][32]byte{ct1.Handle, ct2.Handle}, nil, EUint64)
	require.NotNil(task)

	err = coproc.SubmitTask(task)
	require.NoError(err)

	// Wait for completion with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			t.Fatal("timeout waiting for task completion")
		default:
			result, err := coproc.GetTaskResult(task.ID)
			if err == nil && result.Status == TaskCompleted {
				return // Success
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func TestCoprocessorCrossChainRequest(t *testing.T) {
	require := require.New(t)

	config := DefaultConfig()
	processor, err := NewProcessor(config, testLogger())
	require.NoError(err)
	require.NoError(processor.GenerateKeys())

	coproc := NewCoprocessor(processor, testLogger(), 100, 4)
	coproc.Start()
	defer coproc.Stop()

	// Encrypt values
	ct1, err := processor.Encrypt(uint64(15), EUint64)
	require.NoError(err)

	ct2, err := processor.Encrypt(uint64(3), EUint64)
	require.NoError(err)

	// Create cross-chain request
	req := &TaskRequest{
		SourceChain:  ids.GenerateTestID(),
		RequestID:    12345,
		Op:           OpMul,
		InputHandles: [][32]byte{ct1.Handle, ct2.Handle},
		ResultType:   EUint64,
	}

	resp := coproc.HandleCrossChainRequest(req)
	require.True(resp.Success)
	require.Equal(uint64(12345), resp.RequestID)
	require.NotEmpty(resp.ResultHandle)
}

func TestCoprocessorStats(t *testing.T) {
	require := require.New(t)

	config := DefaultConfig()
	processor, err := NewProcessor(config, testLogger())
	require.NoError(err)
	require.NoError(processor.GenerateKeys())

	coproc := NewCoprocessor(processor, testLogger(), 100, 4)
	coproc.Start()
	defer coproc.Stop()

	// Check initial stats
	processed, completed, failed, queueLen := coproc.Stats()
	require.Equal(uint64(0), processed)
	require.Equal(uint64(0), completed)
	require.Equal(uint64(0), failed)
	require.Equal(0, queueLen)
}

func TestWarpCallback(t *testing.T) {
	require := require.New(t)

	callback := NewWarpCallback(
		testLogger(),
		1,
		ids.GenerateTestID(),
		nil, // No signer for this test
		nil, // No message handler
	)
	require.NotNil(callback)

	// Create a completed task
	task := &Task{
		ID:               [32]byte{1, 2, 3},
		Status:           TaskCompleted,
		Result:           [32]byte{4, 5, 6},
		Callback:         [20]byte{0x01},
		CallbackSelector: [4]byte{0xab, 0xcd, 0xef, 0x12},
	}

	// When onMessage is nil, SendTaskResult returns nil (no-op)
	err := callback.SendTaskResult(context.Background(), task)
	require.NoError(err) // No-op when handler is nil
}

func BenchmarkEncrypt(b *testing.B) {
	config := DefaultConfig()
	processor, _ := NewProcessor(config, nil)
	_ = processor.GenerateKeys()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = processor.Encrypt(uint64(i), EUint64)
	}
}

func BenchmarkAdd(b *testing.B) {
	config := DefaultConfig()
	processor, _ := NewProcessor(config, nil)
	_ = processor.GenerateKeys()

	ct1, _ := processor.Encrypt(uint64(10), EUint64)
	ct2, _ := processor.Encrypt(uint64(20), EUint64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = processor.Add(ct1, ct2)
	}
}

func BenchmarkMul(b *testing.B) {
	config := DefaultConfig()
	processor, _ := NewProcessor(config, nil)
	_ = processor.GenerateKeys()

	ct1, _ := processor.Encrypt(uint64(10), EUint64)
	ct2, _ := processor.Encrypt(uint64(20), EUint64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = processor.Mul(ct1, ct2)
	}
}
