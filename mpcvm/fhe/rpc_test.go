// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

func newTestFHEService(t *testing.T) *FHEService {
	require := require.New(t)

	db := memdb.New()
	reg, err := NewRegistry(db)
	require.NoError(err)

	// Initialize epoch with committee
	committee := []CommitteeMember{
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk1"), Weight: 100, Index: 0},
		{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("pk2"), Weight: 100, Index: 1},
	}
	epochInfo := &EpochInfo{
		Epoch:     1,
		StartTime: time.Now().Unix(),
		Threshold: 67,
		PublicKey: []byte("test-public-key"),
		Committee: committee,
		Status:    EpochActive,
	}
	err = reg.SetEpoch(1, epochInfo)
	require.NoError(err)

	service := &FHEService{
		logger:   log.NewNoOpLogger(),
		registry: reg,
		chainID:  ids.GenerateTestID(),
	}

	return service
}

func TestFHEServiceGetPublicParams(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	args := &GetPublicParamsArgs{}
	reply := &GetPublicParamsReply{}

	err := service.GetPublicParams(context.Background(), args, reply)
	require.NoError(err)

	require.Equal(uint64(1), reply.Epoch)
	require.Equal(67, reply.Threshold)
	require.NotEmpty(reply.PublicKey)
	require.NotEmpty(reply.ChainID)
}

func TestFHEServiceGetCommittee(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	args := &GetCommitteeArgs{}
	reply := &GetCommitteeReply{}

	err := service.GetCommittee(context.Background(), args, reply)
	require.NoError(err)

	require.Equal(uint64(1), reply.Epoch)
	require.Len(reply.Members, 2)
}

func TestFHEServiceRegisterCiphertext(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	args := &RegisterCiphertextArgs{
		Handle: "0102030405060708091011121314151617181920212223242526272829303132",
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	reply := &RegisterCiphertextReply{}

	err := service.RegisterCiphertext(context.Background(), args, reply)
	require.NoError(err)

	require.Equal(args.Handle, reply.Handle)
	require.Equal(uint64(1), reply.Epoch)
	require.NotZero(reply.RegisteredAt)
}

func TestFHEServiceGetCiphertextMeta(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// First register a ciphertext
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	registerReply := &RegisterCiphertextReply{}
	err := service.RegisterCiphertext(context.Background(), registerArgs, registerReply)
	require.NoError(err)

	// Get the metadata
	getArgs := &GetCiphertextMetaArgs{
		Handle: handle,
	}
	getReply := &GetCiphertextMetaReply{}

	err = service.GetCiphertextMeta(context.Background(), getArgs, getReply)
	require.NoError(err)

	require.Equal(handle, getReply.Handle)
	require.Equal(uint8(1), getReply.Type)
	require.Equal(uint32(1024), getReply.Size)
}

func TestFHEServiceRequestDecrypt(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// First register a ciphertext
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	registerReply := &RegisterCiphertextReply{}
	err := service.RegisterCiphertext(context.Background(), registerArgs, registerReply)
	require.NoError(err)

	// First create a permit so we can decrypt
	permitArgs := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1, // decrypt
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	permitReply := &CreatePermitReply{}
	err = service.CreatePermit(context.Background(), permitArgs, permitReply)
	require.NoError(err)

	// Request decryption
	args := &RequestDecryptArgs{
		CiphertextHandle: handle,
		PermitID:         permitReply.PermitID,
		Callback:         "abcdef0123456789abcdef0123456789abcdef01",
		CallbackSelector: "12345678",
	}
	reply := &RequestDecryptReply{}

	err = service.RequestDecrypt(context.Background(), args, reply)
	require.NoError(err)

	require.NotEmpty(reply.RequestID)
	require.Equal("pending", reply.Status)
	require.Equal(uint64(1), reply.Epoch)
}

func TestFHEServiceGetDecryptResult(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register ciphertext
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Create permit
	permitArgs := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1, // decrypt
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	permitReply := &CreatePermitReply{}
	err = service.CreatePermit(context.Background(), permitArgs, permitReply)
	require.NoError(err)

	// Request decryption
	requestArgs := &RequestDecryptArgs{
		CiphertextHandle: handle,
		PermitID:         permitReply.PermitID,
		Callback:         "abcdef0123456789abcdef0123456789abcdef01",
		CallbackSelector: "12345678",
	}
	requestReply := &RequestDecryptReply{}
	err = service.RequestDecrypt(context.Background(), requestArgs, requestReply)
	require.NoError(err)

	// Get result (should be pending)
	args := &GetDecryptResultArgs{
		RequestID: requestReply.RequestID,
	}
	reply := &GetDecryptResultReply{}

	err = service.GetDecryptResult(context.Background(), args, reply)
	require.NoError(err)

	require.Equal(requestReply.RequestID, reply.RequestID)
	require.Equal("pending", reply.Status)
}

func TestFHEServiceCreatePermit(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// First register a ciphertext
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	args := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 3, // decrypt + reencrypt
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	reply := &CreatePermitReply{}

	err = service.CreatePermit(context.Background(), args, reply)
	require.NoError(err)

	require.NotEmpty(reply.PermitID)
	require.NotZero(reply.CreatedAt)
}

func TestFHEServiceVerifyPermit(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	grantee := "abcdef0123456789abcdef0123456789abcdef01"

	// First register a ciphertext
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Create permit
	createArgs := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    grantee,
		Operations: 1, // decrypt
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	createReply := &CreatePermitReply{}
	err = service.CreatePermit(context.Background(), createArgs, createReply)
	require.NoError(err)

	// Verify permit
	verifyArgs := &VerifyPermitArgs{
		PermitID:  createReply.PermitID,
		Handle:    handle,
		Grantee:   grantee,
		Operation: 1, // decrypt
	}
	verifyReply := &VerifyPermitReply{}

	err = service.VerifyPermit(context.Background(), verifyArgs, verifyReply)
	require.NoError(err)

	require.True(verifyReply.Valid)
}

func TestFHEServiceVerifyPermitInvalid(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Verify non-existent permit
	verifyArgs := &VerifyPermitArgs{
		PermitID:  "0102030405060708091011121314151617181920212223242526272829303132",
		Handle:    "0102030405060708091011121314151617181920212223242526272829303132",
		Grantee:   "abcdef0123456789abcdef0123456789abcdef01",
		Operation: 1,
	}
	verifyReply := &VerifyPermitReply{}

	err := service.VerifyPermit(context.Background(), verifyArgs, verifyReply)
	require.NoError(err)

	require.False(verifyReply.Valid)
	require.NotEmpty(verifyReply.Error)
}

func TestFHEServiceNotInitialized(t *testing.T) {
	require := require.New(t)

	service := &FHEService{
		logger:  log.NewNoOpLogger(),
		chainID: ids.GenerateTestID(),
		// registry is nil
	}

	err := service.GetPublicParams(context.Background(), &GetPublicParamsArgs{}, &GetPublicParamsReply{})
	require.Error(err)
	require.Equal(ErrNotInitialized, err)
}

func TestFHEServiceInvalidHandleFormat(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Invalid hex
	args := &RegisterCiphertextArgs{
		Handle: "not-valid-hex",
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	reply := &RegisterCiphertextReply{}

	err := service.RegisterCiphertext(context.Background(), args, reply)
	require.Error(err)

	// Wrong length
	args.Handle = "0102030405" // Too short
	err = service.RegisterCiphertext(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceGetCiphertextMetaNotFound(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Try to get non-existent ciphertext
	args := &GetCiphertextMetaArgs{
		Handle: "0102030405060708091011121314151617181920212223242526272829303132",
	}
	reply := &GetCiphertextMetaReply{}

	err := service.GetCiphertextMeta(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceGetDecryptResultNotFound(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Try to get non-existent decrypt result
	args := &GetDecryptResultArgs{
		RequestID: "0102030405060708091011121314151617181920212223242526272829303132",
	}
	reply := &GetDecryptResultReply{}

	err := service.GetDecryptResult(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceRequestDecryptInvalidHandle(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Try to decrypt with invalid handle format
	args := &RequestDecryptArgs{
		CiphertextHandle: "not-valid-hex",
		PermitID:         "0102030405060708091011121314151617181920212223242526272829303132",
		Callback:         "abcdef0123456789abcdef0123456789abcdef01",
		CallbackSelector: "12345678",
	}
	reply := &RequestDecryptReply{}

	err := service.RequestDecrypt(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceRequestDecryptCiphertextNotFound(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Try to decrypt non-existent ciphertext
	args := &RequestDecryptArgs{
		CiphertextHandle: "0102030405060708091011121314151617181920212223242526272829303132",
		PermitID:         "0102030405060708091011121314151617181920212223242526272829303132",
		Callback:         "abcdef0123456789abcdef0123456789abcdef01",
		CallbackSelector: "12345678",
	}
	reply := &RequestDecryptReply{}

	err := service.RequestDecrypt(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceCreatePermitInvalidHandle(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Try to create permit with invalid handle
	args := &CreatePermitArgs{
		Handle:     "not-valid-hex",
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	reply := &CreatePermitReply{}

	err := service.CreatePermit(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceCreatePermitCiphertextNotFound(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Try to create permit for non-existent ciphertext
	args := &CreatePermitArgs{
		Handle:     "0102030405060708091011121314151617181920212223242526272829303132",
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	reply := &CreatePermitReply{}

	err := service.CreatePermit(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceGetCommitteeSpecificEpoch(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	epoch := uint64(1)
	args := &GetCommitteeArgs{
		Epoch: &epoch,
	}
	reply := &GetCommitteeReply{}

	err := service.GetCommittee(context.Background(), args, reply)
	require.NoError(err)
	require.Equal(uint64(1), reply.Epoch)
}

func TestFHEServiceGetCommitteeEpochNotFound(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	epoch := uint64(999)
	args := &GetCommitteeArgs{
		Epoch: &epoch,
	}
	reply := &GetCommitteeReply{}

	err := service.GetCommittee(context.Background(), args, reply)
	require.Error(err)
}

func TestNewFHEService(t *testing.T) {
	require := require.New(t)

	db := memdb.New()
	reg, err := NewRegistry(db)
	require.NoError(err)

	logger := log.NewNoOpLogger()
	chainID := ids.GenerateTestID()

	service := NewFHEService(reg, nil, logger, chainID)
	require.NotNil(service)
	require.Equal(chainID, service.chainID)
}

func TestFHEServiceRequestDecryptBatch(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// First register ciphertexts
	handle1 := "0102030405060708091011121314151617181920212223242526272829303132"
	handle2 := "0102030405060708091011121314151617181920212223242526272829303133"

	for _, handle := range []string{handle1, handle2} {
		registerArgs := &RegisterCiphertextArgs{
			Handle: handle,
			Owner:  "0102030405060708091011121314151617181920",
			Type:   1,
			Level:  14,
			Size:   1024,
		}
		err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
		require.NoError(err)
	}

	// Create permits for each
	for _, handle := range []string{handle1, handle2} {
		permitArgs := &CreatePermitArgs{
			Handle:     handle,
			Grantor:    "0102030405060708091011121314151617181920",
			Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
			Operations: 1,
			Expiry:     time.Now().Add(time.Hour).Unix(),
		}
		permitReply := &CreatePermitReply{}
		err := service.CreatePermit(context.Background(), permitArgs, permitReply)
		require.NoError(err)
	}

	// Request batch decryption (need to get permit IDs first)
	permitArgs1 := &CreatePermitArgs{
		Handle:     handle1,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef02",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	permitReply1 := &CreatePermitReply{}
	err := service.CreatePermit(context.Background(), permitArgs1, permitReply1)
	require.NoError(err)

	permitArgs2 := &CreatePermitArgs{
		Handle:     handle2,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef02",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	permitReply2 := &CreatePermitReply{}
	err = service.CreatePermit(context.Background(), permitArgs2, permitReply2)
	require.NoError(err)

	args := &RequestDecryptBatchArgs{
		Requests: []RequestDecryptArgs{
			{
				CiphertextHandle: handle1,
				PermitID:         permitReply1.PermitID,
				Callback:         "abcdef0123456789abcdef0123456789abcdef02",
				CallbackSelector: "12345678",
			},
			{
				CiphertextHandle: handle2,
				PermitID:         permitReply2.PermitID,
				Callback:         "abcdef0123456789abcdef0123456789abcdef02",
				CallbackSelector: "12345678",
			},
		},
	}
	reply := &RequestDecryptBatchReply{}

	err = service.RequestDecryptBatch(context.Background(), args, reply)
	require.NoError(err)
	require.Len(reply.RequestIDs, 2)
	require.NotEmpty(reply.RequestIDs[0])
	require.NotEmpty(reply.RequestIDs[1])
}

func TestFHEServiceRequestDecryptBatchTooLarge(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Create batch that exceeds MaxBatchSize (100)
	requests := make([]RequestDecryptArgs, MaxBatchSize+1)
	for i := range requests {
		requests[i] = RequestDecryptArgs{
			CiphertextHandle: "0102030405060708091011121314151617181920212223242526272829303132",
			PermitID:         "0102030405060708091011121314151617181920212223242526272829303132",
			Callback:         "abcdef0123456789abcdef0123456789abcdef01",
			CallbackSelector: "12345678",
		}
	}

	args := &RequestDecryptBatchArgs{
		Requests: requests,
	}
	reply := &RequestDecryptBatchReply{}

	err := service.RequestDecryptBatch(context.Background(), args, reply)
	require.ErrorIs(err, ErrBatchTooLarge)
}

func TestFHEServiceGetDecryptBatchResult(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register and create requests
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	permitArgs := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	permitReply := &CreatePermitReply{}
	err = service.CreatePermit(context.Background(), permitArgs, permitReply)
	require.NoError(err)

	requestArgs := &RequestDecryptArgs{
		CiphertextHandle: handle,
		PermitID:         permitReply.PermitID,
		Callback:         "abcdef0123456789abcdef0123456789abcdef01",
		CallbackSelector: "12345678",
	}
	requestReply := &RequestDecryptReply{}
	err = service.RequestDecrypt(context.Background(), requestArgs, requestReply)
	require.NoError(err)

	// Get batch results
	args := &GetDecryptBatchResultArgs{
		RequestIDs: []string{requestReply.RequestID, "0102030405060708091011121314151617181920212223242526272829303199"},
	}
	reply := &GetDecryptBatchResultReply{}

	err = service.GetDecryptBatchResult(context.Background(), args, reply)
	require.NoError(err)
	require.Len(reply.Results, 2)
	// First should be found
	require.Equal(requestReply.RequestID, reply.Results[0].RequestID)
	require.Equal("pending", reply.Results[0].Status)
	// Second should have error
	require.NotEmpty(reply.Results[1].Error)
}

func TestFHEServiceGetRequestReceipt(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register and create a request
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	permitArgs := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	permitReply := &CreatePermitReply{}
	err = service.CreatePermit(context.Background(), permitArgs, permitReply)
	require.NoError(err)

	requestArgs := &RequestDecryptArgs{
		CiphertextHandle: handle,
		PermitID:         permitReply.PermitID,
		Callback:         "abcdef0123456789abcdef0123456789abcdef01",
		CallbackSelector: "12345678",
	}
	requestReply := &RequestDecryptReply{}
	err = service.RequestDecrypt(context.Background(), requestArgs, requestReply)
	require.NoError(err)

	// Get receipt
	receiptArgs := &GetRequestReceiptArgs{
		RequestID: requestReply.RequestID,
	}
	receiptReply := &GetRequestReceiptReply{}

	err = service.GetRequestReceipt(context.Background(), receiptArgs, receiptReply)
	require.NoError(err)
	require.Equal(requestReply.RequestID, receiptReply.RequestID)
	require.Equal("pending", receiptReply.Status)
	require.NotZero(receiptReply.CreatedAt)
}

func TestFHEServiceGetRequestReceiptNotFound(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Try to get receipt for non-existent request
	args := &GetRequestReceiptArgs{
		RequestID: "0102030405060708091011121314151617181920212223242526272829303132",
	}
	reply := &GetRequestReceiptReply{}

	err := service.GetRequestReceipt(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceGetRequestReceiptInvalidID(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Invalid hex
	args := &GetRequestReceiptArgs{
		RequestID: "not-valid-hex",
	}
	reply := &GetRequestReceiptReply{}

	err := service.GetRequestReceipt(context.Background(), args, reply)
	require.Error(err)

	// Wrong length
	args.RequestID = "0102030405"
	err = service.GetRequestReceipt(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceGetRequestReceiptCompleted(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register and create a request
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	permitArgs := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	permitReply := &CreatePermitReply{}
	err = service.CreatePermit(context.Background(), permitArgs, permitReply)
	require.NoError(err)

	requestArgs := &RequestDecryptArgs{
		CiphertextHandle: handle,
		PermitID:         permitReply.PermitID,
		Callback:         "abcdef0123456789abcdef0123456789abcdef01",
		CallbackSelector: "12345678",
	}
	requestReply := &RequestDecryptReply{}
	err = service.RequestDecrypt(context.Background(), requestArgs, requestReply)
	require.NoError(err)

	// Manually update request to completed status
	requestBytes, _ := hex.DecodeString(requestReply.RequestID)
	var requestID [32]byte
	copy(requestID[:], requestBytes)
	err = service.registry.UpdateDecryptRequest(requestID, RequestCompleted, [32]byte{0xaa, 0xbb}, "")
	require.NoError(err)

	// Get receipt - should have WarpMessageID now
	receiptArgs := &GetRequestReceiptArgs{
		RequestID: requestReply.RequestID,
	}
	receiptReply := &GetRequestReceiptReply{}

	err = service.GetRequestReceipt(context.Background(), receiptArgs, receiptReply)
	require.NoError(err)
	require.Equal("completed", receiptReply.Status)
	require.NotEmpty(receiptReply.WarpMessageID)
}

func TestFHEServiceCreatePermitInvalidGrantee(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register ciphertext first
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Invalid grantee (not valid hex)
	args := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "not-valid-hex",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	reply := &CreatePermitReply{}

	err = service.CreatePermit(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceCreatePermitInvalidGrantor(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register ciphertext first
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Invalid grantor (not valid hex)
	args := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "not-valid-hex",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	reply := &CreatePermitReply{}

	err = service.CreatePermit(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceVerifyPermitInvalidFormat(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Invalid permit ID format - VerifyPermit returns invalid with error message
	args := &VerifyPermitArgs{
		PermitID:  "not-valid-hex",
		Handle:    "0102030405060708091011121314151617181920212223242526272829303132",
		Grantee:   "abcdef0123456789abcdef0123456789abcdef01",
		Operation: 1,
	}
	reply := &VerifyPermitReply{}

	err := service.VerifyPermit(context.Background(), args, reply)
	require.NoError(err)
	require.False(reply.Valid)
	require.NotEmpty(reply.Error)
}

func TestFHEServiceRegisterCiphertextInvalidOwner(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Invalid owner format
	args := &RegisterCiphertextArgs{
		Handle: "0102030405060708091011121314151617181920212223242526272829303132",
		Owner:  "not-valid-hex",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	reply := &RegisterCiphertextReply{}

	err := service.RegisterCiphertext(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceRequestDecryptInvalidPermitID(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register ciphertext
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Invalid permit ID format
	args := &RequestDecryptArgs{
		CiphertextHandle: handle,
		PermitID:         "not-valid-hex",
		Callback:         "abcdef0123456789abcdef0123456789abcdef01",
		CallbackSelector: "12345678",
	}
	reply := &RequestDecryptReply{}

	err = service.RequestDecrypt(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceRequestDecryptInvalidCallback(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register ciphertext
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Create permit
	permitArgs := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	permitReply := &CreatePermitReply{}
	err = service.CreatePermit(context.Background(), permitArgs, permitReply)
	require.NoError(err)

	// Invalid callback format
	args := &RequestDecryptArgs{
		CiphertextHandle: handle,
		PermitID:         permitReply.PermitID,
		Callback:         "not-valid-hex",
		CallbackSelector: "12345678",
	}
	reply := &RequestDecryptReply{}

	err = service.RequestDecrypt(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceRequestDecryptInvalidCallbackSelector(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register ciphertext
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Create permit
	permitArgs := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	permitReply := &CreatePermitReply{}
	err = service.CreatePermit(context.Background(), permitArgs, permitReply)
	require.NoError(err)

	// Invalid callback selector format
	args := &RequestDecryptArgs{
		CiphertextHandle: handle,
		PermitID:         permitReply.PermitID,
		Callback:         "abcdef0123456789abcdef0123456789abcdef01",
		CallbackSelector: "not-valid",
	}
	reply := &RequestDecryptReply{}

	err = service.RequestDecrypt(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceCreatePermitInvalidChainID(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register ciphertext first
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Try to create permit with invalid chain ID
	args := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
		ChainID:    "not-a-valid-chain-id",
	}
	reply := &CreatePermitReply{}

	err = service.CreatePermit(context.Background(), args, reply)
	require.Error(err)
	require.Contains(err.Error(), "invalid chain ID")
}

func TestFHEServiceCreatePermitInvalidAttestation(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register ciphertext first
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Try to create permit with invalid attestation hex
	args := &CreatePermitArgs{
		Handle:      handle,
		Grantor:     "0102030405060708091011121314151617181920",
		Grantee:     "abcdef0123456789abcdef0123456789abcdef01",
		Operations:  1,
		Expiry:      time.Now().Add(time.Hour).Unix(),
		Attestation: "not-valid-hex-string",
	}
	reply := &CreatePermitReply{}

	err = service.CreatePermit(context.Background(), args, reply)
	require.Error(err)
	require.Contains(err.Error(), "invalid attestation")
}

func TestFHEServiceCreatePermitNotOwner(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register ciphertext with one owner
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Try to create permit with different grantor (not the owner)
	args := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "ffffffffffffffffffffffffffffffffffffffff", // Different from owner
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	reply := &CreatePermitReply{}

	err = service.CreatePermit(context.Background(), args, reply)
	require.Error(err)
	require.Contains(err.Error(), "grantor is not the ciphertext owner")
}

func TestFHEServiceGetDecryptResultInvalidRequestID(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	args := &GetDecryptResultArgs{
		RequestID: "not-valid-hex",
	}
	reply := &GetDecryptResultReply{}

	err := service.GetDecryptResult(context.Background(), args, reply)
	require.Error(err)
}

func TestFHEServiceCreatePermitWithValidAttestation(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register ciphertext first
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Create permit with valid attestation hex
	args := &CreatePermitArgs{
		Handle:      handle,
		Grantor:     "0102030405060708091011121314151617181920",
		Grantee:     "abcdef0123456789abcdef0123456789abcdef01",
		Operations:  1,
		Expiry:      time.Now().Add(time.Hour).Unix(),
		Attestation: "0102030405060708", // Valid hex
	}
	reply := &CreatePermitReply{}

	err = service.CreatePermit(context.Background(), args, reply)
	require.NoError(err)
	require.NotEmpty(reply.PermitID)
}

func TestFHEServiceVerifyPermitInvalidHandle(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	args := &VerifyPermitArgs{
		PermitID:  "0102030405060708091011121314151617181920212223242526272829303132",
		Handle:    "not-valid-hex",
		Grantee:   "abcdef0123456789abcdef0123456789abcdef01",
		Operation: 1,
	}
	reply := &VerifyPermitReply{}

	err := service.VerifyPermit(context.Background(), args, reply)
	require.NoError(err) // Returns without error but with Valid=false
	require.False(reply.Valid)
	require.Contains(reply.Error, "invalid handle format")
}

func TestFHEServiceVerifyPermitInvalidGrantee(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	args := &VerifyPermitArgs{
		PermitID:  "0102030405060708091011121314151617181920212223242526272829303132",
		Handle:    "0102030405060708091011121314151617181920212223242526272829303132",
		Grantee:   "not-valid-hex",
		Operation: 1,
	}
	reply := &VerifyPermitReply{}

	err := service.VerifyPermit(context.Background(), args, reply)
	require.NoError(err)
	require.False(reply.Valid)
	require.Contains(reply.Error, "invalid grantee format")
}

func TestFHEServiceVerifyPermitValid(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Register ciphertext
	handle := "0102030405060708091011121314151617181920212223242526272829303132"
	registerArgs := &RegisterCiphertextArgs{
		Handle: handle,
		Owner:  "0102030405060708091011121314151617181920",
		Type:   1,
		Level:  14,
		Size:   1024,
	}
	err := service.RegisterCiphertext(context.Background(), registerArgs, &RegisterCiphertextReply{})
	require.NoError(err)

	// Create permit
	permitArgs := &CreatePermitArgs{
		Handle:     handle,
		Grantor:    "0102030405060708091011121314151617181920",
		Grantee:    "abcdef0123456789abcdef0123456789abcdef01",
		Operations: 1,
		Expiry:     time.Now().Add(time.Hour).Unix(),
	}
	permitReply := &CreatePermitReply{}
	err = service.CreatePermit(context.Background(), permitArgs, permitReply)
	require.NoError(err)

	// Verify permit
	verifyArgs := &VerifyPermitArgs{
		PermitID:  permitReply.PermitID,
		Handle:    handle,
		Grantee:   "abcdef0123456789abcdef0123456789abcdef01",
		Operation: 1,
	}
	verifyReply := &VerifyPermitReply{}

	err = service.VerifyPermit(context.Background(), verifyArgs, verifyReply)
	require.NoError(err)
	require.True(verifyReply.Valid)
	require.Empty(verifyReply.Error)
	require.Greater(verifyReply.Expiry, int64(0))
}

func TestFHEServiceRegisterCiphertextInvalidChainID(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	args := &RegisterCiphertextArgs{
		Handle:  "0102030405060708091011121314151617181920212223242526272829303132",
		Owner:   "0102030405060708091011121314151617181920",
		Type:    1,
		Level:   14,
		Size:    1024,
		ChainID: "not-a-valid-chain-id",
	}
	reply := &RegisterCiphertextReply{}

	err := service.RegisterCiphertext(context.Background(), args, reply)
	require.Error(err)
	require.Contains(err.Error(), "invalid chain ID")
}

func TestFHEServiceRegisterCiphertextWithChainID(t *testing.T) {
	require := require.New(t)

	service := newTestFHEService(t)

	// Generate a valid chain ID
	chainID := ids.GenerateTestID()

	args := &RegisterCiphertextArgs{
		Handle:  "0102030405060708091011121314151617181920212223242526272829303132",
		Owner:   "0102030405060708091011121314151617181920",
		Type:    1,
		Level:   14,
		Size:    1024,
		ChainID: chainID.String(),
	}
	reply := &RegisterCiphertextReply{}

	err := service.RegisterCiphertext(context.Background(), args, reply)
	require.NoError(err)
	require.NotEmpty(reply.Handle)
}

// ---------------------------------------------------------------------------
// Who the RPC surface will answer, and what it refuses
// ---------------------------------------------------------------------------

// callerFrom is an Authenticator that reports a fixed address, or a failure to
// establish one, which is the difference between an authenticated caller and an
// anonymous connection.
type callerFrom struct {
	address [20]byte
	err     error
}

func (c callerFrom) GetCallerAddress(context.Context) ([20]byte, error) {
	if c.err != nil {
		return [20]byte{}, c.err
	}
	return c.address, nil
}

// TestWithAuthenticatorInstallsTheCallerCheck holds that the option reaches the
// service, because every ownership check below is a no-op without it.
func TestWithAuthenticatorInstallsTheCallerCheck(t *testing.T) {
	auth := callerFrom{address: [20]byte{1}}
	service := NewFHEService(nil, nil, log.NewNoOpLogger(), ids.GenerateTestID(), WithAuthenticator(auth))
	require.NotNil(t, service)
	require.Equal(t, auth, service.auth)

	// Without the option there is no authenticator, and the constructor says so
	// rather than failing: the RPC surface is usable unauthenticated.
	require.Nil(t, NewFHEService(nil, nil, log.NewNoOpLogger(), ids.GenerateTestID()).auth)
}

// TestRegisterCiphertextRequiresTheOwnerToBeTheCaller holds that a ciphertext
// is registered only by the address it names as owner. Without it any caller
// can claim a handle under someone else's address, and CreatePermit then treats
// that address as entitled to grant access to it.
func TestRegisterCiphertextRequiresTheOwnerToBeTheCaller(t *testing.T) {
	owner := [20]byte{0xaa}
	handle := hex.EncodeToString(make([]byte, 32))

	register := func(auth Authenticator) error {
		service := newTestFHEService(t)
		service.auth = auth
		return service.RegisterCiphertext(context.Background(), &RegisterCiphertextArgs{
			Handle: handle,
			Owner:  hex.EncodeToString(owner[:]),
		}, &RegisterCiphertextReply{})
	}

	require.NoError(t, register(callerFrom{address: owner}))

	err := register(callerFrom{address: [20]byte{0xbb}})
	require.ErrorIs(t, err, ErrUnauthorized)

	err = register(callerFrom{err: errors.New("no client certificate")})
	require.ErrorIs(t, err, ErrAuthRequired)
}

// TestCreatePermitRequiresTheGrantorToBeTheCallerAndTheOwner holds both halves
// of granting access: the caller must be the grantor they name, and that
// grantor must own the ciphertext. Dropping either turns permit creation into
// an open door -- anyone could mint a permit over anyone's ciphertext.
func TestCreatePermitRequiresTheGrantorToBeTheCallerAndTheOwner(t *testing.T) {
	owner := [20]byte{0xaa}
	stranger := [20]byte{0xbb}
	handle := make([]byte, 32)
	handle[0] = 7

	service := newTestFHEService(t)
	require.NoError(t, service.registry.RegisterCiphertext(&CiphertextMeta{
		Handle: [32]byte(handle), Owner: owner,
	}))

	args := &CreatePermitArgs{
		Handle:     hex.EncodeToString(handle),
		Grantee:    hex.EncodeToString(stranger[:]),
		Grantor:    hex.EncodeToString(owner[:]),
		Operations: PermitOpDecrypt,
	}

	service.auth = callerFrom{address: owner}
	require.NoError(t, service.CreatePermit(context.Background(), args, &CreatePermitReply{}))

	service.auth = callerFrom{address: stranger}
	require.ErrorIs(t, service.CreatePermit(context.Background(), args, &CreatePermitReply{}), ErrUnauthorized)

	service.auth = callerFrom{err: errors.New("no client certificate")}
	require.ErrorIs(t, service.CreatePermit(context.Background(), args, &CreatePermitReply{}), ErrAuthRequired)

	// The grantor must also be the owner, even when it is the caller.
	service.auth = callerFrom{address: stranger}
	require.ErrorContains(t, service.CreatePermit(context.Background(), &CreatePermitArgs{
		Handle:  hex.EncodeToString(handle),
		Grantee: hex.EncodeToString(owner[:]),
		Grantor: hex.EncodeToString(stranger[:]),
	}, &CreatePermitReply{}), "not the ciphertext owner")
}

// TestRequestDecryptRefusesWithoutAValidPermit holds that a decryption request
// is admitted only when the permit names this ciphertext, this callback and the
// decrypt operation. This is the only gate on the request path: RequestDecrypt
// does not consult the authenticator at all, so the permit is what stands
// between a stored ciphertext and a settlement sent to the grantee.
func TestRequestDecryptRefusesWithoutAValidPermit(t *testing.T) {
	service := newTestFHEService(t)

	handle := [32]byte{9}
	grantee := [20]byte{0xcc}
	require.NoError(t, service.registry.RegisterCiphertext(&CiphertextMeta{Handle: handle, Owner: [20]byte{1}}))

	permitID := [32]byte{4}
	require.NoError(t, service.registry.CreatePermit(&Permit{
		PermitID: permitID, Handle: handle, Grantee: grantee,
		Operations: PermitOpCompute, // not decrypt
	}))

	args := &RequestDecryptArgs{
		CiphertextHandle: hex.EncodeToString(handle[:]),
		PermitID:         hex.EncodeToString(permitID[:]),
		Callback:         hex.EncodeToString(grantee[:]),
		CallbackSelector: "deadbeef",
	}
	err := service.RequestDecrypt(context.Background(), args, &RequestDecryptReply{})
	require.ErrorIs(t, err, ErrPermitInvalid)

	// A permit for a different ciphertext is refused for this one.
	otherPermit := [32]byte{5}
	require.NoError(t, service.registry.CreatePermit(&Permit{
		PermitID: otherPermit, Handle: [32]byte{99}, Grantee: grantee,
		Operations: PermitOpDecrypt,
	}))
	args.PermitID = hex.EncodeToString(otherPermit[:])
	require.ErrorIs(t, service.RequestDecrypt(context.Background(), args, &RequestDecryptReply{}), ErrPermitInvalid)

	// The right permit is admitted.
	good := [32]byte{6}
	require.NoError(t, service.registry.CreatePermit(&Permit{
		PermitID: good, Handle: handle, Grantee: grantee,
		Operations: PermitOpDecrypt,
	}))
	args.PermitID = hex.EncodeToString(good[:])
	reply := &RequestDecryptReply{}
	require.NoError(t, service.RequestDecrypt(context.Background(), args, reply))
	require.Len(t, reply.RequestID, 64)
	require.Equal(t, RequestPending.String(), reply.Status)
}

// TestRequestDecryptCarriesTheNamedSourceChain holds that a caller-supplied
// source chain is parsed and recorded, and that an unparseable one is refused
// rather than silently replaced by this chain -- the fulfillment is addressed
// back to whatever is recorded here.
func TestRequestDecryptCarriesTheNamedSourceChain(t *testing.T) {
	service := newTestFHEService(t)

	handle := [32]byte{9}
	grantee := [20]byte{0xcc}
	permitID := [32]byte{4}
	require.NoError(t, service.registry.RegisterCiphertext(&CiphertextMeta{Handle: handle}))
	require.NoError(t, service.registry.CreatePermit(&Permit{
		PermitID: permitID, Handle: handle, Grantee: grantee, Operations: PermitOpDecrypt,
	}))

	args := &RequestDecryptArgs{
		CiphertextHandle: hex.EncodeToString(handle[:]),
		PermitID:         hex.EncodeToString(permitID[:]),
		Callback:         hex.EncodeToString(grantee[:]),
		CallbackSelector: "deadbeef",
		SourceChain:      "not-a-chain-id",
	}
	require.ErrorContains(t, service.RequestDecrypt(context.Background(), args, &RequestDecryptReply{}),
		"invalid source chain")

	source := ids.GenerateTestID()
	args.SourceChain = source.String()
	args.Expiry = time.Now().Add(time.Hour).Unix()
	reply := &RequestDecryptReply{}
	require.NoError(t, service.RequestDecrypt(context.Background(), args, reply))

	raw, err := hex.DecodeString(reply.RequestID)
	require.NoError(t, err)
	stored, err := service.registry.GetDecryptRequest([32]byte(raw))
	require.NoError(t, err)
	require.Equal(t, source, stored.SourceChain)
	require.Equal(t, args.Expiry, stored.Expiry)
}

// TestUninitializedServiceRefusesEveryCall holds that a service with no
// registry answers ErrNotInitialized everywhere instead of dereferencing nil.
// These methods are reachable over the wire the moment the RPC handler is
// registered, which can happen before the registry is attached.
func TestUninitializedServiceRefusesEveryCall(t *testing.T) {
	service := &FHEService{logger: log.NewNoOpLogger()}
	ctx := context.Background()

	require.ErrorIs(t, service.GetPublicParams(ctx, &GetPublicParamsArgs{}, &GetPublicParamsReply{}), ErrNotInitialized)
	require.ErrorIs(t, service.GetCommittee(ctx, &GetCommitteeArgs{}, &GetCommitteeReply{}), ErrNotInitialized)
	require.ErrorIs(t, service.RegisterCiphertext(ctx, &RegisterCiphertextArgs{}, &RegisterCiphertextReply{}), ErrNotInitialized)
	require.ErrorIs(t, service.GetCiphertextMeta(ctx, &GetCiphertextMetaArgs{}, &GetCiphertextMetaReply{}), ErrNotInitialized)
	require.ErrorIs(t, service.RequestDecrypt(ctx, &RequestDecryptArgs{}, &RequestDecryptReply{}), ErrNotInitialized)
	require.ErrorIs(t, service.GetDecryptResult(ctx, &GetDecryptResultArgs{}, &GetDecryptResultReply{}), ErrNotInitialized)
	require.ErrorIs(t, service.GetRequestReceipt(ctx, &GetRequestReceiptArgs{}, &GetRequestReceiptReply{}), ErrNotInitialized)
	require.ErrorIs(t, service.CreatePermit(ctx, &CreatePermitArgs{}, &CreatePermitReply{}), ErrNotInitialized)
	require.ErrorIs(t, service.VerifyPermit(ctx, &VerifyPermitArgs{}, &VerifyPermitReply{}), ErrNotInitialized)
}

// TestGetPublicParamsNeedsAnEpoch holds that the parameters a client encrypts
// against are reported only when there is an epoch to report them for. Serving
// a zero threshold and an empty public key would have clients encrypt to
// nothing.
func TestGetPublicParamsNeedsAnEpoch(t *testing.T) {
	registry, err := NewRegistry(memdb.New())
	require.NoError(t, err)
	service := &FHEService{registry: registry, logger: log.NewNoOpLogger()}

	require.ErrorContains(t,
		service.GetPublicParams(context.Background(), &GetPublicParamsArgs{}, &GetPublicParamsReply{}),
		"failed to get epoch info")
}

// TestGetCiphertextMetaRejectsMalformedHandles holds that a handle that is not
// 32 hex-encoded bytes is refused before it reaches storage, so a short handle
// cannot be zero-extended into a different, existing one.
func TestGetCiphertextMetaRejectsMalformedHandles(t *testing.T) {
	service := newTestFHEService(t)
	for _, handle := range []string{"", "zz", hex.EncodeToString(make([]byte, 31)), hex.EncodeToString(make([]byte, 33))} {
		require.ErrorIs(t,
			service.GetCiphertextMeta(context.Background(), &GetCiphertextMetaArgs{Handle: handle}, &GetCiphertextMetaReply{}),
			ErrInvalidHandle, "handle %q", handle)
	}
}

// TestRegistryFailuresReachTheRPCCaller holds that a store that cannot write is
// reported to the caller rather than answered with a success. A client that
// believes a ciphertext is registered will go on to request its decryption.
func TestRegistryFailuresReachTheRPCCaller(t *testing.T) {
	registry, db := newFaultyRegistry(t)
	service := &FHEService{registry: registry, logger: log.NewNoOpLogger(), chainID: ids.GenerateTestID()}

	handle := make([]byte, 32)
	require.NoError(t, registry.RegisterCiphertext(&CiphertextMeta{Handle: [32]byte(handle)}))
	permitID := [32]byte{1}
	require.NoError(t, registry.CreatePermit(&Permit{
		PermitID: permitID, Handle: [32]byte(handle), Operations: PermitOpDecrypt,
	}))

	db.refusePut = always
	require.ErrorContains(t, service.RegisterCiphertext(context.Background(), &RegisterCiphertextArgs{
		Handle: hex.EncodeToString(handle),
		Owner:  hex.EncodeToString(make([]byte, 20)),
	}, &RegisterCiphertextReply{}), "failed to register ciphertext")

	require.ErrorContains(t, service.RequestDecrypt(context.Background(), &RequestDecryptArgs{
		CiphertextHandle: hex.EncodeToString(handle),
		PermitID:         hex.EncodeToString(permitID[:]),
		Callback:         hex.EncodeToString(make([]byte, 20)),
		CallbackSelector: "deadbeef",
	}, &RequestDecryptReply{}), "failed to create request")

	require.ErrorContains(t, service.CreatePermit(context.Background(), &CreatePermitArgs{
		Handle:  hex.EncodeToString(handle),
		Grantee: hex.EncodeToString(make([]byte, 20)),
		Grantor: hex.EncodeToString(make([]byte, 20)),
	}, &CreatePermitReply{}), "failed to create permit")
}

// TestGetDecryptResultReportsTheResultHandleOnlyWhenCompleted holds that the
// result handle appears exactly when the request is completed. Reporting the
// zero handle on a pending request would have a caller fetch ciphertext 0x00.
func TestGetDecryptResultReportsTheResultHandleOnlyWhenCompleted(t *testing.T) {
	service := newTestFHEService(t)

	requestID := [32]byte{7}
	require.NoError(t, service.registry.CreateDecryptRequest(&DecryptRequest{RequestID: requestID}))

	reply := &GetDecryptResultReply{}
	require.NoError(t, service.GetDecryptResult(context.Background(),
		&GetDecryptResultArgs{RequestID: hex.EncodeToString(requestID[:])}, reply))
	require.Equal(t, RequestPending.String(), reply.Status)
	require.Empty(t, reply.ResultHandle)

	resultHandle := [32]byte{0xab}
	require.NoError(t, service.registry.UpdateDecryptRequest(requestID, RequestCompleted, resultHandle, ""))

	reply = &GetDecryptResultReply{}
	require.NoError(t, service.GetDecryptResult(context.Background(),
		&GetDecryptResultArgs{RequestID: hex.EncodeToString(requestID[:])}, reply))
	require.Equal(t, RequestCompleted.String(), reply.Status)
	require.Equal(t, hex.EncodeToString(resultHandle[:]), reply.ResultHandle)
	require.NotZero(t, reply.CompletedAt)
}

// TestBatchCallsAreBoundedAndFailAsAUnit holds two properties of the batch
// entry points: neither will accept more than MaxBatchSize, and a batch of
// requests fails at the first bad member rather than half-applying. The read
// batch is deliberately the other way around -- one unknown id must not hide
// the results of the others -- so both shapes are pinned here.
func TestBatchCallsAreBoundedAndFailAsAUnit(t *testing.T) {
	service := newTestFHEService(t)
	ctx := context.Background()

	oversized := make([]RequestDecryptArgs, MaxBatchSize+1)
	require.ErrorIs(t, service.RequestDecryptBatch(ctx, &RequestDecryptBatchArgs{Requests: oversized},
		&RequestDecryptBatchReply{}), ErrBatchTooLarge)

	oversizedIDs := make([]string, MaxBatchSize+1)
	require.ErrorIs(t, service.GetDecryptBatchResult(ctx, &GetDecryptBatchResultArgs{RequestIDs: oversizedIDs},
		&GetDecryptBatchResultReply{}), ErrBatchTooLarge)

	require.ErrorContains(t, service.RequestDecryptBatch(ctx, &RequestDecryptBatchArgs{
		Requests: []RequestDecryptArgs{{CiphertextHandle: "not hex"}},
	}, &RequestDecryptBatchReply{}), "request 0 failed")

	// A read batch reports per-entry failures inside the results.
	reply := &GetDecryptBatchResultReply{}
	require.NoError(t, service.GetDecryptBatchResult(ctx,
		&GetDecryptBatchResultArgs{RequestIDs: []string{hex.EncodeToString(make([]byte, 32))}}, reply))
	require.Len(t, reply.Results, 1)
	require.NotEmpty(t, reply.Results[0].Error)
}
