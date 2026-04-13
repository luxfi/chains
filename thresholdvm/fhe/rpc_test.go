// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"encoding/hex"
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
