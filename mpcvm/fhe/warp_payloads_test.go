// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func TestFHEDecryptRequestV1BytesAndParse(t *testing.T) {
	require := require.New(t)

	var requestID [32]byte
	copy(requestID[:], []byte("request-id-12345678901234567"))

	var ctHandle [32]byte
	copy(ctHandle[:], []byte("ciphertext-handle-1234567890"))

	var permitID [32]byte
	copy(permitID[:], []byte("permit-id-12345678901234567"))

	var requester [20]byte
	copy(requester[:], []byte("requester12345678"))

	var callback [20]byte
	copy(callback[:], []byte("callback-address12"))

	var selector [4]byte
	copy(selector[:], []byte{0xAB, 0xCD, 0xEF, 0x12})

	request := &FHEDecryptRequestV1{
		RequestID:        requestID,
		CiphertextHandle: ctHandle,
		PermitID:         permitID,
		SourceChainID:    ids.GenerateTestID(),
		Epoch:            1,
		Nonce:            100,
		Expiry:           time.Now().Add(time.Hour).Unix(),
		Requester:        requester,
		Callback:         callback,
		CallbackSelector: selector,
		GasLimit:         1000000,
	}

	// Serialize
	data := request.Bytes()
	require.Len(data, 202)

	// Parse back
	parsed, err := ParseFHEDecryptRequestV1(data)
	require.NoError(err)

	require.Equal(request.RequestID, parsed.RequestID)
	require.Equal(request.CiphertextHandle, parsed.CiphertextHandle)
	require.Equal(request.PermitID, parsed.PermitID)
	require.Equal(request.SourceChainID, parsed.SourceChainID)
	require.Equal(request.Epoch, parsed.Epoch)
	require.Equal(request.Nonce, parsed.Nonce)
	require.Equal(request.Expiry, parsed.Expiry)
	require.Equal(request.Requester, parsed.Requester)
	require.Equal(request.Callback, parsed.Callback)
	require.Equal(request.CallbackSelector, parsed.CallbackSelector)
	require.Equal(request.GasLimit, parsed.GasLimit)
}

func TestFHEDecryptResultV1BytesAndParse(t *testing.T) {
	require := require.New(t)

	var requestID [32]byte
	copy(requestID[:], []byte("request-id-12345678901234567"))

	var resultHandle [32]byte
	copy(resultHandle[:], []byte("result-handle-12345678901234"))

	var signature [32]byte
	copy(signature[:], []byte("committee-signature-12345678"))

	result := &FHEDecryptResultV1{
		RequestID:          requestID,
		ResultHandle:       resultHandle,
		SourceChainID:      ids.GenerateTestID(),
		Epoch:              1,
		Status:             DecryptStatusSuccess,
		CommitteeSignature: signature,
		Plaintext:          []byte("decrypted-plaintext-data"),
	}

	// Serialize
	data := result.Bytes()
	require.NotEmpty(data)

	// Parse back
	parsed, err := ParseFHEDecryptResultV1(data)
	require.NoError(err)

	require.Equal(result.RequestID, parsed.RequestID)
	require.Equal(result.ResultHandle, parsed.ResultHandle)
	require.Equal(result.SourceChainID, parsed.SourceChainID)
	require.Equal(result.Epoch, parsed.Epoch)
	require.Equal(result.Status, parsed.Status)
	require.Equal(result.CommitteeSignature, parsed.CommitteeSignature)
	require.Equal(result.Plaintext, parsed.Plaintext)
}

func TestFHEDecryptResultV1Failed(t *testing.T) {
	require := require.New(t)

	var requestID [32]byte
	copy(requestID[:], []byte("request-id-12345678901234567"))

	result := &FHEDecryptResultV1{
		RequestID:     requestID,
		SourceChainID: ids.GenerateTestID(),
		Epoch:         1,
		Status:        DecryptStatusFailed,
		Plaintext:     nil,
	}

	data := result.Bytes()
	parsed, err := ParseFHEDecryptResultV1(data)
	require.NoError(err)

	require.Equal(DecryptStatusFailed, parsed.Status)
	require.Empty(parsed.Plaintext)
}

func TestFHEReencryptRequestV1BytesAndParse(t *testing.T) {
	require := require.New(t)

	var requestID [32]byte
	copy(requestID[:], []byte("request-id-12345678901234567"))

	var ctHandle [32]byte
	copy(ctHandle[:], []byte("ciphertext-handle-1234567890"))

	var permitID [32]byte
	copy(permitID[:], []byte("permit-id-12345678901234567"))

	var recipient [20]byte
	copy(recipient[:], []byte("recipient12345678"))

	request := &FHEReencryptRequestV1{
		RequestID:          requestID,
		CiphertextHandle:   ctHandle,
		PermitID:           permitID,
		SourceChainID:      ids.GenerateTestID(),
		Epoch:              1,
		Recipient:          recipient,
		RecipientPublicKey: []byte("recipient-public-key-data-here"),
	}

	// Serialize
	data := request.Bytes()
	require.NotEmpty(data)

	// Parse back
	parsed, err := ParseFHEReencryptRequestV1(data)
	require.NoError(err)

	require.Equal(request.RequestID, parsed.RequestID)
	require.Equal(request.CiphertextHandle, parsed.CiphertextHandle)
	require.Equal(request.PermitID, parsed.PermitID)
	require.Equal(request.SourceChainID, parsed.SourceChainID)
	require.Equal(request.Epoch, parsed.Epoch)
	require.Equal(request.Recipient, parsed.Recipient)
	require.Equal(request.RecipientPublicKey, parsed.RecipientPublicKey)
}

func TestFHETaskResultV1BytesAndParse(t *testing.T) {
	require := require.New(t)

	var taskID [32]byte
	copy(taskID[:], []byte("task-id-123456789012345678901"))

	var resultHandle [32]byte
	copy(resultHandle[:], []byte("result-handle-12345678901234"))

	var callback [20]byte
	copy(callback[:], []byte("callback-address12"))

	var selector [4]byte
	copy(selector[:], []byte{0xAB, 0xCD, 0xEF, 0x12})

	var signature [32]byte
	copy(signature[:], []byte("signature-data-12345678901234"))

	result := &FHETaskResultV1{
		TaskID:           taskID,
		ResultHandle:     resultHandle,
		SourceChainID:    ids.GenerateTestID(),
		Epoch:            1,
		Status:           TaskStatusCompleted,
		Callback:         callback,
		CallbackSelector: selector,
		Signature:        signature,
	}

	// Serialize
	data := result.Bytes()
	require.Len(data, 163)

	// Parse back
	parsed, err := ParseFHETaskResultV1(data)
	require.NoError(err)

	require.Equal(result.TaskID, parsed.TaskID)
	require.Equal(result.ResultHandle, parsed.ResultHandle)
	require.Equal(result.SourceChainID, parsed.SourceChainID)
	require.Equal(result.Epoch, parsed.Epoch)
	require.Equal(result.Status, parsed.Status)
	require.Equal(result.Callback, parsed.Callback)
	require.Equal(result.CallbackSelector, parsed.CallbackSelector)
	require.Equal(result.Signature, parsed.Signature)
}

func TestDecryptStatusConstants(t *testing.T) {
	require := require.New(t)

	require.Equal(uint8(0x00), DecryptStatusSuccess)
	require.Equal(uint8(0x01), DecryptStatusFailed)
	require.Equal(uint8(0x02), DecryptStatusExpired)
	require.Equal(uint8(0x03), DecryptStatusDenied)
}

func TestTaskStatusConstants(t *testing.T) {
	require := require.New(t)

	require.Equal(uint8(0x00), TaskStatusCompleted)
	require.Equal(uint8(0x01), TaskStatusFailed)
	require.Equal(uint8(0x02), TaskStatusTimeout)
}

func TestPayloadVersionAndTypeConstants(t *testing.T) {
	require := require.New(t)

	require.Equal(uint8(0x01), PayloadVersionV1)
	require.Equal(uint8(0x01), PayloadTypeFHEDecryptRequestV1)
	require.Equal(uint8(0x02), PayloadTypeFHEDecryptResultV1)
	require.Equal(uint8(0x03), PayloadTypeFHEReencryptRequestV1)
	require.Equal(uint8(0x04), PayloadTypeFHETaskResultV1)
	require.Equal(uint8(0x05), PayloadTypeFHEKeyRotationV1)
}

func TestParseInvalidPayload(t *testing.T) {
	require := require.New(t)

	// Too short
	_, err := ParseFHEDecryptRequestV1([]byte{0x01, 0x02})
	require.Error(err)

	// Invalid version
	data := make([]byte, 202)
	data[0] = 0xFF
	_, err = ParseFHEDecryptRequestV1(data)
	require.Error(err)

	// Invalid type
	data[0] = PayloadVersionV1
	data[1] = 0xFF
	_, err = ParseFHEDecryptRequestV1(data)
	require.Error(err)
}

func TestFHEKeyRotationV1BytesAndParse(t *testing.T) {
	require := require.New(t)

	rotation := &FHEKeyRotationV1{
		OldEpoch:      1,
		NewEpoch:      2,
		NewThreshold:  67,
		CommitteeSize: 10,
		NewPublicKey:  []byte("new-public-key-data-here-32bytes"),
	}

	// Serialize
	data := rotation.Bytes()
	require.NotEmpty(data)

	// Parse back
	parsed, err := ParseFHEKeyRotationV1(data)
	require.NoError(err)

	require.Equal(rotation.OldEpoch, parsed.OldEpoch)
	require.Equal(rotation.NewEpoch, parsed.NewEpoch)
	require.Equal(rotation.NewThreshold, parsed.NewThreshold)
	require.Equal(rotation.CommitteeSize, parsed.CommitteeSize)
	require.Equal(rotation.NewPublicKey, parsed.NewPublicKey)
}

func TestFHEKeyRotationV1EmptyPublicKey(t *testing.T) {
	require := require.New(t)

	rotation := &FHEKeyRotationV1{
		OldEpoch:      1,
		NewEpoch:      2,
		NewThreshold:  67,
		CommitteeSize: 10,
		NewPublicKey:  []byte{}, // Empty
	}

	data := rotation.Bytes()
	parsed, err := ParseFHEKeyRotationV1(data)
	require.NoError(err)
	require.Empty(parsed.NewPublicKey)
}

func TestParsePayloadAllTypes(t *testing.T) {
	require := require.New(t)

	// Test FHEDecryptRequestV1
	var requestID [32]byte
	copy(requestID[:], []byte("request-id-12345678901234567"))
	var ctHandle [32]byte
	copy(ctHandle[:], []byte("ciphertext-handle-1234567890"))
	var permitID [32]byte
	copy(permitID[:], []byte("permit-id-12345678901234567"))
	var requester [20]byte
	copy(requester[:], []byte("requester12345678"))
	var callback [20]byte
	copy(callback[:], []byte("callback-address12"))
	var selector [4]byte
	copy(selector[:], []byte{0xAB, 0xCD, 0xEF, 0x12})

	request := &FHEDecryptRequestV1{
		RequestID:        requestID,
		CiphertextHandle: ctHandle,
		PermitID:         permitID,
		SourceChainID:    ids.GenerateTestID(),
		Epoch:            1,
		Nonce:            100,
		Expiry:           time.Now().Add(time.Hour).Unix(), // Future expiry to pass validation
		Requester:        requester,
		Callback:         callback,
		CallbackSelector: selector,
		GasLimit:         1000000,
	}
	data := request.Bytes()
	payloadType, parsed, err := ParsePayload(data)
	require.NoError(err)
	require.Equal(PayloadTypeFHEDecryptRequestV1, payloadType)
	require.NotNil(parsed)
	parsedReq := parsed.(*FHEDecryptRequestV1)
	require.Equal(request.RequestID, parsedReq.RequestID)

	// Test FHEDecryptResultV1
	var resultHandle [32]byte
	copy(resultHandle[:], []byte("result-handle-12345678901234"))
	var signature [32]byte
	copy(signature[:], []byte("committee-signature-12345678"))

	result := &FHEDecryptResultV1{
		RequestID:          requestID,
		ResultHandle:       resultHandle,
		SourceChainID:      ids.GenerateTestID(),
		Epoch:              1,
		Status:             DecryptStatusSuccess,
		CommitteeSignature: signature,
		Plaintext:          []byte("plaintext"),
	}
	data = result.Bytes()
	payloadType, parsed, err = ParsePayload(data)
	require.NoError(err)
	require.Equal(PayloadTypeFHEDecryptResultV1, payloadType)
	require.NotNil(parsed)

	// Test FHEReencryptRequestV1
	var recipient [20]byte
	copy(recipient[:], []byte("recipient12345678"))
	reencrypt := &FHEReencryptRequestV1{
		RequestID:          requestID,
		CiphertextHandle:   ctHandle,
		PermitID:           permitID,
		SourceChainID:      ids.GenerateTestID(),
		Epoch:              1,
		Recipient:          recipient,
		RecipientPublicKey: []byte("pubkey"),
	}
	data = reencrypt.Bytes()
	payloadType, parsed, err = ParsePayload(data)
	require.NoError(err)
	require.Equal(PayloadTypeFHEReencryptRequestV1, payloadType)
	require.NotNil(parsed)

	// Test FHETaskResultV1
	var taskID [32]byte
	copy(taskID[:], []byte("task-id-123456789012345678901"))
	var taskSig [32]byte
	copy(taskSig[:], []byte("signature-data-12345678901234"))
	taskResult := &FHETaskResultV1{
		TaskID:           taskID,
		ResultHandle:     resultHandle,
		SourceChainID:    ids.GenerateTestID(),
		Epoch:            1,
		Status:           TaskStatusCompleted,
		Callback:         callback,
		CallbackSelector: selector,
		Signature:        taskSig,
	}
	data = taskResult.Bytes()
	payloadType, parsed, err = ParsePayload(data)
	require.NoError(err)
	require.Equal(PayloadTypeFHETaskResultV1, payloadType)
	require.NotNil(parsed)

	// Test FHEKeyRotationV1
	rotation := &FHEKeyRotationV1{
		OldEpoch:      1,
		NewEpoch:      2,
		NewThreshold:  67,
		CommitteeSize: 10,
		NewPublicKey:  []byte("new-public-key"),
	}
	data = rotation.Bytes()
	payloadType, parsed, err = ParsePayload(data)
	require.NoError(err)
	require.Equal(PayloadTypeFHEKeyRotationV1, payloadType)
	require.NotNil(parsed)
}

func TestParsePayloadUnknownType(t *testing.T) {
	require := require.New(t)

	data := []byte{PayloadVersionV1, 0xFF} // Unknown type
	_, _, err := ParsePayload(data)
	require.ErrorIs(err, ErrInvalidPayloadType)
}

func TestParsePayloadTooShort(t *testing.T) {
	require := require.New(t)

	// Less than 2 bytes
	_, _, err := ParsePayload([]byte{0x01})
	require.ErrorIs(err, ErrPayloadTooShort)

	_, _, err = ParsePayload([]byte{})
	require.ErrorIs(err, ErrPayloadTooShort)
}

func TestParsePayloadInvalidVersion(t *testing.T) {
	require := require.New(t)

	data := []byte{0xFF, PayloadTypeFHEDecryptRequestV1}
	_, _, err := ParsePayload(data)
	require.Error(err)
	require.Contains(err.Error(), "invalid payload version")
}

func TestParseFHEDecryptResultV1TooLargePayload(t *testing.T) {
	require := require.New(t)

	// Create a valid header but claim a huge plaintext length
	data := make([]byte, 143)
	data[0] = PayloadVersionV1
	data[1] = PayloadTypeFHEDecryptResultV1

	// Set plaintext length to a huge value (at offset 139)
	data[139] = 0xFF
	data[140] = 0xFF
	data[141] = 0xFF
	data[142] = 0xFF // 4GB plaintext length

	_, err := ParseFHEDecryptResultV1(data)
	require.ErrorIs(err, ErrPayloadMalformed)
}

func TestParseFHEReencryptRequestV1PublicKeyTooLarge(t *testing.T) {
	require := require.New(t)

	// Create a valid header but claim a huge public key length
	data := make([]byte, 162)
	data[0] = PayloadVersionV1
	data[1] = PayloadTypeFHEReencryptRequestV1

	// Set public key length to a huge value (at offset 158)
	data[158] = 0xFF
	data[159] = 0xFF
	data[160] = 0xFF
	data[161] = 0xFF // 4GB key length

	_, err := ParseFHEReencryptRequestV1(data)
	require.ErrorIs(err, ErrPayloadMalformed)
}

func TestParseFHEKeyRotationV1PublicKeyTooLarge(t *testing.T) {
	require := require.New(t)

	// Create a valid header but claim a huge public key length
	data := make([]byte, 30)
	data[0] = PayloadVersionV1
	data[1] = PayloadTypeFHEKeyRotationV1

	// Set public key length to a huge value (at offset 26)
	data[26] = 0xFF
	data[27] = 0xFF
	data[28] = 0xFF
	data[29] = 0xFF // 4GB key length

	_, err := ParseFHEKeyRotationV1(data)
	require.ErrorIs(err, ErrPayloadMalformed)
}

func TestParseFHEDecryptResultV1TooShort(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 100) // Less than 143
	data[0] = PayloadVersionV1
	data[1] = PayloadTypeFHEDecryptResultV1

	_, err := ParseFHEDecryptResultV1(data)
	require.ErrorIs(err, ErrPayloadTooShort)
}

func TestParseFHEReencryptRequestV1TooShort(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 100) // Less than 162
	data[0] = PayloadVersionV1
	data[1] = PayloadTypeFHEReencryptRequestV1

	_, err := ParseFHEReencryptRequestV1(data)
	require.ErrorIs(err, ErrPayloadTooShort)
}

func TestParseFHETaskResultV1TooShort(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 100) // Less than 163
	data[0] = PayloadVersionV1
	data[1] = PayloadTypeFHETaskResultV1

	_, err := ParseFHETaskResultV1(data)
	require.ErrorIs(err, ErrPayloadTooShort)
}

func TestParseFHEKeyRotationV1TooShort(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 20) // Less than 30
	data[0] = PayloadVersionV1
	data[1] = PayloadTypeFHEKeyRotationV1

	_, err := ParseFHEKeyRotationV1(data)
	require.ErrorIs(err, ErrPayloadTooShort)
}

func TestParseFHEDecryptResultV1InvalidVersion(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 143)
	data[0] = 0xFF // Invalid version
	data[1] = PayloadTypeFHEDecryptResultV1

	_, err := ParseFHEDecryptResultV1(data)
	require.ErrorIs(err, ErrInvalidPayloadVersion)
}

func TestParseFHEReencryptRequestV1InvalidVersion(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 162)
	data[0] = 0xFF // Invalid version
	data[1] = PayloadTypeFHEReencryptRequestV1

	_, err := ParseFHEReencryptRequestV1(data)
	require.ErrorIs(err, ErrInvalidPayloadVersion)
}

func TestParseFHETaskResultV1InvalidVersion(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 163)
	data[0] = 0xFF // Invalid version
	data[1] = PayloadTypeFHETaskResultV1

	_, err := ParseFHETaskResultV1(data)
	require.ErrorIs(err, ErrInvalidPayloadVersion)
}

func TestParseFHEKeyRotationV1InvalidVersion(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 30)
	data[0] = 0xFF // Invalid version
	data[1] = PayloadTypeFHEKeyRotationV1

	_, err := ParseFHEKeyRotationV1(data)
	require.ErrorIs(err, ErrInvalidPayloadVersion)
}

func TestParseFHEDecryptResultV1InvalidType(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 143)
	data[0] = PayloadVersionV1
	data[1] = 0xFF // Invalid type

	_, err := ParseFHEDecryptResultV1(data)
	require.ErrorIs(err, ErrInvalidPayloadType)
}

func TestParseFHEReencryptRequestV1InvalidType(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 162)
	data[0] = PayloadVersionV1
	data[1] = 0xFF // Invalid type

	_, err := ParseFHEReencryptRequestV1(data)
	require.ErrorIs(err, ErrInvalidPayloadType)
}

func TestParseFHETaskResultV1InvalidType(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 163)
	data[0] = PayloadVersionV1
	data[1] = 0xFF // Invalid type

	_, err := ParseFHETaskResultV1(data)
	require.ErrorIs(err, ErrInvalidPayloadType)
}

func TestParseFHEKeyRotationV1InvalidType(t *testing.T) {
	require := require.New(t)

	data := make([]byte, 30)
	data[0] = PayloadVersionV1
	data[1] = 0xFF // Invalid type

	_, err := ParseFHEKeyRotationV1(data)
	require.ErrorIs(err, ErrInvalidPayloadType)
}

func TestFHEDecryptRequestV1Validate(t *testing.T) {
	require := require.New(t)

	// Test valid request with future expiry
	request := &FHEDecryptRequestV1{
		Expiry: time.Now().Add(time.Hour).Unix(),
	}
	require.NoError(request.Validate())

	// Test valid request with zero expiry (no expiration)
	request = &FHEDecryptRequestV1{
		Expiry: 0,
	}
	require.NoError(request.Validate())

	// Test expired request
	request = &FHEDecryptRequestV1{
		Expiry: time.Now().Add(-time.Hour).Unix(), // 1 hour in the past
	}
	require.ErrorIs(request.Validate(), ErrRequestExpired)
}

func TestParsePayloadRejectsExpiredRequest(t *testing.T) {
	require := require.New(t)

	var requestID [32]byte
	copy(requestID[:], []byte("request-id-12345678901234567"))
	var ctHandle [32]byte
	copy(ctHandle[:], []byte("ciphertext-handle-1234567890"))
	var permitID [32]byte
	copy(permitID[:], []byte("permit-id-12345678901234567"))
	var requester [20]byte
	copy(requester[:], []byte("requester12345678"))
	var callback [20]byte
	copy(callback[:], []byte("callback-address12"))
	var selector [4]byte
	copy(selector[:], []byte{0xAB, 0xCD, 0xEF, 0x12})

	// Create an expired request
	request := &FHEDecryptRequestV1{
		RequestID:        requestID,
		CiphertextHandle: ctHandle,
		PermitID:         permitID,
		SourceChainID:    ids.GenerateTestID(),
		Epoch:            1,
		Nonce:            100,
		Expiry:           time.Now().Add(-time.Hour).Unix(), // Expired
		Requester:        requester,
		Callback:         callback,
		CallbackSelector: selector,
		GasLimit:         1000000,
	}

	data := request.Bytes()
	_, _, err := ParsePayload(data)
	require.ErrorIs(err, ErrRequestExpired)
}

func TestParsePayloadAcceptsValidRequest(t *testing.T) {
	require := require.New(t)

	var requestID [32]byte
	copy(requestID[:], []byte("request-id-12345678901234567"))
	var ctHandle [32]byte
	copy(ctHandle[:], []byte("ciphertext-handle-1234567890"))
	var permitID [32]byte
	copy(permitID[:], []byte("permit-id-12345678901234567"))
	var requester [20]byte
	copy(requester[:], []byte("requester12345678"))
	var callback [20]byte
	copy(callback[:], []byte("callback-address12"))
	var selector [4]byte
	copy(selector[:], []byte{0xAB, 0xCD, 0xEF, 0x12})

	// Create a valid request with future expiry
	request := &FHEDecryptRequestV1{
		RequestID:        requestID,
		CiphertextHandle: ctHandle,
		PermitID:         permitID,
		SourceChainID:    ids.GenerateTestID(),
		Epoch:            1,
		Nonce:            100,
		Expiry:           time.Now().Add(time.Hour).Unix(), // Valid
		Requester:        requester,
		Callback:         callback,
		CallbackSelector: selector,
		GasLimit:         1000000,
	}

	data := request.Bytes()
	payloadType, parsed, err := ParsePayload(data)
	require.NoError(err)
	require.Equal(PayloadTypeFHEDecryptRequestV1, payloadType)
	require.NotNil(parsed)
}

func TestParsePayloadAcceptsNoExpiryRequest(t *testing.T) {
	require := require.New(t)

	var requestID [32]byte
	copy(requestID[:], []byte("request-id-12345678901234567"))
	var ctHandle [32]byte
	copy(ctHandle[:], []byte("ciphertext-handle-1234567890"))
	var permitID [32]byte
	copy(permitID[:], []byte("permit-id-12345678901234567"))
	var requester [20]byte
	copy(requester[:], []byte("requester12345678"))
	var callback [20]byte
	copy(callback[:], []byte("callback-address12"))
	var selector [4]byte
	copy(selector[:], []byte{0xAB, 0xCD, 0xEF, 0x12})

	// Create a request with no expiry (0 means never expires)
	request := &FHEDecryptRequestV1{
		RequestID:        requestID,
		CiphertextHandle: ctHandle,
		PermitID:         permitID,
		SourceChainID:    ids.GenerateTestID(),
		Epoch:            1,
		Nonce:            100,
		Expiry:           0, // No expiration
		Requester:        requester,
		Callback:         callback,
		CallbackSelector: selector,
		GasLimit:         1000000,
	}

	data := request.Bytes()
	payloadType, parsed, err := ParsePayload(data)
	require.NoError(err)
	require.Equal(PayloadTypeFHEDecryptRequestV1, payloadType)
	require.NotNil(parsed)
}
