// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/ids"
)

// Warp payload type identifiers (versioned)
const (
	// V1 payload types
	PayloadTypeFHEDecryptRequestV1   uint8 = 0x01
	PayloadTypeFHEDecryptResultV1    uint8 = 0x02
	PayloadTypeFHEReencryptRequestV1 uint8 = 0x03
	PayloadTypeFHETaskResultV1       uint8 = 0x04
	PayloadTypeFHEKeyRotationV1      uint8 = 0x05

	// Version byte
	PayloadVersionV1 uint8 = 0x01
)

var (
	ErrInvalidPayloadVersion = errors.New("invalid payload version")
	ErrInvalidPayloadType    = errors.New("invalid payload type")
	ErrPayloadTooShort       = errors.New("payload too short")
	ErrPayloadMalformed      = errors.New("payload malformed")
	ErrRequestExpired        = errors.New("request has expired")
)

// =====================
// FHE_DECRYPT_REQUEST_V1
// =====================

// FHEDecryptRequestV1 is the canonical Warp payload for decrypt requests
// Wire format:
//
//	[0]:     version (1 byte)
//	[1]:     type (1 byte)
//	[2:34]:  request_id (32 bytes)
//	[34:66]: ciphertext_handle (32 bytes)
//	[66:98]: permit_id (32 bytes)
//	[98:130]: source_chain_id (32 bytes)
//	[130:138]: epoch (8 bytes)
//	[138:146]: nonce (8 bytes)
//	[146:154]: expiry (8 bytes)
//	[154:174]: requester (20 bytes)
//	[174:194]: callback (20 bytes)
//	[194:198]: callback_selector (4 bytes)
//	[198:202]: gas_limit (4 bytes)
type FHEDecryptRequestV1 struct {
	RequestID        [32]byte
	CiphertextHandle [32]byte
	PermitID         [32]byte
	SourceChainID    ids.ID
	Epoch            uint64
	Nonce            uint64
	Expiry           int64
	Requester        [20]byte
	Callback         [20]byte
	CallbackSelector [4]byte
	GasLimit         uint32
}

// Bytes serializes the request to wire format
func (r *FHEDecryptRequestV1) Bytes() []byte {
	buf := make([]byte, 202)
	offset := 0

	buf[offset] = PayloadVersionV1
	offset++
	buf[offset] = PayloadTypeFHEDecryptRequestV1
	offset++

	copy(buf[offset:], r.RequestID[:])
	offset += 32
	copy(buf[offset:], r.CiphertextHandle[:])
	offset += 32
	copy(buf[offset:], r.PermitID[:])
	offset += 32
	copy(buf[offset:], r.SourceChainID[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:], r.Epoch)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], r.Nonce)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], uint64(r.Expiry))
	offset += 8

	copy(buf[offset:], r.Requester[:])
	offset += 20
	copy(buf[offset:], r.Callback[:])
	offset += 20
	copy(buf[offset:], r.CallbackSelector[:])
	offset += 4

	binary.BigEndian.PutUint32(buf[offset:], r.GasLimit)

	return buf
}

// Validate checks if the request is valid and not expired.
// An Expiry of 0 means no expiration (infinite validity).
func (r *FHEDecryptRequestV1) Validate() error {
	if r.Expiry > 0 && time.Now().Unix() > r.Expiry {
		return ErrRequestExpired
	}
	return nil
}

// ParseFHEDecryptRequestV1 parses a decrypt request from wire format
func ParseFHEDecryptRequestV1(data []byte) (*FHEDecryptRequestV1, error) {
	if len(data) < 202 {
		return nil, ErrPayloadTooShort
	}

	if data[0] != PayloadVersionV1 {
		return nil, ErrInvalidPayloadVersion
	}
	if data[1] != PayloadTypeFHEDecryptRequestV1 {
		return nil, ErrInvalidPayloadType
	}

	r := &FHEDecryptRequestV1{}
	offset := 2

	copy(r.RequestID[:], data[offset:])
	offset += 32
	copy(r.CiphertextHandle[:], data[offset:])
	offset += 32
	copy(r.PermitID[:], data[offset:])
	offset += 32
	copy(r.SourceChainID[:], data[offset:])
	offset += 32

	r.Epoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	r.Nonce = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	r.Expiry = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	copy(r.Requester[:], data[offset:])
	offset += 20
	copy(r.Callback[:], data[offset:])
	offset += 20
	copy(r.CallbackSelector[:], data[offset:])
	offset += 4

	r.GasLimit = binary.BigEndian.Uint32(data[offset:])

	return r, nil
}

// =====================
// FHE_DECRYPT_RESULT_V1
// =====================

// FHEDecryptResultV1 is the canonical Warp payload for decrypt results
// Wire format:
//
//	[0]:      version (1 byte)
//	[1]:      type (1 byte)
//	[2:34]:   request_id (32 bytes)
//	[34:66]:  result_handle (32 bytes)
//	[66:98]:  source_chain_id (32 bytes)
//	[98:106]: epoch (8 bytes)
//	[106]:    status (1 byte)
//	[107:139]: committee_signature (32 bytes) - aggregated BLS signature
//	[139:143]: plaintext_len (4 bytes)
//	[143:...]: plaintext (variable)
type FHEDecryptResultV1 struct {
	RequestID          [32]byte
	ResultHandle       [32]byte
	SourceChainID      ids.ID
	Epoch              uint64
	Status             uint8
	CommitteeSignature [32]byte
	Plaintext          []byte
}

const (
	DecryptStatusSuccess uint8 = 0x00
	DecryptStatusFailed  uint8 = 0x01
	DecryptStatusExpired uint8 = 0x02
	DecryptStatusDenied  uint8 = 0x03
)

// Bytes serializes the result to wire format
func (r *FHEDecryptResultV1) Bytes() []byte {
	buf := make([]byte, 143+len(r.Plaintext))
	offset := 0

	buf[offset] = PayloadVersionV1
	offset++
	buf[offset] = PayloadTypeFHEDecryptResultV1
	offset++

	copy(buf[offset:], r.RequestID[:])
	offset += 32
	copy(buf[offset:], r.ResultHandle[:])
	offset += 32
	copy(buf[offset:], r.SourceChainID[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:], r.Epoch)
	offset += 8

	buf[offset] = r.Status
	offset++

	copy(buf[offset:], r.CommitteeSignature[:])
	offset += 32

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(r.Plaintext)))
	offset += 4

	copy(buf[offset:], r.Plaintext)

	return buf
}

// ParseFHEDecryptResultV1 parses a decrypt result from wire format
func ParseFHEDecryptResultV1(data []byte) (*FHEDecryptResultV1, error) {
	if len(data) < 143 {
		return nil, ErrPayloadTooShort
	}

	if data[0] != PayloadVersionV1 {
		return nil, ErrInvalidPayloadVersion
	}
	if data[1] != PayloadTypeFHEDecryptResultV1 {
		return nil, ErrInvalidPayloadType
	}

	r := &FHEDecryptResultV1{}
	offset := 2

	copy(r.RequestID[:], data[offset:])
	offset += 32
	copy(r.ResultHandle[:], data[offset:])
	offset += 32
	copy(r.SourceChainID[:], data[offset:])
	offset += 32

	r.Epoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	r.Status = data[offset]
	offset++

	copy(r.CommitteeSignature[:], data[offset:])
	offset += 32

	plaintextLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if len(data) < offset+int(plaintextLen) {
		return nil, ErrPayloadMalformed
	}

	r.Plaintext = make([]byte, plaintextLen)
	copy(r.Plaintext, data[offset:])

	return r, nil
}

// =====================
// FHE_REENCRYPT_REQUEST_V1
// =====================

// FHEReencryptRequestV1 is for recipient-specific re-encryption
// Wire format:
//
//	[0]:      version (1 byte)
//	[1]:      type (1 byte)
//	[2:34]:   request_id (32 bytes)
//	[34:66]:  ciphertext_handle (32 bytes)
//	[66:98]:  permit_id (32 bytes)
//	[98:130]: source_chain_id (32 bytes)
//	[130:138]: epoch (8 bytes)
//	[138:158]: recipient (20 bytes)
//	[158:...]: recipient_public_key (variable, prefixed with length)
type FHEReencryptRequestV1 struct {
	RequestID          [32]byte
	CiphertextHandle   [32]byte
	PermitID           [32]byte
	SourceChainID      ids.ID
	Epoch              uint64
	Recipient          [20]byte
	RecipientPublicKey []byte
}

// Bytes serializes the request to wire format
func (r *FHEReencryptRequestV1) Bytes() []byte {
	buf := make([]byte, 162+len(r.RecipientPublicKey))
	offset := 0

	buf[offset] = PayloadVersionV1
	offset++
	buf[offset] = PayloadTypeFHEReencryptRequestV1
	offset++

	copy(buf[offset:], r.RequestID[:])
	offset += 32
	copy(buf[offset:], r.CiphertextHandle[:])
	offset += 32
	copy(buf[offset:], r.PermitID[:])
	offset += 32
	copy(buf[offset:], r.SourceChainID[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:], r.Epoch)
	offset += 8

	copy(buf[offset:], r.Recipient[:])
	offset += 20

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(r.RecipientPublicKey)))
	offset += 4

	copy(buf[offset:], r.RecipientPublicKey)

	return buf
}

// ParseFHEReencryptRequestV1 parses a reencrypt request from wire format
func ParseFHEReencryptRequestV1(data []byte) (*FHEReencryptRequestV1, error) {
	if len(data) < 162 {
		return nil, ErrPayloadTooShort
	}

	if data[0] != PayloadVersionV1 {
		return nil, ErrInvalidPayloadVersion
	}
	if data[1] != PayloadTypeFHEReencryptRequestV1 {
		return nil, ErrInvalidPayloadType
	}

	r := &FHEReencryptRequestV1{}
	offset := 2

	copy(r.RequestID[:], data[offset:])
	offset += 32
	copy(r.CiphertextHandle[:], data[offset:])
	offset += 32
	copy(r.PermitID[:], data[offset:])
	offset += 32
	copy(r.SourceChainID[:], data[offset:])
	offset += 32

	r.Epoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	copy(r.Recipient[:], data[offset:])
	offset += 20

	pubKeyLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if len(data) < offset+int(pubKeyLen) {
		return nil, ErrPayloadMalformed
	}

	r.RecipientPublicKey = make([]byte, pubKeyLen)
	copy(r.RecipientPublicKey, data[offset:])

	return r, nil
}

// =====================
// FHE_TASK_RESULT_V1
// =====================

// FHETaskResultV1 is for coprocessor task results
// Wire format:
//
//	[0]:      version (1 byte)
//	[1]:      type (1 byte)
//	[2:34]:   task_id (32 bytes)
//	[34:66]:  result_handle (32 bytes)
//	[66:98]:  source_chain_id (32 bytes)
//	[98:106]: epoch (8 bytes)
//	[106]:    status (1 byte)
//	[107:127]: callback (20 bytes)
//	[127:131]: callback_selector (4 bytes)
//	[131:163]: signature (32 bytes)
type FHETaskResultV1 struct {
	TaskID           [32]byte
	ResultHandle     [32]byte
	SourceChainID    ids.ID
	Epoch            uint64
	Status           uint8
	Callback         [20]byte
	CallbackSelector [4]byte
	Signature        [32]byte
}

const (
	TaskStatusCompleted uint8 = 0x00
	TaskStatusFailed    uint8 = 0x01
	TaskStatusTimeout   uint8 = 0x02
)

// Bytes serializes the task result to wire format
func (r *FHETaskResultV1) Bytes() []byte {
	buf := make([]byte, 163)
	offset := 0

	buf[offset] = PayloadVersionV1
	offset++
	buf[offset] = PayloadTypeFHETaskResultV1
	offset++

	copy(buf[offset:], r.TaskID[:])
	offset += 32
	copy(buf[offset:], r.ResultHandle[:])
	offset += 32
	copy(buf[offset:], r.SourceChainID[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:], r.Epoch)
	offset += 8

	buf[offset] = r.Status
	offset++

	copy(buf[offset:], r.Callback[:])
	offset += 20
	copy(buf[offset:], r.CallbackSelector[:])
	offset += 4
	copy(buf[offset:], r.Signature[:])

	return buf
}

// ParseFHETaskResultV1 parses a task result from wire format
func ParseFHETaskResultV1(data []byte) (*FHETaskResultV1, error) {
	if len(data) < 163 {
		return nil, ErrPayloadTooShort
	}

	if data[0] != PayloadVersionV1 {
		return nil, ErrInvalidPayloadVersion
	}
	if data[1] != PayloadTypeFHETaskResultV1 {
		return nil, ErrInvalidPayloadType
	}

	r := &FHETaskResultV1{}
	offset := 2

	copy(r.TaskID[:], data[offset:])
	offset += 32
	copy(r.ResultHandle[:], data[offset:])
	offset += 32
	copy(r.SourceChainID[:], data[offset:])
	offset += 32

	r.Epoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	r.Status = data[offset]
	offset++

	copy(r.Callback[:], data[offset:])
	offset += 20
	copy(r.CallbackSelector[:], data[offset:])
	offset += 4
	copy(r.Signature[:], data[offset:])

	return r, nil
}

// =====================
// FHE_KEY_ROTATION_V1
// =====================

// FHEKeyRotationV1 announces a key rotation event
// Wire format:
//
//	[0]:      version (1 byte)
//	[1]:      type (1 byte)
//	[2:10]:   old_epoch (8 bytes)
//	[10:18]:  new_epoch (8 bytes)
//	[18:22]:  new_threshold (4 bytes)
//	[22:26]:  committee_size (4 bytes)
//	[26:...]: new_public_key (variable, prefixed with length)
type FHEKeyRotationV1 struct {
	OldEpoch      uint64
	NewEpoch      uint64
	NewThreshold  uint32
	CommitteeSize uint32
	NewPublicKey  []byte
}

// Bytes serializes the key rotation to wire format
func (r *FHEKeyRotationV1) Bytes() []byte {
	buf := make([]byte, 30+len(r.NewPublicKey))
	offset := 0

	buf[offset] = PayloadVersionV1
	offset++
	buf[offset] = PayloadTypeFHEKeyRotationV1
	offset++

	binary.BigEndian.PutUint64(buf[offset:], r.OldEpoch)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], r.NewEpoch)
	offset += 8
	binary.BigEndian.PutUint32(buf[offset:], r.NewThreshold)
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:], r.CommitteeSize)
	offset += 4

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(r.NewPublicKey)))
	offset += 4

	copy(buf[offset:], r.NewPublicKey)

	return buf
}

// ParseFHEKeyRotationV1 parses a key rotation from wire format
func ParseFHEKeyRotationV1(data []byte) (*FHEKeyRotationV1, error) {
	if len(data) < 30 {
		return nil, ErrPayloadTooShort
	}

	if data[0] != PayloadVersionV1 {
		return nil, ErrInvalidPayloadVersion
	}
	if data[1] != PayloadTypeFHEKeyRotationV1 {
		return nil, ErrInvalidPayloadType
	}

	r := &FHEKeyRotationV1{}
	offset := 2

	r.OldEpoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	r.NewEpoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	r.NewThreshold = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	r.CommitteeSize = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	pubKeyLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if len(data) < offset+int(pubKeyLen) {
		return nil, ErrPayloadMalformed
	}

	r.NewPublicKey = make([]byte, pubKeyLen)
	copy(r.NewPublicKey, data[offset:])

	return r, nil
}

// =====================
// Payload Dispatcher
// =====================

// ParsePayload parses any FHE Warp payload and returns the type and data
func ParsePayload(data []byte) (uint8, interface{}, error) {
	if len(data) < 2 {
		return 0, nil, ErrPayloadTooShort
	}

	version := data[0]
	if version != PayloadVersionV1 {
		return 0, nil, fmt.Errorf("%w: got %d, expected %d", ErrInvalidPayloadVersion, version, PayloadVersionV1)
	}

	payloadType := data[1]

	switch payloadType {
	case PayloadTypeFHEDecryptRequestV1:
		req, err := ParseFHEDecryptRequestV1(data)
		if err != nil {
			return payloadType, nil, err
		}
		if err := req.Validate(); err != nil {
			return payloadType, nil, err
		}
		return payloadType, req, nil
	case PayloadTypeFHEDecryptResultV1:
		res, err := ParseFHEDecryptResultV1(data)
		return payloadType, res, err
	case PayloadTypeFHEReencryptRequestV1:
		req, err := ParseFHEReencryptRequestV1(data)
		return payloadType, req, err
	case PayloadTypeFHETaskResultV1:
		res, err := ParseFHETaskResultV1(data)
		return payloadType, res, err
	case PayloadTypeFHEKeyRotationV1:
		rot, err := ParseFHEKeyRotationV1(data)
		return payloadType, rot, err
	default:
		return payloadType, nil, ErrInvalidPayloadType
	}
}
