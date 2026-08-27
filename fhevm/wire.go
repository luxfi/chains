// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for F-Chain (fhevm). No hand-rolled big-endian, no
// cursor codec — the Transaction and the Block each own their marshal/parse
// over zap objects at FIXED field offsets. The on-wire format is exactly these
// offsets (canonical: parse rejects trailing bytes).
//
// SECURITY — the signing/authentication architecture:
//
//   - SigningBytes() is the deterministic preimage the payer SIGNS. It is one
//     zap object binding every semantically-meaningful field (Type, Payer,
//     Subject, GasLimit, Nonce, Scheme, Payload) and EXCLUDING Auth/Sig.
//     Because Payer is bound here and authenticate() requires Payer ==
//     addressOf(Auth), an attacker cannot swap in a different public key. And
//     because Subject is bound here — and SyntacticVerify requires it to equal
//     what the payload derives — the signature covers the OBJECT acted on, not
//     merely the arguments that produce it.
//
//   - Bytes() is SigningBytes() ‖ sigObject, where sigObject carries Auth+Sig.
//     The signed bytes are therefore a genuine byte-prefix of the full wire (the
//     node's proposervm signed-block idiom). ID() = sha256(Bytes()).
//
//   - authenticate() re-derives SigningBytes() from the parsed fields and
//     verifies the signature against it; a deterministic zap marshal guarantees
//     the re-derived preimage equals the signed prefix.

// ---- Transaction signing object (the SIGNED preimage; excludes Auth/Sig) ----
//
//	Type     u8    @ 0
//	Payer    20B   @ 1
//	Subject  32B   @ 21
//	GasLimit u64   @ 53
//	Nonce    u64   @ 61
//	Scheme   bytes @ 69
//	Payload  bytes @ 77
const (
	txType    = 0
	txPayer   = 1
	txSubject = 21
	txGas     = 53
	txNonce   = 61
	txScheme  = 69
	txPayld   = 77
	txSize    = 85
)

// ---- Transaction sig object (appended after the signing object) ----
//
//	Auth bytes @ 0
//	Sig  bytes @ 8
const (
	sgAuth = 0
	sgSig  = 8
	sgSize = 16
)

// SigningBytes is the deterministic encoding the payer signs. It binds every
// semantically meaningful field — including Payer and Subject — but excludes
// Auth and Sig.
func (tx *Transaction) SigningBytes() []byte {
	b := zap.NewBuilder(zap.HeaderSize + txSize + len(tx.Scheme) + len(tx.Payload) + 64)
	ob := b.StartObject(txSize)
	ob.SetUint8(txType, tx.Type)
	ob.SetBytesFixed(txPayer, tx.Payer[:])
	ob.SetBytesFixed(txSubject, tx.Subject[:])
	ob.SetUint64(txGas, tx.GasLimit)
	ob.SetUint64(txNonce, tx.Nonce)
	ob.SetBytes(txScheme, []byte(tx.Scheme))
	ob.SetBytes(txPayld, tx.Payload)
	ob.FinishAsRoot()
	return b.Finish()
}

// Bytes is the full wire encoding: the signing object followed by an appended
// zap object carrying Auth and Sig. The signing prefix is byte-identical to
// SigningBytes(), so the payer's signature covers exactly Bytes()[:zapLen].
func (tx *Transaction) Bytes() []byte {
	signing := tx.SigningBytes()

	sb := zap.NewBuilder(zap.HeaderSize + sgSize + len(tx.Auth) + len(tx.Sig) + 32)
	so := sb.StartObject(sgSize)
	so.SetBytes(sgAuth, tx.Auth)
	so.SetBytes(sgSig, tx.Sig)
	so.FinishAsRoot()
	sig := sb.Finish()

	out := make([]byte, 0, len(signing)+len(sig))
	out = append(out, signing...)
	out = append(out, sig...)
	return out
}

// ParseTransaction decodes a transaction from its wire encoding: the leading
// signing object, then the appended Auth/Sig object. Canonical: rejects
// trailing bytes.
func ParseTransaction(data []byte) (*Transaction, error) {
	n, err := zapLen(data)
	if err != nil {
		return nil, err
	}
	sm, err := zap.Parse(data[:n])
	if err != nil {
		return nil, err
	}
	gm, err := zap.Parse(data[n:])
	if err != nil {
		return nil, err
	}
	if n+gm.Size() != len(data) {
		return nil, fmt.Errorf("fhevm: %w: trailing bytes", ErrInvalidPayload)
	}

	so := sm.Root()
	sig := gm.Root()
	tx := &Transaction{
		Type:     so.Uint8(txType),
		Scheme:   string(so.Bytes(txScheme)),
		GasLimit: so.Uint64(txGas),
		Nonce:    so.Uint64(txNonce),
		Payload:  appendBytes(so.Bytes(txPayld)),
		Auth:     appendBytes(sig.Bytes(sgAuth)),
		Sig:      appendBytes(sig.Bytes(sgSig)),
	}
	copy(tx.Payer[:], so.BytesFixedSlice(txPayer, ids.ShortIDLen))
	copy(tx.Subject[:], so.BytesFixedSlice(txSubject, 32))

	// Canonical wire: zap follows the root offset and ignores unreferenced
	// padding inside a message's declared size, so distinct byte-strings can
	// decode to identical fields. Bind the id to the RE-SERIALIZED (canonical)
	// form and reject any input that is not already canonical — exactly one
	// byte-string authenticates per logical tx (no id-malleability, fail-closed).
	canonical := tx.Bytes()
	if !bytes.Equal(data, canonical) {
		return nil, fmt.Errorf("fhevm: %w: non-canonical tx encoding", ErrInvalidPayload)
	}
	tx.id = ids.ID(sha256.Sum256(canonical))
	return tx, nil
}

// ---- Block ----
//
//	ParentID  32B   @ 0
//	Height    u64   @ 32
//	Timestamp i64   @ 40   (Unix seconds — F-Chain's block-time resolution)
//	TxLens    list  @ 48   (u32 per Transaction wire length)
//	TxBlob    bytes @ 56   (concatenated Transaction wire objects)
const (
	blkParent = 0
	blkHeight = 32
	blkTime   = 40
	blkTxLens = 48
	blkTxBlob = 56
	blkSize   = 64
)

// Bytes serializes the block (parent, height, timestamp, transactions).
func (b *Block) Bytes() []byte {
	txLens := make([]uint32, len(b.transactions))
	var txBlob []byte
	for i, tx := range b.transactions {
		txb := tx.Bytes()
		txLens[i] = uint32(len(txb))
		txBlob = append(txBlob, txb...)
	}

	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(txBlob) + 4*len(txLens) + 128)
	txLensOff := writeU32List(bld, txLens)

	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, b.parentID[:])
	ob.SetUint64(blkHeight, b.height)
	ob.SetInt64(blkTime, b.timestamp.Unix())
	ob.SetList(blkTxLens, txLensOff, len(txLens))
	ob.SetBytes(blkTxBlob, txBlob)
	ob.FinishAsRoot()
	return bld.Finish()
}

func parseBlock(vm *VM, data []byte) (*Block, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data) {
		return nil, fmt.Errorf("fhevm: %w: block trailing bytes", ErrInvalidPayload)
	}
	o := msg.Root()
	b := &Block{vm: vm}
	copy(b.parentID[:], o.BytesFixedSlice(blkParent, 32))
	b.height = o.Uint64(blkHeight)
	b.timestamp = time.Unix(o.Int64(blkTime), 0)

	lens := readU32List(o, blkTxLens)
	blob := o.Bytes(blkTxBlob)
	b.transactions = make([]*Transaction, 0, len(lens))
	pos := 0
	for _, l := range lens {
		if pos+int(l) > len(blob) {
			return nil, fmt.Errorf("fhevm: %w: tx blob out of bounds", ErrInvalidPayload)
		}
		tx, err := ParseTransaction(blob[pos : pos+int(l)])
		if err != nil {
			return nil, err
		}
		b.transactions = append(b.transactions, tx)
		pos += int(l)
	}
	b.id = b.computeID()
	return b, nil
}

// ---- shared helpers ----

// zapLen returns the total length of the leading self-delimiting zap message in
// b (its header size field @[12:16]) — the split point between the signing
// prefix and the appended Auth/Sig object.
func zapLen(b []byte) (int, error) {
	if len(b) < zap.HeaderSize {
		return 0, fmt.Errorf("fhevm: %w: short buffer", ErrInvalidPayload)
	}
	n := int(binary.LittleEndian.Uint32(b[12:16]))
	if n < zap.HeaderSize || n > len(b) {
		return 0, fmt.Errorf("fhevm: %w: bad zap length", ErrInvalidPayload)
	}
	return n, nil
}

func writeU32List(b *zap.Builder, xs []uint32) int {
	lb := b.StartList(4)
	for _, x := range xs {
		lb.AddUint32(x)
	}
	off, _ := lb.Finish()
	return off
}

func readU32List(o zap.Object, ptrOff int) []uint32 {
	l := o.ListStride(ptrOff, 4)
	n := l.Len()
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = l.Uint32(i)
	}
	return out
}

func appendBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}
