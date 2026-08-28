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
// offsets, and BOTH parsers are canonical: each re-serializes what it decoded
// and refuses input that is not already byte-identical to it. Exactly one
// byte-string decodes to each transaction and each block.
//
// SECURITY — the signing/authentication architecture:
//
//   - content() is one zap object binding every semantically-meaningful field
//     (Type, Payer, Subject, GasLimit, Nonce, Scheme, Payload) and EXCLUDING
//     Auth/Sig. Because Payer is bound here and authenticate() requires Payer ==
//     addressOf(Auth), an attacker cannot swap in a different public key. And
//     because Subject is bound here — and SyntacticVerify requires it to equal
//     what the payload derives — the signature covers the OBJECT acted on, not
//     merely the arguments that produce it.
//
//   - SigningBytes(chain) is the deterministic preimage the payer SIGNS: the
//     content, bound to the ONE chain it is meant for. The chain id does not
//     travel — each side supplies its own — so a transaction signed for the
//     testnet F-Chain cannot authenticate on the mainnet one. Without that
//     binding a captured transaction replays verbatim onto every other F-Chain,
//     where the same payer address exists (an address is the hash of a public
//     key), burning its balance there for an operation it never asked for.
//
//   - Bytes() is content() ‖ sigObject, where sigObject carries Auth+Sig, and
//     ID() = sha256(Bytes()). What is authenticated is still exactly what is
//     transmitted: the preimage is a pure function of the chain and the
//     transmitted content prefix, and ParseTransaction accepts only input that
//     is byte-identical to what those fields re-serialize to.
//
//   - authenticate(chain) re-derives the preimage from the parsed fields and
//     verifies the signature against it; a deterministic zap marshal guarantees
//     the re-derived preimage equals the signed one.

// ---- Transaction content object (the semantic fields; excludes Auth/Sig) ----
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

// txDomain separates a transaction preimage from every other thing this chain
// hashes, so no other digest can ever be mistaken for a payer's signature over
// a transaction.
const txDomain = "fhevm/tx/"

// content is the deterministic encoding of the transaction's semantic fields —
// including Payer and Subject — excluding Auth and Sig. It is the leading
// message of the wire encoding.
func (tx *Transaction) content() []byte {
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

// SigningBytes is the preimage the payer signs: the transaction's content bound
// to the chain it is meant for. Clients build it with the chain id they are
// transacting on; a node verifies with its own, so the two agree only on the
// chain the payer chose.
func (tx *Transaction) SigningBytes(chain ids.ID) []byte {
	c := tx.content()
	out := make([]byte, 0, len(txDomain)+len(chain)+len(c))
	out = append(out, txDomain...)
	out = append(out, chain[:]...)
	return append(out, c...)
}

// Bytes is the full wire encoding: the content object followed by an appended
// zap object carrying Auth and Sig.
func (tx *Transaction) Bytes() []byte {
	signing := tx.content()

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

// MaxBlockSize bounds a block on the wire. Without it a peer decides how much
// this node parses, hashes and allocates before anything about the block has
// been checked: an 8 MB message carrying 1,524 transactions parsed to
// completion, because MaxBlockTxs was applied by Verify and Verify runs after
// the parse. Both bounds belong here, at the first byte, and neither implies
// the other — this one bounds the bytes read, MaxBlockTxs bounds the signatures
// verified, and a small block can still declare a great many tiny transactions.
const MaxBlockSize = 2 << 20 // 2 MiB

func parseBlock(vm *VM, data []byte) (*Block, error) {
	if len(data) > MaxBlockSize {
		return nil, fmt.Errorf("fhevm: %w: block is %d bytes, over %d",
			ErrInvalidPayload, len(data), MaxBlockSize)
	}
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
	if len(lens) > MaxBlockTxs {
		return nil, fmt.Errorf("fhevm: %w: block declares %d transactions, over %d",
			ErrInvalidPayload, len(lens), MaxBlockTxs)
	}
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
	// The whole encoding must be the one this block serializes to, the same rule
	// ParseTransaction applies — so the claim in this file's header holds for a
	// block as well as for a transaction. Bytes that no length covers are refused
	// by it too, and not separately: a blob with unread bytes re-serializes
	// SHORTER than it arrived, so the comparison below fails. That is measured,
	// not assumed — deleting the separate check left every test green, which is
	// what makes it a special case of this one rather than a second rule.
	b.id = b.computeID()
	if !bytes.Equal(data, b.Bytes()) {
		return nil, fmt.Errorf("fhevm: %w: non-canonical block encoding", ErrInvalidPayload)
	}
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

// emptyBlockSize is the wire cost of a block carrying no transactions: the zap
// header, the root object, and an empty length list.
var emptyBlockSize = len((&Block{}).Bytes())

// txEntry is what one transaction costs a block BEYOND its own bytes: four for
// its entry in the length list, and up to four more of zap's eight-byte
// alignment. It is an upper bound by construction, which is the direction that
// matters — BuildBlock adds it per selected transaction, so its running total
// can never come in under the block it describes and a proposer cannot select
// its way past a size its own Verify refuses. wire_test.go pins the relation.
const txEntry = 8
