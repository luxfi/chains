// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for Q-Chain (quantumvm). The Block and its
// transactions own their serialization over zap objects at FIXED field offsets.
//
// The wire is CANONICAL, and canonical means one byte string per block, not
// "the encoder emits one shape". Parse re-serializes what it decoded and refuses
// anything that does not come back byte-identical. Nothing weaker holds: a zap
// message declares its own size and its own root offset, so padding after the
// content, a relocated root struct and a root pointed at the wire header all
// decode to the same logical block under different sha256s. The block id is
// sha256(Bytes()), so each of those is a distinct id for one block — a fork the
// network builds by itself.
//
// Parse reconstructs the FULL transaction set, signature included. Verify checks
// every transaction's ML-DSA signature over that set, so binding the check to a
// field the parser skipped is what made it run on locally built blocks and never
// on received ones. A signature check a parser can switch off is not a check.
//
// The block id is NOT stored in the wire: it is the content hash sha256(Bytes())
// (see computeID), matching keyvm/dexvm/aivm — one and only one id derivation
// across every VM in this repo, and the clean invariant id == sha256(Bytes())
// holds.

var (
	errBlockTooLarge  = errors.New("quantumvm: block exceeds the wire bound")
	errNonCanonical   = errors.New("quantumvm: block wire is not the canonical encoding of its content")
	errTxCountAbsurd  = errors.New("quantumvm: block declares more transactions than its bytes can hold")
	errTxBlobMismatch = errors.New("quantumvm: transaction lengths do not partition the transaction blob")
)

// MaxBlockSize bounds a block on the wire. Without it a peer decides how much
// memory this node allocates and how much its store holds: parse, verify and
// commit each walked whatever arrived.
const MaxBlockSize = 2 << 20 // 2 MiB

// ---- Block ----
//
//	Timestamp i64   @ 0    (Unix seconds — Q-Chain block-time resolution)
//	Height    u64   @ 8
//	ParentID  32B   @ 16
//	ChainID   32B   @ 48   (the chain this block belongs to)
//	NetworkID u32   @ 80   (the network that chain belongs to)
//	TxLens    list  @ 88   (u32 per transaction wire length)
//	TxBlob    bytes @ 96   (concatenated transaction wire bytes)
const (
	blkTime    = 0
	blkHeight  = 8
	blkParent  = 16
	blkChain   = 48
	blkNetwork = 80
	blkTxLens  = 88
	blkTxBlob  = 96
	blkSize    = 104
)

// Bytes returns the block's canonical ZAP wire (cached).
func (b *Block) Bytes() []byte {
	if b.bytes != nil {
		return b.bytes
	}

	txLens := make([]uint32, len(b.transactions))
	var txBlob []byte
	for i, tx := range b.transactions {
		txb := marshalTx(tx)
		txLens[i] = uint32(len(txb))
		txBlob = append(txBlob, txb...)
	}

	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(txBlob) + 4*len(txLens) + 128)
	txLensOff := writeU32List(bld, txLens)

	ob := bld.StartObject(blkSize)
	ob.SetInt64(blkTime, b.timestamp.Unix())
	ob.SetUint64(blkHeight, b.height)
	ob.SetBytesFixed(blkParent, b.parentID[:])
	ob.SetBytesFixed(blkChain, b.chainID[:])
	ob.SetUint32(blkNetwork, b.networkID)
	ob.SetList(blkTxLens, txLensOff, len(txLens))
	ob.SetBytes(blkTxBlob, txBlob)
	ob.FinishAsRoot()

	b.bytes = bld.Finish()
	return b.bytes
}

// computeID is the block's content id: sha256 over the canonical ZAP wire. The
// id is not stored in the wire, so this invariant holds unconditionally —
// id == sha256(Bytes()) — identically to every other VM in this repo.
func (b *Block) computeID() ids.ID {
	return ids.ID(sha256.Sum256(b.Bytes()))
}

// parseBlockBytes decodes a block, transaction set included, and accepts the
// bytes only if they are the canonical encoding of what came out.
func parseBlockBytes(vm *VM, data []byte) (*Block, error) {
	if len(data) > MaxBlockSize {
		return nil, fmt.Errorf("%w: %d bytes over %d", errBlockTooLarge, len(data), MaxBlockSize)
	}
	msg, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data) {
		return nil, fmt.Errorf("quantumvm: block trailing bytes")
	}
	o := msg.Root()
	// A field read past the end of the buffer answers zero rather than
	// failing, so a wire too short to hold the header does not decode to
	// nothing — it decodes to height 0, time 0 and the empty parent. Every
	// truncation would name that one value, under as many different ids as
	// there are ways to truncate.
	if o.Offset()+blkSize > msg.Size() {
		return nil, fmt.Errorf("quantumvm: block wire ends %d bytes into a %d-byte header",
			msg.Size()-o.Offset(), blkSize)
	}
	b := &Block{vm: vm}
	b.timestamp = time.Unix(o.Int64(blkTime), 0)
	b.height = o.Uint64(blkHeight)
	copy(b.parentID[:], o.BytesFixedSlice(blkParent, 32))
	copy(b.chainID[:], o.BytesFixedSlice(blkChain, 32))
	b.networkID = o.Uint32(blkNetwork)

	b.transactions, err = parseTxSet(o.List(blkTxLens), o.Bytes(blkTxBlob))
	if err != nil {
		return nil, err
	}

	// Canonical or nothing. Re-serializing what was decoded and comparing is
	// the only check that covers every degree of freedom the container has —
	// the declared size, the root offset, and anything appended past the
	// content — rather than the handful anyone thought to enumerate.
	if !bytes.Equal(b.Bytes(), data) {
		return nil, errNonCanonical
	}
	b.id = ids.ID(sha256.Sum256(data))
	return b, nil
}

// parseTxSet rebuilds the transactions from the length list and the blob the
// lengths partition. The lengths must cover the blob exactly: bytes no length
// names are bytes the block commits to and nothing reads.
func parseTxSet(lens zap.List, blob []byte) ([]Transaction, error) {
	n := lens.Len()
	if n == 0 {
		return nil, nil
	}
	// A list length is attacker-chosen and only clamped to the message size, so
	// bound it by what the blob can actually hold before allocating for it.
	if n > len(blob)/minTxWire {
		return nil, fmt.Errorf("%w: %d in %d bytes", errTxCountAbsurd, n, len(blob))
	}

	txs := make([]Transaction, n)
	off := 0
	for i := 0; i < n; i++ {
		size := int(lens.Uint32(i))
		if size < minTxWire || off+size > len(blob) {
			return nil, fmt.Errorf("%w: entry %d claims %d of %d remaining",
				errTxBlobMismatch, i, size, len(blob)-off)
		}
		tx, err := unmarshalTx(blob[off : off+size])
		if err != nil {
			return nil, fmt.Errorf("quantumvm: transaction %d: %w", i, err)
		}
		txs[i] = tx
		off += size
	}
	if off != len(blob) {
		return nil, fmt.Errorf("%w: %d bytes past the last transaction", errTxBlobMismatch, len(blob)-off)
	}
	return txs, nil
}

// ---- BaseTransaction ----
//
// Two wires, because a transaction is two things. Bytes() is the SIGNATURE
// PREIMAGE — what the ML-DSA signature covers, and therefore what may never
// include the signature. The envelope below is what rides in a block: the
// preimage plus the signature over it.
//
//	Timestamp i64   @ 0   (Unix seconds)
//	Nonce     u64   @ 8
//	Data      bytes @ 16
const (
	txTime  = 0
	txNonce = 8
	txData  = 16
	txSize  = 24
)

// Bytes returns the transaction's canonical ZAP wire. It excludes the quantum
// signature (which signs over exactly these bytes).
func (tx *BaseTransaction) Bytes() []byte {
	b := zap.NewBuilder(zap.HeaderSize + txSize + len(tx.data) + 32)
	ob := b.StartObject(txSize)
	ob.SetInt64(txTime, tx.timestamp.Unix())
	ob.SetUint64(txNonce, tx.nonce)
	ob.SetBytes(txData, tx.data)
	ob.FinishAsRoot()
	return b.Finish()
}

// ---- transaction envelope ----
//
//	Body      bytes @ 0    (the preimage above)
//	Algorithm u32   @ 8
//	Stamped   i64   @ 16   (signature time, Unix nanoseconds)
//	PublicKey bytes @ 24   (ML-DSA public key)
//	Signature bytes @ 32   (ML-DSA signature over body || stamp || stamped)
//	Stamp     bytes @ 40   (quantum stamp)
const (
	envBody  = 0
	envAlg   = 8
	envTime  = 16
	envKey   = 24
	envSig   = 32
	envStamp = 40
	envSize  = 48
)

// minTxWire is the smallest an envelope can be: the zap header plus the fixed
// section, with every variable field null.
const minTxWire = zap.HeaderSize + envSize

// marshalTx writes a transaction and the signature over it. The interface hands
// over exactly the two, so any Transaction serializes the same way.
func marshalTx(tx Transaction) []byte {
	body := tx.Bytes()
	sig := tx.GetQuantumSignature()
	if sig == nil {
		sig = &quantum.QuantumSignature{}
	}

	b := zap.NewBuilder(zap.HeaderSize + envSize +
		len(body) + len(sig.PublicKey) + len(sig.Signature) + len(sig.QuantumStamp) + 64)
	ob := b.StartObject(envSize)
	ob.SetBytes(envBody, body)
	ob.SetUint32(envAlg, sig.Algorithm)
	ob.SetInt64(envTime, sig.Timestamp.UnixNano())
	ob.SetBytes(envKey, sig.PublicKey)
	ob.SetBytes(envSig, sig.Signature)
	ob.SetBytes(envStamp, sig.QuantumStamp)
	ob.FinishAsRoot()
	return b.Finish()
}

// unmarshalTx is marshalTx's inverse. CoronaKey is the public key by
// construction (Sign sets both from one key), so it is derived rather than
// carried — a second copy on the wire is a second thing to disagree.
func unmarshalTx(data []byte) (*BaseTransaction, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data) {
		return nil, fmt.Errorf("quantumvm: transaction trailing bytes")
	}
	o := msg.Root()
	if o.Offset()+envSize > msg.Size() {
		return nil, fmt.Errorf("quantumvm: transaction wire ends %d bytes into a %d-byte header",
			msg.Size()-o.Offset(), envSize)
	}

	tx, err := parseTxBody(o.Bytes(envBody))
	if err != nil {
		return nil, err
	}
	key := o.Bytes(envKey)
	tx.quantumSignature = &quantum.QuantumSignature{
		Algorithm:    o.Uint32(envAlg),
		Timestamp:    time.Unix(0, o.Int64(envTime)),
		PublicKey:    key,
		Signature:    o.Bytes(envSig),
		CoronaKey:    key,
		QuantumStamp: o.Bytes(envStamp),
	}
	return tx, nil
}

// parseTxBody decodes the signature preimage.
func parseTxBody(body []byte) (*BaseTransaction, error) {
	msg, err := zap.Parse(body)
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(body) {
		return nil, fmt.Errorf("quantumvm: transaction body trailing bytes")
	}
	o := msg.Root()
	if o.Offset()+txSize > msg.Size() {
		return nil, fmt.Errorf("quantumvm: transaction body ends %d bytes into a %d-byte header",
			msg.Size()-o.Offset(), txSize)
	}
	return &BaseTransaction{
		timestamp: time.Unix(o.Int64(txTime), 0),
		nonce:     o.Uint64(txNonce),
		data:      o.Bytes(txData),
	}, nil
}

// ---- shared helpers ----

func writeU32List(b *zap.Builder, xs []uint32) int {
	lb := b.StartList(4)
	for _, x := range xs {
		lb.AddUint32(x)
	}
	off, _ := lb.Finish()
	return off
}
