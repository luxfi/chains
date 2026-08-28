// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"errors"
	"fmt"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for Z-Chain. No pcodecs, no reflection, no codec
// registry. Each type owns Marshal() []byte over a zap object; nested slices
// ([]*Sub) are packed as a u32-length list + concatenated sub Marshal() blobs;
// an optional pointer (*ZKProof) is a single bytes field that is empty iff nil;
// [][]byte is a length list + concat blob. Parse rejects trailing bytes
// (canonical). Re-genesis authorized.

var (
	// errTrailingBytes — the frame declares fewer bytes than were handed to the
	// parser. One value has one byte string, so the remainder belongs to nobody.
	errTrailingBytes = errors.New("zkvm wire: trailing bytes")

	// errLength — a declared length vector does not exactly cover the blob it
	// indexes: either a length reaches past the end, or blob bytes are left that
	// no length claims.
	errLength = errors.New("zkvm wire: declared length does not match blob")
)

// ================= leaf helpers =================

// parseFrame returns the root object of a zap frame and refuses one that does
// not account for every byte handed in. Every parser in this file goes through
// it, so canonicality is decided in one place rather than per type.
func parseFrame(data []byte) (zap.Object, error) {
	m, err := zap.Parse(data)
	if err != nil {
		return zap.Object{}, err
	}
	if m.Size() != len(data) {
		return zap.Object{}, errTrailingBytes
	}
	return m.Root(), nil
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

func cp(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

// packBytesList flattens [][]byte into (lengths, concat blob).
func packBytesList(xs [][]byte) (lens []uint32, blob []byte) {
	lens = make([]uint32, len(xs))
	for i, x := range xs {
		lens[i] = uint32(len(x))
		blob = append(blob, x...)
	}
	return lens, blob
}

// unpackBytesList re-splits a concatenated blob by its declared lengths. Both
// halves come from the peer and both are checked: a length the blob cannot back
// is refused rather than dropped, and blob bytes no length claims are refused
// too, since either way the value read is not the value that was sent. The
// capacity comes from the length vector, which the frame already bounds, never
// from a declared length.
func unpackBytesList(lens []uint32, blob []byte) ([][]byte, error) {
	if len(lens) == 0 {
		if len(blob) != 0 {
			return nil, errLength
		}
		return nil, nil
	}
	out := make([][]byte, 0, len(lens))
	pos := 0
	for i, l := range lens {
		if int(l) > len(blob)-pos {
			return nil, fmt.Errorf("%w: entry %d", errLength, i)
		}
		out = append(out, cp(blob[pos:pos+int(l)]))
		pos += int(l)
	}
	if pos != len(blob) {
		return nil, errLength
	}
	return out, nil
}

// packObjs marshals each item and returns (per-item lengths, concat blob).
func packObjs[T any](items []T, marshal func(T) []byte) (lens []uint32, blob []byte) {
	lens = make([]uint32, len(items))
	for i, it := range items {
		m := marshal(it)
		lens[i] = uint32(len(m))
		blob = append(blob, m...)
	}
	return lens, blob
}

// unpackObjs re-splits a packed blob by lengths and parses each sub-object,
// under the same agreement rule as unpackBytesList.
func unpackObjs[T any](lens []uint32, blob []byte, parse func([]byte) (T, error)) ([]T, error) {
	if len(lens) == 0 {
		if len(blob) != 0 {
			return nil, errLength
		}
		return nil, nil
	}
	out := make([]T, 0, len(lens))
	pos := 0
	for i, l := range lens {
		if int(l) > len(blob)-pos {
			return nil, fmt.Errorf("%w: item %d", errLength, i)
		}
		v, err := parse(blob[pos : pos+int(l)])
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		pos += int(l)
	}
	if pos != len(blob) {
		return nil, errLength
	}
	return out, nil
}

func readID(o zap.Object, off int) ids.ID {
	var id ids.ID
	copy(id[:], o.BytesFixedSlice(off, 32))
	return id
}

// ================= TransparentInput: TxID32@0, OutputIdx u32@32, Amount u64@36, Address bytes@44 =================

const tiSize = 52

func marshalTransparentInput(t *TransparentInput) []byte {
	b := zap.NewBuilder(zap.HeaderSize + tiSize + len(t.Address) + 32)
	ob := b.StartObject(tiSize)
	ob.SetBytesFixed(0, t.TxID[:])
	ob.SetUint32(32, t.OutputIdx)
	ob.SetUint64(36, t.Amount)
	ob.SetBytes(44, t.Address)
	ob.FinishAsRoot()
	return b.Finish()
}

func parseTransparentInput(data []byte) (*TransparentInput, error) {
	o, err := parseFrame(data)
	if err != nil {
		return nil, err
	}
	return &TransparentInput{TxID: readID(o, 0), OutputIdx: o.Uint32(32), Amount: o.Uint64(36), Address: cp(o.Bytes(44))}, nil
}

// ================= TransparentOutput: Amount u64@0, AssetID 32B@8, Address bytes@40 =================

const toSize = 48

func marshalTransparentOutput(t *TransparentOutput) []byte {
	b := zap.NewBuilder(zap.HeaderSize + toSize + len(t.Address) + 32)
	ob := b.StartObject(toSize)
	ob.SetUint64(0, t.Amount)
	ob.SetBytesFixed(8, t.AssetID[:])
	ob.SetBytes(40, t.Address)
	ob.FinishAsRoot()
	return b.Finish()
}

func parseTransparentOutput(data []byte) (*TransparentOutput, error) {
	o, err := parseFrame(data)
	if err != nil {
		return nil, err
	}
	return &TransparentOutput{Amount: o.Uint64(0), AssetID: readID(o, 8), Address: cp(o.Bytes(40))}, nil
}

// ================= ShieldedOutput: 4 bytes fields @0/8/16/24 =================

const soSize = 32

func marshalShieldedOutput(s *ShieldedOutput) []byte {
	b := zap.NewBuilder(zap.HeaderSize + soSize + len(s.Commitment) + len(s.EncryptedNote) + len(s.EphemeralPubKey) + len(s.OutputProof) + 64)
	ob := b.StartObject(soSize)
	ob.SetBytes(0, s.Commitment)
	ob.SetBytes(8, s.EncryptedNote)
	ob.SetBytes(16, s.EphemeralPubKey)
	ob.SetBytes(24, s.OutputProof)
	ob.FinishAsRoot()
	return b.Finish()
}

func parseShieldedOutput(data []byte) (*ShieldedOutput, error) {
	o, err := parseFrame(data)
	if err != nil {
		return nil, err
	}
	return &ShieldedOutput{Commitment: cp(o.Bytes(0)), EncryptedNote: cp(o.Bytes(8)), EphemeralPubKey: cp(o.Bytes(16)), OutputProof: cp(o.Bytes(24))}, nil
}

// ================= ZKProof: ProofType bytes@0, ProofData bytes@8, PubInputLens list@16, PubInputBlob bytes@24 =================

const zkpSize = 32

func marshalZKProof(z *ZKProof) []byte {
	if z == nil {
		return nil
	}
	lens, blob := packBytesList(z.PublicInputs)
	b := zap.NewBuilder(zap.HeaderSize + zkpSize + len(z.ProofType) + len(z.ProofData) + len(blob) + 4*len(lens) + 64)
	lensOff := writeU32List(b, lens)
	ob := b.StartObject(zkpSize)
	ob.SetBytes(0, []byte(z.ProofType))
	ob.SetBytes(8, z.ProofData)
	ob.SetList(16, lensOff, len(lens))
	ob.SetBytes(24, blob)
	ob.FinishAsRoot()
	return b.Finish()
}

func parseZKProof(data []byte) (*ZKProof, error) {
	if len(data) == 0 {
		return nil, nil
	}
	o, err := parseFrame(data)
	if err != nil {
		return nil, err
	}
	pub, err := unpackBytesList(readU32List(o, 16), o.Bytes(24))
	if err != nil {
		return nil, err
	}
	return &ZKProof{ProofType: string(o.Bytes(0)), ProofData: cp(o.Bytes(8)), PublicInputs: pub}, nil
}

// ================= UTXO: TxID32@0, OutputIndex u32@32, Height u64@36, Commitment bytes@44, Ciphertext bytes@52, EphemeralPK bytes@60 =================

const utxoSize = 68

func (u *UTXO) Marshal() []byte {
	b := zap.NewBuilder(zap.HeaderSize + utxoSize + len(u.Commitment) + len(u.Ciphertext) + len(u.EphemeralPK) + 64)
	ob := b.StartObject(utxoSize)
	ob.SetBytesFixed(0, u.TxID[:])
	ob.SetUint32(32, u.OutputIndex)
	ob.SetUint64(36, u.Height)
	ob.SetBytes(44, u.Commitment)
	ob.SetBytes(52, u.Ciphertext)
	ob.SetBytes(60, u.EphemeralPK)
	ob.FinishAsRoot()
	return b.Finish()
}

func parseUTXO(data []byte, u *UTXO) error {
	o, err := parseFrame(data)
	if err != nil {
		return err
	}
	u.TxID = readID(o, 0)
	u.OutputIndex = o.Uint32(32)
	u.Height = o.Uint64(36)
	u.Commitment = cp(o.Bytes(44))
	u.Ciphertext = cp(o.Bytes(52))
	u.EphemeralPK = cp(o.Bytes(60))
	return nil
}

// ================= Transaction =================
//
//	Type u8@0, Version u8@1, Fee u64@2, Expiry u64@10,
//	TInLens list@18, TInBlob bytes@26, TOutLens list@34, TOutBlob bytes@42,
//	NullLens list@50, NullBlob bytes@58, SOutLens list@66, SOutBlob bytes@74,
//	Proof bytes@82, Memo bytes@90
//
// The id is NOT here. It is ComputeID() over these fields, so a peer cannot
// choose it, and the proof cache keyed on it cannot be reached by a
// transaction other than the one the proof was verified for.
const txSize = 98

func (tx *Transaction) Marshal() []byte {
	tinLens, tinBlob := packObjs(tx.TransparentInputs, marshalTransparentInput)
	toutLens, toutBlob := packObjs(tx.TransparentOutputs, marshalTransparentOutput)
	nullLens, nullBlob := packBytesList(tx.Nullifiers)
	soutLens, soutBlob := packObjs(tx.Outputs, marshalShieldedOutput)
	proof := marshalZKProof(tx.Proof)

	b := zap.NewBuilder(zap.HeaderSize + txSize + len(tinBlob) + len(toutBlob) + len(nullBlob) +
		len(soutBlob) + len(proof) + len(tx.Memo) +
		4*(len(tinLens)+len(toutLens)+len(nullLens)+len(soutLens)) + 512)
	tinOff := writeU32List(b, tinLens)
	toutOff := writeU32List(b, toutLens)
	nullOff := writeU32List(b, nullLens)
	soutOff := writeU32List(b, soutLens)

	ob := b.StartObject(txSize)
	ob.SetUint8(0, uint8(tx.Type))
	ob.SetUint8(1, tx.Version)
	ob.SetUint64(2, tx.Fee)
	ob.SetUint64(10, tx.Expiry)
	ob.SetList(18, tinOff, len(tinLens))
	ob.SetBytes(26, tinBlob)
	ob.SetList(34, toutOff, len(toutLens))
	ob.SetBytes(42, toutBlob)
	ob.SetList(50, nullOff, len(nullLens))
	ob.SetBytes(58, nullBlob)
	ob.SetList(66, soutOff, len(soutLens))
	ob.SetBytes(74, soutBlob)
	ob.SetBytes(82, proof)
	ob.SetBytes(90, tx.Memo)
	ob.FinishAsRoot()
	return b.Finish()
}

func parseTransaction(data []byte) (*Transaction, error) {
	o, err := parseFrame(data)
	if err != nil {
		return nil, err
	}
	tx := &Transaction{
		Type:    TransactionType(o.Uint8(0)),
		Version: o.Uint8(1),
		Fee:     o.Uint64(2),
		Expiry:  o.Uint64(10),
		Memo:    cp(o.Bytes(90)),
	}
	if tx.TransparentInputs, err = unpackObjs(readU32List(o, 18), o.Bytes(26), parseTransparentInput); err != nil {
		return nil, err
	}
	if tx.TransparentOutputs, err = unpackObjs(readU32List(o, 34), o.Bytes(42), parseTransparentOutput); err != nil {
		return nil, err
	}
	if tx.Nullifiers, err = unpackBytesList(readU32List(o, 50), o.Bytes(58)); err != nil {
		return nil, err
	}
	if tx.Outputs, err = unpackObjs(readU32List(o, 66), o.Bytes(74), parseShieldedOutput); err != nil {
		return nil, err
	}
	if tx.Proof, err = parseZKProof(o.Bytes(82)); err != nil {
		return nil, err
	}
	// The identity is derived, never read. See ComputeID.
	tx.ID = tx.ComputeID()
	return tx, nil
}

// ================= Block =================
//
//	ParentID 32B@0, Height u64@32, Timestamp i64@40, TxLens list@48,
//	TxBlob bytes@56, StateRoot bytes@64, BlockProof bytes@72
const blkSize = 80

func (b *Block) Marshal() []byte {
	txLens, txBlob := packObjs(b.Txs, (*Transaction).Marshal)
	proof := marshalZKProof(b.BlockProof)
	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(txBlob) + len(b.StateRoot) + len(proof) + 4*len(txLens) + 256)
	txOff := writeU32List(bld, txLens)
	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(0, b.ParentID_[:])
	ob.SetUint64(32, b.BlockHeight)
	ob.SetInt64(40, b.BlockTimestamp)
	ob.SetList(48, txOff, len(txLens))
	ob.SetBytes(56, txBlob)
	ob.SetBytes(64, b.StateRoot)
	ob.SetBytes(72, proof)
	ob.FinishAsRoot()
	return bld.Finish()
}

func parseBlockBytes(data []byte, blk *Block) error {
	o, err := parseFrame(data)
	if err != nil {
		return err
	}
	blk.ParentID_ = readID(o, 0)
	blk.BlockHeight = o.Uint64(32)
	blk.BlockTimestamp = o.Int64(40)
	blk.StateRoot = cp(o.Bytes(64))
	if blk.Txs, err = unpackObjs(readU32List(o, 48), o.Bytes(56), parseTransaction); err != nil {
		return err
	}
	if blk.BlockProof, err = parseZKProof(o.Bytes(72)); err != nil {
		return err
	}
	return nil
}
