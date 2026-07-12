// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"fmt"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for Z-Chain. No pcodecs, no reflection, no codec
// registry. Each type owns Marshal() []byte over a zap object; nested slices
// ([]*Sub) are packed as a u32-length list + concatenated sub Marshal() blobs;
// optional pointers (*ZKProof/*FHEData) are a single bytes field that is empty
// iff nil; [][]byte is a length list + concat blob. Parse rejects trailing
// bytes (canonical). Re-genesis authorized.

// ================= leaf helpers =================

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

func unpackBytesList(lens []uint32, blob []byte) [][]byte {
	if len(lens) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(lens))
	pos := 0
	for _, l := range lens {
		if pos+int(l) > len(blob) {
			break
		}
		out = append(out, cp(blob[pos:pos+int(l)]))
		pos += int(l)
	}
	return out
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

// unpackObjs re-splits a packed blob by lengths and parses each sub-object.
func unpackObjs[T any](lens []uint32, blob []byte, parse func([]byte) (T, error)) ([]T, error) {
	if len(lens) == 0 {
		return nil, nil
	}
	out := make([]T, 0, len(lens))
	pos := 0
	for i, l := range lens {
		if pos+int(l) > len(blob) {
			return nil, fmt.Errorf("packed obj %d out of bounds", i)
		}
		v, err := parse(blob[pos : pos+int(l)])
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		pos += int(l)
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
	m, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	o := m.Root()
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
	m, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	o := m.Root()
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
	m, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	o := m.Root()
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
	m, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	o := m.Root()
	return &ZKProof{ProofType: string(o.Bytes(0)), ProofData: cp(o.Bytes(8)), PublicInputs: unpackBytesList(readU32List(o, 16), o.Bytes(24))}, nil
}

// ================= FHEData: EncInLens list@0, EncInBlob bytes@8, CircuitID bytes@16, EncResult bytes@24, CompProof bytes@32 =================

const fheSize = 40

func marshalFHEData(f *FHEData) []byte {
	if f == nil {
		return nil
	}
	lens, blob := packBytesList(f.EncryptedInputs)
	b := zap.NewBuilder(zap.HeaderSize + fheSize + len(blob) + 4*len(lens) + len(f.CircuitID) + len(f.EncryptedResult) + len(f.ComputationProof) + 64)
	lensOff := writeU32List(b, lens)
	ob := b.StartObject(fheSize)
	ob.SetList(0, lensOff, len(lens))
	ob.SetBytes(8, blob)
	ob.SetBytes(16, []byte(f.CircuitID))
	ob.SetBytes(24, f.EncryptedResult)
	ob.SetBytes(32, f.ComputationProof)
	ob.FinishAsRoot()
	return b.Finish()
}

func parseFHEData(data []byte) (*FHEData, error) {
	if len(data) == 0 {
		return nil, nil
	}
	m, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	o := m.Root()
	return &FHEData{EncryptedInputs: unpackBytesList(readU32List(o, 0), o.Bytes(8)), CircuitID: string(o.Bytes(16)), EncryptedResult: cp(o.Bytes(24)), ComputationProof: cp(o.Bytes(32))}, nil
}

// ================= UTXO: TxID32@0, OutputIndex u32@32, Height u64@36, Commitment bytes@44, Ciphertext bytes@52, EphemeralPK bytes@60 =================

const utxoSize = 68

func (u *UTXO) Marshal() ([]byte, error) {
	b := zap.NewBuilder(zap.HeaderSize + utxoSize + len(u.Commitment) + len(u.Ciphertext) + len(u.EphemeralPK) + 64)
	ob := b.StartObject(utxoSize)
	ob.SetBytesFixed(0, u.TxID[:])
	ob.SetUint32(32, u.OutputIndex)
	ob.SetUint64(36, u.Height)
	ob.SetBytes(44, u.Commitment)
	ob.SetBytes(52, u.Ciphertext)
	ob.SetBytes(60, u.EphemeralPK)
	ob.FinishAsRoot()
	return b.Finish(), nil
}

func parseUTXO(data []byte, u *UTXO) error {
	m, err := zap.Parse(data)
	if err != nil {
		return err
	}
	if m.Size() != len(data) {
		return fmt.Errorf("zkvm utxo: trailing bytes")
	}
	o := m.Root()
	u.TxID = readID(o, 0)
	u.OutputIndex = o.Uint32(32)
	u.Height = o.Uint64(36)
	u.Commitment = cp(o.Bytes(44))
	u.Ciphertext = cp(o.Bytes(52))
	u.EphemeralPK = cp(o.Bytes(60))
	return nil
}

// ================= PrivateAddress: 5 byte fields @0/8/16/24/32, CreatedAt i64@40 =================

const paSize = 48

func (p *PrivateAddress) Marshal() ([]byte, error) {
	b := zap.NewBuilder(zap.HeaderSize + paSize + len(p.Address) + len(p.ViewingKey) +
		len(p.SpendingKey) + len(p.Diversifier) + len(p.IncomingViewKey) + 64)
	ob := b.StartObject(paSize)
	ob.SetBytes(0, p.Address)
	ob.SetBytes(8, p.ViewingKey)
	ob.SetBytes(16, p.SpendingKey)
	ob.SetBytes(24, p.Diversifier)
	ob.SetBytes(32, p.IncomingViewKey)
	ob.SetInt64(40, p.CreatedAt)
	ob.FinishAsRoot()
	return b.Finish(), nil
}

func parsePrivateAddress(data []byte, p *PrivateAddress) error {
	m, err := zap.Parse(data)
	if err != nil {
		return err
	}
	o := m.Root()
	p.Address = cp(o.Bytes(0))
	p.ViewingKey = cp(o.Bytes(8))
	p.SpendingKey = cp(o.Bytes(16))
	p.Diversifier = cp(o.Bytes(24))
	p.IncomingViewKey = cp(o.Bytes(32))
	p.CreatedAt = o.Int64(40)
	return nil
}

// ================= Transaction =================
//
//	ID 32B@0, Type u8@32, Version u8@33, Fee u64@34, Expiry u64@42,
//	TInLens list@50, TInBlob bytes@58, TOutLens list@66, TOutBlob bytes@74,
//	NullLens list@82, NullBlob bytes@90, SOutLens list@98, SOutBlob bytes@106,
//	Proof bytes@114, FHE bytes@122, Memo bytes@130, Signature bytes@138
const txSize = 146

func (tx *Transaction) Marshal() ([]byte, error) {
	tinLens, tinBlob := packObjs(tx.TransparentInputs, marshalTransparentInput)
	toutLens, toutBlob := packObjs(tx.TransparentOutputs, marshalTransparentOutput)
	nullLens, nullBlob := packBytesList(tx.Nullifiers)
	soutLens, soutBlob := packObjs(tx.Outputs, marshalShieldedOutput)
	proof := marshalZKProof(tx.Proof)
	fhe := marshalFHEData(tx.FHEData)

	b := zap.NewBuilder(zap.HeaderSize + txSize + len(tinBlob) + len(toutBlob) + len(nullBlob) +
		len(soutBlob) + len(proof) + len(fhe) + len(tx.Memo) + len(tx.Signature) +
		4*(len(tinLens)+len(toutLens)+len(nullLens)+len(soutLens)) + 512)
	tinOff := writeU32List(b, tinLens)
	toutOff := writeU32List(b, toutLens)
	nullOff := writeU32List(b, nullLens)
	soutOff := writeU32List(b, soutLens)

	ob := b.StartObject(txSize)
	ob.SetBytesFixed(0, tx.ID[:])
	ob.SetUint8(32, uint8(tx.Type))
	ob.SetUint8(33, tx.Version)
	ob.SetUint64(34, tx.Fee)
	ob.SetUint64(42, tx.Expiry)
	ob.SetList(50, tinOff, len(tinLens))
	ob.SetBytes(58, tinBlob)
	ob.SetList(66, toutOff, len(toutLens))
	ob.SetBytes(74, toutBlob)
	ob.SetList(82, nullOff, len(nullLens))
	ob.SetBytes(90, nullBlob)
	ob.SetList(98, soutOff, len(soutLens))
	ob.SetBytes(106, soutBlob)
	ob.SetBytes(114, proof)
	ob.SetBytes(122, fhe)
	ob.SetBytes(130, tx.Memo)
	ob.SetBytes(138, tx.Signature)
	ob.FinishAsRoot()
	return b.Finish(), nil
}

func parseTransaction(data []byte) (*Transaction, error) {
	m, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	o := m.Root()
	tx := &Transaction{
		ID:      readID(o, 0),
		Type:    TransactionType(o.Uint8(32)),
		Version: o.Uint8(33),
		Fee:     o.Uint64(34),
		Expiry:  o.Uint64(42),
		Memo:    cp(o.Bytes(130)),
		Signature: cp(o.Bytes(138)),
	}
	if tx.TransparentInputs, err = unpackObjs(readU32List(o, 50), o.Bytes(58), parseTransparentInput); err != nil {
		return nil, err
	}
	if tx.TransparentOutputs, err = unpackObjs(readU32List(o, 66), o.Bytes(74), parseTransparentOutput); err != nil {
		return nil, err
	}
	tx.Nullifiers = unpackBytesList(readU32List(o, 82), o.Bytes(90))
	if tx.Outputs, err = unpackObjs(readU32List(o, 98), o.Bytes(106), parseShieldedOutput); err != nil {
		return nil, err
	}
	if tx.Proof, err = parseZKProof(o.Bytes(114)); err != nil {
		return nil, err
	}
	if tx.FHEData, err = parseFHEData(o.Bytes(122)); err != nil {
		return nil, err
	}
	return tx, nil
}

// MarshalTx / ParseTx are the exported tx wire entry points.
func (tx *Transaction) MarshalTx() ([]byte, error) { return tx.Marshal() }

// ================= Block =================
//
//	ParentID 32B@0, Height u64@32, Timestamp i64@40, TxLens list@48,
//	TxBlob bytes@56, StateRoot bytes@64, BlockProof bytes@72
const blkSize = 80

func (b *Block) Marshal() ([]byte, error) {
	txLens, txBlob := packObjs(b.Txs, func(t *Transaction) []byte { m, _ := t.Marshal(); return m })
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
	return bld.Finish(), nil
}

func parseBlockBytes(data []byte, blk *Block) error {
	m, err := zap.Parse(data)
	if err != nil {
		return err
	}
	if m.Size() != len(data) {
		return fmt.Errorf("zkvm block: trailing bytes")
	}
	o := m.Root()
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
