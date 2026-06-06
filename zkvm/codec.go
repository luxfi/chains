// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/luxfi/ids"
)

// Hand-rolled big-endian binary serialization for zkvm types.
//
// One canonical wire layout per type. No version prefix (hard cut, forward-only).
// Each type owns a marshalX / unmarshalX pair. Length-prefixed []byte uses u32.
// Length-prefixed slices of structs use u32 element count. Optional pointers
// use a 1-byte presence flag (0x00 = nil, 0x01 = present).
//
// Field order is fixed and stable. Renames or reorderings require a chain reset.

const (
	maxByteSliceLen = math.MaxUint32 // 4 GiB ceiling per []byte field
)

var (
	errShortBuffer  = errors.New("zkvm: short buffer")
	errOversizeSlice = errors.New("zkvm: slice exceeds max size")
)

// --- low-level primitive writers ---------------------------------------------

func writeUint8(buf []byte, off int, v uint8) int {
	buf[off] = v
	return off + 1
}

func writeUint32(buf []byte, off int, v uint32) int {
	binary.BigEndian.PutUint32(buf[off:off+4], v)
	return off + 4
}

func writeUint64(buf []byte, off int, v uint64) int {
	binary.BigEndian.PutUint64(buf[off:off+8], v)
	return off + 8
}

func writeBool(buf []byte, off int, v bool) int {
	if v {
		buf[off] = 1
	} else {
		buf[off] = 0
	}
	return off + 1
}

func writeBytes(buf []byte, off int, v []byte) int {
	off = writeUint32(buf, off, uint32(len(v)))
	copy(buf[off:], v)
	return off + len(v)
}

func writeString(buf []byte, off int, v string) int {
	off = writeUint32(buf, off, uint32(len(v)))
	copy(buf[off:], v)
	return off + len(v)
}

func writeID(buf []byte, off int, v ids.ID) int {
	copy(buf[off:off+ids.IDLen], v[:])
	return off + ids.IDLen
}

// --- low-level primitive readers (return new offset or error) ----------------

func readUint8(buf []byte, off int) (uint8, int, error) {
	if off+1 > len(buf) {
		return 0, off, errShortBuffer
	}
	return buf[off], off + 1, nil
}

func readUint32(buf []byte, off int) (uint32, int, error) {
	if off+4 > len(buf) {
		return 0, off, errShortBuffer
	}
	return binary.BigEndian.Uint32(buf[off : off+4]), off + 4, nil
}

func readUint64(buf []byte, off int) (uint64, int, error) {
	if off+8 > len(buf) {
		return 0, off, errShortBuffer
	}
	return binary.BigEndian.Uint64(buf[off : off+8]), off + 8, nil
}

func readBool(buf []byte, off int) (bool, int, error) {
	if off+1 > len(buf) {
		return false, off, errShortBuffer
	}
	return buf[off] != 0, off + 1, nil
}

func readBytes(buf []byte, off int) ([]byte, int, error) {
	n, off, err := readUint32(buf, off)
	if err != nil {
		return nil, off, err
	}
	if uint64(off)+uint64(n) > uint64(len(buf)) {
		return nil, off, errShortBuffer
	}
	if n == 0 {
		return nil, off, nil
	}
	out := make([]byte, n)
	copy(out, buf[off:off+int(n)])
	return out, off + int(n), nil
}

func readString(buf []byte, off int) (string, int, error) {
	b, off, err := readBytes(buf, off)
	if err != nil {
		return "", off, err
	}
	return string(b), off, nil
}

func readID(buf []byte, off int) (ids.ID, int, error) {
	if off+ids.IDLen > len(buf) {
		return ids.Empty, off, errShortBuffer
	}
	var id ids.ID
	copy(id[:], buf[off:off+ids.IDLen])
	return id, off + ids.IDLen, nil
}

// --- byte-slice sizing helpers -----------------------------------------------

func sizeBytes(v []byte) int  { return 4 + len(v) }
func sizeString(v string) int { return 4 + len(v) }

// --- Transaction -------------------------------------------------------------

// Wire layout:
//   id(32) | type(1) | version(1)
//   nTransparentInputs(4) | TransparentInput*
//   nTransparentOutputs(4) | TransparentOutput*
//   nNullifiers(4) | (len(4)|bytes)*
//   nOutputs(4) | ShieldedOutput*
//   proofPresent(1) | ZKProof?
//   fheDataPresent(1) | FHEData?
//   fee(8) | expiry(8) | memo(len4|bytes) | signature(len4|bytes)

func sizeTransaction(tx *Transaction) int {
	n := ids.IDLen + 1 + 1
	n += 4 // TransparentInputs count
	for _, ti := range tx.TransparentInputs {
		n += sizeTransparentInput(ti)
	}
	n += 4 // TransparentOutputs count
	for _, to := range tx.TransparentOutputs {
		n += sizeTransparentOutput(to)
	}
	n += 4 // Nullifiers count
	for _, nl := range tx.Nullifiers {
		n += sizeBytes(nl)
	}
	n += 4 // Outputs count
	for _, o := range tx.Outputs {
		n += sizeShieldedOutput(o)
	}
	n += 1 // Proof presence
	if tx.Proof != nil {
		n += sizeZKProof(tx.Proof)
	}
	n += 1 // FHEData presence
	if tx.FHEData != nil {
		n += sizeFHEData(tx.FHEData)
	}
	n += 8 // Fee
	n += 8 // Expiry
	n += sizeBytes(tx.Memo)
	n += sizeBytes(tx.Signature)
	return n
}

func marshalTransaction(tx *Transaction) ([]byte, error) {
	if tx == nil {
		return nil, errors.New("zkvm: marshal nil transaction")
	}
	if err := boundTransaction(tx); err != nil {
		return nil, err
	}
	buf := make([]byte, sizeTransaction(tx))
	off := 0
	off = writeID(buf, off, tx.ID)
	off = writeUint8(buf, off, uint8(tx.Type))
	off = writeUint8(buf, off, tx.Version)

	off = writeUint32(buf, off, uint32(len(tx.TransparentInputs)))
	for _, ti := range tx.TransparentInputs {
		off = writeTransparentInput(buf, off, ti)
	}

	off = writeUint32(buf, off, uint32(len(tx.TransparentOutputs)))
	for _, to := range tx.TransparentOutputs {
		off = writeTransparentOutput(buf, off, to)
	}

	off = writeUint32(buf, off, uint32(len(tx.Nullifiers)))
	for _, nl := range tx.Nullifiers {
		off = writeBytes(buf, off, nl)
	}

	off = writeUint32(buf, off, uint32(len(tx.Outputs)))
	for _, o := range tx.Outputs {
		off = writeShieldedOutput(buf, off, o)
	}

	if tx.Proof != nil {
		off = writeUint8(buf, off, 1)
		off = writeZKProof(buf, off, tx.Proof)
	} else {
		off = writeUint8(buf, off, 0)
	}

	if tx.FHEData != nil {
		off = writeUint8(buf, off, 1)
		off = writeFHEData(buf, off, tx.FHEData)
	} else {
		off = writeUint8(buf, off, 0)
	}

	off = writeUint64(buf, off, tx.Fee)
	off = writeUint64(buf, off, tx.Expiry)
	off = writeBytes(buf, off, tx.Memo)
	off = writeBytes(buf, off, tx.Signature)

	if off != len(buf) {
		return nil, fmt.Errorf("zkvm: tx marshal size mismatch: wrote %d want %d", off, len(buf))
	}
	return buf, nil
}

func unmarshalTransaction(buf []byte, tx *Transaction) error {
	if tx == nil {
		return errors.New("zkvm: unmarshal into nil transaction")
	}
	off := 0
	var err error

	if tx.ID, off, err = readID(buf, off); err != nil {
		return err
	}
	var tt uint8
	if tt, off, err = readUint8(buf, off); err != nil {
		return err
	}
	tx.Type = TransactionType(tt)
	if tx.Version, off, err = readUint8(buf, off); err != nil {
		return err
	}

	var n uint32
	if n, off, err = readUint32(buf, off); err != nil {
		return err
	}
	if n > maxByteSliceLen {
		return errOversizeSlice
	}
	if n > 0 {
		tx.TransparentInputs = make([]*TransparentInput, n)
		for i := uint32(0); i < n; i++ {
			ti := &TransparentInput{}
			if off, err = readTransparentInput(buf, off, ti); err != nil {
				return err
			}
			tx.TransparentInputs[i] = ti
		}
	}

	if n, off, err = readUint32(buf, off); err != nil {
		return err
	}
	if n > 0 {
		tx.TransparentOutputs = make([]*TransparentOutput, n)
		for i := uint32(0); i < n; i++ {
			to := &TransparentOutput{}
			if off, err = readTransparentOutput(buf, off, to); err != nil {
				return err
			}
			tx.TransparentOutputs[i] = to
		}
	}

	if n, off, err = readUint32(buf, off); err != nil {
		return err
	}
	if n > 0 {
		tx.Nullifiers = make([][]byte, n)
		for i := uint32(0); i < n; i++ {
			if tx.Nullifiers[i], off, err = readBytes(buf, off); err != nil {
				return err
			}
		}
	}

	if n, off, err = readUint32(buf, off); err != nil {
		return err
	}
	if n > 0 {
		tx.Outputs = make([]*ShieldedOutput, n)
		for i := uint32(0); i < n; i++ {
			so := &ShieldedOutput{}
			if off, err = readShieldedOutput(buf, off, so); err != nil {
				return err
			}
			tx.Outputs[i] = so
		}
	}

	var present uint8
	if present, off, err = readUint8(buf, off); err != nil {
		return err
	}
	if present != 0 {
		tx.Proof = &ZKProof{}
		if off, err = readZKProof(buf, off, tx.Proof); err != nil {
			return err
		}
	} else {
		tx.Proof = nil
	}

	if present, off, err = readUint8(buf, off); err != nil {
		return err
	}
	if present != 0 {
		tx.FHEData = &FHEData{}
		if off, err = readFHEData(buf, off, tx.FHEData); err != nil {
			return err
		}
	} else {
		tx.FHEData = nil
	}

	if tx.Fee, off, err = readUint64(buf, off); err != nil {
		return err
	}
	if tx.Expiry, off, err = readUint64(buf, off); err != nil {
		return err
	}
	if tx.Memo, off, err = readBytes(buf, off); err != nil {
		return err
	}
	if tx.Signature, _, err = readBytes(buf, off); err != nil {
		return err
	}
	return nil
}

// --- TransparentInput / TransparentOutput / ShieldedOutput -------------------

// TransparentInput: txID(32) | outputIdx(4) | amount(8) | address(len4|bytes)
func sizeTransparentInput(ti *TransparentInput) int {
	return ids.IDLen + 4 + 8 + sizeBytes(ti.Address)
}

func writeTransparentInput(buf []byte, off int, ti *TransparentInput) int {
	off = writeID(buf, off, ti.TxID)
	off = writeUint32(buf, off, ti.OutputIdx)
	off = writeUint64(buf, off, ti.Amount)
	off = writeBytes(buf, off, ti.Address)
	return off
}

func readTransparentInput(buf []byte, off int, ti *TransparentInput) (int, error) {
	var err error
	if ti.TxID, off, err = readID(buf, off); err != nil {
		return off, err
	}
	if ti.OutputIdx, off, err = readUint32(buf, off); err != nil {
		return off, err
	}
	if ti.Amount, off, err = readUint64(buf, off); err != nil {
		return off, err
	}
	if ti.Address, off, err = readBytes(buf, off); err != nil {
		return off, err
	}
	return off, nil
}

// TransparentOutput: amount(8) | address(len4|bytes) | assetID(32)
func sizeTransparentOutput(to *TransparentOutput) int {
	return 8 + sizeBytes(to.Address) + ids.IDLen
}

func writeTransparentOutput(buf []byte, off int, to *TransparentOutput) int {
	off = writeUint64(buf, off, to.Amount)
	off = writeBytes(buf, off, to.Address)
	off = writeID(buf, off, to.AssetID)
	return off
}

func readTransparentOutput(buf []byte, off int, to *TransparentOutput) (int, error) {
	var err error
	if to.Amount, off, err = readUint64(buf, off); err != nil {
		return off, err
	}
	if to.Address, off, err = readBytes(buf, off); err != nil {
		return off, err
	}
	if to.AssetID, off, err = readID(buf, off); err != nil {
		return off, err
	}
	return off, nil
}

// ShieldedOutput: commitment(len4|bytes) | encryptedNote(len4|bytes) |
//                 ephemeralPubKey(len4|bytes) | outputProof(len4|bytes)
func sizeShieldedOutput(so *ShieldedOutput) int {
	return sizeBytes(so.Commitment) + sizeBytes(so.EncryptedNote) +
		sizeBytes(so.EphemeralPubKey) + sizeBytes(so.OutputProof)
}

func writeShieldedOutput(buf []byte, off int, so *ShieldedOutput) int {
	off = writeBytes(buf, off, so.Commitment)
	off = writeBytes(buf, off, so.EncryptedNote)
	off = writeBytes(buf, off, so.EphemeralPubKey)
	off = writeBytes(buf, off, so.OutputProof)
	return off
}

func readShieldedOutput(buf []byte, off int, so *ShieldedOutput) (int, error) {
	var err error
	if so.Commitment, off, err = readBytes(buf, off); err != nil {
		return off, err
	}
	if so.EncryptedNote, off, err = readBytes(buf, off); err != nil {
		return off, err
	}
	if so.EphemeralPubKey, off, err = readBytes(buf, off); err != nil {
		return off, err
	}
	if so.OutputProof, off, err = readBytes(buf, off); err != nil {
		return off, err
	}
	return off, nil
}

// --- ZKProof -----------------------------------------------------------------

// proofType(len4|string) | proofData(len4|bytes) | nPublicInputs(4) | (len4|bytes)*
func sizeZKProof(p *ZKProof) int {
	n := sizeString(p.ProofType) + sizeBytes(p.ProofData) + 4
	for _, pi := range p.PublicInputs {
		n += sizeBytes(pi)
	}
	return n
}

func writeZKProof(buf []byte, off int, p *ZKProof) int {
	off = writeString(buf, off, p.ProofType)
	off = writeBytes(buf, off, p.ProofData)
	off = writeUint32(buf, off, uint32(len(p.PublicInputs)))
	for _, pi := range p.PublicInputs {
		off = writeBytes(buf, off, pi)
	}
	return off
}

func readZKProof(buf []byte, off int, p *ZKProof) (int, error) {
	var err error
	if p.ProofType, off, err = readString(buf, off); err != nil {
		return off, err
	}
	if p.ProofData, off, err = readBytes(buf, off); err != nil {
		return off, err
	}
	var n uint32
	if n, off, err = readUint32(buf, off); err != nil {
		return off, err
	}
	if n > 0 {
		p.PublicInputs = make([][]byte, n)
		for i := uint32(0); i < n; i++ {
			if p.PublicInputs[i], off, err = readBytes(buf, off); err != nil {
				return off, err
			}
		}
	}
	return off, nil
}

// --- FHEData -----------------------------------------------------------------

// nEncryptedInputs(4) | (len4|bytes)* | circuitID(len4|string) |
// encryptedResult(len4|bytes) | computationProof(len4|bytes)
func sizeFHEData(f *FHEData) int {
	n := 4
	for _, ei := range f.EncryptedInputs {
		n += sizeBytes(ei)
	}
	n += sizeString(f.CircuitID)
	n += sizeBytes(f.EncryptedResult)
	n += sizeBytes(f.ComputationProof)
	return n
}

func writeFHEData(buf []byte, off int, f *FHEData) int {
	off = writeUint32(buf, off, uint32(len(f.EncryptedInputs)))
	for _, ei := range f.EncryptedInputs {
		off = writeBytes(buf, off, ei)
	}
	off = writeString(buf, off, f.CircuitID)
	off = writeBytes(buf, off, f.EncryptedResult)
	off = writeBytes(buf, off, f.ComputationProof)
	return off
}

func readFHEData(buf []byte, off int, f *FHEData) (int, error) {
	var err error
	var n uint32
	if n, off, err = readUint32(buf, off); err != nil {
		return off, err
	}
	if n > 0 {
		f.EncryptedInputs = make([][]byte, n)
		for i := uint32(0); i < n; i++ {
			if f.EncryptedInputs[i], off, err = readBytes(buf, off); err != nil {
				return off, err
			}
		}
	}
	if f.CircuitID, off, err = readString(buf, off); err != nil {
		return off, err
	}
	if f.EncryptedResult, off, err = readBytes(buf, off); err != nil {
		return off, err
	}
	if f.ComputationProof, off, err = readBytes(buf, off); err != nil {
		return off, err
	}
	return off, nil
}

// --- Block -------------------------------------------------------------------

// Wire layout:
//   parentID(32) | height(8) | timestamp(8)
//   nTxs(4) | Transaction*
//   stateRoot(len4|bytes)
//   blockProofPresent(1) | ZKProof?

func sizeBlock(b *Block) int {
	n := ids.IDLen + 8 + 8 + 4
	for _, tx := range b.Txs {
		n += 4 // per-tx length prefix (allows independent skipping)
		n += sizeTransaction(tx)
	}
	n += sizeBytes(b.StateRoot)
	n += 1
	if b.BlockProof != nil {
		n += sizeZKProof(b.BlockProof)
	}
	return n
}

func marshalBlock(b *Block) ([]byte, error) {
	if b == nil {
		return nil, errors.New("zkvm: marshal nil block")
	}
	buf := make([]byte, sizeBlock(b))
	off := 0
	off = writeID(buf, off, b.ParentID_)
	off = writeUint64(buf, off, b.BlockHeight)
	off = writeUint64(buf, off, uint64(b.BlockTimestamp))
	off = writeUint32(buf, off, uint32(len(b.Txs)))
	for _, tx := range b.Txs {
		txBytes, err := marshalTransaction(tx)
		if err != nil {
			return nil, err
		}
		off = writeUint32(buf, off, uint32(len(txBytes)))
		copy(buf[off:], txBytes)
		off += len(txBytes)
	}
	off = writeBytes(buf, off, b.StateRoot)
	if b.BlockProof != nil {
		off = writeUint8(buf, off, 1)
		off = writeZKProof(buf, off, b.BlockProof)
	} else {
		off = writeUint8(buf, off, 0)
	}
	if off != len(buf) {
		return nil, fmt.Errorf("zkvm: block marshal size mismatch: wrote %d want %d", off, len(buf))
	}
	return buf, nil
}

func unmarshalBlock(buf []byte, b *Block) error {
	if b == nil {
		return errors.New("zkvm: unmarshal into nil block")
	}
	off := 0
	var err error
	if b.ParentID_, off, err = readID(buf, off); err != nil {
		return err
	}
	if b.BlockHeight, off, err = readUint64(buf, off); err != nil {
		return err
	}
	var ts uint64
	if ts, off, err = readUint64(buf, off); err != nil {
		return err
	}
	b.BlockTimestamp = int64(ts)
	var n uint32
	if n, off, err = readUint32(buf, off); err != nil {
		return err
	}
	if n > 0 {
		b.Txs = make([]*Transaction, n)
		for i := uint32(0); i < n; i++ {
			var txLen uint32
			if txLen, off, err = readUint32(buf, off); err != nil {
				return err
			}
			if uint64(off)+uint64(txLen) > uint64(len(buf)) {
				return errShortBuffer
			}
			tx := &Transaction{}
			if err := unmarshalTransaction(buf[off:off+int(txLen)], tx); err != nil {
				return err
			}
			off += int(txLen)
			b.Txs[i] = tx
		}
	}
	if b.StateRoot, off, err = readBytes(buf, off); err != nil {
		return err
	}
	var present uint8
	if present, off, err = readUint8(buf, off); err != nil {
		return err
	}
	if present != 0 {
		b.BlockProof = &ZKProof{}
		if _, err = readZKProof(buf, off, b.BlockProof); err != nil {
			return err
		}
	} else {
		b.BlockProof = nil
	}
	return nil
}

// --- UTXO --------------------------------------------------------------------

// txID(32) | outputIndex(4) | commitment(len4|bytes) | ciphertext(len4|bytes) |
// ephemeralPK(len4|bytes) | height(8)

func sizeUTXO(u *UTXO) int {
	return ids.IDLen + 4 + sizeBytes(u.Commitment) + sizeBytes(u.Ciphertext) +
		sizeBytes(u.EphemeralPK) + 8
}

func marshalUTXO(u *UTXO) ([]byte, error) {
	if u == nil {
		return nil, errors.New("zkvm: marshal nil utxo")
	}
	buf := make([]byte, sizeUTXO(u))
	off := 0
	off = writeID(buf, off, u.TxID)
	off = writeUint32(buf, off, u.OutputIndex)
	off = writeBytes(buf, off, u.Commitment)
	off = writeBytes(buf, off, u.Ciphertext)
	off = writeBytes(buf, off, u.EphemeralPK)
	_ = writeUint64(buf, off, u.Height)
	return buf, nil
}

func unmarshalUTXO(buf []byte, u *UTXO) error {
	if u == nil {
		return errors.New("zkvm: unmarshal into nil utxo")
	}
	off := 0
	var err error
	if u.TxID, off, err = readID(buf, off); err != nil {
		return err
	}
	if u.OutputIndex, off, err = readUint32(buf, off); err != nil {
		return err
	}
	if u.Commitment, off, err = readBytes(buf, off); err != nil {
		return err
	}
	if u.Ciphertext, off, err = readBytes(buf, off); err != nil {
		return err
	}
	if u.EphemeralPK, off, err = readBytes(buf, off); err != nil {
		return err
	}
	if u.Height, _, err = readUint64(buf, off); err != nil {
		return err
	}
	return nil
}

// --- Genesis -----------------------------------------------------------------

// timestamp(8) | nInitialTxs(4) | (len4|txBytes)* | setupParamsPresent(1) | SetupParams?
// SetupParams: powersOfTau(len4|bytes) | verifyingKey(len4|bytes) |
//              plonkSRS(len4|bytes) | fhePublicParams(len4|bytes)

func sizeGenesis(g *Genesis) int {
	n := 8 + 4
	for _, tx := range g.InitialTxs {
		n += 4 + sizeTransaction(tx)
	}
	n += 1
	if g.SetupParams != nil {
		n += sizeBytes(g.SetupParams.PowersOfTau) +
			sizeBytes(g.SetupParams.VerifyingKey) +
			sizeBytes(g.SetupParams.PlonkSRS) +
			sizeBytes(g.SetupParams.FHEPublicParams)
	}
	return n
}

func marshalGenesis(g *Genesis) ([]byte, error) {
	if g == nil {
		return nil, errors.New("zkvm: marshal nil genesis")
	}
	buf := make([]byte, sizeGenesis(g))
	off := 0
	off = writeUint64(buf, off, uint64(g.Timestamp))
	off = writeUint32(buf, off, uint32(len(g.InitialTxs)))
	for _, tx := range g.InitialTxs {
		txBytes, err := marshalTransaction(tx)
		if err != nil {
			return nil, err
		}
		off = writeUint32(buf, off, uint32(len(txBytes)))
		copy(buf[off:], txBytes)
		off += len(txBytes)
	}
	if g.SetupParams != nil {
		off = writeUint8(buf, off, 1)
		off = writeBytes(buf, off, g.SetupParams.PowersOfTau)
		off = writeBytes(buf, off, g.SetupParams.VerifyingKey)
		off = writeBytes(buf, off, g.SetupParams.PlonkSRS)
		off = writeBytes(buf, off, g.SetupParams.FHEPublicParams)
	} else {
		off = writeUint8(buf, off, 0)
	}
	if off != len(buf) {
		return nil, fmt.Errorf("zkvm: genesis marshal size mismatch: wrote %d want %d", off, len(buf))
	}
	return buf, nil
}

func unmarshalGenesis(buf []byte, g *Genesis) error {
	if g == nil {
		return errors.New("zkvm: unmarshal into nil genesis")
	}
	off := 0
	var err error
	var ts uint64
	if ts, off, err = readUint64(buf, off); err != nil {
		return err
	}
	g.Timestamp = int64(ts)
	var n uint32
	if n, off, err = readUint32(buf, off); err != nil {
		return err
	}
	if n > 0 {
		g.InitialTxs = make([]*Transaction, n)
		for i := uint32(0); i < n; i++ {
			var txLen uint32
			if txLen, off, err = readUint32(buf, off); err != nil {
				return err
			}
			if uint64(off)+uint64(txLen) > uint64(len(buf)) {
				return errShortBuffer
			}
			tx := &Transaction{}
			if err := unmarshalTransaction(buf[off:off+int(txLen)], tx); err != nil {
				return err
			}
			off += int(txLen)
			g.InitialTxs[i] = tx
		}
	}
	var present uint8
	if present, off, err = readUint8(buf, off); err != nil {
		return err
	}
	if present != 0 {
		sp := &SetupParams{}
		if sp.PowersOfTau, off, err = readBytes(buf, off); err != nil {
			return err
		}
		if sp.VerifyingKey, off, err = readBytes(buf, off); err != nil {
			return err
		}
		if sp.PlonkSRS, off, err = readBytes(buf, off); err != nil {
			return err
		}
		if sp.FHEPublicParams, _, err = readBytes(buf, off); err != nil {
			return err
		}
		g.SetupParams = sp
	} else {
		g.SetupParams = nil
	}
	return nil
}

// --- ZConfig -----------------------------------------------------------------

// Field order matches struct definition (must be stable):
//   enableConfidentialTransfers(1) | enablePrivateAddresses(1)
//   proofSystem(len4|string) | circuitType(len4|string)
//   verifyingKeyPath(len4|string) | trustedSetupPath(len4|string)
//   enableFHE(1) | fheScheme(len4|string) | securityLevel(4)
//   maxUTXOsPerBlock(4) | proofVerificationTimeoutNanos(8) | proofCacheSize(4)

func sizeConfig(c *ZConfig) int {
	return 1 + 1 +
		sizeString(c.ProofSystem) + sizeString(c.CircuitType) +
		sizeString(c.VerifyingKeyPath) + sizeString(c.TrustedSetupPath) +
		1 + sizeString(c.FHEScheme) + 4 +
		4 + 8 + 4
}

func marshalConfig(c *ZConfig) ([]byte, error) {
	if c == nil {
		return nil, errors.New("zkvm: marshal nil config")
	}
	buf := make([]byte, sizeConfig(c))
	off := 0
	off = writeBool(buf, off, c.EnableConfidentialTransfers)
	off = writeBool(buf, off, c.EnablePrivateAddresses)
	off = writeString(buf, off, c.ProofSystem)
	off = writeString(buf, off, c.CircuitType)
	off = writeString(buf, off, c.VerifyingKeyPath)
	off = writeString(buf, off, c.TrustedSetupPath)
	off = writeBool(buf, off, c.EnableFHE)
	off = writeString(buf, off, c.FHEScheme)
	off = writeUint32(buf, off, c.SecurityLevel)
	off = writeUint32(buf, off, c.MaxUTXOsPerBlock)
	off = writeUint64(buf, off, uint64(c.ProofVerificationTimeout.Nanoseconds()))
	_ = writeUint32(buf, off, c.ProofCacheSize)
	return buf, nil
}

func unmarshalConfig(buf []byte, c *ZConfig) error {
	if c == nil {
		return errors.New("zkvm: unmarshal into nil config")
	}
	off := 0
	var err error
	if c.EnableConfidentialTransfers, off, err = readBool(buf, off); err != nil {
		return err
	}
	if c.EnablePrivateAddresses, off, err = readBool(buf, off); err != nil {
		return err
	}
	if c.ProofSystem, off, err = readString(buf, off); err != nil {
		return err
	}
	if c.CircuitType, off, err = readString(buf, off); err != nil {
		return err
	}
	if c.VerifyingKeyPath, off, err = readString(buf, off); err != nil {
		return err
	}
	if c.TrustedSetupPath, off, err = readString(buf, off); err != nil {
		return err
	}
	if c.EnableFHE, off, err = readBool(buf, off); err != nil {
		return err
	}
	if c.FHEScheme, off, err = readString(buf, off); err != nil {
		return err
	}
	if c.SecurityLevel, off, err = readUint32(buf, off); err != nil {
		return err
	}
	if c.MaxUTXOsPerBlock, off, err = readUint32(buf, off); err != nil {
		return err
	}
	var nanos uint64
	if nanos, off, err = readUint64(buf, off); err != nil {
		return err
	}
	c.ProofVerificationTimeout = time.Duration(int64(nanos))
	if c.ProofCacheSize, _, err = readUint32(buf, off); err != nil {
		return err
	}
	return nil
}

// --- PrivateAddress ----------------------------------------------------------

// address(len4|bytes) | viewingKey(len4|bytes) | spendingKey(len4|bytes) |
// diversifier(len4|bytes) | incomingViewKey(len4|bytes) | createdAt(8)

func sizePrivateAddress(p *PrivateAddress) int {
	return sizeBytes(p.Address) + sizeBytes(p.ViewingKey) + sizeBytes(p.SpendingKey) +
		sizeBytes(p.Diversifier) + sizeBytes(p.IncomingViewKey) + 8
}

func marshalPrivateAddress(p *PrivateAddress) ([]byte, error) {
	if p == nil {
		return nil, errors.New("zkvm: marshal nil private address")
	}
	buf := make([]byte, sizePrivateAddress(p))
	off := 0
	off = writeBytes(buf, off, p.Address)
	off = writeBytes(buf, off, p.ViewingKey)
	off = writeBytes(buf, off, p.SpendingKey)
	off = writeBytes(buf, off, p.Diversifier)
	off = writeBytes(buf, off, p.IncomingViewKey)
	_ = writeUint64(buf, off, uint64(p.CreatedAt))
	return buf, nil
}

func unmarshalPrivateAddress(buf []byte, p *PrivateAddress) error {
	if p == nil {
		return errors.New("zkvm: unmarshal into nil private address")
	}
	off := 0
	var err error
	if p.Address, off, err = readBytes(buf, off); err != nil {
		return err
	}
	if p.ViewingKey, off, err = readBytes(buf, off); err != nil {
		return err
	}
	if p.SpendingKey, off, err = readBytes(buf, off); err != nil {
		return err
	}
	if p.Diversifier, off, err = readBytes(buf, off); err != nil {
		return err
	}
	if p.IncomingViewKey, off, err = readBytes(buf, off); err != nil {
		return err
	}
	var ts uint64
	if ts, _, err = readUint64(buf, off); err != nil {
		return err
	}
	p.CreatedAt = int64(ts)
	return nil
}

// --- bounds checking ---------------------------------------------------------

// boundTransaction rejects pathological inputs that would overflow our u32
// length prefixes. Callers should treat tx as untrusted.
func boundTransaction(tx *Transaction) error {
	if len(tx.TransparentInputs) > maxByteSliceLen {
		return errOversizeSlice
	}
	if len(tx.TransparentOutputs) > maxByteSliceLen {
		return errOversizeSlice
	}
	if len(tx.Nullifiers) > maxByteSliceLen {
		return errOversizeSlice
	}
	if len(tx.Outputs) > maxByteSliceLen {
		return errOversizeSlice
	}
	for _, nl := range tx.Nullifiers {
		if len(nl) > maxByteSliceLen {
			return errOversizeSlice
		}
	}
	return nil
}
