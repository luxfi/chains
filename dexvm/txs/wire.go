// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package txs

import (
	"errors"

	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for the D-Chain (dexvm) transaction surface. No
// encoding/json, no reflection, no codec registry — each concrete tx owns its
// marshal/parse over a zap object at FIXED field offsets. Re-genesis is
// authorized, so the on-wire format is exactly these offsets.
//
// Wire envelope (unchanged discriminator contract):
//
//	[0]   = TxType   (TxParser.Parse dispatches on it)
//	[1:]  = ZAP message (one root object per tx)
//
// Determinism is structural: fixed offsets, no maps, list order preserved. The
// same logical tx therefore serializes to identical bytes, so TxID =
// ids.Checksum256(wire) is stable across nodes (strictly better than the prior
// reliance on Go's declaration-order JSON emission).
//
// TxType/TxID/bytes are NOT stored in the ZAP body: TxType is the leading
// discriminator byte (re-stamped from dispatch), and TxID/bytes are derived
// from the wire on parse. This mirrors the JSON codec it replaces.

var errTrailingBytes = errors.New("dexvm tx: trailing bytes after zap message")

// ---- BaseTx (embedded field block, identical prefix in every tx object) ----
//
//	From      20B   @ 0
//	Nonce     u64   @ 20
//	GasPrice  u64   @ 28
//	GasLimit  u64   @ 36
//	CreatedAt i64   @ 44
//	Signature bytes @ 52   (relOffset+length, 8 bytes)
const (
	bsFrom      = 0
	bsNonce     = 20
	bsGasPrice  = 28
	bsGasLimit  = 36
	bsCreatedAt = 44
	bsSig       = 52
	bsEnd       = 60
)

func setBase(ob zap.ObjectBuilder, b *BaseTx) {
	ob.SetBytesFixed(bsFrom, b.From[:])
	ob.SetUint64(bsNonce, b.Nonce)
	ob.SetUint64(bsGasPrice, b.GasPrice)
	ob.SetUint64(bsGasLimit, b.GasLimit)
	ob.SetInt64(bsCreatedAt, b.CreatedAt)
	ob.SetBytes(bsSig, b.Signature)
}

func readBase(o zap.Object, b *BaseTx) {
	copy(b.From[:], o.BytesFixedSlice(bsFrom, 20))
	b.Nonce = o.Uint64(bsNonce)
	b.GasPrice = o.Uint64(bsGasPrice)
	b.GasLimit = o.Uint64(bsGasLimit)
	b.CreatedAt = o.Int64(bsCreatedAt)
	b.Signature = appendBytes(o.Bytes(bsSig))
}

// ---- AtomicInput (nested element, fixed size) ----
//
//	UTXOID 32B @ 0
//	Asset  32B @ 32
//	Amount u64 @ 64
const (
	aiUTXOID = 0
	aiAsset  = 32
	aiAmount = 64
	aiSize   = 72
)

func marshalAtomicInput(in AtomicInput) []byte {
	b := zap.NewBuilder(zap.HeaderSize + aiSize)
	ob := b.StartObject(aiSize)
	ob.SetBytesFixed(aiUTXOID, in.UTXOID[:])
	ob.SetBytesFixed(aiAsset, in.Asset[:])
	ob.SetUint64(aiAmount, in.Amount)
	ob.FinishAsRoot()
	return b.Finish()
}

func readAtomicInput(o zap.Object) AtomicInput {
	var in AtomicInput
	copy(in.UTXOID[:], o.BytesFixedSlice(aiUTXOID, 32))
	copy(in.Asset[:], o.BytesFixedSlice(aiAsset, 32))
	in.Amount = o.Uint64(aiAmount)
	return in
}

// ---- AtomicOutput (nested element, fixed size) ----
//
//	Rail   u8  @ 0
//	Owner  20B @ 1
//	Asset  32B @ 21
//	Amount u64 @ 53
//	Spent  u64 @ 61
const (
	aoRail   = 0
	aoOwner  = 1
	aoAsset  = 21
	aoAmount = 53
	aoSpent  = 61
	aoSize   = 69
)

func marshalAtomicOutput(out AtomicOutput) []byte {
	b := zap.NewBuilder(zap.HeaderSize + aoSize)
	ob := b.StartObject(aoSize)
	ob.SetUint8(aoRail, uint8(out.Rail))
	ob.SetBytesFixed(aoOwner, out.Owner[:])
	ob.SetBytesFixed(aoAsset, out.Asset[:])
	ob.SetUint64(aoAmount, out.Amount)
	ob.SetUint64(aoSpent, out.Spent)
	ob.FinishAsRoot()
	return b.Finish()
}

func readAtomicOutput(o zap.Object) AtomicOutput {
	var out AtomicOutput
	out.Rail = Rail(o.Uint8(aoRail))
	copy(out.Owner[:], o.BytesFixedSlice(aoOwner, 20))
	copy(out.Asset[:], o.BytesFixedSlice(aoAsset, 32))
	out.Amount = o.Uint64(aoAmount)
	out.Spent = o.Uint64(aoSpent)
	return out
}

func packInputs(in []AtomicInput) ([]uint32, []byte) {
	lens := make([]uint32, len(in))
	var blob []byte
	for i := range in {
		e := marshalAtomicInput(in[i])
		lens[i] = uint32(len(e))
		blob = append(blob, e...)
	}
	return lens, blob
}

func packOutputs(out []AtomicOutput) ([]uint32, []byte) {
	lens := make([]uint32, len(out))
	var blob []byte
	for i := range out {
		e := marshalAtomicOutput(out[i])
		lens[i] = uint32(len(e))
		blob = append(blob, e...)
	}
	return lens, blob
}

func readInputs(o zap.Object, lensOff, blobOff int) []AtomicInput {
	lens := readU32List(o, lensOff)
	if len(lens) == 0 {
		return nil
	}
	blob := o.Bytes(blobOff)
	out := make([]AtomicInput, 0, len(lens))
	pos := 0
	for _, l := range lens {
		if pos+int(l) > len(blob) {
			break
		}
		m, err := zap.Parse(blob[pos : pos+int(l)])
		if err != nil {
			break
		}
		out = append(out, readAtomicInput(m.Root()))
		pos += int(l)
	}
	return out
}

func readOutputs(o zap.Object, lensOff, blobOff int) []AtomicOutput {
	lens := readU32List(o, lensOff)
	if len(lens) == 0 {
		return nil
	}
	blob := o.Bytes(blobOff)
	out := make([]AtomicOutput, 0, len(lens))
	pos := 0
	for _, l := range lens {
		if pos+int(l) > len(blob) {
			break
		}
		m, err := zap.Parse(blob[pos : pos+int(l)])
		if err != nil {
			break
		}
		out = append(out, readAtomicOutput(m.Root()))
		pos += int(l)
	}
	return out
}

// ---- ImportTx ----
//
//	base         @ 0..59
//	SourceChain  32B   @ 60
//	InLens       list  @ 92
//	InBlob       bytes @ 100
//	OutLens      list  @ 108
//	OutBlob      bytes @ 116
const (
	imSource  = bsEnd
	imInLens  = 92
	imInBlob  = 100
	imOutLens = 108
	imOutBlob = 116
	imSize    = 124
)

func marshalImportTx(tx *ImportTx) []byte {
	inLens, inBlob := packInputs(tx.ImportedInputs)
	outLens, outBlob := packOutputs(tx.Outputs)

	b := zap.NewBuilder(zap.HeaderSize + imSize + len(tx.Signature) +
		len(inBlob) + len(outBlob) + 4*(len(inLens)+len(outLens)) + 256)
	inLensOff := writeU32List(b, inLens)
	outLensOff := writeU32List(b, outLens)

	ob := b.StartObject(imSize)
	setBase(ob, &tx.BaseTx)
	ob.SetBytesFixed(imSource, tx.SourceChain[:])
	ob.SetList(imInLens, inLensOff, len(inLens))
	ob.SetBytes(imInBlob, inBlob)
	ob.SetList(imOutLens, outLensOff, len(outLens))
	ob.SetBytes(imOutBlob, outBlob)
	ob.FinishAsRoot()
	return withType(TxImport, b.Finish())
}

func parseImportTx(data []byte) (*ImportTx, error) {
	o, err := parseRoot(data)
	if err != nil {
		return nil, err
	}
	tx := &ImportTx{}
	readBase(o, &tx.BaseTx)
	copy(tx.SourceChain[:], o.BytesFixedSlice(imSource, 32))
	tx.ImportedInputs = readInputs(o, imInLens, imInBlob)
	tx.Outputs = readOutputs(o, imOutLens, imOutBlob)
	stampBase(tx, TxImport, data)
	return tx, nil
}

// ---- ExportTx ----
//
//	base       @ 0..59
//	DestChain  32B   @ 60
//	FillRef    32B   @ 92
//	OutLens    list  @ 124
//	OutBlob    bytes @ 132
const (
	exDest    = bsEnd
	exFillRef = 92
	exOutLens = 124
	exOutBlob = 132
	exSize    = 140
)

func marshalExportTx(tx *ExportTx) []byte {
	outLens, outBlob := packOutputs(tx.ExportedOutputs)

	b := zap.NewBuilder(zap.HeaderSize + exSize + len(tx.Signature) +
		len(outBlob) + 4*len(outLens) + 256)
	outLensOff := writeU32List(b, outLens)

	ob := b.StartObject(exSize)
	setBase(ob, &tx.BaseTx)
	ob.SetBytesFixed(exDest, tx.DestinationChain[:])
	ob.SetBytesFixed(exFillRef, tx.FillRef[:])
	ob.SetList(exOutLens, outLensOff, len(outLens))
	ob.SetBytes(exOutBlob, outBlob)
	ob.FinishAsRoot()
	return withType(TxExport, b.Finish())
}

func parseExportTx(data []byte) (*ExportTx, error) {
	o, err := parseRoot(data)
	if err != nil {
		return nil, err
	}
	tx := &ExportTx{}
	readBase(o, &tx.BaseTx)
	copy(tx.DestinationChain[:], o.BytesFixedSlice(exDest, 32))
	copy(tx.FillRef[:], o.BytesFixedSlice(exFillRef, 32))
	tx.ExportedOutputs = readOutputs(o, exOutLens, exOutBlob)
	stampBase(tx, TxExport, data)
	return tx, nil
}

// ---- RelayOrderTx ----
//
//	base           @ 0..59
//	CollateralRef  32B   @ 60
//	AssetOut       32B   @ 92
//	PriceLimit     u64   @ 124
//	LimitIsUpper   u8    @ 132
//	Method         bytes @ 133
//	Payload        bytes @ 141
const (
	rlColl    = bsEnd
	rlAsset   = 92
	rlPrice   = 124
	rlUpper   = 132
	rlMethod  = 133
	rlPayload = 141
	rlSize    = 149
)

func marshalRelayOrderTx(tx *RelayOrderTx) []byte {
	b := zap.NewBuilder(zap.HeaderSize + rlSize + len(tx.Signature) +
		len(tx.Method) + len(tx.Payload) + 128)
	ob := b.StartObject(rlSize)
	setBase(ob, &tx.BaseTx)
	ob.SetBytesFixed(rlColl, tx.CollateralRef[:])
	ob.SetBytesFixed(rlAsset, tx.AssetOut[:])
	ob.SetUint64(rlPrice, tx.PriceLimit)
	ob.SetBool(rlUpper, tx.LimitIsUpper)
	ob.SetBytes(rlMethod, []byte(tx.Method))
	ob.SetBytes(rlPayload, tx.Payload)
	ob.FinishAsRoot()
	return withType(TxRelayOrder, b.Finish())
}

func parseRelayOrderTx(data []byte) (*RelayOrderTx, error) {
	o, err := parseRoot(data)
	if err != nil {
		return nil, err
	}
	tx := &RelayOrderTx{}
	readBase(o, &tx.BaseTx)
	copy(tx.CollateralRef[:], o.BytesFixedSlice(rlColl, 32))
	copy(tx.AssetOut[:], o.BytesFixedSlice(rlAsset, 32))
	tx.PriceLimit = o.Uint64(rlPrice)
	tx.LimitIsUpper = o.Bool(rlUpper)
	tx.Method = string(o.Bytes(rlMethod))
	tx.Payload = appendBytes(o.Bytes(rlPayload))
	stampBase(tx, TxRelayOrder, data)
	return tx, nil
}

// ---- PlaceOrderTx ----
//
//	base           @ 0..59
//	PoolID         32B  @ 60
//	CollateralRef  32B  @ 92
//	Price          u64  @ 124
//	Size           u64  @ 132
//	Side           u8   @ 140
const (
	plPool  = bsEnd
	plColl  = 92
	plPrice = 124
	plSize  = 132
	plSide  = 140
	plObjSz = 141
)

func marshalPlaceOrderTx(tx *PlaceOrderTx) []byte {
	b := zap.NewBuilder(zap.HeaderSize + plObjSz + len(tx.Signature) + 64)
	ob := b.StartObject(plObjSz)
	setBase(ob, &tx.BaseTx)
	ob.SetBytesFixed(plPool, tx.PoolID[:])
	ob.SetBytesFixed(plColl, tx.CollateralRef[:])
	ob.SetUint64(plPrice, tx.Price)
	ob.SetUint64(plSize, tx.Size)
	ob.SetUint8(plSide, tx.Side)
	ob.FinishAsRoot()
	return withType(TxPlaceOrder, b.Finish())
}

func parsePlaceOrderTx(data []byte) (*PlaceOrderTx, error) {
	o, err := parseRoot(data)
	if err != nil {
		return nil, err
	}
	tx := &PlaceOrderTx{}
	readBase(o, &tx.BaseTx)
	copy(tx.PoolID[:], o.BytesFixedSlice(plPool, 32))
	copy(tx.CollateralRef[:], o.BytesFixedSlice(plColl, 32))
	tx.Price = o.Uint64(plPrice)
	tx.Size = o.Uint64(plSize)
	tx.Side = o.Uint8(plSide)
	stampBase(tx, TxPlaceOrder, data)
	return tx, nil
}

// ---- CancelOrderTx ----
//
//	base       @ 0..59
//	PoolID     32B  @ 60
//	OrderID    u64  @ 92
const (
	cnPool    = bsEnd
	cnOrderID = 92
	cnSize    = 100
)

func marshalCancelOrderTx(tx *CancelOrderTx) []byte {
	b := zap.NewBuilder(zap.HeaderSize + cnSize + len(tx.Signature) + 64)
	ob := b.StartObject(cnSize)
	setBase(ob, &tx.BaseTx)
	ob.SetBytesFixed(cnPool, tx.PoolID[:])
	ob.SetUint64(cnOrderID, tx.OrderID)
	ob.FinishAsRoot()
	return withType(TxCancelOrder, b.Finish())
}

func parseCancelOrderTx(data []byte) (*CancelOrderTx, error) {
	o, err := parseRoot(data)
	if err != nil {
		return nil, err
	}
	tx := &CancelOrderTx{}
	readBase(o, &tx.BaseTx)
	copy(tx.PoolID[:], o.BytesFixedSlice(cnPool, 32))
	tx.OrderID = o.Uint64(cnOrderID)
	stampBase(tx, TxCancelOrder, data)
	return tx, nil
}

// ---- shared helpers ----

// parseRoot parses the ZAP message that follows the leading TxType byte and
// returns its root object. Canonical: rejects trailing bytes (the message must
// consume exactly data[1:]).
func parseRoot(data []byte) (zap.Object, error) {
	msg, err := zap.Parse(data[1:])
	if err != nil {
		return zap.Object{}, err
	}
	if msg.Size() != len(data)-1 {
		return zap.Object{}, errTrailingBytes
	}
	return msg.Root(), nil
}

// withType prepends the TxType discriminator byte to a ZAP message body.
func withType(txType TxType, body []byte) []byte {
	out := make([]byte, 1+len(body))
	out[0] = byte(txType)
	copy(out[1:], body)
	return out
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
