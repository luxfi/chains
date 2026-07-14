// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package txs defines the transaction surface for the S-Chain — the Lux
// STORAGE VM. M0 has exactly one mutation: PutManifest, which records the
// (bucket, object) -> manifest mapping for an object whose file blobs already
// exist elsewhere (the S-Chain does NOT carry blobs in M0; it carries the
// content manifest that names them).
//
// Wire format is native ZAP: a single type byte (the discriminator the parser
// dispatches on) followed by the ZAP wire object of the concrete struct — no
// reflection codec, no JSON. Each tx type owns its marshal/parse over a zap
// object at fixed field offsets (the same struct-is-wire idiom as chains/mpcvm
// and chains/bridgevm). The encoding is deterministic — the builder writes the
// fixed section then the variable tails in a fixed field order, and these types
// contain no maps — so the same logical transaction always serializes to
// identical bytes and therefore the same TxID. Re-genesis is authorized, so the
// wire format is these offsets (canonical: parse rejects trailing bytes). One
// codec, one way to read a transaction off the wire.
package txs

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

var (
	// ErrInvalidTxType is returned when the leading type byte names no known tx.
	ErrInvalidTxType = errors.New("invalid transaction type")
	// ErrTrailingBytes rejects a wire object whose ZAP body is shorter than the
	// bytes supplied — a canonical codec consumes its input exactly.
	ErrTrailingBytes = errors.New("transaction: trailing bytes after wire object")
	// ErrEmptyBucket / ErrEmptyObject reject a manifest with no addressable key.
	ErrEmptyBucket = errors.New("manifest: empty bucket")
	ErrEmptyObject = errors.New("manifest: empty object")
	// ErrNoFileIDs rejects a manifest that names no file blobs (M0 carries the
	// content manifest; an object with zero files has nothing to commit).
	ErrNoFileIDs = errors.New("manifest: no file ids")
	// ErrEmptyRange rejects an allocation with no addressable partition key.
	ErrEmptyRange = errors.New("allocate: empty range")
	// ErrZeroCount rejects an allocation that requests no ids (a no-op write that
	// would still consume a tx slot and move the counter by 0 — forbidden so every
	// AllocateTx advances the counter and yields a non-empty id range).
	ErrZeroCount = errors.New("allocate: zero count")
)

// TxType is the transaction discriminator (the leading wire byte).
type TxType uint8

const (
	// TxPutManifest records a (bucket, object) -> manifest mapping. The single
	// mutation of M0.
	TxPutManifest TxType = iota
	// TxAllocate reserves a contiguous, monotonic id range in a per-range
	// allocator counter — the leaderless pinned-writer replacement for raft's
	// global volume-id / fileId sequence. Emitted ONLY by the HRW owner of the
	// range; the owner gate is enforced at block Verify, not in the tx codec.
	TxAllocate
)

func (t TxType) String() string {
	switch t {
	case TxPutManifest:
		return "put_manifest"
	case TxAllocate:
		return "allocate"
	default:
		return "unknown"
	}
}

// Tx is the interface every S-Chain transaction satisfies.
type Tx interface {
	// ID returns the deterministic transaction identifier (checksum of wire bytes).
	ID() ids.ID
	// Type returns the transaction type.
	Type() TxType
	// Bytes returns the serialized transaction (type byte + ZAP wire object).
	Bytes() []byte
	// Verify validates the transaction in isolation (no state access).
	Verify() error
}

// BaseTx carries the fields common to every S-Chain transaction.
//
// TxID is intentionally NOT serialized (json:"-"): the id is the checksum of
// the wire bytes, so embedding it in those bytes would be circular. It is
// always (re)derived from the wire on Parse and stamped by finalize on
// construction — the exact discipline dexvm/txs/tx.go:107 uses.
type BaseTx struct {
	TxID   ids.ID `json:"-"`
	TxType TxType `json:"type"`
	bytes  []byte
}

func (tx *BaseTx) ID() ids.ID    { return tx.TxID }
func (tx *BaseTx) Type() TxType  { return tx.TxType }
func (tx *BaseTx) Bytes() []byte { return tx.bytes }
func (tx *BaseTx) base() *BaseTx { return tx }

// PutManifestTx records the manifest for one object. FileIDs names the content
// blobs (their ids in whatever blob store M1 wires in); Size and ETag are the
// object-level metadata an S3 HEAD returns. M0 commits these verbatim.
type PutManifestTx struct {
	BaseTx
	Bucket  string   `json:"bucket"`
	Object  string   `json:"object"`
	FileIDs []string `json:"fileIds"`
	Size    int64    `json:"size"`
	ETag    string   `json:"etag"`
}

// NewPutManifestTx builds a wire-ready PutManifest transaction. finalize stamps
// the deterministic wire bytes + TxID, so the returned tx is immediately
// Parse-round-trippable (mirrors every dexvm New*Tx constructor).
func NewPutManifestTx(bucket, object string, fileIDs []string, size int64, etag string) *PutManifestTx {
	tx := &PutManifestTx{
		BaseTx:  BaseTx{TxType: TxPutManifest},
		Bucket:  bucket,
		Object:  object,
		FileIDs: fileIDs,
		Size:    size,
		ETag:    etag,
	}
	return finalize(tx, &tx.BaseTx)
}

// Verify validates a PutManifest in isolation: it must name an addressable
// (bucket, object) and at least one file blob. No state is consulted (Verify is
// pure — the same discipline the VM relies on for deterministic block Verify).
func (tx *PutManifestTx) Verify() error {
	if tx.Bucket == "" {
		return ErrEmptyBucket
	}
	if tx.Object == "" {
		return ErrEmptyObject
	}
	if len(tx.FileIDs) == 0 {
		return ErrNoFileIDs
	}
	return nil
}

// AllocateTx reserves Count ids in the per-range allocator counter alloc/<Range>.
// Range is the pinned key-range / partition (a volume-collection or bucket-shard)
// the allocation belongs to; the HRW owner of Range is the ONLY validator
// permitted to emit this tx, and a block containing an AllocateTx not signed by
// that owner is rejected at Verify (the leaderless pinned-writer safety gate —
// see DESIGN_pinned_writer.md §2-3). The id range it reserves is a pure function
// of the committed counter: [base, base+Count), where base is the counter's value
// before this tx — so every validator derives identical ids.
//
// SIGNED PINNED-WRITER AUTHORIZATION (the property that replaces raft's
// serialized writer). The original gate keyed on the block's "proposer" identity,
// which a verifying node CANNOT check — a Lux block carries no verifiable
// proposer, and resolving one may need a network call, so the gate was
// unenforceable for >1 validator. The fix makes ownership SELF-ATTESTED and
// cryptographically verifiable inside the pure, local block apply:
//
//   - Signer       — the claimed HRW owner's NodeID. Verify recomputes
//     pinning.Owner(Range, V@Epoch) and requires Signer == owner.
//   - SignerScheme — the NodeIDScheme byte (0x42 ML-DSA-65 / 0x43 ML-DSA-87) the
//     NodeID was derived under.
//   - SignerPubKey — the signer's ML-DSA public key. Verify RE-DERIVES the NodeID
//     from this key (NodeID = SHAKE256-384(domain‖chainID‖scheme‖
//     pubkey)[:20]) and requires it to equal Signer. The NodeID is
//     thus a binding commitment to the key — a forger cannot supply
//     a different key for the owner's NodeID (~2^160 second-preimage
//     on the truncated SHAKE; the same bound the identity system
//     already rests on).
//   - Sig          — an ML-DSA signature over SigningBytes() (the canonical,
//     SP 800-185-framed encoding of Range‖Count‖Epoch‖Nonce‖
//     Fingerprint — NOT over the Sig/Signer/PubKey fields, which
//     would be circular). Only the holder of the owner's secret key
//     can produce it.
//   - Epoch        — the P-Chain height the validator set was frozen at. Verify
//     requires it to equal the block's epoch so ownership is
//     resolved against the agreed set, and binding it into the
//     signature stops cross-epoch replay where ownership differs.
//   - Nonce        — a per-emission uniquifier (the proposer stamps the block
//     height) so two allocations of the same Range/Count in
//     different blocks sign distinct messages.
//   - Fingerprint  — pinning.EpochFingerprint(Epoch, members): the signer's
//     commitment to the EXACT validator set it pinned against.
//     Verify recomputes it from its OWN local snapshot and rejects
//     a mismatch (DESIGN §6.4) — so a proposer that pinned against a
//     set the verifier does not hold cannot get its block accepted,
//     and Verify never has to fetch a set over the network.
//
// An AllocateTx enters the mempool as an UNSIGNED intent (Range+Count only); the
// owning proposer stamps Epoch/Nonce/Fingerprint and signs it at BuildBlock with
// its ML-DSA staking key.
type AllocateTx struct {
	BaseTx
	Range string `json:"range"`
	Count uint32 `json:"count"`

	// Epoch / Nonce / Fingerprint are proposer-stamped at BuildBlock and bound
	// into the signature. Zero on an unsigned mempool intent.
	Epoch       uint64 `json:"epoch"`
	Nonce       uint64 `json:"nonce"`
	Fingerprint ids.ID `json:"fingerprint"`

	// Signer / SignerScheme / SignerPubKey / Sig are the ML-DSA pinned-writer
	// authorization. Empty on an unsigned intent.
	Signer       ids.NodeID `json:"signer"`
	SignerScheme uint8      `json:"signerScheme"`
	SignerPubKey []byte     `json:"signerPubKey"`
	Sig          []byte     `json:"sig"`
}

// NewAllocateTx builds a wire-ready UNSIGNED Allocate intent (Range + Count). The
// proposer stamps Epoch/Nonce/Fingerprint and the ML-DSA authorization at
// BuildBlock via WithAuthorization. finalize stamps the deterministic wire bytes +
// TxID, so the returned tx is immediately Parse-round-trippable (mirrors
// NewPutManifestTx and every dexvm New*Tx).
func NewAllocateTx(rng string, count uint32) *AllocateTx {
	tx := &AllocateTx{
		BaseTx: BaseTx{TxType: TxAllocate},
		Range:  rng,
		Count:  count,
	}
	return finalize(tx, &tx.BaseTx)
}

// IsSigned reports whether the pinned-writer authorization has been stamped.
func (tx *AllocateTx) IsSigned() bool { return len(tx.Sig) > 0 }

// allocateSigDomain is the SP 800-185 customization string bound into the canonical
// allocate signing bytes. Bumping it invalidates every prior signature, the correct
// behaviour for a hardfork of the signing encoding.
const allocateSigDomain = "lux/schain/allocate/v1"

// AllocateSigningBytes is the canonical message an AllocateTx's owner signs: the
// SP 800-185-framed encoding of (domain, Range, Count, Epoch, Nonce, Fingerprint).
// Every field is length-framed (left_encode of its bit length) so concatenation is
// unambiguous — a verifier cannot be tricked by a Range whose bytes spell another
// field's payload. The Signer/PubKey/Sig fields are deliberately NOT covered: the
// signature authenticates the key, the key re-derives the NodeID, and signing the
// Sig would be circular.
func AllocateSigningBytes(rng string, count uint32, epoch, nonce uint64, fingerprint ids.ID) []byte {
	var b []byte
	b = appendFramed(b, []byte(allocateSigDomain))
	b = appendFramed(b, []byte(rng))
	b = appendFramedU64(b, uint64(count))
	b = appendFramedU64(b, epoch)
	b = appendFramedU64(b, nonce)
	b = appendFramed(b, fingerprint[:])
	return b
}

// SigningBytes returns this tx's canonical signing message (see AllocateSigningBytes).
func (tx *AllocateTx) SigningBytes() []byte {
	return AllocateSigningBytes(tx.Range, tx.Count, tx.Epoch, tx.Nonce, tx.Fingerprint)
}

// WithAuthorization returns a NEW finalized, wire-ready AllocateTx carrying the
// proposer-stamped Epoch/Nonce/Fingerprint and the ML-DSA pinned-writer
// authorization (Signer/SignerScheme/SignerPubKey/Sig). The receiver supplies only
// Range/Count; the returned tx is the authoritative signed image that travels in
// the block (its TxID covers the authorization, so a peer cannot strip or swap it).
func (tx *AllocateTx) WithAuthorization(
	epoch, nonce uint64,
	fingerprint ids.ID,
	signer ids.NodeID,
	scheme uint8,
	pub, sig []byte,
) *AllocateTx {
	out := &AllocateTx{
		BaseTx:       BaseTx{TxType: TxAllocate},
		Range:        tx.Range,
		Count:        tx.Count,
		Epoch:        epoch,
		Nonce:        nonce,
		Fingerprint:  fingerprint,
		Signer:       signer,
		SignerScheme: scheme,
		SignerPubKey: pub,
		Sig:          sig,
	}
	return finalize(out, &out.BaseTx)
}

// Verify validates an Allocate in isolation: it must name a non-empty range and
// reserve at least one id. No state is consulted and the OWNER GATE is NOT
// checked here — Verify is pure and per-tx, but ownership (and the signature over
// the validator set) is a function of the BLOCK's frozen validator set, which a
// single tx cannot see. The owner + signature gate lives in the VM's block-level
// apply (see schain.VM.applyAllocate), the same discipline that keeps
// PutManifestTx.Verify state-free.
func (tx *AllocateTx) Verify() error {
	if tx.Range == "" {
		return ErrEmptyRange
	}
	if tx.Count == 0 {
		return ErrZeroCount
	}
	return nil
}

// appendFramed appends SP 800-185 left_encode(len(data)*8) followed by data.
func appendFramed(dst, data []byte) []byte {
	dst = append(dst, leftEncode(uint64(len(data))*8)...)
	return append(dst, data...)
}

// appendFramedU64 appends a framed 8-byte big-endian encoding of v.
func appendFramedU64(dst []byte, v uint64) []byte {
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], v)
	return appendFramed(dst, u8[:])
}

// leftEncode is the SP 800-185 §2.3.1 left_encode operation — byte-for-byte
// identical to the helper in ids/node_id_scheme.go and consensus/config, so the
// framing here matches the framing the NodeID derivation uses.
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x01, 0x00}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, byte(8-i))
	out = append(out, buf[i:]...)
	return out
}

// TxParser parses raw transaction bytes off the wire.
type TxParser struct{}

// Parse decodes a transaction from its wire bytes (type byte + ZAP wire object).
// It dispatches on the leading type byte and hands the ZAP body to the concrete
// type's parser — one dispatch, one codec.
func (p *TxParser) Parse(data []byte) (Tx, error) {
	if len(data) < 1 {
		return nil, ErrInvalidTxType
	}
	switch TxType(data[0]) {
	case TxPutManifest:
		return parsePutManifest(data)
	case TxAllocate:
		return parseAllocate(data)
	default:
		return nil, ErrInvalidTxType
	}
}

// stampBase sets the embedded BaseTx's type, wire bytes, and checksum TxID. It
// relies on every concrete tx embedding BaseTx.
func stampBase(tx any, txType TxType, data []byte) {
	type baseHolder interface{ base() *BaseTx }
	if h, ok := tx.(baseHolder); ok {
		b := h.base()
		b.TxType = txType
		b.TxID = ids.Checksum256(data)
		b.bytes = data
	}
}

// marshalTx serializes a concrete transaction into wire bytes: type byte + ZAP
// wire object. The single codec used by both constructors and the parser. A tx
// type with no ZAP encoder is a programmer error (an unhandled type byte would
// be undecodable), so it panics rather than returning a swallowed error.
func marshalTx(tx any, txType TxType) []byte {
	var body []byte
	switch v := tx.(type) {
	case *PutManifestTx:
		body = marshalPutManifest(v)
	case *AllocateTx:
		body = marshalAllocate(v)
	default:
		panic(fmt.Sprintf("txs: cannot marshal unknown transaction type %T", tx))
	}
	out := make([]byte, 1+len(body))
	out[0] = byte(txType)
	copy(out[1:], body)
	return out
}

// finalize serializes the constructed transaction and stamps its wire bytes and
// deterministic TxID, so a freshly built tx is immediately wire-ready and
// Parse-round-trippable. ZAP encoding of these plain structs cannot fail; an
// unknown type is a programmer error, not a recoverable condition.
func finalize[T any](tx *T, base *BaseTx) *T {
	wire := marshalTx(tx, base.TxType)
	base.TxID = ids.Checksum256(wire)
	base.bytes = wire
	return tx
}

// ---- PutManifestTx wire object ----
//
//	Bucket   bytes @ 0
//	Object   bytes @ 8
//	FileLens list  @ 16  (u32 per FileID string length)
//	FileBlob bytes @ 24  (concatenated FileID strings)
//	Size     i64   @ 32
//	ETag     bytes @ 40
const (
	pmBucket   = 0
	pmObject   = 8
	pmFileLens = 16
	pmFileBlob = 24
	pmSize     = 32
	pmETag     = 40
	pmObjSize  = 48
)

func marshalPutManifest(tx *PutManifestTx) []byte {
	fileLens, fileBlob := packStrings(tx.FileIDs)
	b := zap.NewBuilder(zap.HeaderSize + pmObjSize + len(tx.Bucket) + len(tx.Object) +
		len(fileBlob) + 4*len(fileLens) + len(tx.ETag) + 64)
	fileLensOff := writeU32List(b, fileLens)

	ob := b.StartObject(pmObjSize)
	ob.SetBytes(pmBucket, []byte(tx.Bucket))
	ob.SetBytes(pmObject, []byte(tx.Object))
	ob.SetList(pmFileLens, fileLensOff, len(fileLens))
	ob.SetBytes(pmFileBlob, fileBlob)
	ob.SetInt64(pmSize, tx.Size)
	ob.SetBytes(pmETag, []byte(tx.ETag))
	ob.FinishAsRoot()
	return b.Finish()
}

func parsePutManifest(data []byte) (*PutManifestTx, error) {
	msg, err := zap.Parse(data[1:])
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data)-1 {
		return nil, ErrTrailingBytes
	}
	o := msg.Root()
	tx := &PutManifestTx{
		Bucket:  string(o.Bytes(pmBucket)),
		Object:  string(o.Bytes(pmObject)),
		FileIDs: unpackStrings(readU32List(o, pmFileLens), o.Bytes(pmFileBlob)),
		Size:    o.Int64(pmSize),
		ETag:    string(o.Bytes(pmETag)),
	}
	stampBase(tx, TxPutManifest, data)
	return tx, nil
}

// ---- AllocateTx wire object ----
//
//	Range        bytes @ 0
//	Count        u32   @ 8
//	SignerScheme u8    @ 12
//	Epoch        u64   @ 16
//	Nonce        u64   @ 24
//	Fingerprint  32B   @ 32  (ids.ID, in place)
//	Signer       20B   @ 64  (ids.NodeID, in place)
//	SignerPubKey bytes @ 88
//	Sig          bytes @ 96
const (
	alRange   = 0
	alCount   = 8
	alScheme  = 12
	alEpoch   = 16
	alNonce   = 24
	alFinger  = 32
	alSigner  = 64
	alPubKey  = 88
	alSig     = 96
	alObjSize = 104
)

func marshalAllocate(tx *AllocateTx) []byte {
	b := zap.NewBuilder(zap.HeaderSize + alObjSize + len(tx.Range) +
		len(tx.SignerPubKey) + len(tx.Sig) + 64)
	ob := b.StartObject(alObjSize)
	ob.SetBytes(alRange, []byte(tx.Range))
	ob.SetUint32(alCount, tx.Count)
	ob.SetUint8(alScheme, tx.SignerScheme)
	ob.SetUint64(alEpoch, tx.Epoch)
	ob.SetUint64(alNonce, tx.Nonce)
	ob.SetBytesFixed(alFinger, tx.Fingerprint[:])
	ob.SetBytesFixed(alSigner, tx.Signer[:])
	ob.SetBytes(alPubKey, tx.SignerPubKey)
	ob.SetBytes(alSig, tx.Sig)
	ob.FinishAsRoot()
	return b.Finish()
}

func parseAllocate(data []byte) (*AllocateTx, error) {
	msg, err := zap.Parse(data[1:])
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data)-1 {
		return nil, ErrTrailingBytes
	}
	o := msg.Root()
	tx := &AllocateTx{
		Range:        string(o.Bytes(alRange)),
		Count:        o.Uint32(alCount),
		Epoch:        o.Uint64(alEpoch),
		Nonce:        o.Uint64(alNonce),
		SignerScheme: o.Uint8(alScheme),
		SignerPubKey: appendBytes(o.Bytes(alPubKey)),
		Sig:          appendBytes(o.Bytes(alSig)),
	}
	copy(tx.Fingerprint[:], o.BytesFixedSlice(alFinger, ids.IDLen))
	copy(tx.Signer[:], o.BytesFixedSlice(alSigner, ids.NodeIDLen))
	stampBase(tx, TxAllocate, data)
	return tx, nil
}

// ---- shared ZAP helpers (mirror chains/mpcvm + chains/bridgevm) ----

// writeU32List tails a u32 list into the builder and returns its offset.
func writeU32List(b *zap.Builder, xs []uint32) int {
	lb := b.StartList(4)
	for _, x := range xs {
		lb.AddUint32(x)
	}
	off, _ := lb.Finish()
	return off
}

// readU32List reads the u32 list at ptrOff.
func readU32List(o zap.Object, ptrOff int) []uint32 {
	l := o.ListStride(ptrOff, 4)
	n := l.Len()
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = l.Uint32(i)
	}
	return out
}

// packStrings returns per-string byte lengths and the concatenated blob.
func packStrings(ss []string) ([]uint32, []byte) {
	lens := make([]uint32, len(ss))
	var blob []byte
	for i, s := range ss {
		lens[i] = uint32(len(s))
		blob = append(blob, s...)
	}
	return lens, blob
}

// unpackStrings re-splits blob by lens. Returns nil (not empty) for no entries.
func unpackStrings(lens []uint32, blob []byte) []string {
	if len(lens) == 0 {
		return nil
	}
	out := make([]string, 0, len(lens))
	pos := 0
	for _, l := range lens {
		if pos+int(l) > len(blob) {
			break
		}
		out = append(out, string(blob[pos:pos+int(l)]))
		pos += int(l)
	}
	return out
}

// appendBytes returns a defensive copy of b (nil for empty), so a parsed tx does
// not alias the caller's wire buffer.
func appendBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}
