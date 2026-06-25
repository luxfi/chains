// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package txs defines the transaction surface for the S-Chain — the Lux
// STORAGE VM. M0 has exactly one mutation: PutManifest, which records the
// (bucket, object) -> manifest mapping for an object whose file blobs already
// exist elsewhere (the S-Chain does NOT carry blobs in M0; it carries the
// content manifest that names them).
//
// Wire format mirrors dexvm/txs exactly — a single type byte followed by the
// JSON body of the concrete struct (dexvm/txs/tx.go:621). The encoding is
// deterministic (encoding/json emits struct fields in declaration order and
// these types contain no maps), so the same logical transaction always
// serializes to identical bytes and therefore the same TxID. One codec, one way
// to read a transaction off the wire.
package txs

import (
	"encoding/json"
	"errors"

	"github.com/luxfi/ids"
)

var (
	// ErrInvalidTxType is returned when the leading type byte names no known tx.
	ErrInvalidTxType = errors.New("invalid transaction type")
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
	// Bytes returns the serialized transaction (type byte + JSON body).
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
// permitted to emit this tx, and a block containing an AllocateTx whose proposer
// is not that owner is rejected at Verify (the leaderless pinned-writer safety
// gate — see DESIGN_pinned_writer.md §2-3). The id range it reserves is a pure
// function of the committed counter: [base, base+Count), where base is the
// counter's value before this tx — so every validator derives identical ids.
//
// Stage 1 carries Range + Count only. The Epoch/Owner/Fingerprint fields the
// DESIGN sketches (§2) are the master-cutover stage's concern: in Stage 1 the
// owner gate is evaluated by the VM against the block's threaded validator-set +
// proposer identity, so the owner identity is NOT yet self-attested in the tx.
// Keeping the tx minimal now means the codec does not change when those fields
// are added — they are additive JSON fields a later parse tolerates.
type AllocateTx struct {
	BaseTx
	Range string `json:"range"`
	Count uint32 `json:"count"`
}

// NewAllocateTx builds a wire-ready Allocate transaction. finalize stamps the
// deterministic wire bytes + TxID, so the returned tx is immediately
// Parse-round-trippable (mirrors NewPutManifestTx and every dexvm New*Tx).
func NewAllocateTx(rng string, count uint32) *AllocateTx {
	tx := &AllocateTx{
		BaseTx: BaseTx{TxType: TxAllocate},
		Range:  rng,
		Count:  count,
	}
	return finalize(tx, &tx.BaseTx)
}

// Verify validates an Allocate in isolation: it must name a non-empty range and
// reserve at least one id. No state is consulted and the OWNER GATE is NOT
// checked here — Verify is pure and per-tx, but ownership is a function of the
// BLOCK's validator set + proposer, which a single tx cannot see. The owner gate
// lives in the VM's block-level apply (see schain.VM.applyAllocate), the same
// discipline that keeps PutManifestTx.Verify state-free.
func (tx *AllocateTx) Verify() error {
	if tx.Range == "" {
		return ErrEmptyRange
	}
	if tx.Count == 0 {
		return ErrZeroCount
	}
	return nil
}

// TxParser parses raw transaction bytes off the wire.
type TxParser struct{}

// Parse decodes a transaction from its wire bytes (type byte + JSON body).
func (p *TxParser) Parse(data []byte) (Tx, error) {
	if len(data) < 1 {
		return nil, ErrInvalidTxType
	}
	switch TxType(data[0]) {
	case TxPutManifest:
		return parse[PutManifestTx](data, TxPutManifest)
	case TxAllocate:
		return parse[AllocateTx](data, TxAllocate)
	default:
		return nil, ErrInvalidTxType
	}
}

// parse decodes the JSON body into a concrete tx and stamps its type, wire
// bytes, and deterministic TxID. One codec for every type.
func parse[T any](data []byte, txType TxType) (*T, error) {
	tx := new(T)
	if err := json.Unmarshal(data[1:], tx); err != nil {
		return nil, err
	}
	stampBase(tx, txType, data)
	return tx, nil
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

// Marshal serializes a concrete transaction into wire bytes: type byte + JSON
// body. The single codec used by both constructors and the parser.
func Marshal[T any](tx *T, txType TxType) ([]byte, error) {
	body, err := json.Marshal(tx)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(body))
	out[0] = byte(txType)
	copy(out[1:], body)
	return out, nil
}

// finalize serializes the constructed transaction and stamps its wire bytes and
// deterministic TxID, so a freshly built tx is immediately wire-ready and
// Parse-round-trippable. JSON encoding of these plain structs cannot fail; a
// failure is a programmer error, not a recoverable condition.
func finalize[T any](tx *T, base *BaseTx) *T {
	wire, err := Marshal(tx, base.TxType)
	if err != nil {
		panic("txs: failed to marshal transaction: " + err.Error())
	}
	base.TxID = ids.Checksum256(wire)
	base.bytes = wire
	return tx
}
