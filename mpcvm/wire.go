// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"fmt"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for M-Chain (MPC custody VM). No pcodecs, no
// reflection, no codec registry — each persisted type owns its Marshal/parse
// over a zap object. Re-genesis authorized, so the on-disk/wire format is
// these offsets (canonical: parse rejects trailing bytes).
//
// The legacy pcodecs LinearCodec keyed on struct tags;
// every type here carries only `json:` tags, so the old codec marshaled ZERO
// fields (a Block round-tripped to all-zero — a latent corruption bug). This
// wire is the correct, field-preserving replacement.
//
// Boundaries kept as JSON (NOT encoded here): ThresholdConfig (init.Config)
// and Genesis (genesis bytes) — see vm.go. Sessions travel as JSON envelopes
// over transport (see transport.go), not through this wire.

// ---- Operation (nested in Block) ----
//
//	Type       bytes @ 0
//	CeremonyID bytes @ 8
//	KeyID      bytes @ 16
//	ReqChain   bytes @ 24
//	Digest     bytes @ 32
//	Artifact   bytes @ 40
//	SignerLens list  @ 48
//	SignerBlob bytes @ 56
//	KeyPresent u8    @ 64   (1 iff a KeyRecord follows — keygen operations)
//	KeyBlob    bytes @ 72   (marshalled KeyRecord)
//
// There is no timestamp field. An operation used to carry one; nothing read it,
// nothing checked it, and it was not in the operation's state-root digest — so
// it was a byte-range any relay could rewrite to produce a DIFFERENT, equally
// valid block from the same transition. A field that changes the block id and
// changes nothing else is malleability with no upside.
const (
	opType       = 0
	opCeremony   = 8
	opKeyID      = 16
	opReqChn     = 24
	opDigest     = 32
	opArtifact   = 40
	opSignerLens = 48
	opSignerBlob = 56
	opKeyPresent = 64
	opKeyBlob    = 72
	opSize       = 80
)

func marshalOperation(op *Operation) []byte {
	signerLens, signerBlob := packStrings(partyIDsToStrings(op.Signers))
	var keyBlob []byte
	if op.Key != nil {
		keyBlob = marshalKeyRecord(op.Key)
	}
	b := zap.NewBuilder(zap.HeaderSize + opSize + len(op.Type) + len(op.CeremonyID) +
		len(op.KeyID) + len(op.RequestingChain) + len(op.Digest) + len(op.Artifact) +
		len(signerBlob) + 4*len(signerLens) + len(keyBlob) + 128)
	signerLensOff := writeU32List(b, signerLens)

	ob := b.StartObject(opSize)
	ob.SetBytes(opType, []byte(op.Type))
	ob.SetBytes(opCeremony, []byte(op.CeremonyID))
	ob.SetBytes(opKeyID, []byte(op.KeyID))
	ob.SetBytes(opReqChn, []byte(op.RequestingChain))
	ob.SetBytes(opDigest, op.Digest)
	ob.SetBytes(opArtifact, op.Artifact)
	ob.SetList(opSignerLens, signerLensOff, len(signerLens))
	ob.SetBytes(opSignerBlob, signerBlob)
	ob.SetUint8(opKeyPresent, boolByte(op.Key != nil))
	ob.SetBytes(opKeyBlob, keyBlob)
	ob.FinishAsRoot()
	return b.Finish()
}

func readOperation(o zap.Object) (*Operation, error) {
	signers, err := unpackStrings(readU32List(o, opSignerLens), o.Bytes(opSignerBlob))
	if err != nil {
		return nil, fmt.Errorf("mpcvm operation: signers: %w", err)
	}
	op := &Operation{
		Type:            string(o.Bytes(opType)),
		CeremonyID:      string(o.Bytes(opCeremony)),
		KeyID:           string(o.Bytes(opKeyID)),
		RequestingChain: string(o.Bytes(opReqChn)),
		Digest:          appendBytes(o.Bytes(opDigest)),
		Artifact:        appendBytes(o.Bytes(opArtifact)),
		Signers:         stringsToPartyIDs(signers),
	}
	if o.Uint8(opKeyPresent) != 0 {
		rec, err := parseKeyRecord(o.Bytes(opKeyBlob))
		if err != nil {
			return nil, fmt.Errorf("mpcvm operation: key record: %w", err)
		}
		op.Key = rec
	}
	return op, nil
}

// ---- Block ----
//
//	ParentID  32B   @ 0    (ID_ is derived: computeID = sha256(Marshal); excluded)
//	Height    u64   @ 32
//	Timestamp i64   @ 40
//	StateRoot 32B   @ 48   (post-application root; commits the transition)
//	OpLens    list  @ 80   (u32 per Operation wire length)
//	OpBlob    bytes @ 88   (concatenated Operation wire objects)
const (
	blkParent = 0
	blkHeight = 32
	blkTime   = 40
	blkRoot   = 48
	blkOpLens = 80
	blkOpBlob = 88
	blkSize   = 96
)

// Marshal encodes the block (excluding the derived ID_) to canonical wire.
//
// Encoding cannot fail. A builder writes into a buffer it sized itself, so
// there is no input for which this returns half a block — which is why it
// returns bytes rather than bytes and an error nobody could produce and every
// caller discarded.
func (b *Block) Marshal() []byte {
	var opBlob []byte
	opLens := make([]uint32, 0, len(b.Operations))
	for _, op := range b.Operations {
		ob := marshalOperation(op)
		opLens = append(opLens, uint32(len(ob)))
		opBlob = append(opBlob, ob...)
	}
	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(opBlob) + 4*len(opLens) + 128)
	opLensOff := writeU32List(bld, opLens)

	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, b.ParentID_[:])
	ob.SetUint64(blkHeight, b.BlockHeight)
	ob.SetInt64(blkTime, b.BlockTimestamp)
	ob.SetBytesFixed(blkRoot, b.StateRoot[:])
	ob.SetList(blkOpLens, opLensOff, len(opLens))
	ob.SetBytes(blkOpBlob, opBlob)
	ob.FinishAsRoot()
	return bld.Finish()
}

func parseBlockBytes(data []byte, blk *Block) error {
	// Refuse the size before decoding it. Everything below allocates in
	// proportion to what the bytes claim, and a peer chooses the bytes.
	if len(data) > maxBlockBytes {
		return fmt.Errorf("mpcvm block: %d bytes, at most %d", len(data), maxBlockBytes)
	}
	msg, err := zap.Parse(data)
	if err != nil {
		return err
	}
	if msg.Size() != len(data) {
		return fmt.Errorf("mpcvm block: trailing bytes")
	}
	o := msg.Root()
	parent := o.BytesFixedSlice(blkParent, 32)
	root := o.BytesFixedSlice(blkRoot, 32)
	// copy() into a fixed array zero-fills whatever the source did not cover,
	// so a truncated object would decode to a block naming a DIFFERENT parent
	// and a different post-state instead of failing.
	if len(parent) != 32 || len(root) != 32 {
		return fmt.Errorf("mpcvm block: header is truncated")
	}
	copy(blk.ParentID_[:], parent)
	blk.BlockHeight = o.Uint64(blkHeight)
	blk.BlockTimestamp = o.Int64(blkTime)
	copy(blk.StateRoot[:], root)

	opLens := readU32List(o, blkOpLens)
	if len(opLens) > maxOpsPerBlock {
		return fmt.Errorf("mpcvm block: %d operations, at most %d", len(opLens), maxOpsPerBlock)
	}
	if len(opLens) == 0 {
		blk.Operations = nil
		return nil
	}
	opBlob := o.Bytes(blkOpBlob)
	blk.Operations = make([]*Operation, 0, len(opLens))
	pos := 0
	for _, l := range opLens {
		if pos+int(l) > len(opBlob) {
			return fmt.Errorf("mpcvm block: operation blob out of bounds")
		}
		omsg, err := zap.Parse(opBlob[pos : pos+int(l)])
		if err != nil {
			return err
		}
		op, err := readOperation(omsg.Root())
		if err != nil {
			return err
		}
		blk.Operations = append(blk.Operations, op)
		pos += int(l)
	}
	// Past the CONTENT, not past the declared size: bytes after the last
	// operation sit inside the object and would otherwise be accepted and
	// silently dropped, so one transition would have unboundedly many
	// encodings on the wire.
	if pos != len(opBlob) {
		return fmt.Errorf("mpcvm block: %d bytes after the last operation", len(opBlob)-pos)
	}
	return nil
}

// ---- CrossChainMPCRequest ----
//
//	Type        bytes @ 0
//	ReqChain    bytes @ 8
//	KeyID       bytes @ 16
//	KeyType     bytes @ 24
//	MessageHash bytes @ 32
//	MessageType bytes @ 40
const (
	ccType    = 0
	ccReqChn  = 8
	ccKeyID   = 16
	ccKeyType = 24
	ccMsgHash = 32
	ccMsgType = 40
	ccSize    = 48
)

func (r *CrossChainMPCRequest) Marshal() []byte {
	b := zap.NewBuilder(zap.HeaderSize + ccSize + len(r.Type) + len(r.RequestingChain) +
		len(r.KeyID) + len(r.KeyType) + len(r.MessageHash) + len(r.MessageType) + 64)
	ob := b.StartObject(ccSize)
	ob.SetBytes(ccType, []byte(r.Type))
	ob.SetBytes(ccReqChn, []byte(r.RequestingChain))
	ob.SetBytes(ccKeyID, []byte(r.KeyID))
	ob.SetBytes(ccKeyType, []byte(r.KeyType))
	ob.SetBytes(ccMsgHash, r.MessageHash)
	ob.SetBytes(ccMsgType, []byte(r.MessageType))
	ob.FinishAsRoot()
	return b.Finish()
}

func parseCrossChainMPCRequest(data []byte, r *CrossChainMPCRequest) error {
	msg, err := zap.Parse(data)
	if err != nil {
		return err
	}
	if msg.Size() != len(data) {
		return fmt.Errorf("mpcvm cross-chain request: trailing bytes")
	}
	o := msg.Root()
	r.Type = string(o.Bytes(ccType))
	r.RequestingChain = string(o.Bytes(ccReqChn))
	r.KeyID = string(o.Bytes(ccKeyID))
	r.KeyType = string(o.Bytes(ccKeyType))
	r.MessageHash = appendBytes(o.Bytes(ccMsgHash))
	r.MessageType = string(o.Bytes(ccMsgType))
	return nil
}

// ---- KeyRecord (replicated custody-key registry entry) ----
//
//	KeyID      bytes @ 0
//	Kind       bytes @ 8
//	PolicyK    i64   @ 16
//	PolicyN    i64   @ 24
//	GroupPub   bytes @ 32
//	Address    bytes @ 40
//	Generation u64   @ 48
//	CreatedHt  u64   @ 56
//	PartyLens  list  @ 64
//	PartyBlob  bytes @ 72
//
// The polynomial degree is NOT a field: it is Policy.Degree(). Storing both a
// policy and a degree invites them to disagree, and a stored disagreement in a
// custody record is a wrong-degree key.
const (
	krKeyID     = 0
	krKind      = 8
	krPolicyK   = 16
	krPolicyN   = 24
	krGroupPub  = 32
	krAddr      = 40
	krGen       = 48
	krCreatedHt = 56
	krPartyLens = 64
	krPartyBlob = 72
	krSize      = 80
)

func marshalKeyRecord(r *KeyRecord) []byte {
	partyLens, partyBlob := packStrings(partyIDsToStrings(r.Participants))
	bld := zap.NewBuilder(zap.HeaderSize + krSize + len(r.KeyID) + len(r.Kind) +
		len(r.GroupPublicKey) + len(r.Address) + len(partyBlob) + 4*len(partyLens) + 128)
	partyLensOff := writeU32List(bld, partyLens)

	ob := bld.StartObject(krSize)
	ob.SetBytes(krKeyID, []byte(r.KeyID))
	ob.SetBytes(krKind, []byte(r.Kind))
	ob.SetInt64(krPolicyK, int64(r.Policy.K))
	ob.SetInt64(krPolicyN, int64(r.Policy.N))
	ob.SetBytes(krGroupPub, r.GroupPublicKey)
	ob.SetBytes(krAddr, r.Address)
	ob.SetUint64(krGen, r.Generation)
	ob.SetUint64(krCreatedHt, r.CreatedHeight)
	ob.SetList(krPartyLens, partyLensOff, len(partyLens))
	ob.SetBytes(krPartyBlob, partyBlob)
	ob.FinishAsRoot()
	return bld.Finish()
}

func parseKeyRecord(data []byte) (*KeyRecord, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data) {
		return nil, fmt.Errorf("mpcvm key record: trailing bytes")
	}
	o := msg.Root()
	parties, err := unpackStrings(readU32List(o, krPartyLens), o.Bytes(krPartyBlob))
	if err != nil {
		return nil, fmt.Errorf("mpcvm key record: participants: %w", err)
	}
	return &KeyRecord{
		KeyID:          string(o.Bytes(krKeyID)),
		Kind:           string(o.Bytes(krKind)),
		Policy:         quorum.Policy{K: int(o.Int64(krPolicyK)), N: int(o.Int64(krPolicyN))},
		GroupPublicKey: appendBytes(o.Bytes(krGroupPub)),
		Address:        appendBytes(o.Bytes(krAddr)),
		Generation:     o.Uint64(krGen),
		CreatedHeight:  o.Uint64(krCreatedHt),
		Participants:   stringsToPartyIDs(parties),
	}, nil
}

// ---- CeremonyRecord (replicated ceremony log entry) ----
//
//	ID         bytes @ 0
//	Kind       bytes @ 8
//	KeyID      bytes @ 16
//	Digest     bytes @ 24
//	Artifact   bytes @ 32
//	ReqChain   bytes @ 40
//	Height     u64   @ 48
//	SignerLens list  @ 56
//	SignerBlob bytes @ 64
const (
	crID         = 0
	crKind       = 8
	crKeyID      = 16
	crDigest     = 24
	crArtifact   = 32
	crReqChain   = 40
	crHeight     = 48
	crSignerLens = 56
	crSignerBlob = 64
	crSize       = 72
)

func marshalCeremonyRecord(c *CeremonyRecord) []byte {
	signerLens, signerBlob := packStrings(partyIDsToStrings(c.Signers))
	bld := zap.NewBuilder(zap.HeaderSize + crSize + len(c.ID) + len(c.Kind) + len(c.KeyID) +
		len(c.Digest) + len(c.Artifact) + len(c.RequestingChain) + len(signerBlob) + 4*len(signerLens) + 128)
	signerLensOff := writeU32List(bld, signerLens)

	ob := bld.StartObject(crSize)
	ob.SetBytes(crID, []byte(c.ID))
	ob.SetBytes(crKind, []byte(c.Kind))
	ob.SetBytes(crKeyID, []byte(c.KeyID))
	ob.SetBytes(crDigest, c.Digest)
	ob.SetBytes(crArtifact, c.Artifact)
	ob.SetBytes(crReqChain, []byte(c.RequestingChain))
	ob.SetUint64(crHeight, c.Height)
	ob.SetList(crSignerLens, signerLensOff, len(signerLens))
	ob.SetBytes(crSignerBlob, signerBlob)
	ob.FinishAsRoot()
	return bld.Finish()
}

func parseCeremonyRecord(data []byte) (*CeremonyRecord, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data) {
		return nil, fmt.Errorf("mpcvm ceremony record: trailing bytes")
	}
	o := msg.Root()
	signers, err := unpackStrings(readU32List(o, crSignerLens), o.Bytes(crSignerBlob))
	if err != nil {
		return nil, fmt.Errorf("mpcvm ceremony record: signers: %w", err)
	}
	return &CeremonyRecord{
		ID:              string(o.Bytes(crID)),
		Kind:            string(o.Bytes(crKind)),
		KeyID:           string(o.Bytes(crKeyID)),
		Digest:          appendBytes(o.Bytes(crDigest)),
		Artifact:        appendBytes(o.Bytes(crArtifact)),
		RequestingChain: string(o.Bytes(crReqChain)),
		Height:          o.Uint64(crHeight),
		Signers:         stringsToPartyIDs(signers),
	}, nil
}

// ---- shared helpers ----

func boolByte(b bool) uint8 {
	if b {
		return 1
	}
	return 0
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
//
// A blob that does not cover exactly what the lengths declare is an error, not
// a short answer. It used to stop at the first overrun and return what it had,
// so a crafted encoding declaring five signers with room for three decoded to
// three signers with no error anywhere — a party set quietly smaller than the
// one on the wire, which is the shape every threshold check downstream trusts.
func unpackStrings(lens []uint32, blob []byte) ([]string, error) {
	if len(lens) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(lens))
	pos := 0
	for i, l := range lens {
		if pos+int(l) > len(blob) {
			return nil, fmt.Errorf("entry %d wants %d bytes, %d remain", i, l, len(blob)-pos)
		}
		out = append(out, string(blob[pos:pos+int(l)]))
		pos += int(l)
	}
	if pos != len(blob) {
		return nil, fmt.Errorf("%d bytes after the last entry", len(blob)-pos)
	}
	return out, nil
}

func partyIDsToStrings(ids []party.ID) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

func stringsToPartyIDs(ss []string) []party.ID {
	if len(ss) == 0 {
		return nil
	}
	out := make([]party.ID, len(ss))
	for i, s := range ss {
		out[i] = party.ID(s)
	}
	return out
}

func appendBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}
