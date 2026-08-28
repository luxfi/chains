// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for I-Chain. No pcodecs, no reflection, no codec
// registry: each record owns its Marshal/parse over a zap object at fixed
// offsets. blockID = sha256(Block.Marshal), and determinism follows from the
// wire (fixed offsets, ordered slices, sorted map keys).
//
// EVERY frame is canonical, including a nested one. The top-level parsers
// checked that the declared size accounted for every byte and the nested ones
// did not, so a credential inside a block could carry arbitrary padding in the
// gap between its declared size and its declared length — and since the block
// id is the hash of the bytes and a parsed block keeps the bytes it arrived in,
// one logical block had unboundedly many ids, all of which verified. parseIn is
// the one place that decides it now.
//
// ONE json holdout, isolated to a single field: Credential.Claims is
// map[string]interface{} — an arbitrary verifiable-credential document with no
// fixed schema. It rides the wire as canonical JSON (Go's encoding/json sorts
// map keys, so the bytes are deterministic). Encoding arbitrary dynamic JSON
// natively would mean re-introducing exactly the reflection codec this kills.

var (
	// errTrailing — a frame declares fewer bytes than it was handed. One value
	// has one byte string, so the remainder belongs to nobody.
	errTrailing = errors.New("identityvm wire: trailing bytes")

	// errLength — a declared length vector does not exactly cover the blob it
	// indexes: a length reaching past the end, or blob bytes no length claims.
	errLength = errors.New("identityvm wire: declared length does not match blob")

	// errClaims — the claims blob is not the JSON document it claims to be.
	// Read as "no claims", a malformed blob passes the claims bound trivially
	// and the credential the chain records is not the one that was sent.
	errClaims = errors.New("identityvm wire: claims are not a JSON object")
)

// parseIn decodes one frame and refuses one that does not account for every
// byte handed in. Every parser here goes through it.
func parseIn(data []byte) (zap.Object, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return zap.Object{}, err
	}
	if msg.Size() != len(data) {
		return zap.Object{}, errTrailing
	}
	return msg.Root(), nil
}

// ---- Identity ----
//
//	ID        32B   @ 0
//	Created   i64   @ 32  (UnixNano)
//	PublicKey bytes @ 40
//	MetaLens  list  @ 48  (u32 per metadata string; entries are k0,v0,k1,v1,…)
//	MetaBlob  bytes @ 56  (concatenated metadata strings, key-sorted)
//	Signature bytes @ 64
const (
	idnID      = 0
	idnCreated = 32
	idnPubKey  = 40
	idnMetaLen = 48
	idnMetaBlb = 56
	idnSig     = 64
	idnSize    = 72
)

// signable is a record's CONTENT: without its name and without its
// authorization. The id is a hash of it and the signature is over it, so
// neither contains the other and both describe the same record.
func (i *Identity) signable() []byte { return i.marshal(ids.Empty, nil) }

func marshalIdentity(i *Identity) []byte { return i.marshal(i.ID, i.Signature) }

func (i *Identity) marshal(id ids.ID, sig []byte) []byte {
	metaLens, metaBlob := packMetadata(i.Metadata)

	b := zap.NewBuilder(zap.HeaderSize + idnSize + len(i.PublicKey) +
		len(metaBlob) + 4*len(metaLens) + len(sig) + 128)
	metaOff := writeU32List(b, metaLens)

	ob := b.StartObject(idnSize)
	ob.SetBytesFixed(idnID, id[:])
	ob.SetInt64(idnCreated, i.Created.UnixNano())
	ob.SetBytes(idnPubKey, i.PublicKey)
	ob.SetList(idnMetaLen, metaOff, len(metaLens))
	ob.SetBytes(idnMetaBlb, metaBlob)
	ob.SetBytes(idnSig, sig)
	ob.FinishAsRoot()
	return b.Finish()
}

func readIdentity(o zap.Object) (*Identity, error) {
	meta, err := unpackMetadata(readU32List(o, idnMetaLen), o.Bytes(idnMetaBlb))
	if err != nil {
		return nil, err
	}
	i := &Identity{
		PublicKey: appendBytes(o.Bytes(idnPubKey)),
		Created:   unixNano(o.Int64(idnCreated)),
		Metadata:  meta,
		Signature: appendBytes(o.Bytes(idnSig)),
	}
	copy(i.ID[:], o.BytesFixedSlice(idnID, 32))
	return i, nil
}

func parseIdentity(data []byte) (*Identity, error) {
	o, err := parseIn(data)
	if err != nil {
		return nil, err
	}
	return readIdentity(o)
}

// ---- Issuer ----
//
//	ID         32B   @ 0
//	CreatedAt  i64   @ 32  (UnixNano)
//	TrustLevel i64   @ 40
//	PublicKey  bytes @ 48
//	Name       bytes @ 56
//	TypeLens   list  @ 64
//	TypeBlob   bytes @ 72
//	Signature  bytes @ 80
const (
	isID       = 0
	isCreated  = 32
	isTrust    = 40
	isPubKey   = 48
	isName     = 56
	isTypeLens = 64
	isTypeBlob = 72
	isSig      = 80
	isSize     = 88
)

func (s *Issuer) signable() []byte { return s.marshal(ids.Empty, nil) }

func marshalIssuer(s *Issuer) []byte { return s.marshal(s.ID, s.Signature) }

func (s *Issuer) marshal(id ids.ID, sig []byte) []byte {
	typeLens, typeBlob := packStrings(s.Types)

	b := zap.NewBuilder(zap.HeaderSize + isSize + len(s.PublicKey) + len(s.Name) +
		len(typeBlob) + 4*len(typeLens) + len(sig) + 128)
	typeOff := writeU32List(b, typeLens)

	ob := b.StartObject(isSize)
	ob.SetBytesFixed(isID, id[:])
	ob.SetInt64(isCreated, s.CreatedAt.UnixNano())
	ob.SetInt64(isTrust, int64(s.TrustLevel))
	ob.SetBytes(isPubKey, s.PublicKey)
	ob.SetBytes(isName, []byte(s.Name))
	ob.SetList(isTypeLens, typeOff, len(typeLens))
	ob.SetBytes(isTypeBlob, typeBlob)
	ob.SetBytes(isSig, sig)
	ob.FinishAsRoot()
	return b.Finish()
}

func readIssuer(o zap.Object) (*Issuer, error) {
	types, err := unpackStrings(readU32List(o, isTypeLens), o.Bytes(isTypeBlob))
	if err != nil {
		return nil, err
	}
	s := &Issuer{
		CreatedAt:  unixNano(o.Int64(isCreated)),
		TrustLevel: int(o.Int64(isTrust)),
		PublicKey:  appendBytes(o.Bytes(isPubKey)),
		Name:       string(o.Bytes(isName)),
		Types:      types,
		Signature:  appendBytes(o.Bytes(isSig)),
	}
	copy(s.ID[:], o.BytesFixedSlice(isID, 32))
	return s, nil
}

func parseIssuer(data []byte) (*Issuer, error) {
	o, err := parseIn(data)
	if err != nil {
		return nil, err
	}
	return readIssuer(o)
}

// ---- Credential ----
//
//	ID             32B   @ 0
//	Issuer         32B   @ 32
//	Subject        32B   @ 64
//	IssuanceDate   i64   @ 96   (UnixNano)
//	ExpirationDate i64   @ 104  (UnixNano)
//	Claims         bytes @ 112  (canonical JSON; see marshalClaims)
//	TypeLens       list  @ 120
//	TypeBlob       bytes @ 128
//	Signature      bytes @ 136
const (
	crID       = 0
	crIssuer   = 32
	crSubject  = 64
	crIssuance = 96
	crExpire   = 104
	crClaims   = 112
	crTypeLens = 120
	crTypeBlob = 128
	crSig      = 136
	crSize     = 144
)

func (c *Credential) signable() []byte { return c.marshal(ids.Empty, nil) }

func marshalCredential(c *Credential) []byte { return c.marshal(c.ID, c.Signature) }

func (c *Credential) marshal(id ids.ID, sig []byte) []byte {
	typeLens, typeBlob := packStrings(c.Type)
	claims := marshalClaims(c.Claims)

	b := zap.NewBuilder(zap.HeaderSize + crSize + len(claims) +
		len(typeBlob) + 4*len(typeLens) + len(sig) + 128)
	typeOff := writeU32List(b, typeLens)

	ob := b.StartObject(crSize)
	ob.SetBytesFixed(crID, id[:])
	ob.SetBytesFixed(crIssuer, c.Issuer[:])
	ob.SetBytesFixed(crSubject, c.Subject[:])
	ob.SetInt64(crIssuance, c.IssuanceDate.UnixNano())
	ob.SetInt64(crExpire, c.ExpirationDate.UnixNano())
	ob.SetBytes(crClaims, claims)
	ob.SetList(crTypeLens, typeOff, len(typeLens))
	ob.SetBytes(crTypeBlob, typeBlob)
	ob.SetBytes(crSig, sig)
	ob.FinishAsRoot()
	return b.Finish()
}

func readCredential(o zap.Object) (*Credential, error) {
	types, err := unpackStrings(readU32List(o, crTypeLens), o.Bytes(crTypeBlob))
	if err != nil {
		return nil, err
	}
	claims, err := parseClaims(o.Bytes(crClaims))
	if err != nil {
		return nil, err
	}
	c := &Credential{
		IssuanceDate:   unixNano(o.Int64(crIssuance)),
		ExpirationDate: unixNano(o.Int64(crExpire)),
		Claims:         claims,
		Type:           types,
		Signature:      appendBytes(o.Bytes(crSig)),
	}
	copy(c.ID[:], o.BytesFixedSlice(crID, 32))
	copy(c.Issuer[:], o.BytesFixedSlice(crIssuer, 32))
	copy(c.Subject[:], o.BytesFixedSlice(crSubject, 32))
	return c, nil
}

func parseCredential(data []byte) (*Credential, error) {
	o, err := parseIn(data)
	if err != nil {
		return nil, err
	}
	return readCredential(o)
}

// ---- Revocation ----
//
//	CredentialID 32B   @ 0
//	RevokedBy    32B   @ 32
//	RevokedAt    i64   @ 64  (UnixNano)
//	Reason       bytes @ 72
//	Signature    bytes @ 80
const (
	rvCredID = 0
	rvBy     = 32
	rvAt     = 64
	rvReason = 72
	rvSig    = 80
	rvSize   = 88
)

func (r *Revocation) signable() []byte { return r.marshal(nil) }

func marshalRevocation(r *Revocation) []byte { return r.marshal(r.Signature) }

// A revocation's name is the credential it withdraws, which is content, so
// there is nothing to leave out but the signature.
func (r *Revocation) marshal(sig []byte) []byte {
	b := zap.NewBuilder(zap.HeaderSize + rvSize + len(r.Reason) + len(sig) + 64)
	ob := b.StartObject(rvSize)
	ob.SetBytesFixed(rvCredID, r.CredentialID[:])
	ob.SetBytesFixed(rvBy, r.RevokedBy[:])
	ob.SetInt64(rvAt, r.RevokedAt.UnixNano())
	ob.SetBytes(rvReason, []byte(r.Reason))
	ob.SetBytes(rvSig, sig)
	ob.FinishAsRoot()
	return b.Finish()
}

func readRevocation(o zap.Object) *Revocation {
	r := &Revocation{
		RevokedAt: unixNano(o.Int64(rvAt)),
		Reason:    string(o.Bytes(rvReason)),
		Signature: appendBytes(o.Bytes(rvSig)),
	}
	copy(r.CredentialID[:], o.BytesFixedSlice(rvCredID, 32))
	copy(r.RevokedBy[:], o.BytesFixedSlice(rvBy, 32))
	return r
}

func parseRevocation(data []byte) (*Revocation, error) {
	o, err := parseIn(data)
	if err != nil {
		return nil, err
	}
	return readRevocation(o), nil
}

// ---- Block ----
//
//	ParentID  32B   @ 0
//	Height    u64   @ 32
//	Timestamp i64   @ 40
//	IdnLens   list  @ 48    IdnBlob   bytes @ 56
//	IssLens   list  @ 64    IssBlob   bytes @ 72
//	CredLens  list  @ 80    CredBlob  bytes @ 88
//	RevLens   list  @ 96    RevBlob   bytes @ 104
const (
	blkParent   = 0
	blkHeight   = 32
	blkTime     = 40
	blkIdnLens  = 48
	blkIdnBlob  = 56
	blkIssLens  = 64
	blkIssBlob  = 72
	blkCredLens = 80
	blkCredBlob = 88
	blkRevLens  = 96
	blkRevBlob  = 104
	blkSize     = 112
)

// Marshal encodes the block. It cannot fail — every field is a value this
// package produced — so it does not claim it can.
func (b *Block) Marshal() []byte {
	idnLens, idnBlob := packEach(b.Identities, marshalIdentity)
	issLens, issBlob := packEach(b.Issuers, marshalIssuer)
	credLens, credBlob := packEach(b.Credentials, marshalCredential)
	revLens, revBlob := packEach(b.Revocations, marshalRevocation)

	bld := zap.NewBuilder(zap.HeaderSize + blkSize +
		len(idnBlob) + len(issBlob) + len(credBlob) + len(revBlob) +
		4*(len(idnLens)+len(issLens)+len(credLens)+len(revLens)) + 512)

	idnOff := writeU32List(bld, idnLens)
	issOff := writeU32List(bld, issLens)
	credOff := writeU32List(bld, credLens)
	revOff := writeU32List(bld, revLens)

	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, b.ParentID_[:])
	ob.SetUint64(blkHeight, b.BlockHeight)
	ob.SetInt64(blkTime, b.BlockTimestamp)
	ob.SetList(blkIdnLens, idnOff, len(idnLens))
	ob.SetBytes(blkIdnBlob, idnBlob)
	ob.SetList(blkIssLens, issOff, len(issLens))
	ob.SetBytes(blkIssBlob, issBlob)
	ob.SetList(blkCredLens, credOff, len(credLens))
	ob.SetBytes(blkCredBlob, credBlob)
	ob.SetList(blkRevLens, revOff, len(revLens))
	ob.SetBytes(blkRevBlob, revBlob)
	ob.FinishAsRoot()
	return bld.Finish()
}

func parseBlock(data []byte, blk *Block) error {
	o, err := parseIn(data)
	if err != nil {
		return err
	}

	copy(blk.ParentID_[:], o.BytesFixedSlice(blkParent, 32))
	blk.BlockHeight = o.Uint64(blkHeight)
	blk.BlockTimestamp = o.Int64(blkTime)

	if blk.Identities, err = unpackEach(readU32List(o, blkIdnLens), o.Bytes(blkIdnBlob), parseIdentity); err != nil {
		return err
	}
	if blk.Issuers, err = unpackEach(readU32List(o, blkIssLens), o.Bytes(blkIssBlob), parseIssuer); err != nil {
		return err
	}
	if blk.Credentials, err = unpackEach(readU32List(o, blkCredLens), o.Bytes(blkCredBlob), parseCredential); err != nil {
		return err
	}
	blk.Revocations, err = unpackEach(readU32List(o, blkRevLens), o.Bytes(blkRevBlob), parseRevocation)
	return err
}

// ---- helpers ----

// marshalClaims encodes a claims map as canonical JSON. Go's encoding/json
// sorts map keys, so the same logical claims always yield identical bytes.
func marshalClaims(claims map[string]interface{}) []byte {
	if len(claims) == 0 {
		return nil
	}
	b, err := json.Marshal(claims)
	if err != nil {
		// A claims map this package can hold is a map json can encode: it came
		// from json in the first place, at the RPC boundary or off the wire.
		return nil
	}
	return b
}

// parseClaims reports a blob that is not a claims document as the failure it
// is. Read as "no claims", a malformed blob passed the claims bound trivially
// and the credential the chain recorded was not the credential that was sent.
func parseClaims(b []byte) (map[string]interface{}, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", errClaims, err)
	}
	return m, nil
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

// packEach marshals each item and returns per-item lengths plus the blob.
func packEach[T any](items []T, marshal func(T) []byte) ([]uint32, []byte) {
	if len(items) == 0 {
		return nil, nil
	}
	lens := make([]uint32, len(items))
	var blob []byte
	for i, it := range items {
		m := marshal(it)
		lens[i] = uint32(len(m))
		blob = append(blob, m...)
	}
	return lens, blob
}

// unpackEach re-splits a packed blob by its lengths and parses each element.
// Both halves come from the peer and both are checked: a length the blob
// cannot back is refused rather than dropped, and blob bytes no length claims
// are refused too, since either way the value read is not the value sent.
func unpackEach[T any](lens []uint32, blob []byte, parse func([]byte) (T, error)) ([]T, error) {
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

// packStrings returns per-string byte lengths and the concatenated blob.
func packStrings(ss []string) ([]uint32, []byte) {
	if len(ss) == 0 {
		return nil, nil
	}
	lens := make([]uint32, len(ss))
	var blob []byte
	for i, s := range ss {
		lens[i] = uint32(len(s))
		blob = append(blob, s...)
	}
	return lens, blob
}

// unpackStrings re-splits blob by lens under the same agreement rule as
// unpackEach. It used to BREAK on a length past the end, silently truncating
// the list — so a credential's type list arrived shorter than it was sent.
func unpackStrings(lens []uint32, blob []byte) ([]string, error) {
	if len(lens) == 0 {
		if len(blob) != 0 {
			return nil, errLength
		}
		return nil, nil
	}
	out := make([]string, 0, len(lens))
	pos := 0
	for i, l := range lens {
		if int(l) > len(blob)-pos {
			return nil, fmt.Errorf("%w: string %d", errLength, i)
		}
		out = append(out, string(blob[pos:pos+int(l)]))
		pos += int(l)
	}
	if pos != len(blob) {
		return nil, errLength
	}
	return out, nil
}

// packMetadata packs a string map as key-sorted [k0,v0,k1,v1,…] strings —
// deterministic regardless of Go map iteration order.
func packMetadata(m map[string]string) ([]uint32, []byte) {
	if len(m) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ss := make([]string, 0, 2*len(keys))
	for _, k := range keys {
		ss = append(ss, k, m[k])
	}
	return packStrings(ss)
}

// unpackMetadata rebuilds the map. An odd number of strings is a map with a
// key that has no value, which is not a map: it used to drop the odd one.
func unpackMetadata(lens []uint32, blob []byte) (map[string]string, error) {
	ss, err := unpackStrings(lens, blob)
	if err != nil {
		return nil, err
	}
	if len(ss) == 0 {
		return nil, nil
	}
	if len(ss)%2 != 0 {
		return nil, fmt.Errorf("%w: metadata has %d strings", errLength, len(ss))
	}
	m := make(map[string]string, len(ss)/2)
	for i := 0; i+1 < len(ss); i += 2 {
		m[ss[i]] = ss[i+1]
	}
	return m, nil
}

func appendBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

// unixNano reconstructs a UTC time from a UnixNano wire value.
func unixNano(nano int64) time.Time {
	return time.Unix(0, nano).UTC()
}
