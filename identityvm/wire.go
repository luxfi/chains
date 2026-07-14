// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// Native-ZAP struct-is-wire for I-Chain (identityvm). No pcodecs, no
// reflection, no codec registry — each persisted block/credential type owns
// its Marshal/parse over a zap object. Re-genesis authorized, so the
// on-disk/wire format is these offsets (canonical: parse rejects trailing
// bytes). blockID = sha256(Block.Marshal); determinism follows from the
// deterministic wire (fixed offsets, ordered slices, sorted map keys).
//
// Nested lists (a block's credentials/revocations/identities, an identity's
// service endpoints) use the "wire-object blob + u32 length list" encoding —
// each element is its own standalone zap message, concatenated into a bytes
// field alongside a parallel list of per-element lengths, re-parsed on read.
// This is the same native-nested idiom as chains/mpcvm and chains/bridgevm.
//
// ONE json holdout, isolated to a single field: Credential.Claims is
// map[string]interface{} — an arbitrary dynamic verifiable-credential
// document with no fixed schema. It rides the wire as a canonical JSON byte
// string (Go's encoding/json sorts map keys, so the bytes are deterministic).
// Encoding arbitrary dynamic JSON "natively" would mean re-introducing
// exactly the reflection codec this migration kills; instead the claims are
// treated as one opaque, self-describing blob in a ZAP bytes slot. See
// marshalClaims/parseClaims. Every structural block/credential field is
// native ZAP.
//
// Boundaries kept as JSON (NOT encoded here): Genesis (config boundary,
// vm.go ParseGenesis), Issuer persistence (genesis-adjacent state, symmetric
// with its JSON genesis representation), and the RPC/service reply types in
// service.go. None of those are block/credential wire.

// ---- ServiceEndpoint (nested in Identity) ----
//
//	ID       bytes @ 0
//	Type     bytes @ 8
//	Endpoint bytes @ 16
const (
	seID   = 0
	seType = 8
	seEndp = 16
	seSize = 24
)

func marshalServiceEndpoint(s ServiceEndpoint) []byte {
	b := zap.NewBuilder(zap.HeaderSize + seSize + len(s.ID) + len(s.Type) + len(s.ServiceEndpoint) + 32)
	ob := b.StartObject(seSize)
	ob.SetBytes(seID, []byte(s.ID))
	ob.SetBytes(seType, []byte(s.Type))
	ob.SetBytes(seEndp, []byte(s.ServiceEndpoint))
	ob.FinishAsRoot()
	return b.Finish()
}

func marshalServiceEndpoints(ss []ServiceEndpoint) [][]byte {
	if len(ss) == 0 {
		return nil
	}
	out := make([][]byte, len(ss))
	for i := range ss {
		out[i] = marshalServiceEndpoint(ss[i])
	}
	return out
}

func readServiceEndpoint(o zap.Object) ServiceEndpoint {
	return ServiceEndpoint{
		ID:              string(o.Bytes(seID)),
		Type:            string(o.Bytes(seType)),
		ServiceEndpoint: string(o.Bytes(seEndp)),
	}
}

// ---- CredentialProof (optional, nested in Credential) ----
//
//	Type               bytes @ 0
//	Created            bytes @ 8
//	VerificationMethod bytes @ 16
//	ProofPurpose       bytes @ 24
//	ProofValue         bytes @ 32
//	ZKProof            bytes @ 40
const (
	cpType    = 0
	cpCreated = 8
	cpVerMeth = 16
	cpPurpose = 24
	cpProofVl = 32
	cpZKProof = 40
	cpSize    = 48
)

func marshalProof(p *CredentialProof) []byte {
	b := zap.NewBuilder(zap.HeaderSize + cpSize + len(p.Type) + len(p.Created) +
		len(p.VerificationMethod) + len(p.ProofPurpose) + len(p.ProofValue) + len(p.ZKProof) + 64)
	ob := b.StartObject(cpSize)
	ob.SetBytes(cpType, []byte(p.Type))
	ob.SetBytes(cpCreated, []byte(p.Created))
	ob.SetBytes(cpVerMeth, []byte(p.VerificationMethod))
	ob.SetBytes(cpPurpose, []byte(p.ProofPurpose))
	ob.SetBytes(cpProofVl, p.ProofValue)
	ob.SetBytes(cpZKProof, p.ZKProof)
	ob.FinishAsRoot()
	return b.Finish()
}

func readProof(o zap.Object) *CredentialProof {
	return &CredentialProof{
		Type:               string(o.Bytes(cpType)),
		Created:            string(o.Bytes(cpCreated)),
		VerificationMethod: string(o.Bytes(cpVerMeth)),
		ProofPurpose:       string(o.Bytes(cpPurpose)),
		ProofValue:         appendBytes(o.Bytes(cpProofVl)),
		ZKProof:            appendBytes(o.Bytes(cpZKProof)),
	}
}

// ---- Identity ----
//
//	ID          32B   @ 0
//	Created     i64   @ 32   (UnixNano)
//	Updated     i64   @ 40   (UnixNano)
//	DID         bytes @ 48
//	PublicKey   bytes @ 56
//	Controllers bytes @ 64   (concatenated 32-byte ids)
//	SvcLens     list  @ 72   (u32 per ServiceEndpoint wire length)
//	SvcBlob     bytes @ 80   (concatenated ServiceEndpoint wire objects)
//	MetaLens    list  @ 88   (u32 per metadata string; entries are k0,v0,k1,v1,…)
//	MetaBlob    bytes @ 96   (concatenated metadata strings, key-sorted)
const (
	idnID       = 0
	idnCreated  = 32
	idnUpdated  = 40
	idnDID      = 48
	idnPubKey   = 56
	idnCtrls    = 64
	idnSvcLens  = 72
	idnSvcBlob  = 80
	idnMetaLens = 88
	idnMetaBlob = 96
	idnSize     = 104
)

func marshalIdentity(id *Identity) []byte {
	svcLens, svcBlob := packBlobs(marshalServiceEndpoints(id.Services))
	metaLens, metaBlob := packMetadata(id.Metadata)
	ctrls := concatIDs(id.Controllers)

	b := zap.NewBuilder(zap.HeaderSize + idnSize + len(id.DID) + len(id.PublicKey) +
		len(ctrls) + len(svcBlob) + 4*len(svcLens) + len(metaBlob) + 4*len(metaLens) + 128)
	svcLensOff := writeU32List(b, svcLens)
	metaLensOff := writeU32List(b, metaLens)

	ob := b.StartObject(idnSize)
	ob.SetBytesFixed(idnID, id.ID[:])
	ob.SetInt64(idnCreated, id.Created.UnixNano())
	ob.SetInt64(idnUpdated, id.Updated.UnixNano())
	ob.SetBytes(idnDID, []byte(id.DID))
	ob.SetBytes(idnPubKey, id.PublicKey)
	ob.SetBytes(idnCtrls, ctrls)
	ob.SetList(idnSvcLens, svcLensOff, len(svcLens))
	ob.SetBytes(idnSvcBlob, svcBlob)
	ob.SetList(idnMetaLens, metaLensOff, len(metaLens))
	ob.SetBytes(idnMetaBlob, metaBlob)
	ob.FinishAsRoot()
	return b.Finish()
}

func readIdentity(o zap.Object) (*Identity, error) {
	id := &Identity{
		DID:       string(o.Bytes(idnDID)),
		PublicKey: appendBytes(o.Bytes(idnPubKey)),
		Created:   unixNano(o.Int64(idnCreated)),
		Updated:   unixNano(o.Int64(idnUpdated)),
		Metadata:  unpackMetadata(readU32List(o, idnMetaLens), o.Bytes(idnMetaBlob)),
	}
	copy(id.ID[:], o.BytesFixedSlice(idnID, 32))
	id.Controllers = splitIDs(o.Bytes(idnCtrls))

	svcBlobs, err := splitBlobs(readU32List(o, idnSvcLens), o.Bytes(idnSvcBlob))
	if err != nil {
		return nil, err
	}
	if len(svcBlobs) > 0 {
		id.Services = make([]ServiceEndpoint, 0, len(svcBlobs))
		for _, sb := range svcBlobs {
			smsg, err := zap.Parse(sb)
			if err != nil {
				return nil, err
			}
			id.Services = append(id.Services, readServiceEndpoint(smsg.Root()))
		}
	}
	return id, nil
}

func parseIdentity(data []byte) (*Identity, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data) {
		return nil, fmt.Errorf("identityvm identity: trailing bytes")
	}
	return readIdentity(msg.Root())
}

// ---- Credential ----
//
//	ID              32B   @ 0
//	Issuer          32B   @ 32
//	Subject         32B   @ 64
//	IssuanceDate    i64   @ 96   (UnixNano)
//	ExpirationDate  i64   @ 104  (UnixNano)
//	RevocationIndex u64   @ 112
//	Status          bytes @ 120
//	Claims          bytes @ 128  (canonical JSON; see marshalClaims)
//	TypeLens        list  @ 136  (u32 per Type string)
//	TypeBlob        bytes @ 144  (concatenated Type strings)
//	Proof           bytes @ 152  (CredentialProof wire; empty = nil)
const (
	crID       = 0
	crIssuer   = 32
	crSubject  = 64
	crIssuance = 96
	crExpire   = 104
	crRevIndex = 112
	crStatus   = 120
	crClaims   = 128
	crTypeLens = 136
	crTypeBlob = 144
	crProof    = 152
	crSize     = 160
)

func marshalCredential(c *Credential) []byte {
	typeLens, typeBlob := packStrings(c.Type)
	claims := marshalClaims(c.Claims)
	var proof []byte
	if c.Proof != nil {
		proof = marshalProof(c.Proof)
	}

	b := zap.NewBuilder(zap.HeaderSize + crSize + len(c.Status) + len(claims) +
		len(typeBlob) + 4*len(typeLens) + len(proof) + 128)
	typeLensOff := writeU32List(b, typeLens)

	ob := b.StartObject(crSize)
	ob.SetBytesFixed(crID, c.ID[:])
	ob.SetBytesFixed(crIssuer, c.Issuer[:])
	ob.SetBytesFixed(crSubject, c.Subject[:])
	ob.SetInt64(crIssuance, c.IssuanceDate.UnixNano())
	ob.SetInt64(crExpire, c.ExpirationDate.UnixNano())
	ob.SetUint64(crRevIndex, c.RevocationIndex)
	ob.SetBytes(crStatus, []byte(c.Status))
	ob.SetBytes(crClaims, claims)
	ob.SetList(crTypeLens, typeLensOff, len(typeLens))
	ob.SetBytes(crTypeBlob, typeBlob)
	ob.SetBytes(crProof, proof)
	ob.FinishAsRoot()
	return b.Finish()
}

func readCredential(o zap.Object) (*Credential, error) {
	c := &Credential{
		IssuanceDate:    unixNano(o.Int64(crIssuance)),
		ExpirationDate:  unixNano(o.Int64(crExpire)),
		RevocationIndex: o.Uint64(crRevIndex),
		Status:          string(o.Bytes(crStatus)),
		Claims:          parseClaims(o.Bytes(crClaims)),
		Type:            unpackStrings(readU32List(o, crTypeLens), o.Bytes(crTypeBlob)),
	}
	copy(c.ID[:], o.BytesFixedSlice(crID, 32))
	copy(c.Issuer[:], o.BytesFixedSlice(crIssuer, 32))
	copy(c.Subject[:], o.BytesFixedSlice(crSubject, 32))
	if pb := o.Bytes(crProof); len(pb) > 0 {
		pmsg, err := zap.Parse(pb)
		if err != nil {
			return nil, err
		}
		c.Proof = readProof(pmsg.Root())
	}
	return c, nil
}

func parseCredential(data []byte) (*Credential, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data) {
		return nil, fmt.Errorf("identityvm credential: trailing bytes")
	}
	return readCredential(msg.Root())
}

// ---- RevocationEntry ----
//
//	CredentialID 32B   @ 0
//	RevokedBy    32B   @ 32
//	RevokedAt    i64   @ 64   (UnixNano)
//	Reason       bytes @ 72
const (
	rvCredID = 0
	rvBy     = 32
	rvAt     = 64
	rvReason = 72
	rvSize   = 80
)

func marshalRevocation(r *RevocationEntry) []byte {
	b := zap.NewBuilder(zap.HeaderSize + rvSize + len(r.Reason) + 32)
	ob := b.StartObject(rvSize)
	ob.SetBytesFixed(rvCredID, r.CredentialID[:])
	ob.SetBytesFixed(rvBy, r.RevokedBy[:])
	ob.SetInt64(rvAt, r.RevokedAt.UnixNano())
	ob.SetBytes(rvReason, []byte(r.Reason))
	ob.FinishAsRoot()
	return b.Finish()
}

func readRevocation(o zap.Object) *RevocationEntry {
	r := &RevocationEntry{
		RevokedAt: unixNano(o.Int64(rvAt)),
		Reason:    string(o.Bytes(rvReason)),
	}
	copy(r.CredentialID[:], o.BytesFixedSlice(rvCredID, 32))
	copy(r.RevokedBy[:], o.BytesFixedSlice(rvBy, 32))
	return r
}

func parseRevocation(data []byte) (*RevocationEntry, error) {
	msg, err := zap.Parse(data)
	if err != nil {
		return nil, err
	}
	if msg.Size() != len(data) {
		return nil, fmt.Errorf("identityvm revocation: trailing bytes")
	}
	return readRevocation(msg.Root()), nil
}

// ---- Block ----
//
//	ParentID  32B   @ 0    (ID_ is derived: sha256(Marshal); excluded)
//	Height    u64   @ 32
//	Timestamp i64   @ 40
//	StateRoot bytes @ 48
//	CredLens  list  @ 56   (u32 per Credential wire length)
//	CredBlob  bytes @ 64
//	RevLens   list  @ 72   (u32 per RevocationEntry wire length)
//	RevBlob   bytes @ 80
//	IdnLens   list  @ 88   (u32 per Identity wire length)
//	IdnBlob   bytes @ 96
const (
	blkParent    = 0
	blkHeight    = 32
	blkTime      = 40
	blkStateRoot = 48
	blkCredLens  = 56
	blkCredBlob  = 64
	blkRevLens   = 72
	blkRevBlob   = 80
	blkIdnLens   = 88
	blkIdnBlob   = 96
	blkSize      = 104
)

// Marshal encodes the block (excluding the derived ID_/cache fields) to
// canonical wire. blockID = sha256(this).
func (b *Block) Marshal() ([]byte, error) {
	credBlobs := make([][]byte, len(b.Credentials))
	for i, c := range b.Credentials {
		credBlobs[i] = marshalCredential(c)
	}
	revBlobs := make([][]byte, len(b.Revocations))
	for i, r := range b.Revocations {
		revBlobs[i] = marshalRevocation(r)
	}
	idnBlobs := make([][]byte, len(b.Identities))
	for i, id := range b.Identities {
		idnBlobs[i] = marshalIdentity(id)
	}
	credLens, credBlob := packBlobs(credBlobs)
	revLens, revBlob := packBlobs(revBlobs)
	idnLens, idnBlob := packBlobs(idnBlobs)

	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(b.StateRoot) +
		len(credBlob) + len(revBlob) + len(idnBlob) +
		4*(len(credLens)+len(revLens)+len(idnLens)) + 256)
	credLensOff := writeU32List(bld, credLens)
	revLensOff := writeU32List(bld, revLens)
	idnLensOff := writeU32List(bld, idnLens)

	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, b.ParentID_[:])
	ob.SetUint64(blkHeight, b.BlockHeight)
	ob.SetInt64(blkTime, b.BlockTimestamp)
	ob.SetBytes(blkStateRoot, b.StateRoot)
	ob.SetList(blkCredLens, credLensOff, len(credLens))
	ob.SetBytes(blkCredBlob, credBlob)
	ob.SetList(blkRevLens, revLensOff, len(revLens))
	ob.SetBytes(blkRevBlob, revBlob)
	ob.SetList(blkIdnLens, idnLensOff, len(idnLens))
	ob.SetBytes(blkIdnBlob, idnBlob)
	ob.FinishAsRoot()
	return bld.Finish(), nil
}

// parseBlock fills the wire fields of blk from canonical block bytes. The
// caller sets the non-wire cache fields (vm, bytes, status).
func parseBlock(data []byte, blk *Block) error {
	msg, err := zap.Parse(data)
	if err != nil {
		return err
	}
	if msg.Size() != len(data) {
		return fmt.Errorf("identityvm block: trailing bytes")
	}
	o := msg.Root()
	copy(blk.ParentID_[:], o.BytesFixedSlice(blkParent, 32))
	blk.BlockHeight = o.Uint64(blkHeight)
	blk.BlockTimestamp = o.Int64(blkTime)
	blk.StateRoot = appendBytes(o.Bytes(blkStateRoot))

	credBlobs, err := splitBlobs(readU32List(o, blkCredLens), o.Bytes(blkCredBlob))
	if err != nil {
		return err
	}
	if len(credBlobs) > 0 {
		blk.Credentials = make([]*Credential, 0, len(credBlobs))
		for _, cb := range credBlobs {
			cmsg, err := zap.Parse(cb)
			if err != nil {
				return err
			}
			c, err := readCredential(cmsg.Root())
			if err != nil {
				return err
			}
			blk.Credentials = append(blk.Credentials, c)
		}
	}

	revBlobs, err := splitBlobs(readU32List(o, blkRevLens), o.Bytes(blkRevBlob))
	if err != nil {
		return err
	}
	if len(revBlobs) > 0 {
		blk.Revocations = make([]*RevocationEntry, 0, len(revBlobs))
		for _, rb := range revBlobs {
			rmsg, err := zap.Parse(rb)
			if err != nil {
				return err
			}
			blk.Revocations = append(blk.Revocations, readRevocation(rmsg.Root()))
		}
	}

	idnBlobs, err := splitBlobs(readU32List(o, blkIdnLens), o.Bytes(blkIdnBlob))
	if err != nil {
		return err
	}
	if len(idnBlobs) > 0 {
		blk.Identities = make([]*Identity, 0, len(idnBlobs))
		for _, ib := range idnBlobs {
			id, err := parseIdentity(ib)
			if err != nil {
				return err
			}
			blk.Identities = append(blk.Identities, id)
		}
	}
	return nil
}

// ---- shared helpers ----

// marshalClaims canonicalizes a dynamic verifiable-credential claims document
// to deterministic bytes. Go's encoding/json sorts map keys, so the same
// logical claims map always yields identical bytes. This is the single JSON
// holdout on the credential wire: Claims is map[string]interface{}, arbitrary
// dynamic data with no fixed schema — carried as one opaque, self-describing
// blob rather than a reflective codec.
func marshalClaims(claims map[string]interface{}) []byte {
	if len(claims) == 0 {
		return nil
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return nil
	}
	return b
}

func parseClaims(b []byte) map[string]interface{} {
	if len(b) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
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

// packBlobs returns per-element byte lengths and the concatenated blob.
func packBlobs(blobs [][]byte) ([]uint32, []byte) {
	if len(blobs) == 0 {
		return nil, nil
	}
	lens := make([]uint32, len(blobs))
	var blob []byte
	for i, bz := range blobs {
		lens[i] = uint32(len(bz))
		blob = append(blob, bz...)
	}
	return lens, blob
}

// splitBlobs re-splits a concatenated blob by lens.
func splitBlobs(lens []uint32, blob []byte) ([][]byte, error) {
	if len(lens) == 0 {
		return nil, nil
	}
	out := make([][]byte, 0, len(lens))
	pos := 0
	for _, l := range lens {
		if pos+int(l) > len(blob) {
			return nil, fmt.Errorf("identityvm: sub-object blob out of bounds")
		}
		out = append(out, blob[pos:pos+int(l)])
		pos += int(l)
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

func unpackMetadata(lens []uint32, blob []byte) map[string]string {
	ss := unpackStrings(lens, blob)
	if len(ss) == 0 {
		return nil
	}
	m := make(map[string]string, len(ss)/2)
	for i := 0; i+1 < len(ss); i += 2 {
		m[ss[i]] = ss[i+1]
	}
	return m
}

func concatIDs(ids []ids.ID) []byte {
	if len(ids) == 0 {
		return nil
	}
	out := make([]byte, 0, 32*len(ids))
	for _, id := range ids {
		out = append(out, id[:]...)
	}
	return out
}

func splitIDs(blob []byte) []ids.ID {
	n := len(blob) / 32
	if n == 0 {
		return nil
	}
	out := make([]ids.ID, n)
	for i := 0; i < n; i++ {
		copy(out[i][:], blob[i*32:(i+1)*32])
	}
	return out
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
