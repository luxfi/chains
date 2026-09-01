// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/zap"
)

// Every record round-trips whole. A field that survives marshalling and comes
// back different is a record the chain agreed on and then holds differently.
func TestRecordsRoundTrip(t *testing.T) {
	h := newHarness(t)
	p := newParty(t)

	identity := h.identity(t, p, map[string]string{"b": "2", "a": "1"})
	back, err := parseIdentity(marshalIdentity(identity))
	require.NoError(t, err)
	require.Equal(t, identity, back)

	issuer := h.issuer(t, p, "registry")
	issuer.TrustLevel = 7
	issuer.Signature = p.sign(t, issuer.signable(), h.bind)
	gotIssuer, err := parseIssuer(marshalIssuer(issuer))
	require.NoError(t, err)
	require.Equal(t, issuer, gotIssuer)

	cred := h.credential(t, p, identity.ID, identity.ID, time.Unix(0, 9).UTC())
	gotCred, err := parseCredential(marshalCredential(cred))
	require.NoError(t, err)
	require.Equal(t, cred, gotCred)

	rev := h.revocation(t, p, cred.ID, identity.ID)
	gotRev, err := parseRevocation(marshalRevocation(rev))
	require.NoError(t, err)
	require.Equal(t, rev, gotRev)

	// A record with nothing optional set round-trips too. Its time is an
	// instant, not the zero value: the wire carries UnixNano, and Go's zero
	// time is not one nanosecond count.
	bare := &Identity{ID: ids.ID{1}, PublicKey: []byte("k"), Created: time.Unix(0, 0).UTC()}
	back, err = parseIdentity(marshalIdentity(bare))
	require.NoError(t, err)
	require.Equal(t, bare, back)
}

// A block round-trips whole, and its bytes are the same bytes every time —
// which is what makes the id the same id on every node.
func TestBlockRoundTripIsDeterministic(t *testing.T) {
	h := newHarness(t)
	p, q := newParty(t), newParty(t)

	subject := h.identity(t, p, map[string]string{"z": "26", "a": "1"})
	issuer := h.issuer(t, q, "registry")
	cred := h.credential(t, q, issuer.ID, subject.ID, time.Unix(0, 9).UTC())
	rev := h.revocation(t, p, cred.ID, subject.ID)

	blk := &Block{
		ParentID_:      ids.ID{2},
		BlockHeight:    5,
		BlockTimestamp: 1_700_000_000,
		Identities:     []*Identity{subject},
		Issuers:        []*Issuer{issuer},
		Credentials:    []*Credential{cred},
		Revocations:    []*Revocation{rev},
		vm:             h.VM,
	}
	raw := blk.Marshal()
	require.Equal(t, raw, blk.Marshal(), "the same block encodes the same way twice")

	var got Block
	require.NoError(t, parseBlock(raw, &got))
	require.Equal(t, blk.ParentID_, got.ParentID_)
	require.Equal(t, blk.BlockHeight, got.BlockHeight)
	require.Equal(t, blk.BlockTimestamp, got.BlockTimestamp)
	require.Equal(t, blk.Identities, got.Identities)
	require.Equal(t, blk.Issuers, got.Issuers)
	require.Equal(t, blk.Credentials, got.Credentials)
	require.Equal(t, blk.Revocations, got.Revocations)

	// An empty block round-trips: nothing is not something.
	empty := &Block{vm: h.VM}
	var back Block
	require.NoError(t, parseBlock(empty.Marshal(), &back))
	require.Empty(t, back.Identities)
	require.Empty(t, back.Issuers)
	require.Empty(t, back.Credentials)
	require.Empty(t, back.Revocations)
}

// One value has one byte string. Every frame is canonical, INCLUDING a nested
// one: the top-level parsers checked this and the nested ones did not, so a
// record inside a block could carry padding — and since the block id is the
// hash of its bytes and a parsed block keeps the bytes it arrived in, one
// logical block had unboundedly many ids, all of which verified.
func TestEveryFrameIsCanonical(t *testing.T) {
	h := newHarness(t)
	p := newParty(t)
	identity := h.identity(t, p, nil)

	for _, tail := range [][]byte{{0}, {0xFF}, make([]byte, 32)} {
		padded := append(append([]byte(nil), marshalIdentity(identity)...), tail...)
		_, err := parseIdentity(padded)
		require.ErrorIs(t, err, errTrailing)
	}

	// The same padding NESTED inside a block.
	nested := append(append([]byte(nil), marshalIdentity(identity)...), 0xFF)
	lens, blob := []uint32{uint32(len(nested))}, nested

	b := zap.NewBuilder(zap.HeaderSize + blkSize + len(blob) + 64)
	off := writeU32List(b, lens)
	ob := b.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, make([]byte, 32))
	ob.SetList(blkIdnLens, off, 1)
	ob.SetBytes(blkIdnBlob, blob)
	ob.FinishAsRoot()

	var blk Block
	require.ErrorIs(t, parseBlock(b.Finish(), &blk), errTrailing)

	// And a block frame with its own padding.
	whole := (&Block{vm: h.VM, Identities: []*Identity{identity}}).Marshal()
	require.ErrorIs(t, parseBlock(append(append([]byte(nil), whole...), 0), &blk), errTrailing)
	require.Error(t, parseBlock([]byte("not a frame"), &blk))
}

// A length vector and the blob it indexes both come from the peer, and both are
// checked: a length the blob cannot back is refused rather than dropped, and
// blob bytes no length claims are refused too — either way the value read is
// not the value that was sent.
func TestDeclaredLengthsMustCoverTheirBlob(t *testing.T) {
	_, err := unpackEach([]uint32{4}, []byte("ab"), parseIdentity)
	require.ErrorIs(t, err, errLength)

	_, err = unpackEach(nil, []byte("orphan"), parseIdentity)
	require.ErrorIs(t, err, errLength)

	_, err = unpackEach([]uint32{2}, []byte("ab"), parseIdentity)
	require.Error(t, err, "the element is decoded, and is not an identity")

	// unpackStrings used to BREAK on a length past the end, silently
	// truncating the list — so a credential's type list arrived shorter than
	// it was sent.
	_, err = unpackStrings([]uint32{4}, []byte("ab"))
	require.ErrorIs(t, err, errLength)

	_, err = unpackStrings(nil, []byte("orphan"))
	require.ErrorIs(t, err, errLength)

	_, err = unpackStrings([]uint32{1}, []byte("ab"))
	require.ErrorIs(t, err, errLength)

	got, err := unpackStrings([]uint32{1, 1}, []byte("ab"))
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, got)

	got, err = unpackStrings(nil, nil)
	require.NoError(t, err)
	require.Nil(t, got)
}

// Metadata is a map: an odd number of strings is a key with no value, which
// the reader used to drop.
func TestMetadataMustPair(t *testing.T) {
	lens, blob := packMetadata(map[string]string{"b": "2", "a": "1"})
	back, err := unpackMetadata(lens, blob)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"a": "1", "b": "2"}, back)

	// Key-sorted, so the same map is the same bytes.
	againLens, againBlob := packMetadata(map[string]string{"a": "1", "b": "2"})
	require.Equal(t, lens, againLens)
	require.Equal(t, blob, againBlob)

	_, err = unpackMetadata([]uint32{1}, []byte("a"))
	require.ErrorIs(t, err, errLength)

	_, err = unpackMetadata([]uint32{4}, []byte("a"))
	require.ErrorIs(t, err, errLength)

	back, err = unpackMetadata(nil, nil)
	require.NoError(t, err)
	require.Nil(t, back)
}

// A claims blob that will not decode is a failure. Read as "no claims", it
// passed the claims bound trivially and the credential the chain recorded was
// not the credential that was sent.
func TestClaimsMustDecode(t *testing.T) {
	claims := map[string]interface{}{"a": float64(1), "b": "two"}
	back, err := parseClaims(marshalClaims(claims))
	require.NoError(t, err)
	require.Equal(t, claims, back)

	back, err = parseClaims(marshalClaims(nil))
	require.NoError(t, err)
	require.Nil(t, back)

	_, err = parseClaims([]byte("{"))
	require.ErrorIs(t, err, errClaims)

	_, err = parseCredential(func() []byte {
		b := zap.NewBuilder(zap.HeaderSize + crSize + 64)
		ob := b.StartObject(crSize)
		ob.SetBytes(crClaims, []byte("{"))
		ob.FinishAsRoot()
		return b.Finish()
	}())
	require.ErrorIs(t, err, errClaims)
}

// A block whose records do not decode is not a block, whichever list they are
// in.
func TestABlocksRecordsMustDecode(t *testing.T) {
	for _, slot := range []struct {
		lens, blob int
	}{
		{blkIdnLens, blkIdnBlob},
		{blkIssLens, blkIssBlob},
		{blkCredLens, blkCredBlob},
		{blkRevLens, blkRevBlob},
	} {
		junk := []byte("not a frame")
		b := zap.NewBuilder(zap.HeaderSize + blkSize + len(junk) + 64)
		off := writeU32List(b, []uint32{uint32(len(junk))})
		ob := b.StartObject(blkSize)
		ob.SetBytesFixed(blkParent, make([]byte, 32))
		ob.SetList(slot.lens, off, 1)
		ob.SetBytes(slot.blob, junk)
		ob.FinishAsRoot()

		var blk Block
		require.Error(t, parseBlock(b.Finish(), &blk))
	}
}

// A public key on the wire that is not an ML-DSA-65 key is refused where it is
// used, not where it is read.
func TestAKeyMustBeAKey(t *testing.T) {
	require.ErrorIs(t, verify([]byte("short"), []byte("msg"), []byte("sig"), nil), errNoKey)

	h := newHarness(t)
	p := newParty(t)
	require.ErrorIs(t,
		verify(p.pub, []byte("msg"), []byte("not a signature"), h.bind[:]),
		errNotAuthorized)
}

// ======== store failures ========

type refusingWrites struct {
	database.Database
	err error
}

func (d *refusingWrites) Put([]byte, []byte) error { return d.err }

// A block that cannot record what it decides records nothing: Write is
// discarded whole.
func TestABlockThatCannotWriteChangesNothing(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	issuer, subject := newParty(t), newParty(t)
	issuerRecord := h.issuer(t, issuer, "registry")
	subjectRecord := h.identity(t, subject, nil)
	cred := h.credential(t, issuer, issuerRecord.ID, subjectRecord.ID, time.Now().Add(time.Hour))
	rev := h.revocation(t, subject, cred.ID, subjectRecord.ID)

	tip, height := h.chain.Tip()
	blk := &Block{
		ParentID_:      tip,
		BlockHeight:    height + 1,
		BlockTimestamp: time.Now().Unix(),
		Identities:     []*Identity{subjectRecord},
		Issuers:        []*Issuer{issuerRecord},
		Credentials:    []*Credential{cred},
		Revocations:    []*Revocation{rev},
		vm:             h.VM,
	}
	require.NoError(t, blk.Verify(ctx))

	boom := errors.New("disk gone")
	require.ErrorIs(t, blk.Write(&refusingWrites{err: boom}), boom)

	// Each list in turn: a store that takes the first n writes and refuses the
	// next names which one the block could not record.
	for n := 1; n <= 3; n++ {
		require.ErrorIs(t, blk.Write(&refusingAfter{Database: memdb.New(), n: n, err: boom}), boom)
	}
	require.NoError(t, blk.Write(memdb.New()))

	_, err := h.Identity(subjectRecord.ID)
	require.Error(t, err, "a block that was not accepted changed nothing")
}

// refusingAfter takes n writes and refuses the rest.
type refusingAfter struct {
	database.Database
	n   int
	err error
}

func (d *refusingAfter) Put(k, v []byte) error {
	if d.n <= 0 {
		return d.err
	}
	d.n--
	return d.Database.Put(k, v)
}

// A record on disk that will not decode is a failure, not a record to skip:
// the chain wrote it, so a node that cannot read it back does not hold the
// state it believes it holds.
func TestAnUnreadableRecordRefusesToOpen(t *testing.T) {
	for _, prefix := range [][]byte{identityPrefix, issuerPrefix, credentialPrefix, revocationPrefix} {
		db := memdb.New()
		require.NoError(t, db.Put(key(prefix, ids.ID{1}), []byte("not a frame")))

		h := &harness{db: db, chainID: ids.ID{5}, network: 1}
		vm := &VM{}
		err := vm.Initialize(context.Background(), initFor(h, nil))
		require.Error(t, err, "prefix %s", prefix)
		require.Contains(t, err.Error(), "record")
	}
}

// A set that cannot be READ is not an empty set: the iterator's failure is
// the answer, not the zero records it produced before failing.
func TestAnUnreadableStoreIsAFailure(t *testing.T) {
	boom := errors.New("iterator gone")
	_, err := load(&failIterDB{Database: memdb.New(), err: boom}, identityPrefix, parseIdentity)
	require.ErrorIs(t, err, boom)
}

type failIterDB struct {
	database.Database
	err error
}

func (d *failIterDB) NewIteratorWithPrefix([]byte) database.Iterator {
	return &brokenIter{err: d.err}
}

type brokenIter struct {
	database.Iterator
	err error
}

func (i *brokenIter) Next() bool    { return false }
func (i *brokenIter) Error() error  { return i.err }
func (i *brokenIter) Release()      {}
func (i *brokenIter) Key() []byte   { return nil }
func (i *brokenIter) Value() []byte { return nil }

var _ = log.NoLog{}

// A record whose own length vectors disagree with their blob is refused where
// it is read, not carried half-decoded into the chain's state.
func TestARecordsListsMustAgreeWithTheirBlob(t *testing.T) {
	// An identity whose metadata lengths overrun their blob.
	b := zap.NewBuilder(zap.HeaderSize + idnSize + 64)
	off := writeU32List(b, []uint32{9})
	ob := b.StartObject(idnSize)
	ob.SetList(idnMetaLen, off, 1)
	ob.SetBytes(idnMetaBlb, []byte("ab"))
	ob.FinishAsRoot()
	_, err := parseIdentity(b.Finish())
	require.ErrorIs(t, err, errLength)

	// An issuer whose type lengths overrun theirs.
	b = zap.NewBuilder(zap.HeaderSize + isSize + 64)
	off = writeU32List(b, []uint32{9})
	ob = b.StartObject(isSize)
	ob.SetList(isTypeLens, off, 1)
	ob.SetBytes(isTypeBlob, []byte("ab"))
	ob.FinishAsRoot()
	_, err = parseIssuer(b.Finish())
	require.ErrorIs(t, err, errLength)

	// And a credential's.
	b = zap.NewBuilder(zap.HeaderSize + crSize + 64)
	off = writeU32List(b, []uint32{9})
	ob = b.StartObject(crSize)
	ob.SetList(crTypeLens, off, 1)
	ob.SetBytes(crTypeBlob, []byte("ab"))
	ob.FinishAsRoot()
	_, err = parseCredential(b.Finish())
	require.ErrorIs(t, err, errLength)
}

// Blob bytes no length claims are refused: what a peer sent and what the node
// reads have to be the same thing, in both directions.
func TestUnclaimedBlobBytesAreRefused(t *testing.T) {
	h := newHarness(t)
	frame := marshalIdentity(h.identity(t, newParty(t), nil))

	_, err := unpackEach([]uint32{uint32(len(frame))}, append(append([]byte(nil), frame...), 0xFF), parseIdentity)
	require.ErrorIs(t, err, errLength)
}
