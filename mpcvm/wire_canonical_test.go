// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// wire_canonical_test.go — what the receive path refuses.
//
// The wire is where a peer chooses the bytes. Everything below asks the same
// question in a different shape: can two different encodings mean one thing, or
// one encoding mean nothing, without the decoder saying so?

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
	"github.com/luxfi/zap"
)

// A block arrives as bytes and is refused by SIZE before anything decodes it.
// Everything below the size check allocates in proportion to what the bytes
// claim, and a peer chooses the bytes.
func TestABlockLargerThanABlockMayBeIsRefusedBeforeDecoding(t *testing.T) {
	vm := newVM(t)
	_, err := vm.ParseBlock(ctx(), make([]byte, maxBlockBytes+1))
	require.ErrorContains(t, err, "at most")
}

// An operation count past the bound is refused at the decoder, so a block that
// would make every validator run an unbounded number of signature checks never
// reaches Verify.
func TestAnOperationCountPastTheBoundIsRefusedAtTheDecoder(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 120)

	ops := make([]*Operation, 0, maxOpsPerBlock+1)
	for i := 0; i <= maxOpsPerBlock; i++ {
		ops = append(ops, key.signOpOver(t, digestOf(byte(i))))
	}
	blk := &Block{BlockHeight: 1, Operations: ops, vm: vm}
	_, err := vm.ParseBlock(ctx(), blk.Marshal())
	require.ErrorContains(t, err, "at most")
}

// Trailing bytes are refused past the CONTENT, not past the declared size.
// Bytes after the last operation sit inside the object and would otherwise be
// accepted and dropped, so one transition would have unboundedly many
// encodings on the wire.
func TestBytesAfterTheLastOperationAreRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 121)
	blk := blockOver(t, vm, key.signOpOver(t, digestOf(1)))

	padded := blockWithPaddedOperationBlob(t, blk, 16)
	_, err := vm.ParseBlock(ctx(), padded)
	require.ErrorContains(t, err, "after the last operation")

	// And past the whole message, which the header length already covers.
	raw := append(append([]byte(nil), blk.Bytes()...), 0, 0, 0, 0)
	_, err = vm.ParseBlock(ctx(), raw)
	require.ErrorContains(t, err, "trailing bytes")
}

// A declared string list that the blob does not exactly cover is an error, not
// a short answer.
//
// It used to stop at the first overrun and return what it had, so an encoding
// declaring five signers with room for three decoded to three signers with no
// error anywhere — a party set quietly smaller than the one on the wire, and
// the shape every threshold check downstream trusts.
func TestADeclaredPartySetTheBlobDoesNotCoverIsRefused(t *testing.T) {
	got, err := unpackStrings(nil, nil)
	require.NoError(t, err)
	require.Nil(t, got)

	got, err = unpackStrings([]uint32{2, 3}, []byte("aabbb"))
	require.NoError(t, err)
	require.Equal(t, []string{"aa", "bbb"}, got)

	_, err = unpackStrings([]uint32{2, 3}, []byte("aabb"))
	require.ErrorContains(t, err, "entry 1 wants 3 bytes, 2 remain")

	_, err = unpackStrings([]uint32{2}, []byte("aabbb"))
	require.ErrorContains(t, err, "after the last entry")
}

// The three records that carry a party list all refuse a truncated one, so the
// property holds wherever a set is decoded rather than at one call site.
func TestEveryRecordThatCarriesAPartySetRefusesATruncatedOne(t *testing.T) {
	rec := sampleKeyRecord()
	raw := marshalKeyRecord(rec)
	_, err := parseKeyRecord(truncateLastList(t, raw))
	require.ErrorContains(t, err, "participants")

	cer := &CeremonyRecord{ID: "mpc/x", Kind: OpTypeSign, KeyID: "vault", Signers: parties(3)}
	raw = marshalCeremonyRecord(cer)
	_, err = parseCeremonyRecord(truncateLastList(t, raw))
	require.ErrorContains(t, err, "signers")
}

// Every record refuses bytes past its declared size.
func TestEveryRecordRefusesTrailingBytes(t *testing.T) {
	rec := sampleKeyRecord()
	raw := marshalKeyRecord(rec)
	_, err := parseKeyRecord(append(raw, 0))
	require.ErrorContains(t, err, "trailing bytes")

	cer := &CeremonyRecord{ID: "mpc/x"}
	raw = marshalCeremonyRecord(cer)
	_, err = parseCeremonyRecord(append(raw, 0))
	require.ErrorContains(t, err, "trailing bytes")

	req := &CrossChainMPCRequest{Type: "sign", KeyID: "vault"}
	raw = req.Marshal()
	require.Error(t, parseCrossChainMPCRequest(append(raw, 0), &CrossChainMPCRequest{}))
}

// Bytes that are not a message at all are refused everywhere, rather than
// decoding to a zero-valued record.
func TestBytesThatAreNotARecordAreRefused(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty": nil,
		"junk":  []byte("hello there"),
		"short": make([]byte, 8),
	} {
		_, err := parseKeyRecord(raw)
		require.Errorf(t, err, "key record: %s", name)
		_, err = parseCeremonyRecord(raw)
		require.Errorf(t, err, "ceremony record: %s", name)
		require.Errorf(t, parseCrossChainMPCRequest(raw, &CrossChainMPCRequest{}), "request: %s", name)
	}
}

// A block header that is truncated decodes to nothing, rather than to a block
// naming a DIFFERENT parent and a different post-state: copy() into a fixed
// array zero-fills whatever the source did not cover.
func TestATruncatedHeaderDoesNotDecodeToADifferentBlock(t *testing.T) {
	vm := newVM(t)
	b := zap.NewBuilder(zap.HeaderSize + 8 + 64)
	ob := b.StartObject(8)
	ob.SetUint64(0, 1)
	ob.FinishAsRoot()

	_, err := vm.ParseBlock(ctx(), b.Finish())
	require.ErrorContains(t, err, "truncated")
}

// An operation that does not decode fails the whole block, rather than yielding
// a block with one fewer operation than its encoding declared.
func TestABlockWhoseNestedOperationIsBrokenIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 122)
	op := key.keygenOp(t)

	// A key record whose own encoding is junk: the operation frames it, the
	// operation decodes, and the record inside it does not.
	_, err := vm.ParseBlock(ctx(), blockCarrying(t, vm, swapNestedKeyRecord(t, op)))
	require.ErrorContains(t, err, "key record")
}

// And an operation whose own framing is junk fails the same way.
func TestABlockWhoseOperationFramingIsJunkIsRefused(t *testing.T) {
	vm := newVM(t)
	_, err := vm.ParseBlock(ctx(), blockCarrying(t, vm, []byte("not an operation")))
	require.Error(t, err)
}

// A block with no operations decodes to no operations rather than to an empty
// non-nil slice that a later check would read as "something happened".
func TestABlockWithNoOperationsDecodesToNone(t *testing.T) {
	vm := newVM(t)
	blk := &Block{BlockHeight: 1, vm: vm}
	got, err := vm.ParseBlock(ctx(), blk.Marshal())
	require.NoError(t, err)
	require.Nil(t, got.(*Block).Operations)
}

// Absent variable-length fields decode to nil rather than to an empty slice, so
// a round trip is byte-identical and a hash over the record is stable.
func TestAnAbsentFieldDecodesToNothing(t *testing.T) {
	require.Nil(t, appendBytes(nil))
	require.Nil(t, appendBytes([]byte{}))
	require.Equal(t, []byte{1, 2}, appendBytes([]byte{1, 2}))

	require.Nil(t, stringsToPartyIDs(nil))
	require.Equal(t, []party.ID{"a"}, stringsToPartyIDs([]string{"a"}))
	require.Nil(t, partyIDsToStrings(nil))
	require.Equal(t, []string{"a"}, partyIDsToStrings([]party.ID{"a"}))
}

// A record round-trips to the same bytes, so two validators that hash what they
// stored hash the same thing.
func TestARecordRoundTripsToTheSameBytes(t *testing.T) {
	rec := sampleKeyRecord()
	raw := marshalKeyRecord(rec)
	back, err := parseKeyRecord(raw)
	require.NoError(t, err)
	again := marshalKeyRecord(back)
	require.Equal(t, raw, again)
	require.Equal(t, KeyCommitDigest(rec), KeyCommitDigest(back))
}

// A block's id is the hash of its canonical bytes, so a peer that pads the
// encoding cannot produce a second id for one transition — the parse refuses
// the padding, and the id is recomputed from a re-marshal rather than from the
// bytes as received.
func TestOneTransitionHasOneId(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 123)
	blk := blockOver(t, vm, key.signOpOver(t, digestOf(1)))

	parsed, err := vm.ParseBlock(ctx(), blk.Bytes())
	require.NoError(t, err)
	require.Equal(t, blk.ID(), parsed.ID())
	require.Equal(t, blk.Bytes(), parsed.Bytes())

	// Every field that is in the encoding moves the id.
	for name, mangle := range map[string]func(*Block){
		"parent":    func(b *Block) { b.ParentID_[0] ^= 1 },
		"height":    func(b *Block) { b.BlockHeight++ },
		"timestamp": func(b *Block) { b.BlockTimestamp++ },
		"root":      func(b *Block) { b.StateRoot[0] ^= 1 },
		"operation": func(b *Block) { b.Operations[0].Digest = digestOf(9) },
	} {
		other := blockOver(t, vm, key.signOpOver(t, digestOf(1)))
		mangle(other)
		require.NotEqualf(t, blk.ID(), other.computeID(), "%s must move the block id", name)
	}
}

// -----------------------------------------------------------------------------
// helpers that produce bytes a builder would never emit
// -----------------------------------------------------------------------------

// blockWithPaddedOperationBlob re-encodes blk with n unreferenced bytes after
// the last operation — an encoding no builder produces and a peer can.
func blockWithPaddedOperationBlob(t *testing.T, blk *Block, n int) []byte {
	t.Helper()
	var opBlob []byte
	opLens := make([]uint32, 0, len(blk.Operations))
	for _, op := range blk.Operations {
		ob := marshalOperation(op)
		opLens = append(opLens, uint32(len(ob)))
		opBlob = append(opBlob, ob...)
	}
	opBlob = append(opBlob, make([]byte, n)...)

	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(opBlob) + 4*len(opLens) + 128)
	off := writeU32List(bld, opLens)
	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, blk.ParentID_[:])
	ob.SetUint64(blkHeight, blk.BlockHeight)
	ob.SetInt64(blkTime, blk.BlockTimestamp)
	ob.SetBytesFixed(blkRoot, blk.StateRoot[:])
	ob.SetList(blkOpLens, off, len(opLens))
	ob.SetBytes(blkOpBlob, opBlob)
	ob.FinishAsRoot()
	return bld.Finish()
}

// truncateLastList shortens the message so its final variable-length blob no
// longer covers what its length list declares.
func truncateLastList(t *testing.T, raw []byte) []byte {
	t.Helper()
	require.Greater(t, len(raw), 4)
	out := append([]byte(nil), raw[:len(raw)-1]...)
	// The declared size lives in the header; shrink it with the buffer so the
	// framing stays consistent and the failure is the list, not the frame.
	out[12]--
	return out
}

// swapNestedKeyRecord re-encodes an operation with junk where its key record
// belongs: the operation frames correctly and the record inside it does not.
func swapNestedKeyRecord(t *testing.T, op *Operation) []byte {
	t.Helper()
	signerLens, signerBlob := packStrings(partyIDsToStrings(op.Signers))
	b := zap.NewBuilder(zap.HeaderSize + opSize + 512)
	off := writeU32List(b, signerLens)

	ob := b.StartObject(opSize)
	ob.SetBytes(opType, []byte(op.Type))
	ob.SetBytes(opCeremony, []byte(op.CeremonyID))
	ob.SetBytes(opKeyID, []byte(op.KeyID))
	ob.SetBytes(opDigest, op.Digest)
	ob.SetBytes(opArtifact, op.Artifact)
	ob.SetList(opSignerLens, off, len(signerLens))
	ob.SetBytes(opSignerBlob, signerBlob)
	ob.SetUint8(opKeyPresent, 1)
	ob.SetBytes(opKeyBlob, []byte("not a key record"))
	ob.FinishAsRoot()
	return b.Finish()
}

// blockCarrying frames one already-encoded operation blob into a block, so a
// test can hand the decoder bytes a builder would never emit.
func blockCarrying(t *testing.T, vm *VM, opBlob []byte) []byte {
	t.Helper()
	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(opBlob) + 128)
	off := writeU32List(bld, []uint32{uint32(len(opBlob))})
	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, make([]byte, 32))
	ob.SetUint64(blkHeight, 1)
	ob.SetInt64(blkTime, 1)
	ob.SetBytesFixed(blkRoot, make([]byte, 32))
	ob.SetList(blkOpLens, off, 1)
	ob.SetBytes(blkOpBlob, opBlob)
	ob.FinishAsRoot()
	return bld.Finish()
}

// An operation whose declared length runs past the blob is refused, rather
// than read from whatever follows it.
func TestAnOperationLengthPastTheBlobIsRefused(t *testing.T) {
	vm := newVM(t)
	bld := zap.NewBuilder(zap.HeaderSize + blkSize + 128)
	off := writeU32List(bld, []uint32{4096})
	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, make([]byte, 32))
	ob.SetUint64(blkHeight, 1)
	ob.SetBytesFixed(blkRoot, make([]byte, 32))
	ob.SetList(blkOpLens, off, 1)
	ob.SetBytes(blkOpBlob, []byte("short"))
	ob.FinishAsRoot()

	_, err := vm.ParseBlock(ctx(), bld.Finish())
	require.ErrorContains(t, err, "out of bounds")
}

// An operation whose signer list declares more than its blob holds is refused
// at the operation, so a block cannot carry a party set smaller than the one
// its encoding names.
func TestAnOperationWithATruncatedSignerListIsRefused(t *testing.T) {
	vm := newVM(t)
	b := zap.NewBuilder(zap.HeaderSize + opSize + 128)
	off := writeU32List(b, []uint32{2, 99})
	ob := b.StartObject(opSize)
	ob.SetBytes(opType, []byte(OpTypeSign))
	ob.SetBytes(opCeremony, []byte("mpc/x"))
	ob.SetList(opSignerLens, off, 2)
	ob.SetBytes(opSignerBlob, []byte("pa"))
	ob.FinishAsRoot()

	_, err := vm.ParseBlock(ctx(), blockCarrying(t, vm, b.Finish()))
	require.ErrorContains(t, err, "signers")
}
