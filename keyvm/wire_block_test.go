// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// TestBlockWireRoundTrip proves a block survives the wire with its position, its
// timestamp and every transaction intact, and that the id is a function of that
// content — a parsed block is the same block.
func TestBlockWireRoundTrip(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	original := blockAt(vm, ids.ID{1, 2, 3}, 7, vm.clock.Time(),
		registerTx(t, k, "wire-one", 300_000, 1),
		registerTx(t, k, "wire-two", 300_000, 2))

	parsed, err := parseBlock(vm, original.Bytes())
	require.NoError(t, err)

	require.Equal(t, original.ParentID(), parsed.ParentID())
	require.Equal(t, original.Parent(), parsed.Parent())
	require.Equal(t, original.Height(), parsed.Height())
	require.Equal(t, original.Timestamp().Unix(), parsed.Timestamp().Unix())
	require.Equal(t, original.ID(), parsed.ID())
	require.Len(t, parsed.transactions, 2)
	for i, tx := range parsed.transactions {
		require.Equal(t, original.transactions[i].ID(), tx.ID())
		require.NoError(t, tx.authenticate(), "a signature must survive the wire")
	}
	require.Equal(t, original.Bytes(), parsed.Bytes(), "re-serialization is byte-identical")

	// An empty block round-trips too — the transaction list is not assumed to be
	// non-empty by the codec.
	empty := blockAt(vm, ids.ID{4}, 1, vm.clock.Time())
	back, err := parseBlock(vm, empty.Bytes())
	require.NoError(t, err)
	require.Empty(t, back.transactions)
	require.Equal(t, empty.ID(), back.ID())
}

// TestBlockIDIsDerivedNotStored proves the id is a function of the block's
// content rather than a field a peer supplies: an unstamped block computes it on
// demand, and any change of parent, height, time or transaction set changes it.
func TestBlockIDIsDerivedNotStored(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	tx := registerTx(t, k, "identified", 300_000, 1)
	base := &Block{parentID: ids.ID{1}, height: 3, timestamp: vm.clock.Time(),
		transactions: []*Transaction{tx}, vm: vm}
	id := base.ID()
	require.NotEqual(t, ids.Empty, id, "an unstamped block computes its id on demand")
	require.Equal(t, id, base.ID(), "and caches it")

	differsFrom := func(mutate func(*Block)) {
		b := &Block{parentID: ids.ID{1}, height: 3, timestamp: base.timestamp,
			transactions: []*Transaction{tx}, vm: vm}
		mutate(b)
		require.NotEqual(t, id, b.ID())
	}
	differsFrom(func(b *Block) { b.parentID = ids.ID{2} })
	differsFrom(func(b *Block) { b.height = 4 })
	differsFrom(func(b *Block) { b.timestamp = b.timestamp.Add(time.Second) })
	differsFrom(func(b *Block) { b.transactions = nil })
	differsFrom(func(b *Block) {
		b.transactions = []*Transaction{tx, registerTx(t, k, "extra", 300_000, 2)}
	})
}

// TestParseBlockRejectsNonCanonical is the regression test for block-wire
// malleability. zap ignores blob bytes past the last declared transaction
// length, so without a canonicality gate two distinct byte-strings decode to one
// block: same transactions, same id, different bytes on the wire and in every
// peer's store. Transactions already had this gate; blocks did not.
func TestParseBlockRejectsNonCanonical(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	original := blockAt(vm, ids.ID{1}, 1, vm.clock.Time(),
		registerTx(t, k, "canonical", 300_000, 1))
	data := original.Bytes()
	require.NotNil(t, data)

	// Append unreferenced padding and bump the message's declared size, so the
	// trailing-bytes check still passes and the root offset still resolves.
	twin := append(append([]byte(nil), data...), make([]byte, 8)...)
	binary.LittleEndian.PutUint32(twin[12:16], uint32(len(twin)))
	require.NotEqual(t, data, twin)

	// The twin still self-reports its padded size, so a size==len check alone
	// would accept it — that is exactly the hole.
	require.Equal(t, len(twin), int(binary.LittleEndian.Uint32(twin[12:16])))

	_, err := parseBlock(vm, twin)
	require.ErrorIs(t, err, ErrInvalidPayload)

	// The canonical original is still accepted, so the refusal is about the
	// padding and not about the block.
	_, err = parseBlock(vm, data)
	require.NoError(t, err)
}

// TestParseBlockRejectsMalformed proves every decode failure is a refusal rather
// than a panic or a partially-built block.
func TestParseBlockRejectsMalformed(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	data := blockAt(vm, ids.ID{1}, 1, vm.clock.Time(),
		registerTx(t, k, "malformed", 300_000, 1)).Bytes()

	for _, cut := range []int{0, 4, zap.HeaderSize, len(data) - 1} {
		_, err := parseBlock(vm, data[:cut])
		require.Errorf(t, err, "truncation to %d bytes must be refused", cut)
	}

	// Trailing bytes past the declared message size.
	_, err := parseBlock(vm, append(append([]byte(nil), data...), 0xff))
	require.Error(t, err)

	// A transaction length that runs past the blob it indexes.
	overrun := blockAt(vm, ids.ID{1}, 1, vm.clock.Time())
	b := zap.NewBuilder(zap.HeaderSize + blkSize + 128)
	lensOff := writeU32List(b, []uint32{9_999})
	ob := b.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, overrun.parentID[:])
	ob.SetUint64(blkHeight, 1)
	ob.SetInt64(blkTime, overrun.timestamp.Unix())
	ob.SetList(blkTxLens, lensOff, 1)
	ob.SetBytes(blkTxBlob, []byte("short"))
	ob.FinishAsRoot()
	_, err = parseBlock(vm, b.Finish())
	require.ErrorIs(t, err, ErrInvalidPayload)
}

// TestParseBlockIsTheVMEntryPoint proves the VM's ParseBlock is the same codec
// and that a parsed block is usable as a chain block: it verifies and accepts
// exactly as the one that was built.
func TestParseBlockIsTheVMEntryPoint(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 100_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	_, err := vm.SubmitTx(registerTx(t, k, "relayed", 300_000, 1))
	require.NoError(t, err)
	built, err := vm.BuildBlock(ctx)
	require.NoError(t, err)

	// A peer receives the bytes and parses them.
	relayed, err := vm.ParseBlock(ctx, built.(*Block).Bytes())
	require.NoError(t, err)
	require.Equal(t, built.ID(), relayed.ID())

	require.NoError(t, relayed.Verify(ctx))
	require.NoError(t, relayed.Accept(ctx))
	_, ok := vm.KeyByName("relayed")
	require.True(t, ok, "a relayed block applies exactly as a built one")

	// And the codec refuses what it cannot decode.
	_, err = vm.ParseBlock(ctx, []byte("nonsense"))
	require.Error(t, err)
}

// TestUnsignedTxSurvivesTheWire proves the codec does not confuse an absent
// field with an empty one: a transaction with no signature round-trips as
// unsigned, and is then refused by authentication rather than by the codec.
func TestUnsignedTxSurvivesTheWire(t *testing.T) {
	tx := &Transaction{
		Type: TxSetPolicy, GasLimit: 5_000, Nonce: 1,
		Payload: mustJSONRaw(SetPolicyPayload{}),
	}
	parsed, err := ParseTransaction(tx.Bytes())
	require.NoError(t, err)
	require.Nil(t, parsed.Auth, "an absent signature parses as absent, not as empty bytes")
	require.Nil(t, parsed.Sig)
	require.Empty(t, parsed.Algorithm)
	require.ErrorIs(t, parsed.authenticate(), ErrUnsignedTx)
	require.NoError(t, parsed.SyntacticVerify(), "the codec's job ends at decoding")
}
