// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// pinRoot is the state root the durability tests are admitted against.
var pinRoot = h(0x55)

// storedAt builds a durability claim for an object read back correctly from the
// given store addresses, which index the pin's file list.
func storedAt(out Handle, shards ...uint32) Durability {
	files := make([]string, 0, len(shards)+1)
	for i := 0; i <= len(shards); i++ {
		files = append(files, "3,01637037d"+string(rune('0'+i)))
	}
	d := Durability{Pin: Pin{Root: pinRoot, Files: files}}
	for _, s := range shards {
		d.Replicas = append(d.Replicas, Replica{Shard: s, Witness: out.Digest})
	}
	return d
}

func withDurability(d Durability) Evidence {
	ev := runcEvidence()
	ev.Durability = d
	return ev
}

// TestOneCopyNeedsAnAdmittedRootAndARealRead.
func TestOneCopyNeedsAnAdmittedRootAndARealRead(t *testing.T) {
	out := outputHandle()
	trust := admits{root: pinRoot}
	claim := h(1)

	ev := withDurability(storedAt(out, 0))
	require.NoError(t, ev.Proves(Require(ReplicaOne), claim, out, common.Address{}, trust))

	// A root nobody admitted is a number.
	bad := ev
	bad.Durability.Pin.Root = h(0x56)
	require.ErrorIs(t, bad.Proves(Require(ReplicaOne), claim, out, common.Address{}, trust), ErrRootNotAdmitted)

	// A pin naming no stored blob claims nothing.
	bad = ev
	bad.Durability.Pin.Files = nil
	require.ErrorIs(t, bad.Proves(Require(ReplicaOne), claim, out, common.Address{}, trust), ErrDurabilityPin)

	// No copies at all.
	bad = ev
	bad.Durability.Replicas = nil
	require.ErrorIs(t, bad.Proves(Require(ReplicaOne), claim, out, common.Address{}, trust), ErrDurabilityReplicas)
}

// TestAWrongObjectIsNotAWeakCopy is the one durability question no storage layer
// can answer on your behalf. A witness that does not hash to the handle is a
// different object, and it is not counted at all: reading something back is not
// evidence, reading the RIGHT thing back is.
func TestAWrongObjectIsNotAWeakCopy(t *testing.T) {
	out := outputHandle()
	trust := admits{root: pinRoot}

	d := storedAt(out, 0, 1)
	d.Replicas[0].Witness = h(0xBA) // opened fine, wrong bytes
	ev := withDurability(d)

	require.ErrorIs(t,
		ev.Proves(Require(ReplicaMany), h(1), out, common.Address{}, trust),
		ErrDurabilityReplicas,
		"a copy that read back different bytes does not count")
	// The one good copy still proves a single copy.
	require.NoError(t, ev.Proves(Require(ReplicaOne), h(1), out, common.Address{}, trust))
}

// TestOneAddressReadTwiceIsOneCopy: copies are counted against the store's own
// addresses for them, so reading the same blob four times is one copy however
// many times it is listed.
func TestOneAddressReadTwiceIsOneCopy(t *testing.T) {
	out := outputHandle()
	trust := admits{root: pinRoot}

	repeated := storedAt(out, 0, 0, 0, 0)
	require.ErrorIs(t,
		withDurability(repeated).Proves(Require(ReplicaMany), h(1), out, common.Address{}, trust),
		ErrDurabilityReplicas,
		"one blob read four times is one copy")

	two := storedAt(out, 0, 1)
	require.NoError(t,
		withDurability(two).Proves(Require(ReplicaMany), h(1), out, common.Address{}, trust))
}

// TestErasureNeedsShardsThatRebuildTheObject: a set of shards that does not
// reconstruct what the handle names is not a coded copy of it.
func TestErasureNeedsShardsThatRebuildTheObject(t *testing.T) {
	shards := []common.Hash{h(0xE0), h(0xE1), h(0xE2)}
	out := Handle{Digest: h(0x33), Size: 256, Shards: ShardRoot(shards), Bucket: "out", Key: "res"}
	trust := admits{root: pinRoot}

	full := Durability{
		Pin: Pin{Root: pinRoot, Files: []string{"a", "b", "c"}},
		Replicas: []Replica{
			{Shard: 0, Witness: shards[0]},
			{Shard: 1, Witness: shards[1]},
			{Shard: 2, Witness: shards[2]},
		},
	}
	require.NoError(t, withDurability(full).Proves(Require(ReplicaErasure), h(1), out, common.Address{}, trust))

	// One shard missing: the coding is incomplete and proves nothing.
	gap := full
	gap.Replicas = []Replica{full.Replicas[0], {Shard: 2, Witness: shards[2]}}
	require.ErrorIs(t, withDurability(gap).Proves(Require(ReplicaErasure), h(1), out, common.Address{}, trust),
		ErrDurabilityShards)

	// A shard that read back the wrong bytes breaks the reconstruction.
	wrong := full
	wrong.Replicas = append([]Replica(nil), full.Replicas...)
	wrong.Replicas[1].Witness = h(0xBB)
	require.ErrorIs(t, withDurability(wrong).Proves(Require(ReplicaErasure), h(1), out, common.Address{}, trust),
		ErrDurabilityShards)

	// Shards in the wrong order are a different object.
	swapped := full
	swapped.Replicas = append([]Replica(nil), full.Replicas...)
	swapped.Replicas[0].Witness, swapped.Replicas[1].Witness = shards[1], shards[0]
	require.ErrorIs(t, withDurability(swapped).Proves(Require(ReplicaErasure), h(1), out, common.Address{}, trust),
		ErrDurabilityShards)
}

// TestReplicaMustNameABlobThePinHolds.
func TestReplicaMustNameABlobThePinHolds(t *testing.T) {
	out := outputHandle()
	trust := admits{root: pinRoot}

	d := storedAt(out, 0)
	d.Replicas[0].Shard = 7 // beyond the pin's file list
	require.ErrorIs(t, withDurability(d).Proves(Require(ReplicaOne), h(1), out, common.Address{}, trust),
		ErrDurabilityReplicas)
}

// TestDurabilityRidesTheSignature: the copies are part of what an operator signs,
// so a durability claim cannot be swapped onto another run's evidence.
func TestDurabilityRidesTheSignature(t *testing.T) {
	op := newKey(t)
	out := outputHandle()
	claim := h(0x77)

	ev := withDurability(storedAt(out, 0))
	require.NoError(t, ev.Sign(claim, out, op))
	require.NoError(t, ev.Proves(Require(AttestSoftware), claim, out, op.addr(), admits{root: pinRoot}))

	tampered := ev
	tampered.Durability = storedAt(out, 0, 1)
	require.ErrorIs(t, tampered.Proves(Require(AttestSoftware), claim, out, op.addr(), admits{root: pinRoot}),
		ErrEvidenceSignature)
}

// TestHandleIsContentAddressed.
func TestHandleIsContentAddressed(t *testing.T) {
	a := Handle{Digest: h(1), Size: 10, Bucket: "b", Key: "k"}
	require.Equal(t, a.ID(), Handle{Digest: h(1), Size: 10, Bucket: "b", Key: "k"}.ID())

	for _, alt := range []Handle{
		{Digest: h(2), Size: 10, Bucket: "b", Key: "k"},
		{Digest: h(1), Size: 11, Bucket: "b", Key: "k"},
		{Digest: h(1), Size: 10, Bucket: "c", Key: "k"},
		{Digest: h(1), Size: 10, Bucket: "b", Key: "l"},
		{Digest: h(1), Size: 10, Shards: h(9), Bucket: "b", Key: "k"},
	} {
		require.NotEqual(t, a.ID(), alt.ID())
	}

	// Length framing: a bucket and key that concatenate the same way are still
	// different handles.
	require.NotEqual(t,
		Handle{Digest: h(1), Size: 1, Bucket: "ab", Key: "c"}.ID(),
		Handle{Digest: h(1), Size: 1, Bucket: "a", Key: "bc"}.ID())

	require.ErrorIs(t, Handle{}.Validate(), ErrHandleEmpty)
	require.ErrorIs(t, Handle{Digest: h(1), Size: 1}.Validate(), ErrHandleLocation)
	require.NoError(t, a.Validate())
}
