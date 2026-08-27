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

// storedAt builds a durability claim for an object read back from the given
// (cluster, host) pairs, each witness being the object's own digest.
func storedAt(out Handle, at ...[2]byte) Durability {
	d := Durability{Pin: Pin{Root: pinRoot, Files: []string{"3,01637037d6"}}}
	for _, p := range at {
		d.Replicas = append(d.Replicas, Replica{
			Cluster: h(p[0]), Host: h(p[1]), Witness: out.Digest,
		})
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

	ev := withDurability(storedAt(out, [2]byte{1, 1}))
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

// TestAWrongObjectIsNotAWeakCopy: a witness that does not hash to the handle is a
// different object, and it is not counted at all. Reading something back is not
// evidence; reading the RIGHT thing back is.
func TestAWrongObjectIsNotAWeakCopy(t *testing.T) {
	out := outputHandle()
	trust := admits{root: pinRoot}

	d := storedAt(out, [2]byte{1, 1}, [2]byte{1, 2})
	d.Replicas[0].Witness = h(0xBA) // opened fine, wrong bytes
	ev := withDurability(d)

	require.ErrorIs(t,
		ev.Proves(Require(ReplicaMany), h(1), out, common.Address{}, trust),
		ErrDurabilityReplicas,
		"a copy that read back different bytes does not count toward replication")
	// The one good copy still proves a single copy.
	require.NoError(t, ev.Proves(Require(ReplicaOne), h(1), out, common.Address{}, trust))
}

// TestFourCopiesInOneProcessAreOneCopy is the production shape this check exists
// for: a store configured as distributed whose master, filer, gateway and biggest
// volume server were one process. Four replicas on one host share one failure, so
// they count once.
func TestFourCopiesInOneProcessAreOneCopy(t *testing.T) {
	out := outputHandle()
	trust := admits{root: pinRoot}

	sameHost := storedAt(out, [2]byte{1, 1}, [2]byte{1, 1}, [2]byte{1, 1}, [2]byte{1, 1})
	require.ErrorIs(t,
		withDurability(sameHost).Proves(Require(ReplicaMany), h(1), out, common.Address{}, trust),
		ErrDurabilityReplicas,
		"four copies in one failure domain are one copy")

	twoHosts := storedAt(out, [2]byte{1, 1}, [2]byte{1, 2})
	require.NoError(t,
		withDurability(twoHosts).Proves(Require(ReplicaMany), h(1), out, common.Address{}, trust))
}

// TestSpreadCountsDomainsNotCopies.
func TestSpreadCountsDomainsNotCopies(t *testing.T) {
	out := outputHandle()
	trust := admits{root: pinRoot}

	oneCluster := withDurability(storedAt(out, [2]byte{1, 1}, [2]byte{1, 2}))
	require.NoError(t, oneCluster.Proves(Require(SpreadCluster), h(1), out, common.Address{}, trust),
		"two hosts is a cluster spread")
	require.ErrorIs(t, oneCluster.Proves(Require(SpreadFederated), h(1), out, common.Address{}, trust),
		ErrDurabilitySpread,
		"two hosts of one cluster is not a federated spread")

	twoClusters := withDurability(storedAt(out, [2]byte{1, 1}, [2]byte{2, 1}))
	require.NoError(t, twoClusters.Proves(Require(SpreadFederated), h(1), out, common.Address{}, trust))

	// Sharing a host is not a claim, so it costs nothing to show.
	require.NoError(t, withDurability(storedAt(out, [2]byte{1, 1})).
		Proves(Require(SpreadHost), h(1), out, common.Address{}, trust))
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
			{Cluster: h(1), Host: h(1), Shard: 0, Witness: shards[0]},
			{Cluster: h(1), Host: h(2), Shard: 1, Witness: shards[1]},
			{Cluster: h(2), Host: h(3), Shard: 2, Witness: shards[2]},
		},
	}
	require.NoError(t, withDurability(full).Proves(Require(ReplicaErasure), h(1), out, common.Address{}, trust))
	// The same shards span two clusters, so the spread reads off the coded set.
	require.NoError(t, withDurability(full).Proves(Require(ReplicaErasure, SpreadFederated), h(1), out, common.Address{}, trust))

	// One shard missing: the coding is incomplete and proves nothing.
	gap := full
	gap.Replicas = full.Replicas[:2]
	gap.Replicas = append([]Replica(nil), gap.Replicas...)
	gap.Replicas[1].Shard = 2 // indices 0 and 2, nothing at 1
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

	d := storedAt(out, [2]byte{1, 1})
	d.Replicas[0].Shard = 7 // the pin names one blob
	require.ErrorIs(t, withDurability(d).Proves(Require(ReplicaOne), h(1), out, common.Address{}, trust),
		ErrDurabilityReplicas)
}

// TestDurabilityRidesTheSignature: the copies are part of what an operator signs,
// so a durability claim cannot be swapped onto another run's evidence.
func TestDurabilityRidesTheSignature(t *testing.T) {
	op := newKey(t)
	out := outputHandle()
	claim := h(0x77)

	ev := withDurability(storedAt(out, [2]byte{1, 1}))
	require.NoError(t, ev.Sign(claim, out, op))
	require.NoError(t, ev.Proves(Require(AttestSoftware), claim, out, op.addr(), admits{root: pinRoot}))

	tampered := ev
	tampered.Durability = storedAt(out, [2]byte{1, 1}, [2]byte{1, 2})
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
