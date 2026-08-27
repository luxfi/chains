// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

// handle.go is how a workload names bytes it does not carry.
//
// Nothing large rides on chain. A workload's input and a run's output are
// content-addressed handles: a digest, a size, and where on S-Chain the object's
// manifest is committed. The bytes live in the object store; the chain holds the
// claim. Retrieval is by digest, and bytes that do not hash to the handle are a
// hard failure — a wrong object is worse than a missing one, because a missing
// one stops and a wrong one continues.
//
// The digest here is AgentVM's own keccak over the full object. It is NOT the
// manifest's ETag: schain/object computes that as base64(md5(blob)) to match the
// S3 wire contract, and MD5 has been collision-broken for two decades. The ETag
// is an S3 compatibility field and this package never treats it as integrity.
//
// What a Pin can and cannot establish, measured rather than assumed:
// schain/state.Root is a SHAKE256 fold over the whole committed keyspace
// (state.go Root, domain SCHAIN_STATE_ROOT_V2, SP 800-185 left_encode framing).
// A fold has no membership proof — the only way to establish that one manifest is
// under a root is to recompute the fold over the entire keyspace, which a
// verifier on another chain cannot do. So a Pin here names a root this chain has
// ADMITTED and binds the handle to it, and the operator signs that statement. It
// is attributable, not proven-included. Proving inclusion needs a commitment with
// membership proofs on S-Chain's side, which is S-Chain's change to make.
//
// Nor does a pin make bytes available. SECURITY_review.md names data availability
// as S-Chain's deepest unsolved blocker: no erasure-coded redundancy, no
// availability sampling, so a committed manifest can point at bytes no honest node
// holds. AgentVM cannot close that from here and does not pretend to. What it can
// do is refuse to believe a durability claim that shows nothing, which is what the
// replica witnesses below are for.

import (
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// Domain separators for the storage digests.
const (
	DomainHandle = "lux/agentvm/handle/v1"
	DomainPin    = "lux/agentvm/pin/v1"
	DomainShard  = "lux/agentvm/shard/v1"
)

// MaxReplicas bounds how many witnesses one durability claim may carry, so
// verifying a claim is bounded work.
const MaxReplicas = 64

// Handle names an object by its content and by where its manifest is committed.
type Handle struct {
	// Digest is keccak over the object's full bytes. It is the identity: two
	// handles with this digest name the same object wherever they are read.
	Digest common.Hash `json:"digest"`
	// Size is the object's length in bytes.
	Size uint64 `json:"size"`
	// Shards commits to the ordered shard digests when the object is stored
	// coded. Zero when the object is stored whole.
	Shards common.Hash `json:"shards"`
	// Bucket and Key locate the object's manifest in S-Chain state.
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
}

// ShardRoot folds ordered shard digests into the commitment a coded handle
// carries. Order is meaning: shard i is the i-th piece, and a different order is
// a different object.
func ShardRoot(shards []common.Hash) common.Hash {
	buf := u32be(uint32(len(shards)))
	for _, s := range shards {
		buf = append(buf, s.Bytes()...)
	}
	return common.BytesToHash(crypto.Keccak256([]byte(DomainShard), buf))
}

// ID is the handle's content address: everything that determines which bytes it
// names and where they were committed.
func (h Handle) ID() common.Hash {
	buf := make([]byte, 0, 128)
	buf = append(buf, []byte(DomainHandle)...)
	buf = append(buf, h.Digest.Bytes()...)
	buf = append(buf, u64be(h.Size)...)
	buf = append(buf, h.Shards.Bytes()...)
	buf = append(buf, blob([]byte(h.Bucket))...)
	buf = append(buf, blob([]byte(h.Key))...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

// Validate refuses a handle that names nothing.
func (h Handle) Validate() error {
	if h.Digest == (common.Hash{}) || h.Size == 0 {
		return ErrHandleEmpty
	}
	if h.Bucket == "" || len(h.Bucket) > MaxName {
		return ErrHandleLocation
	}
	if h.Key == "" || len(h.Key) > MaxName {
		return ErrHandleLocation
	}
	return nil
}

// Pin is the chain record that an object was stored: an S-Chain state root this
// chain has admitted, and the file ids the manifest names.
type Pin struct {
	// Root is an S-Chain state root. It must be one this chain admitted; a root
	// nobody vouched for is a number.
	Root common.Hash `json:"root"`
	// Files are the object store's addresses for the object's blobs — one for a
	// whole object, one per shard for a coded one. They are opaque here; what
	// matters is how many there are and that a witness names one of them.
	Files []string `json:"files"`
}

// Digest identifies the pin for the purpose of binding it into a signed claim.
func (p Pin) Digest(h Handle) common.Hash {
	buf := make([]byte, 0, 128)
	buf = append(buf, []byte(DomainPin)...)
	buf = append(buf, p.Root.Bytes()...)
	buf = append(buf, h.ID().Bytes()...)
	buf = append(buf, u32be(uint32(len(p.Files)))...)
	for _, f := range p.Files {
		buf = append(buf, blob([]byte(f))...)
	}
	return common.BytesToHash(crypto.Keccak256(buf))
}

// Replica is one copy of an object that was actually read back, and where from.
//
// Witness is the digest of the bytes read IN FULL — not a length, not a
// successful open. A short read in this estate turned out to be a dead volume
// server's stale address behind a good Stat, so a read that opens and returns
// plausible bytes proves nothing. Only the digest does.
//
// Cluster and Host are the failure domains the copy sits in. They are what makes
// a replication claim mean anything: a configured replication factor of four
// against one process is one copy, and this chain counts domains rather than
// configuration.
type Replica struct {
	Cluster common.Hash `json:"cluster"`
	Host    common.Hash `json:"host"`
	// Shard is which piece this copy holds, indexing the pin's file list. Zero
	// for a whole object.
	Shard   uint32      `json:"shard"`
	Witness common.Hash `json:"witness"`
}

// Durability is what a run shows for the storage properties its workload
// demanded: where the object was committed, and which copies were read back.
type Durability struct {
	Pin      Pin       `json:"pin"`
	Replicas []Replica `json:"replicas"`
}

// Digest identifies the durability claim for binding into a signed statement.
func (d Durability) Digest(h Handle) common.Hash {
	buf := make([]byte, 0, 128+len(d.Replicas)*100)
	buf = append(buf, d.Pin.Digest(h).Bytes()...)
	buf = append(buf, u32be(uint32(len(d.Replicas)))...)
	for _, r := range d.Replicas {
		buf = append(buf, r.Cluster.Bytes()...)
		buf = append(buf, r.Host.Bytes()...)
		buf = append(buf, u32be(r.Shard)...)
		buf = append(buf, r.Witness.Bytes()...)
	}
	return common.BytesToHash(crypto.Keccak256([]byte(DomainPin), buf))
}

// whole returns the replicas that hold the object entire and read back the right
// bytes: a witness equal to the handle's digest. A witness that does not match is
// not a weaker copy, it is a different object, and it is dropped here rather than
// counted.
func (d Durability) whole(h Handle) []Replica {
	out := make([]Replica, 0, len(d.Replicas))
	for _, r := range d.Replicas {
		if r.Witness == h.Digest {
			out = append(out, r)
		}
	}
	return out
}

// domains counts the distinct values of one failure-domain field across replicas.
func domains(rs []Replica, of func(Replica) common.Hash) int {
	seen := make(map[common.Hash]struct{}, len(rs))
	for _, r := range rs {
		seen[of(r)] = struct{}{}
	}
	return len(seen)
}

// independent returns the replicas sitting in distinct (cluster, host) pairs.
// Copies that share a host share its failure, so however many of them there are
// they count once.
func independent(rs []Replica) []Replica {
	seen := make(map[common.Hash]struct{}, len(rs))
	out := make([]Replica, 0, len(rs))
	for _, r := range rs {
		key := common.BytesToHash(crypto.Keccak256(r.Cluster.Bytes(), r.Host.Bytes()))
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}

// coded returns the shards that read back correctly against the handle's shard
// commitment, at most one per index, each from its own host. It rebuilds the
// commitment from the witnesses in index order and returns nothing unless it
// matches: a set of shards that does not reconstruct the object the handle names
// is not a coded copy of it.
func (d Durability) coded(h Handle) []Replica {
	if h.Shards == (common.Hash{}) || len(d.Replicas) == 0 {
		return nil
	}
	byShard := make(map[uint32]Replica, len(d.Replicas))
	max := uint32(0)
	for _, r := range independent(d.Replicas) {
		if _, dup := byShard[r.Shard]; dup {
			continue
		}
		byShard[r.Shard] = r
		if r.Shard > max {
			max = r.Shard
		}
	}
	if len(byShard) != int(max)+1 {
		return nil // a gap in the shard indices: this is not the whole coding
	}
	witnesses := make([]common.Hash, 0, len(byShard))
	out := make([]Replica, 0, len(byShard))
	for i := uint32(0); i <= max; i++ {
		r := byShard[i]
		witnesses = append(witnesses, r.Witness)
		out = append(out, r)
	}
	if ShardRoot(witnesses) != h.Shards {
		return nil
	}
	return out
}

// pinned reports whether the durability claim rests on a root this chain admitted
// and names at least one stored blob. Every storage property needs this: a claim
// about copies of an object nobody committed is a claim about nothing.
func (d Durability) pinned(trust Trust) error {
	if len(d.Replicas) == 0 || len(d.Replicas) > MaxReplicas {
		return ErrDurabilityReplicas
	}
	if len(d.Pin.Files) == 0 {
		return ErrDurabilityPin
	}
	for _, r := range d.Replicas {
		if int(r.Shard) >= len(d.Pin.Files) {
			return ErrDurabilityReplicas
		}
	}
	if trust == nil || !trust.Pins(d.Pin.Root) {
		return ErrRootNotAdmitted
	}
	return nil
}
