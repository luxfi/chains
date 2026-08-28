// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

// state.go is where AgentVM keeps its own state and how it encodes it.
//
// AgentVM runs on A-Chain's substrate, the same slot store and the same custody
// account, but it keeps its own facts: the capability catalog,
// who advertises what, which workload opened which task, and what an operator
// attested. Those are AgentVM's concern and they live under AgentVM's own
// namespace prefix, so no slot AgentVM writes can ever collide with one A-Chain
// writes even though both are in the same store.
//
// The encoders here are the only place a width or an endianness is chosen. They
// are AgentVM's, deliberately: an encoding is part of what a chain agrees on, and
// borrowing one across a chain boundary would tie two agreements together.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/aivm"
)

// State and Ledger are A-Chain's substrate, named here so AgentVM's own code
// reads in its own vocabulary. They are the same interfaces: AgentVM stores its
// facts in the same slot store and moves value through the same custody account,
// under its own key prefix.
type (
	State  = aivm.QuorumState
	Ledger = aivm.QuorumLedger
)

// Slot namespaces. Every one begins "ag/", which is what keeps them disjoint from
// A-Chain's "av/" keyspace in the shared store.
var (
	nsStateRoot    = []byte("ag/root")        // admitted S-Chain state root -> flag
	nsCatalog      = []byte("ag/cat")         // catalog digest -> version
	nsCatalogAt    = []byte("ag/cat.at")      // version -> catalog digest
	nsCatalogGroup = []byte("ag/cat.grp")     // (catalog, group) -> group digest
	nsGroupIndex   = []byte("ag/grp.idx")     // per-group operator-array length
	nsGroupMember  = []byte("ag/grp.mem")     // per-group operator-array element
	nsGroupSeen    = []byte("ag/grp.seen")    // per-(group, operator) membership flag
	nsAdMech       = []byte("ag/ad.mech")     // operator -> advertised mechanism set
	nsAdNonce      = []byte("ag/ad.nonce")    // operator -> last accepted advertisement nonce
	nsAdDomain     = []byte("ag/ad.domain")   // operator -> declared failure domain
	nsAdPlace      = []byte("ag/ad.place")    // operator -> advertised placement
	nsAdCatalog    = []byte("ag/ad.cat")      // operator -> advertised catalog digest
	nsAdGroup      = []byte("ag/ad.grp")      // (group, operator) -> serves flag
	nsAdCapacity   = []byte("ag/ad.cap")      // operator -> advertised concurrent capacity
	nsAdLoad       = []byte("ag/ad.load")     // operator -> capacity currently held
	nsWorkloadSeen = []byte("ag/wl.seen")     // per-workload consumed marker (anti-replay)
	nsWorkloadTask = []byte("ag/wl.task")     // workload id -> task id
	nsTaskWorkload = []byte("ag/task.wl")     // task id -> workload id
	nsTaskDemand   = []byte("ag/task.demand") // task id -> demanded properties + placement
	nsTaskOpen     = []byte("ag/task.open")   // open-task array element (index -> task id)
	nsTaskOpenLen  = []byte("ag/task.openn")  // open-task array length
	nsAttestOut    = []byte("ag/att.out")     // (task, operator) -> attested output hash
	nsAttestRcpt   = []byte("ag/att.rcpt")    // (task, operator) -> attested receipt hash
	nsAttestKey    = []byte("ag/att.key")     // admitted attesting-key digest -> flag
)

// Slot derivation: keccak over a namespace tuple, so distinct record kinds can
// never share a slot.

func slotNS(ns []byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns))
}

func slotNSIdx(ns []byte, idx uint32) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, u32be(idx)))
}

func slotAddr(ns []byte, a common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, a.Bytes()))
}

func slotHash(ns []byte, h common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, h.Bytes()))
}

func slotHashAddr(ns []byte, h common.Hash, a common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, h.Bytes(), a.Bytes()))
}

func slotHashIdx(ns []byte, h common.Hash, idx uint32) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, h.Bytes(), u32be(idx)))
}

func slotHashHash(ns []byte, a, b common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, a.Bytes(), b.Bytes()))
}

// Fixed-width encoders. The one place a width or an endianness is decided.

func u16be(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func u32be(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func u64be(v uint64) []byte {
	return []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

// blob length-prefixes a byte string so a concatenation of several cannot be
// re-cut differently: "ab"+"c" and "a"+"bc" produce different bytes.
func blob(b []byte) []byte {
	out := make([]byte, 0, 4+len(b))
	out = append(out, u32be(uint32(len(b)))...)
	return append(out, b...)
}

// h32 packs a uint256 into a state word.
func h32(v *uint256.Int) common.Hash {
	b := v.Bytes32()
	return common.BytesToHash(b[:])
}

// readUint reads a uint256-valued slot (zero if unset).
func readUint(st State, slot common.Hash) *uint256.Int {
	return new(uint256.Int).SetBytes(st.GetState(slot).Bytes())
}

// isSet reports whether a slot holds a non-zero value.
func isSet(h common.Hash) bool { return h != (common.Hash{}) }

// oneHash is the canonical "true" flag value.
func oneHash() common.Hash {
	var w [32]byte
	w[31] = 1
	return common.BytesToHash(w[:])
}

// ---------------------------------------------------------------------------
// The enumerable operator set.
// ---------------------------------------------------------------------------

// set is an append-only address array keyed by a 32-byte label, plus a
// per-(label, address) flag that makes appending idempotent.
//
// Engine state is keyed by slot hash and cannot be walked, so anything that has
// to be enumerated is held as an array with a length beside it. Entries are never
// removed: removing one would shift the indices after it and change what a later
// draw over the same registry produces. An entry that stops qualifying is
// filtered when the set is read, not deleted.
type set struct {
	count  []byte
	member []byte
	seen   []byte
}

// groups indexes operators by the capability group they serve.
var groups = set{count: nsGroupIndex, member: nsGroupMember, seen: nsGroupSeen}

// len reports how many addresses the label holds.
func (s set) len(st State, label common.Hash) uint32 {
	return uint32(readUint(st, slotHash(s.count, label)).Uint64())
}

// at reads the address at an index.
func (s set) at(st State, label common.Hash, idx uint32) common.Address {
	return common.BytesToAddress(st.GetState(slotHashIdx(s.member, label, idx)).Bytes())
}

// add appends op under label if it is not already there, so re-advertising never
// duplicates an entry and the array stays a set.
func (s set) add(st State, label common.Hash, op common.Address) {
	seen := slotHashAddr(s.seen, label, op)
	if isSet(st.GetState(seen)) {
		return
	}
	n := s.len(st, label)
	st.SetState(slotHashIdx(s.member, label, n), common.BytesToHash(common.LeftPadBytes(op.Bytes(), 32)))
	st.SetState(slotHash(s.count, label), h32(uint256.NewInt(uint64(n)+1)))
	st.SetState(seen, oneHash())
}

// all reads the addresses under a label in insertion order, keeping the ones
// admit accepts. The filter runs at read time so an operator that stops
// qualifying leaves the array unchanged and the indices stable.
func (s set) all(st State, label common.Hash, admit func(common.Address) bool) []common.Address {
	n := s.len(st, label)
	out := make([]common.Address, 0, n)
	for i := uint32(0); i < n; i++ {
		if op := s.at(st, label, i); admit(op) {
			out = append(out, op)
		}
	}
	return out
}
