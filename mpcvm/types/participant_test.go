// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package types

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

func node(b ...byte) NodeID {
	var n NodeID
	copy(n[:], b)
	return n
}

// A set with no members is refused.
//
// An empty set makes every ParticipantID out of range, so Share.Validate would
// reject every share and the ceremony would stall rather than fail. Refusing at
// construction puts the error where the selection bug is.
func TestParticipantSet_EmptyIsRefused(t *testing.T) {
	for _, in := range [][]Participant{nil, {}} {
		if _, err := NewParticipantSet(CeremonyID{1}, in); err == nil {
			t.Error("an empty participant set was accepted")
		}
	}
}

// A node appearing twice is refused, wherever the repeats sit in the input.
//
// A duplicated node holds two shares of one secret. At 3-of-5 that turns three
// distinct custodians into two, and a policy verified as 3-of-5 signs with two
// operators — precisely the disjoint-quorum failure HasUniqueQuorum exists to
// prevent, arriving through the participant set instead of the policy.
func TestParticipantSet_DuplicateNodeIsRefused(t *testing.T) {
	dup := node(7)
	for _, tc := range []struct {
		name string
		in   []Participant
	}{
		{"adjacent in input", []Participant{{Node: dup}, {Node: dup}, {Node: node(9)}}},
		{"separated in input", []Participant{{Node: dup}, {Node: node(9)}, {Node: dup}}},
		{"differing weights", []Participant{{Node: dup, Weight: 1}, {Node: dup, Weight: 2}}},
		{"the whole set", []Participant{{Node: dup}, {Node: dup}}},
	} {
		_, err := NewParticipantSet(CeremonyID{1}, tc.in)
		if err == nil {
			t.Errorf("%s: a duplicated node was accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), "duplicate node") {
			t.Errorf("%s: want a duplicate-node error, got: %v", tc.name, err)
		}
	}
}

// The set is sorted by NodeID and Index is the position, whatever the caller sent.
//
// Index is what a Share's ParticipantID means and what Digest commits to, so it
// has to be a property of the set rather than of the caller. A caller that
// passes stale indices — resharing code that reuses last ceremony's set,
// selection code that numbered by stake rank — must not be able to make Index
// disagree with position, or a share would authenticate against the wrong
// participant's key.
func TestParticipantSet_IndexIsPositionInNodeOrder(t *testing.T) {
	set, err := NewParticipantSet(CeremonyID{1}, []Participant{
		{Node: node(9), Index: 400, Weight: 90},
		{Node: node(2), Index: 401, Weight: 20},
		{Node: node(5), Index: 402, Weight: 50},
		{Node: node(1), Index: 403, Weight: 10},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := []struct {
		node   NodeID
		weight uint64
	}{{node(1), 10}, {node(2), 20}, {node(5), 50}, {node(9), 90}}

	for i, m := range set.Members {
		if m.Node != want[i].node {
			t.Errorf("position %d holds node %x, want %x", i, m.Node[:1], want[i].node[:1])
		}
		if m.Index != uint32(i) {
			t.Errorf("position %d has Index %d; the caller's value survived", i, m.Index)
		}
		if m.Weight != want[i].weight {
			t.Errorf("position %d has weight %d, want %d", i, m.Weight, want[i].weight)
		}
	}
	for i := 1; i < len(set.Members); i++ {
		if bytes.Compare(set.Members[i-1].Node[:], set.Members[i].Node[:]) >= 0 {
			t.Fatalf("members are not ascending by NodeID at position %d", i)
		}
	}
	if set.CeremonyID != (CeremonyID{1}) {
		t.Fatal("the set does not carry the ceremony it was built for")
	}
}

// Ordering is decided by the whole NodeID, not its first byte.
//
// NodeIDs are content-addressed, so the discriminating byte is anywhere in the
// 32. A comparator that stopped early would order two nodes by luck, and since
// Index is position, two nodes would swap indices between the node that built
// the set and the node that rebuilt it — the same share then verifies against
// two different participants.
func TestParticipantSet_OrderUsesTheWholeNodeID(t *testing.T) {
	for _, at := range []int{0, 1, 15, 30, 31} {
		lo, hi := node(), node()
		for i := 0; i < at; i++ {
			lo[i], hi[i] = 0xFF, 0xFF
		}
		lo[at], hi[at] = 0x01, 0x02

		set, err := NewParticipantSet(CeremonyID{1}, []Participant{{Node: hi}, {Node: lo}})
		if err != nil {
			t.Fatalf("byte %d: %v", at, err)
		}
		if set.Members[0].Node != lo {
			t.Fatalf("byte %d decides the order and was not consulted", at)
		}
	}
}

// The set is independent of the slice the caller handed in.
//
// The caller's slice is the host chain's selection buffer, reused across
// ceremonies. If the set aliased it, the next selection round would silently
// rewrite the membership of a ceremony already in flight.
func TestParticipantSet_DoesNotAliasTheCallersSlice(t *testing.T) {
	in := []Participant{{Node: node(3), Weight: 30}, {Node: node(1), Weight: 10}}
	set, err := NewParticipantSet(CeremonyID{1}, in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	before := set.Digest()

	in[0] = Participant{Node: node(99), Index: 7, Weight: 999}
	in[1] = Participant{Node: node(98), Index: 8, Weight: 998}

	if set.Digest() != before {
		t.Fatal("rewriting the caller's slice changed the set that was already built")
	}
	if set.Members[0].Node != node(1) || set.Members[1].Node != node(3) {
		t.Fatal("the set shares its backing array with the caller's slice")
	}
}

// Two nodes given the same members in any order compute the same digest.
//
// The digest is the participant_root: it goes into the ceremony record and
// seeds the next ceremony's VRF. Every node derives it independently from its
// own view of the selection, which arrives over gossip in no particular order.
// An order-dependent digest is a consensus fork, not a hash mismatch.
func TestParticipantSet_DigestIsOrderIndependent(t *testing.T) {
	members := []Participant{
		{Node: node(4), Weight: 40}, {Node: node(1), Weight: 10},
		{Node: node(3), Weight: 30}, {Node: node(2), Weight: 20},
		{Node: node(5), Weight: 50},
	}
	canonical, err := NewParticipantSet(CeremonyID{0x77}, members)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := canonical.Digest()

	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 50; trial++ {
		shuffled := append([]Participant(nil), members...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		set, err := NewParticipantSet(CeremonyID{0x77}, shuffled)
		if err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		if got := set.Digest(); got != want {
			t.Fatalf("trial %d: a reordered input produced digest %x, want %x", trial, got, want)
		}
	}
}

// Every field the digest claims to commit to actually moves it.
//
// The digest is what a ceremony record binds instead of the membership itself.
// A field left out of the hash is a field an adversary may vary freely after
// the set is committed: a Weight not covered lets stake accounting be rewritten
// post hoc, an Index not covered lets two participants trade positions, and a
// CeremonyID not covered lets one committed set be replayed as another
// ceremony's.
func TestParticipantSet_DigestCommitsToEveryField(t *testing.T) {
	base := ParticipantSet{
		CeremonyID: CeremonyID{0x01},
		Members: []Participant{
			{Node: node(1), Index: 0, Weight: 100},
			{Node: node(2), Index: 1, Weight: 200},
		},
	}
	want := base.Digest()

	alter := func(f func(*ParticipantSet)) [32]byte {
		s := ParticipantSet{CeremonyID: base.CeremonyID, Members: append([]Participant(nil), base.Members...)}
		f(&s)
		return s.Digest()
	}
	for _, tc := range []struct {
		name string
		f    func(*ParticipantSet)
	}{
		{"ceremony id", func(s *ParticipantSet) { s.CeremonyID = CeremonyID{0x02} }},
		{"a member's node", func(s *ParticipantSet) { s.Members[1].Node = node(3) }},
		{"a member's index", func(s *ParticipantSet) { s.Members[1].Index = 9 }},
		{"a member's weight", func(s *ParticipantSet) { s.Members[1].Weight = 201 }},
		{"two members' indices swapped", func(s *ParticipantSet) { s.Members[0].Index, s.Members[1].Index = 1, 0 }},
		{"a member dropped", func(s *ParticipantSet) { s.Members = s.Members[:1] }},
		{"a member appended", func(s *ParticipantSet) { s.Members = append(s.Members, Participant{Node: node(3), Index: 2}) }},
	} {
		if alter(tc.f) == want {
			t.Errorf("changing %s left the digest unchanged", tc.name)
		}
	}

	if base.Digest() != want {
		t.Fatal("Digest is not a pure function of the set")
	}
}
