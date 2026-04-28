// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package types

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

// NodeID identifies a Lux validator. Same definition as the rest of
// luxfi/node — 32 bytes, content-addressed.
type NodeID [32]byte

// Participant is one validator selected (via stake-weighted VRF) into
// the participant set of a ceremony. The substrate does not pick
// participants; the host chain (M-Chain or F-Chain) does, then hands
// the resulting set here.
type Participant struct {
	Node   NodeID
	Index  uint32 // canonical index inside the ParticipantSet (0..n-1)
	Weight uint64 // stake weight at selection time, for accounting only
}

// ParticipantSet is the deterministic, ordered set of validators for
// one ceremony. The set is fixed at registration; resharing is a new
// ceremony with a new set, never an in-place mutation.
type ParticipantSet struct {
	CeremonyID CeremonyID
	Members    []Participant // sorted ascending by NodeID; Index == position
}

// NewParticipantSet builds a ParticipantSet, sorting members by NodeID
// and assigning Index = position. Returns an error if the input has
// duplicate nodes or is empty.
func NewParticipantSet(ceremonyID CeremonyID, members []Participant) (*ParticipantSet, error) {
	if len(members) == 0 {
		return nil, errors.New("participant: empty set")
	}
	out := make([]Participant, len(members))
	copy(out, members)
	sort.Slice(out, func(i, j int) bool {
		for k := 0; k < len(out[i].Node); k++ {
			if out[i].Node[k] != out[j].Node[k] {
				return out[i].Node[k] < out[j].Node[k]
			}
		}
		return false
	})
	for i := 1; i < len(out); i++ {
		if out[i-1].Node == out[i].Node {
			return nil, errors.New("participant: duplicate node in set")
		}
	}
	for i := range out {
		out[i].Index = uint32(i)
	}
	return &ParticipantSet{CeremonyID: ceremonyID, Members: out}, nil
}

// Lookup returns the participant for a node, or false if absent.
func (ps *ParticipantSet) Lookup(node NodeID) (Participant, bool) {
	for _, p := range ps.Members {
		if p.Node == node {
			return p, true
		}
	}
	return Participant{}, false
}

// Digest returns the canonical 32-byte digest of the set. Used as the
// participant_root when a ceremony is registered, and as input to the
// stake-weighted VRF for the next ceremony.
func (ps *ParticipantSet) Digest() [32]byte {
	h := sha256.New()
	h.Write(ps.CeremonyID[:])
	var buf [12]byte
	for _, m := range ps.Members {
		h.Write(m.Node[:])
		binary.BigEndian.PutUint32(buf[0:4], m.Index)
		binary.BigEndian.PutUint64(buf[4:12], m.Weight)
		h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Selector is implemented by the host chain (M-Chain or F-Chain). The
// substrate consumes a Selector to produce a ParticipantSet at
// ceremony registration time.
//
// Selectors must be:
//
//   - deterministic: same input -> same output, byte for byte
//   - permissionless: any validator with stake delegated to the chain
//     is eligible (no allowlist)
//   - stake-weighted: probability of selection is proportional to
//     stake delegated to the chain at the cutoff epoch
//
// The substrate does not implement Selector; M-Chain and F-Chain each
// provide one wired to their stake delegation.
type Selector interface {
	Select(ceremonyID CeremonyID, total uint16, seed [32]byte) (*ParticipantSet, error)
}
