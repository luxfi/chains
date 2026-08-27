// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

// scheduler.go answers one question: which operators may run this workload. It
// does not price anything and it does not pay anyone. Selection and settlement
// are different values with different lifecycles, and settlement stays in
// A-Chain's engine where it already works.
//
// An advertisement is routing state: what an operator can run, where, which
// version of the capability catalog it serves, which groups within it, how much
// work it will hold at once, and which failure domain it sits in. It changes
// whenever a fleet changes, which is why it is kept apart from the catalog, which
// changes when the API surface does.
//
// Three things a node braids together, kept apart here:
//
//	capacity      how much runs at once   a number one operator advertises
//	identity      who is accountable      one address, one bond
//	domain        what fails together     a claim about independence
//
// Capacity is why a many-core machine should be ONE operator with many slots
// rather than one process per core. Running N processes on one box gives N
// addresses and N bonds, and A-Chain's eligible-set margin counts addresses — so
// that shape passes every guard while every replica shares a kernel, a disk and a
// power supply. The bond makes it accountable, not independent.
//
// Domain is what makes duplication mean something. Candidates are grouped by
// domain and exactly one operator per domain enters the draw, so a task drawing N
// operators draws them from N distinct domains, and A-Chain's existing margin then
// applies to DOMAINS rather than to addresses. That is strictly stronger than the
// guard it rides on and it weakens nothing: the address-count check still runs
// underneath, on a pool that now has one entry per domain.
//
// A domain is a CLAIM the operator makes. Nothing here proves two operators are
// independent, and a dishonest operator can put its machines in as many declared
// domains as it likes. What the claim buys is a policy that duplication can be
// written against and a statement the operator's bond is behind. Proving
// independence needs evidence from outside this chain — distinct attestation
// roots, distinct network provenance — and none of that is claimed here.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/aivm"
)

// MaxCapacity bounds what one operator may advertise holding at once.
const MaxCapacity = 4096

// Advertisement is what an operator offers.
type Advertisement struct {
	// Mechanisms is what the operator can actually run.
	Mechanisms Mechanisms `json:"mechanisms"`
	// Storage is the durability the operator provides for what it writes. It is
	// a set of storage properties; naming an execution property here is refused.
	Storage Properties `json:"storage"`
	// Placement is where it runs things.
	Placement Placement `json:"placement"`
	// Domain is the failure domain the operator sits in — a claim, not a proof.
	// Two operators sharing a domain never both enter one draw.
	Domain common.Hash `json:"domain"`
	// Catalog is the capability surface version it serves.
	Catalog common.Hash `json:"catalog"`
	// Groups are the groups within that surface it serves.
	Groups []common.Hash `json:"groups"`
	// Capacity is how many workloads it will hold at once — the parallel slots
	// on its machines. Work spreads across an operator's slots; duplication
	// spreads across domains. They are different questions.
	Capacity uint32 `json:"capacity"`
}

// Advertise records what an operator offers. The operator must already be
// registered and staked on A-Chain — advertising is a statement about a bonded
// identity, so there is nothing to say before the bond exists. The catalog must
// be one the chain knows and must hold every group advertised, so an operator
// cannot offer a group no surface defines.
func (e *Engine) Advertise(st State, op common.Address, ad Advertisement) error {
	if !aivm.Staked(st, op) {
		return ErrOperatorUnknown
	}
	if ad.Mechanisms == 0 {
		return ErrAdvertiseMechanisms
	}
	if !ad.Storage.Wellformed() || ad.Storage&^Storage != 0 {
		return ErrAdvertiseStorage
	}
	if !ad.Placement.Known() || ad.Placement == PlacementAny {
		return ErrAdvertisePlacement
	}
	if ad.Domain == (common.Hash{}) {
		return ErrAdvertiseDomain
	}
	if ad.Capacity == 0 || ad.Capacity > MaxCapacity {
		return ErrAdvertiseCapacity
	}
	if !e.CatalogKnown(st, ad.Catalog) {
		return ErrCatalogUnknown
	}
	if len(ad.Groups) == 0 || len(ad.Groups) > MaxGroups {
		return ErrAdvertiseGroups
	}
	for _, g := range ad.Groups {
		if !e.CatalogHolds(st, ad.Catalog, g) {
			return ErrAdvertiseGroups
		}
	}

	st.SetState(slotAddr(nsAdMech, op), h32(uint256.NewInt(uint64(ad.Mechanisms))))
	st.SetState(slotAddr(nsAdStore, op), h32(uint256.NewInt(uint64(ad.Storage))))
	st.SetState(slotAddr(nsAdPlace, op), h32(uint256.NewInt(uint64(ad.Placement))))
	st.SetState(slotAddr(nsAdDomain, op), ad.Domain)
	st.SetState(slotAddr(nsAdCatalog, op), ad.Catalog)
	st.SetState(slotAddr(nsAdCapacity, op), h32(uint256.NewInt(uint64(ad.Capacity))))
	for _, g := range ad.Groups {
		st.SetState(slotHashAddr(nsAdGroup, g, op), oneHash())
		groups.add(st, g, op)
	}
	return nil
}

// Runs reports whether the operator advertises a mechanism that satisfies the
// execution half of a demand, and storage that satisfies the storage half. One
// predicate, asked of each domain of the demand, because a mechanism has nothing
// to say about where bytes went.
func (e *Engine) Runs(st State, op common.Address, d Properties) bool {
	mech := Mechanisms(readUint(st, slotAddr(nsAdMech, op)).Uint64())
	store := Properties(readUint(st, slotAddr(nsAdStore, op)).Uint64())
	return mech.Serves(d&^Storage) && store.Contains(d&Storage)
}

// PlacedAt reports where the operator runs workloads. PlacementAny means it has
// never advertised.
func (e *Engine) PlacedAt(st State, op common.Address) Placement {
	return Placement(readUint(st, slotAddr(nsAdPlace, op)).Uint64())
}

// DomainOf reports the failure domain an operator declared. Zero means it has
// never advertised one, and such an operator is never a candidate.
func (e *Engine) DomainOf(st State, op common.Address) common.Hash {
	return st.GetState(slotAddr(nsAdDomain, op))
}

// Serves reports whether the operator advertises the capability: the same catalog
// version, and that group within it.
func (e *Engine) Serves(st State, op common.Address, c Capability) bool {
	if st.GetState(slotAddr(nsAdCatalog, op)) != c.Catalog {
		return false
	}
	return isSet(st.GetState(slotHashAddr(nsAdGroup, c.Group, op)))
}

// Capacity reports the parallel slots the operator advertises and how many are
// currently held.
func (e *Engine) Capacity(st State, op common.Address) (advertised, held uint32) {
	advertised = uint32(readUint(st, slotAddr(nsAdCapacity, op)).Uint64())
	held = uint32(readUint(st, slotAddr(nsAdLoad, op)).Uint64())
	return advertised, held
}

// hold and release move an operator's held slots. A slot is occupied for exactly
// as long as the operator owes an answer: taken when a task selects it, given
// back when that task reaches a verdict.
func hold(st State, op common.Address) {
	held := readUint(st, slotAddr(nsAdLoad, op))
	st.SetState(slotAddr(nsAdLoad, op), h32(held.AddUint64(held, 1)))
}

func release(st State, op common.Address) {
	held := readUint(st, slotAddr(nsAdLoad, op))
	if held.IsZero() {
		return
	}
	st.SetState(slotAddr(nsAdLoad, op), h32(held.SubUint64(held, 1)))
}

// Candidates returns the operators that may run this workload, in registry
// insertion order. Reading the group's array and filtering it here is the single
// place "who could serve this" is decided.
func (e *Engine) Candidates(st State, w Workload) []common.Address {
	return groups.all(st, w.Capability.Group, func(op common.Address) bool {
		if !aivm.Staked(st, op) {
			return false
		}
		if !e.Serves(st, op, w.Capability) {
			return false
		}
		if !w.Placement.Admits(e.PlacedAt(st, op)) {
			return false
		}
		if !e.Runs(st, op, w.Demand) {
			return false
		}
		if e.DomainOf(st, op) == (common.Hash{}) {
			return false
		}
		advertised, held := e.Capacity(st, op)
		return held < advertised
	})
}

// Pool reduces the candidates to one operator per declared domain, which is the
// pool a task draws from. Drawing over this rather than over every address is
// what makes duplication mean N independent parties instead of N processes on one
// machine: two candidates in one domain contribute one entry, so a draw of N
// selects N domains.
//
// The domains keep the order their first candidate appeared in, and within a
// domain the representative is chosen by a beacon anchored in the workload id and
// the domain. Both are pure functions of committed state and the workload, so
// every validator builds the identical pool.
func (e *Engine) Pool(st State, w Workload) []common.Address {
	candidates := e.Candidates(st, w)
	order := make([]common.Hash, 0, len(candidates))
	members := make(map[common.Hash][]common.Address, len(candidates))
	for _, op := range candidates {
		d := e.DomainOf(st, op)
		if _, seen := members[d]; !seen {
			order = append(order, d)
		}
		members[d] = append(members[d], op)
	}

	anchor := w.ID()
	pool := make([]common.Address, 0, len(order))
	for _, d := range order {
		group := members[d]
		// One draw over the domain's members: the index is the beacon value
		// reduced modulo the group size, so a domain with one member yields it
		// and a domain with several yields a member nobody can predict before
		// the workload exists.
		pick := new(uint256.Int).SetBytes(crypto.Keccak256(anchor.Bytes(), d.Bytes()))
		idx := new(uint256.Int).Mod(pick, uint256.NewInt(uint64(len(group)))).Uint64()
		pool = append(pool, group[idx])
	}
	return pool
}
