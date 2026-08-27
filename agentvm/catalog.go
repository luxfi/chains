// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

// catalog.go says WHAT capability exists. It does not say who serves it — which
// providers offer which groups is separate state with a different lifecycle, and
// it lives in scheduler.go. A catalog changes when the API surface changes, which
// is rare and deliberate; an advertisement changes whenever an operator's fleet
// does, which is often. Storing them in one record would tie the two together
// and make the frequent change rewrite the stable one.
//
// A catalog is versioned and content-addressed: the digest is over the whole
// surface, so naming the digest names an exact set of operations. Providers
// advertise the groups they serve AT a digest, and a workload names the digest it
// was written against. A surface that gains a route gets a new version and a new
// digest; nothing in this package changes, and a provider that has not re-
// advertised keeps serving the version it advertised. That is the point of
// storing a digest instead of a route list: 2,253 operations are one 32-byte
// commitment here, and adding the 2,254th is a version bump rather than a code
// change.
//
// The catalog is DERIVED from the API document by cmd/catalog, never transcribed.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// MaxGroups bounds a catalog. The measured surface has a few dozen groups; the
// bound exists so a catalog is a bounded thing to register and to walk.
const MaxGroups = 1024

// Group is one family of operations in the surface — the operations reached under
// one top-level name. Digest is over the group's operation identifiers, so two
// groups with the same name but different contents are different groups.
type Group struct {
	Name   string      `json:"name"`
	Paths  uint32      `json:"paths"`
	Ops    uint32      `json:"ops"`
	Digest common.Hash `json:"digest"`
}

// ID is how a group is named on-chain and in a workload's capability.
func (g Group) ID() common.Hash { return GroupID(g.Name) }

// GroupID derives a group's on-chain name from its textual name.
func GroupID(name string) common.Hash {
	return common.BytesToHash(crypto.Keccak256([]byte(DomainGroup), []byte(name)))
}

// Catalog is a version of the capability surface.
type Catalog struct {
	Version uint32  `json:"version"`
	Groups  []Group `json:"groups"`
}

// Digest is the catalog's identity: a commitment to every group it holds, in the
// order it holds them. Validate requires that order to be sorted by name, so one
// surface has one digest.
func (c Catalog) Digest() common.Hash {
	buf := make([]byte, 0, 64+len(c.Groups)*80)
	buf = append(buf, []byte(DomainCatalog)...)
	buf = append(buf, u32be(c.Version)...)
	buf = append(buf, u32be(uint32(len(c.Groups)))...)
	for _, g := range c.Groups {
		buf = append(buf, blob([]byte(g.Name))...)
		buf = append(buf, u32be(g.Paths)...)
		buf = append(buf, u32be(g.Ops)...)
		buf = append(buf, g.Digest.Bytes()...)
	}
	return common.BytesToHash(crypto.Keccak256(buf))
}

// Paths is how many paths the whole surface holds.
func (c Catalog) Paths() uint32 {
	var n uint32
	for _, g := range c.Groups {
		n += g.Paths
	}
	return n
}

// Ops is how many operations the whole surface holds.
func (c Catalog) Ops() uint32 {
	var n uint32
	for _, g := range c.Groups {
		n += g.Ops
	}
	return n
}

// Group finds a group by name.
func (c Catalog) Group(name string) (Group, bool) {
	for _, g := range c.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

// Validate refuses a catalog that is empty, oversized, unsorted, duplicated, or
// carries a group that names nothing.
func (c Catalog) Validate() error {
	if c.Version == 0 {
		return ErrCatalogVersion
	}
	if len(c.Groups) == 0 || len(c.Groups) > MaxGroups {
		return ErrCatalogGroups
	}
	for i, g := range c.Groups {
		if g.Name == "" || len(g.Name) > MaxName {
			return ErrCatalogGroups
		}
		if g.Ops == 0 || g.Digest == (common.Hash{}) {
			return ErrCatalogGroups
		}
		if i > 0 && c.Groups[i-1].Name >= g.Name {
			return ErrCatalogGroups
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// The catalog on-chain: which versions exist, and what is in them.
// ---------------------------------------------------------------------------

// RegisterCatalog records a catalog version and the groups it holds, and returns
// its digest. A version is written once: re-registering a different surface under
// a number that already means something would change what every workload written
// against that number asked for. A surface that changes gets the next version.
func (e *Engine) RegisterCatalog(st State, c Catalog) (common.Hash, error) {
	if err := c.Validate(); err != nil {
		return common.Hash{}, err
	}
	digest := c.Digest()
	if existing := e.CatalogAt(st, c.Version); existing != (common.Hash{}) {
		if existing != digest {
			return common.Hash{}, ErrCatalogVersionTaken
		}
		return digest, nil
	}
	st.SetState(slotNSIdx(nsCatalogAt, c.Version), digest)
	st.SetState(slotHash(nsCatalog, digest), h32(uint256.NewInt(uint64(c.Version))))
	for _, g := range c.Groups {
		st.SetState(slotHashHash(nsCatalogGroup, digest, g.ID()), g.Digest)
	}
	return digest, nil
}

// CatalogAt returns the digest registered at a version, or zero if that version
// has never been registered.
func (e *Engine) CatalogAt(st State, version uint32) common.Hash {
	return st.GetState(slotNSIdx(nsCatalogAt, version))
}

// CatalogKnown reports whether a catalog digest has been registered.
func (e *Engine) CatalogKnown(st State, digest common.Hash) bool {
	return isSet(st.GetState(slotHash(nsCatalog, digest)))
}

// CatalogHolds reports whether a registered catalog holds a group.
func (e *Engine) CatalogHolds(st State, digest, group common.Hash) bool {
	return isSet(st.GetState(slotHashHash(nsCatalogGroup, digest, group)))
}
