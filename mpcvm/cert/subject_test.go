// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cert

import (
	"reflect"
	"strings"
	"testing"
)

// flip returns a copy of r with the named field's first byte set to v.
// Reflection rather than a hand-written switch: a root added to the struct is
// covered the moment it exists, which is the only way TestSubject_EveryRootIsBound
// can outlive the descriptor it was written against.
func flip(field int, v byte) Roots {
	var r Roots
	reflect.ValueOf(&r).Elem().Field(field).Index(0).SetUint(uint64(v))
	return r
}

// Every field of Roots reaches the subject hash.
//
// A root BindSubject forgets to write is a cross-chain replay hole: two rounds
// that differ only in the forgotten root bind the same certificate_subject, so
// a certificate minted for one round is valid on the other. The M-Chain and
// F-Chain roots are the two that make this concrete — if fchain_fhe_root did
// not reach the hash, an M-Chain certificate would verify against an F-Chain
// round that never happened.
func TestSubject_EveryRootIsBound(t *testing.T) {
	zero := BindSubject(Roots{})
	rt := reflect.TypeOf(Roots{})
	for i := 0; i < rt.NumField(); i++ {
		if BindSubject(flip(i, 1)) == zero {
			t.Errorf("root %s does not reach the subject hash", rt.Field(i).Name)
		}
	}
}

// The roots are distinguishable from one another, not just individually bound.
//
// BindSubject writes ten fixed-width roots back to back with no separators, so
// injectivity rests entirely on position. A copy-paste that wrote ParentBlock
// into StateRoot's slot would still let every root move the hash — the previous
// test would pass — while making the two roots interchangeable: a descriptor
// with the values swapped would bind the same subject.
func TestSubject_RootsAreNotInterchangeable(t *testing.T) {
	rt := reflect.TypeOf(Roots{})
	seen := make(map[[32]byte]string, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		s := BindSubject(flip(i, 0xAB))
		if prior, dup := seen[s]; dup {
			t.Errorf("roots %s and %s bind the same subject: they occupy one slot", prior, name)
		}
		seen[s] = name
	}
}

// BindSubject is a function of the roots alone.
//
// The subject is recomputed independently by every node at cert-ingress time.
// If it carried any hidden input — a clock, a map iteration, an allocation
// address — nodes would disagree on a value consensus treats as canonical.
func TestSubject_BindIsDeterministic(t *testing.T) {
	r := Roots{ParentBlock: [32]byte{1}, MChainCeremony: [32]byte{9}, FChainFHE: [32]byte{10}}
	first := BindSubject(r)
	for i := 0; i < 8; i++ {
		if BindSubject(r) != first {
			t.Fatal("BindSubject returned two different subjects for one descriptor")
		}
	}
}

// VerifySubject accepts the claim its own roots produce and nothing else.
//
// This is the ingress check: a certificate arrives carrying a subject, and the
// node recomputes it from the roots it holds. Accepting a mismatch would let a
// proposer bind a subject to a descriptor it did not derive from.
func TestSubject_VerifyAcceptsOnlyTheDerivedClaim(t *testing.T) {
	r := Roots{
		ParentBlock:    [32]byte{0x11},
		MChainCeremony: [32]byte{0x22},
		FChainFHE:      [32]byte{0x33},
	}
	if err := VerifySubject(BindSubject(r), r); err != nil {
		t.Fatalf("the subject derived from these roots must verify against them: %v", err)
	}

	rt := reflect.TypeOf(Roots{})
	for i := 0; i < rt.NumField(); i++ {
		altered := r
		f := reflect.ValueOf(&altered).Elem().Field(i)
		f.Index(31).SetUint(uint64(f.Index(31).Uint()) ^ 1)
		if err := VerifySubject(BindSubject(r), altered); err == nil {
			t.Errorf("VerifySubject accepted a claim after %s changed", rt.Field(i).Name)
		}
	}

	err := VerifySubject([32]byte{}, r)
	if err == nil || !strings.Contains(err.Error(), "does not match descriptor roots") {
		t.Fatalf("a claimed subject of all zeroes must be refused, got: %v", err)
	}
}

// Each chain root is required on its own.
//
// LP-1340 binds mchain_ceremony_root and fchain_fhe_root on every round, even
// the rounds where one chain finalizes nothing (its unchanged root satisfies
// the binding). A check that only fired when *both* were zero would let a round
// that omits one chain through, and the subject would then attest to a single
// chain while claiming to attest to two.
func TestSubject_RequireBothChainRootsIndependently(t *testing.T) {
	nonzero := [32]byte{0x01}

	if err := (Roots{MChainCeremony: nonzero, FChainFHE: nonzero}).RequireBothChains(); err != nil {
		t.Fatalf("both roots present must be accepted: %v", err)
	}

	for _, tc := range []struct {
		name string
		r    Roots
		want string
	}{
		{"m-chain root missing", Roots{FChainFHE: nonzero}, "mchain_ceremony_root is zero"},
		{"f-chain root missing", Roots{MChainCeremony: nonzero}, "fchain_fhe_root is zero"},
		{"both missing", Roots{}, "mchain_ceremony_root is zero"},
	} {
		err := tc.r.RequireBothChains()
		if err == nil {
			t.Errorf("%s: accepted a descriptor that does not bind both chains", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want an error naming %q, got: %v", tc.name, tc.want, err)
		}
	}
}

// A root that is present but zero-valued elsewhere is not the chain roots'
// business. RequireBothChains guards exactly two fields; the other eight are
// legitimately zero at genesis, and a check that rejected them would stop the
// first round of every network from ever binding a subject.
func TestSubject_RequireBothChainsIgnoresTheOtherRoots(t *testing.T) {
	r := Roots{MChainCeremony: [32]byte{1}, FChainFHE: [32]byte{1}}
	if err := r.RequireBothChains(); err != nil {
		t.Fatalf("eight zero roots beside two present chain roots must be accepted: %v", err)
	}
}
