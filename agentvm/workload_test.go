// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// sample is a valid workload the tests vary one field of at a time.
func sample() Workload {
	return Workload{
		Code:        Code{Kind: CodeImage, Ref: "oci://run", Digest: h(0x11), Args: []string{"-x", "1"}},
		Input:       Handle{Digest: h(0x22), Size: 512, Bucket: "in", Key: "job"},
		Env:         []Var{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}},
		Resource:    Resource{CPU: 1000, Memory: 1 << 20, Timeout: 1000},
		Demand:      Require(SyscallFiltered),
		Placement:   PlacementLocal,
		Capability:  Capability{Catalog: h(0xC0), Group: GroupID("ai")},
		Duplication: 3,
		Payer:       common.HexToAddress("0x01"),
		Nonce:       h(0x99),
	}
}

// TestWorkloadIsContentAddressed: the id is over everything that changes what
// running it means, so the same workload has the same id everywhere and any edit
// is a different workload.
func TestWorkloadIsContentAddressed(t *testing.T) {
	base := sample()
	require.Equal(t, base.ID(), sample().ID())

	edits := map[string]func(Workload) Workload{
		"code kind":   func(w Workload) Workload { w.Code.Kind = CodeModule; return w },
		"code digest": func(w Workload) Workload { w.Code.Digest = h(0x12); return w },
		"code ref":    func(w Workload) Workload { w.Code.Ref = "oci://other"; return w },
		"args":        func(w Workload) Workload { w.Code.Args = []string{"-x", "2"}; return w },
		"arg order":   func(w Workload) Workload { w.Code.Args = []string{"1", "-x"}; return w },
		"input":       func(w Workload) Workload { w.Input.Digest = h(0x23); return w },
		"env value":   func(w Workload) Workload { w.Env[1].Value = "3"; return w },
		"cpu":         func(w Workload) Workload { w.Resource.CPU = 2000; return w },
		"memory":      func(w Workload) Workload { w.Resource.Memory = 2 << 20; return w },
		"gpu":         func(w Workload) Workload { w.Resource.GPU = 1; return w },
		"timeout":     func(w Workload) Workload { w.Resource.Timeout = 2000; return w },
		"demand":      func(w Workload) Workload { w.Demand = Require(SyscallMediated); return w },
		"placement":   func(w Workload) Workload { w.Placement = PlacementCluster; return w },
		"catalog":     func(w Workload) Workload { w.Capability.Catalog = h(0xC1); return w },
		"group":       func(w Workload) Workload { w.Capability.Group = GroupID("iam"); return w },
		"duplication": func(w Workload) Workload { w.Duplication = 5; return w },
		"payer":       func(w Workload) Workload { w.Payer = common.HexToAddress("0x02"); return w },
		"nonce":       func(w Workload) Workload { w.Nonce = h(0x9A); return w },
	}
	for name, edit := range edits {
		altered := edit(sample())
		require.NotEqual(t, base.ID(), altered.ID(), "changing the %s changes the workload", name)
	}

	// The signature is not part of the identity: signing a workload names that
	// workload rather than creating a new one.
	signed := sample()
	k := keyFor(t)
	require.NoError(t, signed.Authorize(k))
	require.Equal(t, base.ID(), signed.ID())
}

// TestEnvLengthFramingCannotAlias: two environments whose bytes would concatenate
// identically must still be different workloads.
func TestEnvLengthFramingCannotAlias(t *testing.T) {
	a, b := sample(), sample()
	a.Env = []Var{{Name: "AB", Value: "C"}}
	b.Env = []Var{{Name: "A", Value: "BC"}}
	require.NotEqual(t, a.ID(), b.ID())
}

// TestEnvMustArriveSortedAndUnique: sorting it here would silently accept two
// spellings of one workload, and a duplicate name has no single meaning to
// normalise to.
func TestEnvMustArriveSortedAndUnique(t *testing.T) {
	unsorted := sample()
	unsorted.Env = []Var{{Name: "B", Value: "2"}, {Name: "A", Value: "1"}}
	require.ErrorIs(t, unsorted.Validate(), ErrWorkloadEnv)

	duplicate := sample()
	duplicate.Env = []Var{{Name: "A", Value: "1"}, {Name: "A", Value: "2"}}
	require.ErrorIs(t, duplicate.Validate(), ErrWorkloadEnv)

	empty := sample()
	empty.Env = []Var{{Name: "", Value: "1"}}
	require.ErrorIs(t, empty.Validate(), ErrWorkloadEnv)
}

// TestAuthorizationNamesOneWorkload: a signature is over the id, so it authorises
// exactly that workload and altering any field invalidates it.
func TestAuthorizationNamesOneWorkload(t *testing.T) {
	k := keyFor(t)
	w := sample()
	w.Payer = k.addr()
	require.NoError(t, w.Authorize(k))
	require.NoError(t, w.Authorized())

	altered := w
	altered.Resource.CPU = 2000
	require.ErrorIs(t, altered.Authorized(), ErrWorkloadUnauthorized)

	// Claiming somebody else pays does not carry the signature to them.
	stolen := w
	stolen.Payer = common.HexToAddress("0xdead")
	require.ErrorIs(t, stolen.Authorized(), ErrWorkloadUnauthorized)

	unsigned := sample()
	unsigned.Signature = nil
	require.ErrorIs(t, unsigned.Authorized(), ErrWorkloadUnauthorized)
}

// TestValidateRefusesEveryMalformedShape.
func TestValidateRefusesEveryMalformedShape(t *testing.T) {
	k := keyFor(t)
	// ok signs the workload as its payer, leaving a deliberately absent payer
	// absent so that case reaches the check it is testing.
	ok := func(w Workload) Workload {
		if w.Payer != (common.Address{}) {
			w.Payer = k.addr()
		}
		_ = w.Authorize(k)
		return w
	}
	require.NoError(t, ok(sample()).Validate())

	cases := map[string]struct {
		mangle func(Workload) Workload
		want   error
	}{
		"unknown code kind": {func(w Workload) Workload { w.Code.Kind = CodeKind(9); return w }, ErrWorkloadCode},
		"no code digest":    {func(w Workload) Workload { w.Code.Digest = common.Hash{}; return w }, ErrWorkloadCode},
		"too many args":     {func(w Workload) Workload { w.Code.Args = make([]string, MaxArgs+1); return w }, ErrWorkloadCode},
		"no input":          {func(w Workload) Workload { w.Input = Handle{}; return w }, ErrHandleEmpty},
		"zero cpu":          {func(w Workload) Workload { w.Resource.CPU = 0; return w }, ErrWorkloadResource},
		"huge cpu":          {func(w Workload) Workload { w.Resource.CPU = MaxCPU + 1; return w }, ErrWorkloadResource},
		"zero memory":       {func(w Workload) Workload { w.Resource.Memory = 0; return w }, ErrWorkloadResource},
		"huge gpu":          {func(w Workload) Workload { w.Resource.GPU = MaxGPU + 1; return w }, ErrWorkloadResource},
		"zero timeout":      {func(w Workload) Workload { w.Resource.Timeout = 0; return w }, ErrWorkloadResource},
		"huge timeout":      {func(w Workload) Workload { w.Resource.Timeout = MaxTimeout + 1; return w }, ErrWorkloadResource},
		"two on one axis":   {func(w Workload) Workload { w.Demand = Require(SyscallDirect, SyscallMediated); return w }, ErrDemandMalformed},
		"unknown placement": {func(w Workload) Workload { w.Placement = Placement(9); return w }, ErrWorkloadPlacement},
		"no capability":     {func(w Workload) Workload { w.Capability = Capability{}; return w }, ErrWorkloadCapability},
		"too few copies":    {func(w Workload) Workload { w.Duplication = MinDuplication - 1; return w }, ErrWorkloadDuplication},
		"too many copies":   {func(w Workload) Workload { w.Duplication = MaxDuplication + 1; return w }, ErrWorkloadDuplication},
		"no payer":          {func(w Workload) Workload { w.Payer = common.Address{}; return w }, ErrWorkloadUnauthorized},
	}
	for name, c := range cases {
		w := ok(c.mangle(sample()))
		require.ErrorIs(t, w.Validate(), c.want, name)
	}
}

// TestThresholdIsAStrictMajority: agreement is derived from duplication, so a
// workload cannot ask for copies and then accept a minority of them.
func TestThresholdIsAStrictMajority(t *testing.T) {
	for dup, want := range map[uint32]uint32{3: 2, 4: 3, 5: 3, 8: 5, 256: 129} {
		w := sample()
		w.Duplication = dup
		require.Equal(t, want, w.Threshold(), "duplication %d", dup)
	}
}

// TestResourceWithin: a run that used more than it asked for did not stay inside
// its limits, whichever limit it exceeded.
func TestResourceWithin(t *testing.T) {
	ask := Resource{CPU: 100, Memory: 200, GPU: 1, Timeout: 300}
	require.True(t, ask.Within(ask))
	require.True(t, Resource{}.Within(ask))
	require.False(t, Resource{CPU: 101}.Within(ask))
	require.False(t, Resource{Memory: 201}.Within(ask))
	require.False(t, Resource{GPU: 2}.Within(ask))
	require.False(t, Resource{Timeout: 301}.Within(ask))
}

// TestReceiptCheckRefusesAnOverrun: a receipt claiming more than the workload
// reserved is refused, so pricing the ask prices a real ceiling.
func TestReceiptCheckRefusesAnOverrun(t *testing.T) {
	k := keyFor(t)
	w := sample()
	w.Payer = k.addr()
	require.NoError(t, w.Authorize(k))

	out := outputHandle()
	r := Receipt{
		Workload: w.ID(), Operator: k.addr(), Output: out,
		Consumed: Resource{CPU: w.Resource.CPU + 1},
		Evidence: runcEvidence(),
	}
	require.NoError(t, r.Evidence.Sign(r.Claim(), out, k))
	require.ErrorIs(t, r.Check(w, Require(SyscallFiltered), yes{}), ErrReceiptResource)

	// A receipt for a different workload, and one with no output.
	other := sample()
	other.Nonce = h(0x9B)
	require.ErrorIs(t, r.Check(other, 0, yes{}), ErrReceiptWorkload)

	r.Consumed = Resource{}
	r.Output = Handle{}
	require.ErrorIs(t, r.Check(w, 0, yes{}), ErrReceiptOutput)
}

func keyFor(t *testing.T) key {
	t.Helper()
	return newKey(t)
}
