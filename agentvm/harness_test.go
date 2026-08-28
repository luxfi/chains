// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/aivm"
)

// key is a test operator or payer: a secp256k1 key that signs digests the way an
// operator's own key does in production.
type key struct{ priv *ecdsa.PrivateKey }

func newKey(t *testing.T) key {
	t.Helper()
	priv, err := crypto.GenerateKey()
	require.NoError(t, err)
	return key{priv: priv}
}

func (k key) Sign(digest common.Hash) ([]byte, error) {
	return crypto.Sign(digest.Bytes(), k.priv)
}

// addr is the operator's on-chain identity: the low 20 bytes of the keccak over
// its uncompressed public key, which is exactly what evidence verification
// recovers to.
func (k key) addr() common.Address {
	pub := elliptic.Marshal(k.priv.PublicKey.Curve, k.priv.PublicKey.X, k.priv.PublicKey.Y)
	return common.BytesToAddress(crypto.Keccak256(pub[1:])[12:])
}

func h(b byte) common.Hash {
	var x common.Hash
	x[31] = b
	return x
}

// testCatalog is a small surface with two groups, shaped like the real one.
func testCatalog() Catalog {
	return Catalog{
		Version: 1,
		Groups: []Group{
			{Name: "ai", Paths: 92, Ops: 146, Digest: h(0xA1)},
			{Name: "iam", Paths: 61, Ops: 92, Digest: h(0xA2)},
		},
	}
}

// world is a chain with a registered catalog and a set of staked operators, each
// in its own declared failure domain, all advertising the "ai" group.
type world struct {
	e       *Engine
	st      *aivm.MemState
	lg      *aivm.MemLedger
	cat     common.Hash
	group   common.Hash
	payer   key
	ops     []key
	domains []common.Hash
}

// advertise re-advertises for an operator, signing as that operator and carrying
// a nonce past whatever it last used.
func (w *world) advertise(t *testing.T, op key, nonce uint64, mutate func(*Advertisement)) error {
	t.Helper()
	ad := Advertisement{
		Mechanisms: Offer(MechanismRunc),
		Placement:  PlacementLocal,
		Domain:     w.e.DomainOf(w.st, op.addr()),
		Catalog:    w.cat,
		Groups:     []common.Hash{w.group},
		Capacity:   4,
		Nonce:      nonce,
	}
	if mutate != nil {
		mutate(&ad)
	}
	require.NoError(t, ad.Authorize(op.addr(), op))
	return w.e.Advertise(w.st, op.addr(), ad)
}

// newWorld stakes n operators, each in its own domain. n must leave the pool
// above A-Chain's margin for the duplication a test asks for; nothing here
// relaxes that guard, so a test that stakes too few gets the refusal a real
// network would.
func newWorld(t *testing.T, n int, mechanisms Mechanisms) *world {
	t.Helper()
	core := aivm.NewEngine(h(0xC1), h(0xA0))
	e := New(core)
	st := aivm.NewMemState()

	payer := newKey(t)
	opening := map[common.Address]*uint256.Int{
		payer.addr(): new(uint256.Int).Mul(aivm.MinProviderBond, uint256.NewInt(10_000)),
	}
	ops := make([]key, n)
	for i := range ops {
		ops[i] = newKey(t)
		opening[ops[i].addr()] = new(uint256.Int).Mul(aivm.MinProviderBond, uint256.NewInt(4))
	}
	lg := aivm.NewMemLedger(opening)

	cat, err := e.RegisterCatalog(st, testCatalog())
	require.NoError(t, err)
	group := GroupID("ai")

	domains := make([]common.Hash, n)
	for i, op := range ops {
		stake := new(uint256.Int).Mul(aivm.MinProviderBond, uint256.NewInt(2))
		// A-Chain's registry wants one model specification per operator; for a
		// capability operator that is the group it serves.
		require.NoError(t, core.RegisterOperator(st, lg, op.addr(), stake, group, h(byte(0x80+i))))
		domains[i] = common.BytesToHash(crypto.Keccak256([]byte("domain"), []byte{byte(i)}))
		ad := Advertisement{
			Mechanisms: mechanisms,
			Placement:  PlacementLocal,
			Domain:     domains[i],
			Catalog:    cat,
			Groups:     []common.Hash{group},
			Capacity:   4,
			Nonce:      1,
		}
		require.NoError(t, ad.Authorize(op.addr(), op))
		require.NoError(t, e.Advertise(st, op.addr(), ad))
	}
	return &world{e: e, st: st, lg: lg, cat: cat, group: group, payer: payer, ops: ops, domains: domains}
}

// workload builds an authorised workload against this world.
func (w *world) workload(t *testing.T, demand Properties, dup uint32, nonce byte) Workload {
	t.Helper()
	wl := Workload{
		Code:  Code{Kind: CodeImage, Ref: "oci://run", Digest: h(0x11)},
		Input: Handle{Digest: h(0x22), Size: 512, Bucket: "in", Key: "job"},
		Env:   []Var{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}},
		Resource: Resource{
			CPU: 1000, Memory: 512 << 20, GPU: 0, Timeout: 60_000,
		},
		Demand:      demand,
		Placement:   PlacementLocal,
		Capability:  Capability{Catalog: w.cat, Group: w.group},
		Duplication: dup,
		Payer:       w.payer.addr(),
		Nonce:       h(nonce),
	}
	require.NoError(t, wl.Authorize(w.payer))
	return wl
}

// output is the handle a run produces.
func outputHandle() Handle {
	return Handle{Digest: h(0x33), Size: 256, Bucket: "out", Key: "res"}
}

// receipt builds a signed receipt for an operator, with whatever evidence facts
// the caller wants to present.
func (w *world) receipt(t *testing.T, wl Workload, op key, ev Evidence) Receipt {
	t.Helper()
	r := Receipt{
		Workload: wl.ID(),
		Operator: op.addr(),
		Output:   outputHandle(),
		Exit:     0,
		Consumed: Resource{CPU: 900, Memory: 400 << 20, GPU: 0, Timeout: 5_000},
		Evidence: ev,
	}
	require.NoError(t, r.Evidence.Sign(r.Claim(), r.Output, op))
	return r
}

// runcEvidence is what an operator that ran under runc can honestly show: a
// filter it applied, and a witness naming runc.
func runcEvidence() Evidence {
	return Evidence{
		Witness:   Witness{Serves: MechanismRunc, Digest: h(0x51)},
		Placement: PlacementLocal,
		Filter:    h(0x52),
	}
}

// gvisorEvidence is what an operator that actually ran under gVisor can show: a
// witness naming the sentry it observed from inside the sandbox.
func gvisorEvidence() Evidence {
	return Evidence{
		Witness:   Witness{Serves: MechanismGVisor, Digest: h(0x61)},
		Placement: PlacementLocal,
		Filter:    h(0x62),
	}
}

// firecrackerEvidence is what a microVM run can show: its own kernel and root
// filesystem, and a witness that IS the kernel it declared.
func firecrackerEvidence() Evidence {
	kernel := h(0x71)
	return Evidence{
		Witness:   Witness{Serves: MechanismFirecracker, Digest: kernel},
		Placement: PlacementLocal,
		Filter:    h(0x72),
		Kernel:    kernel,
		Root:      h(0x73),
	}
}
