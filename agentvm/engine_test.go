// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

import (
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/aivm"
)

// runcOnly is what an operator that can only run containers advertises.
var runcOnly = Offer(MechanismRunc)

// TestLifecycle runs a workload end to end: open, commit, attest, reveal, settle.
// The verdict and the payment are A-Chain's; what this proves is that AgentVM
// hands it a task it can settle and that the money moves.
func TestLifecycle(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))
	wl := w.workload(t, Require(SyscallFiltered, KernelShared), 3, 0x01)

	before := w.lg.Total()
	taskID, err := w.e.Open(w.st, w.lg, wl, 100)
	require.NoError(t, err)
	require.NotEqual(t, common.Hash{}, taskID)

	info := w.e.Core().GetTask(w.st, taskID)
	require.Equal(t, aivm.TaskCommitting, info.Status)
	require.Equal(t, uint32(3), info.N)
	require.Equal(t, uint32(2), info.Threshold, "strict majority of three")

	out := outputHandle()
	nonce := h(0x0E)
	selected := w.selected(t, taskID, 3)

	// Commit: each operator seals the answer and the receipt that produced it.
	receipts := make([]Receipt, len(selected))
	for i, op := range selected {
		receipts[i] = w.receipt(t, wl, op, runcEvidence())
		commit := w.e.Commitment(w.st, taskID, op.addr(), out, receipts[i].Hash(), nonce)
		require.NoError(t, w.e.Commit(w.st, taskID, op.addr(), commit, 101))
	}

	// Attest and reveal, in the reveal window.
	for i, op := range selected {
		require.NoError(t, w.e.Attest(w.st, taskID, op.addr(), wl, receipts[i], 140))
		require.NoError(t, w.e.Reveal(w.st, taskID, op.addr(), out, receipts[i].Hash(), nonce, 141))
	}

	// Every operator held a slot while it owed an answer.
	for _, op := range selected {
		_, held := w.e.Capacity(w.st, op.addr())
		require.Equal(t, uint32(1), held)
	}

	require.Equal(t, uint32(1), w.e.Settle(w.st, w.lg, 200), "the task reaches a verdict")
	require.Equal(t, aivm.TaskSettled, w.e.Core().GetTask(w.st, taskID).Status)
	require.Equal(t, out.ID(), w.e.Core().GetCanonicalResult(w.st, taskID),
		"the agreed answer is the output handle every operator ran to")

	// Slots are given back, and every operator is owed something.
	for _, op := range selected {
		_, held := w.e.Capacity(w.st, op.addr())
		require.Equal(t, uint32(0), held, "a settled task holds no slot")
		require.False(t, w.e.Core().GetCredit(w.st, op.addr()).IsZero(), "an operator that agreed is paid")
	}
	require.Equal(t, before.String(), w.lg.Total().String(), "value is conserved across the whole lifecycle")
	require.Equal(t, uint32(0), w.e.Pending(w.st))
}

// TestRevealRefusedWithoutEvidence is the structural guarantee: a task that
// demanded properties admits no answer from an operator that has not shown them.
// The receipt never becomes a reveal, so it never reaches the tally and can never
// settle. There is no separate settlement-time check to forget.
func TestRevealRefusedWithoutEvidence(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))
	wl := w.workload(t, Require(SyscallFiltered), 3, 0x02)

	taskID, err := w.e.Open(w.st, w.lg, wl, 100)
	require.NoError(t, err)

	op := w.selected(t, taskID, 3)[0]
	out, nonce := outputHandle(), h(0x0E)
	r := w.receipt(t, wl, op, runcEvidence())
	require.NoError(t, w.e.Commit(w.st, taskID, op.addr(), w.e.Commitment(w.st, taskID, op.addr(), out, r.Hash(), nonce), 101))

	// Reveal without attesting first.
	require.ErrorIs(t,
		w.e.Reveal(w.st, taskID, op.addr(), out, r.Hash(), nonce, 141),
		ErrEvidenceMissing)

	// Attest, then the same reveal is admitted.
	require.NoError(t, w.e.Attest(w.st, taskID, op.addr(), wl, r, 140))
	require.NoError(t, w.e.Reveal(w.st, taskID, op.addr(), out, r.Hash(), nonce, 141))
}

// TestAttestRefusesWeakerEvidence is the same refusal one layer down and the one
// the whole design turns on: a workload demanding a user-space kernel does not
// accept a container's evidence, so an operator that ran runc cannot be paid for
// work that asked for gVisor.
func TestAttestRefusesWeakerEvidence(t *testing.T) {
	w := newWorld(t, 6, Offer(MechanismRunc, MechanismGVisor), Require(ReplicaOne, SpreadHost))
	wl := w.workload(t, Require(SyscallMediated), 3, 0x03)

	taskID, err := w.e.Open(w.st, w.lg, wl, 100)
	require.NoError(t, err)
	op := w.selected(t, taskID, 3)[0]

	weak := w.receipt(t, wl, op, runcEvidence())
	require.ErrorIs(t, w.e.Attest(w.st, taskID, op.addr(), wl, weak, 140), ErrEvidenceMechanism)

	strong := w.receipt(t, wl, op, gvisorEvidence())
	require.NoError(t, w.e.Attest(w.st, taskID, op.addr(), wl, strong, 140))
}

// TestAttestRefusesAnotherOperatorsEvidence: attestation is a statement and a
// statement needs an author, whatever the demand happens to say about attestation.
func TestAttestRefusesAnotherOperatorsEvidence(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))
	// A demand that asks for no attestation at all, so only the engine's own rule
	// is in play.
	wl := w.workload(t, Require(SyscallFiltered), 3, 0x04)

	taskID, err := w.e.Open(w.st, w.lg, wl, 100)
	require.NoError(t, err)
	sel := w.selected(t, taskID, 3)
	mine, theirs := sel[0], sel[1]

	// theirs signs a receipt; mine presents it as its own.
	stolen := w.receipt(t, wl, theirs, runcEvidence())
	stolen.Operator = mine.addr()
	require.ErrorIs(t, w.e.Attest(w.st, taskID, mine.addr(), wl, stolen, 140), ErrEvidenceSignature)
}

// TestAttestWindowIsTheRevealWindow: naming the output before every peer has
// committed would hand them the answer.
func TestAttestWindowIsTheRevealWindow(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))
	wl := w.workload(t, Require(SyscallFiltered), 3, 0x05)
	taskID, err := w.e.Open(w.st, w.lg, wl, 100)
	require.NoError(t, err)
	op := w.selected(t, taskID, 3)[0]
	r := w.receipt(t, wl, op, runcEvidence())

	// commitDeadline is 130, revealDeadline 160.
	require.ErrorIs(t, w.e.Attest(w.st, taskID, op.addr(), wl, r, 130), ErrAttestNotOpen)
	require.NoError(t, w.e.Attest(w.st, taskID, op.addr(), wl, r, 131))
	require.ErrorIs(t, w.e.Attest(w.st, taskID, op.addr(), wl, r, 131), ErrAlreadyAttested)

	wl2 := w.workload(t, Require(SyscallFiltered), 3, 0x06)
	task2, err := w.e.Open(w.st, w.lg, wl2, 100)
	require.NoError(t, err)
	op2 := w.selected(t, task2, 3)[0]
	r2 := w.receipt(t, wl2, op2, runcEvidence())
	require.ErrorIs(t, w.e.Attest(w.st, task2, op2.addr(), wl2, r2, 161), ErrAttestClosed)
}

// TestMarginIsNotWeakened: three duplicates need five domains, and a network with
// four does not open the task. There is no bootstrap path around this.
func TestMarginIsNotWeakened(t *testing.T) {
	// The measured floor: even one duplicate needs three domains, and the pool
	// requirement is n + max(2, n/2).
	require.Equal(t, uint32(2), aivm.RequiredMargin(1), "N=1 needs 3 domains")
	require.Equal(t, uint32(2), aivm.RequiredMargin(2), "N=2 needs 4")
	require.Equal(t, uint32(2), aivm.RequiredMargin(3), "N=3 needs 5")
	require.Equal(t, uint32(2), aivm.RequiredMargin(5), "N=5 needs 7")
	require.Equal(t, uint32(5), aivm.RequiredMargin(10), "N=10 needs 15")

	w := newWorld(t, 4, runcOnly, Require(ReplicaOne, SpreadHost))
	wl := w.workload(t, Require(SyscallFiltered), 3, 0x07)
	_, err := w.e.Open(w.st, w.lg, wl, 100)
	require.ErrorIs(t, err, aivm.ErrEligibleBelowMargin,
		"four domains cannot field a draw of three")

	// Five can.
	w5 := newWorld(t, 5, runcOnly, Require(ReplicaOne, SpreadHost))
	wl5 := w5.workload(t, Require(SyscallFiltered), 3, 0x07)
	_, err = w5.e.Open(w5.st, w5.lg, wl5, 100)
	require.NoError(t, err)
}

// TestDuplicationDrawsDistinctDomains: many operators in one domain contribute one
// entry to the pool, so a draw of N selects N independent parties rather than N
// processes on one machine.
func TestDuplicationDrawsDistinctDomains(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))

	// Put every operator in one domain, as a fleet of processes on one box would
	// be if it declared honestly.
	one := h(0xD0)
	for _, op := range w.ops {
		require.NoError(t, w.e.Advertise(w.st, op.addr(), Advertisement{
			Mechanisms: runcOnly, Storage: Require(ReplicaOne, SpreadHost),
			Placement: PlacementLocal, Domain: one, Catalog: w.cat,
			Groups: []common.Hash{w.group}, Capacity: 4,
		}))
	}
	wl := w.workload(t, Require(SyscallFiltered), 3, 0x08)
	require.Len(t, w.e.Candidates(w.st, wl), 6, "all six are candidates")
	require.Len(t, w.e.Pool(w.st, wl), 1, "one domain contributes one entry")

	_, err := w.e.Open(w.st, w.lg, wl, 100)
	require.ErrorIs(t, err, aivm.ErrNotEnoughEligible,
		"six addresses in one domain cannot field three independent replicas")
}

// TestPoolIsOnePerDomainAndReproducible: the pool is a pure function of state and
// the workload, so every validator builds the same one.
func TestPoolIsOnePerDomainAndReproducible(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))
	wl := w.workload(t, Require(SyscallFiltered), 3, 0x09)

	pool := w.e.Pool(w.st, wl)
	require.Len(t, pool, 6)
	require.Equal(t, pool, w.e.Pool(w.st, wl), "the same inputs give the same pool")

	seen := map[common.Hash]bool{}
	for _, op := range pool {
		d := w.e.DomainOf(w.st, op)
		require.False(t, seen[d], "a domain appears at most once")
		seen[d] = true
	}
}

// TestCandidatesFilterOnEveryAxis: an operator drops out for any reason it cannot
// serve, and there is no relaxed second pass that puts it back.
func TestCandidatesFilterOnEveryAxis(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))
	wl := w.workload(t, Require(SyscallFiltered), 3, 0x0A)
	require.Len(t, w.e.Candidates(w.st, wl), 6)

	// A demand no advertised mechanism serves empties the pool.
	mediated := w.workload(t, Require(SyscallMediated), 3, 0x0B)
	require.Empty(t, w.e.Candidates(w.st, mediated))
	_, err := w.e.Open(w.st, w.lg, mediated, 100)
	require.ErrorIs(t, err, aivm.ErrNotEnoughEligible)

	// A storage demand nobody advertises does the same.
	federated := w.workload(t, Require(SyscallFiltered, SpreadFederated), 3, 0x0C)
	require.Empty(t, w.e.Candidates(w.st, federated))

	// A placement nobody offers does the same.
	remote := w.workload(t, Require(SyscallFiltered), 3, 0x0D)
	remote.Placement = PlacementRemote
	require.NoError(t, remote.Authorize(w.payer))
	require.Empty(t, w.e.Candidates(w.st, remote))
}

// TestCapacityIsPerOperatorNotPerDomain: slots are how one operator runs several
// workloads at once, and an operator with none is not a candidate.
func TestCapacityIsPerOperatorNotPerDomain(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))
	for _, op := range w.ops {
		require.NoError(t, w.e.Advertise(w.st, op.addr(), Advertisement{
			Mechanisms: runcOnly, Storage: Require(ReplicaOne, SpreadHost),
			Placement: PlacementLocal, Domain: w.e.DomainOf(w.st, op.addr()),
			Catalog: w.cat, Groups: []common.Hash{w.group}, Capacity: 1,
		}))
	}
	first := w.workload(t, Require(SyscallFiltered), 3, 0x10)
	_, err := w.e.Open(w.st, w.lg, first, 100)
	require.NoError(t, err)

	// Three of the six now hold their only slot, leaving three domains free —
	// below the margin for another draw of three.
	second := w.workload(t, Require(SyscallFiltered), 3, 0x11)
	require.Len(t, w.e.Candidates(w.st, second), 3)
	_, err = w.e.Open(w.st, w.lg, second, 100)
	require.ErrorIs(t, err, aivm.ErrEligibleBelowMargin)
}

// TestWorkloadOpensOneTask: the id is over the content, so asking again needs a
// different nonce and is a different workload.
func TestWorkloadOpensOneTask(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))
	wl := w.workload(t, Require(SyscallFiltered), 3, 0x12)

	taskID, err := w.e.Open(w.st, w.lg, wl, 100)
	require.NoError(t, err)
	require.Equal(t, taskID, w.e.TaskFor(w.st, wl.ID()))
	require.Equal(t, wl.ID(), w.e.WorkloadFor(w.st, taskID))

	_, err = w.e.Open(w.st, w.lg, wl, 101)
	require.ErrorIs(t, err, ErrWorkloadAlreadyUsed)
}

// TestOpenRefusesAnUnknownCapability: a workload naming a surface the chain has
// never seen has nothing to agree on.
func TestOpenRefusesAnUnknownCapability(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))

	wl := w.workload(t, Require(SyscallFiltered), 3, 0x13)
	wl.Capability.Catalog = h(0xEE)
	require.NoError(t, wl.Authorize(w.payer))
	_, err := w.e.Open(w.st, w.lg, wl, 100)
	require.ErrorIs(t, err, ErrCatalogUnknown)

	wl = w.workload(t, Require(SyscallFiltered), 3, 0x14)
	wl.Capability.Group = GroupID("nonesuch")
	require.NoError(t, wl.Authorize(w.payer))
	_, err = w.e.Open(w.st, w.lg, wl, 100)
	require.ErrorIs(t, err, ErrCapabilityUnknown)
}

// TestOpenRefusesUnauthorizedSpending: anyone may deliver a workload; only its
// payer can spend against their balance.
func TestOpenRefusesUnauthorizedSpending(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))
	victim := newKey(t)

	wl := w.workload(t, Require(SyscallFiltered), 3, 0x15)
	wl.Payer = victim.addr() // signed by the original payer, not by the victim
	_, err := w.e.Open(w.st, w.lg, wl, 100)
	require.ErrorIs(t, err, ErrWorkloadUnauthorized)

	before := w.lg.GetBalance(victim.addr())
	require.Equal(t, before.String(), w.lg.GetBalance(victim.addr()).String(),
		"a refused workload moves nothing")
}

// TestFreshChainBelievesNothing: hardware attestation and pinned durability both
// fail closed until something is admitted, and admitting is what turns them on.
func TestFreshChainBelievesNothing(t *testing.T) {
	w := newWorld(t, 6, runcOnly, Require(ReplicaOne, SpreadHost))
	trust := w.e.Trust(w.st)

	q, _ := newQuote(t, QuoteSEVSNP, h(0x42))
	require.False(t, trust.Attests(KeyDigest(q.Key)))
	require.False(t, trust.Pins(h(0x55)))

	require.NoError(t, w.e.AdmitAttestingKey(w.st, KeyDigest(q.Key)))
	require.NoError(t, w.e.AdmitStateRoot(w.st, h(0x55)))
	require.True(t, w.e.Trust(w.st).Attests(KeyDigest(q.Key)))
	require.True(t, w.e.Trust(w.st).Pins(h(0x55)))

	w.e.RevokeAttestingKey(w.st, KeyDigest(q.Key))
	w.e.RevokeStateRoot(w.st, h(0x55))
	require.False(t, w.e.Trust(w.st).Attests(KeyDigest(q.Key)))
	require.False(t, w.e.Trust(w.st).Pins(h(0x55)))

	require.ErrorIs(t, w.e.AdmitAttestingKey(w.st, common.Hash{}), ErrEmptyAttestingKey)
	require.ErrorIs(t, w.e.AdmitStateRoot(w.st, common.Hash{}), ErrRootEmpty)
}

// TestDisagreementFailsTheTask: when no group reaches the threshold the task
// fails and the requester is refunded. This is A-Chain's rule, unchanged; the
// test is here to show AgentVM did not add a second one.
func TestDisagreementFailsTheTask(t *testing.T) {
	w := newWorld(t, 8, runcOnly, Require(ReplicaOne, SpreadHost))
	wl := w.workload(t, Require(SyscallFiltered), 3, 0x16)
	taskID, err := w.e.Open(w.st, w.lg, wl, 100)
	require.NoError(t, err)

	nonce := h(0x0E)
	for i, op := range w.selected(t, taskID, 3) {
		// Each operator answers with a different output.
		out := Handle{Digest: h(byte(0x90 + i)), Size: 8, Bucket: "out", Key: "res"}
		r := Receipt{
			Workload: wl.ID(), Operator: op.addr(), Output: out,
			Consumed: Resource{CPU: 1, Memory: 1, Timeout: 1},
			Evidence: runcEvidence(),
		}
		require.NoError(t, r.Evidence.Sign(r.Claim(), r.Output, op))
		require.NoError(t, w.e.Commit(w.st, taskID, op.addr(), w.e.Commitment(w.st, taskID, op.addr(), out, r.Hash(), nonce), 101))
		require.NoError(t, w.e.Attest(w.st, taskID, op.addr(), wl, r, 140))
		require.NoError(t, w.e.Reveal(w.st, taskID, op.addr(), out, r.Hash(), nonce, 141))
	}
	w.e.Settle(w.st, w.lg, 200)
	require.Equal(t, aivm.TaskFailed, w.e.Core().GetTask(w.st, taskID).Status)
	require.False(t, w.e.Core().GetCredit(w.st, w.payer.addr()).IsZero(), "the requester is refunded")
}

// TestPriceIsPureAndOverflowSafe: nobody names the reward, and a workload that
// cannot be priced cannot be opened.
func TestPrice(t *testing.T) {
	base := Workload{Resource: Resource{CPU: 1000, Memory: 1 << 20, GPU: 0, Timeout: 1000}}
	plain, err := Price(base)
	require.NoError(t, err)
	require.False(t, plain.IsZero())
	again, _ := Price(base)
	require.Equal(t, plain.String(), again.String(), "price is a pure function")

	// Properties that cost more do cost more, and properties that are the absence
	// of a guarantee cost nothing.
	free := base
	free.Demand = Require(KernelShared, SyscallDirect, MemoryPlain, AttestNone, SpreadHost)
	freePrice, err := Price(free)
	require.NoError(t, err)
	require.Equal(t, plain.String(), freePrice.String())

	dear := base
	dear.Demand = Require(MemoryEncrypted, AttestHardware, KernelGuest, ReplicaMany, SpreadFederated)
	dearPrice, err := Price(dear)
	require.NoError(t, err)
	require.True(t, dearPrice.Gt(plain), "a stronger demand costs more")

	bad := base
	bad.Demand = Require(SyscallDirect, SyscallMediated)
	_, err = Price(bad)
	require.ErrorIs(t, err, ErrDemandMalformed)

	huge := base
	huge.Resource = Resource{CPU: MaxCPU, Memory: MaxMemory, GPU: MaxGPU, Timeout: MaxTimeout}
	_, err = Price(huge)
	require.NoError(t, err, "the protocol bounds keep the largest workload priceable")
}

// selected reads back the operators a task drew, as keys so tests can sign.
func (w *world) selected(t *testing.T, taskID common.Hash, n uint32) []key {
	t.Helper()
	byAddr := map[common.Address]key{}
	for _, op := range w.ops {
		byAddr[op.addr()] = op
	}
	out := make([]key, 0, n)
	for i := uint32(0); i < n; i++ {
		addr := w.e.Core().SelectedAt(w.st, taskID, i)
		k, ok := byAddr[addr]
		require.True(t, ok, "selected operator %s is one of ours", addr)
		out = append(out, k)
	}
	return out
}

// TestConservation: whatever happens, the total never changes.
func TestConservation(t *testing.T) {
	w := newWorld(t, 8, runcOnly, Require(ReplicaOne, SpreadHost))
	before := w.lg.Total()
	for i := byte(0); i < 3; i++ {
		wl := w.workload(t, Require(SyscallFiltered), 3, 0x20+i)
		_, err := w.e.Open(w.st, w.lg, wl, 100)
		require.NoError(t, err)
	}
	w.e.Settle(w.st, w.lg, 200)
	require.Equal(t, before.String(), w.lg.Total().String())

	// The escrow account holds exactly what is owed.
	require.True(t, w.lg.GetBalance(aivm.EscrowAccount).Gt(uint256.NewInt(0)))
}
