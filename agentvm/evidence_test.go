// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// yes admits everything. It exists so a test can isolate the property check from
// the question of what the chain has admitted; every test that cares about
// admission uses the real state-backed Trust instead.
type yes struct{}

func (yes) Attests(common.Hash) bool { return true }
func (yes) Pins(common.Hash) bool    { return true }

// no admits nothing, which is a fresh chain.
type no struct{}

func (no) Attests(common.Hash) bool { return false }
func (no) Pins(common.Hash) bool    { return false }

// TestGrantsTableIsTheOnlyAuthority reads the table back and asserts the two rows
// an ordering would have had to lie about: gvisor and firecracker each hold a
// property the other lacks, so neither contains the other.
func TestGrantsTableIsTheOnlyAuthority(t *testing.T) {
	g := Grants(MechanismGVisor)
	f := Grants(MechanismFirecracker)

	require.True(t, g.Has(SyscallMediated), "gvisor mediates syscalls")
	require.False(t, f.Has(SyscallMediated), "firecracker filters, it does not mediate")
	require.True(t, f.Has(KernelGuest), "firecracker gives the workload its own kernel")
	require.False(t, g.Has(KernelGuest), "gvisor shares the host kernel")

	require.False(t, g.Contains(f), "gvisor does not dominate firecracker")
	require.False(t, f.Contains(g), "firecracker does not dominate gvisor")

	// An unknown mechanism off the wire grants nothing, so it can satisfy
	// nothing.
	require.Equal(t, Properties(0), Grants(Mechanism(200)))
	require.False(t, Mechanism(200).Satisfies(Require(KernelShared)))
}

// TestMatchIsContainment checks the whole selection rule against the table.
func TestMatchIsContainment(t *testing.T) {
	cases := []struct {
		mech  Mechanism
		want  Properties
		serve bool
	}{
		{MechanismPlain, Require(SyscallDirect), true},
		{MechanismPlain, Require(SyscallFiltered), false},
		{MechanismRunc, Require(SyscallFiltered, KernelShared), true},
		{MechanismRunc, Require(SyscallMediated), false},
		{MechanismGVisor, Require(SyscallMediated), true},
		{MechanismGVisor, Require(SyscallFiltered), false},
		{MechanismFirecracker, Require(KernelGuest, SyscallFiltered), true},
		{MechanismFirecracker, Require(MemoryEncrypted), false},
		{MechanismTEE, Require(MemoryEncrypted, AttestHardware, KernelGuest), true},
		{MechanismTEE, Require(AttestSoftware), false},
	}
	for _, c := range cases {
		require.Equal(t, c.serve, c.mech.Satisfies(c.want),
			"%s serving %v", c.mech, c.want)
	}
}

// TestDemandOnOneAxisIsRefused: a demand naming two values of one axis describes
// no run, and saying so is better than leaving a workload nothing can schedule.
func TestDemandOnOneAxisIsRefused(t *testing.T) {
	require.False(t, Require(SyscallDirect, SyscallMediated).Wellformed())
	require.False(t, Require(ReplicaOne, ReplicaMany).Wellformed())
	require.True(t, Require(SyscallMediated, KernelShared, ReplicaMany, SpreadCluster).Wellformed())

	ev := gvisorEvidence()
	err := ev.Proves(Require(SyscallDirect, SyscallMediated), h(1), outputHandle(), common.Address{}, yes{})
	require.ErrorIs(t, err, ErrDemandMalformed)
}

// TestRuncEvidenceRefusedForMediated is the pair most likely to be silently
// accepted: an operator that ran a container presenting its evidence for work
// that demanded a user-space kernel. runc's row does not contain
// syscall.mediated, so no field it fills in can make its evidence prove it.
func TestRuncEvidenceRefusedForMediated(t *testing.T) {
	ev := runcEvidence()
	err := ev.Proves(Require(SyscallMediated), h(1), outputHandle(), common.Address{}, yes{})
	require.ErrorIs(t, err, ErrEvidenceMechanism,
		"runc evidence must not satisfy a demand for mediated syscalls")

	// The same evidence proves what runc actually gives.
	require.NoError(t, ev.Proves(Require(SyscallFiltered, KernelShared), h(1), outputHandle(), common.Address{}, yes{}))
}

// TestGvisorEvidenceRefusedForFiltered is the same pair the other way. gVisor is
// not "runc but better": its row holds syscall.mediated and not syscall.filtered,
// so a demand for a seccomp filter is not met by a sentry.
func TestGvisorEvidenceRefusedForFiltered(t *testing.T) {
	ev := gvisorEvidence()
	err := ev.Proves(Require(SyscallFiltered), h(1), outputHandle(), common.Address{}, yes{})
	require.ErrorIs(t, err, ErrEvidenceMechanism)

	require.NoError(t, ev.Proves(Require(SyscallMediated), h(1), outputHandle(), common.Address{}, yes{}))
}

// TestGvisorEvidenceRefusedForGuestKernel: mediating syscalls is not the same as
// having your own kernel, in either direction.
func TestGvisorEvidenceRefusedForGuestKernel(t *testing.T) {
	require.ErrorIs(t,
		gvisorEvidence().Proves(Require(KernelGuest), h(1), outputHandle(), common.Address{}, yes{}),
		ErrEvidenceMechanism)
	require.ErrorIs(t,
		firecrackerEvidence().Proves(Require(SyscallMediated), h(1), outputHandle(), common.Address{}, yes{}),
		ErrEvidenceMechanism)
	require.NoError(t,
		firecrackerEvidence().Proves(Require(KernelGuest), h(1), outputHandle(), common.Address{}, yes{}))
}

// TestMediatedNeedsAnObservation: naming gVisor is not evidence. The witness must
// carry an identity the run read from inside the sandbox, and a zero digest is
// what a run that never entered one has to show.
func TestMediatedNeedsAnObservation(t *testing.T) {
	ev := gvisorEvidence()
	ev.Witness.Digest = common.Hash{}
	require.ErrorIs(t,
		ev.Proves(Require(SyscallMediated), h(1), outputHandle(), common.Address{}, yes{}),
		ErrEvidenceWitness)
}

// TestGuestKernelMustBeTheKernelBooted: a microVM claim needs the measurement AND
// the run to have booted that exact kernel. Declaring one kernel and observing
// another is refused.
func TestGuestKernelMustBeTheKernelBooted(t *testing.T) {
	ev := firecrackerEvidence()
	ev.Root = common.Hash{}
	require.ErrorIs(t, ev.Proves(Require(KernelGuest), h(1), outputHandle(), common.Address{}, yes{}), ErrEvidenceKernel)

	ev = firecrackerEvidence()
	ev.Witness.Digest = h(0x99) // booted something other than what it declared
	require.ErrorIs(t, ev.Proves(Require(KernelGuest), h(1), outputHandle(), common.Address{}, yes{}), ErrEvidenceWitness)
}

// TestFilteredNeedsAFilter: claiming a filter without naming one proves nothing.
func TestFilteredNeedsAFilter(t *testing.T) {
	ev := runcEvidence()
	ev.Filter = common.Hash{}
	require.ErrorIs(t,
		ev.Proves(Require(SyscallFiltered), h(1), outputHandle(), common.Address{}, yes{}),
		ErrEvidenceFilter)
}

// TestSoftwareAttestationIsAttributable: the signature must recover to the
// operator the task selected, not merely to somebody.
func TestSoftwareAttestationIsAttributable(t *testing.T) {
	mine, theirs := newKey(t), newKey(t)
	out := outputHandle()
	claim := h(0x77)

	ev := runcEvidence()
	require.NoError(t, ev.Sign(claim, out, mine))

	require.NoError(t, ev.Proves(Require(AttestSoftware), claim, out, mine.addr(), yes{}))
	require.ErrorIs(t, ev.Proves(Require(AttestSoftware), claim, out, theirs.addr(), yes{}),
		ErrEvidenceSignature)

	// A signature over one run does not carry to another.
	require.ErrorIs(t, ev.Proves(Require(AttestSoftware), h(0x78), out, mine.addr(), yes{}),
		ErrEvidenceSignature)
}

// TestSignatureCoversEveryFact: moving a signature onto different evidence for the
// same run must fail, which is why the signed digest covers the facts and not
// just the claim.
func TestSignatureCoversEveryFact(t *testing.T) {
	op := newKey(t)
	out := outputHandle()
	claim := h(0x77)

	ev := runcEvidence()
	require.NoError(t, ev.Sign(claim, out, op))
	require.NoError(t, ev.Proves(Require(AttestSoftware), claim, out, op.addr(), yes{}))

	tampered := ev
	tampered.Filter = h(0xEE)
	require.ErrorIs(t, tampered.Proves(Require(AttestSoftware), claim, out, op.addr(), yes{}),
		ErrEvidenceSignature)
}

// TestHardwareAttestationFailsClosedOnAFreshChain: with nothing admitted, no
// quote is believed, whatever it says.
func TestHardwareAttestationFailsClosedOnAFreshChain(t *testing.T) {
	q, _ := newQuote(t, QuoteSEVSNP, h(0x42))
	ev := Evidence{Witness: Witness{Serves: MechanismTEE}, Quote: q}
	require.ErrorIs(t,
		ev.Proves(Require(AttestHardware), h(0x42), outputHandle(), common.Address{}, no{}),
		ErrQuoteKeyNotAdmitted)
}

// TestEveryPropertyIsCheckedNotJustOne: a demand is met only when all of it is.
func TestEveryPropertyIsCheckedNotJustOne(t *testing.T) {
	op := newKey(t)
	out := outputHandle()
	claim := h(0x77)

	ev := runcEvidence()
	require.NoError(t, ev.Sign(claim, out, op))

	// runc gives filtered syscalls and software attestation, so this passes.
	require.NoError(t, ev.Proves(Require(SyscallFiltered, AttestSoftware), claim, out, op.addr(), yes{}))
	// Adding one property runc does not give makes the whole demand fail, even
	// though the rest still holds.
	require.ErrorIs(t,
		ev.Proves(Require(SyscallFiltered, AttestSoftware, MemoryEncrypted), claim, out, op.addr(), yes{}),
		ErrEvidenceMechanism)
}

// TestUnknownPropertyProvesNothing: a bit this build does not know is a refusal,
// never a pass.
func TestUnknownPropertyProvesNothing(t *testing.T) {
	ev := runcEvidence()
	unknown := Properties(1 << (propertyCount - 1))
	unknown <<= 0 // the top known bit; construct one past it below
	beyond := Properties(0)
	for p := Property(propertyCount); p < 16; p++ {
		beyond |= 1 << p
	}
	if beyond == 0 {
		// Every bit of the word is a known property; there is no unknown bit to
		// present, which is itself the guarantee.
		require.Equal(t, 16, int(propertyCount))
		return
	}
	require.ErrorIs(t, ev.Proves(beyond, h(1), outputHandle(), common.Address{}, yes{}), ErrUnknownProperty)
}
