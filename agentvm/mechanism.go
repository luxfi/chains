// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

// mechanism.go holds three values and one table, and nothing else knows what a
// mechanism guarantees.
//
// A Mechanism is an implementation fact: what actually ran the workload. It is
// unordered. There is no Mechanism comparison anywhere in this package, because
// "gVisor is stronger than Firecracker" is not true — gVisor shrinks the host
// kernel surface a guest can reach, Firecracker gives the guest its own kernel,
// and which one matters is a question about the adversary, not about the code.
//
// A Property is one atomic guarantee on one axis. Four axes, each independent:
//
//	Kernel       Shared | Guest        whose kernel executes the workload
//	Syscall      Direct | Filtered | Mediated
//	Memory       Plain  | Encrypted
//	Attestation  None   | Software | Hardware
//
// Properties is a set of those values. Grants is the ONE table from mechanism to
// the properties it provides; no other line in this package may assert what a
// mechanism guarantees, and every property check reads this table.
//
// A workload demands a set of properties — never a mechanism name, never a level
// number. Selection is one predicate:
//
//	Grants(m).Contains(demand)
//
// A mechanism satisfies a demand or it does not. There is no order to slide down,
// so there is no downgrade to defend against: an unavailable mechanism simply
// never enters the match. Placement (below) is the orthogonal question of WHERE a
// mechanism runs, and it ranks against nothing.

// Mechanism names an isolation implementation. Unordered — the numeric values
// exist only to key the Grants table and to ride the wire.
type Mechanism uint8

const (
	// MechanismPlain is a bare process: the host kernel, the host namespaces,
	// no container.
	MechanismPlain Mechanism = 0
	// MechanismRunc is an OCI container: namespaces, cgroups and a seccomp
	// filter, over the host kernel.
	MechanismRunc Mechanism = 1
	// MechanismGVisor is gVisor: a user-space kernel (the sentry) answers the
	// workload's syscalls instead of the host kernel.
	MechanismGVisor Mechanism = 2
	// MechanismFirecracker is a microVM: hardware virtualisation, its own guest
	// kernel and root filesystem.
	MechanismFirecracker Mechanism = 3
	// MechanismTEE is a trusted execution environment (SEV-SNP, TDX): a guest
	// kernel in encrypted memory, with a hardware attestation quote.
	MechanismTEE Mechanism = 4

	mechanismCount = 5
)

// String names the mechanism.
func (m Mechanism) String() string {
	switch m {
	case MechanismPlain:
		return "plain"
	case MechanismRunc:
		return "runc"
	case MechanismGVisor:
		return "gvisor"
	case MechanismFirecracker:
		return "firecracker"
	case MechanismTEE:
		return "tee"
	default:
		return "unknown"
	}
}

// Known reports whether m is a mechanism this build knows. An unknown mechanism
// grants nothing (see Grants), so a value from the wire cannot invent guarantees.
func (m Mechanism) Known() bool { return m < mechanismCount }

// Property is one atomic guarantee on one axis.
type Property uint8

const (
	// KernelShared: the workload executes on the host's kernel.
	KernelShared Property = 0
	// KernelGuest: the workload executes on a kernel of its own.
	KernelGuest Property = 1

	// SyscallDirect: syscalls reach the host kernel unmediated.
	SyscallDirect Property = 2
	// SyscallFiltered: a seccomp filter screens syscalls before the kernel.
	SyscallFiltered Property = 3
	// SyscallMediated: a user-space kernel answers syscalls; the host kernel
	// sees only what that kernel itself issues.
	SyscallMediated Property = 4

	// MemoryPlain: memory is readable by whoever holds the host.
	MemoryPlain Property = 5
	// MemoryEncrypted: memory is encrypted against the host.
	MemoryEncrypted Property = 6

	// AttestNone: the run makes no attestable statement about itself.
	AttestNone Property = 7
	// AttestSoftware: the run carries a statement signed by the operator, so a
	// false claim is attributable to a bonded identity.
	AttestSoftware Property = 8
	// AttestHardware: the run carries a quote signed by hardware whose key the
	// chain has admitted.
	AttestHardware Property = 9

	// ReplicaOne: the object exists as a single copy.
	ReplicaOne Property = 10
	// ReplicaMany: the object exists as whole independent copies.
	ReplicaMany Property = 11
	// ReplicaErasure: the object exists as coded shards, no one of which is the
	// object.
	ReplicaErasure Property = 12

	propertyCount = 13
)

// String names the property.
func (p Property) String() string {
	switch p {
	case KernelShared:
		return "kernel.shared"
	case KernelGuest:
		return "kernel.guest"
	case SyscallDirect:
		return "syscall.direct"
	case SyscallFiltered:
		return "syscall.filtered"
	case SyscallMediated:
		return "syscall.mediated"
	case MemoryPlain:
		return "memory.plain"
	case MemoryEncrypted:
		return "memory.encrypted"
	case AttestNone:
		return "attest.none"
	case AttestSoftware:
		return "attest.software"
	case AttestHardware:
		return "attest.hardware"
	case ReplicaOne:
		return "replica.one"
	case ReplicaMany:
		return "replica.many"
	case ReplicaErasure:
		return "replica.erasure"
	default:
		return "unknown"
	}
}

// Storage is the set of properties about where the bytes went, as opposed to how
// the code ran. It exists so the execution half of a demand can be asked of a
// mechanism and the storage half of one cannot: a mechanism has nothing to say
// about durability, and the object store has nothing to say about syscalls.
var Storage = Require(ReplicaOne, ReplicaMany, ReplicaErasure)

// Properties is a set of Property values, one bit each. It rides the wire as a
// u16 and is a state word, so the encoding is fixed: bit i is Property(i).
type Properties uint16

// Require builds the set holding exactly ps. It is how a workload states what it
// needs and how the Grants table states what a mechanism provides — the same
// value in both roles, so a demand and a grant are always comparable.
func Require(ps ...Property) Properties {
	var s Properties
	for _, p := range ps {
		s |= 1 << p
	}
	return s
}

// Has reports whether p is in the set.
func (s Properties) Has(p Property) bool { return s&(1<<p) != 0 }

// Contains reports whether s holds every property of d — the ⊇ that selection
// and evidence verification both use.
func (s Properties) Contains(d Properties) bool { return s&d == d }

// Each calls f for every property in the set, in ascending Property order, so
// any walk over a demand is deterministic.
func (s Properties) Each(f func(Property)) {
	for p := Property(0); p < propertyCount; p++ {
		if s.Has(p) {
			f(p)
		}
	}
}

// Len counts the properties in the set.
func (s Properties) Len() int {
	n := 0
	s.Each(func(Property) { n++ })
	return n
}

// known is every property bit this build defines. A demand carrying a bit
// outside it names something this build cannot reason about.
const known = Properties(1)<<propertyCount - 1

// Wellformed reports whether the set names only properties this build defines,
// and at most one value per axis.
//
// Both halves matter. A set naming two values on one axis (Direct and Mediated)
// describes no run and is satisfied by no mechanism. A set carrying a bit this
// build does not define would otherwise be WAIVED rather than refused: Each
// walks the properties it knows, so an unknown bit is invisible to the proof
// walk, and a demand for it would be silently met by evidence that shows nothing.
// Refusing at the boundary is what makes an unknown property prove nothing.
func (s Properties) Wellformed() bool {
	if s&^known != 0 {
		return false
	}
	axes := [][]Property{
		{KernelShared, KernelGuest},
		{SyscallDirect, SyscallFiltered, SyscallMediated},
		{MemoryPlain, MemoryEncrypted},
		{AttestNone, AttestSoftware, AttestHardware},
		{ReplicaOne, ReplicaMany, ReplicaErasure},
	}
	for _, axis := range axes {
		n := 0
		for _, p := range axis {
			if s.Has(p) {
				n++
			}
		}
		if n > 1 {
			return false
		}
	}
	return true
}

// grants is THE table: what each mechanism provides. Every claim in this package
// about what a mechanism guarantees reads this array and no other source.
//
//	plain        shared kernel, direct syscalls,   plain memory,     no attestation
//	runc         shared kernel, seccomp filter,    plain memory,     software attestation
//	gvisor       shared kernel, mediated syscalls, plain memory,     software attestation
//	firecracker  guest kernel,  seccomp filter,    plain memory,     software attestation
//	tee          guest kernel,  seccomp filter,    encrypted memory, hardware attestation
//
// Reading the rows shows what an ordering would have had to hide: gvisor is alone
// in mediating syscalls, firecracker is alone (below tee) in giving the workload
// its own kernel, and neither row contains the other.
var grants = [mechanismCount]Properties{
	MechanismPlain:       Require(KernelShared, SyscallDirect, MemoryPlain, AttestNone),
	MechanismRunc:        Require(KernelShared, SyscallFiltered, MemoryPlain, AttestSoftware),
	MechanismGVisor:      Require(KernelShared, SyscallMediated, MemoryPlain, AttestSoftware),
	MechanismFirecracker: Require(KernelGuest, SyscallFiltered, MemoryPlain, AttestSoftware),
	MechanismTEE:         Require(KernelGuest, SyscallFiltered, MemoryEncrypted, AttestHardware),
}

// Grants returns the properties m provides. An unknown mechanism grants the empty
// set, so a mechanism byte off the wire can satisfy nothing.
func Grants(m Mechanism) Properties {
	if !m.Known() {
		return 0
	}
	return grants[m]
}

// Satisfies is the whole selection rule: m serves demand d exactly when the
// properties m grants contain every property d requires.
func (m Mechanism) Satisfies(d Properties) bool { return Grants(m).Contains(d) }

// Mechanisms is a set of mechanisms, one bit each — what an operator can run, or
// what a host has available. It rides the wire and state as a u8, so the encoding
// is fixed: bit i is Mechanism(i).
type Mechanisms uint8

// Offer builds the set holding exactly ms.
func Offer(ms ...Mechanism) Mechanisms {
	var s Mechanisms
	for _, m := range ms {
		if m.Known() {
			s |= 1 << m
		}
	}
	return s
}

// Has reports whether m is in the set.
func (s Mechanisms) Has(m Mechanism) bool { return m.Known() && s&(1<<m) != 0 }

// Each calls f for every mechanism in the set, in ascending order, so any walk is
// deterministic. The order is an enumeration order and carries no ranking.
func (s Mechanisms) Each(f func(Mechanism)) {
	for m := Mechanism(0); m < mechanismCount; m++ {
		if s.Has(m) {
			f(m)
		}
	}
}

// Serves reports whether any mechanism in the set satisfies the demand. A set
// that holds no such mechanism does not serve it — there is nothing to fall back
// to, because nothing here is ordered.
func (s Mechanisms) Serves(d Properties) bool {
	served := false
	s.Each(func(m Mechanism) {
		if m.Satisfies(d) {
			served = true
		}
	})
	return served
}

// Placement is where a mechanism runs. It is orthogonal to properties — a
// cluster can host any mechanism — and it is unordered: a workload either
// constrains placement or does not care.
type Placement uint8

const (
	// PlacementAny expresses no constraint. The zero value, so a workload that
	// does not care says nothing.
	PlacementAny Placement = 0
	// PlacementLocal is the operator's own host.
	PlacementLocal Placement = 1
	// PlacementCluster is a Kubernetes cluster the operator controls.
	PlacementCluster Placement = 2
	// PlacementRemote is a provider the operator reaches over the network.
	PlacementRemote Placement = 3

	placementCount = 4
)

// String names the placement.
func (p Placement) String() string {
	switch p {
	case PlacementAny:
		return "any"
	case PlacementLocal:
		return "local"
	case PlacementCluster:
		return "cluster"
	case PlacementRemote:
		return "remote"
	default:
		return "unknown"
	}
}

// Known reports whether p is a placement this build knows.
func (p Placement) Known() bool { return p < placementCount }

// Admits reports whether a runner placed at have serves a workload asking for
// want. PlacementAny asks for nothing and admits everything; otherwise the two
// must be the same place. No ranking is involved.
func (want Placement) Admits(have Placement) bool {
	return want == PlacementAny || want == have
}
