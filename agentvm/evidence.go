// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

// evidence.go decides whether a run proved the properties a workload demanded.
// It is keyed by PROPERTY, never by mechanism and never by storage arrangement:
// verification walks the demanded set and asks, for each property in turn,
// whether the evidence carries what proving that property requires. A property
// with nothing to show is refused, and a demand is met only when every one of its
// properties is met.
//
// The evidence has one field per fact and no field that merely asserts a
// conclusion. In particular there is no "mechanism I claim to have used" field:
// the Witness is that statement, and it is the identity of whatever answered the
// run's syscalls, read from INSIDE the run rather than declared from outside.
// Every execution property check begins by asking the one table (Grants) whether
// the witnessed mechanism provides the property at all, so an operator that ran
// under runc cannot present its evidence for a demand of mediated syscalls:
// runc's row does not contain SyscallMediated, and no field it could fill in
// changes that.
//
// What each property costs to prove:
//
//	kernel.shared      nothing — sharing the host kernel is not a claim
//	kernel.guest       a guest kernel measurement, a root filesystem measurement,
//	                   and a witness whose observed kernel IS that measurement
//	syscall.direct     nothing
//	syscall.filtered   the digest of the filter actually applied
//	syscall.mediated   a witnessed identity for the user-space kernel that served
//	                   the syscalls, so installing runsc is not the same as running
//	                   under it
//	memory.plain       nothing
//	memory.encrypted   a verified hardware quote
//	attest.none        nothing
//	attest.software    a signature recovering to the selected operator, over the
//	                   run and every evidence fact, so a false statement is
//	                   attributable to a bonded identity
//	attest.hardware    a verified hardware quote bound to this exact run
//	replica.one        a pin on an admitted root, and one copy read back in full
//	                   whose digest is the object's
//	replica.many       the same, from at least two distinct hosts
//	replica.erasure    the same, from shards covering every index, whose digests
//	                   rebuild the handle's shard commitment
//	spread.host        nothing — sharing a host is not a claim
//	spread.cluster     copies on at least two distinct hosts
//	spread.federated   copies in at least two distinct clusters
//
// Every replica count is over DISTINCT FAILURE DOMAINS and every copy is
// established by a digest over the full object. Configuration is not consulted:
// this estate has run a "distributed" store whose master, filer, gateway and
// largest volume server were one process, and a replication factor read off a
// config would have called that four copies.
//
// Below hardware attestation no cryptography can prove isolation to a remote
// party — that is what confidential computing exists for. What the chain enforces
// there is structure and attribution: strictly more bound facts for a stronger
// property, and a signature that names who said it. Divergence between the
// independent operators a task selects is what catches a liar, and the bond is
// what it costs.

import (
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// Domain separators for the agentic-compute digests. Disjoint keyspaces, and a
// version in each so a later encoding cannot collide with this one.
const (
	DomainQuote    = "lux/agentvm/quote/v1"
	DomainAttest   = "lux/agentvm/attest/v1"
	DomainWorkload = "lux/agentvm/workload/v1"
	DomainRun      = "lux/agentvm/run/v1"
	DomainCatalog  = "lux/agentvm/catalog/v1"
	DomainGroup    = "lux/agentvm/group/v1"
)

// Trust is what this chain has admitted to believe. Two questions, kept apart: an
// attesting key and a state root are both 32-byte digests, and answering them
// from one set would let a key admitted for hardware quotes serve as a storage
// root.
type Trust interface {
	// Attests reports whether quotes signed by this key digest are believed.
	Attests(keyDigest common.Hash) bool
	// Pins reports whether pins naming this S-Chain state root are believed.
	Pins(root common.Hash) bool
}

// Witness is the identity of whatever served the run's syscalls, observed from
// inside the run. Serves names the mechanism that identity belongs to; Digest is
// the digest of the identity itself — the sentry's version string under gVisor,
// the guest kernel's under a microVM or a TEE.
//
// The zero Witness reads as a bare process on the host kernel, which is exactly
// what a run that observed nothing was.
type Witness struct {
	Serves Mechanism   `json:"serves"`
	Digest common.Hash `json:"digest"`
}

// Evidence is what a run carries to show how it ran and where its output went.
// Every field is a fact with one job; none of them states a conclusion.
type Evidence struct {
	// Witness is what answered the run's syscalls, observed from inside it.
	Witness Witness `json:"witness"`
	// Placement is where the run happened. Orthogonal to every property.
	Placement Placement `json:"placement"`
	// Filter is the digest of the syscall filter actually applied.
	Filter common.Hash `json:"filter"`
	// Kernel is the measurement of the guest kernel the run booted.
	Kernel common.Hash `json:"kernel"`
	// Root is the measurement of the guest root filesystem the run booted.
	Root common.Hash `json:"root"`
	// Quote is the hardware attestation report and its signature.
	Quote Quote `json:"quote"`
	// Durability is where the output was committed and which copies were read
	// back.
	Durability Durability `json:"durability"`
	// Signature is the operator's secp256k1 signature over the run's claim and
	// every field above, in the fixed encoding of facts().
	Signature []byte `json:"signature"`
}

// factsLen is the fixed width of the signed evidence encoding:
// serves(1) + witness digest(32) + placement(1) + filter(32) + kernel(32) +
// root(32) + quote digest(32) + durability digest(32).
const factsLen = 1 + 32 + 1 + 32 + 32 + 32 + 32 + 32

// facts is the canonical encoding of every evidence field except the signature.
// Fixed width in a fixed order, so the bytes an operator signs are the bytes a
// verifier rebuilds. The output handle enters through the durability digest,
// which binds the copies to the object they are copies of.
func (e Evidence) facts(out Handle) []byte {
	buf := make([]byte, 0, factsLen)
	buf = append(buf, byte(e.Witness.Serves))
	buf = append(buf, e.Witness.Digest.Bytes()...)
	buf = append(buf, byte(e.Placement))
	buf = append(buf, e.Filter.Bytes()...)
	buf = append(buf, e.Kernel.Bytes()...)
	buf = append(buf, e.Root.Bytes()...)
	buf = append(buf, e.Quote.Digest().Bytes()...)
	buf = append(buf, e.Durability.Digest(out).Bytes()...)
	return buf
}

// Attestation is the digest an operator signs to make its evidence attributable:
// the run's claim together with every evidence fact. Signing the claim alone
// would let a signature be moved onto different evidence for the same run.
func (e Evidence) Attestation(claim common.Hash, out Handle) common.Hash {
	return common.BytesToHash(crypto.Keccak256(
		[]byte(DomainAttest), claim.Bytes(), e.facts(out),
	))
}

// Sign produces the operator signature over this evidence for the given claim.
// The key is the operator's; the address it recovers to is checked at
// verification against the operator the task selected.
func (e *Evidence) Sign(claim common.Hash, out Handle, key Signer) error {
	sig, err := key.Sign(e.Attestation(claim, out))
	if err != nil {
		return err
	}
	e.Signature = sig
	return nil
}

// Signer produces a 65-byte recoverable secp256k1 signature over a digest. An
// operator holds one; the chain only ever verifies.
type Signer interface {
	Sign(digest common.Hash) ([]byte, error)
}

// signer reports the address the evidence signature recovers to, or an error if
// the signature is absent or unrecoverable.
func (e Evidence) signer(claim common.Hash, out Handle) (common.Address, error) {
	if len(e.Signature) != 65 {
		return common.Address{}, ErrEvidenceSignature
	}
	pub, err := crypto.Ecrecover(e.Attestation(claim, out).Bytes(), e.Signature)
	if err != nil {
		return common.Address{}, ErrEvidenceSignature
	}
	return common.BytesToAddress(crypto.Keccak256(pub[1:])[12:]), nil
}

// Proves reports whether this evidence establishes every property in d for the
// given run, attributed to operator, over the output handle. Any property that is
// not established is a refusal; there is no partial credit and no property is
// waived because another one passed.
//
// The quote and the pin, when needed, are each checked once — both cost a
// verification and more than one property can want them.
func (e Evidence) Proves(d Properties, claim common.Hash, out Handle, operator common.Address, trust Trust) error {
	if !d.Wellformed() {
		return ErrDemandMalformed
	}
	granted := Grants(e.Witness.Serves)

	quoteChecked, pinChecked := false, false
	var quoteErr, pinErr error
	quote := func() error {
		if !quoteChecked {
			quoteErr, quoteChecked = e.Quote.Verify(claim, trust), true
		}
		return quoteErr
	}
	pin := func() error {
		if !pinChecked {
			pinErr, pinChecked = e.Durability.pinned(trust), true
		}
		return pinErr
	}

	var failure error
	fail := func(err error) {
		if failure == nil {
			failure = err
		}
	}

	d.Each(func(p Property) {
		if failure != nil {
			return
		}
		switch p {
		// ---- execution: the witnessed mechanism must provide the property at
		// all. This is the one place a mechanism's guarantees are consulted, and
		// it is the same table selection reads.
		case KernelShared, SyscallDirect, MemoryPlain, AttestNone:
			if !granted.Has(p) {
				fail(ErrEvidenceMechanism)
			}
			// Nothing else to show: these are the absence of a stronger
			// guarantee, and the witness has established the mechanism provides
			// them.

		case KernelGuest:
			if !granted.Has(p) {
				fail(ErrEvidenceMechanism)
				return
			}
			// A guest kernel is proved by measuring it and by the run having
			// booted THAT kernel — the measurement declared and the kernel
			// observed from inside must be the same value.
			if e.Kernel == (common.Hash{}) || e.Root == (common.Hash{}) {
				fail(ErrEvidenceKernel)
				return
			}
			if e.Witness.Digest != e.Kernel {
				fail(ErrEvidenceWitness)
			}

		case SyscallFiltered:
			if !granted.Has(p) {
				fail(ErrEvidenceMechanism)
				return
			}
			if e.Filter == (common.Hash{}) {
				fail(ErrEvidenceFilter)
			}

		case SyscallMediated:
			if !granted.Has(p) {
				fail(ErrEvidenceMechanism)
				return
			}
			// The user-space kernel that answered the syscalls has an identity,
			// and the run read it from inside. A zero digest means nothing was
			// observed, which is what a run that never entered the sandbox has
			// to show.
			if e.Witness.Digest == (common.Hash{}) {
				fail(ErrEvidenceWitness)
			}

		case MemoryEncrypted, AttestHardware:
			if !granted.Has(p) {
				fail(ErrEvidenceMechanism)
				return
			}
			fail(quote())

		case AttestSoftware:
			if !granted.Has(p) {
				fail(ErrEvidenceMechanism)
				return
			}
			signer, err := e.signer(claim, out)
			if err != nil {
				fail(err)
				return
			}
			if signer != operator {
				fail(ErrEvidenceSignature)
			}

		// ---- storage: the mechanism table says nothing about where bytes went,
		// so these read the durability claim instead. Copies are counted over
		// distinct failure domains and established by a digest over the full
		// object, never by a configured factor and never by a successful open.
		case SpreadHost:
			// Sharing a host is not a claim.

		case ReplicaOne:
			if err := pin(); err != nil {
				fail(err)
				return
			}
			if len(e.Durability.whole(out)) == 0 {
				fail(ErrDurabilityWitness)
			}

		case ReplicaMany:
			if err := pin(); err != nil {
				fail(err)
				return
			}
			if len(independent(e.Durability.whole(out))) < 2 {
				fail(ErrDurabilityReplicas)
			}

		case ReplicaErasure:
			if err := pin(); err != nil {
				fail(err)
				return
			}
			if len(e.Durability.coded(out)) < 2 {
				fail(ErrDurabilityShards)
			}

		case SpreadCluster:
			if err := pin(); err != nil {
				fail(err)
				return
			}
			if domains(e.Durability.held(out), replicaHost) < 2 {
				fail(ErrDurabilitySpread)
			}

		case SpreadFederated:
			if err := pin(); err != nil {
				fail(err)
				return
			}
			if domains(e.Durability.held(out), replicaCluster) < 2 {
				fail(ErrDurabilitySpread)
			}

		default:
			// A property this build does not know proves nothing.
			fail(ErrUnknownProperty)
		}
	})
	return failure
}

// held is the copies that read back correctly, however the object was stored:
// whole copies when it was stored whole, verified shards when it was coded. It is
// what a spread question is asked about, so spread does not depend on which of
// the two a replication demand happened to name.
func (d Durability) held(h Handle) []Replica {
	if h.Shards != (common.Hash{}) {
		return d.coded(h)
	}
	return independent(d.whole(h))
}

func replicaHost(r Replica) common.Hash    { return r.Host }
func replicaCluster(r Replica) common.Hash { return r.Cluster }
