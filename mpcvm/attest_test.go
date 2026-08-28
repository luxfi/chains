// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// attest_test.go — what a threshold attestation binds, and what verifying one
// actually checks.

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/ownership"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
)

// attestationOver builds the attestation the ceremony would have produced for a
// domain-bound payload, signed by the key that actually holds custody.
func (c *custody) attestationOver(t *testing.T, domain AttestationDomain, subject, root [32]byte, epoch uint64) *QuantumAttestation {
	t.Helper()
	payload := ComputeAttestationPayload(domain, subject, root, epoch)
	return &QuantumAttestation{
		Domain:         domain,
		SubjectID:      subject,
		CommitmentRoot: root,
		Epoch:          epoch,
		KeyID:          c.rec.KeyID,
		Policy:         c.rec.Policy,
		Signers:        c.rec.Participants[:c.rec.Policy.K],
		Signature:      c.sign(t, payload[:]),
	}
}

// -----------------------------------------------------------------------------
// The payload
// -----------------------------------------------------------------------------

// Domain separation is what stops an attestation about one thing being replayed
// as an attestation about another. Every domain M-Chain issues produces a
// different payload for identical inputs.
func TestEveryAttestationDomainSignsADifferentThing(t *testing.T) {
	subject, root := [32]byte{1}, [32]byte{2}

	seen := map[[32]byte]AttestationDomain{}
	for domain := range domainSeparators {
		payload := ComputeAttestationPayload(domain, subject, root, 7)
		prev, dup := seen[payload]
		require.Falsef(t, dup, "%s and %s sign the same payload", domain, prev)
		seen[payload] = domain
	}
	require.Len(t, seen, len(domainSeparators))

	// A domain M-Chain does not issue falls to one separator, which is why it is
	// refused at verification rather than trusted to be distinct.
	require.Equal(t,
		ComputeAttestationPayload("made/up", subject, root, 7),
		ComputeAttestationPayload("also/made/up", subject, root, 7))
}

// Every field of the payload is bound: subject, commitment and epoch each move
// the signature.
func TestAnAttestationPayloadBindsItsSubjectRootAndEpoch(t *testing.T) {
	base := ComputeAttestationPayload(DomainOracleWrite, [32]byte{1}, [32]byte{2}, 7)
	require.NotEqual(t, base, ComputeAttestationPayload(DomainOracleWrite, [32]byte{9}, [32]byte{2}, 7))
	require.NotEqual(t, base, ComputeAttestationPayload(DomainOracleWrite, [32]byte{1}, [32]byte{9}, 7))
	require.NotEqual(t, base, ComputeAttestationPayload(DomainOracleWrite, [32]byte{1}, [32]byte{2}, 8),
		"without the epoch, an attestation from one epoch is an attestation for every epoch")
}

// The bridge and ownership domains register themselves into the same table, so
// the tooling that verifies a quantum attestation verifies theirs too, and no
// registration displaces another.
func TestTheDomainTableIsAdditive(t *testing.T) {
	for _, d := range []AttestationDomain{
		DomainOracleWrite, DomainOracleRead, DomainSessionComplete, DomainEpochBeacon,
		DomainBridgeTransfer, DomainNFTOwnership,
	} {
		require.Containsf(t, domainSeparators, d, "%s is not a domain this chain issues", d)
	}
	require.Equal(t, []byte(ownership.DomainTag), domainSeparators[DomainNFTOwnership])
	require.Equal(t, []byte(bridgeTransferDomainTag), domainSeparators[DomainBridgeTransfer])
}

// -----------------------------------------------------------------------------
// Verification
// -----------------------------------------------------------------------------

// The registry decides the quorum, not the attestation.
//
// The check used to compare len(Signers) against the attestation's OWN Policy
// field — two halves of the same attacker-supplied document — so it held for
// every attestation ever written, including one declaring 1-of-1 with one
// signer. A quorum check against the checked party's own claim is not a check.
func TestAnAttestationCannotDeclareItsOwnQuorum(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 90)
	key.register(t, vm)

	att := key.attestationOver(t, DomainSessionComplete, [32]byte{1}, [32]byte{2}, 7)
	require.NoError(t, vm.VerifyAttestation(att))

	// A real signature by the real custody key, re-labelled as a 2-of-3 key
	// signed by two parties. Under the old rule this passed.
	att.Policy = quorum.MustNew(2, 3)
	att.Signers = key.rec.Participants[:2]
	require.ErrorIs(t, vm.VerifyAttestation(att), ErrInvalidOperation)
}

// A quorum is a set of distinct parties that hold a share of THIS key, counted
// the way the key's policy counts. The same three rules Block.verifySign holds,
// so an attestation cannot pass here under a rule a block would have refused.
func TestAnAttestationsQuorumIsRealAndCanonical(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 91)
	key.register(t, vm)

	one := key.rec.Participants[0]
	for name, signers := range map[string][]party.ID{
		"too few":      key.rec.Participants[:2],
		"none":         nil,
		"one repeated": {one, one, one},
		"unsorted":     {key.rec.Participants[2], key.rec.Participants[0], key.rec.Participants[1]},
		"strangers":    {"za", "zb", "zc"},
	} {
		att := key.attestationOver(t, DomainEpochBeacon, [32]byte{1}, [32]byte{2}, 7)
		att.Signers = signers
		require.Errorf(t, vm.VerifyAttestation(att), "%s must not count as a quorum", name)
	}
}

func TestAnAttestationInADomainThisChainDoesNotIssueIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 92)
	key.register(t, vm)

	att := key.attestationOver(t, "made/up", [32]byte{1}, [32]byte{2}, 7)
	require.ErrorContains(t, vm.VerifyAttestation(att), "unknown attestation domain")

	require.ErrorContains(t, vm.VerifyAttestation(nil), "nil attestation")
}

func TestAnAttestationForAnUnregisteredKeyIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "never-registered", quorum.MustNew(3, 5), 93)
	att := key.attestationOver(t, DomainOracleRead, [32]byte{1}, [32]byte{2}, 7)
	require.ErrorIs(t, vm.VerifyAttestation(att), ErrUnknownKey)
}

// The signature is checked against the payload recomputed from the
// attestation's own fields, so moving a signature onto different content fails.
func TestAnAttestationsSignatureIsCheckedAgainstItsRecomputedPayload(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 94)
	key.register(t, vm)

	for name, mangle := range map[string]func(*QuantumAttestation){
		"a different subject": func(a *QuantumAttestation) { a.SubjectID = [32]byte{9} },
		"a different root":    func(a *QuantumAttestation) { a.CommitmentRoot = [32]byte{9} },
		"a different epoch":   func(a *QuantumAttestation) { a.Epoch++ },
		"a different domain":  func(a *QuantumAttestation) { a.Domain = DomainOracleRead },
		"a mangled r":         func(a *QuantumAttestation) { a.Signature[0] ^= 0xff },
		"a mangled s":         func(a *QuantumAttestation) { a.Signature[40] ^= 0xff },
	} {
		att := key.attestationOver(t, DomainOracleWrite, [32]byte{1}, [32]byte{2}, 7)
		mangle(att)
		require.ErrorIsf(t, vm.VerifyAttestation(att), ErrBadArtifact, "%s", name)
	}
}

// A signature by a key that is not the registered custodian is refused, even
// when everything the attestation says about itself is consistent.
func TestAnAttestationSignedByTheWrongKeyIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 95)
	key.register(t, vm)
	impostor := newCustody(t, "vault", quorum.MustNew(3, 5), 96)

	att := key.attestationOver(t, DomainSessionComplete, [32]byte{1}, [32]byte{2}, 7)
	payload := ComputeAttestationPayload(att.Domain, att.SubjectID, att.CommitmentRoot, att.Epoch)
	att.Signature = impostor.sign(t, payload[:])
	require.ErrorIs(t, vm.VerifyAttestation(att), ErrBadArtifact)
}

// The recovery byte is not verified against, here as everywhere: a wrong v
// cannot make a good attestation fail, and cannot make a bad one pass.
func TestTheRecoveryByteChangesNoAttestationVerdict(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 99)
	key.register(t, vm)

	att := key.attestationOver(t, DomainOracleRead, [32]byte{1}, [32]byte{2}, 7)
	att.Signature[64] ^= 0xff
	require.NoError(t, vm.VerifyAttestation(att))
}

// -----------------------------------------------------------------------------
// Equivocation
// -----------------------------------------------------------------------------

// Two attestations equivocate when they say different things about the SAME
// subject in the SAME domain at the SAME epoch. Anything else is two facts, not
// a contradiction — which is what makes re-attesting at a later epoch the
// legitimate way a fact changes.
func TestEquivocationIsTwoAnswersToOneQuestion(t *testing.T) {
	base := func() *QuantumAttestation {
		return &QuantumAttestation{
			Domain:         DomainOracleWrite,
			SubjectID:      [32]byte{1},
			CommitmentRoot: [32]byte{2},
			Epoch:          7,
		}
	}

	a, b := base(), base()
	require.False(t, DetectEquivocation(a, b), "the same answer twice is not a contradiction")

	b.CommitmentRoot = [32]byte{3}
	require.True(t, DetectEquivocation(a, b))

	for name, mangle := range map[string]func(*QuantumAttestation){
		"a different domain":  func(x *QuantumAttestation) { x.Domain = DomainOracleRead },
		"a different subject": func(x *QuantumAttestation) { x.SubjectID = [32]byte{9} },
		"a later epoch":       func(x *QuantumAttestation) { x.Epoch = 8 },
	} {
		c := base()
		c.CommitmentRoot = [32]byte{3}
		mangle(c)
		require.Falsef(t, DetectEquivocation(a, c), "%s is a different question, not a contradiction", name)
	}

	require.False(t, DetectEquivocation(nil, a))
	require.False(t, DetectEquivocation(a, nil))
}

// -----------------------------------------------------------------------------
// Bridge transfers
// -----------------------------------------------------------------------------

// One attestation authorises exactly one mint — of that amount, to that
// recipient, on that route, once. Every field the digest commits to is a field
// a verifier can flip to make the signature stop verifying.
func TestABridgeSignatureAuthorisesExactlyOneTransfer(t *testing.T) {
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 97)
	bt := BridgeTransfer{
		SrcChainID: 200201,
		DstChainID: 97368,
		Asset:      [32]byte{'L', 'U', 'X'},
		Amount:     1_000_000,
		Recipient:  [20]byte{1, 2, 3},
		Nonce:      7,
	}
	digest := bt.Digest()
	sig := key.sign(t, digest[:])
	pub := key.rec.GroupPublicKey

	require.True(t, VerifyBridgeAttestation(pub, bt, sig))
	require.True(t, VerifyBridgeAttestation(pub, bt, sig[:64]), "r‖s alone verifies; the recovery id is not checked against")

	for name, mangle := range map[string]func(BridgeTransfer) BridgeTransfer{
		"a different source":      func(x BridgeTransfer) BridgeTransfer { x.SrcChainID++; return x },
		"a different destination": func(x BridgeTransfer) BridgeTransfer { x.DstChainID++; return x },
		"a different asset":       func(x BridgeTransfer) BridgeTransfer { x.Asset[0]++; return x },
		"a different amount":      func(x BridgeTransfer) BridgeTransfer { x.Amount++; return x },
		"a different recipient":   func(x BridgeTransfer) BridgeTransfer { x.Recipient[0]++; return x },
		"a replayed nonce":        func(x BridgeTransfer) BridgeTransfer { x.Nonce++; return x },
	} {
		require.Falsef(t, VerifyBridgeAttestation(pub, mangle(bt), sig), "%s must not verify", name)
		require.NotEqualf(t, digest, mangle(bt).Digest(), "%s must move the digest", name)
	}
}

func TestABridgeSignatureOfTheWrongShapeIsRefused(t *testing.T) {
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 98)
	bt := BridgeTransfer{Amount: 1}
	digest := bt.Digest()
	sig := key.sign(t, digest[:])

	require.False(t, VerifyBridgeAttestation(key.rec.GroupPublicKey, bt, sig[:32]))
	require.False(t, VerifyBridgeAttestation(key.rec.GroupPublicKey, bt, nil))
	require.False(t, VerifyBridgeAttestation(nil, bt, sig))
	require.False(t, VerifyBridgeAttestation(flip(key.rec.GroupPublicKey), bt, sig))
}

// A bridge digest can never be replayed as any other message M signs.
func TestABridgeDigestIsNotAnyOtherMessageMChainSigns(t *testing.T) {
	bt := BridgeTransfer{SrcChainID: 1, DstChainID: 2, Amount: 3, Nonce: 4}
	digest := bt.Digest()

	for domain := range domainSeparators {
		payload := ComputeAttestationPayload(domain, [32]byte{}, [32]byte{}, 0)
		require.NotEqualf(t, digest, payload, "a bridge digest collides with the %s payload", domain)
	}

	// And the tag is really in it: the same fields hashed without the domain
	// produce something else.
	h := sha256.New()
	var b [8]byte
	binary.BigEndian.PutUint32(b[:4], bt.SrcChainID)
	h.Write(b[:4])
	var bare [32]byte
	copy(bare[:], h.Sum(nil))
	require.NotEqual(t, digest, bare)
}

// -----------------------------------------------------------------------------
// Ownership
// -----------------------------------------------------------------------------

// The ownership domain and its separator both come from chains/ownership, which
// is also what every verifier hashes — one constant, so M-Chain and its
// verifiers cannot drift into signing and checking different bytes.
func TestOwnershipIsSignedWithTheVerifiersOwnConstants(t *testing.T) {
	require.Equal(t, ownership.Domain, string(DomainNFTOwnership))

	claim := ownership.Claim{Token: 42, Block: 9}
	payload := ComputeAttestationPayload(DomainNFTOwnership, claim.Subject(), claim.Root(), claim.Block)
	require.NotEqual(t, [32]byte{}, payload)

	// A different token at the same block is a different payload, and the same
	// token at a different block is too — which is what gives equivocation its
	// precise meaning and re-attestation its legitimate one.
	other := ownership.Claim{Token: 43, Block: 9}
	require.NotEqual(t, payload, ComputeAttestationPayload(DomainNFTOwnership, other.Subject(), other.Root(), other.Block))
	later := ownership.Claim{Token: 42, Block: 10}
	require.NotEqual(t, payload, ComputeAttestationPayload(DomainNFTOwnership, later.Subject(), later.Root(), later.Block))
}
