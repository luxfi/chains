// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/chains/mpcvm/fhe"
)

// CIPHERTEXT-BODY INVARIANT (the F-Chain's reason to exist).
//
// F-Chain is the COORDINATION plane for confidential compute. It stores the
// PUBLIC coordinates of an encrypted value — a 32-byte handle, the digest of
// the ciphertext body, who owns it, who may act on it, and which threshold
// decryptions were asked for and answered. It never stores a ciphertext body,
// never holds the FHE secret key, and never holds a decryption share: the
// bodies live in off-chain storage and the key shares live on the threshold
// committee, whose members are named here only by public node ID and public
// signing key.
//
// Three things hold that line, because none of them holds it alone.
//
// The four record types below are everything F persists, and every field of
// them is a public coordinate: hashes, addresses, bitmasks, sizes, epochs,
// timestamps. invariant_test.go PINS that field list exactly — a field added,
// removed or retyped fails the test until someone writes it down, which is what
// makes "should F be storing that?" a question somebody has to answer rather
// than one omission answers.
//
// Second, a transaction's payload decodes as EXACTLY its schema: a member the
// schema does not describe is refused, not ignored (transaction.go decode). A
// megabyte of ciphertext body in a "body" member used to decode fine, cost
// nothing extra, and come back out of the block store.
//
// Third, the bytes a transaction does carry are bounded and priced by the byte
// (gas.go GasPerByte), so bulk is refused before it is stored and paid for when
// it is. A reflective walk over field names is a fourth check and the weakest —
// a denylist cannot be complete — so it is kept as a tripwire for new types,
// not relied on.
//
// The records embed the FHE runtime's own types (github.com/luxfi/chains/
// mpcvm/fhe) so the chain and the runtime speak one vocabulary. F owns the
// PERSISTENCE, because persistence in a chain is consensus: every field F
// writes is derived from the accepting block (its timestamp, its transactions)
// and never from a validator's wall clock, so two validators replaying the
// same block write the same bytes. The runtime's own Registry stamps
// time.Now() and is the right store for the off-chain daemon; it is the wrong
// store for a state root. See vm.go.

// Permit lifecycle states. A permit is the only revocable thing on F: a
// registration is a fact about a ciphertext that exists, and a fact does not
// stop being true, whereas the authority to act on it can be withdrawn at any
// time. Access is therefore controlled entirely by granting and revoking
// permits, and there is no second place to look.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// CiphertextRecord is F's record of one registered encrypted value. The body it
// describes is off-chain; Digest binds this record to it, and Handle — derived
// from Digest and Scheme — is the name every other operation and every off-chain
// consumer uses to refer to it.
type CiphertextRecord struct {
	fhe.CiphertextMeta          // Handle, Owner, Type, Level, Epoch, RegisteredAt, Size, ChainID
	Scheme             string   `json:"scheme"` // FHE scheme + ring dimension (drives gas)
	Digest             [32]byte `json:"digest"` // hash of the off-chain ciphertext body
}

// PermitRecord is a capability: the grantor lets the grantee perform a set of
// operations on one handle until Expiry. It is the only thing that authorizes a
// decryption request, so it is checked at admission, in consensus, and again at
// application.
type PermitRecord struct {
	fhe.Permit        // PermitID, Handle, Grantee, Grantor, Operations, Expiry, CreatedAt, Attestation, ChainID
	Status     string `json:"status"`
}

// DecryptRecord is a threshold-decryption request and the committee's answer to
// it. F does not decrypt: the committee combines its shares off-chain and each
// member ATTESTS the resulting public handle here. The request completes when
// Threshold distinct members attest the SAME result, which is why Attestations
// is a list of (member, result) pairs and not a single field — a lone member
// posting a wrong result buys nothing but its own burnt fee, and cannot stall
// the honest majority.
type DecryptRecord struct {
	fhe.DecryptRequest               // RequestID, CiphertextHandle, Requester, Callback, ..., Status, ResultHandle
	PermitID           [32]byte      `json:"permitId"`
	Attestations       []Attestation `json:"attestations"`
}

// Attestation is one committee member's vote for one 32-byte value. It backs
// both of F's threshold decisions — which plaintext handle a decryption
// produced, and which committee the next epoch has — because both are the same
// question: did Threshold distinct members say the same thing?
type Attestation struct {
	Member fee.Account `json:"member"`
	Value  [32]byte    `json:"value"`
}

// EpochRecord is the committee that holds the FHE key shares for one epoch,
// together with the network public key they jointly generated. Epoch 0 comes
// from genesis; every later epoch is installed by TxAdvanceEpoch once Threshold
// members of the CURRENT committee attest the same successor.
type EpochRecord struct {
	fhe.EpochInfo               // Epoch, StartTime, EndTime, Committee, Threshold, PublicKey, Status
	Attestations  []Attestation `json:"attestations"` // approvals of the NEXT epoch, tallied here
}

// tally counts how many DISTINCT members attested value, which is the only
// question a threshold decision asks.
func tally(as []Attestation, value [32]byte) int {
	seen := make(map[fee.Account]struct{}, len(as))
	for _, a := range as {
		if a.Value != value {
			continue
		}
		seen[a.Member] = struct{}{}
	}
	return len(seen)
}

// vote records member's choice, REPLACING whatever it chose before. One member,
// one vote — so a member can neither raise a value's count by repeating itself
// nor hedge across two values — but a vote is not spent by being cast.
//
// It used to be spent. A committee that split its vote could then never
// converge: no proposal reached the threshold, nobody could change their mind,
// nothing timed out, and the tally cleared only on the advance that could not
// happen. At unanimity one member wedged rotation alone; below it, an honest
// race between two DKG results did the same with no adversary at all.
func vote(as []Attestation, member fee.Account, value [32]byte) []Attestation {
	for i := range as {
		if as[i].Member == member {
			as[i].Value = value
			return as
		}
	}
	return append(as, Attestation{Member: member, Value: value})
}

// memberOf reports whether acct is a committee member of this epoch. A member's
// F-Chain account is derived from its PUBLIC signing key by exactly the
// derivation that authenticates a transaction payer (transaction.go
// addressOf), so committee membership and payer identity cannot disagree.
func (e *EpochRecord) memberOf(acct fee.Account) bool {
	for _, m := range e.Committee {
		if addressOf(m.PublicKey) == acct {
			return true
		}
	}
	return false
}

// committeeOrder is the canonical ordering of a committee: ascending node ID.
// A committee is hashed to decide an epoch advance, so two members proposing
// the same set must produce the same bytes — the order is part of the value.
func committeeOrder(c []fhe.CommitteeMember) bool {
	return sort.SliceIsSorted(c, func(i, j int) bool {
		return c[i].NodeID.Compare(c[j].NodeID) < 0
	})
}

// committeeDigest is the value committee members attest when advancing an
// epoch. It hashes the SEMANTIC proposal — epoch, threshold, network public
// key, and the canonically ordered members — rather than the transaction's
// payload bytes, so two members whose clients encode the same proposal
// differently still vote for the same thing.
func committeeDigest(epoch uint64, threshold int, publicKey []byte, c []fhe.CommitteeMember) [32]byte {
	h := sha256.New()
	h.Write([]byte("fhevm/epoch/"))
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], epoch)
	h.Write(u8[:])
	binary.BigEndian.PutUint64(u8[:], uint64(threshold))
	h.Write(u8[:])
	writeLenPrefixed(h, publicKey)
	binary.BigEndian.PutUint64(u8[:], uint64(len(c)))
	h.Write(u8[:])
	for _, m := range c {
		id := m.NodeID
		h.Write(id[:])
		writeLenPrefixed(h, m.PublicKey)
		binary.BigEndian.PutUint64(u8[:], m.Weight)
		h.Write(u8[:])
		binary.BigEndian.PutUint64(u8[:], uint64(m.Index))
		h.Write(u8[:])
	}
	return [32]byte(h.Sum(nil))
}

// writeLenPrefixed writes len(b) then b, so concatenated fields cannot be
// re-split at a different boundary to forge a colliding digest.
func writeLenPrefixed(h interface{ Write([]byte) (int, error) }, b []byte) {
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], uint64(len(b)))
	_, _ = h.Write(u8[:])
	_, _ = h.Write(b)
}

// deriveHandle names a ciphertext by its CONTENT: the digest of the off-chain
// body under a given scheme. Two registrations of the same body under the same
// scheme therefore collide by construction and the second is refused, and a
// handle cannot be squatted by someone who does not have the body to hash.
func deriveHandle(digest [32]byte, scheme string) [32]byte {
	h := sha256.New()
	h.Write([]byte("fhevm/ct/"))
	h.Write(digest[:])
	writeLenPrefixed(h, []byte(scheme))
	return [32]byte(h.Sum(nil))
}

// derivePermitID names a grant by everything that distinguishes it, including
// the grantor's nonce, so a grantor may re-grant the same capability later
// without colliding with the earlier permit.
func derivePermitID(handle [32]byte, grantor, grantee fee.Account, ops uint32, expiry int64, nonce uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte("fhevm/permit/"))
	h.Write(handle[:])
	h.Write(grantor[:])
	h.Write(grantee[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], uint64(ops))
	h.Write(u8[:])
	binary.BigEndian.PutUint64(u8[:], uint64(expiry))
	h.Write(u8[:])
	binary.BigEndian.PutUint64(u8[:], nonce)
	h.Write(u8[:])
	return [32]byte(h.Sum(nil))
}

// deriveRequestID names a decryption request by handle, requester and the
// requester's nonce — all fields the payer signed — so the id is deterministic
// across validators and unique per request.
func deriveRequestID(handle [32]byte, requester fee.Account, nonce uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte("fhevm/decrypt/"))
	h.Write(handle[:])
	h.Write(requester[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], nonce)
	h.Write(u8[:])
	return [32]byte(h.Sum(nil))
}
