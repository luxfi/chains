// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"fmt"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

// Record keys. One prefix per kind; a record lives at prefix ‖ id.
var (
	identityPrefix   = []byte("id:")
	issuerPrefix     = []byte("issuer:")
	credentialPrefix = []byte("cred:")
	revocationPrefix = []byte("revoke:")
)

func identityKey(id ids.ID) []byte   { return key(identityPrefix, id) }
func issuerKey(id ids.ID) []byte     { return key(issuerPrefix, id) }
func credentialKey(id ids.ID) []byte { return key(credentialPrefix, id) }
func revocationKey(id ids.ID) []byte { return key(revocationPrefix, id) }

func key(prefix []byte, id ids.ID) []byte {
	return append(append(make([]byte, 0, len(prefix)+32), prefix...), id[:]...)
}

// reload rebuilds the caches from the records.
//
// It runs at boot and again whenever a block's writes are discarded, so a
// cache that had already recorded that block's records stops claiming them.
// Nothing rebuilt them before: a restarted node held only what genesis named,
// and answered "unknown identity" for every identity it had itself accepted.
func (vm *VM) reload() error {
	identities, err := load(vm.chain.View(), identityPrefix, parseIdentity)
	if err != nil {
		return err
	}
	issuers, err := load(vm.chain.View(), issuerPrefix, parseIssuer)
	if err != nil {
		return err
	}
	credentials, err := load(vm.chain.View(), credentialPrefix, parseCredential)
	if err != nil {
		return err
	}
	revocations, err := load(vm.chain.View(), revocationPrefix, parseRevocation)
	if err != nil {
		return err
	}

	vm.identities = index(identities, func(i *Identity) ids.ID { return i.ID })
	vm.issuers = index(issuers, func(i *Issuer) ids.ID { return i.ID })
	vm.credentials = index(credentials, func(c *Credential) ids.ID { return c.ID })
	vm.revocations = index(revocations, func(r *Revocation) ids.ID { return r.CredentialID })
	return nil
}

// load reads every record under a prefix. A record that does not decode is a
// failure, not a record to skip: the chain wrote it, so a node that cannot
// read it back does not hold the state it believes it holds.
func load[T any](db database.Database, prefix []byte, parse func([]byte) (T, error)) ([]T, error) {
	it := db.NewIteratorWithPrefix(prefix)
	defer it.Release()

	var out []T
	for it.Next() {
		v, err := parse(it.Value())
		if err != nil {
			return nil, fmt.Errorf("identityvm: record %x: %w", it.Key(), err)
		}
		out = append(out, v)
	}
	return out, it.Error()
}

func index[T any](items []T, id func(T) ids.ID) map[ids.ID]T {
	out := make(map[ids.ID]T, len(items))
	for _, item := range items {
		out[id(item)] = item
	}
	return out
}

// check is the ONE predicate. Assembly asks it of a block it is building and
// consensus asks it of a block off the wire, so a proposer cannot assemble
// what its peers refuse — which is a halt, free, for whoever submits it.
//
// Records are checked in order against what the chain holds PLUS what this
// block introduces BEFORE them, so a credential may name an identity the same
// block creates, and one that names an identity the block creates after it is
// a credential with no subject. Each kind has its own name space: a revocation
// is named by the credential it withdraws, which is not a second claim on that
// name.
func (vm *VM) check(b *Block) error {
	pending := &view{
		vm:          vm,
		identities:  make(map[ids.ID]*Identity, len(b.Identities)),
		issuers:     make(map[ids.ID]*Issuer, len(b.Issuers)),
		credentials: make(map[ids.ID]*Credential, len(b.Credentials)),
		revoked:     make(map[ids.ID]struct{}, len(b.Revocations)),
	}

	for _, identity := range b.Identities {
		if err := vm.checkIdentity(identity); err != nil {
			return err
		}
		if _, held := pending.identity(identity.ID); held {
			return fmt.Errorf("%w: identity %s", errExists, identity.ID)
		}
		pending.identities[identity.ID] = identity
	}

	for _, issuer := range b.Issuers {
		if err := vm.checkIssuer(issuer); err != nil {
			return err
		}
		if _, held := pending.issuer(issuer.ID); held {
			return fmt.Errorf("%w: issuer %s", errExists, issuer.ID)
		}
		pending.issuers[issuer.ID] = issuer
	}

	for _, cred := range b.Credentials {
		if err := vm.checkCredential(cred, b, pending); err != nil {
			return err
		}
		if _, held := pending.credential(cred.ID); held {
			return fmt.Errorf("%w: credential %s", errExists, cred.ID)
		}
		pending.credentials[cred.ID] = cred
	}

	for _, rev := range b.Revocations {
		if err := vm.checkRevocation(rev, pending); err != nil {
			return err
		}
		if pending.isRevoked(rev.CredentialID) {
			return fmt.Errorf("%w: revocation of %s", errExists, rev.CredentialID)
		}
		pending.revoked[rev.CredentialID] = struct{}{}
	}

	return nil
}

// view is the chain's state plus what a block introduces before the record
// being checked. Four name spaces, because a revocation named by a credential
// id is not a second credential.
type view struct {
	vm          *VM
	identities  map[ids.ID]*Identity
	issuers     map[ids.ID]*Issuer
	credentials map[ids.ID]*Credential
	revoked     map[ids.ID]struct{}
}

func (v *view) identity(id ids.ID) (*Identity, bool) {
	if i, ok := v.vm.identities[id]; ok {
		return i, true
	}
	i, ok := v.identities[id]
	return i, ok
}

func (v *view) issuer(id ids.ID) (*Issuer, bool) {
	if s, ok := v.vm.issuers[id]; ok {
		return s, true
	}
	s, ok := v.issuers[id]
	return s, ok
}

func (v *view) credential(id ids.ID) (*Credential, bool) {
	if c, ok := v.vm.credentials[id]; ok {
		return c, true
	}
	c, ok := v.credentials[id]
	return c, ok
}

func (v *view) isRevoked(id ids.ID) bool {
	if _, ok := v.vm.revocations[id]; ok {
		return true
	}
	_, ok := v.revoked[id]
	return ok
}

// key finds the public key of an issuer or an identity: a revoker is one or
// the other.
func (v *view) key(id ids.ID) ([]byte, bool) {
	if s, ok := v.issuer(id); ok {
		return s.PublicKey, true
	}
	if i, ok := v.identity(id); ok {
		return i.PublicKey, true
	}
	return nil, false
}

// An identity is its key: the id is derived from the public key, and the
// signature proves the key is held. Registering a DID therefore names a key
// you have, and cannot name an id someone else already holds.
func (vm *VM) checkIdentity(i *Identity) error {
	if i.ID != identityID(i.PublicKey) {
		return fmt.Errorf("%w: identity %s", errWrongID, i.ID)
	}
	return verify(i.PublicKey, i.signable(), i.Signature, vm.bind[:])
}

// An issuer proves it holds its key, and the chain admits it only if its
// allowlist is empty or names it. TrustedIssuers used to be loaded and never
// read, so anyone who paid the fee became a trusted issuer.
func (vm *VM) checkIssuer(s *Issuer) error {
	if s.ID != issuerID(s.PublicKey) {
		return fmt.Errorf("%w: issuer %s", errWrongID, s.ID)
	}
	if len(vm.config.TrustedIssuers) > 0 && !contains(vm.config.TrustedIssuers, s.ID) {
		return fmt.Errorf("%w: %s is not a trusted issuer", errNotIssuer, s.ID)
	}
	return verify(s.PublicKey, s.signable(), s.Signature, vm.bind[:])
}

// A credential is signed by the key of the party that issued it, and names a
// subject the chain has. Its id is the hash of what it says, so the same
// credential has one id everywhere and no two credentials share one.
func (vm *VM) checkCredential(c *Credential, b *Block, pending *view) error {
	if c.ID != tag("identityvm/credential", c.signable()) {
		return fmt.Errorf("%w: credential %s", errWrongID, c.ID)
	}
	if len(c.Claims) > vm.config.MaxClaims {
		return fmt.Errorf("%w: %d claims, the bound is %d", errTooManyClaims, len(c.Claims), vm.config.MaxClaims)
	}

	// Expiry is judged against the BLOCK's clock, not the wall clock. The wall
	// clock makes the verdict depend on when a node happens to verify: the same
	// block is valid before the expiry and invalid after it, and a node
	// replaying history during bootstrap rejects every block whose credentials
	// have since lapsed.
	if !c.ExpirationDate.After(time.Unix(b.BlockTimestamp, 0)) {
		return fmt.Errorf("%w: credential %s", errCredentialExpired, c.ID)
	}

	subject, ok := pending.identity(c.Subject)
	if !ok {
		return fmt.Errorf("%w: subject %s", errUnknownIdentity, c.Subject)
	}

	// The issuer's key signs the credential. A chain that allows self-issue
	// lets an identity make a claim about itself, signed by its own key —
	// which is the only party a chain with no record of the issuer can check.
	if issuer, ok := pending.issuer(c.Issuer); ok {
		return verify(issuer.PublicKey, c.signable(), c.Signature, vm.bind[:])
	}
	if !vm.config.AllowSelfIssue {
		return fmt.Errorf("%w: %s", errNotIssuer, c.Issuer)
	}
	if c.Issuer != c.Subject {
		return fmt.Errorf("%w: %s is neither a known issuer nor the subject", errNotIssuer, c.Issuer)
	}
	return verify(subject.PublicKey, c.signable(), c.Signature, vm.bind[:])
}

// A revocation is signed by the credential's issuer or its subject. RevokedBy
// used to be a bare id compared against those two, both of which the chain
// publishes — so revoking someone's credential was pasting their id into the
// request.
func (vm *VM) checkRevocation(r *Revocation, pending *view) error {
	cred, ok := pending.credential(r.CredentialID)
	if !ok {
		return fmt.Errorf("%w: %s", errUnknownCredential, r.CredentialID)
	}
	if r.RevokedBy != cred.Issuer && r.RevokedBy != cred.Subject {
		return fmt.Errorf("%w: %s is neither the issuer nor the subject", errNotAuthorized, r.RevokedBy)
	}

	signer, ok := pending.key(r.RevokedBy)
	if !ok {
		return fmt.Errorf("%w: revoker %s", errUnknownIdentity, r.RevokedBy)
	}
	return verify(signer, r.signable(), r.Signature, vm.bind[:])
}

func contains(haystack []ids.ID, needle ids.ID) bool {
	for _, id := range haystack {
		if id == needle {
			return true
		}
	}
	return false
}
