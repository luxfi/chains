// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/luxfi/chains/artifacts"
	"github.com/luxfi/ids"
)

// Submit queues one state change for a block. Nothing here writes state: a
// change becomes state when a block carrying it is accepted, on every node,
// which is what "the chain agrees" means. CreateIdentity, RegisterIssuer and
// RevokeCredential used to write straight to the base database on whichever
// node received the call, so no two nodes held the same identity set — and a
// block naming an issuer verified on the node that registered it and nowhere
// else.
func (vm *VM) Submit(c *Change) error {
	vm.chain.Lock()
	defer vm.chain.Unlock()

	// Refuse at the door what no block could carry. The pool is bounded, so a
	// change that can never be built is a slot nothing else can use.
	block := &Block{vm: vm, BlockTimestamp: time.Now().Unix()}
	block.add(c)
	if err := vm.check(block); err != nil {
		return err
	}
	return vm.pending.Add(c)
}

// Identity returns an identity by id.
func (vm *VM) Identity(id ids.ID) (*Identity, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	identity, ok := vm.identities[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errUnknownIdentity, id)
	}
	return identity, nil
}

// Resolve returns the identity a DID names. The DID is derived from the id, so
// this is a lookup rather than the scan of every identity it used to be —
// which returned whichever of two identical DIDs Go's map iteration reached
// first.
func (vm *VM) Resolve(did string) (*Identity, error) {
	id, err := identityFrom(did)
	if err != nil {
		return nil, err
	}
	return vm.Identity(id)
}

// Issuer returns an issuer by id.
func (vm *VM) Issuer(id ids.ID) (*Issuer, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	issuer, ok := vm.issuers[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errUnknownIssuer, id)
	}
	return issuer, nil
}

// Issuers returns every issuer the chain holds, in id order. Map order is not
// an order, and an RPC that answers differently each call is one a client
// cannot page through.
func (vm *VM) Issuers() []*Issuer {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	out := make([]*Issuer, 0, len(vm.issuers))
	for _, issuer := range vm.issuers {
		out = append(out, issuer)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.Compare(out[j].ID) < 0 })
	return out
}

// Credential returns a credential and its status as of now.
func (vm *VM) Credential(id ids.ID) (*Credential, string, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	cred, ok := vm.credentials[id]
	if !ok {
		return nil, "", fmt.Errorf("%w: %s", errUnknownCredential, id)
	}
	return cred, vm.status(cred), nil
}

// Verify reports whether a credential is usable now: recorded, not revoked,
// not expired.
//
// It used to also accept a "ZK proof" whose only test was that it was not
// empty, which is a length check standing in for a verdict. What makes a
// credential this chain's is the issuer's signature over it, and check()
// refuses a block carrying one without it.
func (vm *VM) Verify(id ids.ID) error {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	cred, ok := vm.credentials[id]
	if !ok {
		return fmt.Errorf("%w: %s", errUnknownCredential, id)
	}
	switch vm.status(cred) {
	case CredentialRevoked:
		return fmt.Errorf("%w: %s", errCredentialRevoked, id)
	case CredentialExpired:
		return fmt.Errorf("%w: %s", errCredentialExpired, id)
	}
	return nil
}

// Credential states. A credential's state is DERIVED from the revocation set
// and its own expiry; it is not a field that has to be kept in step with both.
const (
	CredentialActive  = "active"
	CredentialRevoked = "revoked"
	CredentialExpired = "expired"
)

// status is what the chain says about a credential now. Caller holds the lock.
func (vm *VM) status(c *Credential) string {
	if _, revoked := vm.revocations[c.ID]; revoked {
		return CredentialRevoked
	}
	if !c.ExpirationDate.After(time.Now()) {
		return CredentialExpired
	}
	return CredentialActive
}

// Proof builds a selective-disclosure artifact for a credential. It presents
// what the chain holds; the disclosure proof itself is the caller's.
func (vm *VM) Proof(id ids.ID, disclosure []byte) (*artifacts.CredentialProof, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	cred, ok := vm.credentials[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errUnknownCredential, id)
	}

	claims, err := json.Marshal(cred.Claims)
	if err != nil {
		return nil, err
	}

	credType := ""
	if len(cred.Type) > 0 {
		credType = cred.Type[0]
	}

	var revoked uint64
	if _, ok := vm.revocations[id]; ok {
		revoked = 1
	}

	return &artifacts.CredentialProof{
		Version_:         1,
		SigSuite_:        artifacts.SuitePQOnly,
		CredentialID:     id,
		IssuerDID:        didPrefix + cred.Issuer.String(),
		SubjectDID:       didPrefix + cred.Subject.String(),
		CredType:         credType,
		ClaimsCommitment: sha256.Sum256(claims),
		SelectiveProof:   disclosure,
		IssuedAt:         cred.IssuanceDate,
		ExpiresAt:        cred.ExpirationDate,
		RevocationEpoch:  revoked,
	}, nil
}
