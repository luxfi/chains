// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// party holds a key pair. Every authorization on this chain is a signature, so
// a test that wants one holds the key that makes it — which is the point: the
// service used to build the record itself from a public key the caller named.
type party struct {
	priv *mldsa.PrivateKey
	pub  []byte
}

func newParty(t *testing.T) *party {
	t.Helper()
	priv, err := mldsa.GenerateKey(rand.Reader, KeyMode)
	require.NoError(t, err)
	return &party{priv: priv, pub: priv.PublicKey.Bytes()}
}

// sign signs a record's preimage under a chain's binding. Deterministic, so a
// fixture is the same fixture every run.
func (p *party) sign(t *testing.T, message []byte, bind [32]byte) []byte {
	t.Helper()
	sig, err := p.priv.SignCtxDeterministic(message, bind[:])
	require.NoError(t, err)
	return sig
}

// harness is a booted I-Chain and the parties acting on it.
type harness struct {
	*VM
	db      database.Database
	chainID ids.ID
	network uint32
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, nil) }

func newHarnessWith(t *testing.T, config *Config) *harness {
	t.Helper()
	h := &harness{db: memdb.New(), chainID: ids.GenerateTestID(), network: 1}
	h.VM = h.boot(t, config)
	return h
}

func (h *harness) boot(t *testing.T, config *Config) *VM {
	t.Helper()

	genesis, err := json.Marshal(&Genesis{Timestamp: 1607144400, Config: config})
	require.NoError(t, err)

	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: h.chainID, NetworkID: h.network, Log: log.NoLog{}},
		DB:       h.db,
		Genesis:  genesis,
		ToEngine: make(chan vmcore.Message, 1),
		Log:      log.NoLog{},
	}))
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	return vm
}

// restart boots a second VM over the same records. What the chain accepted, a
// restarted node holds.
func (h *harness) restart(t *testing.T) *VM {
	t.Helper()
	h.VM = h.boot(t, nil)
	return h.VM
}

// identity builds a signed identity for a party.
func (h *harness) identity(t *testing.T, p *party, metadata map[string]string) *Identity {
	t.Helper()
	i := &Identity{
		PublicKey: p.pub,
		Created:   time.Unix(0, 1).UTC(),
		Metadata:  metadata,
	}
	i.ID = identityID(p.pub)
	i.Signature = p.sign(t, i.signable(), h.bind)
	return i
}

// issuer builds a signed issuer for a party.
func (h *harness) issuer(t *testing.T, p *party, name string) *Issuer {
	t.Helper()
	s := &Issuer{
		Name:      name,
		PublicKey: p.pub,
		Types:     []string{"VerifiableCredential"},
		CreatedAt: time.Unix(0, 1).UTC(),
	}
	s.ID = issuerID(p.pub)
	s.Signature = p.sign(t, s.signable(), h.bind)
	return s
}

// credential builds a credential signed by the issuing party.
func (h *harness) credential(t *testing.T, by *party, issuer, subject ids.ID, expires time.Time) *Credential {
	t.Helper()
	c := &Credential{
		Type:           []string{"VerifiableCredential"},
		Issuer:         issuer,
		Subject:        subject,
		IssuanceDate:   time.Unix(0, 2).UTC(),
		ExpirationDate: expires,
		Claims:         map[string]interface{}{"degree": "maths"},
	}
	c.Signature = by.sign(t, c.signable(), h.bind)
	c.ID = tag("identityvm/credential", c.signable())
	return c
}

// revocation builds a revocation signed by the revoking party.
func (h *harness) revocation(t *testing.T, by *party, credID, revoker ids.ID) *Revocation {
	t.Helper()
	r := &Revocation{
		CredentialID: credID,
		RevokedBy:    revoker,
		RevokedAt:    time.Unix(0, 3).UTC(),
		Reason:       "superseded",
	}
	r.Signature = by.sign(t, r.signable(), h.bind)
	return r
}

// accept submits changes, builds the block that carries them, verifies it and
// accepts it — the whole path a change takes to become state.
func (h *harness) accept(t *testing.T, changes ...*Change) *Block {
	t.Helper()
	ctx := context.Background()

	for _, c := range changes {
		require.NoError(t, h.Submit(c))
	}

	built, err := h.BuildBlock(ctx)
	require.NoError(t, err)
	blk := built.(*Block)
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))
	return blk
}

// enrolled registers an issuer, a subject, and a credential from one to the
// other — the shape most tests start from.
func (h *harness) enrolled(t *testing.T) (issuer, subject *party, cred *Credential) {
	t.Helper()
	issuer, subject = newParty(t), newParty(t)

	issuerRecord := h.issuer(t, issuer, "registry")
	subjectRecord := h.identity(t, subject, nil)
	h.accept(t, &Change{Issuer: issuerRecord}, &Change{Identity: subjectRecord})

	cred = h.credential(t, issuer, issuerRecord.ID, subjectRecord.ID, time.Now().Add(time.Hour))
	h.accept(t, &Change{Credential: cred})
	return issuer, subject, cred
}
