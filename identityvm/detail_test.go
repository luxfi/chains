// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

func TestBlockAccessors(t *testing.T) {
	h := newHarness(t)
	b := &Block{
		ParentID_:      ids.ID{2},
		BlockHeight:    5,
		BlockTimestamp: 1_700_000_000,
		vm:             h.VM,
	}
	require.Equal(t, ids.ID{2}, b.Parent())
	require.Equal(t, ids.ID{2}, b.ParentID())
	require.EqualValues(t, 5, b.Height())
	require.Equal(t, time.Unix(1_700_000_000, 0), b.Timestamp())
	require.Zero(t, b.records())

	require.NotNil(t, h.FeePolicy())
	require.NoError(t, h.gateUserTx(fee.MinTxFeeFloor))
	require.Error(t, h.gateUserTx(0))
}

// A credential lapses when its expiry passes, whatever the revocation set says.
func TestACredentialLapses(t *testing.T) {
	h := newHarness(t)

	issuer, subject := newParty(t), newParty(t)
	issuerRecord := h.issuer(t, issuer, "registry")
	subjectRecord := h.identity(t, subject, nil)
	h.accept(t, &Change{Issuer: issuerRecord}, &Change{Identity: subjectRecord})

	brief := h.credential(t, issuer, issuerRecord.ID, subjectRecord.ID, time.Now().Add(40*time.Millisecond))
	h.accept(t, &Change{Credential: brief})
	require.NoError(t, h.Verify(brief.ID))

	time.Sleep(60 * time.Millisecond)
	require.ErrorIs(t, h.Verify(brief.ID), errCredentialExpired)

	_, status, err := h.Credential(brief.ID)
	require.NoError(t, err)
	require.Equal(t, CredentialExpired, status)
}

// Claims a credential cannot carry are refused, and a claims document that
// cannot be encoded is not a document.
func TestClaimsAreBounded(t *testing.T) {
	h := newHarnessWith(t, &Config{MaxClaims: 2})

	issuer, subject := newParty(t), newParty(t)
	issuerRecord := h.issuer(t, issuer, "registry")
	subjectRecord := h.identity(t, subject, nil)
	h.accept(t, &Change{Issuer: issuerRecord}, &Change{Identity: subjectRecord})

	cred := &Credential{
		Issuer:         issuerRecord.ID,
		Subject:        subjectRecord.ID,
		IssuanceDate:   time.Unix(0, 1).UTC(),
		ExpirationDate: time.Now().Add(time.Hour),
		Claims:         map[string]interface{}{"a": "1", "b": "2", "c": "3"},
	}
	cred.Signature = issuer.sign(t, cred.signable(), h.bind)
	cred.ID = tag("identityvm/credential", cred.signable())
	require.ErrorIs(t, h.Submit(&Change{Credential: cred}), errTooManyClaims)

	// A claims map json cannot encode encodes as nothing, and the credential
	// the chain records is the one whose id was taken over those bytes.
	require.Nil(t, marshalClaims(map[string]interface{}{"chan": make(chan int)}))

	// The Proof artifact reports what it cannot describe.
	_, _, cred2 := h.enrolled(t)
	held, _, err := h.Credential(cred2.ID)
	require.NoError(t, err)
	held.Claims = map[string]interface{}{"chan": make(chan int)}
	_, err = h.Proof(cred2.ID, nil)
	require.Error(t, err)
}

// A revoker the chain has no key for cannot revoke, even naming the right id.
func TestARevokerNeedsAKeyOnTheChain(t *testing.T) {
	h := newHarnessWith(t, &Config{AllowSelfIssue: true})

	// A self-issued credential whose issuer is an identity, then the identity
	// removed from the caches: the chain has the credential and not the key.
	p := newParty(t)
	record := h.identity(t, p, nil)
	h.accept(t, &Change{Identity: record})
	cred := h.credential(t, p, record.ID, record.ID, time.Now().Add(time.Hour))
	h.accept(t, &Change{Credential: cred})

	h.chain.Lock()
	delete(h.identities, record.ID)
	h.chain.Unlock()

	require.ErrorIs(t, h.Submit(&Change{Revocation: h.revocation(t, p, cred.ID, record.ID)}), errUnknownIdentity)

	var pending view
	pending.vm = h.VM
	_, ok := pending.key(ids.GenerateTestID())
	require.False(t, ok)
}

// A block introducing the same issuer or the same credential twice claims one
// name twice, whichever list it is in.
func TestABlockCannotClaimOneNameTwice(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	issuer := newParty(t)
	issuerRecord := h.issuer(t, issuer, "registry")
	subject := newParty(t)
	subjectRecord := h.identity(t, subject, nil)
	cred := h.credential(t, issuer, issuerRecord.ID, subjectRecord.ID, time.Now().Add(time.Hour))

	tip, height := h.chain.Tip()
	twice := &Block{
		ParentID_:      tip,
		BlockHeight:    height + 1,
		BlockTimestamp: time.Now().Unix(),
		Identities:     []*Identity{subjectRecord},
		Issuers:        []*Issuer{issuerRecord, issuerRecord},
		vm:             h.VM,
	}
	require.ErrorIs(t, twice.Verify(ctx), errExists)

	twice.Issuers = []*Issuer{issuerRecord}
	twice.Credentials = []*Credential{cred, cred}
	twice.bytes, twice.ID_ = nil, ids.Empty
	require.ErrorIs(t, twice.Verify(ctx), errExists)
}

// Assembly drops one change of each kind that it cannot build, leaving the
// block it can.
func TestAssemblyDropsEachKind(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	good := h.identity(t, newParty(t), nil)
	require.NoError(t, h.Submit(&Change{Identity: good}))

	// Reaching past the door: a peer's gossip, or a door that stops checking.
	for _, bad := range []*Change{
		{Issuer: &Issuer{ID: ids.GenerateTestID(), PublicKey: []byte("x")}},
		{Credential: &Credential{ID: ids.GenerateTestID()}},
		{Revocation: &Revocation{CredentialID: ids.GenerateTestID()}},
	} {
		require.NoError(t, h.pending.Add(bad))
	}

	built, err := h.BuildBlock(ctx)
	require.NoError(t, err)
	blk := built.(*Block)
	require.Len(t, blk.Identities, 1)
	require.Empty(t, blk.Issuers)
	require.Empty(t, blk.Credentials)
	require.Empty(t, blk.Revocations)
	require.NoError(t, blk.Verify(ctx))
}

// A chain that cannot read its own tip does not know where it is.
func TestOpenRefusesAnUnreadableTip(t *testing.T) {
	db := memdb.New()
	require.NoError(t, db.Put([]byte("chain/tip"), []byte("not an id")))

	genesis, err := json.Marshal(&Genesis{Timestamp: 1})
	require.NoError(t, err)

	err = (&VM{}).Initialize(context.Background(), vmcore.Init{
		Runtime: &runtime.Runtime{ChainID: ids.ID{8}, Log: log.NoLog{}},
		DB:      db,
		Genesis: genesis,
		Log:     log.NoLog{},
	})
	require.ErrorContains(t, err, "tip")
}
