// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// A block's Identities and Revocations were verified by NOTHING and applied by
// Publish anyway. A peer's block naming {victim's id, attacker's key} took over
// the victim's DID, and one naming any credential revoked it. Nothing else
// produced either list.
func TestABlockCannotHijackAnIdentity(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	victim := newParty(t)
	victimRecord := h.identity(t, victim, map[string]string{"who": "victim"})
	h.accept(t, &Change{Identity: victimRecord})

	// The attacker's block claims the victim's id for its own key.
	attacker := newParty(t)
	forged := &Identity{
		ID:        victimRecord.ID,
		PublicKey: attacker.pub,
		Created:   time.Unix(0, 9).UTC(),
	}
	forged.Signature = attacker.sign(t, forged.signable(), h.bind)

	tip, height := h.chain.Tip()
	blk := &Block{
		ParentID_:      tip,
		BlockHeight:    height + 1,
		BlockTimestamp: time.Now().Unix(),
		Identities:     []*Identity{forged},
		vm:             h.VM,
	}
	require.ErrorIs(t, blk.Verify(ctx), errWrongID,
		"an identity's id is a hash of its key, so it cannot name someone else's")

	// Even signing for its own id does not overwrite an identity the chain
	// already holds: there is no update path, so a second registration of the
	// same id is a second identity, which is not a thing.
	again := h.identity(t, victim, map[string]string{"who": "attacker"})
	blk.Identities = []*Identity{again}
	blk.bytes, blk.ID_ = nil, ids.Empty
	require.ErrorIs(t, blk.Verify(ctx), errExists)

	held, err := h.Identity(victimRecord.ID)
	require.NoError(t, err)
	require.Equal(t, victim.pub, held.PublicKey)
	require.Equal(t, "victim", held.Metadata["who"])
}

// Revoking someone's credential used to be pasting their id into the request:
// RevokedBy was compared against the credential's issuer and subject, both of
// which the chain publishes.
func TestRevocationNeedsTheRevokersKey(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	issuer, subject, cred := h.enrolled(t)
	require.NoError(t, h.Verify(cred.ID))

	// An attacker names the issuer — a public id — and signs with its own key.
	attacker := newParty(t)
	forged := &Revocation{
		CredentialID: cred.ID,
		RevokedBy:    cred.Issuer,
		RevokedAt:    time.Unix(0, 4).UTC(),
	}
	forged.Signature = attacker.sign(t, forged.signable(), h.bind)
	require.ErrorIs(t, h.Submit(&Change{Revocation: forged}), errNotAuthorized)

	// A party with no relation to the credential is refused before any
	// signature is checked.
	stranger := h.identity(t, attacker, nil)
	h.accept(t, &Change{Identity: stranger})
	unrelated := h.revocation(t, attacker, cred.ID, stranger.ID)
	require.ErrorIs(t, h.Submit(&Change{Revocation: unrelated}), errNotAuthorized)

	require.NoError(t, h.Verify(cred.ID), "nothing has revoked it")

	// The issuer can. So can the subject.
	h.accept(t, &Change{Revocation: h.revocation(t, issuer, cred.ID, cred.Issuer)})
	require.ErrorIs(t, h.Verify(cred.ID), errCredentialRevoked)

	_, status, err := h.Credential(cred.ID)
	require.NoError(t, err)
	require.Equal(t, CredentialRevoked, status)

	// And one credential is revoked once.
	require.ErrorIs(t, h.Submit(&Change{Revocation: h.revocation(t, subject, cred.ID, cred.Subject)}), errExists)
	_ = ctx
}

// A credential is signed by the key of the party that issued it. Issuing used
// to be naming an issuer, which anyone can do.
func TestCredentialNeedsTheIssuersKey(t *testing.T) {
	h := newHarness(t)

	issuer, subject := newParty(t), newParty(t)
	issuerRecord := h.issuer(t, issuer, "registry")
	subjectRecord := h.identity(t, subject, nil)
	h.accept(t, &Change{Issuer: issuerRecord}, &Change{Identity: subjectRecord})

	// Someone else's signature over a credential naming this issuer.
	attacker := newParty(t)
	forged := h.credential(t, attacker, issuerRecord.ID, subjectRecord.ID, time.Now().Add(time.Hour))
	require.ErrorIs(t, h.Submit(&Change{Credential: forged}), errNotAuthorized)

	// An issuer the chain has no record of.
	unknown := h.credential(t, attacker, ids.GenerateTestID(), subjectRecord.ID, time.Now().Add(time.Hour))
	require.ErrorIs(t, h.Submit(&Change{Credential: unknown}), errNotIssuer)

	// A subject the chain has no record of.
	noSubject := h.credential(t, issuer, issuerRecord.ID, ids.GenerateTestID(), time.Now().Add(time.Hour))
	require.ErrorIs(t, h.Submit(&Change{Credential: noSubject}), errUnknownIdentity)

	// The issuer's own signature is accepted.
	good := h.credential(t, issuer, issuerRecord.ID, subjectRecord.ID, time.Now().Add(time.Hour))
	h.accept(t, &Change{Credential: good})
	require.NoError(t, h.Verify(good.ID))
}

// A chain that allows self-issue lets an identity claim about itself, signed
// by its own key — and nothing more than that.
func TestSelfIssue(t *testing.T) {
	h := newHarnessWith(t, &Config{AllowSelfIssue: true})

	self, other := newParty(t), newParty(t)
	selfRecord := h.identity(t, self, nil)
	otherRecord := h.identity(t, other, nil)
	h.accept(t, &Change{Identity: selfRecord}, &Change{Identity: otherRecord})

	own := h.credential(t, self, selfRecord.ID, selfRecord.ID, time.Now().Add(time.Hour))
	h.accept(t, &Change{Credential: own})
	require.NoError(t, h.Verify(own.ID))

	// Self-issue is about ONESELF: it does not let one identity issue to
	// another without being an issuer.
	about := h.credential(t, self, selfRecord.ID, otherRecord.ID, time.Now().Add(time.Hour))
	require.ErrorIs(t, h.Submit(&Change{Credential: about}), errNotIssuer)

	// Nor does it accept someone else's signature over a self-issued one.
	forged := h.credential(t, other, selfRecord.ID, selfRecord.ID, time.Now().Add(2*time.Hour))
	require.ErrorIs(t, h.Submit(&Change{Credential: forged}), errNotAuthorized)
}

// TrustedIssuers used to be loaded and never read: an allowlist that allowed
// everything. Anyone who paid the fee became a trusted issuer.
func TestTrustedIssuersIsAnAllowlist(t *testing.T) {
	allowed, refused := newParty(t), newParty(t)
	h := newHarnessWith(t, &Config{TrustedIssuers: []ids.ID{issuerID(allowed.pub)}})

	h.accept(t, &Change{Issuer: h.issuer(t, allowed, "allowed")})
	require.ErrorIs(t, h.Submit(&Change{Issuer: h.issuer(t, refused, "refused")}), errNotIssuer)

	// An empty list admits any issuer that proves it holds its key.
	open := newHarness(t)
	open.accept(t, &Change{Issuer: open.issuer(t, refused, "refused elsewhere")})
}

// A record proves it holds the key its id is derived from.
func TestARecordProvesItsKey(t *testing.T) {
	h := newHarness(t)
	p, other := newParty(t), newParty(t)

	// An id that is not the hash of the key.
	i := h.identity(t, p, nil)
	i.ID = ids.GenerateTestID()
	require.ErrorIs(t, h.Submit(&Change{Identity: i}), errWrongID)

	// A signature by someone else.
	i = h.identity(t, p, nil)
	i.Signature = other.sign(t, i.signable(), h.bind)
	require.ErrorIs(t, h.Submit(&Change{Identity: i}), errNotAuthorized)

	// A signature over different content.
	i = h.identity(t, p, nil)
	i.Metadata = map[string]string{"changed": "after signing"}
	require.ErrorIs(t, h.Submit(&Change{Identity: i}), errNotAuthorized)

	// A public key that is not one.
	i = h.identity(t, p, nil)
	i.PublicKey = []byte("not a key")
	i.ID = identityID(i.PublicKey)
	require.ErrorIs(t, h.Submit(&Change{Identity: i}), errNoKey)

	// The same for an issuer.
	s := h.issuer(t, p, "registry")
	s.ID = ids.GenerateTestID()
	require.ErrorIs(t, h.Submit(&Change{Issuer: s}), errWrongID)

	s = h.issuer(t, p, "registry")
	s.Name = "renamed after signing"
	require.ErrorIs(t, h.Submit(&Change{Issuer: s}), errNotAuthorized)

	// And a credential's id is a hash of what it says.
	issuer, subject, cred := h.enrolled(t)
	forged := *cred
	forged.Claims = map[string]interface{}{"degree": "forged"}
	require.ErrorIs(t, h.Submit(&Change{Credential: &forged}), errWrongID)
	_, _ = issuer, subject
}

// An authorization made for one chain does not authorize anything on another:
// the chain's binding is the signing context, and it is not on the wire.
func TestSignaturesAreChainBound(t *testing.T) {
	first := newHarness(t)
	second := newHarness(t)

	p := newParty(t)
	onFirst := first.identity(t, p, nil)
	first.accept(t, &Change{Identity: onFirst})

	// The same record, byte for byte, on the other chain.
	require.ErrorIs(t, second.Submit(&Change{Identity: onFirst}), errNotAuthorized)

	// And the two chains name the same block differently.
	require.NotEqual(t, first.bind, second.bind)
}

// Two chains with identical genesis and different identities derive different
// blocks, so one chain's blocks have no parent on the other.
func TestChainBindingSeparatesTwoChains(t *testing.T) {
	genesisOf := func(chainID ids.ID, network uint32) ids.ID {
		h := &harness{db: memdb.New(), chainID: chainID, network: network}
		h.VM = h.boot(t, nil)
		id, err := h.LastAccepted(context.Background())
		require.NoError(t, err)
		return id
	}

	id := ids.GenerateTestID()
	same := genesisOf(id, 1)
	require.Equal(t, same, genesisOf(id, 1))
	require.NotEqual(t, same, genesisOf(ids.GenerateTestID(), 1), "a different ChainID is a different chain")
	require.NotEqual(t, same, genesisOf(id, 2), "a different NetworkID is a different chain")
}

// A genesis that names no timestamp is stamped 0, not "now". The timestamp is
// hashed into the genesis id, so a wall-clock reading gave every node a
// different chain for the same genesis file — while the comment above it said
// exactly why that must not happen.
func TestGenesisIsDeterministic(t *testing.T) {
	g, err := ParseGenesis(nil)
	require.NoError(t, err)
	require.Zero(t, g.Timestamp)

	g, err = ParseGenesis([]byte(`{}`))
	require.NoError(t, err)
	require.Zero(t, g.Timestamp)

	g, err = ParseGenesis([]byte(`{"timestamp":7}`))
	require.NoError(t, err)
	require.EqualValues(t, 7, g.Timestamp)

	_, err = ParseGenesis([]byte(`{`))
	require.Error(t, err)

	boot := func() ids.ID {
		vm := &VM{}
		require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
			Runtime: &runtime.Runtime{ChainID: ids.ID{7}, Log: log.NoLog{}},
			DB:      memdb.New(),
			Genesis: []byte(`{"message":"hello"}`),
			Log:     log.NoLog{},
		}))
		id, err := vm.LastAccepted(context.Background())
		require.NoError(t, err)
		return id
	}
	first := boot()
	time.Sleep(2 * time.Millisecond)
	require.Equal(t, first, boot(), "the same genesis file must name the same chain a moment later")
}

// What the chain accepted, a restarted node holds. Nothing rebuilt the caches:
// a restarted node held only what genesis named and answered "unknown
// identity" for every identity it had itself accepted.
func TestARestartedNodeHoldsWhatItAccepted(t *testing.T) {
	h := newHarness(t)
	issuer, subject, cred := h.enrolled(t)
	h.accept(t, &Change{Revocation: h.revocation(t, issuer, cred.ID, cred.Issuer)})

	before, err := h.HealthCheck(context.Background())
	require.NoError(t, err)

	restarted := h.restart(t)

	after, err := restarted.HealthCheck(context.Background())
	require.NoError(t, err)
	require.Equal(t, before.Details, after.Details)

	held, err := restarted.Identity(identityID(subject.pub))
	require.NoError(t, err)
	require.Equal(t, subject.pub, held.PublicKey)

	_, err = restarted.Issuer(issuerID(issuer.pub))
	require.NoError(t, err)

	require.ErrorIs(t, restarted.Verify(cred.ID), errCredentialRevoked,
		"a revocation the chain accepted survives the restart")
}

// A block extends the tip, or a block verified above it. Height alone is not
// that check.
func TestBlockMustExtendTheTip(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	genesisID, _ := h.chain.Tip()
	first := h.accept(t, &Change{Identity: h.identity(t, newParty(t), nil)})

	tip, height := h.chain.Tip()
	require.Equal(t, first.ID(), tip)
	require.EqualValues(t, 1, height)

	// A block whose parent is GENESIS once the chain has moved past it: the
	// store commits a block when it accepts one, and genesis was never
	// accepted, so nothing can resolve it as a parent any more.
	sibling := &Block{
		ParentID_:      genesisID,
		BlockHeight:    1,
		BlockTimestamp: first.BlockTimestamp,
		Identities:     []*Identity{h.identity(t, newParty(t), nil)},
		vm:             h.VM,
	}
	require.Error(t, sibling.Verify(ctx))
	require.ErrorIs(t, sibling.Accept(ctx), ErrNotOnTip)

	// A block whose parent IS resolvable and beneath the tip. Its height
	// follows its parent's perfectly well, which is the whole point: accepting
	// it would rewind the tip and leave the height index naming an orphan.
	second := h.accept(t, &Change{Identity: h.identity(t, newParty(t), nil)})
	require.EqualValues(t, 2, second.BlockHeight)

	rewind := &Block{
		ParentID_:      first.ID(),
		BlockHeight:    2,
		BlockTimestamp: second.BlockTimestamp,
		Identities:     []*Identity{h.identity(t, newParty(t), nil)},
		vm:             h.VM,
	}
	require.ErrorIs(t, rewind.Verify(ctx), ErrNotOnTip)
	require.ErrorIs(t, rewind.Accept(ctx), ErrNotOnTip)

	at1, err := h.GetBlockIDAtHeight(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, first.ID(), at1, "the height index still names the block the chain accepted")
}

// The tip moves between Verify and Accept, so Accept asks again.
func TestAcceptRecheckesTheTip(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	genesisID, _ := h.chain.Tip()
	loser := &Block{
		ParentID_:      genesisID,
		BlockHeight:    1,
		BlockTimestamp: time.Now().Unix(),
		Identities:     []*Identity{h.identity(t, newParty(t), nil)},
		vm:             h.VM,
	}
	require.NoError(t, loser.Verify(ctx))

	// A competitor verifies against the same tip and is accepted first.
	h.accept(t, &Change{Identity: h.identity(t, newParty(t), nil)})

	require.ErrorIs(t, loser.Accept(ctx), ErrNotOnTip)
	require.Equal(t, uint8(choices.Unknown), loser.Status())
}

func TestBlockVerifyRefusals(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	tip, height := h.chain.Tip()
	valid := func() *Block {
		return &Block{
			ParentID_:      tip,
			BlockHeight:    height + 1,
			BlockTimestamp: time.Now().Unix(),
			Identities:     []*Identity{h.identity(t, newParty(t), nil)},
			vm:             h.VM,
		}
	}
	require.NoError(t, valid().Verify(ctx))

	t.Run("genesis with a parent", func(t *testing.T) {
		b := valid()
		b.BlockHeight = 0
		require.ErrorIs(t, b.Verify(ctx), errInvalidBlock)
	})

	t.Run("a block that says nothing", func(t *testing.T) {
		b := valid()
		b.Identities = nil
		require.ErrorIs(t, b.Verify(ctx), errInvalidBlock)
	})

	t.Run("more records than this node would build", func(t *testing.T) {
		b := valid()
		for len(b.Identities) <= h.config.MaxRecordsPerBlock {
			b.Identities = append(b.Identities, h.identity(t, newParty(t), nil))
		}
		require.ErrorIs(t, b.Verify(ctx), errInvalidBlock)
	})

	t.Run("timestamp beyond the skew allowance", func(t *testing.T) {
		b := valid()
		b.BlockTimestamp = time.Now().Unix() + maxClockSkew + 5
		require.ErrorIs(t, b.Verify(ctx), errInvalidBlock)
	})

	t.Run("a parent nothing can resolve", func(t *testing.T) {
		b := valid()
		b.ParentID_ = ids.GenerateTestID()
		require.Error(t, b.Verify(ctx))
	})

	t.Run("a height that does not follow its parent", func(t *testing.T) {
		b := valid()
		b.BlockHeight = height + 2
		require.ErrorIs(t, b.Verify(ctx), errInvalidBlock)
	})

	t.Run("a timestamp behind its parent", func(t *testing.T) {
		b := valid()
		b.BlockTimestamp = -1
		require.ErrorIs(t, b.Verify(ctx), errInvalidBlock)
	})

	t.Run("two records claiming one id", func(t *testing.T) {
		p := newParty(t)
		b := valid()
		b.Identities = []*Identity{h.identity(t, p, nil), h.identity(t, p, nil)}
		require.ErrorIs(t, b.Verify(ctx), errExists)
	})
}

// A block's records may reference each other: a credential names an identity
// the same block creates.
func TestOneBlockCanIntroduceAndUse(t *testing.T) {
	h := newHarness(t)

	ctx := context.Background()
	issuer, subject := newParty(t), newParty(t)
	issuerRecord := h.issuer(t, issuer, "registry")
	subjectRecord := h.identity(t, subject, nil)
	cred := h.credential(t, issuer, issuerRecord.ID, subjectRecord.ID, time.Now().Add(time.Hour))
	rev := h.revocation(t, subject, cred.ID, subjectRecord.ID)

	// This node's door checks one change against the state it HOLDS, so a
	// credential naming an identity not yet accepted is refused there — the
	// client submits the identity first. A block another node built may carry
	// both, and this is that block.
	require.ErrorIs(t, h.Submit(&Change{Credential: cred}), errUnknownIdentity)

	tip, height := h.chain.Tip()
	blk := &Block{
		ParentID_:      tip,
		BlockHeight:    height + 1,
		BlockTimestamp: time.Now().Unix(),
		Issuers:        []*Issuer{issuerRecord},
		Identities:     []*Identity{subjectRecord},
		Credentials:    []*Credential{cred},
		Revocations:    []*Revocation{rev},
		vm:             h.VM,
	}
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))

	require.ErrorIs(t, h.Verify(cred.ID), errCredentialRevoked)

	// The order still has to hold: a credential naming an identity the block
	// introduces AFTER it is a credential with no subject.
	late := &Block{
		ParentID_:      blk.ID(),
		BlockHeight:    blk.BlockHeight + 1,
		BlockTimestamp: blk.BlockTimestamp,
		Credentials:    []*Credential{h.credential(t, issuer, issuerRecord.ID, identityID(newParty(t).pub), time.Now().Add(time.Hour))},
		Identities:     []*Identity{h.identity(t, newParty(t), nil)},
		vm:             h.VM,
	}
	require.ErrorIs(t, late.Verify(ctx), errUnknownIdentity)
}

// Expiry is judged against the BLOCK's clock. The wall clock makes the verdict
// depend on when a node happens to verify, so a node replaying history during
// bootstrap rejects every block whose credentials have since lapsed.
func TestExpiryIsJudgedAgainstTheBlock(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	issuer, subject := newParty(t), newParty(t)
	issuerRecord := h.issuer(t, issuer, "registry")
	subjectRecord := h.identity(t, subject, nil)
	h.accept(t, &Change{Issuer: issuerRecord}, &Change{Identity: subjectRecord})

	lapsed := h.credential(t, issuer, issuerRecord.ID, subjectRecord.ID, time.Unix(0, 1).UTC())
	require.ErrorIs(t, h.Submit(&Change{Credential: lapsed}), errCredentialExpired)

	// One credential, two blocks: valid in the one stamped before it lapses,
	// expired in the one stamped after. The wall clock plays no part.
	lapses := time.Now().Add(time.Hour)
	cred := h.credential(t, issuer, issuerRecord.ID, subjectRecord.ID, lapses)

	before := &Block{BlockTimestamp: lapses.Add(-time.Minute).Unix(), Credentials: []*Credential{cred}, vm: h.VM}
	require.NoError(t, h.check(before))

	after := &Block{BlockTimestamp: lapses.Add(time.Minute).Unix(), Credentials: []*Credential{cred}, vm: h.VM}
	require.ErrorIs(t, h.check(after), errCredentialExpired)
	_ = ctx
}

// A credential whose lifetime the caller chose to be negative used to be
// admitted, queued, put into every block this node proposed and refused by
// every node including this one — with nothing to remove it. Assembly runs the
// predicate Verify runs and drops what it cannot build.
func TestAssemblyDropsWhatItCannotBuild(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	// Reaching past Submit is how a change gets into the pool that the door
	// would have refused — a peer's gossip, or a door that stops checking.
	poison := &Change{Identity: &Identity{ID: ids.GenerateTestID(), PublicKey: []byte("nonsense")}}
	require.NoError(t, h.pending.Add(poison))

	_, err := h.BuildBlock(ctx)
	require.ErrorIs(t, err, errNothingToBuild)
	require.Empty(t, h.pending.Take(0), "the pool must not keep what no block can carry")

	// And with nothing pending at all.
	_, err = h.BuildBlock(ctx)
	require.ErrorIs(t, err, errNothingToBuild)

	// A good change beside a poison one still builds.
	good := h.identity(t, newParty(t), nil)
	require.NoError(t, h.pending.Add(&Change{Identity: &Identity{ID: ids.GenerateTestID(), PublicKey: []byte("x")}}))
	require.NoError(t, h.Submit(&Change{Identity: good}))

	built, err := h.BuildBlock(ctx)
	require.NoError(t, err)
	require.Len(t, built.(*Block).Identities, 1)
}

// Assembly clamps its timestamp to the parent's: a parent may legally be up to
// maxClockSkew ahead of this node's clock, and Verify refuses a block below its
// parent.
func TestBuildClampsToTheParentTimestamp(t *testing.T) {
	ahead := &Block{BlockTimestamp: time.Now().Unix() + maxClockSkew - 5}
	require.Equal(t, ahead.BlockTimestamp, buildTimestamp(ahead))

	behind := &Block{BlockTimestamp: 0}
	require.GreaterOrEqual(t, buildTimestamp(behind), time.Now().Unix()-2)
}

// A block the engine may build on has to be findable by id, including one
// parsed from a peer: tracking only self-built blocks leaves a follower able to
// verify the first block of a run and not the second.
func TestAParsedBlockIsTracked(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	first := h.accept(t, &Change{Identity: h.identity(t, newParty(t), nil)})

	// A second block on top of the first, as a follower sees it: bytes.
	second := &Block{
		ParentID_:      first.ID(),
		BlockHeight:    2,
		BlockTimestamp: first.BlockTimestamp + 1,
		Identities:     []*Identity{h.identity(t, newParty(t), nil)},
		vm:             h.VM,
	}
	parsed, err := h.ParseBlock(ctx, second.Bytes())
	require.NoError(t, err)
	require.Equal(t, second.ID(), parsed.ID())
	require.NoError(t, parsed.Verify(ctx))

	// A third resolves the second as its parent because parsing tracked it.
	third := &Block{
		ParentID_:      parsed.ID(),
		BlockHeight:    3,
		BlockTimestamp: second.BlockTimestamp + 1,
		Identities:     []*Identity{h.identity(t, newParty(t), nil)},
		vm:             h.VM,
	}
	require.NoError(t, third.Verify(ctx))

	_, err = h.ParseBlock(ctx, []byte("not a block"))
	require.Error(t, err)
}

// A rejected block wrote nothing; what it carried stays queued.
func TestRejectKeepsTheChangesQueued(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	require.NoError(t, h.Submit(&Change{Identity: h.identity(t, newParty(t), nil)}))
	built, err := h.BuildBlock(ctx)
	require.NoError(t, err)
	blk := built.(*Block)

	require.NoError(t, blk.Reject(ctx))
	require.Equal(t, uint8(choices.Rejected), blk.Status())
	require.Len(t, h.pending.Take(0), 1)

	_, err = h.GetBlock(ctx, blk.ID())
	require.Error(t, err, "a rejected block is not one the chain holds")
}

func TestVMLifecycle(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	require.NoError(t, h.SetState(ctx, 0))
	v, err := h.Version(ctx)
	require.NoError(t, err)
	require.Equal(t, "1.0.0", v)

	tip, _ := h.chain.Tip()
	require.NoError(t, h.SetPreference(ctx, tip))

	handlers, err := h.CreateHandlers(ctx)
	require.NoError(t, err)
	require.Contains(t, handlers, "/rpc")

	mux, err := h.NewHTTPHandler(ctx)
	require.NoError(t, err)
	require.NotNil(t, mux)

	require.NoError(t, h.Connected(ctx, ids.EmptyNodeID, nil))
	require.NoError(t, h.Disconnected(ctx, ids.EmptyNodeID))
	require.ErrorIs(t, h.Request(ctx, ids.EmptyNodeID, 0, time.Now(), nil), errNoAppProtocol)
	require.NoError(t, h.Response(ctx, ids.EmptyNodeID, 0, nil))
	require.NoError(t, h.RequestFailed(ctx, ids.EmptyNodeID, 0, nil))
	require.NoError(t, h.Gossip(ctx, ids.EmptyNodeID, nil))
	require.NoError(t, h.CrossChainRequest(ctx, ids.Empty, 0, time.Now(), nil))
	require.NoError(t, h.CrossChainResponse(ctx, ids.Empty, 0, nil))
	require.NoError(t, h.CrossChainRequestFailed(ctx, ids.Empty, 0, nil))

	_, err = h.GetBlockIDAtHeight(ctx, 99)
	require.Error(t, err)

	stopped, cancel := context.WithCancel(ctx)
	cancel()
	_, err = h.WaitForEvent(stopped)
	require.ErrorIs(t, err, context.Canceled)
}

func TestInitializeRefusals(t *testing.T) {
	ctx := context.Background()
	boot := func(init vmcore.Init) error { return (&VM{}).Initialize(ctx, init) }

	require.ErrorContains(t, boot(vmcore.Init{}), "runtime is nil")
	require.ErrorContains(t, boot(vmcore.Init{Runtime: &runtime.Runtime{}}), "invalid logger type")
	require.ErrorContains(t, boot(vmcore.Init{
		Runtime: &runtime.Runtime{Log: log.NoLog{}}, DB: memdb.New(), Genesis: []byte(`{`),
	}), "parse genesis")

	// A config naming no bound gets the default rather than none.
	vm := &VM{}
	genesis, err := json.Marshal(&Genesis{Config: &Config{}})
	require.NoError(t, err)
	require.NoError(t, vm.Initialize(ctx, vmcore.Init{
		Runtime: &runtime.Runtime{Log: log.NoLog{}},
		DB:      memdb.New(),
		Genesis: genesis,
		Log:     log.NoLog{},
	}))
	require.EqualValues(t, defaultCredentialTTL, vm.config.CredentialTTL)
	require.Equal(t, defaultMaxClaims, vm.config.MaxClaims)
	require.Equal(t, defaultMaxRecordsPerBlock, vm.config.MaxRecordsPerBlock)
	require.NoError(t, vm.Shutdown(ctx))
}

// Genesis names issuers and identities the chain starts with.
func TestGenesisRecords(t *testing.T) {
	p := newParty(t)
	genesis, err := json.Marshal(&Genesis{
		Timestamp:  1,
		Issuers:    []*Issuer{{ID: issuerID(p.pub), Name: "root", PublicKey: p.pub}},
		Identities: []*Identity{{ID: identityID(p.pub), PublicKey: p.pub}},
	})
	require.NoError(t, err)

	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime: &runtime.Runtime{ChainID: ids.ID{3}, Log: log.NoLog{}},
		DB:      memdb.New(),
		Genesis: genesis,
		Log:     log.NoLog{},
	}))

	_, err = vm.Issuer(issuerID(p.pub))
	require.NoError(t, err)
	_, err = vm.Identity(identityID(p.pub))
	require.NoError(t, err)
	require.NoError(t, vm.Shutdown(context.Background()))
}
