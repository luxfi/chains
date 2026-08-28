// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// block_test.go — what a validator refuses.
//
// Every test here is an adversary: it builds the block a dishonest proposer
// would build, hands it to Verify, and holds that Verify says no. A test that
// only builds honest blocks proves the happy path and nothing about custody.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/consensus/core/choices"
	luxcrypto "github.com/luxfi/crypto"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
)

func ctx() context.Context { return context.Background() }

// -----------------------------------------------------------------------------
// The block extends applied state, or it extends nothing
// -----------------------------------------------------------------------------

// A block whose parent this node has not applied is refused, even though its
// height, its parent link and its accumulated root are all internally
// consistent.
//
// This is the defect that halts the chain. Every check in verifyOperation reads
// APPLIED state — the registry, the ceremony log, this node's own shares — and
// the root is accumulated from the applied root. So a block built on a parent
// still in flight carries a root computed as if the parent's operations had not
// happened. It verifies on every peer, wins consensus, and then fails at Accept
// once the parent lands, because Write recomputes the root against state that
// has moved. A decided block that cannot be applied is not a rejected block; it
// is a stopped chain.
//
// The parent's own declared post-state is what says this, and it says it
// without asking the store for its tip: a parent that leaves a root this node
// is not at is a parent this node has not applied.
func TestABlockOnAnUnappliedParentIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 7)
	key.register(t, vm)

	// A block that is verified but NOT accepted — the engine's preferred block
	// while consensus is still running.
	first := blockOver(t, vm, key.signOpOver(t, digestOf(1)))
	require.NoError(t, first.Verify(ctx()))

	// A second block built on it, exactly as BuildBlock would if it followed the
	// engine's preference: correct parent, correct height, and a root
	// accumulated from applied state.
	second := &Block{
		ParentID_:      first.ID(),
		BlockHeight:    first.BlockHeight + 1,
		BlockTimestamp: first.BlockTimestamp,
		StateRoot:      advance(vm.state.Root(), key.signOpOver(t, digestOf(2)).digest()),
		Operations:     []*Operation{key.signOpOver(t, digestOf(2))},
		vm:             vm,
	}
	second.ID_ = second.computeID()
	vm.chain.Track(first)

	require.ErrorIs(t, second.Verify(ctx()), ErrStaleParent,
		"a block whose parent has not been applied must be refused at Verify, "+
			"not accepted and then found unapplicable")

	// And the property that makes it safe: once the parent IS applied, the same
	// shape verifies.
	require.NoError(t, first.Accept(ctx()))
	after := blockOver(t, vm, key.signOpOver(t, digestOf(2)))
	require.NoError(t, after.Verify(ctx()))
}

// The builder holds the same rule, so this node never proposes a block its own
// peers — or its own Accept — would refuse. One predicate, both ends.
func TestTheBuilderWillNotBuildOnAnUnappliedParent(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 8)
	key.register(t, vm)

	vm.stage(key.signOpOver(t, digestOf(1)))
	first, err := vm.BuildBlock(ctx())
	require.NoError(t, err)
	require.NoError(t, first.Verify(ctx()))

	// The engine prefers the block it just verified; it is not applied.
	require.NoError(t, vm.SetPreference(ctx(), first.ID()))
	vm.stage(key.signOpOver(t, digestOf(2)))
	_, err = vm.BuildBlock(ctx())
	require.ErrorIs(t, err, ErrStaleParent)

	// Neither ceremony is lost. A taken operation leaves the queue only when the
	// block carrying it is durable, so the first block's is still there too —
	// and the next proposal, once the parent lands, carries the second.
	require.Equal(t, 2, vm.staged.Len())
	require.NoError(t, first.Accept(ctx()))
	require.Equal(t, 1, vm.staged.Len())
	next, err := vm.BuildBlock(ctx())
	require.NoError(t, err)
	require.NoError(t, next.Verify(ctx()))
	require.NoError(t, next.Accept(ctx()))
	require.Zero(t, vm.staged.Len())
}

// A sibling of the applied tip — same parent, different operations — is refused
// for the same reason. Height and parent link both check out; the parent's
// post-state is one the chain has moved past.
func TestASiblingOfTheTipCannotRewindTheChain(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 9)
	key.register(t, vm)

	tipParent, _ := vm.chain.Tip()
	rootBefore := vm.state.Root()

	landed := blockOver(t, vm, key.signOpOver(t, digestOf(1)))
	require.NoError(t, landed.Verify(ctx()))
	require.NoError(t, landed.Accept(ctx()))

	sibling := &Block{
		ParentID_:      tipParent,
		BlockHeight:    landed.BlockHeight,
		BlockTimestamp: landed.BlockTimestamp,
		StateRoot:      advance(rootBefore, key.signOpOver(t, digestOf(2)).digest()),
		Operations:     []*Operation{key.signOpOver(t, digestOf(2))},
		vm:             vm,
	}
	sibling.ID_ = sibling.computeID()

	require.ErrorIs(t, sibling.Verify(ctx()), ErrStaleParent)

	// And the height index still names the block that was actually accepted, so
	// a bootstrapping peer is not served an orphan as canonical.
	at, err := vm.GetBlockIDAtHeight(ctx(), landed.BlockHeight)
	require.NoError(t, err)
	require.Equal(t, landed.ID(), at)
}

// -----------------------------------------------------------------------------
// Shape: height, timestamp, emptiness, size
// -----------------------------------------------------------------------------

func TestGenesisIsNotVerifiableAsATransition(t *testing.T) {
	vm := newVM(t)
	require.Error(t, vm.genesisBlock.Verify(ctx()),
		"height 0 registers nothing and signs nothing; verifying it as a transition would verify an empty claim")
}

func TestABlockWithNoVMVerifiesNothing(t *testing.T) {
	require.Error(t, (&Block{BlockHeight: 1}).Verify(ctx()))
}

func TestAnUnknownParentIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 10)
	key.register(t, vm)

	blk := blockOver(t, vm, key.signOpOver(t, digestOf(1)))
	blk.ParentID_[0] ^= 0xff
	blk.ID_ = blk.computeID()
	require.ErrorContains(t, blk.Verify(ctx()), "unknown parent")
}

func TestHeightMustBeParentPlusOne(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 11)
	key.register(t, vm)

	for _, h := range []uint64{0, 1, 3, 99} {
		blk := blockOver(t, vm, key.signOpOver(t, digestOf(1)))
		blk.BlockHeight = h
		blk.ID_ = blk.computeID()
		require.Error(t, blk.Verify(ctx()), "height %d must not verify against a tip at %d", h, blk.BlockHeight)
	}
}

// The timestamp floor is monotonic, which is exactly why it needs a ceiling.
//
// Without one, a single proposer dates a block a year out, every validator
// accepts it, and the floor every later block must clear is a year away: the
// chain produces nothing until the clock catches up. The damage from bounding
// it is one rejected block.
func TestATimestampFarAheadIsRefusedBecauseTheFloorIsMonotonic(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 12)
	key.register(t, vm)

	blk := blockOver(t, vm, key.signOpOver(t, digestOf(1)))
	blk.BlockTimestamp = time.Now().Add(365 * 24 * time.Hour).Unix()
	blk.ID_ = blk.computeID()
	require.ErrorIs(t, blk.Verify(ctx()), ErrFutureBlock)

	// Ordinary clock disagreement between honest validators still passes.
	blk.BlockTimestamp = time.Now().Add(maxFutureSkew / 2).Unix()
	blk.ID_ = blk.computeID()
	require.NoError(t, blk.Verify(ctx()))
}

func TestATimestampBeforeItsParentIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 13)
	key.register(t, vm)

	first := blockOver(t, vm, key.signOpOver(t, digestOf(1)))
	first.BlockTimestamp = time.Now().Unix()
	first.ID_ = first.computeID()
	require.NoError(t, first.Verify(ctx()))
	require.NoError(t, first.Accept(ctx()))

	back := blockOver(t, vm, key.signOpOver(t, digestOf(2)))
	back.BlockTimestamp = first.BlockTimestamp - 1
	back.ID_ = back.computeID()
	require.ErrorContains(t, back.Verify(ctx()), "precedes parent")
}

// The builder never emits a timestamp its own Verify would refuse: it clamps to
// the parent's floor rather than to a clock that may have run backwards.
func TestTheBuilderNeverEmitsATimestampItsOwnVerifyRefuses(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 14)
	key.register(t, vm)

	// A parent dated at the ceiling — the latest a peer's block could legally be.
	first := blockOver(t, vm, key.signOpOver(t, digestOf(1)))
	first.BlockTimestamp = time.Now().Add(maxFutureSkew - time.Second).Unix()
	first.ID_ = first.computeID()
	require.NoError(t, first.Verify(ctx()))
	require.NoError(t, first.Accept(ctx()))

	vm.stage(key.signOpOver(t, digestOf(2)))
	built, err := vm.BuildBlock(ctx())
	require.NoError(t, err)
	require.NoError(t, built.Verify(ctx()),
		"the proposer built a block its own rules refuse")
	require.GreaterOrEqual(t, built.(*Block).BlockTimestamp, first.BlockTimestamp)
}

func TestAnEmptyBlockIsNotATransition(t *testing.T) {
	vm := newVM(t)
	blk := blockOver(t, vm)
	require.ErrorContains(t, blk.Verify(ctx()), "empty block")
}

// The operation count is a consensus rule, so it is a constant and Verify
// enforces it. Each sign operation costs every validator an ECDSA verification;
// an unbounded block is an unbounded verification cost that a proposer chooses
// and the whole network pays.
func TestABlockCannotMakeTheNetworkVerifyUnboundedWork(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 15)
	key.register(t, vm)

	ops := make([]*Operation, 0, maxOpsPerBlock+1)
	for i := 0; i <= maxOpsPerBlock; i++ {
		ops = append(ops, key.signOpOver(t, digestOf(byte(i))))
	}
	blk := blockOver(t, vm, ops...)
	require.ErrorIs(t, blk.Verify(ctx()), ErrBlockTooLarge)

	// And the builder holds the same bound, so a node with more staged than a
	// block may carry proposes a block that fits.
	for _, op := range ops {
		vm.stage(op)
	}
	require.Equal(t, len(ops), vm.staged.Len())
	built, err := vm.BuildBlock(ctx())
	require.NoError(t, err)
	require.Len(t, built.(*Block).Operations, maxOpsPerBlock)
	require.NoError(t, built.Verify(ctx()))
}

// -----------------------------------------------------------------------------
// Operations
// -----------------------------------------------------------------------------

func TestAnOperationWithoutIdentityIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 16)
	key.register(t, vm)

	for name, mangle := range map[string]func(*Operation){
		"no ceremony id": func(op *Operation) { op.CeremonyID = "" },
		"no key id":      func(op *Operation) { op.KeyID = "" },
		"unknown type":   func(op *Operation) { op.Type = "reshare" },
	} {
		op := key.signOpOver(t, digestOf(1))
		mangle(op)
		blk := blockOver(t, vm, op)
		require.ErrorIsf(t, blk.Verify(ctx()), ErrInvalidOperation, "%s", name)
	}
}

// A ceremony id is derived from its task, so the same id twice is the same task
// twice. For a bridge release that is the same funds released twice, and the
// two ways to attempt it — twice in one block, or once in each of two — are
// refused by the same rule reading two different places.
func TestARecordedCeremonyCannotBeRecordedAgain(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 17)
	key.register(t, vm)

	op := key.signOpOver(t, digestOf(1))

	twiceInOne := blockOver(t, vm, op, op)
	require.ErrorIs(t, twiceInOne.Verify(ctx()), ErrInvalidOperation)
	require.ErrorContains(t, twiceInOne.Verify(ctx()), "appears twice")

	landed := blockOver(t, vm, op)
	require.NoError(t, landed.Verify(ctx()))
	require.NoError(t, landed.Accept(ctx()))

	again := blockOver(t, vm, op)
	require.ErrorIs(t, again.Verify(ctx()), ErrCeremonyExists)
}

// -----------------------------------------------------------------------------
// Keygen
// -----------------------------------------------------------------------------

// A keygen's ceremony id must be the one its registration derives.
//
// Left unchecked the id is whatever the proposer writes, and a recorded id is
// permanently unusable — verifyOperation refuses any ceremony already in the
// log. Signing ids are derived from public inputs (the key, the digest, the
// quorum), so a proposer can name a future release in advance, register a
// keygen under that id, and censor that exact release forever. Nothing about
// the key it registers has to be wrong.
func TestAKeygenCannotClaimAFutureReleasesCeremonyId(t *testing.T) {
	vm := newVM(t)
	victim := newCustody(t, "vault", quorum.MustNew(3, 5), 18)
	victim.register(t, vm)

	// The release the attacker wants to stop, named before it happens.
	release := digestOf(0x42)
	target := ceremonyID(victim.rec.KeyID, release, quorumFor(victim.rec, release))

	// A perfectly valid registration of an unrelated key — right policy, right
	// address, real proof of possession — wearing the release's id.
	squatter := newCustody(t, "unrelated", quorum.MustNew(3, 5), 19)
	op := squatter.keygenOp(t)
	op.CeremonyID = target

	blk := blockOver(t, vm, op)
	require.ErrorIs(t, blk.Verify(ctx()), ErrInvalidOperation)
	require.ErrorContains(t, blk.Verify(ctx()), "not derived from this registration")

	// With the id it actually derives, the same registration is fine — so what
	// was refused is the squatting, not the key.
	require.NoError(t, blockOver(t, vm, squatter.keygenOp(t)).Verify(ctx()))
}

// A keygen's signer set is its participant set. A DKG has no K-subset — every
// party runs every round — so any other set is a claim about who generated a
// custody key that nothing produced.
//
// The ceremony log is the replicated evidence of exactly that, and it is what
// an audit, an attribution or a slashing argument reads.
func TestAKeygenCannotFabricateWhoGeneratedTheKey(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 20)

	for name, signers := range map[string][]party.ID{
		"a quorum instead of the committee": key.rec.Participants[:3],
		"strangers":                         {"zz-nobody"},
		"nobody":                            nil,
		"the committee plus a stranger":     append(append([]party.ID(nil), key.rec.Participants...), "zz-nobody"),
	} {
		op := key.keygenOp(t)
		op.Signers = signers
		blk := blockOver(t, vm, op)
		require.ErrorIsf(t, blk.Verify(ctx()), ErrInvalidOperation, "%s", name)
	}

	// And the honest one lands, carrying the true set into the log.
	key.register(t, vm)
	rec, err := vm.Ceremony(key.keygenOp(t).CeremonyID)
	require.NoError(t, err)
	require.Equal(t, key.rec.Participants, rec.Signers)
}

// The address is recomputed from the group key, so a proposer cannot publish a
// custody address the group key does not control. Funds sent to a wrong address
// are unspendable and there is no recovery.
func TestTheCustodyAddressIsRecomputedNotBelieved(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 21)

	other := newCustody(t, "other", quorum.MustNew(3, 5), 22)
	key.rec.Address = other.rec.Address
	op := key.keygenOp(t) // signs the commit over the mangled record, so the PoP is real
	blk := blockOver(t, vm, op)
	require.ErrorIs(t, blk.Verify(ctx()), ErrInvalidOperation)
	require.ErrorContains(t, blk.Verify(ctx()), "is not keccak(pubkey)")
}

// It must be Keccak-256, not SHA-256: the address is what holds bridged funds
// on every EVM chain and what an external ecrecover produces from a signature
// by this key.
func TestTheCustodyAddressIsTheOneAnExternalEcrecoverProduces(t *testing.T) {
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 23)
	digest := digestOf(5)
	sig := key.sign(t, digest)

	pub, err := luxcrypto.Ecrecover(digest, sig)
	require.NoError(t, err)
	require.Equal(t, key.rec.Address, publicKeyToAddress(pub),
		"the registered address is not the account an external chain sees signing")
}

func TestAKeygenWithoutARecordRegistersNothing(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 24)
	op := key.keygenOp(t)
	op.Key = nil
	require.ErrorIs(t, blockOver(t, vm, op).Verify(ctx()), ErrInvalidOperation)
}

func TestAKeygenWhoseRecordNamesADifferentKeyIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 25)
	op := key.keygenOp(t)
	op.KeyID = "somewhere-else"
	require.ErrorIs(t, blockOver(t, vm, op).Verify(ctx()), ErrInvalidOperation)
}

func TestAKeygenWhoseDigestIsNotItsOwnCommitmentIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 26)
	op := key.keygenOp(t)
	op.Digest = digestOf(9)
	op.Artifact = key.sign(t, op.Digest) // a real signature, over the wrong thing
	require.ErrorIs(t, blockOver(t, vm, op).Verify(ctx()), ErrInvalidOperation)
}

// Proof of possession: the registering key signs its own commitment. Without
// it a proposer registers a public key it does not hold — a rogue-key
// registration that names an attacker's address as the chain's custodian.
func TestAKeyMustProveItCanSignItsOwnRegistration(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 27)
	impostor := newCustody(t, "vault", quorum.MustNew(3, 5), 28)

	op := key.keygenOp(t)
	op.Artifact = impostor.sign(t, op.Digest) // signed by a key that is not this one
	require.ErrorIs(t, blockOver(t, vm, op).Verify(ctx()), ErrBadArtifact)
}

func TestAKeyIsRegisteredOnce(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 29)
	key.register(t, vm)

	require.ErrorIs(t, blockOver(t, vm, key.keygenOp(t)).Verify(ctx()), ErrCeremonyExists)

	// And under a fresh ceremony id — a genuinely different registration of the
	// same id — the key registry itself refuses.
	again := newCustody(t, "vault", quorum.MustNew(4, 5), 30)
	require.ErrorIs(t, blockOver(t, vm, again.keygenOp(t)).Verify(ctx()), ErrKeyExists)
}

func TestTheSameKeyCannotBeRegisteredTwiceInOneBlock(t *testing.T) {
	vm := newVM(t)
	a := newCustody(t, "vault", quorum.MustNew(3, 5), 31)
	b := newCustody(t, "vault", quorum.MustNew(4, 5), 32)
	require.ErrorIs(t, blockOver(t, vm, a.keygenOp(t), b.keygenOp(t)).Verify(ctx()), ErrKeyExists)
}

// A key registered earlier in the same block can be used later in it, which is
// what lets a chain register and immediately sign without waiting a height.
func TestAKeyRegisteredInABlockIsUsableInThatBlock(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 33)

	blk := blockOver(t, vm, key.keygenOp(t), key.signOpOver(t, digestOf(1)))
	require.NoError(t, blk.Verify(ctx()))
	require.NoError(t, blk.Accept(ctx()))

	rec, err := vm.Key("vault")
	require.NoError(t, err)
	require.Equal(t, key.rec.GroupPublicKey, rec.GroupPublicKey)
}

// One honest participant is enough to stop a mis-declared key. The proof of
// possession alone cannot bind the degree — a single party holding the whole
// secret could also produce one — so a validator that holds a share for the key
// compares the record against what its own share says and contradicts it.
func TestOneParticipantContradictsAMisdeclaredKey(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 34)

	// This node holds a share whose group key is a different key entirely.
	stranger := newCustody(t, "stranger", quorum.MustNew(3, 5), 35)
	key.hold(vm, testShare(t, stranger.rec.GroupPublicKey, key.rec.Degree()))
	require.ErrorContains(t, blockOver(t, vm, key.keygenOp(t)).Verify(ctx()),
		"our share belongs to")

	// And a share of the right key generated at a different degree.
	key.hold(vm, testShare(t, key.rec.GroupPublicKey, key.rec.Degree()+1))
	require.ErrorContains(t, blockOver(t, vm, key.keygenOp(t)).Verify(ctx()),
		"our share has degree")

	// Agreement lets it through.
	key.hold(vm, testShare(t, key.rec.GroupPublicKey, key.rec.Degree()))
	require.NoError(t, blockOver(t, vm, key.keygenOp(t)).Verify(ctx()))
}

// A node that holds no share for the key has nothing to compare and says so by
// admitting the block on the evidence that does not need participation.
func TestANonParticipantVerifiesWithoutAShare(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 36)
	require.Empty(t, vm.shares)
	require.NoError(t, blockOver(t, vm, key.keygenOp(t)).Verify(ctx()))
}

// An unreadable share is a corrupted store, not a reason to admit the block.
func TestAnUnreadableShareRefusesRatherThanAbstains(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 37)
	key.hold(vm, &heldShare{kind: KindCGGMP21})
	require.ErrorContains(t, blockOver(t, vm, key.keygenOp(t)).Verify(ctx()), "reading own share")
}

// -----------------------------------------------------------------------------
// Sign
// -----------------------------------------------------------------------------

func TestSigningWithAnUnregisteredKeyIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "never-registered", quorum.MustNew(3, 5), 38)
	require.ErrorIs(t, blockOver(t, vm, key.signOpOver(t, digestOf(1))).Verify(ctx()), ErrUnknownKey)
}

func TestADigestThatIsNotThirtyTwoBytesIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 39)
	key.register(t, vm)

	for _, n := range []int{0, 31, 33, 64} {
		op := key.signOpOver(t, digestOf(1))
		op.Digest = make([]byte, n)
		require.ErrorIsf(t, blockOver(t, vm, op).Verify(ctx()), ErrInvalidOperation, "digest of %d bytes", n)
	}
}

// The signer set must satisfy the key's own policy, and it must be a real set
// of real participants — counted the way the policy counts.
//
// K signers, not K-1: a set the size of the polynomial degree cannot produce a
// signature, so a record claiming one did is either a lie or a wrong-degree key.
func TestAQuorumSmallerThanThePolicyIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 40)
	key.register(t, vm)

	digest := digestOf(1)
	short := quorumFor(key.rec, digest)[:2]
	op := &Operation{
		Type:       OpTypeSign,
		CeremonyID: ceremonyID(key.rec.KeyID, digest, short),
		KeyID:      key.rec.KeyID,
		Digest:     digest,
		Artifact:   key.sign(t, digest),
		Signers:    short,
	}
	require.ErrorIs(t, blockOver(t, vm, op).Verify(ctx()), ErrQuorumTooSmall)
}

// One signer counted K times is not K signers. Without canonicality, a quorum
// is a number a proposer can reach alone — by repeating a name, or by spelling
// one name several ways.
func TestOneSignerRepeatedIsNotAQuorum(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 41)
	key.register(t, vm)

	digest := digestOf(1)
	one := quorumFor(key.rec, digest)[0]
	for name, signers := range map[string][]party.ID{
		"repeated":  {one, one, one},
		"unsorted":  {"pc", "pa", "pb"},
		"strangers": {"za", "zb", "zc"},
	} {
		op := &Operation{
			Type:       OpTypeSign,
			CeremonyID: ceremonyID(key.rec.KeyID, digest, signers),
			KeyID:      key.rec.KeyID,
			Digest:     digest,
			Artifact:   key.sign(t, digest),
			Signers:    signers,
		}
		require.ErrorIsf(t, blockOver(t, vm, op).Verify(ctx()), ErrInvalidOperation, "%s", name)
	}
}

// The ceremony id must be the one this exact task derives. That is what makes
// the id unforgeable rather than a proposer-chosen label, and it is what makes
// replay detection mean anything: two spellings of one task would be two log
// entries, and for a release, two releases.
func TestASigningCeremonyIdIsDerivedFromItsTask(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 42)
	key.register(t, vm)

	op := key.signOpOver(t, digestOf(1))
	op.CeremonyID = "mpc/whatever-i-like"
	require.ErrorContains(t, blockOver(t, vm, op).Verify(ctx()), "not derived from this task")
}

// The check that needs no participation and no trust: does the signature verify
// under the registered group key, over the digest the operation names?
func TestASignatureForOneMessageDoesNotVerifyForAnother(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 43)
	key.register(t, vm)

	honest := key.signOpOver(t, digestOf(1))
	other := key.signOpOver(t, digestOf(2))

	// A real signature by the real custody key, moved onto a different message.
	forged := &Operation{
		Type:       OpTypeSign,
		CeremonyID: honest.CeremonyID,
		KeyID:      honest.KeyID,
		Digest:     honest.Digest,
		Artifact:   other.Artifact,
		Signers:    honest.Signers,
	}
	require.ErrorIs(t, blockOver(t, vm, forged).Verify(ctx()), ErrBadArtifact)
}

func TestASignatureByAKeyThatIsNotTheCustodianIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 44)
	key.register(t, vm)
	impostor := newCustody(t, "vault", quorum.MustNew(3, 5), 45)

	op := key.signOpOver(t, digestOf(1))
	op.Artifact = impostor.sign(t, op.Digest)
	require.ErrorIs(t, blockOver(t, vm, op).Verify(ctx()), ErrBadArtifact)
}

// -----------------------------------------------------------------------------
// The root
// -----------------------------------------------------------------------------

// Every block carries the state it reaches, and every validator recomputes it.
// Two validators that would diverge cannot both accept.
func TestAClaimedRootThatIsNotTheReachedRootIsRefused(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 46)
	key.register(t, vm)

	blk := blockOver(t, vm, key.signOpOver(t, digestOf(1)))
	blk.StateRoot[0] ^= 0xff
	blk.ID_ = blk.computeID()
	require.ErrorIs(t, blk.Verify(ctx()), ErrRootMismatch)
}

// The root binds the CHAIN, so a block built on one chain does not verify on
// another. The genesis root is seeded from the chain id, and every later root
// is a hash chain over it, so an identical operation history on a different
// chain reaches a different root.
func TestABlockDoesNotCrossFromOneChainToAnother(t *testing.T) {
	a, b := newVM(t), newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 47)

	require.NotEqual(t, a.StateRoot(), b.StateRoot(),
		"two chains with empty state must not share a root, or a block from one applies to the other")

	blk := blockOver(t, a, key.keygenOp(t))
	require.NoError(t, blk.Verify(ctx()))

	// The same bytes, handed to the other chain.
	crossed, err := b.ParseBlock(ctx(), blk.Bytes())
	require.NoError(t, err)
	require.Error(t, crossed.Verify(ctx()),
		"a block built on chain A must not verify on chain B")
}

// Operation digests are domain-separated by kind, so a keygen digest can never
// be replayed as a sign digest even when every other field coincides.
func TestAKeygenDigestIsNotASignDigest(t *testing.T) {
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 48)
	kg := key.keygenOp(t)

	sign := &Operation{
		Type:       OpTypeSign,
		CeremonyID: kg.CeremonyID,
		KeyID:      kg.KeyID,
		Digest:     kg.Digest,
		Artifact:   kg.Artifact,
		Signers:    kg.Signers,
	}
	require.NotEqual(t, kg.digest(), sign.digest())
}

// -----------------------------------------------------------------------------
// Accept and Reject
// -----------------------------------------------------------------------------

func TestARejectedBlockLeavesItsCeremoniesStaged(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 49)
	key.register(t, vm)

	op := key.signOpOver(t, digestOf(1))
	vm.stage(op)
	built, err := vm.BuildBlock(ctx())
	require.NoError(t, err)

	require.NoError(t, built.Reject(ctx()))
	require.Equal(t, uint8(choices.Rejected), built.(*Block).Status(), "a rejected block reports rejected")
	require.Equal(t, choices.Rejected, built.(*Block).ChoicesStatus())
	require.Equal(t, 1, vm.staged.Len(),
		"rejection means the block did not land, not that the ceremony was invalid")

	// So the ceremony reaches the next block instead.
	next, err := vm.BuildBlock(ctx())
	require.NoError(t, err)
	require.NoError(t, next.Verify(ctx()))
	require.NoError(t, next.Accept(ctx()))
	require.Zero(t, vm.staged.Len())
}

func TestAnAcceptedBlockPublishesItsRootAndReleasesItsCeremonies(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 50)
	key.register(t, vm)

	op := key.signOpOver(t, digestOf(1))
	vm.stage(op)
	built, err := vm.BuildBlock(ctx())
	require.NoError(t, err)
	require.NoError(t, built.Verify(ctx()))
	require.NoError(t, built.Accept(ctx()))

	require.Equal(t, built.(*Block).StateRoot, vm.StateRoot())
	require.Zero(t, vm.staged.Len())
	require.Equal(t, uint8(choices.Accepted), built.(*Block).Status())

	tip, err := vm.LastAccepted(ctx())
	require.NoError(t, err)
	require.Equal(t, built.ID(), tip)

	rec, err := vm.Ceremony(op.CeremonyID)
	require.NoError(t, err)
	require.Equal(t, built.(*Block).BlockHeight, rec.Height,
		"a recorded ceremony names the height that recorded it")
}

// -----------------------------------------------------------------------------
// verifyGroupSignature, in isolation
// -----------------------------------------------------------------------------

func TestGroupSignatureShapesAreRefusedBeforeTheCurveIsTouched(t *testing.T) {
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 51)
	digest := digestOf(1)
	sig := key.sign(t, digest)
	pub := key.rec.GroupPublicKey

	require.NoError(t, verifyGroupSignature(pub, digest, sig))

	for name, call := range map[string]func() error{
		"short signature":     func() error { return verifyGroupSignature(pub, digest, sig[:64]) },
		"long signature":      func() error { return verifyGroupSignature(pub, digest, append(sig, 0)) },
		"short digest":        func() error { return verifyGroupSignature(pub, digest[:31], sig) },
		"uncompressed key":    func() error { return verifyGroupSignature(uncompressedXY(pub), digest, sig) },
		"empty key":           func() error { return verifyGroupSignature(nil, digest, sig) },
		"wrong key same size": func() error { return verifyGroupSignature(flip(pub), digest, sig) },
	} {
		require.Errorf(t, call(), "%s must not verify", name)
	}
}

// The recovery byte is not verified against — only r‖s — so a wrong v cannot
// make a good signature fail, and cannot make a bad one pass.
func TestTheRecoveryByteChangesNoVerdict(t *testing.T) {
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 52)
	digest := digestOf(1)
	good := key.sign(t, digest)
	bad := key.sign(t, digestOf(2))
	bad = append(append([]byte(nil), bad[:64]...), good[64])

	for v := 0; v < 256; v++ {
		g := append(append([]byte(nil), good[:64]...), byte(v))
		require.NoErrorf(t, verifyGroupSignature(key.rec.GroupPublicKey, digest, g), "v=%d", v)
		b := append(append([]byte(nil), bad[:64]...), byte(v))
		require.Errorf(t, verifyGroupSignature(key.rec.GroupPublicKey, digest, b), "v=%d", v)
	}
}

// -----------------------------------------------------------------------------
// Public-key normalisation
// -----------------------------------------------------------------------------

func TestEveryAcceptedKeyEncodingDerivesOneAddress(t *testing.T) {
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 53)
	compressed := key.rec.GroupPublicKey
	xy := uncompressedXY(compressed)
	require.Len(t, xy, 64)

	want := publicKeyToAddress(compressed)
	require.Equal(t, want, publicKeyToAddress(xy))
	require.Equal(t, want, publicKeyToAddress(append([]byte{0x04}, xy...)))
}

func TestAKeyThatIsNotAPointDerivesNoAddress(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":               nil,
		"short":               make([]byte, 20),
		"33 bytes, off curve": func() []byte { b := make([]byte, 33); b[0] = 0x02; return b }(),
		"65 bytes, bad tag":   make([]byte, 65),
		"66 bytes":            make([]byte, 66),
	} {
		require.Nilf(t, uncompressedXY(b), "%s", name)
		require.Nilf(t, publicKeyToAddress(b), "%s: callers must treat nil as a hard failure", name)
	}
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func flip(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[len(out)-1] ^= 0xff
	return out
}

// testShare is a share whose two publicly-derivable facts — the group key it
// belongs to and the degree it was generated at — are the ones a test names.
//
// One party in Public makes the Lagrange coefficient 1, so PublicPoint() is
// exactly that party's point. The real cross-check reads these two values out
// of a real CMP config; what is under test is what it DOES with them.
func testShare(t *testing.T, groupPub []byte, degree int) *heldShare {
	t.Helper()
	grp := curve.Secp256k1{}
	pt := grp.NewPoint()
	require.NoError(t, pt.UnmarshalBinary(groupPub))
	return &heldShare{
		kind: KindCGGMP21,
		cmp: &cmpconfig.Config{
			Group:     grp,
			ID:        "pa",
			Threshold: degree,
			Public:    map[party.ID]*cmpconfig.Public{"pa": {ECDSA: pt}},
		},
	}
}
