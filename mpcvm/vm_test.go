// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// vm_test.go — boot, configuration, and the entry points that are reachable
// from outside the ceremony path.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/constants"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/pkg/quorum"
	validators "github.com/luxfi/validators"
	"github.com/luxfi/validators/validatorstest"
	vmcore "github.com/luxfi/vm"
	vmchain "github.com/luxfi/vm/chain"
	"github.com/luxfi/warp"
)

// -----------------------------------------------------------------------------
// Boot
// -----------------------------------------------------------------------------

// A restarted node comes back at the height it left, with the registry it had.
// Recomputing genesis unconditionally would discard every accepted block and
// re-run history from an empty registry — which for a custody chain means
// losing the record of who holds the funds.
func TestARestartedNodeResumesItsCustodyRegistry(t *testing.T) {
	db := memdb.New()
	chainID := ids.GenerateTestID()

	first := openVM(t, db, chainID, nil, nil)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 60)
	blk := key.register(t, first)
	wantRoot := first.StateRoot()
	require.NoError(t, first.Shutdown(ctx()))

	second := openVM(t, db, chainID, nil, nil)
	defer second.Shutdown(ctx())

	tip, err := second.LastAccepted(ctx())
	require.NoError(t, err)
	require.Equal(t, blk.ID(), tip, "a restarted node must come back at the tip it accepted")
	require.Equal(t, wantRoot, second.StateRoot())

	rec, err := second.Key("vault")
	require.NoError(t, err)
	require.Equal(t, key.rec.GroupPublicKey, rec.GroupPublicKey)

	at, err := second.GetBlockIDAtHeight(ctx(), blk.BlockHeight)
	require.NoError(t, err)
	require.Equal(t, blk.ID(), at, "the height index survives a restart; an in-memory one would not")

	// And the block itself is readable back out of committed state, decoded by
	// the same parser the wire uses.
	got, err := second.GetBlock(ctx(), blk.ID())
	require.NoError(t, err)
	require.Equal(t, blk.ID(), got.ID())
}

// A restart before the first block. This chain seeds nothing — Seed commits
// what NewState staged and writes no records of its own — so re-running the
// genesis path was idempotent and this node never carried the restart failure
// that a chain WITH an allocation carries. It shares the shape and not the
// defect, and the difference is worth pinning: the tip Seed now records is
// what makes the second boot resume rather than install genesis again, and
// either way the root it comes back at is the one it left.
func TestARestartBeforeTheFirstBlockKeepsItsGenesisRoot(t *testing.T) {
	db := memdb.New()
	chainID := ids.GenerateTestID()

	first := openVM(t, db, chainID, nil, nil)
	root := first.StateRoot()
	require.NoError(t, first.Shutdown(ctx()))

	second := openVM(t, db, chainID, nil, nil)
	defer second.Shutdown(ctx())

	require.Equal(t, root, second.StateRoot())
	tip, height := second.chain.Tip()
	require.Equal(t, second.genesisBlock.ID(), tip, "still sitting on genesis")
	require.Zero(t, height)

	// And it can do what a node that restarted is for.
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 62)
	blk := key.register(t, second)
	require.EqualValues(t, 1, blk.BlockHeight)
}

// "Fresh chain" is a claim about the tip pointer, and this checks it against
// the thing it implies: a chain that has applied nothing is at its genesis
// root, and one that has applied anything is not.
//
// A missing tip over a live registry is what a partial restore looks like — the
// block namespace rolled back, or a key range wiped, while the custody records
// survive. Believing the pointer there installs genesis over the registry,
// durably, and the next accepted block writes a new tip on top. Refusing to
// start loses nothing: the operator can look at the disk, and a node that will
// not start holds no funds wrongly.
func TestAMissingTipOverALiveRegistryDoesNotReinstallGenesis(t *testing.T) {
	db := memdb.New()
	chainID := ids.GenerateTestID()

	first := openVM(t, db, chainID, nil, nil)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 61)
	key.register(t, first)
	require.NoError(t, first.Shutdown(ctx()))

	// The tip is on disk; the node restarts normally.
	require.NoError(t, openVM(t, db, chainID, nil, nil).Shutdown(ctx()))

	// The tip is gone and the registry is not.
	require.NoError(t, db.Delete([]byte("chain/tip")))
	vm := &VM{}
	err := vm.Initialize(ctx(), vmcore.Init{
		Runtime:  &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), ChainID: chainID},
		DB:       db,
		Log:      log.NewNoOpLogger(),
		ToEngine: make(chan vmcore.Message, 1),
	})
	require.ErrorContains(t, err, "refusing to install genesis over applied state")

	// And the registry is still there, because nothing was written over it.
	rec, err := NewState(db, chainID)
	require.NoError(t, err)
	_, err = rec.GetKey("vault")
	require.NoError(t, err)
}

// A genuinely empty database seeds genesis and commits the root, so a node that
// accepts no block still comes back to the same root rather than re-deriving
// one.
func TestAFreshChainSeedsItsRootAndComesBackToIt(t *testing.T) {
	db := memdb.New()
	chainID := ids.GenerateTestID()

	first := openVM(t, db, chainID, nil, nil)
	root := first.StateRoot()
	require.Equal(t, genesisRoot(chainID), root)
	require.NoError(t, first.Shutdown(ctx()))

	second := openVM(t, db, chainID, nil, nil)
	defer second.Shutdown(ctx())
	require.Equal(t, root, second.StateRoot())

	tip, err := second.LastAccepted(ctx())
	require.NoError(t, err)
	require.Equal(t, second.genesisBlock.ID(), tip)
}

// The genesis timestamp is part of the genesis block, so two nodes given the
// same genesis derive the same id for it.
func TestGenesisIsDerivedFromWhatEveryValidatorHolds(t *testing.T) {
	chainID := ids.GenerateTestID()
	genesis, err := json.Marshal(Genesis{Timestamp: 1_700_000_000, Policy: quorum.MustNew(4, 7)})
	require.NoError(t, err)

	a := openVM(t, memdb.New(), chainID, nil, genesis)
	b := openVM(t, memdb.New(), chainID, nil, genesis)
	defer a.Shutdown(ctx())
	defer b.Shutdown(ctx())

	require.Equal(t, a.genesisBlock.ID(), b.genesisBlock.ID())
	require.Equal(t, int64(1_700_000_000), a.genesisBlock.BlockTimestamp)
	require.Equal(t, "4-of-7", a.Policy().String(),
		"a genesis policy overrides the per-node config, so the chain's quorum is one value")
}

func TestUnparseableGenesisRefusesToBoot(t *testing.T) {
	vm := &VM{}
	err := vm.Initialize(ctx(), vmcore.Init{
		Runtime:  &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), ChainID: ids.GenerateTestID()},
		DB:       memdb.New(),
		Genesis:  []byte("{not json"),
		Log:      log.NewNoOpLogger(),
		ToEngine: make(chan vmcore.Message, 1),
	})
	require.ErrorContains(t, err, "failed to parse genesis")
}

// A malformed genesis policy leaves the config default in place rather than
// failing: an absent policy is the normal case, and the config default is the
// documented fallback.
func TestAnAbsentGenesisPolicyLeavesTheConfigDefault(t *testing.T) {
	genesis, err := json.Marshal(map[string]any{"timestamp": 5})
	require.NoError(t, err)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, genesis)
	defer vm.Shutdown(ctx())
	require.Equal(t, "3-of-5", vm.Policy().String())
}

// The default policy is 3-of-5, and two seats are deliberately not a quorum:
// validator entry is permissionless, so a policy an adversary can buy two seats
// into is a policy it holds a quorum of every key with.
func TestTheDefaultQuorumCostsAMajorityOfTheCustodySet(t *testing.T) {
	vm := newVM(t)
	p := vm.Policy()
	require.Equal(t, "3-of-5", p.String())
	require.Equal(t, 2, p.Degree())
	require.True(t, 2*p.K > p.N, "the default policy must admit only one quorum at a time")
}

// A policy that does not decode is a hard failure, not a default. Falling back
// to a built-in quorum for a chain holding bridged funds would mean the
// operator's intent and the deployed key silently differ.
func TestAnUndeployablePolicyRefusesToBoot(t *testing.T) {
	for _, cfg := range []string{
		`{"policy":"1-of-5"}`,
		`{"policy":"9-of-5"}`,
		`{"policy":"nonsense"}`,
		`{"policy":""}`,
		`{}`,
	} {
		vm := &VM{}
		err := vm.Initialize(ctx(), vmcore.Init{
			Runtime:  &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), ChainID: ids.GenerateTestID()},
			DB:       memdb.New(),
			Config:   []byte(cfg),
			Log:      log.NewNoOpLogger(),
			ToEngine: make(chan vmcore.Message, 1),
		})
		require.Errorf(t, err, "config %s must not boot", cfg)
	}
}

func TestUnparseableConfigRefusesToBoot(t *testing.T) {
	vm := &VM{}
	err := vm.Initialize(ctx(), vmcore.Init{
		Runtime:  &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), ChainID: ids.GenerateTestID()},
		DB:       memdb.New(),
		Config:   []byte("{"),
		Log:      log.NewNoOpLogger(),
		ToEngine: make(chan vmcore.Message, 1),
	})
	require.ErrorContains(t, err, "failed to parse config")
}

// An operator-supplied config replaces the defaults wholesale, including the
// permission table: a config that names one chain grants custody to one chain.
func TestAnOperatorConfigReplacesTheStockPermissionTable(t *testing.T) {
	bridge := ids.GenerateTestID()
	cfg := fmt.Sprintf(`{"policy":"2-of-3","sessionTimeout":60000000000,
		"authorizedChains":{"B-Chain":{"chainId":%q,"canSign":true,"canKeygen":true,"maxSigningSize":64}}}`, bridge)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, nil, cfg)
	defer vm.Shutdown(ctx())

	require.Equal(t, "2-of-3", vm.Policy().String())
	require.Equal(t, time.Minute, vm.sessionTimeout())

	by, err := vm.caller(bridge)
	require.NoError(t, err)
	require.Equal(t, "B-Chain", by.Name())

	perms, ok := vm.permissions("B-Chain")
	require.True(t, ok)
	require.True(t, perms.CanSign)
	_, ok = vm.permissions("X-Chain")
	require.False(t, ok, "the stock entries are gone; the operator's table is the table")
}

// The boot log distinguishes a permission entry BOUND to a chain id from one
// carrying a label. A label never equals a base58 chain id, so an entry
// carrying one authorizes nobody — and counting it as bound reported five
// authorized chains on a node where none were.
func TestOnlyAnEntryCarryingARealChainIdCountsAsBound(t *testing.T) {
	real := ids.GenerateTestID()
	cfg := fmt.Sprintf(`{"policy":"3-of-5","authorizedChains":{
		"B-Chain":{"chainId":"B-Chain"},
		"C-Chain":{"chainId":""},
		"X-Chain":{"chainId":%q}}}`, real)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, nil, cfg)
	defer vm.Shutdown(ctx())

	// The one that is bound resolves; the two that are not do not, whatever
	// they are called.
	by, err := vm.caller(real)
	require.NoError(t, err)
	require.Equal(t, "X-Chain", by.Name())
	_, err = vm.caller(ids.GenerateTestID())
	require.ErrorIs(t, err, ErrUnauthorizedChain)
}

// The stock table binds nothing: every entry names a chain by label, so a
// default node grants custody to nobody until an operator sets chainId.
func TestTheStockPermissionTableGrantsCustodyToNobody(t *testing.T) {
	vm := newVM(t)
	require.NotEmpty(t, vm.config.AuthorizedChains)
	for name, p := range vm.config.AuthorizedChains {
		_, err := ids.FromString(p.ChainID)
		require.Errorf(t, err, "stock entry %q must not carry a parseable chain id", name)
	}
	_, err := vm.caller(ids.GenerateTestID())
	require.ErrorIs(t, err, ErrUnauthorizedChain)
}

// A node that restarts reloads its shares, and a share that does not match the
// registry it is filed under is a corrupted store: signing with it would
// produce signatures that fail against the registered group key.
func TestAShareThatDoesNotMatchItsRegistryEntryRefusesToBoot(t *testing.T) {
	raw, _, _ := realShare(t)

	// The registry says this key is a DIFFERENT group key from the one the
	// stored share belongs to. Signing with it would produce signatures that
	// fail against the registered key, so there is nothing to recover to.
	stranger := newCustody(t, "vault", quorum.MustNew(3, 5), 62)
	require.ErrorContains(t, bootWithStoredShare(t, stranger.rec, raw),
		"belongs to a different group key")
}

func TestAShareAtTheWrongDegreeRefusesToBoot(t *testing.T) {
	raw, pub, degree := realShare(t)

	// Right group key, but the registry declares a quorum the share was not
	// generated for — the off-by-one this whole design exists to catch.
	rec := custodyFor(t, "vault", quorum.MustNew(degree+3, degree+4), pub)
	require.NotEqual(t, degree, rec.Degree())
	require.ErrorContains(t, bootWithStoredShare(t, rec, raw), "has degree")
}

// A share that agrees with its registry entry is loaded, and the node comes back
// able to sign. Without it a restarted validator is a registry reader counted as
// a committee member while unable to contribute a partial signature.
func TestAShareThatAgreesWithItsRegistryEntryIsReloaded(t *testing.T) {
	raw, pub, degree := realShare(t)
	rec := custodyFor(t, "vault", quorum.MustNew(degree+1, degree+2), pub)
	require.Equal(t, degree, rec.Degree())

	db, chainID := memdb.New(), ids.GenerateTestID()
	seedRegistryAndShare(t, db, chainID, rec, raw)

	vm := openVM(t, db, chainID, nil, nil)
	defer vm.Shutdown(ctx())
	require.Contains(t, vm.shares, "vault")

	health, err := vm.HealthCheck(ctx())
	require.NoError(t, err)
	require.Equal(t, "1", health.Details["sharesHeld"])
}

func TestAnUnreadableShareRefusesToBoot(t *testing.T) {
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 65)
	require.ErrorContains(t, bootWithStoredShare(t, key.rec, []byte("not a config")), "load key shares")
}

// A key this node holds no share for is skipped rather than failing the boot:
// a validator legitimately participates in some keys and not others.
func TestARestartedNodeReloadsOnlyTheSharesItHolds(t *testing.T) {
	raw, pub, degree := realShare(t)
	mine := custodyFor(t, "mine", quorum.MustNew(degree+1, degree+2), pub)
	theirs := newCustody(t, "theirs", quorum.MustNew(3, 5), 67)

	db, chainID := memdb.New(), ids.GenerateTestID()
	seedRegistryAndShare(t, db, chainID, mine, raw)

	seed := openVM(t, db, chainID, nil, nil)
	require.NoError(t, seed.state.PutKey(theirs.rec))
	require.NoError(t, seed.chain.Seed(func(database.Database) error { return nil }))
	require.NoError(t, seed.Shutdown(ctx()))

	restarted := openVM(t, db, chainID, nil, nil)
	defer restarted.Shutdown(ctx())
	require.Len(t, restarted.shares, 1)
	require.Contains(t, restarted.shares, "mine")
}

// M-Chain's committee is the primary network's validator set. Nothing else on
// this chain decides who may hold a share.
func TestTheCommitteeIsThePrimaryNetworkValidatorSet(t *testing.T) {
	vm := newVM(t)
	require.Equal(t, constants.PrimaryNetworkID, vm.netID)
}

// -----------------------------------------------------------------------------
// Reads
// -----------------------------------------------------------------------------

func TestTheRegistryIsReadableThroughTheVM(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 68)
	key.register(t, vm)

	keys, err := vm.Keys()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pub, err := vm.PublicKey("vault")
	require.NoError(t, err)
	require.Equal(t, key.rec.GroupPublicKey, pub)

	addr, err := vm.Address("vault")
	require.NoError(t, err)
	require.Equal(t, key.rec.Address, addr)

	_, err = vm.PublicKey("nothing")
	require.ErrorIs(t, err, ErrUnknownKey)
	_, err = vm.Address("nothing")
	require.ErrorIs(t, err, ErrUnknownKey)

	ceremonies, err := vm.Ceremonies()
	require.NoError(t, err)
	require.Len(t, ceremonies, 1)
	_, err = vm.Ceremony("mpc/never")
	require.Error(t, err)
}

// Health is "can this node read its own state", not "does this node hold a
// key". A validator that holds no share still serves reads and still verifies
// every block; gating health on key material takes healthy nodes out of
// rotation for doing their job. What such a node cannot do is visible in
// sharesHeld.
func TestHealthIsAboutReadingStateNotHoldingKeys(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 69)
	key.register(t, vm)

	health, err := vm.HealthCheck(ctx())
	require.NoError(t, err)
	require.True(t, health.Healthy, "a node holding no share is healthy")
	require.Equal(t, "1", health.Details["custodyKeys"])
	require.Equal(t, "0", health.Details["sharesHeld"])
	require.Equal(t, "0", health.Details["stagedCeremonies"])
	require.Len(t, health.Details["stateRoot"], 64)

	// And the HTTP probe reports the same thing, from the same call — a probe
	// that computed health separately could say "healthy" while the engine was
	// being told otherwise.
	w := httptest.NewRecorder()
	vm.handleHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Healthy bool              `json:"healthy"`
		Details map[string]string `json:"details"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.True(t, body.Healthy)
	require.Equal(t, health.Details, body.Details)
}

// A node that cannot read its registry is not healthy, and says so with a
// service-unavailable rather than a healthy body.
func TestANodeThatCannotReadItsRegistryIsNotHealthy(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 70)
	key.register(t, vm)

	vm.state.db = &faultyIterDB{Database: vm.state.db}
	_, err := vm.HealthCheck(ctx())
	require.Error(t, err)

	w := httptest.NewRecorder()
	vm.handleHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Contains(t, w.Body.String(), "error")
}

func TestTheVMServesItsRPCAndHealthHandlers(t *testing.T) {
	vm := newVM(t)

	handlers, err := vm.CreateHandlers(ctx())
	require.NoError(t, err)
	require.Contains(t, handlers, "/rpc")
	require.Contains(t, handlers, "/health")

	static, err := vm.CreateStaticHandlers(ctx())
	require.NoError(t, err)
	require.Nil(t, static, "M-Chain has no chain-independent surface")

	h, err := vm.NewHTTPHandler(ctx())
	require.NoError(t, err)
	require.NotNil(t, h)

	version, err := vm.Version(ctx())
	require.NoError(t, err)
	require.Equal(t, Version.String(), version)
}

// -----------------------------------------------------------------------------
// Building
// -----------------------------------------------------------------------------

func TestABuilderWithNothingStagedProposesNothing(t *testing.T) {
	vm := newVM(t)
	_, err := vm.BuildBlock(ctx())
	require.ErrorContains(t, err, "no completed ceremonies")
}

// A ceremony staged and then invalidated by a block that landed first is
// dropped rather than proposed: proposing it would build a block every peer
// rejects, and it would keep doing so.
func TestAStagedCeremonyInvalidatedByAnEarlierBlockIsDropped(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 71)
	key.register(t, vm)

	op := key.signOpOver(t, digestOf(1))
	landed := blockOver(t, vm, op)
	require.NoError(t, landed.Verify(ctx()))
	require.NoError(t, landed.Accept(ctx()))

	// The same ceremony completes again on this node and is staged. It is now
	// recorded, so it cannot go into another block.
	vm.stage(op)
	vm.stage(key.signOpOver(t, digestOf(2)))
	built, err := vm.BuildBlock(ctx())
	require.NoError(t, err)
	require.Len(t, built.(*Block).Operations, 1, "the recorded ceremony must not be re-proposed")
	require.NoError(t, built.Verify(ctx()))
}

func TestABuilderWithOnlyInvalidCeremoniesProposesNothing(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 72)
	key.register(t, vm)

	op := key.signOpOver(t, digestOf(1))
	landed := blockOver(t, vm, op)
	require.NoError(t, landed.Verify(ctx()))
	require.NoError(t, landed.Accept(ctx()))

	vm.stage(op)
	_, err := vm.BuildBlock(ctx())
	require.ErrorContains(t, err, "no completed ceremonies")
	require.Zero(t, vm.staged.Len(), "an operation that can never be included is dropped, not requeued")
}

// The builder is demand-driven: it wakes when a ceremony completes, and blocks
// otherwise. Returning eagerly would spin the engine; blocking forever would
// mean a completed ceremony never reaches a block.
func TestTheBuilderWakesOnACompletedCeremonyAndNotBefore(t *testing.T) {
	vm := newVM(t)

	early, cancel := context.WithTimeout(ctx(), 20*time.Millisecond)
	defer cancel()
	_, err := vm.WaitForEvent(early)
	require.Error(t, err, "with nothing staged there is nothing for the engine to do")

	key := newCustody(t, "vault", quorum.MustNew(3, 5), 73)
	key.register(t, vm)
	vm.stage(key.signOpOver(t, digestOf(1)))

	woken, cancel2 := context.WithTimeout(ctx(), 2*time.Second)
	defer cancel2()
	msg, err := vm.WaitForEvent(woken)
	require.NoError(t, err)
	require.Equal(t, vmcore.PendingTxs, msg.Type,
		"a completed ceremony is the only thing that wakes the builder")
}

// -----------------------------------------------------------------------------
// Parsing
// -----------------------------------------------------------------------------

func TestABlockIsIdentifiedByItsBytesOnEveryValidator(t *testing.T) {
	a, b := newVM(t), newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 74)

	built := blockOver(t, a, key.keygenOp(t))
	parsed, err := b.ParseBlock(ctx(), built.Bytes())
	require.NoError(t, err)
	require.Equal(t, built.ID(), parsed.ID())
	require.Equal(t, built.Bytes(), parsed.Bytes())
	require.Equal(t, built.BlockHeight, parsed.Height())
	require.Equal(t, built.Timestamp().Unix(), parsed.(*Block).Timestamp().Unix())
	require.Equal(t, built.ParentID_, parsed.(*Block).Parent())
	require.Equal(t, built.ParentID_, parsed.(*Block).ParentID())
}

func TestBytesThatAreNotABlockAreRefused(t *testing.T) {
	vm := newVM(t)
	for name, raw := range map[string][]byte{
		"empty":  nil,
		"junk":   []byte("hello"),
		"header": make([]byte, 16),
	} {
		_, err := vm.ParseBlock(ctx(), raw)
		require.Errorf(t, err, "%s must not parse as a block", name)
	}
}

func TestAnUnknownBlockIsNamedNotEmpty(t *testing.T) {
	vm := newVM(t)
	_, err := vm.GetBlock(ctx(), ids.GenerateTestID())
	require.Error(t, err)
	_, err = vm.GetBlockIDAtHeight(ctx(), 99)
	require.Error(t, err)
}

func TestSetStatusIsWhatTheEngineSaysItIs(t *testing.T) {
	blk := &Block{}
	blk.SetStatus(3)
	require.Equal(t, uint8(3), blk.Status())
}

// -----------------------------------------------------------------------------
// Quota
// -----------------------------------------------------------------------------

// A quota is per-node rate limiting: refusing to START a ceremony is local, and
// a ceremony that completes is verified by everyone on its own evidence. It is
// therefore checked before the ceremony runs and counted after it succeeds.
func TestAChainThatIsOverItsDailyQuotaIsRefusedBeforeTheCeremony(t *testing.T) {
	bridge := ids.GenerateTestID()
	cfg := fmt.Sprintf(`{"policy":"3-of-5","authorizedChains":{
		"B-Chain":{"chainId":%q,"canSign":true,"dailySigningLimit":2}}}`, bridge)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, nil, cfg)
	defer vm.Shutdown(ctx())

	by, err := vm.caller(bridge)
	require.NoError(t, err)

	vm.mu.Lock()
	vm.dailySigningCount["B-Chain"] = 2
	vm.mu.Unlock()

	_, err = vm.RequestSignature(ctx(), by, "vault", digestOf(1))
	require.ErrorIs(t, err, ErrQuotaExceeded)

	// The counters roll over on their own schedule.
	vm.mu.Lock()
	vm.quotaResetTime = time.Now().Add(-time.Second)
	vm.checkQuotaReset()
	remaining := vm.dailySigningCount["B-Chain"]
	next := vm.quotaResetTime
	vm.mu.Unlock()
	require.Zero(t, remaining)
	require.True(t, next.After(time.Now()))
}

// A global override outranks the chain's own limit, so an operator can throttle
// one chain without editing its permission entry.
func TestAGlobalQuotaOverridesTheChainsOwnLimit(t *testing.T) {
	bridge := ids.GenerateTestID()
	cfg := fmt.Sprintf(`{"policy":"3-of-5","dailySigningQuota":{"B-Chain":1},
		"authorizedChains":{"B-Chain":{"chainId":%q,"canSign":true,"dailySigningLimit":1000}}}`, bridge)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, nil, cfg)
	defer vm.Shutdown(ctx())

	by, err := vm.caller(bridge)
	require.NoError(t, err)
	vm.mu.Lock()
	vm.dailySigningCount["B-Chain"] = 1
	vm.mu.Unlock()
	_, err = vm.RequestSignature(ctx(), by, "vault", digestOf(1))
	require.ErrorIs(t, err, ErrQuotaExceeded)
}

// A message larger than the chain is permitted to sign is refused before any
// ceremony starts.
func TestAMessageLargerThanTheChainMaySignIsRefused(t *testing.T) {
	bridge := ids.GenerateTestID()
	cfg := fmt.Sprintf(`{"policy":"3-of-5","authorizedChains":{
		"B-Chain":{"chainId":%q,"canSign":true,"maxSigningSize":16}}}`, bridge)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, nil, cfg)
	defer vm.Shutdown(ctx())

	by, err := vm.caller(bridge)
	require.NoError(t, err)
	_, err = vm.RequestSignature(ctx(), by, "vault", digestOf(1))
	require.ErrorContains(t, err, "message too large")
}

// A chain authorised to sign is not thereby authorised to generate keys, and
// vice versa. The two are separate rights on the same entry.
func TestSigningRightsAndKeygenRightsAreSeparate(t *testing.T) {
	signer, keygen := ids.GenerateTestID(), ids.GenerateTestID()
	cfg := fmt.Sprintf(`{"policy":"3-of-5","authorizedChains":{
		"Signer":{"chainId":%q,"canSign":true},
		"Keygen":{"chainId":%q,"canKeygen":true}}}`, signer, keygen)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, nil, cfg)
	defer vm.Shutdown(ctx())

	signerCaller, err := vm.caller(signer)
	require.NoError(t, err)
	_, err = vm.StartKeygen(ctx(), "vault", signerCaller)
	require.ErrorIs(t, err, ErrUnauthorizedChain)

	keygenCaller, err := vm.caller(keygen)
	require.NoError(t, err)
	_, err = vm.RequestSignature(ctx(), keygenCaller, "vault", digestOf(1))
	require.ErrorIs(t, err, ErrUnauthorizedChain)
}

// -----------------------------------------------------------------------------
// Cross-chain
// -----------------------------------------------------------------------------

// Authorization comes from the chain id the TRANSPORT authenticated, never from
// the requesting-chain field the sender writes about itself. That field
// survives only as attribution, set from the authenticated name.
func TestACrossChainRequestIsAuthorizedByTheTransportNotTheBody(t *testing.T) {
	bridge := ids.GenerateTestID()
	cfg := fmt.Sprintf(`{"policy":"3-of-5","authorizedChains":{
		"B-Chain":{"chainId":%q,"canSign":true,"canKeygen":true}}}`, bridge)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, nil, cfg)
	defer vm.Shutdown(ctx())

	// A stranger whose body says it is B-Chain gets nothing.
	req := &CrossChainMPCRequest{Type: "sign", RequestingChain: "B-Chain", KeyID: "vault", MessageHash: digestOf(1)}
	raw := req.Marshal()
	err := vm.CrossChainRequest(ctx(), ids.GenerateTestID(), 1, time.Now(), raw)
	require.ErrorIs(t, err, ErrUnauthorizedChain)

	// The authenticated chain gets as far as the ceremony, which needs a key.
	err = vm.CrossChainRequest(ctx(), bridge, 1, time.Now(), raw)
	require.ErrorIs(t, err, ErrUnknownKey)

	// And keygen reaches the ceremony, which needs a committee this node has no
	// validator state for.
	kg := &CrossChainMPCRequest{Type: "keygen", KeyID: "vault"}
	require.ErrorIs(t, vm.CrossChainRequest(ctx(), bridge, 1, time.Now(), kg.Marshal()), ErrNoCommittee)
}

func TestAnUnknownCrossChainRequestTypeIsRefused(t *testing.T) {
	bridge := ids.GenerateTestID()
	cfg := fmt.Sprintf(`{"policy":"3-of-5","authorizedChains":{"B-Chain":{"chainId":%q,"canSign":true}}}`, bridge)
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), nil, nil, cfg)
	defer vm.Shutdown(ctx())

	raw := (&CrossChainMPCRequest{Type: "reshare"}).Marshal()
	require.ErrorContains(t, vm.CrossChainRequest(ctx(), bridge, 1, time.Now(), raw), "unknown cross-chain request type")

	require.Error(t, vm.CrossChainRequest(ctx(), bridge, 1, time.Now(), []byte("junk")))
}

// -----------------------------------------------------------------------------
// Gossip
// -----------------------------------------------------------------------------

// A ceremony message is attributable to the peer that sent it.
//
// The threshold library carries the sender in the message body and does not
// authenticate it — it is written for an authenticated channel and expects its
// transport to supply that. This is the transport. party.ID IS the NodeID
// string here, so a message whose From names a different party is one peer
// speaking as another: enough to abort every custody ceremony on demand, and
// enough to make the protocol's identifiable abort name an honest validator
// for it.
func TestAPeerCannotSpeakUnderAnotherPartysName(t *testing.T) {
	vm := newVM(t)
	self, impostor := ids.GenerateTestNodeID(), ids.GenerateTestNodeID()

	router := newGossipRouter(ctx(), "mpc/session", party.ID(self.String()), nil, nil)
	vm.registerSessionRouter("mpc/session", router)
	defer vm.unregisterSessionRouter("mpc/session")

	honest := &protocol.Message{From: party.ID(impostor.String()), Protocol: "cmp", RoundNumber: 1}
	env, err := marshalEnvelope("mpc/session", honest)
	require.NoError(t, err)

	// Sent by the party it names: delivered.
	require.NoError(t, vm.Gossip(ctx(), impostor, env))
	require.Len(t, router.Receive(), 1)
	<-router.Receive()

	// Sent by anyone else, claiming to be that party: dropped.
	require.NoError(t, vm.Gossip(ctx(), ids.GenerateTestNodeID(), env))
	require.Empty(t, router.Receive(),
		"a peer must not be able to inject rounds under another committee member's name")
}

// Malformed gossip is ignored, never faulted on: a peer's junk must not be able
// to fail this node's consensus.
func TestMalformedGossipIsIgnored(t *testing.T) {
	vm := newVM(t)
	require.NoError(t, vm.Gossip(ctx(), ids.GenerateTestNodeID(), []byte("not an envelope")))
	require.NoError(t, vm.Gossip(ctx(), ids.GenerateTestNodeID(), nil))

	bad, err := json.Marshal(sessionEnvelope{SessionID: "s", Message: []byte("not a protocol message")})
	require.NoError(t, err)
	require.NoError(t, vm.Gossip(ctx(), ids.GenerateTestNodeID(), bad))
}

// A message that arrives before this node's own router for that ceremony is
// registered is buffered and drained on register, so no round-one broadcast is
// lost to a start-order race — and the buffer is bounded, so junk-session
// gossip cannot exhaust memory.
func TestAnEarlyRoundIsBufferedAndTheBufferIsBounded(t *testing.T) {
	vm := newVM(t)
	sender := ids.GenerateTestNodeID()
	msg := &protocol.Message{From: party.ID(sender.String()), Protocol: "cmp", RoundNumber: 1}
	env, err := marshalEnvelope("mpc/early", msg)
	require.NoError(t, err)

	for i := 0; i < maxPendingPerSession+10; i++ {
		require.NoError(t, vm.Gossip(ctx(), sender, env))
	}
	vm.routerMu.Lock()
	buffered := len(vm.pendingBySession["mpc/early"])
	vm.routerMu.Unlock()
	require.Equal(t, maxPendingPerSession, buffered)

	router := newGossipRouter(ctx(), "mpc/early", "self", nil, nil)
	vm.registerSessionRouter("mpc/early", router)
	require.Len(t, router.Receive(), maxPendingPerSession)

	// Tearing the ceremony down drops both the router and anything still
	// buffered for it.
	vm.unregisterSessionRouter("mpc/early")
	vm.routerMu.Lock()
	_, stillBuffered := vm.pendingBySession["mpc/early"]
	_, stillRouted := vm.sessionRouters["mpc/early"]
	vm.routerMu.Unlock()
	require.False(t, stillBuffered)
	require.False(t, stillRouted)

	vm.unregisterSessionRouter("mpc/early") // idempotent
}

// -----------------------------------------------------------------------------
// The engine surface that M-Chain does not use
// -----------------------------------------------------------------------------

// M-Chain answers no peer requests: every ceremony message rides app-gossip, so
// there is ONE receive path and one demux point. These exist to satisfy the
// engine and are deliberately empty rather than deliberately absent — a VM that
// did not implement them would not start.
func TestMChainAnswersNoPeerRequests(t *testing.T) {
	vm := newVM(t)
	node := ids.GenerateTestNodeID()

	require.NoError(t, vm.Connected(ctx(), node, &vmchain.VersionInfo{}))
	require.NoError(t, vm.Disconnected(ctx(), node))
	require.NoError(t, vm.Request(ctx(), node, 1, time.Now(), nil))
	require.NoError(t, vm.Response(ctx(), node, 1, nil))
	require.NoError(t, vm.RequestFailed(ctx(), node, 1, &warp.Error{}))
	require.NoError(t, vm.CrossChainResponse(ctx(), ids.GenerateTestID(), 1, nil))
	require.NoError(t, vm.CrossChainRequestFailed(ctx(), ids.GenerateTestID(), 1, &warp.Error{}))
	require.NoError(t, vm.SetState(ctx(), 0))
}

// Nothing is flushed at shutdown. Every durable fact is written at the moment
// it becomes true, so a crash, a kill or a power cut loses nothing — which for
// a custody chain means not losing the record of who holds the funds.
func TestShutdownFlushesNothingBecauseNothingIsPending(t *testing.T) {
	db := memdb.New()
	chainID := ids.GenerateTestID()
	vm := openVM(t, db, chainID, nil, nil)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 75)
	key.register(t, vm)
	root := vm.StateRoot()

	// No Shutdown at all — the process simply ends.
	reopened := openVM(t, db, chainID, nil, nil)
	defer reopened.Shutdown(ctx())
	require.Equal(t, root, reopened.StateRoot())
	_, err := reopened.Key("vault")
	require.NoError(t, err)

	require.NoError(t, vm.Shutdown(ctx()))
	require.NoError(t, vm.Shutdown(ctx()), "shutdown is idempotent")
}

// The factory holds no state: everything that needs configuration or a database
// arrives at Initialize.
func TestTheFactoryProducesAChainVMWithNoState(t *testing.T) {
	raw, err := (&Factory{}).New(log.NewNoOpLogger())
	require.NoError(t, err)
	vm, ok := raw.(vmchain.ChainVM)
	require.True(t, ok, "the plugin serves what the node's registry expects")
	require.Equal(t, &VM{}, vm)
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// seedRegistryAndShare puts a key record and this node's share for it on disk,
// committed, so the next VM opened over that database finds them at boot.
func seedRegistryAndShare(t *testing.T, db database.Database, chainID ids.ID, rec *KeyRecord, share []byte) {
	t.Helper()
	vm := openVM(t, db, chainID, nil, nil)
	require.NoError(t, vm.state.PutKey(rec))
	require.NoError(t, vm.state.PutShare(rec.KeyID, share))
	require.NoError(t, vm.chain.Seed(func(database.Database) error { return nil }))
	require.NoError(t, vm.Shutdown(ctx()))
}

// bootWithStoredShare seeds a registry entry plus a share and returns whatever
// the next boot says about the pair.
func bootWithStoredShare(t *testing.T, rec *KeyRecord, share []byte) error {
	t.Helper()
	db, chainID := memdb.New(), ids.GenerateTestID()
	seedRegistryAndShare(t, db, chainID, rec, share)

	vm := &VM{}
	return vm.Initialize(ctx(), vmcore.Init{
		Runtime:  &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), ChainID: chainID},
		DB:       db,
		Log:      log.NewNoOpLogger(),
		ToEngine: make(chan vmcore.Message, 1),
	})
}

// openVM initializes a VM the way the node does, with whatever validator state,
// genesis and config the test supplies.
func openVM(t *testing.T, db database.Database, chainID ids.ID, vs *validatorstest.TestState, genesis []byte, config ...string) *VM {
	t.Helper()
	var cfg []byte
	if len(config) > 0 {
		cfg = []byte(config[0])
	}
	rt := &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), ChainID: chainID}
	if vs != nil {
		rt.ValidatorState = vs
	}
	vm := &VM{}
	require.NoError(t, vm.Initialize(ctx(), vmcore.Init{
		Runtime:  rt,
		DB:       db,
		Genesis:  genesis,
		Config:   cfg,
		Log:      log.NewNoOpLogger(),
		ToEngine: make(chan vmcore.Message, 1),
	}))
	return vm
}

// oneValidator is the validator state of a chain with a single validator, which
// is enough for the committee paths and not enough for a 3-of-5 custody set.
func oneValidator(node ids.NodeID) *validatorstest.TestState {
	return &validatorstest.TestState{
		GetValidatorSetF: func(context.Context, uint64, ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
			return map[ids.NodeID]*validators.GetValidatorOutput{
				node: {NodeID: node, Weight: 1},
			}, nil
		},
	}
}

// faultyIterDB fails only iteration, which is how a registry read fails.
type faultyIterDB struct {
	database.Database
}

func (d *faultyIterDB) NewIteratorWithPrefix([]byte) database.Iterator {
	return &faultyIter{}
}

type faultyIter struct{ database.Iterator }

func (*faultyIter) Next() bool    { return false }
func (*faultyIter) Error() error  { return errors.New("iterator fault") }
func (*faultyIter) Key() []byte   { return nil }
func (*faultyIter) Value() []byte { return nil }
func (*faultyIter) Release()      {}

// A node that is given no logger of its own falls back to the runtime's, so a
// VM always has somewhere to report. A VM with neither logs nowhere rather than
// faulting on the first Info call.
func TestANodeAlwaysHasSomewhereToReport(t *testing.T) {
	rt := &runtime.Runtime{
		NodeID:  ids.GenerateTestNodeID(),
		ChainID: ids.GenerateTestID(),
		Log:     log.NewNoOpLogger(),
	}
	vm := &VM{}
	require.NoError(t, vm.Initialize(ctx(), vmcore.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 1),
	}))
	defer vm.Shutdown(ctx())
	require.NotNil(t, vm.log)
}
