// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// fault_test.go — what a validator does when the disk under it fails.
//
// A custody chain's worst failure is not a rejected block; it is a node that
// keeps going on state it could not read. Every path below is driven by a real
// store that refuses one key, so the failure is the one that actually happens
// in the field: the read or the write, not a mocked-out layer that never had a
// disk.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
	vmcore "github.com/luxfi/vm"
)

// breakOn wraps the VM's state store so one key fails, and restores it after
// the test. The store is reached directly because a fault in the middle of a
// block is exactly what has no other entry point.
func breakOn(t *testing.T, vm *VM, db database.Database) {
	t.Helper()
	was := vm.state.db
	vm.state.db = db
	t.Cleanup(func() { vm.state.db = was })
}

// -----------------------------------------------------------------------------
// The registry and the ceremony log
// -----------------------------------------------------------------------------

// Every read of the registry either answers or says why. There is no path that
// turns an unreadable key into "no such key", because that is the answer that
// lets a chain forget who holds the funds.
func TestAnUnreadableRegistryIsNeverAnEmptyOne(t *testing.T) {
	s, raw := newState(t)
	rec := sampleKeyRecord()
	require.NoError(t, s.PutKey(rec))

	keyOf := func(prefix, id string) []byte { return append([]byte(prefix), id...) }

	s.db = &faultyDB{Database: raw, failGet: keyOf("c/key/", rec.KeyID)}
	_, err := s.GetKey(rec.KeyID)
	require.ErrorIs(t, err, errFaulty)
	_, err = s.HasKey(rec.KeyID)
	require.ErrorIs(t, err, errFaulty)
	require.ErrorIs(t, s.PutKey(rec), errFaulty, "a registration must not land on a store that cannot be read")

	s.db = &faultyDB{Database: raw, failPut: keyOf("c/key/", "fresh")}
	fresh := sampleKeyRecord()
	fresh.KeyID = "fresh"
	require.ErrorIs(t, s.PutKey(fresh), errFaulty)

	s.db = &faultyIterDB{Database: raw}
	_, err = s.Keys()
	require.Error(t, err)
}

func TestAnUnreadableCeremonyLogIsNeverAnEmptyOne(t *testing.T) {
	s, raw := newState(t)
	cer := &CeremonyRecord{ID: "mpc/one", Kind: OpTypeSign, KeyID: "vault"}
	require.NoError(t, s.PutCeremony(cer))

	s.db = &faultyDB{Database: raw, failGet: []byte("c/ceremony/mpc/one")}
	_, err := s.GetCeremony("mpc/one")
	require.ErrorIs(t, err, errFaulty)
	require.ErrorIs(t, s.PutCeremony(cer), errFaulty)

	s.db = &faultyDB{Database: raw, failPut: []byte("c/ceremony/mpc/two")}
	require.ErrorIs(t, s.PutCeremony(&CeremonyRecord{ID: "mpc/two"}), errFaulty)

	s.db = &faultyIterDB{Database: raw}
	_, err = s.Ceremonies()
	require.Error(t, err)
}

func TestAnUnreadableShareIsNeverAnAbsentOne(t *testing.T) {
	s, raw := newState(t)
	require.NoError(t, s.PutShare("vault", []byte("share")))

	s.db = &faultyDB{Database: raw, failGet: []byte("n/share/vault")}
	_, err := s.GetShare("vault")
	require.ErrorIs(t, err, errFaulty)
	_, err = s.HasShare("vault")
	require.ErrorIs(t, err, errFaulty)
}

func TestAnUnreadableRootIsAnError(t *testing.T) {
	s, raw := newState(t)
	s.db = &faultyDB{Database: raw, failGet: keyRoot}
	require.ErrorIs(t, s.ReadRoot(), errFaulty)
}

// -----------------------------------------------------------------------------
// Applying a block onto a failing store
// -----------------------------------------------------------------------------

// A block that cannot be written is refused whole. Nothing it staged survives,
// the root does not move, and the ceremony stays queued — so the block is
// applicable again once the store is.
func TestABlockOntoAFailingStoreLeavesNothingBehind(t *testing.T) {
	for name, breaking := range map[string]func(*VM) database.Database{
		"the registry write fails": func(vm *VM) database.Database {
			return &faultyDB{Database: vm.state.db, failPut: []byte("c/key/vault")}
		},
		"the ceremony write fails": func(vm *VM) database.Database {
			return &faultyDB{Database: vm.state.db, failPut: []byte("c/ceremony/")}
		},
		"the registry read fails": func(vm *VM) database.Database {
			return &faultyDB{Database: vm.state.db, failGet: []byte("c/key/vault")}
		},
	} {
		vm := newVM(t)
		key := newCustody(t, "vault", quorum.MustNew(3, 5), 130)
		op := key.keygenOp(t)
		blk := blockOver(t, vm, op)
		require.NoErrorf(t, blk.Verify(ctx()), "%s: the block is valid before the store fails", name)

		rootBefore := vm.state.Root()
		tipBefore, heightBefore := vm.chain.Tip()

		broken := breaking(vm)
		if f, ok := broken.(*faultyDB); ok && string(f.failPut) == "c/ceremony/" {
			f.failPut = []byte("c/ceremony/" + op.CeremonyID)
		}
		breakOn(t, vm, broken)

		require.Errorf(t, blk.Accept(ctx()), "%s: a block that cannot be written must not be accepted", name)

		vm.state.db = vm.chain.View()
		require.Equalf(t, rootBefore, vm.state.Root(), "%s: the root must not have moved", name)
		_, err := vm.state.GetKey("vault")
		require.Errorf(t, err, "%s: no key may survive a block the chain refused", name)
		tip, height := vm.chain.Tip()
		require.Equalf(t, tipBefore, tip, "%s", name)
		require.Equalf(t, heightBefore, height, "%s", name)
	}
}

// A block whose operation cannot be checked against the registry is refused,
// rather than admitted because the check could not run.
func TestAnUncheckableOperationIsRefusedNotAdmitted(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 131)
	blk := blockOver(t, vm, key.keygenOp(t))

	breakOn(t, vm, &faultyDB{Database: vm.state.db, failGet: []byte("c/key/vault")})
	require.ErrorIs(t, blk.Verify(ctx()), errFaulty)
}

// A record whose structure would fail validation is refused at Verify, before
// it can reach the registry — the same rule PutKey holds, one step earlier so
// the block is named rather than the write.
func TestAStructurallyInvalidRecordIsRefusedAtVerify(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 132)

	op := key.keygenOp(t)
	op.Key.Kind = "" // a key bound to no protocol
	require.Error(t, blockOver(t, vm, op).Verify(ctx()))
}

// A group key that is 33 bytes and not a point derives no address, and a
// registration that cannot derive its own custody address is refused rather
// than registered with an empty one.
func TestAKeyThatIsNotAPointRegistersNoAddress(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 133)

	op := key.keygenOp(t)
	notAPoint := make([]byte, 33)
	notAPoint[0] = 0x02 // a well-formed prefix over an x that is not on the curve
	op.Key.GroupPublicKey = notAPoint
	require.Nil(t, publicKeyToAddress(notAPoint))
	require.ErrorIs(t, blockOver(t, vm, op).Verify(ctx()), ErrInvalidOperation)
}

// -----------------------------------------------------------------------------
// Booting onto a failing store
// -----------------------------------------------------------------------------

// A node whose state cannot be read does not start, and a node whose genesis
// cannot be committed does not start either — the second is what makes the
// genesis root durable, so a node that skipped it would come back deriving a
// root rather than reading one.
func TestANodeThatCannotReadOrSeedItsStateDoesNotStart(t *testing.T) {
	vm := &VM{}
	require.ErrorIs(t, vm.Initialize(ctx(), vmcore.Init{
		Runtime:  &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), ChainID: ids.GenerateTestID()},
		DB:       &faultyDB{Database: memdb.New(), failGet: keyRoot},
		Log:      log.NewNoOpLogger(),
		ToEngine: make(chan vmcore.Message, 1),
	}), errFaulty)

	// The genesis root is staged through the view and made durable by one
	// commit; a store that will not flush must not report a started chain.
	refusing := &refusingDB{Database: memdb.New(), refuse: true}
	vm = &VM{}
	require.ErrorIs(t, vm.Initialize(ctx(), vmcore.Init{
		Runtime:  &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), ChainID: ids.GenerateTestID()},
		DB:       refusing,
		Log:      log.NewNoOpLogger(),
		ToEngine: make(chan vmcore.Message, 1),
	}), errRefused)
}

// A tip pointer that names a block the store does not hold is a corrupted
// store, not an empty chain.
func TestATipNamingNoBlockDoesNotStart(t *testing.T) {
	db := memdb.New()
	require.NoError(t, db.Put([]byte("chain/tip"), idBytes(ids.GenerateTestID())))

	vm := &VM{}
	err := vm.Initialize(ctx(), vmcore.Init{
		Runtime:  &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), ChainID: ids.GenerateTestID()},
		DB:       db,
		Log:      log.NewNoOpLogger(),
		ToEngine: make(chan vmcore.Message, 1),
	})
	require.ErrorContains(t, err, "open chain state")
}

// A share that is on disk but unreadable stops the boot, rather than being
// skipped as "not a participant" — those are different facts and only one of
// them is safe to assume.
func TestAnUnreadableShareIsNotMistakenForNotParticipating(t *testing.T) {
	raw, pub, degree := realShare(t)
	rec := custodyFor(t, "vault", quorum.MustNew(degree+1, degree+2), pub)

	db, chainID := memdb.New(), ids.GenerateTestID()
	seedRegistryAndShare(t, db, chainID, rec, raw)

	vm := &VM{}
	err := vm.Initialize(ctx(), vmcore.Init{
		Runtime:  &runtime.Runtime{NodeID: ids.GenerateTestNodeID(), ChainID: chainID},
		DB:       &faultyDB{Database: db, failGet: []byte("n/share/vault")},
		Log:      log.NewNoOpLogger(),
		ToEngine: make(chan vmcore.Message, 1),
	})
	require.ErrorIs(t, err, errFaulty)
}

// A keygen ceremony that cannot read the registry does not proceed to generate
// a key it might not be allowed to register.
func TestAKeygenThatCannotReadTheRegistryDoesNotRun(t *testing.T) {
	self, peer := ids.NodeID{1}, ids.NodeID{2}
	vm := openVM(t, memdb.New(), ids.GenerateTestID(),
		weightedValidators(map[ids.NodeID]uint64{self: 10, peer: 10}), nil)
	defer vm.Shutdown(ctx())
	vm.partyID = party.ID(self.String())

	breakOn(t, vm, &faultyDB{Database: vm.state.db, failGet: []byte("c/key/vault")})
	_, err := vm.StartKeygenWithPolicy(ctx(), "vault", quorum.MustNew(2, 2),
		authenticatedFor(vm, "B-Chain", true))
	require.ErrorIs(t, err, errFaulty)
}

// The engine is told the node is unhealthy, and the HTTP probe says the same
// thing from the same call.
func TestAnUnreadableRegistryIsReportedAsUnhealthyEverywhere(t *testing.T) {
	vm := newVM(t)
	breakOn(t, vm, &faultyIterDB{Database: vm.state.db})

	_, err := vm.HealthCheck(ctx())
	require.Error(t, err)

	w := httptest.NewRecorder()
	vm.handleHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// -----------------------------------------------------------------------------
// Failures over the wire
// -----------------------------------------------------------------------------

// Every list method reports the failure rather than an empty list, and every
// one of them classifies it the same way.
func TestAnUnreadableStateIsReportedOverRPCNotHiddenAsEmpty(t *testing.T) {
	vm := newVM(t)
	breakOn(t, vm, &faultyIterDB{Database: vm.state.db})
	_, srv := serve(t, vm)

	for _, method := range []string{"mpc_listKeys", "mpc_listCeremonies", "threshold_getInfo"} {
		got := call(t, srv, method, nil)
		require.NotNilf(t, got.Error, "%s must report the fault", method)
		require.Equalf(t, RPCErrorInternal, got.Error.Code, "%s", method)
	}
}

// One classifier, exercised over every failure it names. A method that already
// classified its own failure keeps that code; anything else gets this table's.
func TestOneClassifierNamesEveryFailure(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{ErrUnauthorizedChain, RPCErrorUnauthorized},
		{ErrQuotaExceeded, RPCErrorQuotaExceeded},
		{ErrUnknownKey, RPCErrorKeyNotFound},
		{ErrShareNotHeld, RPCErrorKeyNotFound},
		{errFaulty, RPCErrorInternal},
		{&RPCError{Code: RPCErrorCeremonyNotFound, Message: "already classified"}, RPCErrorCeremonyNotFound},
	} {
		require.Equal(t, tc.want, asRPCError(tc.err).Code, "%v", tc.err)
	}

	// And through a wrap, because the VM wraps its errors with context.
	wrapped := &RPCError{Code: RPCErrorQuotaExceeded, Message: "over"}
	require.Equal(t, RPCErrorQuotaExceeded, asRPCError(wrapError(wrapped)).Code)
}

// A client whose server refuses reports the refusal on every method, rather
// than a zero value the caller reads as an answer.
func TestEveryClientMethodReportsARefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"the disk fell off"}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "B-Chain")

	for name, call := range map[string]func() error{
		"GetCeremony":    func() error { _, err := c.GetCeremony(ctx(), "mpc/x"); return err },
		"ListCeremonies": func() error { _, err := c.ListCeremonies(ctx()); return err },
		"StateRoot":      func() error { _, err := c.StateRoot(ctx()); return err },
		"ListKeys":       func() error { _, err := c.ListKeys(ctx()); return err },
		"GetKey":         func() error { _, err := c.GetKey(ctx(), "vault"); return err },
		"GetPublicKey":   func() error { _, err := c.GetPublicKey(ctx(), "vault"); return err },
		"GetAddress":     func() error { _, err := c.GetAddress(ctx(), "vault"); return err },
		"GetInfo":        func() error { _, err := c.GetInfo(ctx()); return err },
		"GetStats":       func() error { _, err := c.GetStats(ctx()); return err },
		"GetQuota":       func() error { _, err := c.GetQuota(ctx()); return err },
		"Health":         func() error { _, err := c.Health(ctx()); return err },
	} {
		require.ErrorContainsf(t, call(), "the disk fell off", "%s swallowed the refusal", name)
	}
}

// A request that cannot even be encoded is reported as such, rather than sent
// as something else.
func TestARequestThatCannotBeEncodedIsNotSent(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", "B-Chain")
	err := c.call(ctx(), "threshold_getInfo", make(chan int), nil)
	require.ErrorContains(t, err, "failed to marshal request")
}

// A response that stops mid-body is a failure, not a short answer.
func TestATruncatedResponseIsAFailureNotAShortAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0"`))
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL, "B-Chain").GetInfo(ctx())
	require.ErrorContains(t, err, "failed to read response")
}

// wrapError puts an error behind another, which is what the VM's own error
// paths do and what errors.As must see through.
func wrapError(err error) error { return &wrapped{err} }

type wrapped struct{ err error }

func (w *wrapped) Error() string { return "context: " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }

func idBytes(id ids.ID) []byte { return id[:] }

// -----------------------------------------------------------------------------
// A node whose store holds bytes that are not records
// -----------------------------------------------------------------------------

// Enumerating the registry decodes every entry, and an entry that does not
// decode fails the enumeration rather than being skipped. A skipped custody key
// is a key the chain believes it does not hold.
func TestAnUndecodableEntryFailsTheEnumeration(t *testing.T) {
	s, raw := newState(t)
	require.NoError(t, s.PutKey(sampleKeyRecord()))
	require.NoError(t, raw.Put([]byte("c/key/junk"), []byte("not a key record")))
	_, err := s.Keys()
	require.Error(t, err)

	require.NoError(t, s.PutCeremony(&CeremonyRecord{ID: "mpc/one"}))
	require.NoError(t, raw.Put([]byte("c/ceremony/junk"), []byte("not a ceremony")))
	_, err = s.Ceremonies()
	require.Error(t, err)
}

// -----------------------------------------------------------------------------
// A ceremony with no transport
// -----------------------------------------------------------------------------

// A node with no p2p cannot run a ceremony, and every entry point says so with
// the same reason rather than hanging or producing a one-party artifact.
func TestACeremonyWithNoTransportIsRefusedAtEveryEntryPoint(t *testing.T) {
	self, peer := ids.NodeID{1}, ids.NodeID{2}
	vm := openVM(t, memdb.New(), ids.GenerateTestID(),
		weightedValidators(map[ids.NodeID]uint64{self: 10, peer: 10}), nil)
	defer vm.Shutdown(ctx())
	vm.partyID = party.ID(self.String())

	// Keygen reaches the ceremony and finds no way to carry it.
	_, err := vm.StartKeygenWithPolicy(ctx(), "vault", quorum.MustNew(2, 2),
		authenticatedFor(vm, "B-Chain", true))
	require.ErrorContains(t, err, "no warp sender")

	// And so does signing, once the key and the share are in place.
	key := newCustody(t, "vault", quorum.MustNew(2, 2), 140)
	key.rec.Participants = []party.ID{party.ID(self.String()), party.ID(peer.String())}
	key.rec.Participants = canonicalParties(key.rec.Participants)
	key.register(t, vm)
	key.hold(vm, testShare(t, key.rec.GroupPublicKey, key.rec.Degree()))

	digest := digestOf(1)
	vm.partyID = quorumFor(key.rec, digest)[0]
	_, err = vm.RequestSignature(ctx(), authenticatedFor(vm, "B-Chain", false), "vault", digest)
	require.ErrorContains(t, err, "no warp sender")
}

// A signer that is not a validator id cannot be routed to, and the ceremony
// says which one rather than stalling on a round nobody receives.
func TestASignerThatIsNotAValidatorIdIsNamedNotAwaited(t *testing.T) {
	self := ids.GenerateTestNodeID()
	fab := newMemFabric()
	vm := newFabricVM(t, fab, self, oneValidator(self))
	defer vm.Shutdown(ctx())

	// A key whose committee is names, not node ids — which the block rules
	// permit, because routing is the transport's business and not consensus'.
	key := newCustody(t, "vault", quorum.MustNew(2, 3), 141)
	key.register(t, vm)
	key.hold(vm, testShare(t, key.rec.GroupPublicKey, key.rec.Degree()))

	digest := digestOf(1)
	vm.partyID = quorumFor(key.rec, digest)[0]
	_, err := vm.RequestSignature(ctx(), authenticatedFor(vm, "B-Chain", false), "vault", digest)
	require.ErrorContains(t, err, "is not a node id")
}
