// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
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

// ---- shared test helpers ----

// genesisTime is the fixed time every test chain starts at, so block time is a
// controlled input rather than the wall clock.
var genesisTime = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// newTestVM initializes an in-memory K-Chain seeded with the given funding
// allocation (hex address -> nLUX). Its clock is pinned to genesisTime.
func newTestVM(t *testing.T, alloc map[string]uint64) *VM {
	t.Helper()
	return newTestVMOn(t, memdb.New(), alloc)
}

// initFor builds the boot input for a chain over db with the given allocation.
func initFor(t *testing.T, db database.Database, alloc map[string]uint64) vmcore.Init {
	t.Helper()
	logger := log.NewNoOpLogger()
	gb, err := json.Marshal(Genesis{Version: 1, Timestamp: genesisTime.Unix(), Alloc: alloc})
	require.NoError(t, err)
	return vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: logger},
		DB:       db,
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  gb,
	}
}

// newTestVMOn is newTestVM over a caller-supplied database, so a test can reopen
// the same store or inject a failing one.
func newTestVMOn(t *testing.T, db database.Database, alloc map[string]uint64) *VM {
	t.Helper()
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), initFor(t, db, alloc)))
	vm.clock.Set(genesisTime)
	return vm
}

// testKey is an external payer identity (the payer holds its own secret; K never
// does). The ML-DSA-65 private key here lives ONLY in the test, exercising the
// public-key authentication path on the VM side.
type testKey struct {
	priv *mldsa.PrivateKey
	pub  []byte
	addr fee_Account
}

// fee_Account aliases the fee package account type for brevity in tests.
type fee_Account = ids.ShortID

func newTestKey(t *testing.T) testKey {
	t.Helper()
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	pub := priv.PublicKey.Bytes()
	return testKey{priv: priv, pub: pub, addr: addressOf(pub)}
}

func (k testKey) hexAddr() string { return hex.EncodeToString(k.addr[:]) }

// sign attaches the payer's public key and a valid signature over the tx's
// signing bytes, then clears the cached id so ID() recomputes.
func (k testKey) sign(t *testing.T, tx *Transaction) {
	t.Helper()
	tx.Auth = k.pub
	sig, err := k.priv.Sign(rand.Reader, tx.SigningBytes(), crypto.Hash(0))
	require.NoError(t, err)
	tx.Sig = sig
	tx.id = ids.Empty
}

// registerTx builds a signed RegisterKey transaction for an ML-DSA-65 key.
func registerTx(t *testing.T, k testKey, name string, gasLimit, nonce uint64) *Transaction {
	t.Helper()
	payload, err := json.Marshal(RegisterKeyPayload{
		Name:        name,
		PublicKey:   []byte("PUBLIC-KEY-MATERIAL-ONLY"),
		Threshold:   3,
		TotalShares: 5,
		Commitments: [][]byte{{0x01}, {0x02}, {0x03}}, // PUBLIC VSS commitments
		Committee:   []ids.NodeID{},
		Policy:      AuthPolicy{},
	})
	require.NoError(t, err)
	tx := &Transaction{
		Type:      TxRegisterKey,
		Algorithm: "ml-dsa-65",
		Payer:     k.addr,
		KeyID:     deriveKeyID(name),
		GasLimit:  gasLimit,
		Nonce:     nonce,
		Payload:   payload,
	}
	k.sign(t, tx)
	return tx
}

func TestVMInitializeAuthOnly(t *testing.T) {
	vm := newTestVM(t, nil)
	defer func() { _ = vm.Shutdown(context.Background()) }()

	v, err := vm.Version(context.Background())
	require.NoError(t, err)
	require.Equal(t, Version, v)

	h, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	require.True(t, h.Healthy)
	require.Equal(t, "true", h.Details["authOnly"])
}

// TestNetworkIDResolution proves the network id has ONE resolution order rather
// than a factory copy silently discarded by a config copy: the factory value is
// the fallback, the runtime overrides it, and the chain config blob overrides
// that. Before the config collapse the factory's value was overwritten by
// ParseConfig on every boot, so NewFactory's argument never reached the chain.
func TestNetworkIDResolution(t *testing.T) {
	logger := log.NewNoOpLogger()
	boot := func(t *testing.T, rtNetwork uint32, cfgBlob []byte) uint32 {
		t.Helper()
		raw, err := NewFactory(Config{NetworkID: 11}).New(logger)
		require.NoError(t, err)
		vm := raw.(*VM)
		var rt *runtime.Runtime
		if rtNetwork != 0 {
			rt = &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: rtNetwork, Log: logger}
		}
		require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
			Runtime: rt, DB: memdb.New(), ToEngine: make(chan vmcore.Message, 1),
			Log: logger, Config: cfgBlob,
		}))
		defer func() { _ = vm.Shutdown(context.Background()) }()
		return vm.networkID
	}

	require.Equal(t, uint32(11), boot(t, 0, nil), "factory value survives when nothing overrides it")
	require.Equal(t, uint32(22), boot(t, 22, nil), "runtime overrides the factory")
	require.Equal(t, uint32(33), boot(t, 22, []byte(`{"networkId":33}`)), "chain config overrides the runtime")
}

// TestInitializeRefusesUndecodableInput proves boot fails closed on input it
// cannot decode rather than starting on a silently-empty configuration or
// genesis — a chain that boots with no allocation is a chain whose funded
// accounts have vanished.
func TestInitializeRefusesUndecodableInput(t *testing.T) {
	logger := log.NewNoOpLogger()
	start := func(cfg, gen []byte) error {
		vm := &VM{}
		return vm.Initialize(context.Background(), vmcore.Init{
			DB: memdb.New(), ToEngine: make(chan vmcore.Message, 1),
			Log: logger, Config: cfg, Genesis: gen,
		})
	}
	require.Error(t, start([]byte("{not json"), nil))
	require.Error(t, start(nil, []byte("{not json")))

	// A genesis allocation keyed by something that is not a 20-byte address is
	// refused too: crediting the wrong account is worse than not booting.
	bad, err := json.Marshal(Genesis{Alloc: map[string]uint64{"0xdeadbeef": 1}})
	require.NoError(t, err)
	require.Error(t, start(nil, bad))
}

// TestGenesisSeedsOnceAndSurvivesRestart proves the allocation is credited
// exactly once: reopening the same store must not double-credit, and the
// genesis block must still be retrievable so height 1 has a parent to verify
// against.
func TestGenesisSeedsOnceAndSurvivesRestart(t *testing.T) {
	k := newTestKey(t)
	db := memdb.New()

	vm := newTestVMOn(t, db, map[string]uint64{k.hexAddr(): 500})
	bal, err := vm.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, uint64(500), bal)
	genesisID, err := vm.LastAccepted(context.Background())
	require.NoError(t, err)

	// Reopen over the SAME store. The marker must suppress a second credit.
	vm2 := newTestVMOn(t, db, map[string]uint64{k.hexAddr(): 500})
	defer func() { _ = vm2.Shutdown(context.Background()) }()
	bal2, err := vm2.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, uint64(500), bal2, "genesis must not credit twice on restart")

	blk, err := vm2.GetBlock(context.Background(), genesisID)
	require.NoError(t, err)
	require.Equal(t, uint64(0), blk.Height())

	atZero, err := vm2.GetBlockIDAtHeight(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, genesisID, atZero)
}

// TestShutdownRefusesToBuild proves the VM fails closed once stopped: no block
// may be produced after Shutdown, whatever is queued.
func TestShutdownRefusesToBuild(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000_000_000})
	_, err := vm.SubmitTx(registerTx(t, k, "late", 200_000, 1))
	require.NoError(t, err)

	require.NoError(t, vm.Shutdown(context.Background()))
	_, err = vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errVMShutdown)

	h, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	require.False(t, h.Healthy, "a stopped VM must not report healthy")
}

// TestWaitForEventWakesOnSubmit proves the VM actually tells consensus there is
// work. A VM that never signals never builds, whatever it has admitted.
func TestWaitForEventWakesOnSubmit(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	woke := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := vm.WaitForEvent(ctx)
		woke <- err
	}()

	_, err := vm.SubmitTx(registerTx(t, k, "wake", 200_000, 1))
	require.NoError(t, err)
	require.NoError(t, <-woke, "SubmitTx must wake a waiting builder")
}

// TestLifecycleSurfaceIsInert proves the ChainVM callbacks K does not implement
// are genuinely inert: they neither error nor move the chain. K has no bootstrap
// state machine and no peer-version tracking, so each is a deliberate no-op
// rather than a missing implementation.
func TestLifecycleSurfaceIsInert(t *testing.T) {
	vm := newTestVM(t, nil)
	defer func() { _ = vm.Shutdown(context.Background()) }()
	ctx := context.Background()

	before, err := vm.LastAccepted(ctx)
	require.NoError(t, err)

	require.NoError(t, vm.SetState(ctx, 1))
	require.NoError(t, vm.SetPreference(ctx, ids.GenerateTestID()))
	require.NoError(t, vm.Connected(ctx, ids.GenerateTestNodeID(), nil))
	require.NoError(t, vm.Disconnected(ctx, ids.GenerateTestNodeID()))

	static, err := vm.CreateStaticHandlers(ctx)
	require.NoError(t, err)
	require.Empty(t, static, "K exposes no static handlers")

	after, err := vm.LastAccepted(ctx)
	require.NoError(t, err)
	require.Equal(t, before, after, "no lifecycle callback may move the chain tip")
}
