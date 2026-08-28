// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
	luxvm "github.com/luxfi/vm"
	"github.com/stretchr/testify/require"
)

// TestAnEmptyConfigStartsAUsableVM. The config is normalised in exactly one
// place — Initialize — so a VM built by the factory and one built by hand start
// from the same rules, and neither comes up batching nothing.
func TestAnEmptyConfigStartsAUsableVM(t *testing.T) {
	raw, err := (&Factory{Config: config.Config{}}).New(log.NewNoOpLogger())
	require.NoError(t, err)
	vm, ok := raw.(*VM)
	require.True(t, ok)

	require.NoError(t, vm.Initialize(context.Background(), luxvm.Init{
		DB:  memdb.New(),
		Log: log.NewNoOpLogger(),
	}))
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })

	require.Positive(t, vm.Config.MaxParallelTxs)
	require.Positive(t, vm.Config.ParallelBatchSize)
	require.Equal(t, config.AlgorithmDefault, vm.Config.QuantumAlgorithmVersion)

	// No Runtime was supplied, and the VM still starts — with a tip.
	require.NotEqual(t, ids.Empty, vm.getLastAcceptedID())

	// And it builds, verifies and accepts on those settled values.
	vm.clock.Set(chainTime)
	require.NoError(t, vm.txPool.AddTransaction(signedTx(t, vm, 1, "work")))
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.NoError(t, blk.(*Block).Verify(context.Background()))
	require.NoError(t, blk.(*Block).Accept(context.Background()))
}

// TestInitializeRefusesAnAlgorithmThatDoesNotExist: an operator who configures
// a parameter set that is not real gets a refusal at boot, not a chain quietly
// signing under a different one.
func TestInitializeRefusesAnAlgorithmThatDoesNotExist(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.QuantumAlgorithmVersion = 42
	vm := &VM{Config: cfg}
	require.Error(t, vm.Initialize(context.Background(), luxvm.Init{
		DB: memdb.New(), Log: log.NewNoOpLogger(),
	}))
}

// TestInitializeWithoutALoggerDoesNotPanic: Initialize accepts a nil Log, so it
// has to survive one. Every path out of Initialize logs.
func TestInitializeWithoutALoggerDoesNotPanic(t *testing.T) {
	vm := &VM{Config: config.DefaultConfig()}
	require.NoError(t, vm.Initialize(context.Background(), luxvm.Init{DB: memdb.New()}))
	require.NoError(t, vm.Shutdown(context.Background()))
}

// TestEveryNodeSignsUnderItsOwnName.
//
// Both finality legs count DISTINCT validator ids against the threshold, so the
// id has to name the node. It named the CHAIN — a field that was never even
// assigned, so every Q-Chain node in the world signed as the empty id. Each
// peer's signature arrived as a duplicate of the first, the count never passed
// one, and no threshold above one could ever be met.
func TestEveryNodeSignsUnderItsOwnName(t *testing.T) {
	a, _ := bootVM(t, quietConfig())
	b, _ := bootVM(t, quietConfig())

	idA := a.GetQuasarBridge().validatorID
	idB := b.GetQuasarBridge().validatorID

	require.NotEqual(t, ids.EmptyNodeID.String(), idA, "the node signs as nobody")
	require.NotEqual(t, idA, idB, "two nodes sign under one name, so their signatures cancel out")

	// What that costs, concretely: their two signatures must count as two.
	blockID := ids.GenerateTestID()
	q, err := NewQuasar(QuasarConfig{ValidatorID: idA, TotalNodes: 3, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)
	q.pendingBlocks[blockID] = &PendingBlock{BlockID: blockID, BlockHash: blockID[:], Height: 1}

	require.NoError(t, q.AddBLSSignature(blockID, &quasar.BLSSignature{Signature: []byte{1}, ValidatorID: idA}))
	require.NoError(t, q.AddBLSSignature(blockID, &quasar.BLSSignature{Signature: []byte{2}, ValidatorID: idB}))
	require.Len(t, q.pendingBlocks[blockID].BLSSignatures, 2)
}

// TestBuildBlockRefusesAnEmptyMempool: a block with nothing in it costs a round
// of consensus and settles nothing.
func TestBuildBlockRefusesAnEmptyMempool(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	_, err := vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errNoPendingTxs)
}

// TestBuildBlockRefusesWhenNothingVerifies: transactions that are in the pool
// but cannot be verified do not make a block.
func TestBuildBlockRefusesWhenNothingVerifies(t *testing.T) {
	vm, _ := bootVM(t, config.DefaultConfig()) // stamps ON
	require.NoError(t, vm.txPool.AddTransaction(stampedTx(1, "junk")))

	_, err := vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errParallelProcessingFailed)
}

// TestBuildBlockEvictsWhatItCannotVerify.
//
// A quantum stamp only ages. A transaction that fails verification now fails
// forever, and left in the pool it holds its slot for the life of the process —
// enough of them and the pool is full, AddTransaction refuses everything, and
// the chain accepts no new work at all.
func TestBuildBlockEvictsWhatItCannotVerify(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.MaxParallelTxs = 4
	vm, _ := bootVM(t, cfg)

	for i := 0; i < 4; i++ {
		require.NoError(t, vm.txPool.AddTransaction(stampedTx(uint64(i), "junk")))
	}
	require.Equal(t, 4, vm.txPool.PendingCount())
	require.Error(t, vm.txPool.AddTransaction(stampedTx(99, "more")), "precondition: the pool is full")

	_, err := vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errParallelProcessingFailed)

	require.Zero(t, vm.txPool.PendingCount(), "unverifiable transactions kept their pool slots for good")
	require.NoError(t, vm.txPool.AddTransaction(signedTx(t, vm, 100, "real work")),
		"the chain could not accept new work behind the wedged transactions")
}

// TestBuildBlockStampsNoEarlierThanItsParent.
//
// Peers' clocks differ, and the skew allowance is what tolerates that: a
// slightly fast proposer stamps a block ahead of this node's clock and this
// node accepts it. Building the next one then reads a clock that trails its own
// tip — and a block stamped there is one Verify refuses for going backwards. So
// the builder never stamps behind the parent, and the chain does not stop at
// whatever height a marginally slow node is asked to extend.
func TestBuildBlockStampsNoEarlierThanItsParent(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	parent := advance(t, vm, 1)

	// A clock trailing the tip by less than the skew allowance: a peer's clock
	// was fast, and this node accepted the block.
	vm.clock.Set(parent.timestamp.Add(-MaxFutureSkew / 2))

	blk := buildOn(t, vm)
	require.False(t, blk.timestamp.Before(parent.timestamp),
		"the builder stamped behind its own parent")
	require.NoError(t, blk.Verify(context.Background()),
		"a node built a block it will not itself verify")
}

// TestBuildBlockRefusesDuringShutdown.
func TestBuildBlockRefusesDuringShutdown(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	require.NoError(t, vm.txPool.AddTransaction(stampedTx(1, "op")))
	require.NoError(t, vm.Shutdown(context.Background()))

	_, err := vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errVMShutdown)
}

// TestShutdownIsIdempotent: the engine may call it more than once, and the
// second call must not report a failure to close what is already closed.
func TestShutdownIsIdempotent(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	require.NoError(t, vm.Shutdown(context.Background()))
	require.NoError(t, vm.Shutdown(context.Background()))

	healthy, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	require.False(t, healthy.Healthy, "a shut-down VM reported itself healthy")
}

// TestAcceptOnAClosedStoreFailsRatherThanClaimingSuccess: after Shutdown the
// version layer is closed, so staging a write cannot succeed — and Accept must
// say so instead of reporting a block it did not store.
func TestAcceptOnAClosedStoreFailsRatherThanClaimingSuccess(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	blk := buildOn(t, vm)
	require.NoError(t, vm.Shutdown(context.Background()))

	require.Error(t, blk.Accept(context.Background()))
}

// TestHeightIndexAnswersEveryAcceptedHeight. A peer catching up asks by height;
// the index is written in the same commit as the block, so the two cannot
// disagree.
func TestHeightIndexAnswersEveryAcceptedHeight(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	accepted := []ids.ID{vm.getLastAcceptedID()}
	for i := 0; i < 4; i++ {
		accepted = append(accepted, advance(t, vm, 1).id)
	}

	for height, want := range accepted {
		got, err := vm.GetBlockIDAtHeight(context.Background(), uint64(height))
		require.NoError(t, err, "no answer for height %d", height)
		require.Equal(t, want, got, "wrong block at height %d", height)
	}

	_, err := vm.GetBlockIDAtHeight(context.Background(), 999)
	require.ErrorIs(t, err, errNoBlockAtHeight)
}

// TestHeightIndexRefusesAMalformedEntry: the index answers with an id or an
// error, never with a truncated one that would name a different block.
func TestHeightIndexRefusesAMalformedEntry(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	require.NoError(t, vm.state.Put(heightKey(42), []byte("short")))

	_, err := vm.GetBlockIDAtHeight(context.Background(), 42)
	require.ErrorIs(t, err, errNoBlockAtHeight)
}

// TestGetBlockRefusesWhatItDoesNotHold: an unknown id is an error, never a
// zero-valued block that would then verify against nothing.
func TestGetBlockRefusesWhatItDoesNotHold(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	_, err := vm.GetBlock(context.Background(), ids.GenerateTestID())
	require.Error(t, err)
}

// TestGetBlockRefusesCorruptedBytes: the store holds bytes, and bytes that are
// not a block must fail rather than decode to a zero block.
func TestGetBlockRefusesCorruptedBytes(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	id := ids.GenerateTestID()
	require.NoError(t, vm.state.Put(id[:], []byte("not a block")))

	_, err := vm.GetBlock(context.Background(), id)
	require.Error(t, err)
}

// TestParseBlockRoundTripsWhatBuildBlockProduced across the two doors: the
// responder serves through parseBlockBytes, the requester admits through
// ParseBlock, and a disagreement means the fleet serves what it will not accept.
func TestParseBlockRoundTripsWhatBuildBlockProduced(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	blk := buildOn(t, vm)

	parsed, err := vm.ParseBlock(context.Background(), blk.Bytes())
	require.NoError(t, err)
	require.Equal(t, blk.id, parsed.ID())
	require.Equal(t, blk.height, parsed.Height())

	_, err = vm.ParseBlock(context.Background(), []byte("garbage"))
	require.Error(t, err)
}

// TestWaitForEventWakesOnWork and stops on a cancelled context.
func TestWaitForEventWakesOnWork(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())

	idle, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := vm.WaitForEvent(idle)
	require.Error(t, err, "an idle VM claimed there was a block to build")

	require.NoError(t, vm.txPool.AddTransaction(stampedTx(1, "op")))
	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	_, err = vm.WaitForEvent(ctx)
	require.NoError(t, err, "work arrived and consensus was never told")
}

// TestHealthCheckReportsTheChain.
func TestHealthCheckReportsTheChain(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	require.NoError(t, vm.txPool.AddTransaction(stampedTx(1, "op")))

	health, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	require.True(t, health.Healthy)
	require.Equal(t, Version, health.Details["version"])
	require.Equal(t, "1", health.Details["pendingTxs"])
}

// TestHTTPHandlerServesTheRPC end to end, through the mux the node mounts.
func TestHTTPHandlerServesTheRPC(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())

	handler, err := vm.NewHTTPHandler(context.Background())
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/rpc", "application/json",
		jsonBody(`{"jsonrpc":"2.0","id":1,"method":"quantumvm.getConfig","params":[{}]}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	static, err := vm.CreateStaticHandlers(context.Background())
	require.NoError(t, err)
	require.Nil(t, static)
}

// TestVMLifecycleCallbacks are the engine notifications the VM answers without
// doing anything, and must keep answering.
func TestVMLifecycleCallbacks(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	ctx := context.Background()

	version, err := vm.Version(ctx)
	require.NoError(t, err)
	require.Equal(t, Version, version)

	require.NoError(t, vm.Connected(ctx, ids.GenerateTestNodeID(), nil))
	require.NoError(t, vm.Disconnected(ctx, ids.GenerateTestNodeID()))
	require.NoError(t, vm.SetState(ctx, 3))
	require.NoError(t, vm.SetPreference(ctx, ids.GenerateTestID()))
}

// TestStampBlockSurvivesAShortMessage.
//
// The Corona leg used the first 32 bytes of whatever it was handed as a PRF
// key. StampBlock takes an arbitrary message from the finality bridge, so any
// message under 32 bytes took the slice out of range and killed the process.
func TestStampBlockSurvivesAShortMessage(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())

	for _, msg := range [][]byte{nil, {}, []byte("x"), []byte("under thirty-two bytes")} {
		require.NotPanics(t, func() {
			_, _ = vm.StampBlock(ids.GenerateTestID(), 7, msg)
		}, "a %d-byte message crashed the node", len(msg))
	}
}

// TestStampBlockFallsBackToMLDSA: with no bridge and no block id, the stamp is
// an ML-DSA signature over the message, and it verifies.
func TestStampBlockFallsBackToMLDSA(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	vm.quasarBridge = nil

	msg := []byte("a round digest to attest")
	stamp, err := vm.StampBlock(ids.Empty, 1, msg)
	require.NoError(t, err)

	sig, ok := stamp.(*quantum.QuantumSignature)
	require.True(t, ok)
	require.NoError(t, vm.quantumSigner.Verify(msg, sig))
	require.NoError(t, vm.VerifyStamp(sig))
}

// TestVerifyStampRefusesWhatItCannotCheck. Each arm is a shape a peer can send,
// and an empty one must not read as verified.
func TestVerifyStampRefusesWhatItCannotCheck(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	threshold := vm.GetQuasarBridge().GetThreshold()

	require.NoError(t, vm.VerifyStamp(&quasar.QuasarSignature{
		BLS: &quasar.BLSSignature{Signature: []byte{1}},
	}))
	require.Error(t, vm.VerifyStamp(&quasar.QuasarSignature{}), "a Quasar stamp with no BLS half")
	require.Error(t, vm.VerifyStamp(&quasar.QuasarSignature{BLS: &quasar.BLSSignature{}}), "an empty BLS signature")

	require.NoError(t, vm.VerifyStamp(&quasar.AggregatedSignature{
		BLSAggregated: []byte{1}, SignerCount: threshold,
	}))
	require.Error(t, vm.VerifyStamp(&quasar.AggregatedSignature{
		BLSAggregated: []byte{1}, SignerCount: threshold - 1,
	}), "an aggregate one signer short of the threshold")
	require.Error(t, vm.VerifyStamp(&quasar.AggregatedSignature{SignerCount: threshold}),
		"an aggregate carrying no signature bytes")

	require.Error(t, vm.VerifyStamp(&quantum.QuantumSignature{}), "an empty ML-DSA stamp")
	require.Error(t, vm.VerifyStamp("a string"), "an unknown stamp type")

	// With no bridge there is no threshold to check an aggregate against, so
	// the aggregate is refused rather than waved through.
	vm.quasarBridge = nil
	require.Error(t, vm.VerifyStamp(&quasar.AggregatedSignature{
		BLSAggregated: []byte{1}, SignerCount: threshold,
	}))
}

// TestFeePolicyRefusesEveryUserTransaction. Q-Chain sells no blockspace: cert
// inclusion is a validator obligation, so no amount buys it (LP-0130 §6).
func TestFeePolicyRefusesEveryUserTransaction(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	require.IsType(t, fee.NoUserTxPolicy{}, vm.FeePolicy())
	require.NoError(t, fee.Validate(vm.FeePolicy()))

	for _, paid := range []uint64{0, fee.MinTxFeeFloor, fee.MinTxFeeFloor * 1000} {
		tx := &BaseTransaction{timestamp: chainTime, nonce: paid, fee: paid,
			quantumSignature: &quantum.QuantumSignature{Signature: []byte{1}, QuantumStamp: []byte{1}}}
		require.Equal(t, paid, tx.Fee())
		require.ErrorIs(t, vm.IssueTx(tx), fee.ErrChainAcceptsNoUserTxs, "fee=%d bought a slot", paid)
	}
	require.Zero(t, vm.txPool.PendingCount(), "a refused transaction still reached the pool")

	// Consensus-internal work reaches the pool directly, which is the only way in.
	require.NoError(t, vm.txPool.AddTransaction(stampedTx(1, "cert")))
	require.Equal(t, 1, vm.txPool.PendingCount())
}

// TestIssueTxWithoutAPolicyFailsClosed: an unset policy refuses rather than
// admitting everything.
func TestIssueTxWithoutAPolicyFailsClosed(t *testing.T) {
	vm := &VM{log: log.NewNoOpLogger()}
	vm.txPool = NewTransactionPool(4, vm.log)
	require.Error(t, vm.IssueTx(stampedTx(1, "op")))
	require.Zero(t, vm.txPool.PendingCount())
}
