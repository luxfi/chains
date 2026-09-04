// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	luxvm "github.com/luxfi/vm"
	"github.com/stretchr/testify/require"
)

// testRuntime is the identity the node hands the VM: one chain, one node.
func testRuntime() *runtime.Runtime {
	return &runtime.Runtime{
		NetworkID: testNetwork, ChainID: testChain, NodeID: ids.GenerateTestNodeID(),
	}
}

// TestAnEmptyConfigStartsAUsableVM. The config is normalised in exactly one
// place — Initialize — so a VM built by the factory and one built by hand start
// from the same rules, and neither comes up batching nothing.
func TestAnEmptyConfigStartsAUsableVM(t *testing.T) {
	raw, err := (&Factory{Config: config.Config{}}).New(log.NewNoOpLogger())
	require.NoError(t, err)
	vm, ok := raw.(*VM)
	require.True(t, ok)

	require.NoError(t, vm.Initialize(context.Background(), luxvm.Init{
		DB:      memdb.New(),
		Log:     log.NewNoOpLogger(),
		Runtime: testRuntime(),
	}))
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })

	require.Positive(t, vm.Config.MaxParallelTxs)
	require.Positive(t, vm.Config.ParallelBatchSize)
	require.Equal(t, config.AlgorithmDefault, vm.Config.QuantumAlgorithmVersion)
	require.Equal(t, config.CommitteeMin, vm.Config.Committee)

	// The settled config and the stock one agree on the parameter set. Two
	// spellings of the default is a chain whose algorithm depends on which door
	// its operator came through.
	require.Equal(t, config.DefaultConfig().QuantumAlgorithmVersion, vm.Config.QuantumAlgorithmVersion)

	require.NotEqual(t, ids.Empty, tipOf(t, vm))

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
		DB: memdb.New(), Log: log.NewNoOpLogger(), Runtime: testRuntime(),
	}))
}

// TestInitializeRefusesACommitteeThatSurvivesNoFault. The threshold is derived
// from the committee, and ⌊2n/3⌋+1 is unanimity for every n below four: one
// absent validator halts the chain, one dishonest validator decides it, and the
// consensus core will not even build the key set for it.
func TestInitializeRefusesACommitteeThatSurvivesNoFault(t *testing.T) {
	for _, n := range []int{1, 2, 3} {
		cfg := config.DefaultConfig()
		cfg.Committee = n
		vm := &VM{Config: cfg}
		require.Error(t, vm.Initialize(context.Background(), luxvm.Init{
			DB: memdb.New(), Log: log.NewNoOpLogger(), Runtime: testRuntime(),
		}), "a committee of %d was accepted", n)
	}
}

// TestInitializeWithoutALoggerDoesNotPanic: Initialize accepts a nil Log, so it
// has to survive one. Every path out of Initialize logs.
func TestInitializeWithoutALoggerDoesNotPanic(t *testing.T) {
	vm := &VM{Config: config.DefaultConfig()}
	require.NoError(t, vm.Initialize(context.Background(), luxvm.Init{
		DB: memdb.New(), Runtime: testRuntime(),
	}))
	require.NoError(t, vm.Shutdown(context.Background()))
}

// TestInitializeRefusesANodeWithNoIdentity.
//
// Without a runtime the VM took the EMPTY node id and started anyway, so every
// node that came up that way signed under one shared name: their signatures
// arrived as duplicates of each other and no threshold above one could be met.
// A node that cannot say who it is cannot be one of a number of distinct
// signers, so it does not start.
func TestInitializeRefusesANodeWithNoIdentity(t *testing.T) {
	for _, rt := range []*runtime.Runtime{
		nil,
		{NetworkID: testNetwork, ChainID: testChain},
		{NetworkID: testNetwork, ChainID: testChain, NodeID: ids.EmptyNodeID},
	} {
		vm := &VM{Config: config.DefaultConfig()}
		require.ErrorIs(t, vm.Initialize(context.Background(), luxvm.Init{
			DB: memdb.New(), Log: log.NewNoOpLogger(), Runtime: rt,
		}), errNoIdentity)
	}
}

// TestEveryNodeSignsUnderItsOwnName.
//
// The threshold counts DISTINCT validator ids, so the id has to name the NODE.
// It named the CHAIN — which every node of a chain shares, by definition — so
// each peer's signature arrived as a duplicate of the first, the count never
// passed one, and no threshold above one could ever be met.
//
// The three VMs below share ONE chain id and hold three node ids, which is the
// only shape production ever has. Giving each test VM its own chain id varied
// the wrong field: under that shape the broken code prints three different
// names too, and the test passes while the fleet cannot finalize anything.
func TestEveryNodeSignsUnderItsOwnName(t *testing.T) {
	a, _ := bootVM(t, quietConfig())
	b, _ := bootVM(t, quietConfig())
	c, _ := bootVM(t, quietConfig())

	require.Equal(t, a.blockchainID, b.blockchainID, "precondition: one chain")
	require.Equal(t, a.blockchainID, c.blockchainID, "precondition: one chain")

	names := map[string]bool{}
	for _, vm := range []*VM{a, b, c} {
		id := vm.GetQuasarBridge().validatorID
		require.NotEqual(t, ids.EmptyNodeID.String(), id, "the node signs as nobody")
		require.NotEqual(t, vm.blockchainID.String(), id, "the node signs under the chain's name")
		names[id] = true
	}
	require.Len(t, names, 3, "three nodes of one chain signed under fewer than three names")
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

// TestBuildBlockRefusesWhenItsClockTrailsTheTipTooFar.
//
// The two halves of the clock rule contradicted each other. Clamping the
// timestamp forward to the parent's keeps a slightly slow node building; but a
// node whose clock trails the tip by MORE than the skew allowance clamps to a
// value its own Verify then rejects for exceeding now+skew. The VM built a block
// and immediately refused it, over and over. The node's clock is what is wrong,
// so the node says so.
func TestBuildBlockRefusesWhenItsClockTrailsTheTipTooFar(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	parent := advance(t, vm, 1)

	// Exactly at the allowance still builds, and still verifies.
	vm.clock.Set(parent.timestamp.Add(-MaxFutureSkew))
	blk := buildOn(t, vm)
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))

	// One second past it, the node refuses rather than producing a block it
	// will not itself accept.
	vm.clock.Set(blk.timestamp.Add(-MaxFutureSkew - time.Second))
	require.NoError(t, vm.txPool.AddTransaction(stampedTx(77, "op")))
	_, err := vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errClockBehindTip)
}

// TestABlockTooLargeToHoldIsRefusedEverywhere.
//
// Nothing bounded a block anywhere: parse, verify and commit each walked
// whatever arrived, so a peer decided how much memory this node allocated and
// how much its store held.
func TestABlockTooLargeToHoldIsRefusedEverywhere(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	genesis, err := vm.blockAt(tipOf(t, vm))
	require.NoError(t, err)

	huge := blockOn(vm, genesis, stampedTx(1, string(make([]byte, MaxBlockSize))))
	require.Greater(t, len(huge.Bytes()), MaxBlockSize, "precondition: over the bound")

	_, err = vm.ParseBlock(context.Background(), huge.Bytes())
	require.ErrorIs(t, err, errBlockTooLarge)
	require.ErrorIs(t, huge.Verify(context.Background()), errBlockTooLarge)

	// And the builder will not produce one either.
	require.NoError(t, vm.txPool.AddTransaction(stampedTx(2, string(make([]byte, MaxBlockSize)))))
	_, err = vm.BuildBlock(context.Background())
	require.ErrorIs(t, err, errBlockTooLarge)
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
// version layer is closed, so nothing can be read or staged — and Accept must
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
	accepted := []ids.ID{tipOf(t, vm)}
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
	require.Len(t, parsed.(*Block).transactions, len(blk.transactions))

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
// The signing lane used the first 32 bytes of whatever it was handed as a PRF
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

// TestStampBlockSignsWithTheNodesOwnKey, and the stamp verifies against the
// message it attests — which it could not do while the node was not registered
// with its own consensus core.
func TestStampBlockSignsWithTheNodesOwnKey(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())

	msg := []byte("a round digest to attest")
	stamp, err := vm.StampBlock(ids.GenerateTestID(), 1, msg)
	require.NoError(t, err)

	sig, ok := stamp.(*quasar.QuasarSig)
	require.True(t, ok, "the bridge is up and produced no Quasar signature")
	require.NoError(t, vm.VerifyStamp(msg, sig))
	require.Error(t, vm.VerifyStamp([]byte("a different digest"), sig))
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
	require.NoError(t, vm.VerifyStamp(msg, sig))
	require.Error(t, vm.VerifyStamp([]byte("another message"), sig))
}

// TestVerifyStampChecksTheSignatureAgainstTheMessage.
//
// It took no message, so no arm could check a signature against anything: each
// looked at the stamp's own SHAPE, and shape is what the sender chose. A
// two-byte aggregate declaring three signers passed; so did a one-byte BLS
// signature. A self-declared signer count is not evidence of anything.
func TestVerifyStampChecksTheSignatureAgainstTheMessage(t *testing.T) {
	ctx := context.Background()
	vm, _ := bootVM(t, quietConfig())
	bridge := vm.GetQuasarBridge()
	threshold := bridge.GetThreshold()
	msg := []byte("the message under attestation")

	// A validator signature: the real one verifies, a forged shape does not.
	sig, err := bridge.SignBlock(ctx, ids.GenerateTestID(), msg, 1)
	require.NoError(t, err)
	require.NoError(t, vm.VerifyStamp(msg, sig))
	require.Error(t, vm.VerifyStamp(msg, &quasar.QuasarSig{
		BLS: []byte{1}, ValidatorID: bridge.validatorID,
	}), "a one-byte BLS signature was accepted")
	require.Error(t, vm.VerifyStamp([]byte("another message"), sig),
		"a signature was accepted for a message it does not sign")

	// An aggregate: a self-declared signer count buys nothing.
	require.Error(t, vm.VerifyStamp(msg, &quasar.AggregatedSignature{
		BLSAggregated: []byte{1, 2}, SignerCount: threshold,
	}), "two bytes declaring a quorum were accepted as an aggregate")
	require.Error(t, vm.VerifyStamp(msg, &quasar.AggregatedSignature{
		BLSAggregated: []byte{1}, SignerCount: threshold + 100,
	}), "declaring more signers made a forgery verify")
	require.Error(t, vm.VerifyStamp(msg, &quasar.AggregatedSignature{SignerCount: threshold}),
		"an aggregate carrying no signature bytes")

	// An ML-DSA stamp is checked the same way.
	require.Error(t, vm.VerifyStamp(msg, &quantum.QuantumSignature{}), "an empty ML-DSA stamp")

	require.ErrorIs(t, vm.VerifyStamp(msg, nil), errNoStamp)
	require.Error(t, vm.VerifyStamp(msg, "a string"), "an unknown stamp type")

	// With no bridge there is nothing to check a Quasar stamp against, so it is
	// refused rather than waved through.
	vm.quasarBridge = nil
	require.Error(t, vm.VerifyStamp(msg, sig))
	require.Error(t, vm.VerifyStamp(msg, &quasar.AggregatedSignature{
		BLSAggregated: []byte{1}, SignerCount: threshold,
	}))
}

// TestVerifyStampAcceptsAQuorumAggregate is the other half: an aggregate built
// from a verified quorum verifies, over the message it was built on and no
// other.
func TestVerifyStampAcceptsAQuorumAggregate(t *testing.T) {
	ctx := context.Background()
	vm, _ := bootVM(t, quietConfig())
	bridge := vm.GetQuasarBridge()

	blockID := ids.GenerateTestID()
	msg := blockID[:]
	_, err := bridge.SignBlock(ctx, blockID, msg, 1)
	require.NoError(t, err)

	for _, peer := range []string{"peer-1", "peer-2"} {
		require.NoError(t, bridge.AddValidator(peer, 1))
		require.NoError(t, bridge.AddSignature(blockID, signAs(t, bridge, peer, msg)))
	}

	agg, finalized, err := bridge.TryFinalize(ctx, blockID)
	require.NoError(t, err)
	require.True(t, finalized)
	require.NoError(t, vm.VerifyStamp(msg, agg))
	require.Error(t, vm.VerifyStamp([]byte("another block"), agg))
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
