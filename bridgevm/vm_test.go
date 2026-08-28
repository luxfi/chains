// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/constants"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/warp"
)

// =============================================================================
// Booting
// =============================================================================

// TestTheVMBoots is the whole of what was wrong: the chain store was never
// built, so Initialize dereferenced a nil store and B-Chain could not start.
func TestTheVMBoots(t *testing.T) {
	vm := boot(t)
	require.NotNil(t, vm.chain)
	require.NotNil(t, vm.genesisBlock)
	require.NotNil(t, vm.signerSet)
	require.NotNil(t, vm.quoteEngine)
	require.NotNil(t, vm.swapStore)
	require.Equal(t, testChainID, vm.chainID)
	require.NotNil(t, vm.FeePolicy())

	version, err := vm.Version(context.Background())
	require.NoError(t, err)
	require.Equal(t, Version.String(), version)
}

// TestInitializeRefusesWhatItCannotRunOn. A VM that boots without the things
// it needs is a chain that fails later, somewhere less obvious.
func TestInitializeRefusesWhatItCannotRunOn(t *testing.T) {
	ctx := context.Background()

	require.ErrorContains(t, (&VM{}).Initialize(ctx, vmcore.Init{}), "no runtime")

	noDB := initFor(memdb.New(), testConfig())
	noDB.DB = nil
	require.ErrorContains(t, (&VM{}).Initialize(ctx, noDB), "no database")

	noLog := initFor(memdb.New(), testConfig())
	noLog.Runtime = &runtime.Runtime{NetworkID: 96369}
	require.ErrorContains(t, (&VM{}).Initialize(ctx, noLog), "invalid logger")

	badConfig := initFor(memdb.New(), testConfig())
	badConfig.Config = []byte(`{"maxBridgeAmount": "not a number"}`)
	require.ErrorContains(t, (&VM{}).Initialize(ctx, badConfig), "parse config")

	badGenesis := initFor(memdb.New(), testConfig())
	badGenesis.Genesis = []byte(`{`)
	require.ErrorContains(t, (&VM{}).Initialize(ctx, badGenesis), "parse genesis")
}

// TestABridgeDeclaresItsCaps. A zero per-transfer cap refuses every transfer,
// silently, at every block — which looks exactly like a bridge nobody is
// using. A bridge whose limits nobody decided does not get to run.
func TestABridgeDeclaresItsCaps(t *testing.T) {
	ctx := context.Background()

	for name, mutate := range map[string]func(*BridgeConfig){
		"minConfirmations must be at least 1": func(c *BridgeConfig) { c.MinConfirmations = 0 },
		"maxBridgeAmount must be declared":    func(c *BridgeConfig) { c.MaxBridgeAmount = 0 },
		"is below maxBridgeAmount":            func(c *BridgeConfig) { c.DailyBridgeLimit = c.MaxBridgeAmount - 1 },
		"is below the":                        func(c *BridgeConfig) { c.RequireValidatorBond = minValidatorBond - 1 },
	} {
		cfg := testConfig()
		mutate(&cfg)
		require.ErrorContains(t, (&VM{}).Initialize(ctx, initFor(memdb.New(), cfg)), name)
	}

	// An empty configuration declares nothing, so it runs nothing.
	empty := initFor(memdb.New(), testConfig())
	empty.Config = nil
	require.Error(t, (&VM{}).Initialize(ctx, empty))
}

// The signer set freezes at a size, and that size has a default because it is a
// capacity rather than a risk decision.
func TestTheSignerSetSizeDefaults(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSigners = 0
	vm := bootOn(t, memdb.New(), cfg)
	require.Equal(t, 100, vm.config.MaxSigners)
}

// TestTheGenesisTimestampIsTheChainsFirstTime.
func TestGenesisComesFromItsBytes(t *testing.T) {
	vm := boot(t)
	require.Equal(t, int64(1000000), vm.genesisBlock.BlockTimestamp)
	require.Equal(t, ids.Empty, vm.genesisBlock.ParentID())
	require.Zero(t, vm.genesisBlock.Height())
	require.Equal(t, time.Unix(1000000, 0), vm.genesisBlock.Timestamp())
}

// TestTheVMIDIsTheSharedOne. A chain is resolved to a plugin binary by this
// id, so a private copy of the value beside the shared one is a chain nothing
// can open.
func TestTheVMIDIsTheSharedOne(t *testing.T) {
	require.Equal(t, constants.BridgeVMID, VMID)
	require.NotEqual(t, ids.Empty, VMID)
	require.NotEqual(t, constants.MPCVMID, VMID)
	// The encoding the node resolves a plugin binary by. Computed outside this
	// package — base58(bytes ‖ sha256(bytes)[28:]) over "bridgevm" padded to 32
	// — so it pins the value rather than restating whatever the code produces.
	require.Equal(t, "kMhHABHM8j4bH94MCc4rsTNdo5E9En37MMyiujk4WdNxgXFsY", VMID.String())
}

// =============================================================================
// What consensus asks of the VM
// =============================================================================

func TestTheChainAnswersConsensus(t *testing.T) {
	ctx := context.Background()
	vm := boot(t)
	pend(vm, requestFor(1, 100))
	blk := buildAndAccept(t, vm)

	last, err := vm.LastAccepted(ctx)
	require.NoError(t, err)
	require.Equal(t, blk.ID(), last)

	require.NoError(t, vm.SetPreference(ctx, blk.ID()))

	got, err := vm.GetBlock(ctx, blk.ID())
	require.NoError(t, err)
	require.Equal(t, blk.Bytes(), got.Bytes())

	_, err = vm.GetBlock(ctx, ids.GenerateTestID())
	require.Error(t, err)

	parsed, err := vm.ParseBlock(ctx, blk.Bytes())
	require.NoError(t, err)
	require.Equal(t, blk.ID(), parsed.ID())

	health, err := vm.HealthCheck(ctx)
	require.NoError(t, err)
	require.True(t, health.Healthy)
}

// A block reports where it is and what became of it.
func TestABlockReportsItself(t *testing.T) {
	vm := boot(t)
	pend(vm, requestFor(1, 100))
	blk := build(t, vm)

	require.Equal(t, vm.genesisBlock.ID(), blk.Parent())
	require.Equal(t, vm.genesisBlock.ID(), blk.ParentID())
	require.Equal(t, uint64(1), blk.Height())
	require.Equal(t, time.Unix(blk.BlockTimestamp, 0), blk.Timestamp())
	require.NotEmpty(t, blk.Bytes())
	require.Equal(t, blk.Bytes(), blk.Bytes(), "the encoding is cached, not recomputed")

	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))
	require.Equal(t, uint8(choices.Accepted), blk.Status())
	require.Nil(t, blk.spend, "an accepted block's state is the database")
}

// A rejected block leaves nothing behind, so its transfers are proposed again
// rather than lost with it.
func TestARejectedBlockLeavesItsTransfersWaiting(t *testing.T) {
	vm := boot(t)
	req := requestFor(1, 100)
	pend(vm, req)

	blk := build(t, vm)
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Reject(context.Background()))
	require.Equal(t, uint8(choices.Rejected), blk.Status())
	require.Nil(t, blk.spend)

	_, err := vm.GetBlock(context.Background(), blk.ID())
	require.Error(t, err, "a rejected block is not a parent anything can build on")

	vm.mu.RLock()
	_, waiting := vm.pendingBridges[req.ID]
	vm.mu.RUnlock()
	require.True(t, waiting)

	// And it can be carried by the block that replaces it.
	again := buildAndAccept(t, vm)
	require.Equal(t, req.ID, again.BridgeRequests[0].ID)
}

// The block id is computed once and cached, and computing it twice gives the
// same answer.
func TestABlockIDIsAFunctionOfItsContents(t *testing.T) {
	vm := boot(t)
	blk := blockOn(t, vm, vm.genesisBlock, 1_000_000, requestFor(1, 100))
	want := blk.ID()

	blk.ID_ = ids.Empty
	require.Equal(t, want, blk.ID(), "the id is not a function of its contents")
	require.Equal(t, want, blk.computeID())
}

// The peer-to-peer surface is answered rather than left to time out. B-Chain
// carries no application protocol of its own: what it learns, it learns from
// the source chains it reads.
func TestThePeerSurfaceIsAnswered(t *testing.T) {
	ctx := context.Background()
	vm := boot(t)
	node := ids.GenerateTestNodeID()
	chain := ids.GenerateTestID()

	require.NoError(t, vm.Connected(ctx, node, nil))
	require.NoError(t, vm.Disconnected(ctx, node))
	require.NoError(t, vm.Request(ctx, node, 1, time.Now(), nil))
	require.NoError(t, vm.Response(ctx, node, 1, nil))
	require.NoError(t, vm.RequestFailed(ctx, node, 1, &warp.Error{}))
	require.NoError(t, vm.Gossip(ctx, node, nil))
	require.NoError(t, vm.CrossChainRequest(ctx, chain, 1, time.Now(), nil))
	require.NoError(t, vm.CrossChainResponse(ctx, chain, 1, nil))
	require.NoError(t, vm.CrossChainRequestFailed(ctx, chain, 1, &warp.Error{}))
	require.NoError(t, vm.SetState(ctx, 0))
	require.NoError(t, vm.Shutdown(ctx))
}

// =============================================================================
// The reshare request
// =============================================================================

// signingWarp is a node's BLS signer, answering with a signature of the width
// the envelope requires.
type signingWarp struct {
	sig []byte
	err error
}

func (s signingWarp) Sign(*warp.Message) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.sig, nil
}

type recordingSender struct {
	warp.FakeSender
	mu   sync.Mutex
	sent [][]byte
	err  error
}

func (s *recordingSender) SendGossip(_ context.Context, _ warp.SendConfig, msg []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.sent = append(s.sent, msg)
	return nil
}

// TestReplacingASignerAsksMChainToReshare. B-Chain holds no custody key: the
// reshare happens on M, and this is the request that asks for it.
func TestReplacingASignerAsksMChainToReshare(t *testing.T) {
	vm := boot(t)
	sender := &recordingSender{}
	vm.rt.WarpSigner = signingWarp{sig: make([]byte, warp.SignatureLen)}
	vm.rt.Sender = sender

	nodes := make([]ids.NodeID, 0, 4)
	for i := 0; i < 4; i++ {
		node := ids.GenerateTestNodeID()
		nodes = append(nodes, node)
		require.NoError(t, registerSigner(vm, node))
	}
	replacement := ids.GenerateTestNodeID()

	result, err := vm.RemoveSigner(nodes[2], &replacement)
	require.NoError(t, err)
	require.True(t, result.Success)

	sender.mu.Lock()
	defer sender.mu.Unlock()
	require.Len(t, sender.sent, 1, "M-Chain was never asked to reshare")

	env, err := warp.ParseEnvelope(sender.sent[0])
	require.NoError(t, err)
	var asked CrossChainMPCRequest
	require.NoError(t, json.Unmarshal(env.Message.Payload, &asked))

	require.Equal(t, MPCRequestReshare, asked.Type)
	require.Equal(t, result.ReshareSession, asked.SessionID)
	require.Equal(t, uint64(1), asked.Epoch)
	require.Equal(t, vm.signerSet.ThresholdT, asked.Threshold)
	require.Equal(t, testChainID[:], asked.SourceChainID,
		"the request must name the chain it came from")
	require.Len(t, asked.NewPartyIDs, 4)
	require.Len(t, asked.OldPartyIDs, 3, "the removed and the arriving signer are not old parties")
}

// A node with no warp plumbing is not a fault: it validates like any other and
// has no reshare to broadcast.
func TestANodeWithoutWarpAsksNobody(t *testing.T) {
	vm := boot(t)
	node := ids.GenerateTestNodeID()
	require.NoError(t, registerSigner(vm, node))

	result, err := vm.RemoveSigner(node, nil)
	require.NoError(t, err)
	require.True(t, result.Success, "removal stands whether or not the request goes out")
}

// A reshare request that cannot be signed or sent does not undo the removal:
// the signer is out either way, and the request is retryable.
func TestAReshareRequestThatFailsDoesNotUndoTheRemoval(t *testing.T) {
	for name, wire := range map[string]func(*VM){
		"the signature is the wrong width": func(vm *VM) {
			vm.rt.WarpSigner = signingWarp{sig: make([]byte, 10)}
			vm.rt.Sender = &recordingSender{}
		},
		"the node cannot sign": func(vm *VM) {
			vm.rt.WarpSigner = signingWarp{err: errors.New("no key")}
			vm.rt.Sender = &recordingSender{}
		},
		"the gossip does not go out": func(vm *VM) {
			vm.rt.WarpSigner = signingWarp{sig: make([]byte, warp.SignatureLen)}
			vm.rt.Sender = &recordingSender{err: errors.New("no peers")}
		},
	} {
		vm := boot(t)
		wire(vm)
		node := ids.GenerateTestNodeID()
		require.NoError(t, registerSigner(vm, node))

		result, err := vm.RemoveSigner(node, nil)
		require.NoError(t, err, name)
		require.True(t, result.Success, name)
		require.False(t, vm.HasSigner(node), name)
	}
}

// A VM with no logger does not panic when something happens worth logging.
func TestALoglessVMDoesNotPanic(t *testing.T) {
	vm := &VM{signerSet: &SignerSet{}, config: testConfig()}
	vm.logInfo("nothing here")
	vm.logWarn("nor here")

	vm.log = log.NewNoOpLogger()
	vm.logInfo("nor here either")
	vm.logWarn("nor here either")
}
