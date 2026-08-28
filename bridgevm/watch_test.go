// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/internal/bridgeattest"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// fakeSource is a chain that reports a head and answers for a range, so the
// watcher can be driven without an EVM behind it.
type fakeSource struct {
	mu      sync.Mutex
	head    uint64
	locks   map[uint64][]lock // block -> what was locked in it
	asked   [][2]uint64       // ranges asked for, in order
	headErr error
}

func (f *fakeSource) HeadBlock(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.headErr != nil {
		return 0, f.headErr
	}
	return f.head, nil
}

func (f *fakeSource) FetchLockEvents(_ context.Context, from, to *big.Int) ([]lock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, [2]uint64{from.Uint64(), to.Uint64()})
	var out []lock
	for n := from.Uint64(); n <= to.Uint64(); n++ {
		for _, l := range f.locks[n] {
			l.Block = n
			out = append(out, l)
		}
	}
	return out, nil
}

// The watcher only reads chains through the client map, so it has to satisfy
// ChainClient as well as lockSource.
func (f *fakeSource) GetTransaction(context.Context, ids.ID) (interface{}, error) { return nil, nil }
func (f *fakeSource) GetConfirmations(context.Context, ids.ID) (uint32, error)    { return 0, nil }
func (f *fakeSource) SendTransaction(context.Context, interface{}) (ids.ID, error) {
	return ids.Empty, nil
}
func (f *fakeSource) ValidateAddress([]byte) error { return nil }
func (f *fakeSource) IsProcessed(context.Context, bridgeattest.BridgeTransfer) (bool, error) {
	return false, nil
}

// TestWatchStartsAtTheSettledHead. Anything locked before B was watching was
// either released already or is not B's to release now, so a first pass adopts
// the head rather than replaying a chain's whole history into the queue.
func TestWatchStartsAtTheSettledHead(t *testing.T) {
	src := &fakeSource{head: 1000, locks: map[uint64][]lock{
		500: {{Transfer: transferFor(1, 1000)}},
	}}
	vm := boot(t)
	w := watcherOn(vm, src)

	w.pass()

	require.Empty(t, src.asked, "a first pass should only take its bearings")
	require.Empty(t, vm.pendingBridges, "a first pass queued requests from before it was watching")
	require.Equal(t, uint64(1000)-w.lag(), w.cursor[srcChain])
}

// TestWatchQueuesWhatWasLocked is the whole point: a lock on the source chain
// becomes a request a block can carry, and consensus is told there is work.
func TestWatchQueuesWhatWasLocked(t *testing.T) {
	src := &fakeSource{head: 1000}
	vm := boot(t)
	w := watcherOn(vm, src)
	w.pass() // take bearings

	locked := transferFor(42, 1000)
	src.mu.Lock()
	src.head = 1010
	src.locks = map[uint64][]lock{995: {{Transfer: locked, TxID: ids.ID{0xAB}}}}
	src.mu.Unlock()

	w.pass()

	require.Len(t, vm.pendingBridges, 1)
	req, ok := vm.pendingBridges[ids.ID(locked.Digest())]
	require.True(t, ok, "the request is not keyed by the transfer digest the gateway replays against")
	require.Equal(t, uint64(42), req.Nonce)
	require.Equal(t, uint64(1000), req.Amount)
	require.Equal(t, srcChain, req.SrcChainID)
	require.Equal(t, dstChain, req.DstChainID)
	require.Equal(t, ids.ID{0xAB}, req.SourceTxID)

	// Consensus must have been told, or the request sits in the queue forever.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := vm.WaitForEvent(ctx)
	require.NoError(t, err, "a lock was queued and consensus was never told")
}

// The same lock read twice is the same request. Re-reading a range after a
// restart must not queue a second copy of what is already pending.
func TestWatchDoesNotQueueALockTwice(t *testing.T) {
	locked := transferFor(7, 1000)
	src := &fakeSource{head: 1000}
	vm := boot(t)
	w := watcherOn(vm, src)
	w.pass()

	src.mu.Lock()
	src.head = 1010
	src.locks = map[uint64][]lock{995: {{Transfer: locked}}}
	src.mu.Unlock()
	w.pass()

	// Wind the cursor back, as a restart would, and read the same block again.
	w.cursor[srcChain] = 990
	src.mu.Lock()
	src.head = 1020
	src.mu.Unlock()
	w.pass()

	require.Len(t, vm.pendingBridges, 1, "the same lock queued twice")
}

// A chain read stays behind the head so a lock a reorg takes back never becomes
// a request, and one pass is bounded so a long backlog is asked for in pieces.
func TestWatchStaysBehindTheHeadAndBoundsAPass(t *testing.T) {
	src := &fakeSource{head: 100_000}
	vm := boot(t)
	w := watcherOn(vm, src)
	w.cursor[srcChain] = 0

	w.pass()

	require.Len(t, src.asked, 1, "asked more than once in one pass")
	from, to := src.asked[0][0], src.asked[0][1]
	require.LessOrEqual(t, to-from+1, uint64(watchSpan), "one pass asked for more than the bound")
	require.LessOrEqual(t, to, src.head-w.lag(), "read too close to the head")
}

// TestWatchReadsAsDeepAsTheChainAsksFor is the defect the depth field hid.
//
// A request was stamped with the depth its lock happened to have when it was
// first seen, and the cursor then moved past that block for good. A chain
// asking for more confirmations than the fixed reorg margin therefore queued
// every transfer at a depth that would never be enough, and none of them was
// ever carried. Reading as deep as the chain asks makes anything read eligible
// by construction, and there is no depth left to go stale.
func TestWatchReadsAsDeepAsTheChainAsksFor(t *testing.T) {
	cfg := testConfig()
	cfg.MinConfirmations = 500
	vm := bootOn(t, memdb.New(), cfg)
	src := &fakeSource{head: 1000}
	w := watcherOn(vm, src)

	require.Equal(t, uint64(500), w.lag())
	w.pass()
	require.Equal(t, uint64(500), w.cursor[srcChain], "the cursor sits 500 blocks behind the head")

	// Only what is now buried 500 deep is read.
	src.mu.Lock()
	src.head = 1100
	src.locks = map[uint64][]lock{550: {{Transfer: transferFor(1, 1000)}}}
	src.mu.Unlock()
	w.pass()

	require.Len(t, vm.pendingBridges, 1)
	require.Equal(t, [2]uint64{501, 600}, src.asked[0])
}

// A chain that cannot be reached is left for the next pass with its cursor
// where it was, so an endpoint having a bad minute does not skip its blocks.
func TestWatchDoesNotAdvancePastAChainItCannotRead(t *testing.T) {
	src := &fakeSource{head: 1000}
	vm := boot(t)
	w := watcherOn(vm, src)
	w.pass()
	settled := w.cursor[srcChain]

	src.mu.Lock()
	src.head = 2000
	src.headErr = errors.New("endpoint down")
	src.mu.Unlock()
	w.pass()

	require.Equal(t, settled, w.cursor[srcChain], "cursor moved while the chain was unreadable")
}

// TestAChainTooShortToReadIsLeftAlone: a source chain with fewer blocks than
// the read depth has nothing settled to read yet.
func TestAChainTooShortToReadIsLeftAlone(t *testing.T) {
	src := &fakeSource{head: 3}
	vm := boot(t)
	w := watcherOn(vm, src)
	w.pass()
	_, seen := w.cursor[srcChain]
	require.False(t, seen, "a chain shorter than the read depth was given a cursor")
}

// TestAClientThatIsNotASourceIsSkipped: a destination-only client answers none
// of the questions the watcher asks, and is not one it reads.
func TestAClientThatIsNotASourceIsSkipped(t *testing.T) {
	vm := boot(t)
	w := watcherOn(vm, &recordingClient{})
	w.pass()
	require.Empty(t, w.cursor)
}

// TestALockThatCanNeverBeCarriedIsNotHeld. A transfer no block can carry —
// over the per-transfer cap, say — used to sit in the pending set, be
// proposed, be refused, and go straight back in. Deciding it once, where the
// lock is read, is the difference between one warning and a proposer that
// never makes progress again.
func TestALockThatCanNeverBeCarriedIsNotHeld(t *testing.T) {
	cfg := testConfig()
	cfg.MaxBridgeAmount = 10
	vm := bootOn(t, memdb.New(), cfg)
	src := &fakeSource{head: 1000}
	w := watcherOn(vm, src)
	w.pass()

	src.mu.Lock()
	src.head = 1010
	src.locks = map[uint64][]lock{995: {
		{Transfer: transferFor(1, 5_000)}, // over the cap
		{Transfer: transferFor(2, 5)},     // fine
	}}
	src.mu.Unlock()
	w.pass()

	require.Len(t, vm.pendingBridges, 1, "an uncarryable transfer was held")
	_, ok := vm.pendingBridges[ids.ID(transferFor(2, 5).Digest())]
	require.True(t, ok)
}

// TestALockBecomesABlock is the whole path in one test: a gateway locks value
// on the source chain, the watcher reads it, consensus is told there is work,
// and the block that gets built carries exactly that transfer — and settles.
func TestALockBecomesABlock(t *testing.T) {
	vm := boot(t)
	src := &fakeSource{head: 1000}
	w := watcherOn(vm, src)
	w.pass() // take bearings

	locked := transferFor(11, 1000)
	src.mu.Lock()
	src.head = 1010
	src.locks = map[uint64][]lock{995: {{Transfer: locked, TxID: ids.ID{0xCD}}}}
	src.mu.Unlock()
	w.pass()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := vm.WaitForEvent(ctx)
	require.NoError(t, err, "consensus was never told there was work")

	built := buildAndAccept(t, vm)
	require.Len(t, built.BridgeRequests, 1)
	require.Equal(t, ids.ID(locked.Digest()), built.BridgeRequests[0].ID)
	require.Equal(t, uint64(1000), vm.movedToday(built.BlockTimestamp, dstChain))

	vm.mu.RLock()
	defer vm.mu.RUnlock()
	require.Empty(t, vm.pendingBridges, "a settled transfer is no longer waiting for a block")
}

// TestHealthSaysWhatItCannotDo. Releasing needs a threshold key to attest with
// and a chain to broadcast to, so health reports whether this node has both and
// names what is missing when it does not.
func TestHealthSaysWhatItCannotDo(t *testing.T) {
	// A node with no chains wired is not a relayer. That is a configuration,
	// not a fault, and calling it unhealthy would take validators that were
	// never meant to relay out of rotation.
	plain := boot(t)
	res, err := plain.HealthCheck(context.Background())
	require.NoError(t, err)
	require.True(t, res.Healthy, "a validator that relays nothing reported unhealthy")

	// A node that IS configured to relay but cannot attest is a different
	// matter: answering healthy routes transfers at a node that cannot carry
	// them.
	relayer := boot(t)
	watcherOn(relayer, &fakeSource{})
	res, err = relayer.HealthCheck(context.Background())
	require.NoError(t, err)
	require.False(t, res.Healthy, "a relayer with no threshold signing key reported healthy")
	require.Equal(t, "no threshold signing key", res.Details["status"])
	require.Equal(t, "1", res.Details["chains"])
}

// The endpoint and the node's own check must not disagree about the same node.
func TestHealthEndpointAgreesWithTheNodeCheck(t *testing.T) {
	vm := boot(t)
	watcherOn(vm, &fakeSource{})

	res, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	var reply HealthReply
	require.NoError(t, (&Service{vm: vm}).Health(nil, &HealthArgs{}, &reply))
	require.Equal(t, res.Healthy, reply.Ready)
	require.Equal(t, res.Details["status"], reply.Status)
}

// The bridge's API is the JSON-RPC service, and that is what gets served.
func TestTheServedAPIIsTheRealOne(t *testing.T) {
	vm := &VM{log: log.NewNoOpLogger()}
	handlers, err := vm.CreateHandlers(context.Background())
	require.NoError(t, err)
	require.Contains(t, handlers, "/rpc")
	for _, canned := range []string{"/status", "/validators", "/bridge"} {
		require.NotContains(t, handlers, canned,
			"%s is served again, and it answers the same thing whatever the state", canned)
	}

	mux, err := vm.NewHTTPHandler(context.Background())
	require.NoError(t, err)
	require.NotNil(t, mux)

	static, err := vm.CreateStaticHandlers(context.Background())
	require.NoError(t, err)
	require.Nil(t, static)
}
