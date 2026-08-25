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

	"github.com/luxfi/chains/internal/bridgeattest"
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

func transferAt(nonce uint64) bridgeattest.BridgeTransfer {
	bt := bridgeattest.BridgeTransfer{
		SrcChainID: 96368,
		DstChainID: 200201,
		Amount:     1000,
		Nonce:      nonce,
	}
	bt.Asset[0] = 7
	bt.Recipient[0] = 9
	return bt
}

// watchingVM is the smallest VM the watcher touches: a client map, a pending
// queue, a latch and a logger.
func watchingVM(src *fakeSource) *VM {
	vm := &VM{
		log:            log.NewNoOpLogger(),
		pendingBridges: make(map[ids.ID]*BridgeRequest),
		evmByChainID:   map[uint32]ChainClient{96368: src},
	}
	return vm
}

func newTestWatcher(vm *VM) *watcher {
	return &watcher{
		vm:     vm,
		names:  map[uint32]string{96368: "lux-testnet-c", 200201: "zoo-testnet"},
		cursor: make(map[uint32]uint64),
		quit:   make(chan struct{}),
	}
}

// TestWatchStartsAtTheSettledHead. Anything locked before B was watching was
// either released already or is not B's to release now, so a first pass adopts
// the head rather than replaying a chain's whole history into the queue.
func TestWatchStartsAtTheSettledHead(t *testing.T) {
	src := &fakeSource{head: 1000, locks: map[uint64][]lock{
		500: {{Transfer: transferAt(1)}},
	}}
	vm := watchingVM(src)
	w := newTestWatcher(vm)

	w.pass()

	if len(src.asked) != 0 {
		t.Fatalf("a first pass asked for %v; it should only take its bearings", src.asked)
	}
	if len(vm.pendingBridges) != 0 {
		t.Fatalf("a first pass queued %d requests from before it was watching", len(vm.pendingBridges))
	}
	if got, want := w.cursor[96368], uint64(1000-watchLag); got != want {
		t.Fatalf("cursor = %d, want the settled head %d", got, want)
	}
}

// TestWatchQueuesWhatWasLocked is the whole point: a lock on the source chain
// becomes a request a block can carry, and consensus is told there is work.
func TestWatchQueuesWhatWasLocked(t *testing.T) {
	src := &fakeSource{head: 1000}
	vm := watchingVM(src)
	w := newTestWatcher(vm)
	w.pass() // take bearings at 988

	locked := transferAt(42)
	src.mu.Lock()
	src.head = 1010
	src.locks = map[uint64][]lock{995: {{Transfer: locked, TxID: ids.ID{0xAB}}}}
	src.mu.Unlock()

	w.pass()

	if len(vm.pendingBridges) != 1 {
		t.Fatalf("queued %d requests, want 1", len(vm.pendingBridges))
	}
	req, ok := vm.pendingBridges[ids.ID(locked.Digest())]
	if !ok {
		t.Fatal("the request is not keyed by the transfer digest the gateway replays against")
	}
	if req.Nonce != 42 || req.Amount != 1000 || req.SrcChainID != 96368 || req.DstChainID != 200201 {
		t.Fatalf("request does not carry the locked transfer: %+v", req)
	}
	if req.SourceChain != "lux-testnet-c" || req.DestChain != "zoo-testnet" {
		t.Fatalf("route labels not resolved: %q -> %q", req.SourceChain, req.DestChain)
	}
	if req.SourceTxID != (ids.ID{0xAB}) {
		t.Fatalf("source transaction not carried: %v", req.SourceTxID)
	}

	// Consensus must have been told, or the request sits in the queue forever.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := vm.WaitForEvent(ctx); err != nil {
		t.Fatal("a lock was queued and consensus was never told; the block would never be built")
	}
}

// The same lock read twice is the same request. Re-reading a range after a
// restart must not queue a second copy of what is already pending.
func TestWatchDoesNotQueueALockTwice(t *testing.T) {
	locked := transferAt(7)
	src := &fakeSource{head: 1000}
	vm := watchingVM(src)
	w := newTestWatcher(vm)
	w.pass()

	src.mu.Lock()
	src.head = 1010
	src.locks = map[uint64][]lock{995: {{Transfer: locked}}}
	src.mu.Unlock()
	w.pass()

	// Wind the cursor back, as a restart would, and read the same block again.
	w.cursor[96368] = 990
	src.mu.Lock()
	src.head = 1020
	src.mu.Unlock()
	w.pass()

	if len(vm.pendingBridges) != 1 {
		t.Fatalf("the same lock queued %d requests", len(vm.pendingBridges))
	}
}

// A chain read stays behind the head so a lock a reorg takes back never becomes
// a request, and one pass is bounded so a long backlog is asked for in pieces.
func TestWatchStaysBehindTheHeadAndBoundsAPass(t *testing.T) {
	src := &fakeSource{head: 100_000}
	vm := watchingVM(src)
	w := newTestWatcher(vm)
	w.cursor[96368] = 0

	w.pass()

	if len(src.asked) != 1 {
		t.Fatalf("asked %d times in one pass", len(src.asked))
	}
	from, to := src.asked[0][0], src.asked[0][1]
	if to-from+1 > watchSpan {
		t.Fatalf("one pass asked for %d blocks, more than the %d bound", to-from+1, watchSpan)
	}
	if to > src.head-watchLag {
		t.Fatalf("read to block %d, within %d of the head %d", to, watchLag, src.head)
	}
}

// A chain that cannot be reached is left for the next pass with its cursor
// where it was, so an endpoint having a bad minute does not skip its blocks.
func TestWatchDoesNotAdvancePastAChainItCannotRead(t *testing.T) {
	src := &fakeSource{head: 1000}
	vm := watchingVM(src)
	w := newTestWatcher(vm)
	w.pass()
	settled := w.cursor[96368]

	src.mu.Lock()
	src.head = 2000
	src.headErr = errors.New("endpoint down")
	src.mu.Unlock()
	w.pass()

	if w.cursor[96368] != settled {
		t.Fatalf("cursor moved to %d while the chain was unreadable, skipping its blocks", w.cursor[96368])
	}
}

// TestALockBecomesABlock is the whole path in one test: a gateway locks value
// on the source chain, the watcher reads it, consensus is told there is work,
// and the block that gets built carries exactly that transfer.
//
// Before the watcher existed nothing wrote to the pending queue outside of
// tests, so BuildBlock answered "no pending bridge requests" forever and B could
// not leave genesis however much was bridged.
func TestALockBecomesABlock(t *testing.T) {
	vm, _ := vmWithPending(t, 0)
	vm.evmByChainID = map[uint32]ChainClient{96368: nil}

	src := &fakeSource{head: 1000}
	vm.evmByChainID[96368] = src
	w := newTestWatcher(vm)
	w.pass() // take bearings

	locked := transferAt(11)
	src.mu.Lock()
	src.head = 1010
	src.locks = map[uint64][]lock{995: {{Transfer: locked, TxID: ids.ID{0xCD}}}}
	src.mu.Unlock()
	w.pass()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := vm.WaitForEvent(ctx); err != nil {
		t.Fatalf("consensus was never told there was work: %v", err)
	}

	blk, err := vm.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("building a block from an observed lock: %v", err)
	}
	built, ok := blk.(*Block)
	if !ok {
		t.Fatalf("BuildBlock returned %T", blk)
	}
	if len(built.BridgeRequests) != 1 {
		t.Fatalf("the block carries %d requests, want the one that was locked", len(built.BridgeRequests))
	}
	carried := built.BridgeRequests[0]
	if carried.ID != ids.ID(locked.Digest()) {
		t.Fatalf("the block carries %v, not the locked transfer %v", carried.ID, ids.ID(locked.Digest()))
	}
	if carried.Nonce != 11 || carried.SrcChainID != 96368 || carried.DstChainID != 200201 {
		t.Fatalf("the block carries a different transfer: %+v", carried)
	}
}

// TestHealthSaysWhatItCannotDo. HealthCheck answered healthy whatever the state
// was, which routes traffic at a node that cannot bridge and tells an operator
// nothing about why. Releasing needs a threshold key to attest with and a chain
// to broadcast to.
func TestHealthSaysWhatItCannotDo(t *testing.T) {
	// A node with no chains wired is not a relayer. That is a configuration,
	// not a fault, and calling it unhealthy would take validators that were
	// never meant to relay out of rotation.
	plain := &VM{log: log.NewNoOpLogger(), pendingBridges: make(map[ids.ID]*BridgeRequest)}
	res, err := plain.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	if !res.Healthy {
		t.Fatalf("a validator that relays nothing reported unhealthy: %q", res.Details["status"])
	}

	// A node that IS configured to relay but cannot attest is a different
	// matter: answering healthy routes transfers at a node that cannot carry
	// them.
	relayer := &VM{
		log:            log.NewNoOpLogger(),
		pendingBridges: make(map[ids.ID]*BridgeRequest),
		evmByChainID:   map[uint32]ChainClient{96368: &fakeSource{}},
	}
	res, err = relayer.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	if res.Healthy {
		t.Fatal("a relayer with no threshold signing key reported healthy")
	}
	if res.Details["status"] != "no threshold signing key" {
		t.Fatalf("health does not say what is missing: %q", res.Details["status"])
	}
	if res.Details["chains"] != "1" {
		t.Fatalf("health does not say how many chains it relays: %q", res.Details["chains"])
	}
}

// The endpoint and the node's own check must not disagree about the same node.
func TestHealthEndpointAgreesWithTheNodeCheck(t *testing.T) {
	vm := &VM{
		log:            log.NewNoOpLogger(),
		pendingBridges: make(map[ids.ID]*BridgeRequest),
		evmByChainID:   map[uint32]ChainClient{96368: &fakeSource{}},
	}

	res, err := vm.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	var reply HealthReply
	if err := (&Service{vm: vm}).Health(nil, &HealthArgs{}, &reply); err != nil {
		t.Fatalf("health rpc: %v", err)
	}
	if reply.Ready != res.Healthy || reply.Status != res.Details["status"] {
		t.Fatalf("the endpoint says %q/%v and the node says %q/%v",
			reply.Status, reply.Ready, res.Details["status"], res.Healthy)
	}
}

// The bridge's API is the JSON-RPC service; the canned handlers that used to
// stand in front of it answered fiction.
func TestTheServedAPIIsTheRealOne(t *testing.T) {
	vm := &VM{log: log.NewNoOpLogger()}
	handlers, err := vm.CreateHandlers(context.Background())
	if err != nil {
		t.Fatalf("create handlers: %v", err)
	}
	if _, ok := handlers["/rpc"]; !ok {
		t.Fatalf("the bridge API is not served; handlers are %v", handlers)
	}
	for _, canned := range []string{"/status", "/validators", "/bridge"} {
		if _, ok := handlers[canned]; ok {
			t.Errorf("%s is served again, and it answers the same thing whatever the state", canned)
		}
	}
}
