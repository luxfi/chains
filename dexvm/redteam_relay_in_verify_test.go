// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build redteam

// redteam_relay_in_verify_test.go — RED TEAM proof for the HEADLINE finding:
// "Network RPC (clob_submit) executed per-validator inside block processing —
// per-validator fills split consensus."
//
// THE FINDING (verbatim core): a VM whose block output must be a pure function of
// (height, carried timestamp, tx bytes) CANNOT fetch consensus-relevant data
// per-validator. clob_submit is STATE-MUTATING on the d-chain AND its returned
// fills depend on WHEN the call lands (the book moves between calls). If each
// validator issues its own clob_submit while processing the block, each receives
// independently-timed fills => different settlement export => different StateRoot
// => the network cannot agree. "Fills must be carried INTO the block ... and
// verified from bytes, not fetched."
//
// These tests model that EXACTLY: a single submit block is processed+accepted on
// TWO validators against a matcher that returns DIFFERENT fills per call (the
// book moved between their independent relays). The consensus requirement is that
// both validators derive the IDENTICAL StateRoot and the IDENTICAL exported value
// from the same block bytes. They FAIL against any design that relays per
// validator (whether in Verify or at Accept) and PASS only once the fills are
// carried in the block and settled purely from those carried bytes.

package dexvm

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/vm"
	dexatomic "github.com/luxfi/vm/chains/atomic"
	"github.com/luxfi/warp"

	"github.com/luxfi/chains/dexvm/config"
)

// movingBookMatcher is a fake d-chain that returns a DIFFERENT fill on each
// clob_submit call — the literal "the book moves between calls" condition. The
// FIRST validator to relay sees perCall[0]; the second sees perCall[1]; etc. It
// is the ground truth for "the matcher is consensus-relevant per-call state".
type movingBookMatcher struct {
	mu      sync.Mutex
	calls   int64
	perCall [][]Fill
}

func (m *movingBookMatcher) Call(_ context.Context, method string, _ []byte) ([]byte, error) {
	if method != ZAPMethodSubmit {
		ack := make([]byte, 17)
		binary.BigEndian.PutUint64(ack[0:8], 1)
		return ack, nil
	}
	i := atomic.AddInt64(&m.calls, 1) - 1
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := int(i)
	if idx >= len(m.perCall) {
		idx = len(m.perCall) - 1
	}
	return encodeFillsWire(m.perCall[idx]), nil
}

func (m *movingBookMatcher) Close() error { return nil }

// newValidatorVM builds a fresh proxy VM (one "validator") wired to the supplied
// zapConn matcher and REAL two-chain shared memory, with a pinned C-Chain id so
// the settlement export destination is identical across validators. It mirrors
// the conservation harness init but injects an arbitrary matcher and a fixed
// destination chain — the two degrees of freedom this finding needs.
func newValidatorVM(t *testing.T, conn zapConn, cChainID ids.ID) (*VM, dexatomic.SharedMemory, ids.ID) {
	t.Helper()
	logger := log.NewNoOpLogger()

	baseDB := memdb.New()
	m := dexatomic.NewMemory(prefixdb.New([]byte{0}, baseDB))
	proxyChain := ids.GenerateTestID()
	proxySM := m.NewSharedMemory(proxyChain)
	cChainSM := m.NewSharedMemory(cChainID)

	prev := zapDialer
	zapDialer = func(_ context.Context, _ string) (zapConn, error) { return conn, nil }
	t.Cleanup(func() { zapDialer = prev })

	rt := &runtime.Runtime{
		ChainID:      proxyChain,
		CChainID:     cChainID,
		NetworkID:    96369,
		Log:          logger,
		SharedMemory: proxySM,
	}
	v := &VM{}
	v.Config = config.DefaultConfig()
	v.Config.DexZapEndpoint = "127.0.0.1:0"
	if err := v.Initialize(context.Background(), vm.Init{
		Runtime:  rt,
		DB:       prefixdb.New([]byte{1}, baseDB),
		ToEngine: make(chan vm.Message, 8),
		Sender:   warp.FakeSender{},
		Log:      logger,
	}); err != nil {
		t.Fatalf("init validator vm: %v", err)
	}
	v.bootstrapped = true
	return v, cChainSM, proxyChain
}

// exportedToTaker sums the value the proxy committed to C-Chain shared memory for
// the taker trait — the proceeds the C-Chain can claim post-accept. Each element
// value is owner(20)|asset(32)|amount(8).
func exportedToTaker(t *testing.T, cChainSM dexatomic.SharedMemory, proxyChain ids.ID, taker ids.ShortID) uint64 {
	t.Helper()
	vals, _, _, err := cChainSM.Indexed(proxyChain, [][]byte{taker[:]}, nil, nil, 100)
	if err != nil {
		t.Fatalf("indexed taker proceeds: %v", err)
	}
	var total uint64
	for _, v := range vals {
		if len(v) >= exportedOutputSize {
			total += binary.BigEndian.Uint64(v[53:61])
		}
	}
	return total
}

// TestRED_PerValidatorRelay_SplitsConsensus is the headline proof. ONE submit
// block (byte-identical on every node) is processed and accepted on TWO
// independent validators. The d-chain's book MOVED between their two independent
// relays, so validator A's relay returns 1000 base filled and validator B's
// returns 600 base filled. A consensus VM MUST derive the same StateRoot and the
// same exported proceeds from the same block bytes — otherwise the two validators
// disagree on the post-accept shared-memory commit and the chain forks.
//
// Under per-validator relay (the relay frame is sent during block processing on
// each node — Verify OR Accept), this FAILS: the two validators export different
// amounts and commit different roots. The fix carries the matcher's fills INTO
// the block at build time (one relay, by the proposer) and settles purely from
// those carried bytes, so both validators reproduce byte-identical output. The
// matcher's per-call counter then proves the d-chain was hit AT MOST ONCE for the
// whole network.
func TestRED_PerValidatorRelay_SplitsConsensus(t *testing.T) {
	ctx := context.Background()
	const height = uint64(1)
	blockTime := time.Unix(1_700_000_000, 0)

	// The book moves: first relay fills 1000 base @1; a later relay fills only 600.
	matcher := &movingBookMatcher{perCall: [][]Fill{
		{{Price: 1, Size: 1000, Side: 0}},
		{{Price: 1, Size: 600, Side: 0}},
	}}

	// Fixed ids so the block is byte-identical across both validators — the ONLY
	// variable is which fills each validator's own relay happens to observe.
	taker := fixedShortID("per-validator-taker")
	asset := idFromByte(0xa1)
	srcUTXOID := idFromByte(0x1a)
	sharedCChain := idFromByte(0xce)

	// The byte-identical block both validators process: import locks 1000, then a
	// clob_submit relay bound to that escrow.
	importTx := newImportTxBytes(t, taker, sharedCChain, srcUTXOID, asset, 1000)
	relayTx := newRelayTxBytes(t, taker, srcUTXOID, clobSubmitPayload(asset, 1000))
	blockTxs := [][]byte{importTx, relayTx}

	runValidator := func(label string) (root ids.ID, exported uint64) {
		v, cChainSM, proxyChain := newValidatorVM(t, matcher, sharedCChain)
		// Seed the C-Chain -> proxy export the import consumes (byte-identical id).
		seedFixedUTXO(t, cChainSM, proxyChain, taker, asset, srcUTXOID, 1000)
		res, err := v.ProcessBlock(ctx, height, blockTime, blockTxs)
		if err != nil {
			t.Fatalf("%s ProcessBlock: %v", label, err)
		}
		if err := v.acceptBlock(ctx, res); err != nil {
			t.Fatalf("%s acceptBlock: %v", label, err)
		}
		return res.StateRoot, exportedToTaker(t, cChainSM, proxyChain, taker)
	}

	rootA, expA := runValidator("validator A")
	rootB, expB := runValidator("validator B")

	t.Logf("validator A: exported=%d root=%s", expA, rootA.Hex()[:16])
	t.Logf("validator B: exported=%d root=%s", expB, rootB.Hex()[:16])
	t.Logf("d-chain clob_submit calls across BOTH validators: %d", atomic.LoadInt64(&matcher.calls))

	if expA != expB {
		t.Fatalf("CONSENSUS SPLIT (value): same block bytes, but validator A exported %d and "+
			"validator B exported %d — each settled its OWN per-validator clob_submit fills "+
			"(the book moved between their relays). The post-accept shared-memory commit "+
			"diverges; the chain forks. Fills must be carried in the block and settled from "+
			"bytes, not fetched per validator.", expA, expB)
	}
	if rootA != rootB {
		t.Fatalf("CONSENSUS SPLIT (root): same block bytes => different StateRoot (A=%s B=%s). "+
			"The block output is NOT a pure function of (height, carried time, tx bytes) because "+
			"each validator fetched its own fills.", rootA.Hex()[:16], rootB.Hex()[:16])
	}

	// Once fills are carried in the block, the matcher is hit AT MOST ONCE for the
	// whole network (the proposer's build-time relay), never once per validator.
	if c := atomic.LoadInt64(&matcher.calls); c > 1 {
		t.Fatalf("N-FOLD SUBMISSION: the state-mutating clob_submit hit the d-chain %d times for "+
			"ONE order — once per validator. The same order matched %d times against resting "+
			"makers on the source-of-truth matcher. It must be relayed exactly once.", c, c)
	}
}

// TestRED_VerifyDoesNotRelay pins the purity of the VERIFY path directly: running
// ProcessBlock (Verify) for a submit must perform ZERO d-chain calls. Verify runs
// on every validator and must be a pure function of bytes; any relay there is the
// finding. (Accept is also per-validator, so the fix forbids the relay there too;
// the split test above covers accept — this isolates the Verify leg.)
func TestRED_VerifyDoesNotRelay(t *testing.T) {
	ctx := context.Background()
	matcher := &movingBookMatcher{perCall: [][]Fill{{{Price: 1, Size: 1000, Side: 0}}}}

	taker := fixedShortID("verify-purity-taker")
	asset := idFromByte(0xb2)
	srcUTXOID := idFromByte(0x2b)
	cChain := idFromByte(0xcf)

	v, cChainSM, proxyChain := newValidatorVM(t, matcher, cChain)
	seedFixedUTXO(t, cChainSM, proxyChain, taker, asset, srcUTXOID, 1000)
	importTx := newImportTxBytes(t, taker, cChain, srcUTXOID, asset, 1000)
	relayTx := newRelayTxBytes(t, taker, srcUTXOID, clobSubmitPayload(asset, 1000))

	if _, err := v.ProcessBlock(ctx, 1, time.Unix(1, 0), [][]byte{importTx, relayTx}); err != nil {
		t.Fatalf("ProcessBlock: %v", err)
	}
	if c := atomic.LoadInt64(&matcher.calls); c != 0 {
		t.Fatalf("VERIFY IS IMPURE: ProcessBlock (Verify) issued %d d-chain clob_submit call(s). "+
			"Verify runs on every validator and must be a pure function of (height, carried time, "+
			"tx bytes); it may NOT fetch consensus-relevant data. (calls=%d)", c, c)
	}
}

// fixedShortID returns a deterministic 20-byte address from a label so two
// validators build byte-identical blocks (ids.GenerateTestShortID is random).
func fixedShortID(label string) ids.ShortID {
	var a ids.ShortID
	copy(a[:], label)
	return a
}

// idFromByte returns a deterministic 32-byte id filled from one byte — a stable
// stand-in for ids.GenerateTestID where cross-validator byte-identity matters.
func idFromByte(b byte) ids.ID {
	var id ids.ID
	for i := range id {
		id[i] = b
	}
	return id
}
