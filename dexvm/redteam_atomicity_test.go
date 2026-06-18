// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build redteam

// redteam_atomicity_test.go — RED TEAM adversarial proofs that the proxy<->d-chain
// boundary is NOT atomic. These tests EXERCISE THE FAILURE PATHS the happy-path
// conservation_test.go never touches: verify-then-reject, re-verify (reorg/
// restart), and fractional-fill truncation.
//
// They are written to FAIL against the current code to demonstrate the bugs.
// A counter on the fake matcher records how many times the d-chain was actually
// hit, which is the ground truth of "did value move on the d-chain".

package dexvm

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/vm"
	"github.com/luxfi/vm/chains/atomic"
	"github.com/luxfi/warp"

	"github.com/luxfi/chains/dexvm/config"
	"github.com/luxfi/chains/dexvm/txs"
)

// countingMatcher is a fake d-chain matcher that COUNTS how many times each
// clob_* method was invoked — the ground truth for "how many real matches /
// placements happened on the d-chain". Each clob_submit returns the canned fills.
type countingMatcher struct {
	mu      sync.Mutex
	fills   []Fill
	submits int
	places  int
	cancels int
}

func (m *countingMatcher) Call(_ context.Context, method string, _ []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch method {
	case ZAPMethodSubmit:
		m.submits++
		return encodeFillsWire(m.fills), nil
	case ZAPMethodPlace:
		m.places++
	case ZAPMethodCancel:
		m.cancels++
	}
	ack := make([]byte, 17)
	binary.BigEndian.PutUint64(ack[0:8], 1)
	return ack, nil
}

func (m *countingMatcher) Close() error { return nil }

func (m *countingMatcher) counts() (int, int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.submits, m.places, m.cancels
}

// newCountingHarness wires a ChainVM (the real block-lifecycle wrapper) with a
// counting matcher and real two-chain shared memory, so we can drive
// Verify/Accept/Reject exactly as consensus does.
func newCountingHarness(t *testing.T, fills []Fill) (*ChainVM, *countingMatcher, atomic.SharedMemory, ids.ID, ids.ID) {
	t.Helper()
	logger := log.NewNoOpLogger()

	baseDB := memdb.New()
	memoryDB := prefixdb.New([]byte{0}, baseDB)
	m := atomic.NewMemory(memoryDB)

	proxyChain := ids.GenerateTestID()
	cChain := ids.GenerateTestID()
	proxySM := m.NewSharedMemory(proxyChain)
	cChainSM := m.NewSharedMemory(cChain)

	matcher := &countingMatcher{fills: fills}
	prev := zapDialer
	zapDialer = func(_ context.Context, _ string) (zapConn, error) { return matcher, nil }
	t.Cleanup(func() { zapDialer = prev })

	rt := &runtime.Runtime{
		ChainID:      proxyChain,
		CChainID:     cChain,
		NetworkID:    96369,
		Log:          logger,
		SharedMemory: proxySM,
	}

	cvm := NewChainVM(logger)
	cvm.inner.Config = config.DefaultConfig()
	cvm.inner.Config.DexZapEndpoint = "127.0.0.1:0"
	if err := cvm.Initialize(context.Background(), vm.Init{
		Runtime:  rt,
		DB:       prefixdb.New([]byte{1}, baseDB),
		ToEngine: make(chan vm.Message, 8),
		Sender:   warp.FakeSender{},
		Log:      logger,
	}); err != nil {
		t.Fatalf("init chain vm: %v", err)
	}
	cvm.inner.bootstrapped = true
	return cvm, matcher, cChainSM, proxyChain, cChain
}

// seedExportedUTXO makes the C-Chain export `amount` of `asset` to the proxy so
// the proxy's import has something to consume. Returns the source UTXO id.
func seedExportedUTXO(t *testing.T, cChainSM atomic.SharedMemory, proxyChain ids.ID, owner ids.ShortID, asset ids.ID, amount uint64) ids.ID {
	t.Helper()
	srcUTXOID := deriveUTXOID(ids.GenerateTestID(), 0)
	val := encodeExportedOutput(txs.AtomicOutput{Owner: owner, Asset: asset, Amount: amount})
	if err := cChainSM.Apply(map[ids.ID]*atomic.Requests{
		proxyChain: {PutRequests: []*atomic.Element{{
			Key:    srcUTXOID[:],
			Value:  val,
			Traits: [][]byte{owner[:]},
		}}},
	}); err != nil {
		t.Fatalf("seed exported UTXO: %v", err)
	}
	return srcUTXOID
}

// makeBlock builds a *Block directly (bypassing BuildBlock's now() timestamp) so
// the test controls (height, time) deterministically.
func makeBlock(cvm *ChainVM, parentID ids.ID, height uint64, ts time.Time, txBytes [][]byte) *Block {
	b := &Block{
		vm:        cvm,
		id:        deriveBlockHash(height, ts), // any stable id is fine for the test
		parentID:  parentID,
		height:    height,
		timestamp: ts,
		txs:       txBytes,
		status:    StatusUnknown,
	}
	cvm.blocks[b.id] = b
	return b
}

// TestRED_VerifyThenReject_StrandsDChainFill is the regression proof that the
// VALIDATOR path (Verify/Accept) is relay-free and that a rejected block moves no
// C-side value. Under the carried-fills model (RED #9) the d-chain relay happens
// exactly ONCE, at the PROPOSER's build; Verify and Accept never relay on ANY node.
// It asserts:
//
//   - A non-proposer block (no carried fills) Verified then Rejected: NEVER hits
//     the d-chain at Verify/Accept, and Reject moves value on NEITHER side (no
//     C-credit, the consumed UTXO is rolled back) — a plain db.Abort.
//   - The PROPOSER build+accept (positive control) moves value on both sides,
//     atomically: exactly one d-chain submit AT BUILD, the C-Chain credited the
//     filled proceeds, and the source UTXO consumed — all-or-nothing.
//
// NOTE on the build-relay trust surface (documented in carried_fills.go): a block
// the proposer BUILT (relayed) but that later loses the poll DOES strand a d-chain
// match. That is the bounded, interim proposer-trust cost of carried-fills
// determinism (single-operator venue today; trustless via the reserved fill-sig).
// This test exercises the validator path (makeBlock, no build), which never relays,
// so its reject strands nothing.
func TestRED_VerifyThenReject_StrandsDChainFill(t *testing.T) {
	fills := []Fill{{Price: 1, Size: 1000, Side: 0}} // taker BUY, receives 1000 base
	cvm, matcher, cChainSM, proxyChain, _ := newCountingHarness(t, fills)
	ctx := context.Background()

	taker := ids.GenerateTestShortID()
	asset := ids.GenerateTestID()
	srcUTXOID := seedExportedUTXO(t, cChainSM, proxyChain, taker, asset, 1000)

	importTx := newImportTxBytes(t, taker, cvm.inner.cChainID(), srcUTXOID, asset, 1000)
	relayTx := newRelayTxBytes(t, taker, srcUTXOID, clobSubmitPayload(asset, 1000))

	// A VALIDATOR's view of a block (makeBlock: no carried fills, not built here).
	// Verify+Reject must never relay and must move nothing.
	blk := makeBlock(cvm, cvm.lastAcceptedID, 1, time.Unix(1, 0), [][]byte{importTx, relayTx})

	if err := blk.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if submits, _, _ := matcher.counts(); submits != 0 {
		t.Fatalf("ATOMICITY REGRESSION: Verify hit the d-chain %d times — Verify runs on "+
			"every validator and must NEVER relay (the proposer relays once at build).", submits)
	}

	// Consensus REJECTS the block (a conflicting block won the poll). A correct
	// Reject is a plain db.Abort() with NOTHING to compensate on the C-side.
	if err := blk.Reject(ctx); err != nil {
		t.Fatalf("reject: %v", err)
	}

	submits, _, _ := matcher.counts()
	credited := creditedTo(t, cChainSM, proxyChain, taker)
	consumed, _ := cvm.inner.state.IsConsumed(srcUTXOID)
	t.Logf("AFTER VERIFY+REJECT (validator path): d-chain submits=%d  C-Chain credited=%d  utxo consumed=%v",
		submits, credited, consumed)

	if submits != 0 || credited != 0 || consumed {
		t.Fatalf("ATOMICITY VIOLATED on reject: submits=%d credited=%d consumed=%v — a rejected "+
			"block on the validator path must move value on NEITHER chain (no relay at "+
			"Verify/Accept, no C-Chain credit, source UTXO rolled back).", submits, credited, consumed)
	}

	// POSITIVE CONTROL: the PROPOSER builds (relays ONCE at build, carries fills)
	// and accepts. Value MUST move on both sides atomically, with exactly one
	// d-chain submit performed at build.
	cvm.inner.clock.Set(time.Unix(1, 0))
	cvm.pendingTxs = [][]byte{importTx, relayTx}
	built, err := cvm.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock (proposer): %v", err)
	}
	if err := cvm.SetPreference(ctx, built.ID()); err != nil {
		t.Fatalf("SetPreference: %v", err)
	}
	if err := built.Verify(ctx); err != nil {
		t.Fatalf("verify built: %v", err)
	}
	if err := built.Accept(ctx); err != nil {
		t.Fatalf("accept built: %v", err)
	}
	submits, _, _ = matcher.counts()
	credited = creditedTo(t, cChainSM, proxyChain, taker)
	consumed, _ = cvm.inner.state.IsConsumed(srcUTXOID)
	t.Logf("AFTER PROPOSER BUILD+ACCEPT: d-chain submits=%d  C-Chain credited=%d  utxo consumed=%v",
		submits, credited, consumed)
	if submits != 1 || credited != 1000 || !consumed {
		t.Fatalf("ATOMIC SETTLE BROKEN: submits=%d (want 1) credited=%d (want 1000) "+
			"consumed=%v (want true) — the proposer must relay once AT BUILD, and accept must "+
			"credit the C-Chain AND consume the source UTXO together.", submits, credited, consumed)
	}
}

// creditedTo sums the value the proxy exported to `owner` on the C-Chain, read
// through the C-Chain's Indexed view on the owner trait. Each element value is
// owner(20)|asset(32)|amount(8).
func creditedTo(t *testing.T, cChainSM atomic.SharedMemory, proxyChain ids.ID, owner ids.ShortID) uint64 {
	t.Helper()
	vals, _, _, err := cChainSM.Indexed(proxyChain, [][]byte{owner[:]}, nil, nil, 100)
	if err != nil {
		t.Fatalf("indexed: %v", err)
	}
	var credited uint64
	for _, v := range vals {
		if len(v) >= 60 {
			credited += binary.BigEndian.Uint64(v[52:60])
		}
	}
	return credited
}

// TestRED_ReVerify_DoublesPlaceOrder proves place-order relays have NO
// idempotency guard: re-verifying the same block (restart/reorg replay) re-sends
// clob_place, duplicating the resting maker order on the d-chain.
func TestRED_ReVerify_DoublesPlaceOrder(t *testing.T) {
	cvm, matcher, _, _, _ := newCountingHarness(t, nil)
	ctx := context.Background()

	maker := ids.GenerateTestShortID()
	pid := ids.GenerateTestID()
	var poolID [32]byte
	copy(poolID[:], pid[:])
	placeTx := txs.NewPlaceOrderTx(maker, 0, poolID, 1 /*sell*/, 100, 5).Bytes()

	blk := makeBlock(cvm, cvm.lastAcceptedID, 1, time.Unix(1, 0), [][]byte{placeTx})

	// First Verify (normal). Then a SECOND Verify simulating restart-before-accept
	// or a reorg that re-processes the same height.
	if err := blk.Verify(ctx); err != nil {
		t.Fatalf("verify #1: %v", err)
	}
	if err := blk.Verify(ctx); err != nil {
		t.Fatalf("verify #2: %v", err)
	}

	_, places, _ := matcher.counts()
	t.Logf("clob_place sent to d-chain after 2 verifies: %d", places)
	if places > 1 {
		t.Fatalf("ORDER DUPLICATION: a single place-order tx, re-verified, sent %d "+
			"clob_place frames to the d-chain — the maker now has %dx the liquidity "+
			"resting they intended (no receipt/idempotency guard on executePlaceOrder).", places, places)
	}
}

// TestRED_FractionalFill_NeverMints is the fractional-fill conservation proof. A
// CLOB fill crosses the wire as float64, but on-chain value is integer asset
// units, so a sub-integer proceeds amount cannot be credited without minting a
// fractional unit. The CONSERVATION-SAFE rule (the law: the proxy NEVER mints)
// is to round a RECEIVED quantity DOWN (quantToCredit) and a SPENT quantity UP
// (quantToCharge). Worst case the taker is under-credited by <1 unit; that
// sub-unit is conserved on the d-chain side (the maker's leg), never fabricated
// out of the proxy — the opposite of a mint.
//
// This pins the resolved behavior with an ESCROW present so both legs are
// auditable: a taker BUY locks 10 quote and fills 4.5 base @ price 2 (a fill
// stream with a fractional base AND a fractional notional). The quote spent
// ceils to 9, base proceeds floor to 4; value_out (4 base + 1 quote refund) must
// never exceed value_in, and the locked-quote ledger must balance exactly.
func TestRED_FractionalFill_NeverMints(t *testing.T) {
	// BUY: receives base = sum(size) = 4.5 -> floor 4. spends quote =
	// sum(price*size) = 9.0 -> ceil 9. locked 10 quote -> refund 10-9 = 1.
	fills := []Fill{{Price: 2, Size: 4.5, Side: 0}}
	cvm, _, _, _, _ := newCountingHarness(t, fills)

	taker := ids.GenerateTestShortID()
	collateralRef := ids.GenerateTestID()
	lockedAsset := ids.GenerateTestID()
	const lockedQuote uint64 = 10
	if err := cvm.inner.state.PutEscrow(collateralRef, lockedAsset, lockedQuote); err != nil {
		t.Fatalf("seed escrow: %v", err)
	}

	ar := newAtomicRequests()
	if err := cvm.inner.settleFromFills(taker, collateralRef, fills, ids.GenerateTestID(), 0, ar); err != nil {
		t.Fatalf("settleFromFills: %v", err)
	}

	// Split the exported value by asset: base proceeds vs the locked-quote refund.
	var base, refund uint64
	for _, reqs := range ar.reqs {
		for _, e := range reqs.PutRequests {
			if len(e.Value) < 60 {
				continue
			}
			var a ids.ID
			copy(a[:], e.Value[20:52])
			amt := binary.BigEndian.Uint64(e.Value[52:60])
			if a == lockedAsset {
				refund += amt
			} else {
				base += amt
			}
		}
	}
	t.Logf("fractional fill: base proceeds=%d (floor 4.5) quote refund=%d (locked 10 - ceil(9.0))", base, refund)

	// Proceeds round DOWN: never credit more base than the integer floor.
	if base > 4 {
		t.Fatalf("MINT: credited %d base for a 4.5 fill — proceeds must floor to 4, never round up.", base)
	}
	// Spent quote ceils to 9, so refund is exactly 1 — never inflated (that would
	// be the escrow-truncation mint), never negative.
	if refund != lockedQuote-9 {
		t.Fatalf("CONSERVATION VIOLATED: quote refund=%d, want %d (locked 10 - spent ceil(9.0)=9).", refund, lockedQuote-9)
	}
	// No-mint over the locked-quote ledger: spent(9) + refund(1) == locked(10).
	if spent := lockedQuote - refund; spent != 9 {
		t.Fatalf("NO-MINT VIOLATED: spent+refund != locked (spent=%d refund=%d locked=%d).", spent, refund, lockedQuote)
	}
}

// TestRED_OverflowFill_SaturatesUint64 is the float64->uint64 SATURATION proof —
// the headline of the finding: a fill amount that exceeds what a uint64 can hold
// must be REFUSED at the asset boundary, never silently truncated/saturated into
// a valid-looking on-chain amount.
//
// Go's float64->uint64 conversion does NOT wrap or error on overflow: uint64(19e18)
// SATURATES to 18446744073709551615 (uint64 max). uint64 max is ~1.845e19 = only
// ~18.44 tokens at 18 decimals, so a single 19-token fill, cast naively, would be
// summed into the exported amount as a plausible ~18.44-token value — value minted
// out of thin air, and (because the export amount is a fixed 8-byte uint64 with no
// widening downstream — atomic.go encodeExportedOutput PutUint64(v[52:60])) there
// is nothing downstream to catch it.
//
// The closed behavior: settlement aggregates fills as exact float64 ONCE, then
// quantToCredit/quantToCharge reject any aggregate > maxSettlementUnit (the largest
// float64 strictly below 2^64) BEFORE the uint64() cast. So an oversized fill makes
// settleFromFills ERROR and export NOTHING — refusal, never a saturated mint.
//
// Two legs are exercised, since the finding's PoC inflates BOTH the proceeds cast
// (uint64(size)) and the spent/notional cast (uint64(price*size)):
//   - PROCEEDS overflow: a taker BUY whose base size sums to 19e18 (> uint64 max).
//   - NOTIONAL overflow: a taker BUY whose quote notional (price*size) overflows,
//     which would understate spent => inflate the escrow refund (the mint vector).
func TestRED_OverflowFill_SaturatesUint64(t *testing.T) {
	// Ground truth the guard must beat: a naive cast saturates instead of erroring.
	// overSize is a runtime float64 (NOT an untyped constant) so the uint64() cast
	// is the runtime saturating conversion under test — a constant conversion of an
	// out-of-range value is a compile error, which is not the behavior being probed.
	var overSize float64 = 19e18 // 19 tokens @ 18 decimals; > uint64 max (~1.845e19)
	if uint64(overSize) != ^uint64(0) {
		t.Fatalf("precondition: expected uint64(%v) to saturate to uint64 max, got %d",
			overSize, uint64(overSize))
	}

	auditCredited := func(ar *atomicRequests) uint64 {
		var total uint64
		for _, reqs := range ar.reqs {
			for _, e := range reqs.PutRequests {
				if len(e.Value) >= 60 {
					total += binary.BigEndian.Uint64(e.Value[52:60])
				}
			}
		}
		return total
	}

	// --- Leg 1: PROCEEDS overflow (uint64(size) saturation) ---------------------
	// taker BUY receives base = sum(size) = 19e18 -> overflows; settle must refuse.
	t.Run("proceeds", func(t *testing.T) {
		fills := []Fill{{Price: 1, Size: overSize, Side: 0}}
		cvm, _, _, _, _ := newCountingHarness(t, fills)

		taker := ids.GenerateTestShortID()
		// No escrow: isolate the proceeds cast (refund leg absent).
		ar := newAtomicRequests()
		err := cvm.inner.settleFromFills(taker, ids.GenerateTestID(), fills, ids.GenerateTestID(), 0, ar)
		credited := auditCredited(ar)
		t.Logf("proceeds overflow: settle err=%v  exported=%d (naive cast would saturate to %d)", err, credited, ^uint64(0))

		if err == nil {
			t.Fatalf("SATURATION MINT: settle accepted a 19e18 base fill (> uint64 max); it must be "+
				"refused at the asset boundary, not cast (which saturates to %d).", ^uint64(0))
		}
		if credited != 0 {
			t.Fatalf("SATURATION MINT: refused settle still exported %d — refusal must export nothing.", credited)
		}
	})

	// --- Leg 2: NOTIONAL overflow (uint64(price*size) saturation) ---------------
	// taker BUY spends quote = sum(price*size); make the NOTIONAL overflow while
	// the base size stays in range, so the only overflow is the spent/refund leg.
	// A saturated-but-floored spent would UNDERstate spend => inflate refund =
	// locked - spent => quote minted out of the proxy's own escrow.
	t.Run("notional_refund", func(t *testing.T) {
		// size 1e10 (in range), price 1e10 -> notional 1e20 > uint64 max.
		fills := []Fill{{Price: 1e10, Size: 1e10, Side: 0}}
		cvm, _, _, _, _ := newCountingHarness(t, fills)

		taker := ids.GenerateTestShortID()
		collateralRef := ids.GenerateTestID()
		lockedAsset := ids.GenerateTestID()
		const lockedQuote uint64 = 1000 // tiny escrow; an inflated refund would mint
		if err := cvm.inner.state.PutEscrow(collateralRef, lockedAsset, lockedQuote); err != nil {
			t.Fatalf("seed escrow: %v", err)
		}

		ar := newAtomicRequests()
		err := cvm.inner.settleFromFills(taker, collateralRef, fills, ids.GenerateTestID(), 0, ar)
		credited := auditCredited(ar)
		t.Logf("notional overflow: settle err=%v  exported=%d (a saturated/floored spent would inflate the refund)", err, credited)

		if err == nil {
			t.Fatalf("SATURATION MINT: settle accepted a 1e20 quote notional (> uint64 max); the spent " +
				"cast would saturate and inflate refund = locked - spent => minted quote.")
		}
		if credited != 0 {
			t.Fatalf("SATURATION MINT: refused settle still exported %d — refusal must export nothing.", credited)
		}
		// The escrow must NOT have been consumed by a refused settle (so a later,
		// well-formed relay can still legitimately refund it).
		_, _, haveEscrow, eerr := cvm.inner.state.GetEscrow(collateralRef)
		if eerr != nil {
			t.Fatalf("escrow lookup: %v", eerr)
		}
		if !haveEscrow {
			t.Fatalf("SATURATION MINT: refused settle consumed the escrow — a refused settle must leave it intact.")
		}
	})
}

// TestRED_SettlementBoundary_ExactUint64Edge pins the float->uint64 boundary
// CONSTANT (maxSettlementUnit) exactly, so a future edit cannot widen it past the
// representable range and silently reintroduce the saturation mint. maxSettlementUnit
// is the largest float64 strictly below 2^64 (== 2^64 - 2048; 2^64 itself is the
// next representable float64 and is ONE above uint64 max):
//
//   - the largest passing aggregate (maxSettlementUnit) converts IN-RANGE for both
//     a credit (floor) and a charge (ceil);
//   - the next float64 up (2^64) is refused by both — it is exactly one above
//     uint64 max, the value uint64(.) would wrap/saturate on.
func TestRED_SettlementBoundary_ExactUint64Edge(t *testing.T) {
	const u64max = ^uint64(0)

	// maxSettlementUnit must be strictly below 2^64 and cast in-range.
	if maxSettlementUnit >= float64(u64max) {
		// (float64(u64max) rounds to 2^64; the constant must be below it.)
		t.Fatalf("maxSettlementUnit %.0f must be strictly below 2^64", maxSettlementUnit)
	}
	if got, err := quantToCredit(maxSettlementUnit); err != nil {
		t.Fatalf("quantToCredit(maxSettlementUnit) must pass, got err=%v", err)
	} else if uint64(got) > u64max { // tautology on uint64, but documents in-range intent
		t.Fatalf("quantToCredit(maxSettlementUnit)=%d out of uint64 range", got)
	}
	if _, err := quantToCharge(maxSettlementUnit); err != nil {
		t.Fatalf("quantToCharge(maxSettlementUnit) must pass, got err=%v", err)
	}

	// The next representable float64 above the boundary is exactly 2^64 — one above
	// uint64 max — and MUST be refused by both directions.
	over := math.Nextafter(maxSettlementUnit, math.Inf(1))
	if over != float64(u64max)+1 && over != 18446744073709551616.0 {
		t.Logf("note: nextafter(maxSettlementUnit)=%.0f (expected 2^64=18446744073709551616)", over)
	}
	if _, err := quantToCredit(over); err == nil {
		t.Fatalf("OVERFLOW: quantToCredit(%.0f) accepted a value above uint64 max — must refuse.", over)
	}
	if _, err := quantToCharge(over); err == nil {
		t.Fatalf("OVERFLOW: quantToCharge(%.0f) accepted a value above uint64 max — must refuse.", over)
	}

	// +Inf (e.g. a per-fill product that overflowed to +Inf in the aggregate loop)
	// is refused too — the aggregate never reaches the cast.
	if _, err := quantToCredit(math.Inf(1)); err == nil {
		t.Fatalf("OVERFLOW: quantToCredit(+Inf) accepted — must refuse.")
	}
	if _, err := quantToCharge(math.Inf(1)); err == nil {
		t.Fatalf("OVERFLOW: quantToCharge(+Inf) accepted — must refuse.")
	}
}

// TestRED_MixedSideFills_OverCredits is the mixed-side over-credit/mint proof,
// now CLOSED: settleFromFills applies ONE direction (fills[0].Side) to the whole
// aggregate, so summing fills of BOTH sides under that one side mints the
// opposite-side volume. A lying/MITM backend (the threat model DecodeFills
// defends against) returns [BUY 10, SELL 1000]; the old code credited base =
// 10+1000 = 1010 for a taker BUY that legitimately filled only 10.
//
// The fix: a single marketable submit takes exactly ONE side, so a fill stream
// that mixes sides is a lying backend and is REFUSED — the proxy exports nothing
// rather than over-crediting. Refusal is strictly conservation-safe: credited=0,
// never the 1010 mint.
func TestRED_MixedSideFills_OverCredits(t *testing.T) {
	// First fill BUY 10 base, second claims SELL 1000 base — a stream no honest
	// single submit can produce.
	fills := []Fill{
		{Price: 1, Size: 10, Side: 0},
		{Price: 1, Size: 1000, Side: 1},
	}
	cvm, _, _, _, _ := newCountingHarness(t, fills)

	taker := ids.GenerateTestShortID()
	ar := newAtomicRequests()
	err := cvm.inner.settleFromFills(taker, ids.GenerateTestID(), fills, ids.GenerateTestID(), 0, ar)

	var credited uint64
	for _, reqs := range ar.reqs {
		for _, e := range reqs.PutRequests {
			if len(e.Value) >= 60 {
				credited += binary.BigEndian.Uint64(e.Value[52:60])
			}
		}
	}
	t.Logf("mixed-side fills: settle err=%v  credited base=%d (honest BUY-leg total would be 10, mint would be 1010)", err, credited)

	// The mixed-side stream MUST be refused, and refusal must export nothing.
	if err == nil {
		t.Fatalf("OVER-CREDIT/MINT: settle accepted a mixed-side fill stream (credited base=%d); "+
			"a single submit takes one side — the stream must be refused.", credited)
	}
	if credited != 0 {
		t.Fatalf("OVER-CREDIT/MINT: refused settle still exported %d base — refusal must accumulate nothing.", credited)
	}
	_ = math.Float64bits
}

// TestRED_DecodeFills_RejectsInvalidSideByte is the WIRE-BOUNDARY proof for the
// other half of the finding: "DecodeFills validates positivity but NOT side
// consistency." A lying/MITM backend can put ANY byte in the side field. Side is
// a 2-value enum (0=BUY, 1=SELL); a byte outside {0,1} is malformed wire exactly
// like a NaN price. DecodeFills MUST reject it at the boundary so no impossible
// Fill value ever reaches settlement — never silently coerced, never defaulted.
//
// Without the boundary check, a side byte of e.g. 7 slips past DecodeFills and is
// caught downstream only incidentally by settle's consistency check (7 != 0). The
// boundary is the correct, single home for per-fill side validity.
func TestRED_DecodeFills_RejectsInvalidSideByte(t *testing.T) {
	// Two structurally-valid fills; poison the SECOND fill's side byte to 7 — a
	// value no honest matcher emits.
	wire := encodeFillsWire([]Fill{
		{Price: 1, Size: 10, Side: 0},
		{Price: 1, Size: 5, Side: 0},
	})
	// Overwrite the second fill's side byte (offset: 4 count + 1*FillWireSize + 16).
	wire[4+FillWireSize+16] = 7

	fills, err := DecodeFills(wire)
	if err == nil {
		t.Fatalf("WIRE INJECTION: DecodeFills accepted a fill with side byte 7 "+
			"(decoded %d fills) — an out-of-range side is malformed wire and must be "+
			"rejected at the boundary, not coerced into a Fill.", len(fills))
	}
	t.Logf("DecodeFills correctly rejected invalid side byte: %v", err)

	// Positive control: the same wire with a VALID side (1=SELL) decodes cleanly,
	// so the check rejects only the malformed value, not the whole format.
	wire[4+FillWireSize+16] = 1
	if _, err := DecodeFills(wire); err != nil {
		t.Fatalf("FALSE REJECT: DecodeFills rejected a wire with valid sides {0,1}: %v", err)
	}
}

// TestRED_CrashBeforeAccept_DoubleSubmits proves the replay/double-spend window:
// the relay (clob_submit) fires during Verify and the idempotency RECEIPT is
// written only into the versiondb in-memory layer — it is NOT durable until
// Accept calls CommitBatch. A crash between Verify and Accept loses the receipt
// (db.Abort on restart), so re-Verify re-submits the SAME order to the d-chain:
// a SECOND irreversible match. The maker is filled twice; the taker double-pays.
func TestRED_CrashBeforeAccept_DoubleSubmits(t *testing.T) {
	fills := []Fill{{Price: 1, Size: 1000, Side: 0}}
	cvm, matcher, cChainSM, proxyChain, _ := newCountingHarness(t, fills)
	ctx := context.Background()

	taker := ids.GenerateTestShortID()
	asset := ids.GenerateTestID()
	srcUTXOID := seedExportedUTXO(t, cChainSM, proxyChain, taker, asset, 1000)
	importTx := newImportTxBytes(t, taker, cvm.inner.cChainID(), srcUTXOID, asset, 1000)
	relayTx := newRelayTxBytes(t, taker, srcUTXOID, clobSubmitPayload(asset, 1000))

	blk := makeBlock(cvm, cvm.lastAcceptedID, 1, time.Unix(1, 0), [][]byte{importTx, relayTx})

	// Verify fires the relay (submit #1) and writes the receipt to the versiondb
	// in-memory layer.
	if err := blk.Verify(ctx); err != nil {
		t.Fatalf("verify #1: %v", err)
	}
	s1, _, _ := matcher.counts()

	// Receipt visible in the in-memory layer right now?
	_, foundInMem, _ := cvm.inner.state.GetReceipt(deriveBlockHash(1, time.Unix(1, 0)), 1)

	// CRASH before Accept: the in-memory versiondb layer is discarded (no
	// CommitBatch ever ran). This is exactly what db.Abort() on restart / a
	// process kill before Accept does.
	cvm.inner.db.Abort()

	// Receipt durable after the abort (i.e. did it survive the "crash")?
	_, foundAfterCrash, _ := cvm.inner.state.GetReceipt(deriveBlockHash(1, time.Unix(1, 0)), 1)

	// Restart: the same block is re-verified (consensus replays unaccepted height).
	blk2 := makeBlock(cvm, cvm.lastAcceptedID, 1, time.Unix(1, 0), [][]byte{importTx, relayTx})
	if err := blk2.Verify(ctx); err != nil {
		t.Fatalf("verify #2 (post-restart): %v", err)
	}
	s2, _, _ := matcher.counts()

	t.Logf("submits after verify#1=%d  receipt-in-mem=%v  receipt-after-crash=%v  submits after re-verify=%d",
		s1, foundInMem, foundAfterCrash, s2)

	if !foundAfterCrash && s2 > s1 {
		t.Fatalf("DOUBLE-SPEND WINDOW: the idempotency receipt was lost on crash "+
			"(durable=%v) and re-Verify re-submitted to the d-chain (submits %d -> %d). "+
			"The same order matched TWICE on the source-of-truth matcher; the taker's "+
			"single locked collateral backs two fills.", foundAfterCrash, s1, s2)
	}
}

// TestRED_EscrowTruncation_OverRefunds is the value-EXTRACTION proof. The settle
// computes spent quote as sum(uint64(price*size)) — truncating each fill's notional
// DOWN. For a taker BUY, refund = locked - spent. Understated spent => INFLATED
// refund. The taker receives the (real) base proceeds AND a refund larger than
// their true unspent collateral: net value extracted from the proxy escrow.
//
// Concretely: lock 100 quote. Fill 100 base across fills priced 0.99 each, so the
// TRUE quote cost is 99 (taker should get ~1 quote refund + 100 base). But each
// uint64(0.99*1)=0 => recorded spent=0 => refund=100 quote, PLUS 100 base. The
// taker walks away with 100 quote + 100 base from a 100-quote lock that bought
// 100 base. ~99 quote minted.
func TestRED_EscrowTruncation_OverRefunds(t *testing.T) {
	// 100 fills of size 1 @ price 0.99 (taker BUY). True spent ~= 99 quote.
	fills := make([]Fill, 100)
	for i := range fills {
		fills[i] = Fill{Price: 0.99, Size: 1, Side: 0}
	}
	cvm, _, _, _, _ := newCountingHarness(t, fills)

	taker := ids.GenerateTestShortID()
	collateralRef := ids.GenerateTestID()
	lockedAsset := ids.GenerateTestID()
	const locked uint64 = 100

	// Import recorded escrow of 100 quote under this ref.
	if err := cvm.inner.state.PutEscrow(collateralRef, lockedAsset, locked); err != nil {
		t.Fatalf("seed escrow: %v", err)
	}

	ar := newAtomicRequests()
	if err := cvm.inner.settleFromFills(taker, collateralRef, fills, ids.GenerateTestID(), 0, ar); err != nil {
		t.Fatalf("settleFromFills: %v", err)
	}

	// Sum the exported value by asset: base (proceeds) vs the locked asset (refund).
	var refund, base uint64
	for _, reqs := range ar.reqs {
		for _, e := range reqs.PutRequests {
			if len(e.Value) < 60 {
				continue
			}
			var a ids.ID
			copy(a[:], e.Value[20:52])
			amt := binary.BigEndian.Uint64(e.Value[52:60])
			if a == lockedAsset {
				refund += amt
			} else {
				base += amt
			}
		}
	}
	trueBase := uint64(100) // sum(size)
	trueSpent := uint64(99) // 100 * 0.99
	trueRefund := locked - trueSpent
	t.Logf("locked=%d  base proceeds=%d (true %d)  refund=%d (true %d)",
		locked, base, trueBase, refund, trueRefund)

	// Value extracted = refund beyond what was truly unspent. The taker also keeps
	// base proceeds (the bought asset), so any refund > trueRefund is net theft.
	if refund > trueRefund {
		t.Fatalf("VALUE EXTRACTION: settle refunded %d of the locked asset but only %d "+
			"was truly unspent (spent quote truncated via uint64(price*size)). The taker "+
			"keeps %d base proceeds too. ~%d quote minted out of the proxy escrow.",
			refund, trueRefund, base, refund-trueRefund)
	}
}

// exportKeys returns every shared-memory PutRequest key the settle accumulated,
// sorted, so two runs can be compared byte-for-byte. The KEY (not the value) is
// the consensus-critical artifact: atomic.Apply commits these keys into the
// destination chain's shared memory, so if they differ across validators the
// commit diverges and the network splits.
func exportKeys(ar *atomicRequests) [][]byte {
	var keys [][]byte
	for _, reqs := range ar.reqs {
		for _, e := range reqs.PutRequests {
			k := make([]byte, len(e.Key))
			copy(k, e.Key)
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
	return keys
}

// TestRED_SettlementExportKeyDeterminism is the regression proof for the
// "export shared-memory key derived from time.Now()" split. It replicates the
// original PoC at the real consensus boundary: TWO independent VM instances
// ("validator A" and "validator B") settle the IDENTICAL fills for the IDENTICAL
// (taker, collateralRef, block coordinate). The exported atomic PutRequest keys
// — which atomic.Apply commits into C-Chain shared memory on accept — MUST be
// byte-identical.
//
// The bug (now closed): settleFromFills built the export via NewExportTx, which
// stamped CreatedAt: time.Now().UnixNano(); finalize() hashed that into the
// TxID; executeExport keyed the PutRequest off deriveUTXOID(tx.ID(), i). Two
// validators stamped different clocks => different TxIDs => different keys =>
// divergent shared-memory commit => consensus split. The fix seeds the export
// identity from the consensus-agreed (blockHash, txIndex) only, so the keys
// match. This test FAILS hard against the time.Now() code and passes with the
// deterministic-seed fix.
func TestRED_SettlementExportKeyDeterminism(t *testing.T) {
	fills := []Fill{
		{Price: 2, Size: 50, Side: 0}, // taker BUY: receives base, pays quote
		{Price: 2, Size: 50, Side: 0},
	}
	// The consensus-agreed settlement coordinate every validator sees identically.
	blockHash := deriveBlockHash(7, time.Unix(1_700_000_000, 0))
	const txIndex = uint32(3)
	// Fix the cross-validator-shared inputs so the ONLY thing that could differ is
	// the per-node wall clock the bug folded into the key. Co-validators of one
	// chain share the SAME C-Chain id (the export's DestinationChain) — pin it so
	// the test isolates wall-clock nondeterminism, not a harness-random chain id.
	sharedCChainID := ids.GenerateTestID()
	taker := ids.GenerateTestShortID()
	collateralRef := ids.GenerateTestID()
	lockedAsset := ids.GenerateTestID()
	const locked uint64 = 1000

	settleOn := func(label string) [][]byte {
		// A fresh VM instance models a distinct validator. seedEscrow gives the
		// refund leg something to conserve so the export carries multiple outputs.
		cvm, _, _, _, _ := newCountingHarness(t, fills)
		cvm.inner.consensusRuntime.CChainID = sharedCChainID
		if err := cvm.inner.state.PutEscrow(collateralRef, lockedAsset, locked); err != nil {
			t.Fatalf("%s: seed escrow: %v", label, err)
		}
		ar := newAtomicRequests()
		if err := cvm.inner.settleFromFills(taker, collateralRef, fills, blockHash, txIndex, ar); err != nil {
			t.Fatalf("%s: settleFromFills: %v", label, err)
		}
		return exportKeys(ar)
	}

	// Validator B runs after a real wall-clock advance — the exact condition that
	// produced divergent keys under the time.Now() code.
	keysA := settleOn("validator A")
	time.Sleep(2 * time.Millisecond)
	keysB := settleOn("validator B")

	if len(keysA) == 0 {
		t.Fatal("precondition: settle produced no export keys (test would be vacuous)")
	}
	if len(keysA) != len(keysB) {
		t.Fatalf("export-key COUNT diverged across validators: A=%d B=%d", len(keysA), len(keysB))
	}
	for i := range keysA {
		if !bytes.Equal(keysA[i], keysB[i]) {
			t.Fatalf("NONDETERMINISTIC EXPORT KEY (consensus split): for identical fills/ref/block, "+
				"validator A export key[%d]=%x but validator B=%x. atomic.Apply commits these into "+
				"C-Chain shared memory on accept; divergent keys => divergent commit => the network "+
				"forks on the value-settlement path. (The time.Now() in the export TxID is back.)",
				i, keysA[i], keysB[i])
		}
	}
	t.Logf("DETERMINISTIC: %d export key(s) byte-identical across two validators despite a wall-clock advance; first=%x",
		len(keysA), keysA[0])
}

// TestRED_SettlementExportKeyIndependentOfWallClock pins the mechanism directly:
// the same logical settlement, run twice on ONE VM with a clock advance between,
// yields the same export keys. This isolates the regression to the export
// identity (independent of any cross-instance noise) — if a future change folds
// time.Now() (or any per-call nondeterminism) back into the settlement export's
// TxID, deriveUTXOID flips and this fails.
func TestRED_SettlementExportKeyIndependentOfWallClock(t *testing.T) {
	fills := []Fill{{Price: 1, Size: 1000, Side: 0}}
	blockHash := deriveBlockHash(42, time.Unix(123, 0))
	const txIndex = uint32(0)
	taker := ids.GenerateTestShortID()
	collateralRef := ids.GenerateTestID()

	cvm, _, _, _, _ := newCountingHarness(t, fills)

	ar1 := newAtomicRequests()
	if err := cvm.inner.settleFromFills(taker, collateralRef, fills, blockHash, txIndex, ar1); err != nil {
		t.Fatalf("settle #1: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	ar2 := newAtomicRequests()
	if err := cvm.inner.settleFromFills(taker, collateralRef, fills, blockHash, txIndex, ar2); err != nil {
		t.Fatalf("settle #2: %v", err)
	}

	k1, k2 := exportKeys(ar1), exportKeys(ar2)
	if len(k1) == 0 || len(k1) != len(k2) {
		t.Fatalf("export-key count mismatch/empty: #1=%d #2=%d", len(k1), len(k2))
	}
	for i := range k1 {
		if !bytes.Equal(k1[i], k2[i]) {
			t.Fatalf("WALL-CLOCK LEAK INTO EXPORT KEY: same (blockHash, txIndex, fills) produced "+
				"key[%d] %x then %x across a clock advance — the settlement export identity is "+
				"not a pure function of consensus inputs.", i, k1[i], k2[i])
		}
	}
	t.Logf("export key stable across wall-clock advance: %x", k1[0])
}
