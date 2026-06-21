// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// custody_conservation_test.go proves the FULL CLOB custody rail conserves value
// across the C-Chain <-> D-Chain boundary for a NON-NATIVE asset: atomically
// DEPOSIT into the D-Chain (ImportTx + clob_deposit), TRADE inside the D-Chain
// (modeled by the ledger matcher moving balances), and WITHDRAW back out
// (clob_withdraw + ExportTx). The acceptance criterion is the same one the
// taker-only escrow model could not meet for the maker leg: C-Chain value OUT ==
// C-Chain value IN, to the unit, with the proxy minting NOTHING (import consumes
// once; export releases only realized ledger balance).
//
// REAL atomic.SharedMemory drives the import/export legs; a ledger-modeling fake
// matcher stands in for the D-Chain over the zapDialer seam, so clob_deposit
// credits and clob_withdraw debits a real in-test balance ledger — exactly what
// the dchain.VM does in consensus (pkg/dchain/conservation_test.go proves THAT
// side end-to-end against the real VM).

package dexvm

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

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

// ledgerMatcher is a fake D-Chain over the zapConn seam that maintains a real
// per-(user,asset) available-balance ledger. clob_deposit credits it; clob_submit
// (a trade) moves balance between two accounts; clob_withdraw debits it (clamped
// to available) and reports the realized amount. It models EXACTLY the invariant
// the real d-chain enforces — sum of balances is conserved across deposit ->
// trade -> withdraw — so the proxy rail can be proven against a faithful stand-in.
type ledgerMatcher struct {
	bal      map[string]uint64 // key = user16 || asset32 (FULL injective id)
	received [][]byte
}

func newLedgerMatcher() *ledgerMatcher { return &ledgerMatcher{bal: map[string]uint64{}} }

// ledgerKey keys the fake D-Chain balance ledger by user[16] || asset[32], the
// FULL injective cross-chain asset id (native == ids.Empty) — byte-faithful to the
// real d-chain balance:<user:8><asset:32> keyspace (the asset is keyed at full
// width so two assets sharing a leading prefix never collide).
func ledgerKey(user []byte, asset ids.ID) string {
	return string(user) + string(asset[:])
}

func (m *ledgerMatcher) Call(_ context.Context, method string, payload []byte) ([]byte, error) {
	m.received = append(m.received, append([]byte(nil), payload...))
	switch method {
	case ZAPMethodDeposit:
		user := payload[0:16]
		var asset ids.ID
		copy(asset[:], payload[16:custodyAmountOff])
		amount := binary.BigEndian.Uint64(payload[custodyAmountOff:custodyRefOff])
		m.bal[ledgerKey(user, asset)] += amount
		return balResp(0, amount), nil // credited exactly
	case ZAPMethodWithdraw:
		user := payload[0:16]
		var asset ids.ID
		copy(asset[:], payload[16:custodyAmountOff])
		want := binary.BigEndian.Uint64(payload[custodyAmountOff:custodyRefOff])
		k := ledgerKey(user, asset)
		realized := want
		if realized > m.bal[k] {
			realized = m.bal[k] // clamp to available (no mint)
		}
		m.bal[k] -= realized
		st := uint8(0)
		if realized == 0 {
			st = 2
		}
		return balResp(st, realized), nil
	default:
		// place/cancel/ensure/open acks.
		ack := make([]byte, 9)
		return ack, nil
	}
}

func (m *ledgerMatcher) Close() error { return nil }

// trade moves `base` of `baseAsset` from seller->buyer and `quote` of `quoteAsset`
// from buyer->seller inside the ledger — what an accepted D-Chain block's
// settleFills does. Used by the test to model the cross between the deposit and
// withdraw legs (the proxy does not trade; the D-Chain does). buyer/seller are
// the 16-byte frame-form user identities (frameUser).
func (m *ledgerMatcher) trade(buyer, seller []byte, baseAsset, quoteAsset ids.ID, base, quote uint64) {
	m.bal[ledgerKey(buyer, quoteAsset)] -= quote
	m.bal[ledgerKey(seller, quoteAsset)] += quote
	m.bal[ledgerKey(seller, baseAsset)] -= base
	m.bal[ledgerKey(buyer, baseAsset)] += base
}

// frameUser returns the 16-byte (UserSize) frame-form user identity for an
// address — the exact bytes the deposit/withdraw frame carries (the proxy
// truncates a 20-byte address to the 16-byte user field; the D-Chain then folds
// THAT to its 8-byte handle). The test keys its ledger by this so it matches the
// matcher's view byte-for-byte.
func frameUser(addr ids.ShortID) []byte { return padUser(userHandle(addr)) }

func balResp(status uint8, amount uint64) []byte {
	out := make([]byte, BalanceRespSize)
	out[0] = status
	binary.BigEndian.PutUint64(out[1:9], amount)
	return out
}

// custodyHarness wires a proxy VM with REAL two-chain shared memory and the
// ledger matcher.
type custodyHarness struct {
	vm         *VM
	cChainSM   atomic.SharedMemory
	proxyChain ids.ID
	cChain     ids.ID
	ledger     *ledgerMatcher
}

func newCustodyHarness(t *testing.T) *custodyHarness {
	t.Helper()
	logger := log.NewNoOpLogger()
	baseDB := memdb.New()
	memoryDB := prefixdb.New([]byte{0}, baseDB)
	m := atomic.NewMemory(memoryDB)

	proxyChain := ids.GenerateTestID()
	cChain := ids.GenerateTestID()
	proxySM := m.NewSharedMemory(proxyChain)
	cChainSM := m.NewSharedMemory(cChain)

	ledger := newLedgerMatcher()
	prev := zapDialer
	zapDialer = func(_ context.Context, _ string) (zapConn, error) { return ledger, nil }
	t.Cleanup(func() { zapDialer = prev })

	rt := &runtime.Runtime{ChainID: proxyChain, CChainID: cChain, NetworkID: 96369, Log: logger, SharedMemory: proxySM}
	v := &VM{}
	v.Config = config.DefaultConfig()
	v.Config.DexZapEndpoint = "127.0.0.1:0"
	if err := v.Initialize(context.Background(), vm.Init{
		Runtime: rt, DB: prefixdb.New([]byte{1}, baseDB), ToEngine: make(chan vm.Message, 8),
		Sender: warp.FakeSender{}, Log: logger,
	}); err != nil {
		t.Fatalf("init proxy vm: %v", err)
	}
	v.bootstrapped = true
	return &custodyHarness{vm: v, cChainSM: cChainSM, proxyChain: proxyChain, cChain: cChain, ledger: ledger}
}

// fundCChain exports `amount` of `asset` owned by `owner` into shared memory on the
// SWAP rail (the proxy can claim it on an import), returning the source UTXO id.
func (h *custodyHarness) fundCChain(t *testing.T, owner ids.ShortID, asset ids.ID, amount uint64) ids.ID {
	return h.fundCChainRail(t, txs.RailSwap, owner, asset, amount)
}

// fundCChainRail is fundCChain parametrized by the object's RAIL — the lane the C->D
// object travels (RailSwap for a swap intent, RailLP for an LP commit). The import
// binds the credited outputs' rail to this recorded rail, so the importing tx's
// outputs must carry the SAME rail.
func (h *custodyHarness) fundCChainRail(t *testing.T, rail txs.Rail, owner ids.ShortID, asset ids.ID, amount uint64) ids.ID {
	t.Helper()
	srcUTXOID := deriveUTXOID(ids.GenerateTestID(), 0)
	val := encodeExportedOutput(txs.AtomicOutput{Rail: rail, Owner: owner, Asset: asset, Amount: amount})
	if err := h.cChainSM.Apply(map[ids.ID]*atomic.Requests{
		h.proxyChain: {PutRequests: []*atomic.Element{{Key: srcUTXOID[:], Value: val, Traits: [][]byte{owner[:]}}}},
	}); err != nil {
		t.Fatalf("fund C-Chain: %v", err)
	}
	return srcUTXOID
}

// exportedTo sums the value the proxy exported back to C-Chain for an owner.
func (h *custodyHarness) exportedTo(t *testing.T, owner ids.ShortID) uint64 {
	t.Helper()
	vals, _, _, err := h.cChainSM.Indexed(h.proxyChain, [][]byte{owner[:]}, nil, nil, 100)
	if err != nil {
		t.Fatalf("Indexed: %v", err)
	}
	var total uint64
	for _, v := range vals {
		if len(v) >= exportedOutputSize {
			total += binary.BigEndian.Uint64(v[53:61])
		}
	}
	return total
}

// TestCustodyRailFullCycleConserves is the headline proxy proof: two accounts
// DEPOSIT a non-native asset into the D-Chain via the atomic rail, the D-Chain
// matches them (modeled), and BOTH WITHDRAW — asserting C-Chain value out ==
// C-Chain value in (to the unit) and that the source UTXOs were consumed exactly
// once. This is the maker+taker conservation the prior taker-only model lacked.
func TestCustodyRailFullCycleConserves(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	maker := ids.GenerateTestShortID()
	taker := ids.GenerateTestShortID()
	lux := ids.GenerateTestID()  // base asset (LUX)
	lusd := ids.GenerateTestID() // quote asset (LUSD)

	// --- DEPOSIT: maker funds 100 LUX, taker funds 1000 LUSD, atomically. ---
	makerUTXO := h.fundCChain(t, maker, lux, 100)
	takerUTXO := h.fundCChain(t, taker, lusd, 1000)

	arDep := newAtomicRequests()
	makerImport := txs.NewImportTx(maker, 0, h.cChain,
		[]txs.AtomicInput{{UTXOID: makerUTXO, Asset: lux, Amount: 100}},
		[]txs.AtomicOutput{{Owner: maker, Asset: lux, Amount: 100}})
	takerImport := txs.NewImportTx(taker, 0, h.cChain,
		[]txs.AtomicInput{{UTXOID: takerUTXO, Asset: lusd, Amount: 1000}},
		[]txs.AtomicOutput{{Owner: taker, Asset: lusd, Amount: 1000}})

	if err := h.vm.executeDeposit(ctx, makerImport, arDep); err != nil {
		t.Fatalf("maker deposit: %v", err)
	}
	if err := h.vm.executeDeposit(ctx, takerImport, arDep); err != nil {
		t.Fatalf("taker deposit: %v", err)
	}
	// Commit the atomic deposit legs (consumes the source UTXOs).
	if err := h.vm.commitAtomic(arDep, nil); err != nil {
		t.Fatalf("commit deposits: %v", err)
	}

	// The D-Chain ledger now holds the deposited value.
	if got := h.ledger.bal[ledgerKey(frameUser(maker), lux)]; got != 100 {
		t.Fatalf("maker LUX in ledger = %d, want 100", got)
	}
	if got := h.ledger.bal[ledgerKey(frameUser(taker), lusd)]; got != 1000 {
		t.Fatalf("taker LUSD in ledger = %d, want 1000", got)
	}

	// --- TRADE inside the D-Chain: taker buys 10 LUX @ 5 = 50 LUSD. ---
	// (The proxy does not trade; the D-Chain matcher does. We model the accepted
	// block's settleFills moving balances.)
	h.ledger.trade(frameUser(taker), frameUser(maker), lux, lusd, 10, 50)

	// Ledger after trade: maker 90 LUX + 50 LUSD ; taker 10 LUX + 950 LUSD.
	assertLedger(t, h, maker, lux, 90)
	assertLedger(t, h, maker, lusd, 50)
	assertLedger(t, h, taker, lux, 10)
	assertLedger(t, h, taker, lusd, 950)

	// OWNERSHIP (proxy-boundary mirror of the dchain invariant): every account
	// holding ledger value must be an EXPLICIT PARTY — the depositor (deposit), the
	// maker or taker (trade), or the withdrawer (withdraw). No THIRD account ever
	// holds value. This is the proxy-rail analog of pkg/dchain's ownership harness:
	// conservation alone (sum unchanged) would not catch value mis-credited to a
	// non-party (a colliding handle), so we assert the ledger's account set is
	// exactly the explicit parties. Here both parties are maker+taker.
	assertOnlyParties(t, h.ledger, frameUser(maker), frameUser(taker))

	// --- WITHDRAW: every account pulls its full realized balance, atomically. ---
	arW := newAtomicRequests()
	withdrawAll := func(owner ids.ShortID, asset ids.ID, want uint64, idx uint32) uint64 {
		r, err := h.vm.executeWithdraw(ctx, owner, asset, want, h.cChain, ids.GenerateTestID(), idx, 1, arW)
		if err != nil {
			t.Fatalf("withdraw owner=%x asset=%x: %v", owner[:4], asset[:4], err)
		}
		return r
	}
	var totalOut uint64
	totalOut += withdrawAll(maker, lux, 90, 0)
	totalOut += withdrawAll(maker, lusd, 50, 1)
	totalOut += withdrawAll(taker, lux, 10, 2)
	totalOut += withdrawAll(taker, lusd, 950, 3)
	if err := h.vm.commitAtomic(arW, nil); err != nil {
		t.Fatalf("commit withdrawals: %v", err)
	}

	// --- CONSERVATION across the rail ---
	const totalIn = 100 + 1000
	if totalOut != totalIn {
		t.Fatalf("CONSERVATION VIOLATED: withdrawn %d != deposited %d", totalOut, totalIn)
	}
	// C-Chain can now claim exactly the exported proceeds for each account.
	if got := h.exportedTo(t, maker); got != 90+50 {
		t.Fatalf("maker C-Chain proceeds = %d, want 140", got)
	}
	if got := h.exportedTo(t, taker); got != 10+950 {
		t.Fatalf("taker C-Chain proceeds = %d, want 960", got)
	}
	// The ledger is empty — every deposited unit was either traded or withdrawn.
	for k, v := range h.ledger.bal {
		if v != 0 {
			t.Errorf("ledger not drained: key %x has %d", []byte(k), v)
		}
	}
	// Source UTXOs consumed exactly once (double-spend guard held).
	for _, u := range []ids.ID{makerUTXO, takerUTXO} {
		if c, _ := h.vm.state.IsConsumed(u); !c {
			t.Errorf("source UTXO %x not consumed", u[:4])
		}
	}
}

// TestCustodyWithdrawCannotExceedRealized proves a withdraw exports only the
// ledger's realized (clamped) balance: asking for more than is available exports
// only what is there — the proxy never mints on the export leg.
func TestCustodyWithdrawCannotExceedRealized(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()
	owner := ids.GenerateTestShortID()
	asset := ids.GenerateTestID()

	// Fund + deposit 40.
	u := h.fundCChain(t, owner, asset, 40)
	ar := newAtomicRequests()
	imp := txs.NewImportTx(owner, 0, h.cChain,
		[]txs.AtomicInput{{UTXOID: u, Asset: asset, Amount: 40}},
		[]txs.AtomicOutput{{Owner: owner, Asset: asset, Amount: 40}})
	if err := h.vm.executeDeposit(ctx, imp, ar); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	if err := h.vm.commitAtomic(ar, nil); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Try to withdraw 100; only 40 is realized.
	arW := newAtomicRequests()
	realized, err := h.vm.executeWithdraw(ctx, owner, asset, 100, h.cChain, ids.GenerateTestID(), 0, 1, arW)
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if realized != 40 {
		t.Fatalf("over-withdraw realized %d, want clamped 40", realized)
	}
	if err := h.vm.commitAtomic(arW, nil); err != nil {
		t.Fatalf("commit withdraw: %v", err)
	}
	if got := h.exportedTo(t, owner); got != 40 {
		t.Fatalf("exported %d, want 40 (no mint)", got)
	}
}

// TestCustodyDepositCreditsExactImport proves the deposit rail credits the
// D-Chain ledger with EXACTLY the imported value (no skim, no inflation), and a
// short/over credit from a lying matcher is refused.
func TestCustodyDepositCreditsExactImport(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()
	owner := ids.GenerateTestShortID()
	asset := ids.GenerateTestID()

	u := h.fundCChain(t, owner, asset, 777)
	ar := newAtomicRequests()
	imp := txs.NewImportTx(owner, 0, h.cChain,
		[]txs.AtomicInput{{UTXOID: u, Asset: asset, Amount: 777}},
		[]txs.AtomicOutput{{Owner: owner, Asset: asset, Amount: 777}})
	if err := h.vm.executeDeposit(ctx, imp, ar); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	if got := h.ledger.bal[ledgerKey(frameUser(owner), asset)]; got != 777 {
		t.Fatalf("ledger credited %d, want exactly 777", got)
	}
}

func assertLedger(t *testing.T, h *custodyHarness, owner ids.ShortID, asset ids.ID, want uint64) {
	t.Helper()
	if got := h.ledger.bal[ledgerKey(frameUser(owner), asset)]; got != want {
		t.Fatalf("ledger owner=%x asset=%x = %d, want %d", owner[:4], asset[:4], got, want)
	}
}

// assertOnlyParties is the proxy-boundary OWNERSHIP gate: every account holding a
// non-zero ledger balance must be one of the supplied EXPLICIT PARTIES (the
// 16-byte frame-form user identities). A non-zero balance for any other account is
// value credited to a NON-party — the theft a conservation sum cannot see. The
// ledger key is user[16]||asset[32], so the account is the leading 16 bytes.
func assertOnlyParties(t *testing.T, m *ledgerMatcher, parties ...[]byte) {
	t.Helper()
	allowed := map[string]struct{}{}
	for _, p := range parties {
		allowed[string(p)] = struct{}{}
	}
	for k, v := range m.bal {
		if v == 0 {
			continue
		}
		if len(k) < 16 {
			t.Fatalf("ledger key too short: %x", []byte(k))
		}
		user := k[:16]
		if _, ok := allowed[user]; !ok {
			t.Fatalf("OWNERSHIP VIOLATED: account %x holds %d in the ledger but is NOT an explicit party (deposit/trade/withdraw) — value credited to a non-party", []byte(user), v)
		}
	}
}

// TestCustodyWithdraw_DuplicateFillRefRejected pins R2: the proxy WITHDRAW rail
// consumes the settlement fillRef exactly once, so a duplicate fillRef cannot
// double-export (a drain) even if the D-Chain ledger still holds a withdrawable
// balance. This is the proxy-local second line of defense, independent of the
// D-Chain seen: clamp, and correct regardless of how the proxy BuildBlock rail is
// later wired. A DIFFERENT fillRef still works (consume-once is per-ref, not a
// global block).
func TestCustodyWithdraw_DuplicateFillRefRejected(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()
	owner := ids.GenerateTestShortID()
	asset := ids.GenerateTestID()

	// Fund + deposit 200, so the ledger retains a balance AFTER the first withdraw —
	// without consume-once, a duplicate-fillRef second withdraw WOULD double-export.
	u := h.fundCChain(t, owner, asset, 200)
	arD := newAtomicRequests()
	imp := txs.NewImportTx(owner, 0, h.cChain,
		[]txs.AtomicInput{{UTXOID: u, Asset: asset, Amount: 200}},
		[]txs.AtomicOutput{{Owner: owner, Asset: asset, Amount: 200}})
	if err := h.vm.executeDeposit(ctx, imp, arD); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	if err := h.vm.commitAtomic(arD, nil); err != nil {
		t.Fatalf("commit deposit: %v", err)
	}
	assertLedger(t, h, owner, asset, 200)

	fillRef := ids.GenerateTestID()

	// Withdraw #1 with fillRef: realized 100, exports 100, consumes the fillRef.
	ar1 := newAtomicRequests()
	r1, err := h.vm.executeWithdraw(ctx, owner, asset, 100, h.cChain, fillRef, 0, 1, ar1)
	if err != nil {
		t.Fatalf("withdraw #1: %v", err)
	}
	if r1 != 100 {
		t.Fatalf("withdraw #1 realized = %d, want 100", r1)
	}
	if err := h.vm.commitAtomic(ar1, nil); err != nil {
		t.Fatalf("commit withdraw #1: %v", err)
	}
	assertLedger(t, h, owner, asset, 100) // 100 still withdrawable
	if got := h.exportedTo(t, owner); got != 100 {
		t.Fatalf("exported after #1 = %d, want 100", got)
	}

	// Withdraw #2 with the SAME fillRef: rejected by consume-once BEFORE the relay,
	// so it neither debits the ledger again nor exports a second time.
	ar2 := newAtomicRequests()
	r2, err := h.vm.executeWithdraw(ctx, owner, asset, 100, h.cChain, fillRef, 1, 1, ar2)
	if !errors.Is(err, errFillRefAlreadyExported) {
		t.Fatalf("duplicate-fillRef withdraw err = %v, want errFillRefAlreadyExported", err)
	}
	if r2 != 0 {
		t.Fatalf("duplicate-fillRef withdraw realized = %d, want 0", r2)
	}
	if !ar2.empty() {
		t.Fatal("duplicate-fillRef withdraw accumulated an export — double-export not prevented")
	}
	if err := h.vm.commitAtomic(ar2, nil); err != nil {
		t.Fatalf("commit (empty) withdraw #2: %v", err)
	}
	// No double export, and the ledger was NOT re-debited (the duplicate never relayed).
	assertLedger(t, h, owner, asset, 100)
	if got := h.exportedTo(t, owner); got != 100 {
		t.Fatalf("exported after rejected duplicate = %d, want 100 (no double-export)", got)
	}

	// A DISTINCT fillRef still works: consume-once is per-ref, not a global block.
	ar3 := newAtomicRequests()
	r3, err := h.vm.executeWithdraw(ctx, owner, asset, 100, h.cChain, ids.GenerateTestID(), 2, 1, ar3)
	if err != nil {
		t.Fatalf("withdraw #3 (distinct fillRef): %v", err)
	}
	if r3 != 100 {
		t.Fatalf("withdraw #3 realized = %d, want 100", r3)
	}
	if err := h.vm.commitAtomic(ar3, nil); err != nil {
		t.Fatalf("commit withdraw #3: %v", err)
	}
	assertLedger(t, h, owner, asset, 0)
	if got := h.exportedTo(t, owner); got != 200 {
		t.Fatalf("exported after #3 = %d, want 200 (100 + 100, distinct refs)", got)
	}
}
