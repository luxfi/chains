// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fee

import (
	"bytes"
	"errors"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/stretchr/testify/require"
)

// errKV is a KV whose operations fail on demand, so the settlement primitive's
// storage-failure arms can be reached. Every one of them denies the operation;
// a fee that cannot be recorded must not be treated as paid.
type errKV struct {
	inner   KV
	failHas []byte // Has(key) errors when key has this prefix
	failGet []byte // Get(key) errors when key has this prefix
	failPut []byte // Put(key) errors when key has this prefix
	corrupt []byte // Get(key) returns a non-8-byte value for this prefix
}

var errStore = errors.New("store unavailable")

func (e *errKV) Has(k []byte) (bool, error) {
	if e.failHas != nil && bytes.HasPrefix(k, e.failHas) {
		return false, errStore
	}
	return e.inner.Has(k)
}

func (e *errKV) Get(k []byte) ([]byte, error) {
	if e.failGet != nil && bytes.HasPrefix(k, e.failGet) {
		return nil, errStore
	}
	if e.corrupt != nil && bytes.HasPrefix(k, e.corrupt) {
		return []byte{1, 2, 3}, nil
	}
	return e.inner.Get(k)
}

func (e *errKV) Put(k, v []byte) error {
	if e.failPut != nil && bytes.HasPrefix(k, e.failPut) {
		return errStore
	}
	return e.inner.Put(k, v)
}

func funded(t *testing.T, kv *errKV, a Account, amount uint64) *Ledger {
	t.Helper()
	seed := NewLedger(kv.inner)
	require.NoError(t, seed.Credit(a, amount))
	return NewLedger(kv)
}

// A balance that cannot be READ is not a balance of zero. Reporting zero would
// make an unfunded account and an unreachable store indistinguishable, and the
// caller would charge the one it could not read.
func TestUnreadableBalanceIsRefusedNotReportedAsZero(t *testing.T) {
	a := acct(1)

	for _, tc := range []struct {
		name string
		kv   *errKV
	}{
		{"has fails", &errKV{inner: memdb.New(), failHas: balPrefix}},
		{"get fails", &errKV{inner: memdb.New(), failGet: balPrefix}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := funded(t, tc.kv, a, 1000)

			_, err := l.Balance(a)
			require.ErrorIs(t, err, errStore)

			require.ErrorIs(t, l.Credit(a, 1), errStore)
			require.ErrorIs(t, l.Burn(a, 1), errStore)
			require.ErrorIs(t, CanPay(l, a, 1), errStore)
		})
	}
}

// A stored balance of the wrong width is corruption, not a number. Decoding it
// would invent a balance from whatever bytes happen to be there.
func TestCorruptBalanceIsRefused(t *testing.T) {
	kv := &errKV{inner: memdb.New(), corrupt: balPrefix}
	a := acct(2)
	l := funded(t, kv, a, 1000)

	_, err := l.Balance(a)
	require.ErrorContains(t, err, "corrupt u64")
	require.ErrorContains(t, l.Credit(a, 1), "corrupt u64")
	require.ErrorContains(t, l.Burn(a, 1), "corrupt u64")
}

// The burned counter is the audit total. If it cannot be read, the burn cannot
// be recorded, so the debit must not happen either.
func TestUnreadableBurnCounterRefusesTheBurn(t *testing.T) {
	kv := &errKV{inner: memdb.New(), failGet: burnedKey}
	a := acct(3)
	// Seed a prior burn so the counter exists: readU64 answers an ABSENT key
	// with zero and never reads it, so an unreadable counter is only reachable
	// once something has been burned.
	require.NoError(t, NewLedger(kv.inner).writeU64(burnedKey, 42))
	l := funded(t, kv, a, 1000)

	require.ErrorIs(t, l.Burn(a, 100), errStore)

	// The debit did not happen: the account is whole.
	bal, err := l.Balance(a)
	require.NoError(t, err)
	require.Equal(t, uint64(1000), bal, "a burn that could not be recorded must not debit")

	_, err = l.Burned()
	require.ErrorIs(t, err, errStore)
}

// A write that fails denies the operation. Credit is the mint path: a failed
// mint must not report success, or supply and the ledger diverge.
func TestUnwritableBalanceRefusesCreditAndBurn(t *testing.T) {
	a := acct(4)

	kv := &errKV{inner: memdb.New(), failPut: balPrefix}
	require.ErrorIs(t, NewLedger(kv).Credit(a, 100), errStore)

	kv2 := &errKV{inner: memdb.New(), failPut: balPrefix}
	l2 := funded(t, kv2, a, 1000)
	require.ErrorIs(t, l2.Burn(a, 100), errStore)
	bal, err := l2.Balance(a)
	require.NoError(t, err)
	require.Equal(t, uint64(1000), bal)
}

// The debit lands before the burned counter, and that order is deliberate.
// Either write can fail, and whichever half is staged alone is wrong; the
// caller MUST abort, because the Balances contract requires both writes to
// share the block's commit. But the two halves are not equally wrong if one
// ever did commit. Debit-then-record leaves 100 nLUX destroyed
// (live + burned falls short of credited). Record-then-debit leaves 100 nLUX
// invented (live + burned exceeds credited), and a burned counter that
// overstates supply reduction is unrecoverable — nobody can tell which account
// should have paid. So the survivable failure is chosen on purpose, and this
// test pins it against a quiet reordering.
func TestFailedBurnCounterLeavesTheCallerToAbort(t *testing.T) {
	kv := &errKV{inner: memdb.New(), failPut: burnedKey}
	a := acct(5)
	l := funded(t, kv, a, 1000)

	require.ErrorIs(t, l.Burn(a, 100), errStore)

	// Staged, uncommitted: the debit is visible, the burn is not. Committing
	// this would destroy 100 nLUX. The error is the caller's signal to abort.
	bal, err := l.Balance(a)
	require.NoError(t, err)
	require.Equal(t, uint64(900), bal)
	burned, err := l.Burned()
	require.NoError(t, err)
	require.Zero(t, burned)
}

// Burning must never wrap the audit total. Unreachable while burned <= genesis
// supply, but the guard is what makes that true rather than assumed.
func TestBurnedSupplyOverflowIsRefused(t *testing.T) {
	kv := memdb.New()
	l := NewLedger(kv)
	a := acct(6)

	require.NoError(t, l.writeU64(burnedKey, ^uint64(0)))
	require.NoError(t, l.Credit(a, 1000))

	require.ErrorIs(t, l.Burn(a, 1), ErrBalanceOverflow)

	bal, _ := l.Balance(a)
	require.Equal(t, uint64(1000), bal, "refused burn must not debit")
}

// Zero is a no-op on both paths, and must not touch the store: a zero-fee
// operation writes nothing.
func TestZeroAmountTouchesNothing(t *testing.T) {
	kv := &errKV{inner: memdb.New(), failHas: balPrefix, failPut: balPrefix}
	l := NewLedger(kv)
	a := acct(7)

	require.NoError(t, l.Credit(a, 0))
	require.NoError(t, l.Burn(a, 0))
}

// Cost is the only multiplication in the fee path. It must never wrap, and a
// zero on either side is a zero fee rather than an error — a chain may price an
// operation at nothing, but it may never price it at less than nothing.
func TestCostBoundaries(t *testing.T) {
	max := ^Gas(0)

	for _, tc := range []struct {
		name       string
		gas, price Gas
		want       uint64
		wantErr    bool
	}{
		{"zero gas", 0, 1_000, 0, false},
		{"zero price", 81_000, 0, 0, false},
		{"both zero", 0, 0, 0, false},
		{"unit", 1, 1, 1, false},
		{"largest exact", max, 1, uint64(max), false},
		{"smallest overflow", max, 2, 0, true},
		{"squared overflow", 1 << 32, 1 << 32, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Cost(tc.gas, tc.price)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrBalanceOverflow)
				require.Zero(t, got, "a refused cost must not return a partial fee")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// The meter's three readings are one number viewed three ways. If Used and
// Remaining can ever disagree with Limit, a caller can be charged for gas the
// meter never granted.
func TestMeterReadingsAgree(t *testing.T) {
	m := NewGasMeter(100)
	for _, step := range []Gas{0, 1, 40, 59, 0} {
		require.NoError(t, m.Consume(step))
		require.Equal(t, m.Limit(), m.Used()+m.Remaining())
	}
	require.Zero(t, m.Remaining())

	// Exhausted: any further consumption is refused, including one unit.
	require.ErrorIs(t, m.Consume(1), ErrOutOfGas)
	require.Equal(t, m.Limit(), m.Used()+m.Remaining())

	// A zero-limit meter grants nothing but is not an error to construct.
	z := NewGasMeter(0)
	require.NoError(t, z.Consume(0))
	require.ErrorIs(t, z.Consume(1), ErrOutOfGas)
}

// Conservation: a burn moves value from an account to the burned counter. It
// creates nothing and destroys nothing. Across an arbitrary interleaving of
// credits and burns, everything ever credited is still either spendable or
// burned — the invariant that makes this a ledger rather than a pair of
// counters that happen to move together.
func TestBurnConservesEveryCreditedUnit(t *testing.T) {
	l := NewLedger(memdb.New())
	accounts := []Account{acct(10), acct(11), acct(12)}

	var credited uint64
	// A fixed schedule: deterministic, and it interleaves accounts so a
	// cross-account leak would show up as a shortfall.
	steps := []struct {
		who         int
		credit      uint64
		burn        uint64
		burnRefused bool
	}{
		{0, 1_000, 300, false},
		{1, 500, 500, false},
		{2, 0, 1, true}, // never funded
		{0, 250, 900, false},
		{1, 0, 1, true}, // spent to zero above
		{2, 7, 8, true}, // one short
		{2, 1, 8, false},
		{0, 0, 50, false},
	}

	for _, s := range steps {
		a := accounts[s.who]
		require.NoError(t, l.Credit(a, s.credit))
		credited += s.credit

		err := l.Burn(a, s.burn)
		if s.burnRefused {
			require.ErrorIs(t, err, ErrInsufficientFunds)
		} else {
			require.NoError(t, err)
		}

		var live uint64
		for _, x := range accounts {
			b, err := l.Balance(x)
			require.NoError(t, err)
			live += b
		}
		burned, err := l.Burned()
		require.NoError(t, err)

		require.Equal(t, credited, live+burned,
			"every credited unit must be spendable or burned, never both and never neither")
	}
}

// Accounts are namespaced by the full address. Two addresses that share a
// prefix must not share a balance.
func TestAccountsDoNotAlias(t *testing.T) {
	l := NewLedger(memdb.New())
	a, b := acct(1), acct(1)
	b[len(b)-1] = 1

	require.NoError(t, l.Credit(a, 100))
	balB, err := l.Balance(b)
	require.NoError(t, err)
	require.Zero(t, balB, "a neighbouring address must not see another's funds")

	require.ErrorIs(t, l.Burn(b, 1), ErrInsufficientFunds)
	balA, _ := l.Balance(a)
	require.Equal(t, uint64(100), balA)
}

// The burned counter's key must not collide with any account's balance key,
// or a burn would overwrite someone's funds.
func TestBurnedKeyCannotCollideWithABalance(t *testing.T) {
	var a Account
	for i := range a {
		a[i] = 0xff
	}
	require.NotEqual(t, burnedKey, balKey(a))
	require.False(t, bytes.HasPrefix(balKey(a), burnedKey))
	require.False(t, bytes.HasPrefix(burnedKey, balPrefix))
}
