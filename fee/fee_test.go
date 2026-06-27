// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fee

import (
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/stretchr/testify/require"
)

func acct(b byte) Account {
	var a Account
	a[0] = b
	return a
}

// Pillar (a): debitable balance + burn.
func TestLedger_CreditBurnBurned(t *testing.T) {
	l := NewLedger(memdb.New())
	a := acct(1)

	bal, err := l.Balance(a)
	require.NoError(t, err)
	require.Zero(t, bal)

	require.NoError(t, l.Credit(a, 1000))
	bal, _ = l.Balance(a)
	require.Equal(t, uint64(1000), bal)

	require.NoError(t, l.Burn(a, 300))
	bal, _ = l.Balance(a)
	require.Equal(t, uint64(700), bal)

	burned, _ := l.Burned()
	require.Equal(t, uint64(300), burned, "burn must reduce circulating supply")
}

func TestLedger_InsufficientFundsLeavesStateUntouched(t *testing.T) {
	l := NewLedger(memdb.New())
	a := acct(2)
	require.NoError(t, l.Credit(a, 100))

	require.ErrorIs(t, l.Burn(a, 101), ErrInsufficientFunds)
	bal, _ := l.Balance(a)
	require.Equal(t, uint64(100), bal, "failed burn must not debit")
	burned, _ := l.Burned()
	require.Zero(t, burned, "failed burn must not change burned supply")
}

func TestLedger_OverflowRefused(t *testing.T) {
	l := NewLedger(memdb.New())
	a := acct(3)
	require.NoError(t, l.Credit(a, ^uint64(0)))
	require.ErrorIs(t, l.Credit(a, 1), ErrBalanceOverflow)
}

// Pillar (b): gas metering.
func TestGasMeter(t *testing.T) {
	m := NewGasMeter(100)
	require.NoError(t, m.Consume(40))
	require.Equal(t, Gas(60), m.Remaining())
	require.Equal(t, Gas(40), m.Used())
	require.Equal(t, Gas(100), m.Limit())

	require.ErrorIs(t, m.Consume(61), ErrOutOfGas)
	require.Equal(t, Gas(60), m.Remaining(), "out-of-gas must not consume")
}

// Pillar (c): settlement (cost, affordability, charge=debit+burn).
func TestCost_OverflowRefused(t *testing.T) {
	f, err := Cost(81_000, 1_000)
	require.NoError(t, err)
	require.Equal(t, uint64(81_000_000), f)

	_, err = Cost(^Gas(0), 2)
	require.ErrorIs(t, err, ErrBalanceOverflow)
}

func TestCanPayAndCharge(t *testing.T) {
	l := NewLedger(memdb.New())
	a := acct(4)
	require.NoError(t, l.Credit(a, 1000))

	require.NoError(t, CanPay(l, a, 1000))
	require.ErrorIs(t, CanPay(l, a, 1001), ErrInsufficientFunds)

	// CanPay is read-only: nothing moved.
	bal, _ := l.Balance(a)
	require.Equal(t, uint64(1000), bal)

	require.NoError(t, Charge(l, a, 600))
	bal, _ = l.Balance(a)
	require.Equal(t, uint64(400), bal)
	burned, _ := l.Burned()
	require.Equal(t, uint64(600), burned)
}
