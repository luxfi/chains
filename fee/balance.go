// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fee

import (
	"errors"

	"github.com/luxfi/ids"
)

// Account is a fee payer identity. It is the canonical 20-byte Lux address
// (ids.ShortID) — the same type P/X-Chain use for UTXO owners — so balances
// here interoperate with existing address tooling. It is PUBLIC: an account
// identifier never carries secret material.
type Account = ids.ShortID

// Sentinel errors. Settlement is fail-secure: every error path denies the
// operation (the block fails Verify or Accept) — none silently proceeds.
var (
	// ErrInsufficientFunds mirrors the EVM's error of the same intent
	// (core/state_transition.go buyGas): the payer cannot cover the fee.
	ErrInsufficientFunds = errors.New("fee: insufficient funds")

	// ErrBalanceOverflow is returned by Credit when an account balance or the
	// burned-supply counter would exceed 2^64-1 nLUX.
	ErrBalanceOverflow = errors.New("fee: balance overflow")
)

// Balances is the debitable balance surface a fee-charging VM exposes to the
// settler. It is the minimal contract the EVM expresses as GetBalance /
// SubBalance, adapted to the native account model and to BURNING (no coinbase):
//
//   - Balance reports an account's spendable nLUX.
//   - Credit adds nLUX (genesis seeding; future treasury/bridge inflows).
//   - Burn removes nLUX from the payer AND reduces circulating supply — the
//     fee debit. It is the only spend path here; there is intentionally no
//     account->account transfer, because service-chain fees are burned, not
//     paid to a validator. (A treasury split, if ever wanted, is a new method,
//     not a reinterpretation of Burn.)
//   - Burned reports cumulative burned supply, for audit.
//
// Implementations MUST be atomic with respect to a single call and MUST be
// driven inside a transaction/versiondb whose commit is the block's commit, so
// a fee debit and the operation it pays for either both land or neither does.
type Balances interface {
	Balance(acct Account) (uint64, error)
	Credit(acct Account, amount uint64) error
	Burn(acct Account, amount uint64) error
	Burned() (uint64, error)
}

// addOverflow returns a+b and whether the addition overflowed uint64.
func addOverflow(a, b uint64) (uint64, bool) {
	sum := a + b
	return sum, sum < a
}
