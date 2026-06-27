// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fee

// Cost converts metered gas to a fee in nLUX at the given per-unit price,
// refusing overflow (fail-secure: a fee must never wrap to a smaller number).
// price is nLUX per unit of Gas.
func Cost(gasUsed, price Gas) (uint64, error) {
	if gasUsed == 0 || price == 0 {
		return 0, nil
	}
	g := uint64(gasUsed)
	p := uint64(price)
	fee := g * p
	if fee/p != g {
		return 0, ErrBalanceOverflow
	}
	return fee, nil
}

// CanPay is the read-only affordability check a block runs in Verify, for every
// fee-bearing transaction, BEFORE the block can be accepted. It never mutates
// state, so verifying a block cannot move funds; it only proves the payer could
// cover the fee. A block containing any unaffordable transaction fails Verify
// and is never accepted — fail closed.
func CanPay(b Balances, acct Account, fee uint64) error {
	bal, err := b.Balance(acct)
	if err != nil {
		return err
	}
	if bal < fee {
		return ErrInsufficientFunds
	}
	return nil
}

// Charge is the authoritative settlement a block runs in Accept: it debits the
// fee from the payer and burns it (reduces circulating supply). It is the
// native analogue of the EVM's buyGas SubBalance, but burning rather than
// crediting a coinbase. Because it writes through the VM's versiondb, the debit
// commits atomically with the operation it pays for. If the payer cannot cover
// the fee (which Verify should already have prevented), Charge returns
// ErrInsufficientFunds and the caller MUST abort block acceptance — a key
// operation never takes effect unpaid.
func Charge(b Balances, acct Account, fee uint64) error {
	return b.Burn(acct, fee)
}
