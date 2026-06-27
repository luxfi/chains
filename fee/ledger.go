// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fee

import (
	"encoding/binary"
	"fmt"
)

// KV is the minimal key/value surface Ledger needs. It is the read/write subset
// of luxfi/database.Database (satisfied by versiondb, memdb, and any backing
// store), declared locally so the settlement primitive does not pin a database
// module version — keeping it buildable beside any VM under GOWORK=off.
type KV interface {
	Has(key []byte) (bool, error)
	Get(key []byte) ([]byte, error)
	Put(key []byte, value []byte) error
}

var (
	// balPrefix namespaces per-account balance entries: balPrefix||acct -> u64.
	balPrefix = []byte("fee/bal/")
	// burnedKey holds the cumulative burned-supply counter: -> u64.
	burnedKey = []byte("fee/burned")
)

// Ledger is the canonical KV-backed Balances implementation. It writes to the
// VM's state KV (a versiondb in production), so every Credit/Burn participates
// in the block's atomic commit: a fee burn and the operation it pays for land
// together or not at all. Balances are nLUX (1e-6 LUX), matching the
// node/vms/types/fee floor units.
type Ledger struct {
	kv KV
}

// NewLedger returns a Ledger over kv. kv is the VM's state database; in a block
// Accept it is the versiondb whose Commit the block performs.
func NewLedger(kv KV) *Ledger {
	return &Ledger{kv: kv}
}

func balKey(acct Account) []byte {
	k := make([]byte, 0, len(balPrefix)+len(acct))
	k = append(k, balPrefix...)
	k = append(k, acct[:]...)
	return k
}

// readU64 returns the uint64 stored at key, or 0 if the key is absent.
func (l *Ledger) readU64(key []byte) (uint64, error) {
	ok, err := l.kv.Has(key)
	if err != nil {
		return 0, fmt.Errorf("fee ledger: has %x: %w", key, err)
	}
	if !ok {
		return 0, nil
	}
	b, err := l.kv.Get(key)
	if err != nil {
		return 0, fmt.Errorf("fee ledger: get %x: %w", key, err)
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("fee ledger: corrupt u64 at %x: len %d", key, len(b))
	}
	return binary.BigEndian.Uint64(b), nil
}

func (l *Ledger) writeU64(key []byte, v uint64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	if err := l.kv.Put(key, b[:]); err != nil {
		return fmt.Errorf("fee ledger: put %x: %w", key, err)
	}
	return nil
}

// Balance returns acct's spendable nLUX (0 if never funded).
func (l *Ledger) Balance(acct Account) (uint64, error) {
	return l.readU64(balKey(acct))
}

// Credit adds amount nLUX to acct. Overflow is refused (fail-secure: minting
// must never silently wrap to a smaller balance).
func (l *Ledger) Credit(acct Account, amount uint64) error {
	if amount == 0 {
		return nil
	}
	key := balKey(acct)
	cur, err := l.readU64(key)
	if err != nil {
		return err
	}
	next, over := addOverflow(cur, amount)
	if over {
		return ErrBalanceOverflow
	}
	return l.writeU64(key, next)
}

// Burn debits amount nLUX from acct and reduces circulating supply by the same
// amount (the burned counter rises). It is the fee settlement op: it returns
// ErrInsufficientFunds if acct cannot cover amount, leaving state untouched.
func (l *Ledger) Burn(acct Account, amount uint64) error {
	if amount == 0 {
		return nil
	}
	key := balKey(acct)
	cur, err := l.readU64(key)
	if err != nil {
		return err
	}
	if cur < amount {
		return ErrInsufficientFunds
	}
	burned, err := l.readU64(burnedKey)
	if err != nil {
		return err
	}
	nextBurned, over := addOverflow(burned, amount)
	if over {
		// Burned-supply accounting must never wrap; refuse rather than corrupt
		// the audit total. Unreachable in practice (burned <= genesis supply).
		return ErrBalanceOverflow
	}
	// Debit first, then record the burn. Both writes hit the same versiondb and
	// commit atomically with the block; a mid-sequence failure aborts the block.
	if err := l.writeU64(key, cur-amount); err != nil {
		return err
	}
	return l.writeU64(burnedKey, nextBurned)
}

// Burned returns cumulative burned supply in nLUX.
func (l *Ledger) Burned() (uint64, error) {
	return l.readU64(burnedKey)
}

// Ledger is a Balances.
var _ Balances = (*Ledger)(nil)
