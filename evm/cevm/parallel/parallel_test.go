// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && lux_cevm_native

package parallel

import (
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/luxfi/chains/evm/cevm"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/geth/core/types"
)

// These run against the linked library and hold it to go_bridge.h (ABI 7).

// A batch that carries code is declined on every backend the library offers:
// gpu_execute_block passes no host, so it would run the code as a message on
// its whole limit, which is not the tx's gas. Declined means ErrDeclined and
// no result.
func TestABatchWithCodeIsDeclinedOnEveryBackend(t *testing.T) {
	tx := cevm.Transaction{
		From:     [20]byte{0x11},
		To:       [20]byte{0x22},
		HasTo:    true,
		Code:     []byte{0x60, 0x01, 0x60, 0x01, 0x01, 0x50, 0x00}, // 1+1, POP, STOP
		GasLimit: 100_000,
		GasPrice: 1,
	}
	for _, b := range cevm.AvailableBackends() {
		t.Run(cevm.BackendName(b), func(t *testing.T) {
			r, err := cevm.ExecuteBlock(b, 0, []cevm.Transaction{tx}, nil, nil)
			if !errors.Is(err, cevm.ErrDeclined) {
				t.Fatalf("ExecuteBlock = %v, want ErrDeclined", err)
			}
			if r != nil {
				t.Errorf("a declined block came back with a result: %+v", r)
			}
		})
	}
}

// A block of plain transfers from funded senders, end to end through the
// executor: a GPU lane runs it and receipts every transfer at 21000 gas; a
// CPU lane, which runs nothing through the Go entry, declines it to the Go
// EVM. Neither is an error. A GPU lane is listed when the library was built
// with it, whether or not this host has the device, and one without it
// declines too: that lane is skipped.
func TestAPlainTransferBlockIsReceiptedOrDeclined(t *testing.T) {
	const n = 8
	sdb := newState(t)
	header := newHeader()
	header.BaseFee = big.NewInt(1)
	header.Coinbase = common.Address{0xC0}

	txs := make(types.Transactions, n)
	from := senders(n)
	for i := range txs {
		sdb.AddBalance(from[i], uint256.NewInt(1_000_000_000_000_000_000), tracing.BalanceChangeUnspecified)
		to := common.Address{0xB0, byte(i + 1)} // fresh: not in the state
		txs[i] = types.NewTx(&types.LegacyTx{To: &to, Value: big.NewInt(1), Gas: 21000, GasPrice: big.NewInt(1)})
	}

	for _, b := range cevm.AvailableBackends() {
		t.Run(cevm.BackendName(b), func(t *testing.T) {
			receipts, err := (&Executor{CevmBackend: b}).run(chainConfig(), header, txs, from, sdb)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if b != cevm.GPUMetal && b != cevm.GPUCUDA {
				if receipts != nil {
					t.Fatalf("CPU lane %s receipted a block; it runs none", cevm.BackendName(b))
				}
				return
			}
			if receipts == nil {
				t.Skipf("GPU lane %s declined a block of funded plain transfers: no device on this host",
					cevm.BackendName(b))
			}
			if len(receipts) != n {
				t.Fatalf("%d receipts for %d transactions", len(receipts), n)
			}
			for i, r := range receipts {
				if r.Status != types.ReceiptStatusSuccessful || r.GasUsed != 21000 {
					t.Errorf("receipt %d: status %d gas %d, want success at 21000", i, r.Status, r.GasUsed)
				}
			}
		})
	}
}
