// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/luxfi/chains/dexvm/txs"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	"github.com/luxfi/vm"
	"github.com/luxfi/warp"
)

// newChainVMForFeeTest returns a fully-initialized ChainVM wired with the
// canonical D-Chain FlatPolicy. networkID=96369 (mainnet) so the asset
// is the legacy UTXO_ASSET_ID, the same on-chain literal mainnet pays.
func newChainVMForFeeTest(t *testing.T) *ChainVM {
	t.Helper()
	logger := log.NewNoOpLogger()
	cvm := NewChainVM(logger)
	rt := &runtime.Runtime{
		ChainID:   ids.GenerateTestID(),
		NetworkID: 96369,
		Log:       logger,
	}
	if err := cvm.Initialize(context.Background(), vm.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		ToEngine: make(chan vm.Message, 8),
		Sender:   warp.FakeSender{},
		Log:      logger,
	}); err != nil {
		t.Fatalf("init dexvm: %v", err)
	}
	return cvm
}

func TestDexVM_FeePolicy_AttachedAtInit(t *testing.T) {
	cvm := newChainVMForFeeTest(t)
	if cvm.FeePolicy() == nil {
		t.Fatal("FeePolicy() = nil after Initialize; want non-nil FlatPolicy")
	}
	if got := cvm.FeePolicy().MinTxFee(); got != fee.MinTxFeeFloor {
		t.Errorf("MinTxFee() = %d, want %d", got, fee.MinTxFeeFloor)
	}
	if err := fee.Validate(cvm.FeePolicy()); err != nil {
		t.Errorf("fee.Validate = %v, want nil", err)
	}
}

func TestDexVM_FeePolicy_RejectsZeroFee(t *testing.T) {
	cvm := newChainVMForFeeTest(t)
	tx := &txs.PlaceOrderTx{BaseTx: txs.BaseTx{
		TxType:   txs.TxPlaceOrder,
		From:     ids.GenerateTestShortID(),
		Nonce:    1,
		GasPrice: 0, // <-- the bug we are closing
		GasLimit: 0,
	}, PoolID: [32]byte{1}, Side: 0, Price: 1, Size: 1}
	b, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	err = cvm.SubmitTx(b)
	if !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("SubmitTx(zero-fee) = %v, want ErrInsufficientFee", err)
	}
}

func TestDexVM_FeePolicy_AcceptsMinFee(t *testing.T) {
	cvm := newChainVMForFeeTest(t)
	// GasPrice * GasLimit = MinTxFeeFloor (1_000_000 nLUX = 1 mLUX).
	tx := &txs.PlaceOrderTx{BaseTx: txs.BaseTx{
		TxType:   txs.TxPlaceOrder,
		From:     ids.GenerateTestShortID(),
		Nonce:    1,
		GasPrice: 1_000,
		GasLimit: 1_000,
	}, PoolID: [32]byte{1}, Side: 0, Price: 1, Size: 1}
	b, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := cvm.SubmitTx(b); err != nil {
		t.Fatalf("SubmitTx(min-fee) = %v, want nil", err)
	}
}

func TestDexVM_FeePolicy_RejectsUndecodable(t *testing.T) {
	cvm := newChainVMForFeeTest(t)
	if err := cvm.SubmitTx([]byte("not json")); err == nil {
		t.Fatal("SubmitTx(garbage) = nil, want decode error")
	}
}
