// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// newZKVMForFeeTest builds an initialized Z-Chain VM wired with the
// canonical FlatPolicy at MinTxFeeFloor. networkID=96369 -> the legacy
// mainnet UTXO_ASSET_ID.
func newZKVMForFeeTest(t *testing.T) *VM {
	t.Helper()
	logger := log.NewNoOpLogger()
	rt := &runtime.Runtime{
		ChainID:   ids.GenerateTestID(),
		NetworkID: 96369,
		Log:       logger,
	}
	v := &VM{}
	if err := v.Initialize(context.Background(), vmcore.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  []byte(`{"timestamp":0}`),
	}); err != nil {
		t.Fatalf("init zkvm: %v", err)
	}
	return v
}

func TestZKVM_FeePolicy_AttachedAtInit(t *testing.T) {
	v := newZKVMForFeeTest(t)
	if v.FeePolicy() == nil {
		t.Fatal("FeePolicy() = nil; want non-nil FlatPolicy")
	}
	if got := v.FeePolicy().MinTxFee(); got != fee.MinTxFeeFloor {
		t.Errorf("MinTxFee() = %d, want %d", got, fee.MinTxFeeFloor)
	}
	if err := fee.Validate(v.FeePolicy()); err != nil {
		t.Errorf("fee.Validate = %v, want nil", err)
	}
}

func TestZKVM_FeePolicy_RejectsZeroFee(t *testing.T) {
	v := newZKVMForFeeTest(t)
	tx := &Transaction{
		ID:   ids.GenerateTestID(),
		Type: TransactionTypeTransfer,
		Fee:  0, // <-- the bug we are closing
	}
	if err := v.gateUserTx(tx); !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("gateUserTx(zero-fee) = %v, want ErrInsufficientFee", err)
	}
}

func TestZKVM_FeePolicy_AcceptsMinFee(t *testing.T) {
	v := newZKVMForFeeTest(t)
	tx := &Transaction{
		ID:   ids.GenerateTestID(),
		Type: TransactionTypeTransfer,
		Fee:  fee.MinTxFeeFloor,
	}
	if err := v.gateUserTx(tx); err != nil {
		t.Fatalf("gateUserTx(min-fee) = %v, want nil", err)
	}
}

// HTTP-level test: the public /sendTransaction handler MUST refuse a
// zero-fee tx with a 4xx; a paying tx admits into the mempool.
func TestZKVM_HTTP_SendTransaction_FeePolicy(t *testing.T) {
	v := newZKVMForFeeTest(t)
	mux := NewRPCHandler(v)

	post := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/sendTransaction", bytes.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	zero, _ := json.Marshal(&Transaction{ID: ids.GenerateTestID(), Fee: 0})
	if got := post(zero); got.Code < 400 {
		t.Fatalf("POST /sendTransaction (zero-fee) status = %d, want >= 400", got.Code)
	}

	paid, _ := json.Marshal(&Transaction{ID: ids.GenerateTestID(), Fee: fee.MinTxFeeFloor})
	if got := post(paid); got.Code != http.StatusOK {
		t.Fatalf("POST /sendTransaction (paid) status = %d body=%q, want 200", got.Code, got.Body.String())
	}
}
