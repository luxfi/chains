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
	"strings"
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
	handler := v.endpoints()["/sendTransaction"]

	post := func(tx *Transaction) *httptest.ResponseRecorder {
		body, err := json.Marshal(tx)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/bc/z/sendTransaction", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	// A transaction with a shape no block can carry.
	shaped := func(fee uint64) *Transaction {
		return &Transaction{
			ID:         ids.GenerateTestID(), // ignored: the id is derived
			Type:       TransactionTypeTransfer,
			Nullifiers: [][]byte{[]byte("n")},
			Outputs:    []*ShieldedOutput{{Commitment: []byte("c")}},
			Proof:      &ZKProof{ProofType: "stark", ProofData: []byte("p")},
			Expiry:     100,
			Fee:        fee,
		}
	}

	if got := post(shaped(0)); got.Code != http.StatusPaymentRequired {
		t.Fatalf("POST /sendTransaction (zero-fee) status = %d, want 402", got.Code)
	}

	// A transaction that pays but can never enter a block occupies a slot in a
	// bounded pool forever, so the door refuses its shape too.
	empty := &Transaction{Fee: fee.MinTxFeeFloor, Expiry: 100}
	if got := post(empty); got.Code != http.StatusBadRequest {
		t.Fatalf("POST /sendTransaction (no inputs) status = %d, want 400", got.Code)
	}

	noExpiry := shaped(fee.MinTxFeeFloor)
	noExpiry.Expiry = 0
	if got := post(noExpiry); got.Code != http.StatusBadRequest {
		t.Fatalf("POST /sendTransaction (no expiry) status = %d, want 400", got.Code)
	}

	paid := shaped(fee.MinTxFeeFloor)
	got := post(paid)
	if got.Code != http.StatusOK {
		t.Fatalf("POST /sendTransaction (paid) status = %d body=%q, want 200", got.Code, got.Body.String())
	}
	if !strings.Contains(got.Body.String(), paid.ComputeID().String()) {
		t.Fatalf("the reply must name the derived id, got %q", got.Body.String())
	}
	if v.mempool.Size() != 1 {
		t.Fatalf("mempool size = %d, want 1", v.mempool.Size())
	}

	// A method the endpoint does not serve is refused, not silently accepted.
	req := httptest.NewRequest(http.MethodGet, "/v1/bc/z/sendTransaction", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /sendTransaction status = %d, want 405", w.Code)
	}
}
