// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

func newKeyVMForFeeTest(t *testing.T) *VM {
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
	}); err != nil {
		t.Fatalf("init keyvm: %v", err)
	}
	return v
}

func TestKeyVM_FeePolicy_AttachedAtInit(t *testing.T) {
	v := newKeyVMForFeeTest(t)
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

func TestKeyVM_FeePolicy_RejectsZeroFee(t *testing.T) {
	v := newKeyVMForFeeTest(t)
	if err := v.gateUserFee(0); !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("gateUserFee(0) = %v, want ErrInsufficientFee", err)
	}
}

func TestKeyVM_FeePolicy_AcceptsMinFee(t *testing.T) {
	v := newKeyVMForFeeTest(t)
	if err := v.gateUserFee(fee.MinTxFeeFloor); err != nil {
		t.Fatalf("gateUserFee(MinTxFeeFloor) = %v, want nil", err)
	}
}

// Service-level gate test: CreateKey refuses zero-fee requests before
// any key material is allocated. We do not assert on the reply because
// the fee error short-circuits before the CreateKey path runs.
func TestKeyVM_Service_CreateKey_RejectsZeroFee(t *testing.T) {
	v := newKeyVMForFeeTest(t)
	s := &Service{vm: v}
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	reply := &CreateKeyReply{}
	err := s.CreateKey(req, &CreateKeyArgs{Name: "x", Algorithm: "ml-dsa-65", Fee: 0}, reply)
	if !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("Service.CreateKey(zero-fee) = %v, want ErrInsufficientFee", err)
	}
}
