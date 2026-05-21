// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"context"
	"errors"
	"testing"

	luxai "github.com/luxfi/ai/pkg/aivm"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

func newAIVMForFeeTest(t *testing.T) *VM {
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
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	}); err != nil {
		t.Fatalf("init aivm: %v", err)
	}
	return v
}

func TestAIVM_FeePolicy_AttachedAtInit(t *testing.T) {
	v := newAIVMForFeeTest(t)
	defer v.Shutdown(context.Background())
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

func TestAIVM_FeePolicy_RejectsZeroFee(t *testing.T) {
	v := newAIVMForFeeTest(t)
	defer v.Shutdown(context.Background())
	task := &luxai.Task{ID: "t-zero", Fee: 0}
	if err := v.SubmitTask(task); !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("SubmitTask(zero-fee) = %v, want ErrInsufficientFee", err)
	}
}

func TestAIVM_FeePolicy_AcceptsMinFee(t *testing.T) {
	v := newAIVMForFeeTest(t)
	defer v.Shutdown(context.Background())
	task := &luxai.Task{ID: "t-paid", Fee: fee.MinTxFeeFloor}
	// gateUserTask must return nil; downstream core.SubmitTask may fail
	// for reasons unrelated to fees (model not registered, etc.) — we
	// assert on the fee gate path only.
	if err := v.gateUserTask(task); err != nil {
		t.Fatalf("gateUserTask(min-fee) = %v, want nil", err)
	}
}
