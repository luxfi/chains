// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayvm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
)

// feegate.go states that a caller constructing a VM through this shim
// "transitively gets the NoUserTxPolicy{}". That is a claim about a value in
// another repo, held here only in prose.
//
// luxfi/relay's own feegate test builds `&VM{feePolicy: fee.NoUserTxPolicy{}}`
// — it assigns the field it then reads, so it passes unchanged if Initialize
// stops pinning the policy. This starts from the Factory the node uses, runs
// the real Initialize, and reads the policy back. It is the shim's claim, so
// it is the shim's test.
func TestAVMBuiltThroughThisShimTakesNoUserTransactions(t *testing.T) {
	vm := start(t)

	policy := vm.FeePolicy()
	if policy == nil {
		t.Fatal("FeePolicy() = nil; a chain that declares no policy is a chain with no declared cost")
	}
	if _, ok := policy.(fee.NoUserTxPolicy); !ok {
		t.Fatalf("FeePolicy() = %T, want fee.NoUserTxPolicy — R-Chain is service-only, "+
			"relayed messages arrive through consensus and there is no user mempool", policy)
	}
	if err := fee.Validate(policy); err != nil {
		t.Fatalf("the node's boot gate rejects R-Chain's own declaration: %v", err)
	}
}

// An uninitialized VM has not declared anything, and the shim's claim is about
// initialized VMs only. Pinned so the test above cannot be read as "any *VM
// refuses" — it is Initialize that pins the policy, and that is the statement.
func TestAnUninitializedVMHasNoPolicy(t *testing.T) {
	raw, err := (&Factory{}).New(log.Root())
	if err != nil {
		t.Fatalf("Factory.New: %v", err)
	}
	if policy := raw.(*VM).FeePolicy(); policy != nil {
		t.Fatalf("a VM that never ran Initialize reports policy %T; the policy is "+
			"pinned by Initialize and nowhere else", policy)
	}
}

// start builds a VM the way the node does — through the Factory — and runs
// Initialize against an in-memory database.
func start(t *testing.T) *VM {
	t.Helper()

	raw, err := (&Factory{}).New(log.Root())
	if err != nil {
		t.Fatalf("Factory.New: %v", err)
	}
	vm := raw.(*VM)

	genesis, err := json.Marshal(Genesis{})
	if err != nil {
		t.Fatalf("marshal genesis: %v", err)
	}
	init := vmcore.Init{
		Runtime: &runtime.Runtime{
			ChainID: ids.GenerateTestID(),
			Log:     log.NewNoOpLogger(),
		},
		DB:       memdb.New(),
		Genesis:  genesis,
		ToEngine: make(chan vmcore.Message, 1),
	}
	if err := vm.Initialize(context.Background(), init); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })

	// Initialize is the ChainVM contract's entry point, so what it returns must
	// still be the thing the plugin serves.
	var _ chain.ChainVM = vm
	return vm
}
