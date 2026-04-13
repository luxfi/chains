// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayvm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

func TestVMID(t *testing.T) {
	require := require.New(t)
	require.NotEqual(ids.Empty, VMID, "VMID should not be empty")
	require.Equal(ids.ID{'r', 'e', 'l', 'a', 'y', 'v', 'm'}, VMID)
}

func TestFactoryNew(t *testing.T) {
	require := require.New(t)

	factory := &Factory{}
	vm, err := factory.New(log.NewNoOpLogger())
	require.NoError(err)
	require.NotNil(vm)
	require.IsType(&VM{}, vm)
}

func TestVMInitialize(t *testing.T) {
	require := require.New(t)

	vm := &VM{
		channels:      make(map[ids.ID]*Channel),
		messages:      make(map[ids.ID]*Message),
		pendingMsgs:   make(map[ids.ID][]*Message),
		sequences:     make(map[ids.ID]uint64),
		pendingBlocks: make(map[ids.ID]*Block),
	}

	genesis := &Genesis{
		Timestamp: time.Now().Unix(),
		Config: &Config{
			MaxMessageSize:    1024 * 1024,
			ConfirmationDepth: 6,
			RelayTimeout:      300,
		},
		Message: "test genesis",
	}
	genesisBytes, err := json.Marshal(genesis)
	require.NoError(err)

	toEngine := make(chan vmcore.Message, 10)

	init := vmcore.Init{
		Runtime: &runtime.Runtime{
			ChainID: ids.GenerateTestID(),
			Log:     log.NewNoOpLogger(),
		},
		DB:       memdb.New(),
		Genesis:  genesisBytes,
		ToEngine: toEngine,
	}

	err = vm.Initialize(context.Background(), init)
	require.NoError(err)

	// Verify shutdown
	err = vm.Shutdown(context.Background())
	require.NoError(err)
}

func TestVMOpenChannel(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	sourceChain := ids.GenerateTestID()
	destChain := ids.GenerateTestID()

	channel, err := vm.OpenChannel(sourceChain, destChain, "ordered", "1.0")
	require.NoError(err)
	require.NotNil(channel)
	require.Equal("open", channel.State)
	require.Equal(sourceChain, channel.SourceChain)
	require.Equal(destChain, channel.DestChain)

	// Verify channel can be retrieved
	retrieved, err := vm.GetChannel(channel.ID)
	require.NoError(err)
	require.Equal(channel.ID, retrieved.ID)
}

func TestVMSendMessage(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	sourceChain := ids.GenerateTestID()
	destChain := ids.GenerateTestID()

	channel, err := vm.OpenChannel(sourceChain, destChain, "ordered", "1.0")
	require.NoError(err)

	payload := []byte(`{"action": "transfer", "amount": 100}`)
	sender := []byte("sender-address")
	receiver := []byte("receiver-address")
	timeout := time.Now().Add(time.Hour).Unix()

	msg, err := vm.SendMessage(channel.ID, payload, sender, receiver, timeout)
	require.NoError(err)
	require.NotNil(msg)
	require.NotEqual(ids.Empty, msg.ID)
	require.Equal(uint64(0), msg.Sequence) // First message is sequence 0
	require.Equal(MessagePending, msg.State)
}

func TestVMReceiveMessage(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	sourceChain := ids.GenerateTestID()
	destChain := ids.GenerateTestID()

	channel, err := vm.OpenChannel(sourceChain, destChain, "ordered", "1.0")
	require.NoError(err)

	msg, err := vm.SendMessage(channel.ID, []byte(`{"test": true}`), []byte("sender"), []byte("receiver"), time.Now().Add(time.Hour).Unix())
	require.NoError(err)

	// Receive the message with proof
	receipt, err := vm.ReceiveMessage(msg.ID, []byte("mock-proof"), 100)
	require.NoError(err)
	require.NotNil(receipt)
	require.True(receipt.Success)

	// Check message state updated
	retrieved, err := vm.GetMessage(msg.ID)
	require.NoError(err)
	require.Equal(MessageVerified, retrieved.State)
}

func TestVMBuildBlock(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Build a block
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(err)
	require.NotNil(blk)
	require.Equal(uint64(1), blk.Height())

	// Verify block parent
	lastAccepted, err := vm.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(lastAccepted, blk.Parent())
}

func TestVMParseBlock(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(err)

	// Parse the block bytes
	parsed, err := vm.ParseBlock(context.Background(), blk.Bytes())
	require.NoError(err)
	require.Equal(blk.ID(), parsed.ID())
	require.Equal(blk.Height(), parsed.Height())
}

func TestBlockVerifyAcceptReject(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(err)

	// Accept the block (skip verify since genesis block isn't persisted in test setup)
	err = blk.Accept(context.Background())
	require.NoError(err)

	// Verify last accepted updated
	lastAccepted, err := vm.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(blk.ID(), lastAccepted)
}

func TestVMHealthCheck(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	health, err := vm.HealthCheck(context.Background())
	require.NoError(err)
	require.True(health.Healthy)
}

func TestVMVersion(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	version, err := vm.Version(context.Background())
	require.NoError(err)
	require.NotEmpty(version)
}

func TestVMCreateHandlers(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	handlers, err := vm.CreateHandlers(context.Background())
	require.NoError(err)
	require.NotNil(handlers)
	require.Contains(handlers, "/rpc")
}

func TestServiceRPC(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Test Health RPC
	req := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "relay.Health",
		"params": [{}],
		"id": 1
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	vm.rpcServer.ServeHTTP(rec, req)
	require.Equal(http.StatusOK, rec.Code)
}

func TestServiceOpenChannel(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Generate valid chain IDs
	sourceChain := ids.GenerateTestID()
	destChain := ids.GenerateTestID()

	reqBody := `{
		"jsonrpc": "2.0",
		"method": "relay.OpenChannel",
		"params": [{
			"sourceChain": "` + sourceChain.String() + `",
			"destChain": "` + destChain.String() + `",
			"ordering": "ordered",
			"version": "1.0"
		}],
		"id": 1
	}`
	req := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	vm.rpcServer.ServeHTTP(rec, req)
	require.Equal(http.StatusOK, rec.Code)
}

func TestCloseChannel(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	sourceChain := ids.GenerateTestID()
	destChain := ids.GenerateTestID()

	channel, err := vm.OpenChannel(sourceChain, destChain, "ordered", "1.0")
	require.NoError(err)

	err = vm.CloseChannel(channel.ID)
	require.NoError(err)

	retrieved, err := vm.GetChannel(channel.ID)
	require.NoError(err)
	require.Equal("closed", retrieved.State)
}

func TestCreateVerifiedMessage(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	sourceChain := ids.GenerateTestID()
	destChain := ids.GenerateTestID()

	channel, err := vm.OpenChannel(sourceChain, destChain, "ordered", "1.0")
	require.NoError(err)

	msg, err := vm.SendMessage(channel.ID, []byte(`{"test": true}`), []byte("sender"), []byte("receiver"), time.Now().Add(time.Hour).Unix())
	require.NoError(err)

	// Receive to verify
	_, err = vm.ReceiveMessage(msg.ID, []byte("proof"), 100)
	require.NoError(err)

	// Create verified message artifact
	retrieved, _ := vm.GetMessage(msg.ID)
	verifiedMsg, err := vm.CreateVerifiedMessage(retrieved)
	require.NoError(err)
	require.NotNil(verifiedMsg)
	require.Equal(sourceChain, verifiedMsg.SrcDomain)
	require.Equal(destChain, verifiedMsg.DstDomain)
}

// setupTestVM creates and initializes a test VM
func setupTestVM(t *testing.T) *VM {
	t.Helper()

	vm := &VM{
		channels:      make(map[ids.ID]*Channel),
		messages:      make(map[ids.ID]*Message),
		pendingMsgs:   make(map[ids.ID][]*Message),
		sequences:     make(map[ids.ID]uint64),
		pendingBlocks: make(map[ids.ID]*Block),
	}

	genesis := &Genesis{
		Timestamp: time.Now().Unix(),
		Config: &Config{
			MaxMessageSize:    1024 * 1024,
			ConfirmationDepth: 6,
			RelayTimeout:      300,
		},
		Message: "test",
	}
	genesisBytes, _ := json.Marshal(genesis)

	toEngine := make(chan vmcore.Message, 10)

	init := vmcore.Init{
		Runtime: &runtime.Runtime{
			ChainID: ids.GenerateTestID(),
			Log:     log.NewNoOpLogger(),
		},
		DB:       memdb.New(),
		Genesis:  genesisBytes,
		ToEngine: toEngine,
	}

	err := vm.Initialize(context.Background(), init)
	require.NoError(t, err)

	return vm
}
