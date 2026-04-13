// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

func TestVMID(t *testing.T) {
	require := require.New(t)
	require.NotEqual(ids.Empty, VMID, "VMID should not be empty")
	require.Equal(ids.ID{'a', 'i', 'v', 'm'}, VMID)
}

func TestFactoryNew(t *testing.T) {
	require := require.New(t)

	factory := &Factory{}
	vm, err := factory.New(log.NewNoOpLogger())
	require.NoError(err)
	require.NotNil(vm)
	require.IsType(&VM{}, vm)
}

func TestDefaultConfig(t *testing.T) {
	require := require.New(t)

	cfg := DefaultConfig()
	require.Equal(100, cfg.MaxProvidersPerNode)
	require.Equal(10, cfg.MaxTasksPerProvider)
	require.True(cfg.RequireTEEAttestation)
	require.Equal(uint8(50), cfg.MinTrustScore)
	require.Equal("30s", cfg.AttestationTimeout)
	require.Equal(1000, cfg.MaxTaskQueueSize)
	require.Equal("5m", cfg.TaskTimeout)
	require.Equal(uint64(1000000000), cfg.BaseReward) // 1 LUX
	require.Equal("1h", cfg.EpochDuration)
	require.Equal(100, cfg.MerkleAnchorFreq)
}

func TestConfigJSON(t *testing.T) {
	require := require.New(t)

	cfg := DefaultConfig()
	data, err := json.Marshal(cfg)
	require.NoError(err)

	var parsed Config
	require.NoError(json.Unmarshal(data, &parsed))
	require.Equal(cfg.MaxProvidersPerNode, parsed.MaxProvidersPerNode)
	require.Equal(cfg.RequireTEEAttestation, parsed.RequireTEEAttestation)
	require.Equal(cfg.BaseReward, parsed.BaseReward)
}

func TestGenesisJSON(t *testing.T) {
	require := require.New(t)

	g := &Genesis{
		Version:   1,
		Message:   "test genesis",
		Timestamp: time.Now().Unix(),
	}
	data, err := json.Marshal(g)
	require.NoError(err)

	var parsed Genesis
	require.NoError(json.Unmarshal(data, &parsed))
	require.Equal(g.Version, parsed.Version)
	require.Equal(g.Message, parsed.Message)
	require.Equal(g.Timestamp, parsed.Timestamp)
}

func TestBlockComputeID(t *testing.T) {
	require := require.New(t)

	blk := &Block{
		ParentID_:  ids.Empty,
		Height_:    1,
		Timestamp_: time.Unix(1700000000, 0),
	}

	id := blk.computeID()
	require.NotEqual(ids.Empty, id)

	// Same block data → same ID (deterministic).
	id2 := blk.computeID()
	require.Equal(id, id2)

	// Different height → different ID.
	blk2 := &Block{
		ParentID_:  ids.Empty,
		Height_:    2,
		Timestamp_: time.Unix(1700000000, 0),
	}
	require.NotEqual(id, blk2.computeID())
}

func TestBlockInterface(t *testing.T) {
	require := require.New(t)

	parentID := ids.GenerateTestID()
	now := time.Now().Truncate(time.Millisecond)

	blk := &Block{
		ParentID_:  parentID,
		Height_:    42,
		Timestamp_: now,
	}
	blk.ID_ = blk.computeID()

	require.Equal(parentID, blk.Parent())
	require.Equal(parentID, blk.ParentID())
	require.Equal(uint64(42), blk.Height())
	require.Equal(now, blk.Timestamp())
	require.NotNil(blk.Bytes())
}

func TestBlockVerify(t *testing.T) {
	require := require.New(t)

	blk := &Block{Height_: 1, Timestamp_: time.Now()}
	require.NoError(blk.Verify(context.Background()))
}

func TestVMNotInitialized(t *testing.T) {
	require := require.New(t)

	vm := &VM{running: false}

	require.ErrorIs(vm.SubmitTask(nil), ErrNotInitialized)
	require.ErrorIs(vm.SubmitResult(nil), ErrNotInitialized)

	_, err := vm.GetTask("test")
	require.ErrorIs(err, ErrNotInitialized)

	_, err = vm.ClaimRewards("test")
	require.ErrorIs(err, ErrNotInitialized)

	_, err = vm.GetRewardStats("test")
	require.ErrorIs(err, ErrNotInitialized)

	_, err = vm.VerifyGPUAttestation(nil)
	require.ErrorIs(err, ErrNotInitialized)

	require.Nil(vm.GetProviders())
	require.Nil(vm.GetModels())
	require.Nil(vm.GetStats())
	require.Equal([32]byte{}, vm.GetMerkleRoot())
}

func TestVMVersion(t *testing.T) {
	require := require.New(t)

	vm := &VM{}
	v, err := vm.Version(context.Background())
	require.NoError(err)
	require.Equal("v1.0.0", v)
}

func TestVMHealthCheck(t *testing.T) {
	require := require.New(t)

	vm := &VM{running: true}
	result, err := vm.HealthCheck(context.Background())
	require.NoError(err)
	require.True(result.Healthy)

	vm.running = false
	result, err = vm.HealthCheck(context.Background())
	require.NoError(err)
	require.False(result.Healthy)
}

func TestVMLastAccepted(t *testing.T) {
	require := require.New(t)

	expectedID := ids.GenerateTestID()
	vm := &VM{lastAcceptedID: expectedID}

	id, err := vm.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(expectedID, id)
}

func TestVMSetState(t *testing.T) {
	require := require.New(t)

	vm := &VM{}
	require.NoError(vm.SetState(context.Background(), 0))
	require.NoError(vm.SetState(context.Background(), 1))
}

func TestVMSetPreference(t *testing.T) {
	require := require.New(t)

	vm := &VM{}
	require.NoError(vm.SetPreference(context.Background(), ids.GenerateTestID()))
}

func TestVMConnectedDisconnected(t *testing.T) {
	require := require.New(t)

	vm := &VM{}
	nodeID := ids.GenerateTestNodeID()

	require.NoError(vm.Connected(context.Background(), nodeID, nil))
	require.NoError(vm.Disconnected(context.Background(), nodeID))
}

func TestVMShutdownIdempotent(t *testing.T) {
	require := require.New(t)

	vm := &VM{running: false}
	require.NoError(vm.Shutdown(context.Background()))
	require.NoError(vm.Shutdown(context.Background()))
}

func TestVMCreateHandlers(t *testing.T) {
	require := require.New(t)

	vm := &VM{}
	handlers, err := vm.CreateHandlers(context.Background())
	require.NoError(err)
	require.Contains(handlers, "/rpc")
}

func TestProviderRegJSON(t *testing.T) {
	require := require.New(t)

	reg := ProviderReg{
		ProviderID:    "provider-1",
		WalletAddress: "0xdead",
		Endpoint:      "https://gpu.example.com",
	}
	data, err := json.Marshal(reg)
	require.NoError(err)

	var parsed ProviderReg
	require.NoError(json.Unmarshal(data, &parsed))
	require.Equal(reg.ProviderID, parsed.ProviderID)
	require.Equal(reg.Endpoint, parsed.Endpoint)
}
