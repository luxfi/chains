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
	// Public-BFT-safe default: TEE attestation NOT required.
	// Providers without TEE register via the optimistic-verification
	// flow (challenge period + fraud proofs).
	require.False(cfg.RequireTEEAttestation, "public-chain default must NOT require TEE")
	require.Equal(ModeOptimistic, cfg.VerificationMode, "public-chain default is optimistic mode")
	require.Equal("primary", cfg.HostChainID, "default host chain is primary network")
	require.Equal(uint64(100), cfg.ChallengeWindowBlocks)
	require.Equal(3, cfg.RedundancyFactor)
	require.Equal(uint8(50), cfg.MinTrustScore)
	require.Equal("30s", cfg.AttestationTimeout)
	require.Equal(1000, cfg.MaxTaskQueueSize)
	require.Equal("5m", cfg.TaskTimeout)
	require.Equal(uint64(1000000000), cfg.BaseReward) // 1 LUX
	require.Equal("1h", cfg.EpochDuration)
	require.Equal(100, cfg.MerkleAnchorFreq)
}

// TestDefaultPermissionedConfig pins the permissioned-subnet opt-in
// path. NOT for public mainnet use.
func TestDefaultPermissionedConfig(t *testing.T) {
	require := require.New(t)

	cfg := DefaultPermissionedConfig()
	require.True(cfg.RequireTEEAttestation, "permissioned config requires TEE")
	require.Equal(ModeTEEAttested, cfg.VerificationMode)
	require.Equal(uint8(70), cfg.MinTrustScore)
}

// TestVerificationMode_PublicBFTSafe pins that the default mode is
// one of the public-BFT-safe modes (Optimistic or MultiPartyRedundant),
// NEVER TEE-attested as the trust root.
func TestVerificationMode_PublicBFTSafe(t *testing.T) {
	require := require.New(t)
	cfg := DefaultConfig()
	publicSafe := cfg.VerificationMode == ModeOptimistic || cfg.VerificationMode == ModeMultiPartyRedundant
	require.True(publicSafe, "default VerificationMode must be public-BFT-safe (Optimistic or MultiPartyRedundant), got %v", cfg.VerificationMode)
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

func TestBlockName(t *testing.T) {
	require := require.New(t)

	blk := &Block{
		ParentID_:  ids.Empty,
		Height_:    1,
		Timestamp_: time.Unix(1700000000, 0),
	}
	require.NoError(blk.name())
	require.NotEqual(ids.Empty, blk.ID_)
	require.NotEmpty(blk.bytes)

	// Naming is deterministic.
	id := blk.ID_
	require.NoError(blk.name())
	require.Equal(id, blk.ID_)

	// Different height → different ID.
	blk2 := &Block{
		ParentID_:  ids.Empty,
		Height_:    2,
		Timestamp_: time.Unix(1700000000, 0),
	}
	require.NoError(blk2.name())
	require.NotEqual(id, blk2.ID_)
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
	require.NoError(blk.name())

	require.Equal(parentID, blk.Parent())
	require.Equal(parentID, blk.ParentID())
	require.Equal(uint64(42), blk.Height())
	require.Equal(now, blk.Timestamp())
	require.NotNil(blk.Bytes())
	require.Equal(uint8(0), blk.Status(), "a block with no chain is not accepted anywhere")
}

// A block with no chain behind it has no parent to sit on, no state to check
// against and no chain id to be named by. Every question Verify asks of it is
// unanswerable, and it used to answer "no objection" to all of them — so a
// hand-built Block satisfied the one gate consensus has.
func TestADetachedBlockIsRefused(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	blk := &Block{Height_: 1, Timestamp_: time.Now()}
	require.ErrorIs(blk.Verify(ctx), ErrDetachedBlock)
	require.ErrorIs(blk.Accept(ctx), ErrDetachedBlock)
	require.ErrorIs(blk.Reject(ctx), ErrDetachedBlock)
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

	// A VM that has not opened a chain has no head to report, and reporting one
	// anyway is how a caller builds on a block that does not exist.
	vm := &VM{}
	_, err := vm.LastAccepted(context.Background())
	require.ErrorIs(err, ErrNotInitialized)

	tip := &Block{Height_: 7}
	require.NoError(tip.name())
	vm.lastAccepted = tip

	id, err := vm.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(tip.ID_, id)
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

	// Each key is a route the node mounts under /v1/bc/<chainID>, so the set of
	// keys IS the chain's public surface. Collapsing them behind one key hides
	// every endpoint but the one named.
	keys := make([]string, 0, len(handlers))
	for k := range handlers {
		keys = append(keys, k)
	}
	require.ElementsMatch([]string{
		"/providers",
		"/providers/register",
		"/tasks",
		"/tasks/submit",
		"/tasks/result",
		"/models",
		"/attestation/verify",
		"/rewards/claim",
		"/rewards/stats",
		"/stats",
		"/merkle",
		"/health",
	}, keys)
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
