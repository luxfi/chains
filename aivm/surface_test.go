// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// surface_test.go covers what the VM exposes to the node and to callers: the
// ChainVM lifecycle, the AI task/provider surface, and the HTTP endpoints. These
// are the paths a request actually takes, and the ones where a refusal has to
// come back as a refusal rather than as a zero value.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/stretchr/testify/require"

	aicore "github.com/luxfi/ai/pkg/aivm"
	"github.com/luxfi/ai/pkg/attestation"
)

// initWith starts a VM with an explicit config blob, for the branches that only
// a non-default policy reaches.
func initWith(t *testing.T, cfg Config) *VM {
	t.Helper()
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: log.NewNoOpLogger()},
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      log.NewNoOpLogger(),
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
		Config:   raw,
	}))
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	return vm
}

// -----------------------------------------------------------------------------
// Initialize.
// -----------------------------------------------------------------------------

func TestInitializeRefusesMalformedInput(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	rt := func() *runtime.Runtime {
		return &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: log.NewNoOpLogger()}
	}

	err := (&VM{}).Initialize(ctx, vmcore.Init{
		Runtime: rt(), DB: memdb.New(), Log: log.NewNoOpLogger(),
		Config: []byte(`{not json`),
	})
	require.ErrorContains(err, "config")

	err = (&VM{}).Initialize(ctx, vmcore.Init{
		Runtime: rt(), DB: memdb.New(), Log: log.NewNoOpLogger(),
		Genesis: []byte(`{not json`),
	})
	require.ErrorContains(err, "genesis")

	// A runtime whose logger is not a logger leaves the VM with nothing to
	// report through.
	err = (&VM{}).Initialize(ctx, vmcore.Init{
		Runtime: &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369},
		DB:      memdb.New(),
	})
	require.ErrorContains(err, "logger")
}

// A permissioned deployment is a policy choice, and it has to survive the round
// trip through the config blob or the node runs the public policy while its
// operator believes otherwise.
func TestPermissionedConfigSurvivesInitialize(t *testing.T) {
	vm := initWith(t, DefaultPermissionedConfig())
	require.True(t, vm.config.RequireTEEAttestation)
	require.Equal(t, ModeTEEAttested, vm.config.VerificationMode)
}

// -----------------------------------------------------------------------------
// The AI surface.
// -----------------------------------------------------------------------------

func TestProviderRegistrationPolicies(t *testing.T) {
	require := require.New(t)

	// Public path: no attestation needed, the bond and the challenge flow carry
	// correctness.
	open := oneVM(t)
	require.NoError(open.RegisterProvider(&aicore.Provider{ID: "p1", GPUs: []aicore.GPUInfo{{Model: "gb10"}}}))
	require.Len(open.GetProviders(), 1)

	// Permissioned path: a provider with no attestation at all is refused.
	gated := initWith(t, DefaultPermissionedConfig())
	err := gated.RegisterProvider(&aicore.Provider{ID: "p2"})
	require.ErrorContains(err, "TEE attestation")

	// An attestation that does not verify is refused too.
	err = gated.RegisterProvider(&aicore.Provider{ID: "p3", GPUAttestation: &attestation.GPUAttestation{}})
	require.Error(err)
	require.Empty(gated.GetProviders())
}

// Every read path answers "not initialized" once the VM has stopped, rather than
// a zero value a caller would read as an empty answer.
func TestTheSurfaceClosesOnShutdown(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	vm := oneVM(t)
	require.NoError(vm.SubmitTask(&aicore.Task{ID: "t1", Fee: 1_000_000_000_000_000}))
	task, err := vm.GetTask("t1")
	require.NoError(err)
	require.Equal("t1", task.ID)
	require.NoError(vm.SubmitResult(&aicore.TaskResult{TaskID: "t1", ProviderID: "p1"}))
	require.NotNil(vm.GetStats())
	require.NotNil(vm.GetModels())

	_, err = vm.GetRewardStats("nobody")
	require.Error(err)
	// A provider with nothing owing claims zero rather than failing.
	claimed, err := vm.ClaimRewards("nobody")
	require.NoError(err)
	require.Equal("0", claimed)
	_, err = vm.VerifyGPUAttestation(&attestation.GPUAttestation{})
	require.Error(err)

	require.NoError(vm.Shutdown(ctx))

	require.ErrorIs(vm.SubmitTask(&aicore.Task{ID: "t2"}), ErrNotInitialized)
	require.ErrorIs(vm.SubmitResult(&aicore.TaskResult{TaskID: "t1"}), ErrNotInitialized)
	require.ErrorIs(vm.RegisterProvider(&aicore.Provider{ID: "p"}), ErrNotInitialized)
	_, err = vm.GetTask("t1")
	require.ErrorIs(err, ErrNotInitialized)
	_, err = vm.ClaimRewards("p")
	require.ErrorIs(err, ErrNotInitialized)
	_, err = vm.GetRewardStats("p")
	require.ErrorIs(err, ErrNotInitialized)
	_, err = vm.VerifyGPUAttestation(nil)
	require.ErrorIs(err, ErrNotInitialized)
	require.Nil(vm.GetProviders())
	require.Nil(vm.GetModels())
	require.Nil(vm.GetStats())
	require.Equal([32]byte{}, vm.GetMerkleRoot())
	_, err = vm.BuildBlock(ctx)
	require.ErrorIs(err, ErrNotInitialized)

	health, err := vm.HealthCheck(ctx)
	require.NoError(err)
	require.False(health.Healthy)
}

// A submission wakes the builder. Returning only on ctx.Done() would mean
// BuildBlock is never called and the chain never leaves genesis.
func TestASubmissionWakesTheBuilder(t *testing.T) {
	require := require.New(t)
	vm := oneVM(t)

	require.NoError(vm.SubmitTask(&aicore.Task{ID: "t1", Fee: 1_000_000_000_000_000}))
	_, err := vm.WaitForEvent(context.Background())
	require.NoError(err)

	// And a cancelled context releases the waiter rather than hanging.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = vm.WaitForEvent(ctx)
	require.Error(err)
}

func TestUnknownBlocksAndHeightsAreNotFound(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	vm := oneVM(t)

	_, err := vm.GetBlock(ctx, ids.GenerateTestID())
	require.Error(err)

	// A stored value that is not a block does not become one by being read.
	stray := ids.GenerateTestID()
	require.NoError(vm.db.Put(blockKey(stray), []byte("not a block")))
	_, err = vm.GetBlock(ctx, stray)
	require.Error(err)

	require.NoError(vm.SetPreference(ctx, ids.GenerateTestID()))
	require.NoError(vm.SetState(ctx, 1))
}

// -----------------------------------------------------------------------------
// The HTTP surface.
// -----------------------------------------------------------------------------

// call drives one endpoint through the handler the node would mount.
func call(t *testing.T, vm *VM, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
		r = nil
	case string:
		r = bytes.NewBufferString(b)
	default:
		raw, err := json.Marshal(b)
		require.NoError(t, err)
		r = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, r)
	w := httptest.NewRecorder()
	h, err := vm.NewHTTPHandler(context.Background())
	require.NoError(t, err)
	h.ServeHTTP(w, req)
	return w
}

// Each endpoint answers at its own mount, refuses the wrong method, and refuses
// a body it cannot read — rather than acting on a half-decoded request.
func TestEveryEndpointRefusesTheWrongMethodAndABadBody(t *testing.T) {
	require := require.New(t)
	vm := oneVM(t)

	gets := []string{"/providers", "/tasks", "/models", "/rewards/stats", "/stats", "/merkle"}
	for _, p := range gets {
		require.Equal(http.StatusMethodNotAllowed, call(t, vm, http.MethodPost, p, nil).Code, p)
	}
	posts := []string{"/providers/register", "/tasks/submit", "/tasks/result", "/attestation/verify", "/rewards/claim"}
	for _, p := range posts {
		require.Equal(http.StatusMethodNotAllowed, call(t, vm, http.MethodGet, p, nil).Code, p)
		require.Equal(http.StatusBadRequest, call(t, vm, http.MethodPost, p, "{not json").Code, p)
	}
}

func TestTheEndpointsAnswer(t *testing.T) {
	require := require.New(t)
	vm := oneVM(t)

	require.Equal(http.StatusOK, call(t, vm, http.MethodGet, "/health", nil).Code)
	require.Equal(http.StatusOK, call(t, vm, http.MethodGet, "/providers", nil).Code)
	require.Equal(http.StatusOK, call(t, vm, http.MethodGet, "/models", nil).Code)
	require.Equal(http.StatusOK, call(t, vm, http.MethodGet, "/stats", nil).Code)
	require.Equal(http.StatusOK, call(t, vm, http.MethodGet, "/merkle", nil).Code)
	require.Equal(http.StatusOK, call(t, vm, http.MethodGet, "/tasks", nil).Code)

	// Register, then submit a task and a result through the wire.
	reg := call(t, vm, http.MethodPost, "/providers/register",
		RegisterProviderRequest{ID: "p1", Endpoint: "https://gpu.example", GPUs: []aicore.GPUInfo{{Model: "gb10"}}})
	require.Equal(http.StatusOK, reg.Code, reg.Body.String())

	sub := call(t, vm, http.MethodPost, "/tasks/submit",
		SubmitTaskRequest{ID: "t1", Type: string(aicore.TaskTypeInference), Model: "zen", Fee: 1_000_000_000_000_000})
	require.Equal(http.StatusOK, sub.Code, sub.Body.String())

	got := call(t, vm, http.MethodGet, "/tasks?id=t1", nil)
	require.Equal(http.StatusOK, got.Code)
	require.Contains(got.Body.String(), "t1")
	require.Equal(http.StatusNotFound, call(t, vm, http.MethodGet, "/tasks?id=nope", nil).Code)

	res := call(t, vm, http.MethodPost, "/tasks/result",
		SubmitResultRequest{TaskID: "t1", ProviderID: "p1", Output: json.RawMessage(`{"a":1}`)})
	require.Equal(http.StatusOK, res.Code, res.Body.String())

	// A result for a task nobody submitted is refused.
	require.Equal(http.StatusBadRequest,
		call(t, vm, http.MethodPost, "/tasks/result", SubmitResultRequest{TaskID: "ghost"}).Code)

	// A task below the fee floor is refused at admission.
	require.Equal(http.StatusBadRequest,
		call(t, vm, http.MethodPost, "/tasks/submit", SubmitTaskRequest{ID: "cheap", Fee: 0}).Code)

	// Rewards: the provider did work, so its stats exist and a claim answers.
	stats := call(t, vm, http.MethodGet, "/rewards/stats?provider_id=p1", nil)
	require.Equal(http.StatusOK, stats.Code, stats.Body.String())
	require.Equal(http.StatusBadRequest, call(t, vm, http.MethodGet, "/rewards/stats", nil).Code)
	require.Equal(http.StatusNotFound, call(t, vm, http.MethodGet, "/rewards/stats?provider_id=ghost", nil).Code)

	claim := call(t, vm, http.MethodPost, "/rewards/claim", map[string]string{"provider_id": "p1"})
	require.Equal(http.StatusOK, claim.Code, claim.Body.String())

	// An attestation that does not verify comes back as a refusal.
	require.Equal(http.StatusBadRequest, call(t, vm, http.MethodPost, "/attestation/verify",
		VerifyAttestationRequest{GPUAttestation: &attestation.GPUAttestation{}}).Code)

	// A registration the policy refuses comes back as a refusal too.
	gated := initWith(t, DefaultPermissionedConfig())
	require.Equal(http.StatusBadRequest,
		call(t, gated, http.MethodPost, "/providers/register", RegisterProviderRequest{ID: "p2"}).Code)
}

// A task with no name cannot be tracked or answered, so the core refuses it and
// the refusal reaches the caller instead of a silent enqueue.
func TestATaskWithNoNameIsRefused(t *testing.T) {
	vm := oneVM(t)
	require.ErrorContains(t, vm.SubmitTask(&aicore.Task{Fee: 1_000_000_000_000_000}), "task")
}

// Shutdown is idempotent and does not depend on the core being there.
func TestShutdownWithoutACore(t *testing.T) {
	vm := &VM{running: true}
	require.NoError(t, vm.Shutdown(context.Background()))
	require.False(t, vm.live())
}

// The VM reports the policy it came up under, so an operator can read from the
// boot line whether the permissioned gate is on. A no-op logger reports nothing
// and the line is skipped; a real one has to carry it.
func TestInitializeReportsItsPolicy(t *testing.T) {
	logger := log.NewTestLogger()
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: logger},
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	}))
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	require.False(t, vm.log.IsZero())
	require.True(t, vm.live())
}
