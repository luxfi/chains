// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/internal/bridgeattest"
	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/ids"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/cmp/config"
)

// The release worker: what leaves the chain, and under what authority.

// countingClient is a destination gateway that records every broadcast and can
// be told to fail a number of times first.
type countingClient struct {
	mu        sync.Mutex
	sent      int
	confirms  uint32
	failFirst int
	processed bool
	confErr   error
}

func (c *countingClient) GetTransaction(context.Context, ids.ID) (interface{}, error) {
	return nil, nil
}

func (c *countingClient) GetConfirmations(context.Context, ids.ID) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.confirms, c.confErr
}
func (c *countingClient) ValidateAddress([]byte) error { return nil }

func (c *countingClient) IsProcessed(context.Context, bridgeattest.BridgeTransfer) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.processed, nil
}

func (c *countingClient) SendTransaction(context.Context, interface{}) (ids.ID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failFirst > 0 {
		c.failFirst--
		return ids.Empty, errors.New("endpoint refused")
	}
	c.sent++
	return ids.GenerateTestID(), nil
}

func (c *countingClient) broadcasts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent
}

// custodyRig wires a VM that holds a real custody group key, an M-Chain that
// signs with it, and a destination gateway — the shape a relayer runs in.
func custodyRig(t *testing.T) (*VM, *countingClient, *secp256k1.PrivateKey) {
	t.Helper()
	custody, err := secp256k1.NewPrivateKey()
	require.NoError(t, err)

	vm := boot(t)
	vm.mpcConfig = groupConfig(t, custody)
	dst := &countingClient{confirms: 64}
	vm.mu.Lock()
	vm.evmByChainID[dstChain] = dst
	vm.evmByChainID[srcChain] = dst
	vm.attestClient = signingAttester{key: custody}
	vm.mu.Unlock()
	return vm, dst, custody
}

// groupConfig is a CMP config whose group public point is the custody key, so
// mpcGroupPublicKey returns exactly what M signs with.
func groupConfig(t *testing.T, key *secp256k1.PrivateKey) *config.Config {
	t.Helper()
	group := curve.Secp256k1{}
	secret := group.NewScalar()
	require.NoError(t, secret.UnmarshalBinary(key.Bytes()))
	return &config.Config{
		Group:     group,
		Threshold: 0,
		Public:    map[party.ID]*config.Public{"m": {ECDSA: secret.ActOnBase()}},
	}
}

// signingAttester is M-Chain: it signs the transfer's digest with the custody
// key.
type signingAttester struct{ key *secp256k1.PrivateKey }

func (a signingAttester) AttestBridgeTransfer(_ context.Context, bt bridgeattest.BridgeTransfer) (*bridgeattest.Attestation, error) {
	digest := bt.Digest()
	sig, err := secp256k1.Sign(digest[:], a.key.Bytes())
	if err != nil {
		return nil, err
	}
	return &bridgeattest.Attestation{Transfer: bt, Digest: digest, Signature: sig}, nil
}

// TestTheChainVerifiesTheKeyItWasConfiguredWith end to end: a genuine
// attestation over the configured group key is released, and the same
// attestation is worthless to a chain configured with a different key.
func TestTheChainVerifiesTheKeyItWasConfiguredWith(t *testing.T) {
	vm, dst, _ := custodyRig(t)
	require.NotEmpty(t, vm.mpcGroupPublicKey())

	_, err := vm.releaseTransfer(context.Background(), transferFor(1, 5_000))
	require.NoError(t, err)
	require.Equal(t, 1, dst.broadcasts())

	// A chain holding a different group key refuses the same attestation.
	other, err := secp256k1.NewPrivateKey()
	require.NoError(t, err)
	vm.mpcConfig = groupConfig(t, other)
	_, err = vm.releaseTransfer(context.Background(), transferFor(2, 5_000))
	require.ErrorIs(t, err, errBadAttestation)
	require.Equal(t, 1, dst.broadcasts(), "a second release on an unverifiable attestation")
}

// A destination with no client is a transfer with nowhere to go.
func TestAReleaseNeedsAClientForItsDestination(t *testing.T) {
	vm, _, _ := custodyRig(t)
	unknown := transferFor(1, 5_000)
	unknown.DstChainID = 4242
	_, err := vm.releaseTransfer(context.Background(), unknown)
	require.ErrorIs(t, err, errNoDestClient)
}

// M returning an error is not consent either.
func TestAReleaseStopsWhenMWillNotAttest(t *testing.T) {
	vm, dst, _ := custodyRig(t)
	vm.mu.Lock()
	vm.attestClient = refusingAttester{}
	vm.mu.Unlock()

	_, err := vm.releaseTransfer(context.Background(), transferFor(1, 5_000))
	require.ErrorContains(t, err, "attest")
	require.Zero(t, dst.broadcasts())

	vm.mu.Lock()
	vm.attestClient = nil
	vm.mu.Unlock()
	_, err = vm.releaseTransfer(context.Background(), transferFor(1, 5_000))
	require.ErrorContains(t, err, "attestation client not configured")
}

type refusingAttester struct{}

func (refusingAttester) AttestBridgeTransfer(context.Context, bridgeattest.BridgeTransfer) (*bridgeattest.Attestation, error) {
	return nil, errors.New("M is not signing today")
}

// =============================================================================
// The worker
// =============================================================================

// A transfer the chain cannot turn into a release is dropped where it is
// found, not retried forever.
func TestTheWorkerSkipsATransferItCannotBuild(t *testing.T) {
	vm, dst, _ := custodyRig(t)
	r := &releaser{vm: vm, queue: make(chan *BridgeRequest, 1), quit: make(chan struct{}), retries: 1}

	broken := requestFor(1, 5_000)
	broken.Recipient = nil
	r.handle(broken)
	require.Zero(t, dst.broadcasts())
}

// The source lock is re-confirmed from this node's OWN view before anything is
// released: the depth on the request is the proposer's claim.
func TestTheWorkerReconfirmsTheSourceLock(t *testing.T) {
	vm, dst, _ := custodyRig(t)
	r := &releaser{vm: vm, queue: make(chan *BridgeRequest, 1), quit: make(chan struct{}),
		retries: 1, backoff: time.Millisecond}

	dst.mu.Lock()
	dst.confirms = 1 // shallower than the chain requires
	dst.mu.Unlock()

	req := requestFor(1, 5_000)
	require.ErrorIs(t, r.releaseOnce(context.Background(), req, mustTransfer(t, req)),
		errInsufficientConfirmations)
	require.Zero(t, dst.broadcasts())

	dst.mu.Lock()
	dst.confErr = errors.New("endpoint down")
	dst.mu.Unlock()
	require.ErrorContains(t, r.releaseOnce(context.Background(), req, mustTransfer(t, req)),
		"source confirmation check")

	dst.mu.Lock()
	dst.confErr = nil
	dst.confirms = 64
	dst.mu.Unlock()
	require.NoError(t, r.releaseOnce(context.Background(), req, mustTransfer(t, req)))
	require.Equal(t, 1, dst.broadcasts())
}

// A transfer the gateway has already released converges: no attestation is
// requested and nothing is broadcast again.
func TestTheWorkerConvergesOnAnAlreadyReleasedTransfer(t *testing.T) {
	vm, dst, _ := custodyRig(t)
	dst.mu.Lock()
	dst.processed = true
	dst.mu.Unlock()

	r := &releaser{vm: vm, queue: make(chan *BridgeRequest, 1), quit: make(chan struct{}),
		retries: 3, backoff: time.Millisecond}
	r.handle(requestFor(1, 5_000))
	require.Zero(t, dst.broadcasts())
}

// A refusal is retried, and a transfer that never lands is dropped rather than
// held forever: it can be re-observed, and other relayers broadcast on their
// own.
func TestTheWorkerRetriesThenGivesUp(t *testing.T) {
	vm, dst, _ := custodyRig(t)
	dst.mu.Lock()
	dst.failFirst = 2
	dst.mu.Unlock()

	r := &releaser{vm: vm, queue: make(chan *BridgeRequest, 1), quit: make(chan struct{}),
		retries: 5, backoff: time.Millisecond}
	r.handle(requestFor(1, 5_000))
	require.Equal(t, 1, dst.broadcasts(), "the third attempt should land")

	dst.mu.Lock()
	dst.failFirst = 1_000
	dst.mu.Unlock()
	r.handle(requestFor(2, 5_000))
	require.Equal(t, 1, dst.broadcasts(), "a transfer that never lands must not be released")
}

// Stopping ends a retry in progress rather than waiting out the backoff.
func TestStoppingEndsARetryInFlight(t *testing.T) {
	vm, dst, _ := custodyRig(t)
	dst.mu.Lock()
	dst.failFirst = 1_000
	dst.mu.Unlock()

	r := &releaser{vm: vm, queue: make(chan *BridgeRequest, 1), quit: make(chan struct{}),
		retries: 5, backoff: time.Hour}
	done := make(chan struct{})
	go func() { r.handle(requestFor(1, 5_000)); close(done) }()

	time.Sleep(20 * time.Millisecond)
	close(r.quit)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker waited out an hour-long backoff after being told to stop")
	}
}

// The worker runs off the consensus path: what a block hands it is picked up
// and released without the block waiting.
func TestTheWorkerReleasesWhatABlockHandsIt(t *testing.T) {
	vm, dst, _ := custodyRig(t)
	r := newReleaser(vm)
	vm.mu.Lock()
	vm.releaser = r
	vm.mu.Unlock()

	pend(vm, requestFor(1, 5_000))
	buildAndAccept(t, vm)

	require.Eventually(t, func() bool { return dst.broadcasts() == 1 },
		5*time.Second, 5*time.Millisecond, "the settled transfer was never released")

	vm.stopReleaser()
	// Stopping twice is not an error: Shutdown may follow a re-enable.
	vm.stopReleaser()
	r.stop()
}

// A full queue drops rather than blocking a block's commit. The transfer is
// re-observed, and every other relayer is broadcasting anyway.
func TestAFullQueueDoesNotBlockConsensus(t *testing.T) {
	vm := boot(t)
	r := &releaser{vm: vm, queue: make(chan *BridgeRequest, 1), quit: make(chan struct{})}
	r.enqueue(requestFor(1, 5_000))
	r.enqueue(requestFor(2, 5_000))
	require.Len(t, r.queue, 1)
}

// =============================================================================
// Wiring
// =============================================================================

// TestEnableBridgeReleaseWiresBothDirections. Both chains are dialled, both
// workers start, and the node reports itself ready to relay.
func TestEnableBridgeReleaseWiresBothDirections(t *testing.T) {
	vm, _, custody := custodyRig(t)

	src := newEVMNode(uint64(srcChain))
	dst := newEVMNode(uint64(dstChain))
	chains := []ExternalChainConfig{
		chainCfg("lux-testnet-c", uint64(srcChain), src.serve(t)),
		chainCfg("zoo-testnet", uint64(dstChain), dst.serve(t)),
	}

	asked := map[string]int{}
	kp := func(_ context.Context, path string) (*ecdsa.PrivateKey, error) {
		asked[path]++
		return relayerKey(t), nil
	}
	require.NoError(t, vm.EnableBridgeRelease(context.Background(), chains, kp, signingAttester{key: custody}))
	t.Cleanup(vm.stopReleaser)

	require.Equal(t, map[string]int{"kms://bridge/relayer": 2}, asked,
		"each chain's relayer key is resolved from KMS, once")

	vm.mu.RLock()
	require.Len(t, vm.evmByChainID, 2)
	require.NotNil(t, vm.releaser)
	require.NotNil(t, vm.watcher)
	vm.mu.RUnlock()

	ready, reason, count := vm.readiness()
	require.True(t, ready, reason)
	require.Equal(t, 2, count)

	// Enabling again replaces the wiring rather than stacking a second pair of
	// workers on the same queues.
	require.NoError(t, vm.EnableBridgeRelease(context.Background(), chains, kp, signingAttester{key: custody}))
	vm.mu.RLock()
	require.Len(t, vm.evmByChainID, 2)
	vm.mu.RUnlock()

	require.NoError(t, vm.Shutdown(context.Background()))
	vm.mu.RLock()
	require.Nil(t, vm.releaser)
	require.Nil(t, vm.watcher)
	vm.mu.RUnlock()
}

// Fail secure: anything the enable cannot complete leaves the node relaying
// nothing rather than half-wired.
func TestEnableBridgeReleaseIsAllOrNothing(t *testing.T) {
	vm := boot(t)
	node := newEVMNode(uint64(dstChain))
	url := node.serve(t)
	good := chainCfg("zoo", uint64(dstChain), url)
	kp := func(context.Context, string) (*ecdsa.PrivateKey, error) { return relayerKey(t), nil }
	ac := signingAttester{}

	require.ErrorContains(t, vm.EnableBridgeRelease(context.Background(), nil, kp, ac),
		"no external chains")
	require.ErrorContains(t, vm.EnableBridgeRelease(context.Background(), []ExternalChainConfig{good}, nil, ac),
		"KeyProvider required")
	require.ErrorContains(t, vm.EnableBridgeRelease(context.Background(), []ExternalChainConfig{good}, kp, nil),
		"AttestationClient required")

	// No KMS path is not a licence to look for the key somewhere else.
	inline := good
	inline.GasKeyKMSPath = ""
	require.ErrorContains(t, vm.EnableBridgeRelease(context.Background(), []ExternalChainConfig{inline}, kp, ac),
		"gasKeyKmsPath required")

	// A key KMS will not hand over stops the whole enable.
	refusing := func(context.Context, string) (*ecdsa.PrivateKey, error) {
		return nil, errors.New("no such secret")
	}
	require.ErrorContains(t, vm.EnableBridgeRelease(context.Background(), []ExternalChainConfig{good}, refusing, ac),
		"resolve gas key from KMS")

	// Two chains claiming one id would make routing a coin flip.
	require.ErrorContains(t, vm.EnableBridgeRelease(context.Background(),
		[]ExternalChainConfig{good, good}, kp, ac), "duplicate chain id")

	// A chain that cannot be dialled stops it too.
	unreachable := chainCfg("dead", 4242, "http://127.0.0.1:1/")
	require.ErrorContains(t, vm.EnableBridgeRelease(context.Background(),
		[]ExternalChainConfig{unreachable}, kp, ac), "dial")

	vm.mu.RLock()
	defer vm.mu.RUnlock()
	require.Empty(t, vm.evmByChainID, "a failed enable left this node half-wired")
	require.Nil(t, vm.releaser)
}

func TestATransferIsBuiltFromTheRequestOrNotAtAll(t *testing.T) {
	good := requestFor(9, 1234)
	transfer, err := good.transfer()
	require.NoError(t, err)
	require.Equal(t, ids.ID(transfer.Digest()), good.ID)

	short := requestFor(1, 1)
	short.Recipient = short.Recipient[:10]
	_, err = short.transfer()
	require.ErrorContains(t, err, "20 bytes")

	noDst := requestFor(1, 1)
	noDst.DstChainID = 0
	_, err = noDst.transfer()
	require.ErrorContains(t, err, "destination chain id")
}

func mustTransfer(t *testing.T, req *BridgeRequest) bridgeattest.BridgeTransfer {
	t.Helper()
	transfer, err := req.transfer()
	require.NoError(t, err)
	return transfer
}
