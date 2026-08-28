// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

// release.go — the release path. On a confirmed lock/burn (a bridge request in
// an accepted block), B builds the destination-chain release call, obtains a
// threshold-signed attestation from M-Chain, verifies it, and broadcasts the
// release to the destination gateway. Both directions (Zoo->Lux and Lux->Zoo)
// are the same code — the transfer carries src/dst chain ids and the releaser
// routes by them.
//
// This subsystem is ORTHOGONAL to consensus boot: Initialize brings up the VM;
// EnableBridgeRelease wires the EVM plumbing with its runtime dependencies (the
// KMS-backed relayer keys and the Warp-backed attestation client). A node that
// is not a bridge relayer never calls it, and Block.Accept then behaves exactly
// as before. The broadcast itself happens OFF the consensus path in a worker, so
// Accept never blocks on network I/O; every relayer validator broadcasts and the
// on-chain nonce replay-guard collapses the duplicates to a single mint.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/chains/internal/bridgeattest"
	ethereum "github.com/luxfi/geth"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

var (
	errNoDestClient              = errors.New("bridgevm: no EVM client for destination chain")
	errBadAttestation            = errors.New("bridgevm: attestation failed local verification")
	errInsufficientConfirmations = errors.New("bridgevm: source confirmations below minimum")
	errAlreadyReleased           = errors.New("bridgevm: transfer already released on destination")
)

// How hard the worker retries a single transfer before logging and dropping
// it, and how long it waits between attempts (doubling each time). Dropping is
// safe: the transfer can be re-observed and re-enqueued, and other relayer
// validators broadcast independently.
const (
	releaseMaxRetries = 5
	releaseBackoff    = 250 * time.Millisecond
)

// transfer maps a consensus bridge request to the canonical, domain-bound value
// M signs and the gateway verifies. ids.ID is a [32]byte, so Asset maps directly.
func (r *BridgeRequest) transfer() (bridgeattest.BridgeTransfer, error) {
	if len(r.Recipient) != 20 {
		return bridgeattest.BridgeTransfer{}, fmt.Errorf("bridgevm: recipient must be 20 bytes, got %d", len(r.Recipient))
	}
	if r.DstChainID == 0 {
		return bridgeattest.BridgeTransfer{}, errors.New("bridgevm: request missing destination chain id")
	}
	var recip [20]byte
	copy(recip[:], r.Recipient)
	return bridgeattest.BridgeTransfer{
		SrcChainID: r.SrcChainID,
		DstChainID: r.DstChainID,
		Asset:      [32]byte(r.Asset),
		Amount:     r.Amount,
		Recipient:  recip,
		Nonce:      r.Nonce,
	}, nil
}

// releaser drives releases off the consensus path. The retry policy is data on
// the worker rather than literals inside its loop, so what it will do is one
// thing to read.
type releaser struct {
	vm      *VM
	queue   chan *BridgeRequest
	quit    chan struct{}
	retries int
	backoff time.Duration
	wg      sync.WaitGroup
	once    sync.Once
}

func newReleaser(vm *VM) *releaser {
	r := &releaser{
		vm:      vm,
		queue:   make(chan *BridgeRequest, 1024),
		quit:    make(chan struct{}),
		retries: releaseMaxRetries,
		backoff: releaseBackoff,
	}
	r.wg.Add(1)
	go r.run()
	return r
}

// enqueue is a non-blocking submit, called once a block carrying the transfer
// has committed. If the queue is full the request is dropped with a warning; it
// will be re-observed.
func (r *releaser) enqueue(req *BridgeRequest) {
	select {
	case r.queue <- req:
	default:
		if r.vm.log != nil {
			r.vm.log.Warn("bridgevm: release queue full, dropping (will re-observe)",
				log.Stringer("requestID", req.ID))
		}
	}
}

func (r *releaser) stop() {
	r.once.Do(func() { close(r.quit) })
	r.wg.Wait()
}

func (r *releaser) run() {
	defer r.wg.Done()
	for {
		select {
		case <-r.quit:
			return
		case req := <-r.queue:
			r.handle(req)
		}
	}
}

func (r *releaser) handle(req *BridgeRequest) {
	transfer, err := req.transfer()
	if err != nil {
		r.vm.log.Warn("bridgevm: skip release, bad request", log.Stringer("requestID", req.ID), log.Any("err", err))
		return
	}

	backoff := r.backoff
	for attempt := 0; attempt < r.retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := r.releaseOnce(ctx, req, transfer)
		cancel()
		if err == nil {
			return
		}
		if errors.Is(err, errAlreadyReleased) {
			r.vm.log.Info("bridgevm: release already processed on-chain",
				log.Stringer("requestID", req.ID), log.Uint64("nonce", transfer.Nonce))
			return
		}
		r.vm.log.Warn("bridgevm: release attempt failed",
			log.Stringer("requestID", req.ID),
			log.Int("attempt", attempt+1),
			log.Any("err", err))
		select {
		case <-r.quit:
			return
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	r.vm.log.Error("bridgevm: release gave up after retries",
		log.Stringer("requestID", req.ID), log.Uint64("nonce", transfer.Nonce))
}

// releaseOnce re-confirms the source lock from B's OWN view (the trust-gap fix)
// then runs the release. Confirmation re-check needs the source tx hash, which
// lives on the request — so it happens here, not in releaseTransfer.
func (r *releaser) releaseOnce(ctx context.Context, req *BridgeRequest, transfer bridgeattest.BridgeTransfer) error {
	if src := r.vm.evmClientByID(transfer.SrcChainID); src != nil && req.SourceTxID != ids.Empty {
		conf, err := src.GetConfirmations(ctx, req.SourceTxID)
		if err != nil {
			return fmt.Errorf("bridgevm: source confirmation check: %w", err)
		}
		if conf < r.vm.config.MinConfirmations {
			return fmt.Errorf("%w: %d < %d", errInsufficientConfirmations, conf, r.vm.config.MinConfirmations)
		}
	}
	destTx, err := r.vm.releaseTransfer(ctx, transfer)
	if err != nil {
		return err
	}
	// The destination tx hash is this relayer's own broadcast, not a fact the
	// chain agreed: every relayer signs its own tx and gets its own hash. It
	// is reported, not recorded.
	r.vm.log.Info("bridgevm: release settled",
		log.Stringer("requestID", req.ID),
		log.Stringer("destTxID", destTx))
	return nil
}

// releaseTransfer runs the destination-side release for one transfer: idempotency
// check, attestation from M, local verification, then broadcast to the gateway.
// Direction-agnostic: it routes purely by transfer.DstChainID.
func (vm *VM) releaseTransfer(ctx context.Context, transfer bridgeattest.BridgeTransfer) (ids.ID, error) {
	dst := vm.evmClientByID(transfer.DstChainID)
	if dst == nil {
		return ids.Empty, fmt.Errorf("%w: dstChainId=%d", errNoDestClient, transfer.DstChainID)
	}

	// 1. Idempotent convergence: if the destination gateway already processed
	//    this exact transfer (keyed by its digest, so cross-source nonces never
	//    collide), we are done — no attestation request, no broadcast.
	if done, err := dst.IsProcessed(ctx, transfer); err == nil && done {
		return ids.Empty, errAlreadyReleased
	}

	// 2. Obtain the threshold-signed attestation from M-Chain.
	if vm.attestClient == nil {
		return ids.Empty, errors.New("bridgevm: attestation client not configured")
	}
	att, err := vm.attestClient.AttestBridgeTransfer(ctx, transfer)
	if err != nil {
		return ids.Empty, fmt.Errorf("bridgevm: attest: %w", err)
	}

	// 3. Verify M's attestation against the group key THIS chain was configured
	//    with, before spending gas. Verifying against the key carried inside the
	//    attestation would accept any key an attacker supplied alongside it.
	if att == nil || !att.VerifyAgainst(vm.mpcGroupPublicKey()) {
		return ids.Empty, errBadAttestation
	}

	// 4. Broadcast the release to the destination gateway.
	return dst.SendTransaction(ctx, &ReleaseCall{Transfer: transfer, Signature: att.Signature})
}

func (vm *VM) evmClientByID(id uint32) ChainClient {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.evmByChainID[id]
}

// EnableBridgeRelease wires the EVM release plumbing: it dials each external
// chain, resolves that chain's gas-paying relayer key from KMS via kp, records
// the clients in the id-keyed routing index, sets the attestation client, and
// starts the release worker. Idempotent per process: calling it twice replaces
// the wiring. Fail secure: any misconfigured chain or unresolved key aborts the
// whole enable — no partial, half-wired bridge.
func (vm *VM) EnableBridgeRelease(ctx context.Context, chains []ExternalChainConfig, kp KeyProvider, ac AttestationClient) error {
	if len(chains) == 0 {
		return errors.New("bridgevm: EnableBridgeRelease: no external chains configured")
	}
	if kp == nil {
		return errors.New("bridgevm: EnableBridgeRelease: KeyProvider required (KMS-backed; no plaintext fallback)")
	}
	if ac == nil {
		return errors.New("bridgevm: EnableBridgeRelease: AttestationClient required")
	}

	byID := make(map[uint32]ChainClient, len(chains))
	for _, cfg := range chains {
		if cfg.GasKeyKMSPath == "" {
			return fmt.Errorf("bridgevm: chain %q: gasKeyKmsPath required (KMS only)", cfg.Name)
		}
		if _, dup := byID[uint32(cfg.ChainID)]; dup {
			return fmt.Errorf("bridgevm: duplicate chain id %d", cfg.ChainID)
		}
		key, err := kp(ctx, cfg.GasKeyKMSPath)
		if err != nil {
			return fmt.Errorf("bridgevm: chain %q: resolve gas key from KMS %q: %w", cfg.Name, cfg.GasKeyKMSPath, err)
		}
		client, err := newEVMChainClient(ctx, cfg, key, vm.log)
		if err != nil {
			return err
		}
		byID[uint32(cfg.ChainID)] = client
	}

	// Swap in the new wiring, then (re)start the workers.
	vm.mu.Lock()
	old := vm.releaser
	oldWatch := vm.watcher
	vm.evmByChainID = byID
	vm.attestClient = ac
	vm.mu.Unlock()

	if old != nil {
		old.stop()
	}
	if oldWatch != nil {
		oldWatch.stop()
	}
	r := newReleaser(vm)
	w := newWatcher(vm, chains)
	vm.mu.Lock()
	vm.releaser = r
	vm.watcher = w
	vm.mu.Unlock()
	return nil
}

// stopReleaser halts the workers if running (called from Shutdown).
func (vm *VM) stopReleaser() {
	vm.mu.Lock()
	r := vm.releaser
	w := vm.watcher
	vm.releaser = nil
	vm.watcher = nil
	vm.mu.Unlock()
	if r != nil {
		r.stop()
	}
	if w != nil {
		w.stop()
	}
}

// IsProcessed reports whether the destination gateway has already released this
// exact transfer — the on-chain replay guard keyed by the transfer digest (so
// two source chains reusing the same nonce never collide), read via eth_call.
func (c *evmChainClient) IsProcessed(ctx context.Context, transfer bridgeattest.BridgeTransfer) (bool, error) {
	digest := transfer.Digest()
	data, err := parsedGatewayABI.Pack("processed", digest)
	if err != nil {
		return false, fmt.Errorf("bridgevm: chain %q: pack processed: %w", c.name, err)
	}
	gateway := c.gateway
	out, err := c.primary().CallContract(ctx, ethereum.CallMsg{To: &gateway, Data: data}, nil)
	if err != nil {
		return false, fmt.Errorf("bridgevm: chain %q: eth_call processed: %w", c.name, err)
	}
	vals, err := parsedGatewayABI.Unpack("processed", out)
	if err != nil || len(vals) != 1 {
		return false, fmt.Errorf("bridgevm: chain %q: unpack processed: %w", c.name, err)
	}
	done, _ := vals[0].(bool)
	return done, nil
}
