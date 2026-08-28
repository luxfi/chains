// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// executor.go — the one place that knows the threshold library exists.
//
// M-Chain runs exactly one threshold protocol: CGGMP21 (cmp), the threshold
// ECDSA that produces signatures an external chain's ecrecover accepts. There
// is no protocol registry and no selection: a custody key's Kind names the
// protocol it was generated with, and cggmp21 is the only value that can be
// written. A registry offering four protocols and implementing one is not a
// choice, and a caller that reaches the other three finds an error where a
// signature should be.
//
// Everything above this file speaks in ceremonies; everything below it is
// github.com/luxfi/threshold. The MessageRouter is the seam: the executor
// drives a per-party protocol.Handler and the router moves that handler's
// opaque messages to the other parties (transport.go).

import (
	"context"
	"fmt"
	"sync"

	"github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"

	"github.com/luxfi/threshold/protocols/cmp"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
)

// MessageRouter carries one ceremony's protocol messages between parties. It
// never interprets them: the cryptography is the threshold library's, the
// delivery is the router's, and neither knows the other's business.
type MessageRouter interface {
	// Send sends a message to the party it addresses, or broadcasts it to the
	// whole ceremony when To is empty.
	Send(msg *protocol.Message) error
	// Receive yields messages addressed to this party.
	Receive() <-chan *protocol.Message
}

// ProtocolExecutor drives threshold protocols to completion over a router.
type ProtocolExecutor struct {
	pool   *pool.Pool
	logger log.Logger

	// handlers are the ceremonies running right now, keyed by session id, so a
	// ceremony can be torn down by name when it finishes or its context dies.
	mu       sync.RWMutex
	handlers map[string]*protocol.Handler
}

// NewProtocolExecutor creates a new protocol executor.
func NewProtocolExecutor(workerPool *pool.Pool, logger log.Logger) *ProtocolExecutor {
	return &ProtocolExecutor{
		pool:     workerPool,
		logger:   logger,
		handlers: make(map[string]*protocol.Handler),
	}
}

// CreateHandler starts one ceremony and registers it under sessionID.
func (pe *ProtocolExecutor) CreateHandler(
	ctx context.Context,
	sessionID string,
	startFunc protocol.StartFunc,
) (*protocol.Handler, error) {
	handler, err := protocol.NewHandler(
		ctx,
		pe.logger,
		nil, // no metrics registry
		startFunc,
		[]byte(sessionID),
		protocol.DefaultConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("mpcvm: create ceremony handler: %w", err)
	}

	pe.mu.Lock()
	pe.handlers[sessionID] = handler
	pe.mu.Unlock()

	return handler, nil
}

// RemoveHandler stops a ceremony and forgets it. Idempotent.
func (pe *ProtocolExecutor) RemoveHandler(sessionID string) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if handler, ok := pe.handlers[sessionID]; ok {
		handler.Stop()
		delete(pe.handlers, sessionID)
	}
}

// Live reports how many ceremonies this executor is driving. It is what a
// leaked handler shows up in.
func (pe *ProtocolExecutor) Live() int {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return len(pe.handlers)
}

// RunCMPKeygen runs one distributed key generation to completion. threshold is
// the polynomial degree t, never the signer count: see quorum.Policy.Degree.
func (pe *ProtocolExecutor) RunCMPKeygen(
	ctx context.Context,
	sessionID string,
	selfID party.ID,
	participants []party.ID,
	threshold int,
	router MessageRouter,
) (*cmpconfig.Config, error) {
	start := cmp.Keygen(curve.Secp256k1{}, selfID, participants, threshold, pe.pool)
	return runProtocol[*cmpconfig.Config](ctx, pe, sessionID, start, router)
}

// RunCMPSign runs one signing ceremony to completion and returns the canonical
// Ethereum r‖s‖v encoding.
func (pe *ProtocolExecutor) RunCMPSign(
	ctx context.Context,
	sessionID string,
	config *cmpconfig.Config,
	signers []party.ID,
	messageHash []byte,
	router MessageRouter,
) (*ECDSASignature, error) {
	start := cmp.Sign(config, signers, messageHash, pe.pool)
	// cmp.Sign yields *ecdsa.Signature (R point, S scalar). Asserting the
	// protocol result straight to *ECDSASignature never matches — it produced
	// "unexpected result type" on every signature. Assert the real type, then
	// convert.
	sig, err := runProtocol[*ecdsa.Signature](ctx, pe, sessionID, start, router)
	if err != nil {
		return nil, err
	}
	return ecdsaSigToWrapper(sig)
}

// runProtocol drives one ceremony to its result, moving messages both ways over
// the router for as long as it runs.
func runProtocol[T any](
	ctx context.Context,
	pe *ProtocolExecutor,
	sessionID string,
	startFunc protocol.StartFunc,
	router MessageRouter,
) (T, error) {
	var zero T

	handler, err := pe.CreateHandler(ctx, sessionID, startFunc)
	if err != nil {
		return zero, err
	}
	defer pe.RemoveHandler(sessionID)

	done := make(chan struct{})
	var routerErr error

	// Outgoing: everything this party emits goes to the other parties.
	go func() {
		defer close(done)
		for msg := range handler.Listen() {
			if err := router.Send(msg); err != nil {
				routerErr = err
				return
			}
		}
	}()

	// Incoming: everything the other parties emit reaches this handler.
	go func() {
		for msg := range router.Receive() {
			handler.Accept(msg)
		}
	}()

	result, err := handler.WaitForResult()
	if err != nil {
		return zero, fmt.Errorf("mpcvm: ceremony %s: %w", sessionID, err)
	}

	<-done
	if routerErr != nil {
		return zero, fmt.Errorf("mpcvm: ceremony %s transport: %w", sessionID, routerErr)
	}

	typed, ok := result.(T)
	if !ok {
		return zero, fmt.Errorf("mpcvm: ceremony %s produced %T, want %T", sessionID, result, zero)
	}
	return typed, nil
}

// ECDSASignature is a threshold ECDSA signature in the one encoding M-Chain
// stores and every verifier reads: r(32) ‖ s(32) ‖ v(1).
type ECDSASignature struct {
	R []byte
	S []byte
	V byte
}

// ecdsaSigToWrapper converts a threshold-library ECDSA signature into the wire
// wrapper as canonical Ethereum r(32)‖s(32)‖v(1): low-S normalised, so it
// verifies under luxfi/crypto secp256k1.VerifySignature and on-chain ecrecover.
func ecdsaSigToWrapper(sig *ecdsa.Signature) (*ECDSASignature, error) {
	if sig == nil {
		return nil, fmt.Errorf("mpcvm: nil signature")
	}
	// SigEthereum builds a fixed 65-byte array and checks both component lengths
	// on the way in, so a successful return is 65 bytes by construction. A
	// length check here would restate that and could never fire.
	eth, err := sig.SigEthereum()
	if err != nil {
		return nil, fmt.Errorf("mpcvm: encode signature: %w", err)
	}
	return &ECDSASignature{R: eth[0:32], S: eth[32:64], V: eth[64]}, nil
}
