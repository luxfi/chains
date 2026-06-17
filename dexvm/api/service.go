// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package api provides the RPC API for the DEX VM proxy. The proxy holds NO
// canonical DEX state, so this service is a THIN PASS-THROUGH: order reads and
// writes are forwarded to the d-chain over ZAP via the relay client. There are
// NO local orderbook / pool / position / perpetuals / MEV / ADL endpoints —
// those concerns live ONLY on the d-chain.
package api

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrNotBootstrapped   = errors.New("DEX proxy not bootstrapped")
	ErrInvalidRequest    = errors.New("invalid request")
	ErrRelayNotAvailable = errors.New("d-chain relay not configured")
)

// Relayer is the relay surface the proxy VM exposes to the API: forward an
// opaque clob_* frame to the d-chain and return the raw response. It is the
// ONLY DEX capability the proxy has — pure transport to the matcher.
type Relayer interface {
	Configured() bool
	Relay(ctx context.Context, method string, payload []byte) ([]byte, error)
}

// VM is the minimal surface the API service needs from the proxy VM.
type VM interface {
	IsBootstrapped() bool
	Relay() Relayer
}

// Service provides the RPC API for the DEX VM proxy.
type Service struct {
	vm VM
}

// NewService creates a new API service.
func NewService(vm VM) *Service {
	return &Service{vm: vm}
}

// ============================================
// Health and Status
// ============================================

// PingArgs is the argument for the Ping API.
type PingArgs struct{}

// PingReply is the reply for the Ping API.
type PingReply struct {
	Success bool `json:"success"`
}

// Ping returns a simple health check response.
func (s *Service) Ping(_ *http.Request, _ *PingArgs, reply *PingReply) error {
	reply.Success = true
	return nil
}

// StatusArgs is the argument for the Status API.
type StatusArgs struct{}

// StatusReply is the reply for the Status API.
type StatusReply struct {
	Bootstrapped    bool   `json:"bootstrapped"`
	RelayConfigured bool   `json:"relayConfigured"`
	Version         string `json:"version"`
}

// Status returns the proxy status.
func (s *Service) Status(_ *http.Request, _ *StatusArgs, reply *StatusReply) error {
	reply.Bootstrapped = s.vm.IsBootstrapped()
	reply.RelayConfigured = s.vm.Relay().Configured()
	reply.Version = "2.0.0"
	return nil
}

// ============================================
// Relay pass-through (the only DEX surface)
// ============================================

// RelayArgs forwards an opaque, hex-encoded clob_* frame to the d-chain. The
// proxy does not interpret the payload — the d-chain matcher is the single
// source of truth. Method MUST be one of the frozen clob_* names.
type RelayArgs struct {
	Method  string `json:"method"`
	Payload string `json:"payload"` // hex-encoded ZAP frame
}

// RelayReply returns the d-chain's raw response (hex-encoded).
type RelayReply struct {
	Response string `json:"response"`
}

// Relay forwards a clob_* frame to the d-chain and returns its response. This
// is the proxy's entire DEX API: it neither matches nor reads a local book.
func (s *Service) Relay(r *http.Request, args *RelayArgs, reply *RelayReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}
	if args.Method == "" {
		return fmt.Errorf("%w: method required", ErrInvalidRequest)
	}
	relayer := s.vm.Relay()
	if !relayer.Configured() {
		return ErrRelayNotAvailable
	}
	payload, err := hex.DecodeString(args.Payload)
	if err != nil {
		return fmt.Errorf("%w: payload must be hex", ErrInvalidRequest)
	}
	resp, err := relayer.Relay(reqCtx(r), args.Method, payload)
	if err != nil {
		return err
	}
	reply.Response = hex.EncodeToString(resp)
	return nil
}

// reqCtx extracts the request context (or a background context if absent).
func reqCtx(r *http.Request) context.Context {
	if r != nil && r.Context() != nil {
		return r.Context()
	}
	return context.Background()
}
