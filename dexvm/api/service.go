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

	"github.com/luxfi/ids"
)

var (
	ErrNotBootstrapped   = errors.New("DEX proxy not bootstrapped")
	ErrInvalidRequest    = errors.New("invalid request")
	ErrRelayNotAvailable = errors.New("d-chain relay not configured")
	ErrSubmitUnavailable = errors.New("tx submission not available on this VM instance")
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
	// GetSettlement returns the proceeds D->C object's (outputID, amount) recorded
	// under a collateral ref (the C->D intentID) once a swap settled with proceeds.
	// found is false until the settling block is accepted. Purely informational — it
	// is the seam the keeper polls to build the C-side Phase-B ImportSettlement.
	GetSettlement(ref ids.ID) (outputID ids.ID, amount uint64, found bool, err error)
}

// TxSubmitter is the OPTIONAL mempool-entry surface. The atomic proxy txs
// (ImportTx / RelayOrderTx / ExportTx) are deterministic block inputs; the
// proposer builds a block from whatever sits in the pending pool. SubmitTx is
// the canonical PUBLIC entry that appends a wire-encoded tx to that pool and
// notifies the consensus engine. It is implemented by the ChainVM wrapper (which
// owns the pending pool + the engine channel), NOT the inner proxy VM — so the
// dex service exposes it only when wired against a TxSubmitter (the node path).
// A nil/absent submitter => SubmitTx RPC reports ErrSubmitUnavailable, leaving
// the read-only Ping/Status/Relay surface intact (standalone/test path).
//
// WHY THIS IS THE C<->D KEEPER ENTRY: the C-side 0x9999 SubmitSwapIntent writes a
// C->D atomic object + emits IntentSubmitted. Nothing on D consumes that object
// on its own — executeImport runs only over an ImportTx that arrives in a block,
// and the proposer's pending pool was previously unreachable from outside the
// process (CreateHandlers exposed only Ping/Status/Relay). This method is the
// missing seam: an off-chain keeper that watches IntentSubmitted submits the
// ImportTx (consume the C->D object, fund the D order) + the settling
// RelayOrderTx (clob_submit, CollateralRef-bound) here; the proposer then relays
// once (obtainFills) and settles the D->C proceeds, which the C-side Phase-B
// ImportSettlement consumes to emit DEXFill.
type TxSubmitter interface {
	SubmitTx(tx []byte) error
}

// Service provides the RPC API for the DEX VM proxy.
type Service struct {
	vm VM
	// submitter is the OPTIONAL mempool entry. nil on the standalone/test path
	// (read-only surface); set to the ChainVM on the node path so SubmitTx works.
	submitter TxSubmitter
}

// NewService creates a new API service with the read-only surface
// (Ping/Status/Relay). SubmitTx reports ErrSubmitUnavailable until a submitter is
// wired (see NewServiceWithSubmitter / the node's ChainVM.CreateHandlers).
func NewService(vm VM) *Service {
	return &Service{vm: vm}
}

// NewServiceWithSubmitter creates the API service with the tx-submission surface
// enabled. The submitter (the ChainVM wrapper) owns the pending pool + the engine
// channel; this is the seam the C<->D keeper uses to inject ImportTx/RelayOrderTx.
func NewServiceWithSubmitter(vm VM, submitter TxSubmitter) *Service {
	return &Service{vm: vm, submitter: submitter}
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

// ============================================
// Tx submission (the C<->D keeper mempool entry)
// ============================================

// SubmitTxArgs carries a single wire-encoded proxy transaction (hex). The wire is
// the dexvm tx codec: type byte (TxImport/TxExport/TxRelayOrder/…) + JSON body, as
// produced by chains/dexvm/txs.Marshal. The service does NOT parse or validate the
// body — the VM parses + Verify-s it deterministically when it is drawn into a
// block. Submitting a malformed tx is harmless: it fails Verify in ProcessBlock and
// is dropped, never settled.
type SubmitTxArgs struct {
	Tx string `json:"tx"` // hex-encoded tx wire bytes
}

// SubmitTxReply returns the submitted tx's id (sha-256 checksum of the wire,
// matching txs.BaseTx.TxID) so the caller can correlate it on-chain.
type SubmitTxReply struct {
	TxID string `json:"txID"`
}

// SubmitTx appends a wire-encoded proxy transaction to the pending pool so the
// proposer includes it in the next block. This is the canonical public mempool
// entry and the SEAM the C<->D keeper drives: it submits the ImportTx (consume the
// C->D atomic object the C-side 0x9999 SubmitSwapIntent wrote, funding the D order)
// and the settling RelayOrderTx (clob_submit, CollateralRef-bound) here; the
// proposer relays once (obtainFills) and the D->C proceeds settle back, which the
// C-side Phase-B ImportSettlement consumes to emit DEXFill.
//
// It requires the VM to be bootstrapped (a tx submitted mid-bootstrap would race
// the state machine) and a wired submitter (the node path; ErrSubmitUnavailable on
// the read-only standalone/test surface). The fee/admission gate lives in the
// submitter (ChainVM.SubmitTx), not here — this is a thin transport shim, exactly
// like Relay.
func (s *Service) SubmitTx(_ *http.Request, args *SubmitTxArgs, reply *SubmitTxReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}
	if s.submitter == nil {
		return ErrSubmitUnavailable
	}
	if args.Tx == "" {
		return fmt.Errorf("%w: tx required", ErrInvalidRequest)
	}
	raw, err := hex.DecodeString(args.Tx)
	if err != nil {
		return fmt.Errorf("%w: tx must be hex", ErrInvalidRequest)
	}
	if err := s.submitter.SubmitTx(raw); err != nil {
		return err
	}
	// TxID is the dexvm's canonical tx id: ids.Checksum256 over the wire bytes,
	// byte-identical to txs.BaseTx.TxID (stampBase). Reuse it (not a private
	// re-hash) so the id the keeper gets back is exactly the one the VM stamps.
	reply.TxID = ids.Checksum256(raw).String()
	return nil
}

// ============================================
// Settlement coordinate (the keeper's Phase-B input)
// ============================================

// GetSettlementArgs names the collateral ref (the C->D intentID, hex/cb58 ids.ID
// string) whose proceeds D->C object the keeper wants to claim.
type GetSettlementArgs struct {
	CollateralRef string `json:"collateralRef"`
}

// GetSettlementReply returns the proceeds object's coordinate. Settled=false means
// the settling block has not been accepted yet (the keeper keeps polling) or the
// settle was a pure refund (no proceeds object to claim). When Settled is true,
// OutputID + Amount are the DS01 Phase-B body inputs (outputID|amount|intentID).
type GetSettlementReply struct {
	Settled  bool   `json:"settled"`
	OutputID string `json:"outputID"`
	Amount   uint64 `json:"amount"`
}

// GetSettlement reports the proceeds D->C object's (outputID, amount) recorded under
// a collateral ref once the dexvm settled a swap with proceeds. This is the SEAM the
// keeper polls after submitting the ImportTx + settling RelayOrderTx: once the
// settling block accepts, settleFromFills records the proceeds export's outputID +
// realized amount here, and the keeper reads them to build the C-side Phase-B
// ImportSettlement (DS01 outputID|amount|intentID) that consumes the object and emits
// DEXFill. It is a read of committed state; it credits nothing.
func (s *Service) GetSettlement(_ *http.Request, args *GetSettlementArgs, reply *GetSettlementReply) error {
	if !s.vm.IsBootstrapped() {
		return ErrNotBootstrapped
	}
	if args.CollateralRef == "" {
		return fmt.Errorf("%w: collateralRef required", ErrInvalidRequest)
	}
	ref, err := ids.FromString(args.CollateralRef)
	if err != nil {
		return fmt.Errorf("%w: collateralRef must be a valid id: %v", ErrInvalidRequest, err)
	}
	outputID, amount, found, err := s.vm.GetSettlement(ref)
	if err != nil {
		return err
	}
	reply.Settled = found
	if found {
		reply.OutputID = outputID.String()
		reply.Amount = amount
	}
	return nil
}

// reqCtx extracts the request context (or a background context if absent).
func reqCtx(r *http.Request) context.Context {
	if r != nil && r.Context() != nil {
		return r.Context()
	}
	return context.Background()
}
