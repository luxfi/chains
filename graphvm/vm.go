// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package graphvm implements the Graph VM (G-Chain) — a shared GraphQL database
// across all Lux chains. Any chain's state is queryable through a unified
// GraphQL endpoint.
package graphvm

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/warp"

	nodeversion "github.com/luxfi/node/version"
)

var (
	_ chain.ChainVM = (*VM)(nil)

	Version = &nodeversion.Semantic{
		Major: 1,
		Minor: 0,
		Patch: 0,
	}

	errNoAppProtocol = errors.New("graphvm: this chain has no app protocol")

	// errEmptyAPIKey refuses a configuration that would admit an empty token.
	// subtle.ConstantTimeCompare reports equal for two zero-length slices, so a
	// configured "" matches the token in `Authorization: Bearer ` — auth on,
	// everyone in. A chain refuses to boot rather than serve that.
	errEmptyAPIKey = errors.New("graphvm: requireAuth with an empty api key")

	// errReadOnlyChain is the ONE predicate. G-Chain indexes what other chains
	// have already agreed, so it holds no state of its own to agree on and never
	// advances past genesis. BuildBlock declines by it, ParseBlock refuses any
	// bytes but genesis by it, and Verify/Accept refuse any block but genesis by
	// it — because a chain that admits what it cannot build has a gap between
	// admission and consensus, and that gap is where a peer parks a block whose
	// parent no one can resolve.
	errReadOnlyChain = errors.New("graphvm: this chain indexes other chains and builds no blocks")
)

// GConfig contains VM configuration. Every field here is read; a knob that
// changes nothing is worse than no knob, because it reads as a control.
type GConfig struct {
	// Query bounds
	MaxQueryDepth  int `json:"maxQueryDepth"`
	QueryTimeoutMs int `json:"queryTimeoutMs"`
	MaxResultSize  int `json:"maxResultSize"`

	// Authentication
	RequireAuth bool     `json:"requireAuth"`
	APIKeys     []string `json:"apiKeys"`
}

// VM implements the chain.ChainVM interface for the Graph Chain (G-Chain)
type VM struct {
	rt        *runtime.Runtime
	db        database.Database
	config    GConfig
	toEngine  chan<- vmcore.Message
	appSender warp.Sender

	// genesis is the whole of this chain's consensus state: it is the first
	// block, the last-accepted block and the preferred block, permanently. One
	// value, so the three can never disagree.
	genesis *Block

	// queries answers /graphql against the chain database.
	queries *QueryExecutor

	// G-Chain is read-only; the policy refuses all user-tx at the boundary.
	// See feegate.go.
	feePolicy fee.Policy
}

// Initialize implements the common.VM interface
func (vm *VM) Initialize(ctx context.Context, vmInit vmcore.Init) error {
	vm.rt = vmInit.Runtime
	vm.db = vmInit.DB
	vm.toEngine = vmInit.ToEngine
	vm.appSender = vmInit.Sender

	if len(vmInit.Config) > 0 {
		if err := json.Unmarshal(vmInit.Config, &vm.config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	}
	if vm.config.RequireAuth {
		if len(vm.config.APIKeys) == 0 {
			return errEmptyAPIKey
		}
		for _, k := range vm.config.APIKeys {
			if k == "" {
				return errEmptyAPIKey
			}
		}
	}

	// Fee gate: read-only chain → NoUserTxPolicy (refuses all user-tx).
	vm.feePolicy = newFeePolicy()
	if err := fee.Validate(vm.feePolicy); err != nil {
		return fmt.Errorf("feepolicy: %w", err)
	}

	vm.queries = NewQueryExecutor(vm.db, &vm.config)

	// The consensus engine REQUIRES a resolvable last-accepted block at boot:
	// the ZAP VM server calls LastAccepted() then GetBlock(lastAccepted) inside
	// Initialize, and a miss there is the "get last accepted block: not
	// implemented" failure that fails the node's G-Chain health check.
	vm.genesis = newBlock(vm, vmInit.Genesis)

	if logger, ok := vm.rt.Log.(log.Logger); ok {
		logger.Info("initialized Graph VM",
			log.Reflect("version", Version),
			log.String("genesisBlockID", vm.genesis.ID().String()),
		)
	}

	return nil
}

// SetState implements the common.VM interface
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	return nil
}

// Shutdown implements the common.VM interface
func (vm *VM) Shutdown(context.Context) error {
	if vm.db != nil {
		return vm.db.Close()
	}
	return nil
}

// Version implements the common.VM interface
func (vm *VM) Version(context.Context) (string, error) {
	return Version.String(), nil
}

// CreateHandlers implements the common.VM interface.
//
// The node mounts each key under /v1/bc/<chainID> and matches that full path
// EXACTLY, then hands the handler the request with the path it arrived on. A
// handler that dispatches on r.URL.Path therefore never recognizes anything.
// The key IS the route; one handler per key.
func (vm *VM) CreateHandlers(context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{"/graphql": vm.graphql()}, nil
}

// NewHTTPHandler returns the same one route, mounted by path.
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.Handle("/graphql", vm.graphql())
	return mux, nil
}

// graphql builds the query endpoint. Authentication is decided here, once, so
// there is no second door onto the executor.
func (vm *VM) graphql() http.Handler {
	var h http.Handler = &queryHandler{vm: vm}
	if vm.config.RequireAuth {
		h = authenticated(h, vm.config.APIKeys)
	}
	return h
}

// HealthCheck implements the health.Checker interface
func (vm *VM) HealthCheck(context.Context) (chain.HealthResult, error) {
	return chain.HealthResult{
		Healthy: true,
		Details: map[string]string{
			"version": Version.String(),
			"state":   "active",
		},
	}, nil
}

// Connected implements the validators.Connector interface
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *chain.VersionInfo) error {
	return nil
}

// Disconnected implements the validators.Connector interface
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return nil
}

// Request implements the common.AppHandler interface
func (vm *VM) Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, request []byte) error {
	return errNoAppProtocol
}

// RequestFailed implements the common.AppHandler interface
func (vm *VM) RequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, appErr *warp.Error) error {
	return nil
}

// Response implements the common.AppHandler interface
func (vm *VM) Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	return nil
}

// Gossip implements the common.AppHandler interface
func (vm *VM) Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	return nil
}

// CrossChainRequest implements the common.VM interface
func (vm *VM) CrossChainRequest(ctx context.Context, chainID ids.ID, requestID uint32, deadline time.Time, msg []byte) error {
	return nil
}

// CrossChainRequestFailed implements the common.VM interface
func (vm *VM) CrossChainRequestFailed(ctx context.Context, chainID ids.ID, requestID uint32, appErr *warp.Error) error {
	return nil
}

// CrossChainResponse implements the common.VM interface
func (vm *VM) CrossChainResponse(ctx context.Context, chainID ids.ID, requestID uint32, msg []byte) error {
	return nil
}

// WaitForEvent waits out the context and reports nothing, because this chain
// has nothing to report: it never builds a block, so there is never news of one
// to send. A latch here would wake a builder that declines, which is why this
// is not the frozen WaitForEvent the other chains had — those had work and no
// way to say so. See errReadOnlyChain.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	<-ctx.Done()
	return vmcore.Message{}, ctx.Err()
}

// BuildBlock implements the chain.ChainVM interface, by declining. See
// errReadOnlyChain.
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	return nil, errReadOnlyChain
}

// ParseBlock implements the chain.ChainVM interface. The only block this chain
// has is genesis, so those are the only bytes that name a block of it: anything
// else is refused here rather than admitted, verified, accepted, and then found
// unresolvable by the next node that boots.
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (chain.Block, error) {
	return parseBlock(vm, blockBytes)
}

// GetBlock implements the chain.ChainVM interface. The G-Chain has exactly one
// block — genesis — which is permanently the accepted frontier; any other ID is
// unknown. Returning database.ErrNotFound (not a "not implemented") lets the ZAP
// VM server map a genuine miss to the wire NotFound code.
func (vm *VM) GetBlock(ctx context.Context, blkID ids.ID) (chain.Block, error) {
	if blkID != vm.genesis.ID() {
		return nil, database.ErrNotFound
	}
	return vm.genesis, nil
}

// SetPreference implements the chain.ChainVM interface. Preferring a block this
// chain does not have is a caller error, not a value to store.
func (vm *VM) SetPreference(ctx context.Context, blkID ids.ID) error {
	if blkID != vm.genesis.ID() {
		return errReadOnlyChain
	}
	return nil
}

// LastAccepted implements the chain.ChainVM interface.
func (vm *VM) LastAccepted(context.Context) (ids.ID, error) {
	return vm.genesis.ID(), nil
}

// GetBlockIDAtHeight implements the chain.ChainVM interface. Genesis (height 0)
// is the only block; every other height is absent.
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	if height != 0 {
		return ids.Empty, database.ErrNotFound
	}
	return vm.genesis.ID(), nil
}

// maxRequestBytes bounds what a caller may POST. parseQuery's length check runs
// after decoding, which is too late to stop a body that never ends.
const maxRequestBytes = maxQueryLength + 1<<16

// queryHandler answers GraphQL over HTTP. POST with a JSON body is the one way
// in; a query in a URL is a second way to say the same thing.
type queryHandler struct {
	vm *VM
}

func (h *queryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		writeErr(w, "graphql: POST a JSON body")
		return
	}

	var req GraphQLRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeErr(w, err.Error())
		return
	}

	// A GraphQL error is a 200 with an errors array; the request was understood.
	json.NewEncoder(w).Encode(h.vm.queries.Execute(r.Context(), &req))
}

func writeErr(w http.ResponseWriter, msg string) {
	json.NewEncoder(w).Encode(&GraphQLResponse{Errors: []GraphQLError{{Message: msg}}})
}

// authenticated admits a request carrying one of the configured API keys.
// Initialize has already refused an empty key, so an empty token matches
// nothing here.
func authenticated(next http.Handler, keys []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))

		var ok bool
		for _, key := range keys {
			if subtle.ConstantTimeCompare([]byte(token), []byte(key)) == 1 {
				ok = true
			}
		}
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
