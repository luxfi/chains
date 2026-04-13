// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gvm implements the Graph VM (G-Chain) — a shared GraphQL database
// across all Lux chains. Any chain's state is queryable through a unified
// GraphQL endpoint with auto-indexing and cross-chain query resolution.
package graphvm

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/luxfi/vm/chain"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
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

	errNotImplemented = errors.New("not implemented")
)

// GConfig contains VM configuration
type GConfig struct {
	// DGraph configuration
	DgraphEndpoint   string `serialize:"true" json:"dgraphEndpoint"`
	SchemaVersion    string `serialize:"true" json:"schemaVersion"`
	EnableFederation bool   `serialize:"true" json:"enableFederation"`

	// Query configuration
	MaxQueryDepth  int `serialize:"true" json:"maxQueryDepth"`
	QueryTimeoutMs int `serialize:"true" json:"queryTimeoutMs"`
	MaxResultSize  int `serialize:"true" json:"maxResultSize"`

	// Index configuration
	AutoIndex      bool `serialize:"true" json:"autoIndex"`
	IndexBatchSize int  `serialize:"true" json:"indexBatchSize"`

	// Authentication configuration
	RequireAuth bool     `serialize:"true" json:"requireAuth"`
	APIKeys     []string `serialize:"true" json:"apiKeys"`
}

// VM implements the chain.ChainVM interface for the Graph Chain (G-Chain)
type VM struct {
	rt        *runtime.Runtime
	db        database.Database
	config    GConfig
	toEngine  chan<- vmcore.Message
	appSender warp.Sender

	// State
	preferredID ids.ID

	// Graph-specific fields
	schemas       map[string]*GraphSchema
	queries       map[ids.ID]*Query
	subscriptions map[ids.ID]*Subscription
	dataIndexes   map[string]*DataIndex
	chainSources  map[ids.ID]*ChainDataSource

	// Synchronization
	schemaMu sync.RWMutex
	queryMu  sync.RWMutex
}

// GraphSchema represents a GraphQL schema definition
type GraphSchema struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Schema     string   `json:"schema"`
	Types      []string `json:"types"`
	Directives []string `json:"directives"`
	CreatedAt  int64    `json:"createdAt"`
	UpdatedAt  int64    `json:"updatedAt"`
}

// Query represents a GraphQL query
type Query struct {
	ID          ids.ID      `json:"id"`
	QueryText   string      `json:"queryText"`
	Variables   []byte      `json:"variables"`
	ChainScope  []ids.ID    `json:"chainScope"`
	Result      []byte      `json:"result,omitempty"`
	Status      QueryStatus `json:"status"`
	SubmittedAt int64       `json:"submittedAt"`
	CompletedAt int64       `json:"completedAt,omitempty"`
}

// Subscription represents a GraphQL subscription
type Subscription struct {
	ID         ids.ID   `json:"id"`
	QueryText  string   `json:"queryText"`
	ChainScope []ids.ID `json:"chainScope"`
	Active     bool     `json:"active"`
	CreatedAt  int64    `json:"createdAt"`
}

// DataIndex represents an index for optimized queries
type DataIndex struct {
	ID        string   `json:"id"`
	ChainID   ids.ID   `json:"chainId"`
	IndexType string   `json:"indexType"`
	Fields    []string `json:"fields"`
	Status    string   `json:"status"`
}

// ChainDataSource represents a connected chain data source
type ChainDataSource struct {
	ChainID     ids.ID `json:"chainId"`
	ChainName   string `json:"chainName"`
	Connected   bool   `json:"connected"`
	LastSync    int64  `json:"lastSync"`
	BlockHeight uint64 `json:"blockHeight"`
}

// QueryStatus represents the status of a query
type QueryStatus uint8

const (
	QueryPending QueryStatus = iota
	QueryProcessing
	QueryCompleted
	QueryFailed
)

// Initialize implements the common.VM interface
func (vm *VM) Initialize(
	ctx context.Context,
	vmInit vmcore.Init,
) error {
	vm.rt = vmInit.Runtime
	vm.db = vmInit.DB
	vm.toEngine = vmInit.ToEngine
	vm.appSender = vmInit.Sender

	// Parse config
	if len(vmInit.Config) > 0 {
		if err := json.Unmarshal(vmInit.Config, &vm.config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	}

	// Initialize state management
	vm.schemas = make(map[string]*GraphSchema)
	vm.queries = make(map[ids.ID]*Query)
	vm.subscriptions = make(map[ids.ID]*Subscription)
	vm.dataIndexes = make(map[string]*DataIndex)
	vm.chainSources = make(map[ids.ID]*ChainDataSource)

	// Parse genesis if needed
	if len(vmInit.Genesis) > 0 {
		if err := vm.parseGenesis(vmInit.Genesis); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}

	if logger, ok := vm.rt.Log.(log.Logger); ok {
		logger.Info("initialized Graph VM",
			log.Reflect("version", Version),
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

// CreateHandlers implements the common.VM interface
func (vm *VM) CreateHandlers(context.Context) (map[string]http.Handler, error) {
	handler := &apiHandler{vm: vm}

	// Wrap sensitive endpoints with authentication if required
	var graphqlHandler http.Handler = handler
	if vm.config.RequireAuth {
		graphqlHandler = authMiddleware(handler, vm.config.APIKeys)
	}

	return map[string]http.Handler{
		"/graphql": graphqlHandler,
		"/schema":  handler, // Schema can be public
		"/query":   graphqlHandler,
		"/index":   handler, // Index metadata can be public
	}, nil
}

// NewHTTPHandler returns HTTP handlers for the VM
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	return &apiHandler{vm: vm}, nil
}

// WaitForEvent blocks until an event occurs that should trigger block building
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	// Block until context is cancelled
	// In production, this would wait for queries/schema updates in queue
	// CRITICAL: Must block here to avoid notification flood loop in chains/manager.go
	<-ctx.Done()
	return vmcore.Message{}, ctx.Err()
}

// HealthCheck implements the health.Checker interface
func (vm *VM) HealthCheck(context.Context) (chain.HealthResult, error) {
	vm.schemaMu.RLock()
	schemaCount := len(vm.schemas)
	vm.schemaMu.RUnlock()

	vm.queryMu.RLock()
	queryCount := len(vm.queries)
	subCount := len(vm.subscriptions)
	vm.queryMu.RUnlock()

	return chain.HealthResult{
		Healthy: true,
		Details: map[string]string{
			"version":       Version.String(),
			"schemas":       fmt.Sprintf("%d", schemaCount),
			"queries":       fmt.Sprintf("%d", queryCount),
			"subscriptions": fmt.Sprintf("%d", subCount),
			"indexes":       fmt.Sprintf("%d", len(vm.dataIndexes)),
			"chainSources":  fmt.Sprintf("%d", len(vm.chainSources)),
			"state":         "active",
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
	return errNotImplemented
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

// BuildBlock implements the chain.ChainVM interface
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	return nil, errNotImplemented
}

// ParseBlock implements the chain.ChainVM interface
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (chain.Block, error) {
	return nil, errNotImplemented
}

// GetBlock implements the chain.ChainVM interface
func (vm *VM) GetBlock(ctx context.Context, blkID ids.ID) (chain.Block, error) {
	return nil, errNotImplemented
}

// SetPreference implements the chain.ChainVM interface
func (vm *VM) SetPreference(ctx context.Context, blkID ids.ID) error {
	vm.preferredID = blkID
	return nil
}

// LastAccepted implements the chain.ChainVM interface
func (vm *VM) LastAccepted(context.Context) (ids.ID, error) {
	return vm.preferredID, nil
}

// GetBlockIDAtHeight implements the chain.ChainVM interface
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return ids.Empty, database.ErrNotFound
}

// parseGenesis parses the genesis data
func (vm *VM) parseGenesis(genesisBytes []byte) error {
	type Genesis struct {
		DefaultSchema  string   `json:"defaultSchema"`
		ChainSources   []string `json:"chainSources"`
		DgraphEndpoint string   `json:"dgraphEndpoint"`
		SchemaVersion  string   `json:"schemaVersion"`
	}

	var genesis Genesis
	if err := json.Unmarshal(genesisBytes, &genesis); err != nil {
		return err
	}

	// Initialize default schema
	if genesis.DefaultSchema != "" {
		vm.schemas["default"] = &GraphSchema{
			ID:        "default",
			Name:      "Default Schema",
			Version:   genesis.SchemaVersion,
			Schema:    genesis.DefaultSchema,
			CreatedAt: time.Now().Unix(),
		}
	}

	return nil
}

// ExecuteQuery executes a GraphQL query against registered schemas and data sources
func (vm *VM) ExecuteQuery(query *Query) error {
	vm.queryMu.Lock()
	defer vm.queryMu.Unlock()

	query.Status = QueryProcessing
	query.SubmittedAt = time.Now().Unix()

	vm.queries[query.ID] = query

	// Parse and execute the GraphQL query
	result, err := vm.executeGraphQLQuery(query.QueryText, query.Variables, query.ChainScope)
	if err != nil {
		query.Status = QueryFailed
		query.Result = []byte(fmt.Sprintf(`{"errors":[{"message":%q}]}`, err.Error()))
		return err
	}

	query.Status = QueryCompleted
	query.CompletedAt = time.Now().Unix()
	query.Result = result

	return nil
}

// executeGraphQLQuery is the core GraphQL execution engine
func (vm *VM) executeGraphQLQuery(queryText string, variables []byte, chainScope []ids.ID) ([]byte, error) {
	// Parse query to extract operation type and fields
	op, fields, err := parseGraphQLQuery(queryText)
	if err != nil {
		return nil, fmt.Errorf("query parse error: %w", err)
	}

	// Only queries are supported for now (no mutations/subscriptions)
	if op != "query" && op != "" {
		return nil, fmt.Errorf("unsupported operation type: %s", op)
	}

	// Build response data by resolving each top-level field
	data := make(map[string]interface{})
	for _, field := range fields {
		value, err := vm.resolveField(field, chainScope)
		if err != nil {
			// GraphQL returns partial results with errors
			data[field] = nil
			continue
		}
		data[field] = value
	}

	// Encode response as JSON
	response := map[string]interface{}{
		"data": data,
	}
	return json.Marshal(response)
}

// parseGraphQLQuery is a minimal GraphQL query parser
// Supports basic queries like: query { field1 field2 }
func parseGraphQLQuery(queryText string) (operation string, fields []string, err error) {
	// Trim whitespace and normalize
	queryText = strings.TrimSpace(queryText)
	if queryText == "" {
		return "", nil, errors.New("empty query")
	}

	// Check for operation type prefix
	operation = "query" // default
	if strings.HasPrefix(queryText, "query") {
		queryText = strings.TrimPrefix(queryText, "query")
		queryText = strings.TrimSpace(queryText)
	} else if strings.HasPrefix(queryText, "mutation") {
		return "mutation", nil, errors.New("mutations not supported")
	} else if strings.HasPrefix(queryText, "subscription") {
		return "subscription", nil, errors.New("subscriptions not supported")
	}

	// Skip optional operation name
	if idx := strings.Index(queryText, "{"); idx > 0 {
		queryText = queryText[idx:]
	}

	// Extract fields from within braces
	if !strings.HasPrefix(queryText, "{") || !strings.HasSuffix(queryText, "}") {
		return "", nil, errors.New("invalid query format: expected { fields }")
	}

	// Remove braces and extract field names
	fieldStr := strings.TrimPrefix(queryText, "{")
	fieldStr = strings.TrimSuffix(fieldStr, "}")
	fieldStr = strings.TrimSpace(fieldStr)

	// Split by whitespace or newlines to get field names
	// Note: This is simplified and doesn't handle nested fields
	fieldNames := strings.Fields(fieldStr)
	for _, f := range fieldNames {
		// Clean up field names (remove any sub-selections for now)
		if idx := strings.Index(f, "{"); idx > 0 {
			f = f[:idx]
		}
		if f != "" && f != "{" && f != "}" {
			fields = append(fields, f)
		}
	}

	return operation, fields, nil
}

// resolveField resolves a single GraphQL field against the available data sources
func (vm *VM) resolveField(fieldName string, chainScope []ids.ID) (interface{}, error) {
	vm.schemaMu.RLock()
	defer vm.schemaMu.RUnlock()

	// Built-in introspection fields
	switch fieldName {
	case "__schema":
		return vm.introspectSchema(), nil
	case "__typename":
		return "Query", nil
	case "schemas":
		// Return all registered schemas
		schemas := make([]map[string]string, 0, len(vm.schemas))
		for _, s := range vm.schemas {
			schemas = append(schemas, map[string]string{
				"id":      s.ID,
				"name":    s.Name,
				"version": s.Version,
			})
		}
		return schemas, nil
	case "chainSources":
		// Return connected chain sources
		sources := make([]map[string]interface{}, 0, len(vm.chainSources))
		for _, cs := range vm.chainSources {
			sources = append(sources, map[string]interface{}{
				"chainId":     cs.ChainID.String(),
				"chainName":   cs.ChainName,
				"connected":   cs.Connected,
				"blockHeight": cs.BlockHeight,
			})
		}
		return sources, nil
	case "indexes":
		// Return data indexes
		indexes := make([]map[string]interface{}, 0, len(vm.dataIndexes))
		for _, idx := range vm.dataIndexes {
			indexes = append(indexes, map[string]interface{}{
				"id":        idx.ID,
				"indexType": idx.IndexType,
				"status":    idx.Status,
				"fields":    idx.Fields,
			})
		}
		return indexes, nil
	}

	return nil, fmt.Errorf("unknown field: %s", fieldName)
}

// introspectSchema returns GraphQL schema introspection data
func (vm *VM) introspectSchema() map[string]interface{} {
	return map[string]interface{}{
		"queryType": map[string]string{
			"name": "Query",
		},
		"types": []map[string]string{
			{"name": "Query"},
			{"name": "Schema"},
			{"name": "ChainSource"},
			{"name": "Index"},
		},
	}
}

// RegisterSchema registers a new GraphQL schema
func (vm *VM) RegisterSchema(schema *GraphSchema) error {
	vm.schemaMu.Lock()
	defer vm.schemaMu.Unlock()

	schema.CreatedAt = time.Now().Unix()
	schema.UpdatedAt = schema.CreatedAt
	vm.schemas[schema.ID] = schema

	return nil
}

// ConnectChainSource connects a chain as a data source
func (vm *VM) ConnectChainSource(chainID ids.ID, chainName string) error {
	vm.chainSources[chainID] = &ChainDataSource{
		ChainID:   chainID,
		ChainName: chainName,
		Connected: true,
		LastSync:  time.Now().Unix(),
	}
	return nil
}

// API handler for Graph-specific endpoints
type apiHandler struct {
	vm *VM
}

func (h *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/graphql":
		h.handleGraphQL(w, r)
	case "/schema":
		h.handleSchema(w, r)
	case "/query":
		h.handleQuery(w, r)
	case "/index":
		h.handleIndex(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (h *apiHandler) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":   nil,
		"errors": []string{"GraphQL endpoint ready"},
	})
}

func (h *apiHandler) handleSchema(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	h.vm.schemaMu.RLock()
	defer h.vm.schemaMu.RUnlock()
	json.NewEncoder(w).Encode(h.vm.schemas)
}

func (h *apiHandler) handleQuery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "query endpoint ready",
	})
}

func (h *apiHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.vm.dataIndexes)
}

// authMiddleware validates API key from Authorization header
func authMiddleware(next http.Handler, validKeys []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized: missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Support both "Bearer <token>" and just "<token>"
		token := strings.TrimPrefix(authHeader, "Bearer ")
		token = strings.TrimSpace(token)

		// Validate token against configured API keys (constant-time comparison)
		var valid bool
		for _, validKey := range validKeys {
			if subtle.ConstantTimeCompare([]byte(token), []byte(validKey)) == 1 {
				valid = true
				break
			}
		}

		if !valid {
			http.Error(w, "Unauthorized: invalid API key", http.StatusUnauthorized)
			return
		}

		// Token is valid, proceed
		next.ServeHTTP(w, r)
	})
}
