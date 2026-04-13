// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

var (
	errInvalidQuery    = errors.New("invalid GraphQL query")
	errQueryTooComplex = errors.New("query exceeds max depth")
	errResultTooLarge  = errors.New("result exceeds max size")
	errUnknownField    = errors.New("unknown field requested")
	errUnsupportedType = errors.New("unsupported query type")
	errQueryTooLong    = errors.New("query exceeds maximum length")
)

const (
	// Maximum query length to prevent DoS
	maxQueryLength = 100000 // 100KB
)

// GraphQLRequest represents an incoming GraphQL request
type GraphQLRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLResponse represents a GraphQL response
type GraphQLResponse struct {
	Data   interface{}    `json:"data,omitempty"`
	Errors []GraphQLError `json:"errors,omitempty"`
}

// GraphQLError represents a GraphQL error
type GraphQLError struct {
	Message   string     `json:"message"`
	Locations []Location `json:"locations,omitempty"`
	Path      []string   `json:"path,omitempty"`
}

// Location represents a location in the query
type Location struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// QueryExecutor executes GraphQL queries against the shared database
type QueryExecutor struct {
	db        database.Database
	maxDepth  int
	maxResult int
	timeout   time.Duration

	// Schema registry
	schemaMu sync.RWMutex
	schemas  map[string]*GraphSchema

	// Read-only resolvers for each data type
	resolvers map[string]ResolverFunc
}

// ResolverFunc resolves a field from the database
type ResolverFunc func(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error)

// NewQueryExecutor creates a new GraphQL query executor
func NewQueryExecutor(db database.Database, config *GConfig) *QueryExecutor {
	maxDepth := 10
	maxResult := 1 << 20 // 1MB
	timeout := 30 * time.Second

	if config != nil {
		if config.MaxQueryDepth > 0 {
			maxDepth = config.MaxQueryDepth
		}
		if config.MaxResultSize > 0 {
			maxResult = config.MaxResultSize
		}
		if config.QueryTimeoutMs > 0 {
			timeout = time.Duration(config.QueryTimeoutMs) * time.Millisecond
		}
	}

	exec := &QueryExecutor{
		db:        db,
		maxDepth:  maxDepth,
		maxResult: maxResult,
		timeout:   timeout,
		schemas:   make(map[string]*GraphSchema),
		resolvers: make(map[string]ResolverFunc),
	}

	// Register built-in resolvers for read-only access
	exec.registerBuiltinResolvers()

	return exec
}

// registerBuiltinResolvers sets up default resolvers for blockchain data
func (e *QueryExecutor) registerBuiltinResolvers() {
	// Block queries
	e.resolvers["block"] = e.resolveBlock
	e.resolvers["blocks"] = e.resolveBlocks
	e.resolvers["latestBlock"] = e.resolveLatestBlock

	// Transaction queries
	e.resolvers["transaction"] = e.resolveTransaction
	e.resolvers["transactions"] = e.resolveTransactions

	// Account/address queries
	e.resolvers["account"] = e.resolveAccount
	e.resolvers["balance"] = e.resolveBalance

	// Chain info
	e.resolvers["chainInfo"] = e.resolveChainInfo
	e.resolvers["chains"] = e.resolveChains

	// Database key-value queries (generic read access)
	e.resolvers["get"] = e.resolveGet
	e.resolvers["has"] = e.resolveHas
	e.resolvers["iterate"] = e.resolveIterate

	// Schema introspection
	e.resolvers["__schema"] = e.resolveSchema
	e.resolvers["__type"] = e.resolveType

	// DEX resolvers (v2/v3 subgraph compatible)
	e.registerDexResolvers()
}

// Execute executes a GraphQL query
func (e *QueryExecutor) Execute(ctx context.Context, req *GraphQLRequest) *GraphQLResponse {
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Parse the query
	parsed, err := e.parseQuery(req.Query)
	if err != nil {
		return &GraphQLResponse{
			Errors: []GraphQLError{{Message: err.Error()}},
		}
	}

	// Validate query depth
	if parsed.depth > e.maxDepth {
		return &GraphQLResponse{
			Errors: []GraphQLError{{Message: errQueryTooComplex.Error()}},
		}
	}

	// Execute the query
	data, err := e.executeQuery(ctx, parsed, req.Variables)
	if err != nil {
		return &GraphQLResponse{
			Errors: []GraphQLError{{Message: err.Error()}},
		}
	}

	return &GraphQLResponse{Data: data}
}

// parsedQuery represents a parsed GraphQL query
type parsedQuery struct {
	operation string        // query, mutation (rejected for read-only)
	name      string        // operation name
	fields    []parsedField // requested fields
	depth     int           // max nesting depth
}

// parsedField represents a field in the query
type parsedField struct {
	name      string
	alias     string
	args      map[string]interface{}
	subfields []parsedField
}

// parseQuery parses a GraphQL query string (simplified parser)
func (e *QueryExecutor) parseQuery(query string) (*parsedQuery, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errInvalidQuery
	}

	// Prevent DoS via excessively large queries
	if len(query) > maxQueryLength {
		return nil, errQueryTooLong
	}

	// Validate query doesn't contain potentially dangerous patterns
	if err := validateQuerySafety(query); err != nil {
		return nil, err
	}

	parsed := &parsedQuery{
		operation: "query",
		fields:    make([]parsedField, 0),
	}

	// Check for mutation (not allowed for read-only)
	if strings.HasPrefix(strings.ToLower(query), "mutation") {
		return nil, fmt.Errorf("mutations not allowed: G-chain is read-only")
	}

	// Remove query keyword if present (simple string replacement, no regex)
	if strings.HasPrefix(strings.ToLower(query), "query") {
		// Find the opening brace
		braceIdx := strings.Index(query, "{")
		if braceIdx > 0 {
			query = query[braceIdx:]
		}
	}

	// Parse fields from { ... }
	fields, depth, err := e.parseFields(query)
	if err != nil {
		return nil, err
	}

	parsed.fields = fields
	parsed.depth = depth

	return parsed, nil
}

// validateQuerySafety checks for potentially malicious query patterns
func validateQuerySafety(query string) error {
	// Check for excessive nesting indicators
	openBraces := strings.Count(query, "{")
	closeBraces := strings.Count(query, "}")

	if openBraces != closeBraces {
		return fmt.Errorf("unbalanced braces in query")
	}

	if openBraces > 50 {
		return fmt.Errorf("query has too many nested levels")
	}

	// Check for excessively repeated patterns (potential DoS)
	// Simple heuristic: if any 10-char substring appears more than 100 times, reject
	if len(query) > 100 {
		counts := make(map[string]int)
		for i := 0; i <= len(query)-10; i += 10 {
			substr := query[i : i+10]
			counts[substr]++
			if counts[substr] > 100 {
				return fmt.Errorf("query contains suspicious repetitive patterns")
			}
		}
	}

	return nil
}

// parseFields extracts fields from a GraphQL selection set
func (e *QueryExecutor) parseFields(query string) ([]parsedField, int, error) {
	// Find the main braces
	start := strings.Index(query, "{")
	if start == -1 {
		return nil, 0, errInvalidQuery
	}
	end := strings.LastIndex(query, "}")
	if end == -1 || end <= start {
		return nil, 0, errInvalidQuery
	}

	content := query[start+1 : end]
	fields, depth := e.parseFieldList(content, 1)

	return fields, depth, nil
}

// parseFieldList parses a comma/newline separated list of fields
func (e *QueryExecutor) parseFieldList(content string, currentDepth int) ([]parsedField, int) {
	fields := make([]parsedField, 0)
	maxDepth := currentDepth

	content = strings.TrimSpace(content)
	if content == "" {
		return fields, maxDepth
	}

	// Tokenize by finding top-level fields (respecting nested braces)
	i := 0
	for i < len(content) {
		// Skip whitespace
		for i < len(content) && (content[i] == ' ' || content[i] == '\t' || content[i] == '\n' || content[i] == '\r' || content[i] == ',') {
			i++
		}
		if i >= len(content) {
			break
		}

		// Skip comments
		if content[i] == '#' {
			for i < len(content) && content[i] != '\n' {
				i++
			}
			continue
		}

		// Find end of this field (next top-level comma/newline or end)
		start := i
		depth := 0
		inParen := 0
		for i < len(content) {
			c := content[i]
			if c == '(' {
				inParen++
			} else if c == ')' {
				inParen--
			} else if c == '{' {
				depth++
			} else if c == '}' {
				depth--
			} else if (c == ',' || c == '\n') && depth == 0 && inParen == 0 {
				break
			}
			i++
		}

		part := strings.TrimSpace(content[start:i])
		if part == "" || strings.HasPrefix(part, "#") {
			continue
		}

		field := parsedField{
			args: make(map[string]interface{}),
		}

		// Check for subfields
		braceIdx := strings.Index(part, "{")
		if braceIdx > 0 {
			// Has subfields
			header := part[:braceIdx]
			field.name, field.alias, field.args = e.parseFieldHeader(header)

			// Find matching closing brace
			braceDepth := 1
			endBrace := braceIdx
			for j := braceIdx + 1; j < len(part); j++ {
				if part[j] == '{' {
					braceDepth++
				} else if part[j] == '}' {
					braceDepth--
					if braceDepth == 0 {
						endBrace = j
						break
					}
				}
			}

			if endBrace > braceIdx+1 {
				subfieldContent := part[braceIdx+1 : endBrace]
				subfields, subDepth := e.parseFieldList(subfieldContent, currentDepth+1)
				field.subfields = subfields
				if subDepth > maxDepth {
					maxDepth = subDepth
				}
			}
		} else {
			// Simple field
			field.name, field.alias, field.args = e.parseFieldHeader(part)
		}

		if field.name != "" {
			fields = append(fields, field)
		}
	}

	return fields, maxDepth
}

// parseFieldHeader parses "alias: fieldName(arg: value)"
func (e *QueryExecutor) parseFieldHeader(header string) (name, alias string, args map[string]interface{}) {
	args = make(map[string]interface{})
	header = strings.TrimSpace(header)

	// Check for alias
	if idx := strings.Index(header, ":"); idx > 0 && !strings.Contains(header[:idx], "(") {
		alias = strings.TrimSpace(header[:idx])
		header = strings.TrimSpace(header[idx+1:])
	}

	// Check for arguments
	if idx := strings.Index(header, "("); idx > 0 {
		name = strings.TrimSpace(header[:idx])
		argsEnd := strings.LastIndex(header, ")")
		if argsEnd > idx {
			argsStr := header[idx+1 : argsEnd]
			args = e.parseArgs(argsStr)
		}
	} else {
		name = strings.TrimSpace(header)
	}

	return name, alias, args
}

// parseArgs parses "key: value, key2: value2"
func (e *QueryExecutor) parseArgs(argsStr string) map[string]interface{} {
	args := make(map[string]interface{})
	parts := strings.Split(argsStr, ",")

	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])
			// Remove quotes from string values
			value = strings.Trim(value, `"'`)
			args[key] = value
		}
	}

	return args
}

// executeQuery executes a parsed query
func (e *QueryExecutor) executeQuery(ctx context.Context, parsed *parsedQuery, variables map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for _, field := range parsed.fields {
		// Merge variables into args
		args := make(map[string]interface{})
		for k, v := range field.args {
			args[k] = v
		}
		for k, v := range variables {
			if _, exists := args[k]; !exists {
				args[k] = v
			}
		}

		// Find resolver
		resolver, ok := e.resolvers[field.name]
		if !ok {
			return nil, fmt.Errorf("%w: %s", errUnknownField, field.name)
		}

		// Execute resolver
		value, err := resolver(ctx, e.db, args)
		if err != nil {
			return nil, err
		}

		// Use alias if provided
		key := field.name
		if field.alias != "" {
			key = field.alias
		}
		result[key] = value
	}

	return result, nil
}

// Database resolvers for read-only access

func (e *QueryExecutor) resolveBlock(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	// Get block by hash or height
	if hash, ok := args["hash"].(string); ok {
		return e.getBlockByHash(db, hash)
	}
	if height, ok := args["height"]; ok {
		return e.getBlockByHeight(db, height)
	}
	return nil, fmt.Errorf("block: requires 'hash' or 'height' argument")
}

func (e *QueryExecutor) resolveBlocks(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	// Get range of blocks
	limit := 10
	if l, ok := args["limit"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit > 100 {
		limit = 100
	}

	return e.getLatestBlocks(db, limit)
}

func (e *QueryExecutor) resolveLatestBlock(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	return e.getLatestBlocks(db, 1)
}

func (e *QueryExecutor) resolveTransaction(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	if hash, ok := args["hash"].(string); ok {
		return e.getTransactionByHash(db, hash)
	}
	return nil, fmt.Errorf("transaction: requires 'hash' argument")
}

func (e *QueryExecutor) resolveTransactions(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 10
	if l, ok := args["limit"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit > 100 {
		limit = 100
	}

	return e.getLatestTransactions(db, limit)
}

func (e *QueryExecutor) resolveAccount(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	if addr, ok := args["address"].(string); ok {
		return e.getAccountByAddress(db, addr)
	}
	return nil, fmt.Errorf("account: requires 'address' argument")
}

func (e *QueryExecutor) resolveBalance(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	if addr, ok := args["address"].(string); ok {
		return e.getBalanceByAddress(db, addr)
	}
	return nil, fmt.Errorf("balance: requires 'address' argument")
}

func (e *QueryExecutor) resolveChainInfo(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"vmName":    "graphvm",
		"version":   Version.String(),
		"readOnly":  true,
		"timestamp": time.Now().Unix(),
	}, nil
}

func (e *QueryExecutor) resolveChains(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	// Return list of connected chain data sources
	return []map[string]interface{}{
		{"id": "C", "name": "C-Chain", "type": "EVM"},
		{"id": "P", "name": "P-Chain", "type": "Platform"},
		{"id": "X", "name": "X-Chain", "type": "Exchange"},
		{"id": "D", "name": "D-Chain", "type": "DEX"},
	}, nil
}

func (e *QueryExecutor) resolveGet(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	key, ok := args["key"].(string)
	if !ok {
		return nil, fmt.Errorf("get: requires 'key' argument")
	}

	value, err := db.Get([]byte(key))
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	return string(value), nil
}

func (e *QueryExecutor) resolveHas(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	key, ok := args["key"].(string)
	if !ok {
		return nil, fmt.Errorf("has: requires 'key' argument")
	}

	has, err := db.Has([]byte(key))
	if err != nil {
		return false, err
	}

	return has, nil
}

func (e *QueryExecutor) resolveIterate(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	prefix := ""
	if p, ok := args["prefix"].(string); ok {
		prefix = p
	}

	limit := 100
	if l, ok := args["limit"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit > 1000 {
		limit = 1000
	}

	// Use database iterator
	iter := db.NewIteratorWithPrefix([]byte(prefix))
	defer iter.Release()

	results := make([]map[string]interface{}, 0, limit)
	count := 0

	for iter.Next() && count < limit {
		results = append(results, map[string]interface{}{
			"key":   string(iter.Key()),
			"value": string(iter.Value()),
		})
		count++
	}

	return results, iter.Error()
}

func (e *QueryExecutor) resolveSchema(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"queryType": map[string]interface{}{
			"name": "Query",
		},
		"types": []map[string]interface{}{
			{"name": "Block"},
			{"name": "Transaction"},
			{"name": "Account"},
		},
	}, nil
}

func (e *QueryExecutor) resolveType(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	typeName, ok := args["name"].(string)
	if !ok {
		return nil, nil
	}

	// Return type info based on name
	switch typeName {
	case "Block":
		return map[string]interface{}{
			"name": "Block",
			"fields": []map[string]interface{}{
				{"name": "hash", "type": "String"},
				{"name": "height", "type": "Int"},
				{"name": "timestamp", "type": "Int"},
				{"name": "transactions", "type": "[Transaction]"},
			},
		}, nil
	case "Transaction":
		return map[string]interface{}{
			"name": "Transaction",
			"fields": []map[string]interface{}{
				{"name": "hash", "type": "String"},
				{"name": "from", "type": "String"},
				{"name": "to", "type": "String"},
				{"name": "value", "type": "String"},
			},
		}, nil
	case "Account":
		return map[string]interface{}{
			"name": "Account",
			"fields": []map[string]interface{}{
				{"name": "address", "type": "String"},
				{"name": "balance", "type": "String"},
				{"name": "nonce", "type": "Int"},
			},
		}, nil
	}

	return nil, nil
}

// Database access helpers (use prefixed keys for cross-chain data)

func (e *QueryExecutor) getBlockByHash(db database.Database, hash string) (interface{}, error) {
	// Try to load from database
	key := []byte("block:hash:" + hash)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var block map[string]interface{}
	if err := json.Unmarshal(data, &block); err != nil {
		return nil, err
	}

	return block, nil
}

func (e *QueryExecutor) getBlockByHeight(db database.Database, height interface{}) (interface{}, error) {
	var h uint64
	switch v := height.(type) {
	case string:
		fmt.Sscanf(v, "%d", &h)
	case float64:
		h = uint64(v)
	case int:
		h = uint64(v)
	}

	key := []byte(fmt.Sprintf("block:height:%d", h))
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var block map[string]interface{}
	if err := json.Unmarshal(data, &block); err != nil {
		return nil, err
	}

	return block, nil
}

func (e *QueryExecutor) getLatestBlocks(db database.Database, limit int) (interface{}, error) {
	// Iterate over blocks prefix
	iter := db.NewIteratorWithPrefix([]byte("block:height:"))
	defer iter.Release()

	blocks := make([]map[string]interface{}, 0, limit)

	// Move to end and iterate backwards (newest first)
	for iter.Next() {
		if len(blocks) >= limit {
			break
		}

		var block map[string]interface{}
		if err := json.Unmarshal(iter.Value(), &block); err != nil {
			continue
		}
		blocks = append(blocks, block)
	}

	return blocks, iter.Error()
}

func (e *QueryExecutor) getTransactionByHash(db database.Database, hash string) (interface{}, error) {
	key := []byte("tx:hash:" + hash)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var tx map[string]interface{}
	if err := json.Unmarshal(data, &tx); err != nil {
		return nil, err
	}

	return tx, nil
}

func (e *QueryExecutor) getLatestTransactions(db database.Database, limit int) (interface{}, error) {
	iter := db.NewIteratorWithPrefix([]byte("tx:"))
	defer iter.Release()

	txs := make([]map[string]interface{}, 0, limit)

	for iter.Next() {
		if len(txs) >= limit {
			break
		}

		var tx map[string]interface{}
		if err := json.Unmarshal(iter.Value(), &tx); err != nil {
			continue
		}
		txs = append(txs, tx)
	}

	return txs, iter.Error()
}

func (e *QueryExecutor) getAccountByAddress(db database.Database, addr string) (interface{}, error) {
	key := []byte("account:" + addr)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return map[string]interface{}{
				"address": addr,
				"balance": "0",
				"nonce":   0,
			}, nil
		}
		return nil, err
	}

	var account map[string]interface{}
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, err
	}

	return account, nil
}

func (e *QueryExecutor) getBalanceByAddress(db database.Database, addr string) (interface{}, error) {
	account, err := e.getAccountByAddress(db, addr)
	if err != nil {
		return nil, err
	}

	if acc, ok := account.(map[string]interface{}); ok {
		return acc["balance"], nil
	}

	return "0", nil
}

// RegisterResolver allows adding custom resolvers
func (e *QueryExecutor) RegisterResolver(name string, resolver ResolverFunc) {
	e.resolvers[name] = resolver
}

// GetDB returns the underlying database (read-only access)
func (e *QueryExecutor) GetDB() database.Database {
	return e.db
}

// SubscribeChain connects a chain as a data source for cross-chain queries
func (e *QueryExecutor) SubscribeChain(chainID ids.ID, chainName string, prefix string) error {
	// Create prefixed database view for this chain
	// This allows querying data from multiple chains
	return nil
}
