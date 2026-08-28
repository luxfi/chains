// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/luxfi/database"
)

var (
	errInvalidQuery    = errors.New("invalid GraphQL query")
	errQueryTooComplex = errors.New("query exceeds max depth")
	errResultTooLarge  = errors.New("result exceeds max size")
	errUnknownField    = errors.New("unknown field requested")
	errQueryTooLong    = errors.New("query exceeds maximum length")
	errQueryTooWide    = errors.New("query requests too many fields")
)

const (
	// maxQueryLength bounds the bytes a caller may send.
	maxQueryLength = 100000 // 100KB

	// maxFields bounds the resolvers one query may run. Length and depth do not
	// bound breadth: `{ a b c ... }` is shallow, short per field, and each field
	// is a database scan.
	maxFields = 100
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
	Message string `json:"message"`
}

// QueryExecutor executes GraphQL queries against the shared database. Its
// resolver table is built once in NewQueryExecutor and read-only thereafter, so
// concurrent requests need no lock.
type QueryExecutor struct {
	db        database.Database
	maxDepth  int
	maxResult int
	timeout   time.Duration

	resolvers map[string]ResolverFunc
}

// ResolverFunc resolves a field from the database. What it returns must be
// JSON-encodable: the response is measured and sent by encoding it.
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

	// MaxResultSize is a promise about the response, so it is measured on the
	// response. Bounding the row count instead would let one wide row past it.
	// A result the response cannot carry and a result too big to send are the
	// same answer — no answer fits — so they are one refusal, not two.
	if encoded, err := json.Marshal(data); err != nil || len(encoded) > e.maxResult {
		return &GraphQLResponse{
			Errors: []GraphQLError{{Message: errResultTooLarge.Error()}},
		}
	}

	return &GraphQLResponse{Data: data}
}

// parsedQuery represents a parsed GraphQL query
type parsedQuery struct {
	fields []parsedField // requested fields
	depth  int           // max nesting depth
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

	if len(fields) > maxFields {
		return nil, errQueryTooWide
	}

	return &parsedQuery{fields: fields, depth: depth}, nil
}

// validateQuerySafety bounds the shape of a query before it is parsed.
//
// It used to also reject "suspicious repetitive patterns" — any aligned 10-byte
// window recurring 100 times. That guard never held: `{ a b a b ... }` repeats
// no aligned window, and every field in it is still a database scan. The bound
// that does hold is maxFields, on the count of resolvers a query runs.
func validateQuerySafety(query string) error {
	openBraces := strings.Count(query, "{")
	closeBraces := strings.Count(query, "}")

	if openBraces != closeBraces {
		return fmt.Errorf("unbalanced braces in query")
	}

	if openBraces > 50 {
		return fmt.Errorf("query has too many nested levels")
	}

	return nil
}

// parseFields extracts the top-level selection set from a query.
func (e *QueryExecutor) parseFields(query string) ([]parsedField, int, error) {
	start := strings.Index(query, "{")
	if start == -1 {
		return nil, 0, errInvalidQuery
	}
	end := strings.LastIndex(query, "}")
	if end <= start {
		return nil, 0, errInvalidQuery
	}
	return e.parseFieldList(query[start+1:end], 1)
}

// parseFieldList reads a selection set: a sequence of
//
//	[alias:] name [(args)] [{ subfields }]
//
// separated by whitespace or commas. Splitting on commas and NEWLINES alone —
// which is what this did — makes `{ a b }` a single field named "a b", so a
// query written the way every GraphQL client prints it came back "unknown field
// requested: a b".
func (e *QueryExecutor) parseFieldList(content string, depth int) ([]parsedField, int, error) {
	fields := make([]parsedField, 0)
	maxDepth := depth

	for i := 0; i < len(content); {
		if isSpace(content[i]) || content[i] == ',' {
			i++
			continue
		}
		if content[i] == '#' { // comment to end of line
			for i < len(content) && content[i] != '\n' {
				i++
			}
			continue
		}

		name, next := readName(content, i)
		if next == i { // not a name: step over the byte so the scan advances
			i++
			continue
		}
		i = skipSpace(content, next)

		field := parsedField{name: name, args: make(map[string]interface{})}

		if i < len(content) && content[i] == ':' { // what was read is the alias
			field.alias = name
			i = skipSpace(content, i+1)
			if field.name, next = readName(content, i); next == i {
				return nil, 0, errInvalidQuery
			}
			i = skipSpace(content, next)
		}

		if i < len(content) && content[i] == '(' {
			args, next, ok := readBalanced(content, i, '(', ')')
			if !ok {
				return nil, 0, errInvalidQuery
			}
			field.args = parseArgs(args)
			i = skipSpace(content, next)
		}

		if i < len(content) && content[i] == '{' {
			sub, next, ok := readBalanced(content, i, '{', '}')
			if !ok {
				return nil, 0, errInvalidQuery
			}
			subfields, subDepth, err := e.parseFieldList(sub, depth+1)
			if err != nil {
				return nil, 0, err
			}
			field.subfields = subfields
			if subDepth > maxDepth {
				maxDepth = subDepth
			}
			i = next
		}

		fields = append(fields, field)
	}

	return fields, maxDepth, nil
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func skipSpace(s string, i int) int {
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	return i
}

// readName reads a GraphQL name — letters, digits and underscore — returning it
// and the index just past it.
func readName(s string, i int) (string, int) {
	start := i
	for i < len(s) && (s[i] == '_' || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	return s[start:i], i
}

// readBalanced takes the opening delimiter at i and returns what it encloses
// plus the index just past its match. An unterminated group is not a group.
func readBalanced(s string, i int, open, close byte) (string, int, bool) {
	start, depth := i, 0
	for ; i < len(s); i++ {
		switch s[i] {
		case open:
			depth++
		case close:
			if depth--; depth == 0 {
				return s[start+1 : i], i + 1, true
			}
		}
	}
	return "", 0, false
}

// parseArgs reads "key: value, key2: {k: v}, key3: [a, b]".
//
// A nested object is the `where:` filter every subgraph client sends. Splitting
// the argument list on commas made `where: {token0: "0x1"}` the STRING
// "{token0", which no resolver recognised as a filter — so `pools(where: ...)`
// answered with every pool on the chain and reported no error.
func parseArgs(s string) map[string]interface{} {
	args := make(map[string]interface{})

	for i := 0; i < len(s); {
		if isSpace(s[i]) || s[i] == ',' {
			i++
			continue
		}
		key, next := readName(s, i)
		if next == i { // not a name: step over it
			i++
			continue
		}
		i = skipSpace(s, next)
		if i >= len(s) || s[i] != ':' {
			continue // a bare token is not an argument, and i is past it
		}
		args[key], i = readValue(s, i+1)
	}

	return args
}

// readValue reads one argument value: an object, a list, a quoted string, or a
// bare token.
func readValue(s string, i int) (interface{}, int) {
	i = skipSpace(s, i)
	if i >= len(s) {
		return "", i
	}

	switch s[i] {
	case '{':
		body, next, ok := readBalanced(s, i, '{', '}')
		if !ok {
			return "", len(s)
		}
		return parseArgs(body), next

	case '[':
		body, next, ok := readBalanced(s, i, '[', ']')
		if !ok {
			return "", len(s)
		}
		list := []interface{}{}
		for j := 0; j < len(body); {
			if isSpace(body[j]) || body[j] == ',' {
				j++
				continue
			}
			var v interface{}
			v, j = readValue(body, j)
			list = append(list, v)
		}
		return list, next

	case '"', '\'':
		quote := s[i]
		var out []byte
		for j := i + 1; j < len(s); j++ {
			if s[j] == '\\' && j+1 < len(s) {
				j++
				out = append(out, s[j])
				continue
			}
			if s[j] == quote {
				return string(out), j + 1
			}
			out = append(out, s[j])
		}
		return string(out), len(s)
	}

	start := i
	for i < len(s) && s[i] != ',' && s[i] != '}' && s[i] != ']' && !isSpace(s[i]) {
		i++
	}
	return s[start:i], i
}

// executeQuery executes a parsed query
func (e *QueryExecutor) executeQuery(ctx context.Context, parsed *parsedQuery, variables map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for _, field := range parsed.fields {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

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
	return e.getLatestBlocks(ctx, db, bound(args, "limit", 10, 100))
}

func (e *QueryExecutor) resolveLatestBlock(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	return e.getLatestBlocks(ctx, db, 1)
}

func (e *QueryExecutor) resolveTransaction(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	if hash, ok := args["hash"].(string); ok {
		return e.getTransactionByHash(db, hash)
	}
	return nil, fmt.Errorf("transaction: requires 'hash' argument")
}

func (e *QueryExecutor) resolveTransactions(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	return e.getLatestTransactions(ctx, db, bound(args, "limit", 10, 100))
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

// resolveChainInfo describes this VM. It carries no clock: a wall-clock reading
// is the server's, not the chain's, and two nodes answering the same query
// differently is the thing this chain exists to avoid.
func (e *QueryExecutor) resolveChainInfo(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"vmName":   "graphvm",
		"version":  Version.String(),
		"readOnly": true,
	}, nil
}

func (e *QueryExecutor) resolveGet(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	key, ok := args["key"].(string)
	if !ok {
		return nil, fmt.Errorf("get: requires 'key' argument")
	}

	value, err := db.Get([]byte(key))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
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
	prefix, _ := args["prefix"].(string)
	limit := bound(args, "limit", 100, 1000)

	iter := db.NewIteratorWithPrefix([]byte(prefix))
	defer iter.Release()

	results := make([]map[string]interface{}, 0, limit)
	for iter.Next() && len(results) < limit {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		results = append(results, map[string]interface{}{
			"key":   string(iter.Key()),
			"value": string(iter.Value()),
		})
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
	return object(db, "block:hash:"+hash)
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
	return object(db, fmt.Sprintf("block:height:%d", h))
}

func (e *QueryExecutor) getLatestBlocks(ctx context.Context, db database.Database, limit int) (interface{}, error) {
	return scan[map[string]interface{}](ctx, db, "block:height:", limit)
}

func (e *QueryExecutor) getTransactionByHash(db database.Database, hash string) (interface{}, error) {
	return object(db, "tx:hash:"+hash)
}

func (e *QueryExecutor) getLatestTransactions(ctx context.Context, db database.Database, limit int) (interface{}, error) {
	return scan[map[string]interface{}](ctx, db, "tx:", limit)
}

// getAccountByAddress answers a zero account for an address with no record —
// an address that has never been seen has a balance, and it is zero.
func (e *QueryExecutor) getAccountByAddress(db database.Database, addr string) (map[string]interface{}, error) {
	acct, err := object(db, "account:"+addr)
	if err != nil {
		return nil, err
	}
	if acct == nil {
		return map[string]interface{}{"address": addr, "balance": "0", "nonce": 0}, nil
	}
	return acct.(map[string]interface{}), nil
}

func (e *QueryExecutor) getBalanceByAddress(db database.Database, addr string) (interface{}, error) {
	account, err := e.getAccountByAddress(db, addr)
	if err != nil {
		return nil, err
	}
	return account["balance"], nil
}

// scan reads one bounded window of JSON records under a prefix. It is `list`
// without the ordering and where-narrowing the subgraph surface adds.
func scan[T any](ctx context.Context, db database.Database, prefix string, limit int) ([]T, error) {
	iter := db.NewIteratorWithPrefix([]byte(prefix))
	defer iter.Release()

	out := make([]T, 0, limit)
	for iter.Next() && len(out) < limit {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var v T
		if err := json.Unmarshal(iter.Value(), &v); err != nil {
			continue
		}
		out = append(out, v)
	}
	return out, iter.Error()
}
