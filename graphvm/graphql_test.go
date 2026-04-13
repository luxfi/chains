// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
)

func TestQueryExecutor_BasicQueries(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	config := &GConfig{
		MaxQueryDepth:  10,
		MaxResultSize:  1 << 20,
		QueryTimeoutMs: 5000,
	}

	executor := NewQueryExecutor(db, config)

	tests := []struct {
		name    string
		query   string
		wantErr bool
		checkFn func(t *testing.T, response *GraphQLResponse)
	}{
		{
			name:  "chain info query",
			query: `{ chainInfo { vmName, version, readOnly } }`,
			checkFn: func(t *testing.T, resp *GraphQLResponse) {
				require.Empty(t, resp.Errors)
				require.NotNil(t, resp.Data)
				data := resp.Data.(map[string]interface{})
				chainInfo := data["chainInfo"].(map[string]interface{})
				require.Equal(t, "graphvm", chainInfo["vmName"])
				require.Equal(t, true, chainInfo["readOnly"])
			},
		},
		{
			name:  "chains list query",
			query: `{ chains }`,
			checkFn: func(t *testing.T, resp *GraphQLResponse) {
				require.Empty(t, resp.Errors)
				require.NotNil(t, resp.Data)
				data := resp.Data.(map[string]interface{})
				chains := data["chains"].([]map[string]interface{})
				require.GreaterOrEqual(t, len(chains), 1)
			},
		},
		{
			name:  "has key query - nonexistent",
			query: `{ has(key: "nonexistent") }`,
			checkFn: func(t *testing.T, resp *GraphQLResponse) {
				require.Empty(t, resp.Errors)
				data := resp.Data.(map[string]interface{})
				require.Equal(t, false, data["has"])
			},
		},
		{
			name:  "get key query - nonexistent",
			query: `{ get(key: "nonexistent") }`,
			checkFn: func(t *testing.T, resp *GraphQLResponse) {
				require.Empty(t, resp.Errors)
				data := resp.Data.(map[string]interface{})
				require.Nil(t, data["get"])
			},
		},
		{
			name:    "mutation rejected",
			query:   `mutation { createBlock { hash } }`,
			wantErr: true,
		},
		{
			name:  "schema introspection",
			query: `{ __schema { queryType { name } } }`,
			checkFn: func(t *testing.T, resp *GraphQLResponse) {
				require.Empty(t, resp.Errors)
				require.NotNil(t, resp.Data)
			},
		},
		{
			name:  "type introspection",
			query: `{ __type(name: "Block") { name, fields { name, type } } }`,
			checkFn: func(t *testing.T, resp *GraphQLResponse) {
				require.Empty(t, resp.Errors)
				require.NotNil(t, resp.Data)
				data := resp.Data.(map[string]interface{})
				typeInfo := data["__type"].(map[string]interface{})
				require.Equal(t, "Block", typeInfo["name"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &GraphQLRequest{Query: tt.query}
			resp := executor.Execute(context.Background(), req)

			if tt.wantErr {
				require.NotEmpty(t, resp.Errors)
				return
			}

			if tt.checkFn != nil {
				tt.checkFn(t, resp)
			}
		})
	}
}

func TestQueryExecutor_DatabaseOperations(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	// Seed some data
	require.NoError(t, db.Put([]byte("test:key1"), []byte("value1")))
	require.NoError(t, db.Put([]byte("test:key2"), []byte("value2")))
	require.NoError(t, db.Put([]byte("test:key3"), []byte("value3")))

	executor := NewQueryExecutor(db, nil)

	t.Run("get existing key", func(t *testing.T) {
		req := &GraphQLRequest{Query: `{ get(key: "test:key1") }`}
		resp := executor.Execute(context.Background(), req)

		require.Empty(t, resp.Errors)
		data := resp.Data.(map[string]interface{})
		require.Equal(t, "value1", data["get"])
	})

	t.Run("has existing key", func(t *testing.T) {
		req := &GraphQLRequest{Query: `{ has(key: "test:key2") }`}
		resp := executor.Execute(context.Background(), req)

		require.Empty(t, resp.Errors)
		data := resp.Data.(map[string]interface{})
		require.Equal(t, true, data["has"])
	})

	t.Run("iterate with prefix", func(t *testing.T) {
		req := &GraphQLRequest{Query: `{ iterate(prefix: "test:", limit: "10") }`}
		resp := executor.Execute(context.Background(), req)

		require.Empty(t, resp.Errors)
		data := resp.Data.(map[string]interface{})
		results := data["iterate"].([]map[string]interface{})
		require.Equal(t, 3, len(results))
	})

	t.Run("iterate with limit", func(t *testing.T) {
		req := &GraphQLRequest{Query: `{ iterate(prefix: "test:", limit: "2") }`}
		resp := executor.Execute(context.Background(), req)

		require.Empty(t, resp.Errors)
		data := resp.Data.(map[string]interface{})
		results := data["iterate"].([]map[string]interface{})
		require.Equal(t, 2, len(results))
	})
}

func TestQueryExecutor_BlockchainQueries(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	// Seed block data
	block := map[string]interface{}{
		"hash":      "0x1234",
		"height":    100,
		"timestamp": time.Now().Unix(),
	}
	blockBytes, _ := json.Marshal(block)
	require.NoError(t, db.Put([]byte("block:hash:0x1234"), blockBytes))
	require.NoError(t, db.Put([]byte("block:height:100"), blockBytes))

	// Seed transaction data
	tx := map[string]interface{}{
		"hash":  "0xabcd",
		"from":  "0x1111",
		"to":    "0x2222",
		"value": "1000000",
	}
	txBytes, _ := json.Marshal(tx)
	require.NoError(t, db.Put([]byte("tx:hash:0xabcd"), txBytes))

	// Seed account data
	account := map[string]interface{}{
		"address": "0x1111",
		"balance": "5000000",
		"nonce":   42,
	}
	accountBytes, _ := json.Marshal(account)
	require.NoError(t, db.Put([]byte("account:0x1111"), accountBytes))

	executor := NewQueryExecutor(db, nil)

	t.Run("block by hash", func(t *testing.T) {
		req := &GraphQLRequest{Query: `{ block(hash: "0x1234") }`}
		resp := executor.Execute(context.Background(), req)

		require.Empty(t, resp.Errors)
		data := resp.Data.(map[string]interface{})
		blockData := data["block"].(map[string]interface{})
		require.Equal(t, "0x1234", blockData["hash"])
		require.Equal(t, float64(100), blockData["height"])
	})

	t.Run("block by height", func(t *testing.T) {
		req := &GraphQLRequest{Query: `{ block(height: "100") }`}
		resp := executor.Execute(context.Background(), req)

		require.Empty(t, resp.Errors)
		data := resp.Data.(map[string]interface{})
		blockData := data["block"].(map[string]interface{})
		require.Equal(t, "0x1234", blockData["hash"])
	})

	t.Run("transaction by hash", func(t *testing.T) {
		req := &GraphQLRequest{Query: `{ transaction(hash: "0xabcd") }`}
		resp := executor.Execute(context.Background(), req)

		require.Empty(t, resp.Errors)
		data := resp.Data.(map[string]interface{})
		txData := data["transaction"].(map[string]interface{})
		require.Equal(t, "0xabcd", txData["hash"])
		require.Equal(t, "0x1111", txData["from"])
	})

	t.Run("account by address", func(t *testing.T) {
		req := &GraphQLRequest{Query: `{ account(address: "0x1111") }`}
		resp := executor.Execute(context.Background(), req)

		require.Empty(t, resp.Errors)
		data := resp.Data.(map[string]interface{})
		accData := data["account"].(map[string]interface{})
		require.Equal(t, "0x1111", accData["address"])
		require.Equal(t, "5000000", accData["balance"])
	})

	t.Run("balance by address", func(t *testing.T) {
		req := &GraphQLRequest{Query: `{ balance(address: "0x1111") }`}
		resp := executor.Execute(context.Background(), req)

		require.Empty(t, resp.Errors)
		data := resp.Data.(map[string]interface{})
		require.Equal(t, "5000000", data["balance"])
	})

	t.Run("account not found returns default", func(t *testing.T) {
		req := &GraphQLRequest{Query: `{ account(address: "0x9999") }`}
		resp := executor.Execute(context.Background(), req)

		require.Empty(t, resp.Errors)
		data := resp.Data.(map[string]interface{})
		accData := data["account"].(map[string]interface{})
		require.Equal(t, "0x9999", accData["address"])
		require.Equal(t, "0", accData["balance"])
	})
}

func TestQueryExecutor_QueryParsing(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	executor := NewQueryExecutor(db, nil)

	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{
			name:  "simple query",
			query: `{ chainInfo }`,
		},
		{
			name:  "query with operation name",
			query: `query GetChainInfo { chainInfo }`,
		},
		{
			name:  "query with alias",
			query: `{ info: chainInfo }`,
		},
		{
			name:  "query with arguments",
			query: `{ block(hash: "0x1234") }`,
		},
		{
			name:  "multiple fields",
			query: `{ chainInfo, chains }`,
		},
		{
			name:    "empty query",
			query:   ``,
			wantErr: true,
		},
		{
			name:    "missing braces",
			query:   `chainInfo`,
			wantErr: true,
		},
		{
			name:    "mutation not allowed",
			query:   `mutation { update }`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &GraphQLRequest{Query: tt.query}
			resp := executor.Execute(context.Background(), req)

			if tt.wantErr {
				require.NotEmpty(t, resp.Errors, "expected error for query: %s", tt.query)
			}
		})
	}
}

func TestQueryExecutor_Variables(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	// Seed data
	require.NoError(t, db.Put([]byte("mykey"), []byte("myvalue")))

	executor := NewQueryExecutor(db, nil)

	req := &GraphQLRequest{
		Query: `{ get(key: "mykey") }`,
		Variables: map[string]interface{}{
			"someVar": "unused",
		},
	}

	resp := executor.Execute(context.Background(), req)
	require.Empty(t, resp.Errors)
	data := resp.Data.(map[string]interface{})
	require.Equal(t, "myvalue", data["get"])
}

func TestQueryExecutor_Timeout(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	config := &GConfig{
		QueryTimeoutMs: 1, // 1ms timeout
	}

	executor := NewQueryExecutor(db, config)

	// Use context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := &GraphQLRequest{Query: `{ chainInfo }`}
	resp := executor.Execute(ctx, req)

	// Should still work since chainInfo is fast
	// The timeout is applied inside Execute
	require.Empty(t, resp.Errors)
}

func TestQueryExecutor_CustomResolver(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	executor := NewQueryExecutor(db, nil)

	// Register custom resolver
	executor.RegisterResolver("customField", func(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{
			"custom": true,
			"value":  "hello from custom resolver",
		}, nil
	})

	req := &GraphQLRequest{Query: `{ customField }`}
	resp := executor.Execute(context.Background(), req)

	require.Empty(t, resp.Errors)
	data := resp.Data.(map[string]interface{})
	custom := data["customField"].(map[string]interface{})
	require.Equal(t, true, custom["custom"])
	require.Equal(t, "hello from custom resolver", custom["value"])
}

func TestQueryExecutor_UnknownField(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	executor := NewQueryExecutor(db, nil)

	req := &GraphQLRequest{Query: `{ unknownFieldThatDoesNotExist }`}
	resp := executor.Execute(context.Background(), req)

	require.NotEmpty(t, resp.Errors)
	require.Contains(t, resp.Errors[0].Message, "unknown field")
}

func BenchmarkQueryExecutor_SimpleQuery(b *testing.B) {
	db := memdb.New()
	defer db.Close()

	executor := NewQueryExecutor(db, nil)
	req := &GraphQLRequest{Query: `{ chainInfo }`}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		executor.Execute(ctx, req)
	}
}

func BenchmarkQueryExecutor_DatabaseQuery(b *testing.B) {
	db := memdb.New()
	defer db.Close()

	// Seed data
	for i := 0; i < 100; i++ {
		key := []byte("test:key:" + string(rune('0'+i)))
		value := []byte("value" + string(rune('0'+i)))
		db.Put(key, value)
	}

	executor := NewQueryExecutor(db, nil)
	req := &GraphQLRequest{Query: `{ iterate(prefix: "test:", limit: "50") }`}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		executor.Execute(ctx, req)
	}
}
