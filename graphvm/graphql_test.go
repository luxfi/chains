// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
)

// failDB answers every read with a failure that is NOT ErrNotFound, so a
// resolver reporting "nothing found" for a database that could not be read is
// visible as the wrong answer it is.
type failDB struct {
	database.Database
	err error
}

func (d *failDB) Get([]byte) ([]byte, error) { return nil, d.err }
func (d *failDB) Has([]byte) (bool, error)   { return false, d.err }
func (d *failDB) NewIteratorWithPrefix(p []byte) database.Iterator {
	return &failIter{err: d.err}
}

type failIter struct {
	database.Iterator
	err error
}

func (i *failIter) Next() bool    { return false }
func (i *failIter) Error() error  { return i.err }
func (i *failIter) Release()      {}
func (i *failIter) Key() []byte   { return nil }
func (i *failIter) Value() []byte { return nil }

func query(t *testing.T, e *QueryExecutor, q string) map[string]interface{} {
	t.Helper()
	resp := e.Execute(context.Background(), &GraphQLRequest{Query: q})
	require.Empty(t, resp.Errors, "query %q", q)
	require.NotNil(t, resp.Data)
	return resp.Data.(map[string]interface{})
}

func queryErr(t *testing.T, e *QueryExecutor, q string) string {
	t.Helper()
	resp := e.Execute(context.Background(), &GraphQLRequest{Query: q})
	require.NotEmpty(t, resp.Errors, "query %q was expected to fail", q)
	return resp.Errors[0].Message
}

func TestQueryExecutorBasicQueries(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	e := NewQueryExecutor(db, &GConfig{MaxQueryDepth: 10, MaxResultSize: 1 << 20, QueryTimeoutMs: 5000})

	t.Run("chainInfo", func(t *testing.T) {
		info := query(t, e, `{ chainInfo { vmName, version, readOnly } }`)["chainInfo"].(map[string]interface{})
		require.Equal(t, "graphvm", info["vmName"])
		require.Equal(t, Version.String(), info["version"])
		require.Equal(t, true, info["readOnly"])
	})

	t.Run("chainInfo carries no clock", func(t *testing.T) {
		// A wall-clock reading here is the server's, not the chain's; two
		// answers to the same query must be the same answer.
		a := query(t, e, `{ chainInfo }`)
		b := query(t, e, `{ chainInfo }`)
		require.Equal(t, a, b)
		require.NotContains(t, a["chainInfo"].(map[string]interface{}), "timestamp")
	})

	t.Run("has missing key", func(t *testing.T) {
		require.Equal(t, false, query(t, e, `{ has(key: "nonexistent") }`)["has"])
	})

	t.Run("get missing key", func(t *testing.T) {
		require.Nil(t, query(t, e, `{ get(key: "nonexistent") }`)["get"])
	})

	t.Run("mutation rejected", func(t *testing.T) {
		require.Contains(t, queryErr(t, e, `mutation { createBlock { hash } }`), "read-only")
	})

	t.Run("schema introspection", func(t *testing.T) {
		s := query(t, e, `{ __schema { queryType { name } } }`)["__schema"].(map[string]interface{})
		require.Equal(t, "Query", s["queryType"].(map[string]interface{})["name"])
	})

	t.Run("type introspection", func(t *testing.T) {
		for _, name := range []string{"Block", "Transaction", "Account"} {
			info := query(t, e, `{ __type(name: "`+name+`") }`)["__type"].(map[string]interface{})
			require.Equal(t, name, info["name"])
			require.NotEmpty(t, info["fields"])
		}
		require.Nil(t, query(t, e, `{ __type(name: "Nope") }`)["__type"])
		require.Nil(t, query(t, e, `{ __type }`)["__type"])
	})
}

func TestQueryExecutorDatabaseOperations(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	for _, k := range []string{"test:key1", "test:key2", "test:key3"} {
		require.NoError(t, db.Put([]byte(k), []byte("v-"+k)))
	}

	e := NewQueryExecutor(db, nil)

	require.Equal(t, "v-test:key1", query(t, e, `{ get(key: "test:key1") }`)["get"])
	require.Equal(t, true, query(t, e, `{ has(key: "test:key2") }`)["has"])

	rows := query(t, e, `{ iterate(prefix: "test:", limit: "10") }`)["iterate"].([]map[string]interface{})
	require.Len(t, rows, 3)
	require.Equal(t, "test:key1", rows[0]["key"])

	rows = query(t, e, `{ iterate(prefix: "test:", limit: "2") }`)["iterate"].([]map[string]interface{})
	require.Len(t, rows, 2)

	require.Contains(t, queryErr(t, e, `{ get }`), "requires 'key'")
	require.Contains(t, queryErr(t, e, `{ has }`), "requires 'key'")
}

// A read that FAILED is not "found nothing". A resolver that flattens the two
// tells a caller an account has no balance when the disk is gone.
func TestFailedReadIsNotAnEmptyAnswer(t *testing.T) {
	boom := errors.New("disk gone")
	e := NewQueryExecutor(&failDB{err: boom}, nil)

	for _, q := range []string{
		`{ get(key: "k") }`,
		`{ has(key: "k") }`,
		`{ block(hash: "0x1") }`,
		`{ block(height: "1") }`,
		`{ blocks }`,
		`{ transaction(hash: "0x1") }`,
		`{ transactions }`,
		`{ account(address: "0x1") }`,
		`{ balance(address: "0x1") }`,
		`{ iterate }`,
		`{ token(id: "0x1") }`,
		`{ tokens }`,
		`{ factory }`,
		`{ pools(where: {token0: "0x1"}) }`,
	} {
		resp := e.Execute(context.Background(), &GraphQLRequest{Query: q})
		require.NotEmpty(t, resp.Errors, "query %q reported success against an unreadable database", q)
		require.Contains(t, resp.Errors[0].Message, "disk gone", "query %q", q)
	}
}

func TestQueryExecutorBlockchainQueries(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	put := func(key string, v interface{}) {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		require.NoError(t, db.Put([]byte(key), raw))
	}

	block := map[string]interface{}{"hash": "0x1234", "height": 100}
	put("block:hash:0x1234", block)
	put("block:height:100", block)
	put("tx:hash:0xabcd", map[string]interface{}{"hash": "0xabcd", "from": "0x1111"})
	put("account:0x1111", map[string]interface{}{"address": "0x1111", "balance": "5000000", "nonce": 42})

	e := NewQueryExecutor(db, nil)

	require.Equal(t, "0x1234", query(t, e, `{ block(hash: "0x1234") }`)["block"].(map[string]interface{})["hash"])
	require.Equal(t, "0x1234", query(t, e, `{ block(height: "100") }`)["block"].(map[string]interface{})["hash"])
	require.Nil(t, query(t, e, `{ block(hash: "0xdead") }`)["block"])
	require.Contains(t, queryErr(t, e, `{ block }`), "requires 'hash' or 'height'")

	require.Equal(t, "0xabcd", query(t, e, `{ transaction(hash: "0xabcd") }`)["transaction"].(map[string]interface{})["hash"])
	require.Contains(t, queryErr(t, e, `{ transaction }`), "requires 'hash'")

	acct := query(t, e, `{ account(address: "0x1111") }`)["account"].(map[string]interface{})
	require.Equal(t, "5000000", acct["balance"])
	require.Equal(t, "5000000", query(t, e, `{ balance(address: "0x1111") }`)["balance"])
	require.Contains(t, queryErr(t, e, `{ account }`), "requires 'address'")
	require.Contains(t, queryErr(t, e, `{ balance }`), "requires 'address'")

	// An address never seen has a balance, and it is zero.
	unseen := query(t, e, `{ account(address: "0x9999") }`)["account"].(map[string]interface{})
	require.Equal(t, "0x9999", unseen["address"])
	require.Equal(t, "0", unseen["balance"])
	require.Equal(t, "0", query(t, e, `{ balance(address: "0x9999") }`)["balance"])

	require.Len(t, query(t, e, `{ blocks }`)["blocks"], 1)
	require.Len(t, query(t, e, `{ latestBlock }`)["latestBlock"], 1)
	require.Len(t, query(t, e, `{ transactions }`)["transactions"], 1)

	// A record that is not JSON is skipped, not fatal.
	require.NoError(t, db.Put([]byte("block:height:101"), []byte("not json")))
	require.Len(t, query(t, e, `{ blocks }`)["blocks"], 1)

	// ... but a record that is not JSON where one was named IS an error.
	require.Contains(t, queryErr(t, e, `{ block(height: "101") }`), "invalid character")
}

func TestQueryParsing(t *testing.T) {
	e := NewQueryExecutor(memdb.New(), nil)

	for _, tt := range []struct {
		name, q string
		fail    string
	}{
		{name: "simple", q: `{ chainInfo }`},
		{name: "operation name", q: `query GetChainInfo { chainInfo }`},
		{name: "alias", q: `{ info: chainInfo }`},
		{name: "arguments", q: `{ block(hash: "0x1234") }`},
		{name: "multiple fields", q: `{ chainInfo, __schema }`},
		{name: "comments", q: "{\n# a comment\nchainInfo\n}"},
		{name: "nested", q: `{ chainInfo { vmName } }`},
		{name: "empty", q: ``, fail: "invalid GraphQL query"},
		{name: "blank", q: `    `, fail: "invalid GraphQL query"},
		{name: "no braces", q: `chainInfo`, fail: "invalid GraphQL query"},
		{name: "open brace only", q: `{ chainInfo`, fail: "unbalanced braces"},
		{name: "close before open", q: `} chainInfo {`, fail: "invalid GraphQL query"},
		{name: "mutation", q: `mutation { update }`, fail: "read-only"},
		{name: "too long", q: "{" + strings.Repeat("a", maxQueryLength) + "}", fail: "maximum length"},
		{name: "too deep for braces", q: "{" + strings.Repeat("a{", 51) + strings.Repeat("}", 51) + "}", fail: "too many nested levels"},
		{name: "too many fields", q: "{" + strings.Repeat("chainInfo ", maxFields+1) + "}", fail: "too many fields"},
		{name: "unknown field", q: `{ nope }`, fail: "unknown field"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.fail == "" {
				query(t, e, tt.q)
				return
			}
			require.Contains(t, queryErr(t, e, tt.q), tt.fail)
		})
	}
}

// Depth and length say nothing about breadth: every field is a database scan,
// so the bound that holds is on the count of them.
func TestBreadthIsBounded(t *testing.T) {
	e := NewQueryExecutor(memdb.New(), nil)
	require.NotEmpty(t, e.Execute(context.Background(), &GraphQLRequest{
		Query: "{" + strings.Repeat("chainInfo ", maxFields+1) + "}",
	}).Errors)
	require.Empty(t, e.Execute(context.Background(), &GraphQLRequest{
		Query: "{" + strings.Repeat("chainInfo ", maxFields) + "}",
	}).Errors)
}

func TestQueryDepthBound(t *testing.T) {
	e := NewQueryExecutor(memdb.New(), &GConfig{MaxQueryDepth: 2})
	query(t, e, `{ chainInfo { a } }`)
	require.Contains(t, queryErr(t, e, `{ chainInfo { a { b { c } } } }`), "max depth")
}

// MaxResultSize is a promise about the response. It used to be stored and never
// read, so a configured bound of 16 bytes returned megabytes.
func TestResultSizeBound(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	for i := 0; i < 64; i++ {
		require.NoError(t, db.Put([]byte{'k', byte(i)}, []byte(strings.Repeat("x", 512))))
	}

	require.Contains(t, queryErr(t, NewQueryExecutor(db, &GConfig{MaxResultSize: 16}), `{ iterate }`), "exceeds max size")
	query(t, NewQueryExecutor(db, &GConfig{MaxResultSize: 1 << 20}), `{ iterate }`)
}

func TestVariablesFillArgumentsTheQueryOmits(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	require.NoError(t, db.Put([]byte("mykey"), []byte("myvalue")))

	e := NewQueryExecutor(db, nil)

	// A variable supplies an absent argument...
	resp := e.Execute(context.Background(), &GraphQLRequest{
		Query:     `{ get }`,
		Variables: map[string]interface{}{"key": "mykey"},
	})
	require.Empty(t, resp.Errors)
	require.Equal(t, "myvalue", resp.Data.(map[string]interface{})["get"])

	// ...and does not overwrite one the query gave.
	resp = e.Execute(context.Background(), &GraphQLRequest{
		Query:     `{ get(key: "mykey") }`,
		Variables: map[string]interface{}{"key": "other"},
	})
	require.Empty(t, resp.Errors)
	require.Equal(t, "myvalue", resp.Data.(map[string]interface{})["get"])
}

// A cancelled context must stop the work, not finish it. The previous version of
// this test cancelled the context and then asserted the query SUCCEEDED, which
// is the behaviour that makes QueryTimeoutMs decorative.
func TestCancelledContextStopsTheQuery(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	for i := 0; i < 8; i++ {
		require.NoError(t, db.Put([]byte{'k', byte(i)}, []byte(`{"id":"x"}`)))
	}

	e := NewQueryExecutor(db, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, q := range []string{`{ chainInfo }`, `{ iterate }`, `{ tokens }`, `{ blocks }`, `{ pools(where: {token0: "t"}) }`} {
		resp := e.Execute(ctx, &GraphQLRequest{Query: q})
		require.NotEmpty(t, resp.Errors, "query %q ran to completion after cancellation", q)
		require.Contains(t, resp.Errors[0].Message, "context canceled")
	}
}

func TestArgumentParsing(t *testing.T) {
	e := NewQueryExecutor(memdb.New(), nil)

	for _, q := range []string{
		`{ get(key: "k") }`,
		`{ get(key: 'k') }`,
		`{ get(key:k) }`,
		`{ alias: get(key: "k") }`,
		`{ get( key : "k" ) }`,
	} {
		require.Nil(t, query(t, e, q)["get"], q)
	}

	// An alias renames the answer.
	require.Contains(t, query(t, e, `{ latest: chainInfo }`), "latest")

	// An argument list with no colon contributes nothing rather than erroring.
	require.Contains(t, queryErr(t, e, `{ get(nonsense) }`), "requires 'key'")
}

func BenchmarkQueryExecutorSimpleQuery(b *testing.B) {
	e := NewQueryExecutor(memdb.New(), nil)
	req := &GraphQLRequest{Query: `{ chainInfo }`}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Execute(ctx, req)
	}
}
