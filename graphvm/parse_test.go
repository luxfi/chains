// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

func TestFactoryBuildsAVM(t *testing.T) {
	vm, err := (&Factory{}).New(log.NewNoOpLogger())
	require.NoError(t, err)
	require.IsType(t, &VM{}, vm)
	require.Equal(t, ids.ID{'g', 'r', 'a', 'p', 'h', 'v', 'm'}, VMID)
}

func TestInitializeLogsThroughTheRuntimeLogger(t *testing.T) {
	require.NoError(t, (&VM{}).Initialize(context.Background(), vmcore.Init{
		Runtime: &runtime.Runtime{NetworkID: 1, Log: log.NewNoOpLogger()},
		DB:      memdb.New(),
	}))
}

// An argument value is an object, a list, a quoted string or a bare token. It
// used to be "everything between two commas", which is why `where: {a: "b"}`
// arrived as the string "{a".
func TestArgumentValues(t *testing.T) {
	for _, tt := range []struct {
		name, in string
		want     map[string]interface{}
	}{
		{name: "empty", in: ``, want: map[string]interface{}{}},
		{name: "bare", in: `a: 1`, want: map[string]interface{}{"a": "1"}},
		{name: "quoted", in: `a: "x y"`, want: map[string]interface{}{"a": "x y"}},
		{name: "single quoted", in: `a: 'x'`, want: map[string]interface{}{"a": "x"}},
		{name: "escape", in: `a: "x\"y"`, want: map[string]interface{}{"a": `x"y`}},
		{name: "unterminated quote", in: `a: "xy`, want: map[string]interface{}{"a": "xy"}},
		{name: "two", in: `a: 1, b: 2`, want: map[string]interface{}{"a": "1", "b": "2"}},
		{name: "spaces", in: `  a  :  1  `, want: map[string]interface{}{"a": "1"}},
		{name: "no value", in: `a:`, want: map[string]interface{}{"a": ""}},
		{name: "bare token, no colon", in: `nonsense`, want: map[string]interface{}{}},
		{name: "leading junk", in: `!! a: 1`, want: map[string]interface{}{"a": "1"}},
		{
			name: "object",
			in:   `where: {token0: "0xA", n: 2}, first: "5"`,
			want: map[string]interface{}{
				"where": map[string]interface{}{"token0": "0xA", "n": "2"},
				"first": "5",
			},
		},
		{
			name: "nested object",
			in:   `where: {a: {b: "c"}}`,
			want: map[string]interface{}{"where": map[string]interface{}{"a": map[string]interface{}{"b": "c"}}},
		},
		{
			name: "list",
			in:   `ids: ["a", b, {c: "d"}]`,
			want: map[string]interface{}{"ids": []interface{}{"a", "b", map[string]interface{}{"c": "d"}}},
		},
		{name: "empty list", in: `ids: [ , ]`, want: map[string]interface{}{"ids": []interface{}{}}},
		{name: "unterminated object", in: `where: {a: "b"`, want: map[string]interface{}{"where": ""}},
		{name: "unterminated list", in: `ids: [a`, want: map[string]interface{}{"ids": ""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, parseArgs(tt.in))
		})
	}
}

// The tokenizer must refuse what it cannot read rather than inventing a field.
func TestMalformedSelectionSetsAreRefused(t *testing.T) {
	e := NewQueryExecutor(memdb.New(), nil)

	for _, tt := range []struct{ name, q string }{
		// An unmatched brace inside an otherwise balanced query.
		{name: "unmatched open brace", q: `{ a } b { c }`},
		// A colon with no name after it is an alias of nothing.
		{name: "alias with no name", q: `{ a { b: } }`},
		{name: "alias with no name, top level", q: `{ b: }`},
		// An argument list that never closes.
		{name: "unclosed args", q: `{ get(key: "k" }`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.NotEmpty(t, e.Execute(context.Background(), &GraphQLRequest{Query: tt.q}).Errors)
		})
	}

	// A byte that starts no name is stepped over, not turned into a field.
	require.Len(t, query(t, e, `{ ,,, chainInfo ;;; }`), 1)
	require.Len(t, query(t, e, `{ !! chainInfo }`), 1)
}

// A height may arrive as a JSON number through variables or as a Go int; both
// name the same block as the string form.
func TestBlockHeightAcceptsEveryNumberShape(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	seed(t, db, "block:height:100", map[string]interface{}{"hash": "0x1234"})

	e := NewQueryExecutor(db, nil)
	for _, height := range []interface{}{"100", float64(100), 100} {
		resp := e.Execute(context.Background(), &GraphQLRequest{
			Query:     `{ block }`,
			Variables: map[string]interface{}{"height": height},
		})
		require.Empty(t, resp.Errors, "height %#v", height)
		blk := resp.Data.(map[string]interface{})["block"].(map[string]interface{})
		require.Equal(t, "0x1234", blk["hash"], "height %#v", height)
	}
}

// prefixDB fails reads under one prefix and serves the rest, so a resolver that
// reads two keys can be caught reporting success for the one that failed.
type prefixDB struct {
	database.Database
	fail string
	err  error
}

func (d *prefixDB) Get(k []byte) ([]byte, error) {
	if len(k) >= len(d.fail) && string(k[:len(d.fail)]) == d.fail {
		return nil, d.err
	}
	return d.Database.Get(k)
}

// A resolver stops when the caller has gone. Execute checks the deadline once
// per field, so these inner checks are reached only by driving the resolver
// itself — which is how a long scan gets interrupted mid-scan in production.
func TestResolversStopOnCancellation(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	for i := 0; i < 4; i++ {
		seed(t, db, string(PrefixToken)+string(rune('a'+i)), &Token{ID: "t"})
		seed(t, db, string(PrefixPool)+string(rune('a'+i)), &Pool{ID: "p"})
	}
	seed(t, db, PrefixPoolByToken+"0xtok", []string{"a", "b"})

	e := NewQueryExecutor(db, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := e.resolvers["tokens"](ctx, db, map[string]interface{}{})
	require.ErrorIs(t, err, context.Canceled)

	_, err = e.resolvers["pools"](ctx, db, map[string]interface{}{
		"where": map[string]interface{}{"token0": "0xtok"},
	})
	require.ErrorIs(t, err, context.Canceled)

	_, err = e.resolvers["iterate"](ctx, db, map[string]interface{}{})
	require.ErrorIs(t, err, context.Canceled)

	_, err = scan[map[string]interface{}](ctx, db, "dex:", 10)
	require.ErrorIs(t, err, context.Canceled)
}

// The pool-by-token index names addresses; a read of one of them that FAILS is
// an error, not a pool quietly missing from the answer.
func TestPoolIndexReportsAFailedMemberRead(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	seed(t, db, PrefixPoolByToken+"0xtok", []string{"a"})
	seed(t, db, PrefixPool+"a", &Pool{ID: "a"})

	e := NewQueryExecutor(db, nil)
	require.Len(t, query(t, e, `{ pools(where: {token0: "0xtok"}) }`)["pools"], 1)

	broken := &prefixDB{Database: db, fail: PrefixPool, err: context.DeadlineExceeded}
	_, err := e.resolvers["pools"](context.Background(), broken, map[string]interface{}{
		"where": map[string]interface{}{"token0": "0xtok"},
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestTimeSeriesOrderNewestFirst(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	e := NewQueryExecutor(db, nil)

	for i := 1; i <= 3; i++ {
		n := int64(i)
		seed(t, db, PrefixTokenDay+"t-"+string(rune('0'+i)), &TokenDayData{Token: "t", Date: n})
		seed(t, db, PrefixTokenHour+"t-"+string(rune('0'+i)), &TokenHourData{Token: "t", PeriodStartUnix: n})
		seed(t, db, PrefixPairDay+"p-"+string(rune('0'+i)), &PairDayData{PairAddress: "p", Date: n})
	}

	days := query(t, e, `{ tokenDayDatas(where: {token: "T"}) }`)["tokenDayDatas"].([]*TokenDayData)
	require.Equal(t, []int64{3, 2, 1}, []int64{days[0].Date, days[1].Date, days[2].Date})

	hours := query(t, e, `{ tokenHourDatas(where: {token: "t"}) }`)["tokenHourDatas"].([]*TokenHourData)
	require.Equal(t, []int64{3, 2, 1}, []int64{hours[0].PeriodStartUnix, hours[1].PeriodStartUnix, hours[2].PeriodStartUnix})

	pairs := query(t, e, `{ pairDayDatas(where: {pairAddress: "p"}) }`)["pairDayDatas"].([]*PairDayData)
	require.Equal(t, []int64{3, 2, 1}, []int64{pairs[0].Date, pairs[1].Date, pairs[2].Date})

	require.Len(t, query(t, e, `{ uniswapDayDatas }`)["uniswapDayDatas"], 0)
}
