// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
)

func seed(t *testing.T, db database.Database, key string, v interface{}) {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, db.Put([]byte(key), raw))
}

// A caller must never choose an allocation. `first: "-1"` reached
// make([]*T, 0, -1) and panicked the process — a remote crash from one
// unauthenticated query — and `mints`/`burns` had no upper bound at all.
func TestPagingArgumentCannotChooseTheAllocation(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	e := NewQueryExecutor(db, nil)

	lists := []string{
		"tokens", "pools", "pairs", "ticks", "swaps", "mints", "burns",
		"factories", "bundles", "tokenDayDatas", "tokenHourDatas",
		"poolDayDatas", "poolHourDatas", "pairDayDatas", "uniswapDayDatas",
		"blocks", "transactions", "iterate",
	}
	arg := map[string]string{"blocks": "limit", "transactions": "limit", "iterate": "limit"}

	for _, name := range lists {
		key := arg[name]
		if key == "" {
			key = "first"
		}
		for _, v := range []string{"-1", "0", "-9223372036854775808", "999999999999", "abc", ""} {
			q := fmt.Sprintf(`{ %s(%s: "%s") }`, name, key, v)
			resp := e.Execute(context.Background(), &GraphQLRequest{Query: q})
			require.Empty(t, resp.Errors, "query %q", q)
		}
	}
}

func TestBound(t *testing.T) {
	for _, tt := range []struct {
		arg  interface{}
		want int
	}{
		{arg: nil, want: 10},
		{arg: "5", want: 5},
		{arg: " 5 ", want: 5},
		{arg: "0", want: 1},
		{arg: "-1", want: 1},
		{arg: "999", want: 100},
		{arg: "junk", want: 10},
		{arg: float64(7), want: 7},  // a JSON variable arrives as a number
		{arg: float64(-7), want: 1}, // ...and is clamped the same way
		{arg: true, want: 10},       // a type nobody handles falls back
	} {
		args := map[string]interface{}{}
		if tt.arg != nil {
			args["first"] = tt.arg
		}
		require.Equal(t, tt.want, bound(args, "first", 10, 100), "arg %#v", tt.arg)
	}
}

func TestDexSingletonsAnswerZeroesWhenAbsent(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	e := NewQueryExecutor(db, nil)

	// A client reading protocol totals wants zeroes, not a null to special-case.
	f := query(t, e, `{ factory }`)["factory"].(*DexFactory)
	require.Equal(t, "1", f.ID)
	require.Equal(t, "0", f.TotalVolumeUSD)
	require.Equal(t, f, query(t, e, `{ uniswapFactory }`)["uniswapFactory"], "the v2 alias must resolve to the same record")

	b := query(t, e, `{ bundle }`)["bundle"].(*Bundle)
	require.Equal(t, "1", b.ID)
	require.Equal(t, "0", b.EthPriceUSD)

	// A stored record replaces the zeroes.
	seed(t, db, PrefixFactory+"1", &DexFactory{ID: "1", PoolCount: 3, TotalVolumeUSD: "42"})
	seed(t, db, PrefixBundle+"1", &Bundle{ID: "1", EthPriceUSD: "1800"})
	require.Equal(t, "42", query(t, e, `{ factory(id: "1") }`)["factory"].(*DexFactory).TotalVolumeUSD)
	require.Equal(t, "1800", query(t, e, `{ bundle(id: "1") }`)["bundle"].(*Bundle).EthPriceUSD)

	require.Len(t, query(t, e, `{ factories }`)["factories"], 1)
	require.Len(t, query(t, e, `{ bundles }`)["bundles"], 1)
}

func TestDexRecordsByID(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	e := NewQueryExecutor(db, nil)

	seed(t, db, PrefixToken+"0xaaa", &Token{ID: "0xAAA", Symbol: "LUX"})
	seed(t, db, PrefixPool+"0xbbb", &Pool{ID: "0xBBB", FeeTier: 3000})
	seed(t, db, PrefixPair+"0xccc", &Pair{ID: "0xCCC", Reserve0: "1"})
	seed(t, db, PrefixTick+"0xbbb#7", &Tick{ID: "0xbbb#7", TickIdx: 7})
	seed(t, db, PrefixSwap+"s1", &Swap{ID: "s1", Timestamp: 5})
	seed(t, db, PrefixMint+"m1", &Mint{ID: "m1", Timestamp: 5})
	seed(t, db, PrefixBurn+"b1", &Burn{ID: "b1", Timestamp: 5})
	seed(t, db, PrefixTokenDay+"d1", &TokenDayData{ID: "d1", Date: 1})
	seed(t, db, PrefixTokenHour+"h1", &TokenHourData{ID: "h1", PeriodStartUnix: 1})
	seed(t, db, PrefixPoolDay+"pd1", &PoolDayData{ID: "pd1", Date: 1})
	seed(t, db, PrefixPoolHour+"ph1", &PoolHourData{ID: "ph1", PeriodStartUnix: 1})
	seed(t, db, PrefixPairDay+"pr1", &PairDayData{ID: "pr1", Date: 1})
	seed(t, db, PrefixDayData+"u1", map[string]interface{}{"id": "u1", "volumeUSD": "9"})

	// An address argument is folded to the case the indexer wrote.
	require.Equal(t, "LUX", query(t, e, `{ token(id: "0xAAA") }`)["token"].(*Token).Symbol)
	require.Equal(t, "LUX", query(t, e, `{ token(id: "0xaaa") }`)["token"].(*Token).Symbol)
	require.EqualValues(t, 3000, query(t, e, `{ pool(id: "0xBBB") }`)["pool"].(*Pool).FeeTier)
	require.Equal(t, "1", query(t, e, `{ pair(id: "0xCCC") }`)["pair"].(*Pair).Reserve0)

	// ...but an id that is not an address is not folded.
	require.EqualValues(t, 7, query(t, e, `{ tick(id: "0xbbb#7") }`)["tick"].(*Tick).TickIdx)
	require.Nil(t, query(t, e, `{ tick(id: "0xBBB#7") }`)["tick"])

	for _, name := range []string{"swap", "mint", "burn"} {
		require.NotNil(t, query(t, e, `{ `+name+`(id: "`+name[:1]+`1") }`)[name])
	}
	require.EqualValues(t, 1, query(t, e, `{ tokenDayData(id: "d1") }`)["tokenDayData"].(*TokenDayData).Date)
	require.EqualValues(t, 1, query(t, e, `{ tokenHourData(id: "h1") }`)["tokenHourData"].(*TokenHourData).PeriodStartUnix)
	require.EqualValues(t, 1, query(t, e, `{ poolDayData(id: "pd1") }`)["poolDayData"].(*PoolDayData).Date)
	require.EqualValues(t, 1, query(t, e, `{ poolHourData(id: "ph1") }`)["poolHourData"].(*PoolHourData).PeriodStartUnix)
	require.EqualValues(t, 1, query(t, e, `{ pairDayData(id: "pr1") }`)["pairDayData"].(*PairDayData).Date)
	require.Equal(t, "9", query(t, e, `{ uniswapDayData(id: "u1") }`)["uniswapDayData"].(map[string]interface{})["volumeUSD"])

	// A record that is not there is null; an id that is not given is an error.
	for _, name := range []string{"token", "pool", "pair", "tick", "swap", "mint", "burn",
		"tokenDayData", "tokenHourData", "poolDayData", "poolHourData", "pairDayData", "uniswapDayData"} {
		require.Nil(t, query(t, e, `{ `+name+`(id: "absent") }`)[name], name)
		require.Contains(t, queryErr(t, e, `{ `+name+` }`), "requires 'id' argument", name)
	}

	// A stored record that is not JSON is an error, not a null.
	require.NoError(t, db.Put([]byte(PrefixToken+"0xbad"), []byte("{")))
	require.Contains(t, queryErr(t, e, `{ token(id: "0xbad") }`), "unexpected end of JSON")
}

func TestDexListsNarrowAndOrder(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	e := NewQueryExecutor(db, nil)

	// Two pools' worth of ticks and day data, keyed the way the indexer writes.
	for _, pool := range []string{"0xaaa", "0xbbb"} {
		for i := 1; i <= 3; i++ {
			seed(t, db, fmt.Sprintf("%s%s#%d", PrefixTick, pool, i), &Tick{ID: pool, TickIdx: int64(i)})
			seed(t, db, fmt.Sprintf("%s%s-%d", PrefixPoolDay, pool, i), &PoolDayData{Pool: pool, Date: int64(i)})
			seed(t, db, fmt.Sprintf("%s%s-%d", PrefixPoolHour, pool, i), &PoolHourData{Pool: pool, PeriodStartUnix: int64(i)})
		}
	}

	require.Len(t, query(t, e, `{ ticks }`)["ticks"], 6)
	require.Len(t, query(t, e, `{ ticks(where: {pool: "0xAAA"}) }`)["ticks"], 3)
	require.Len(t, query(t, e, `{ ticks(where: {poolAddress: "0xbbb"}) }`)["ticks"], 3)
	require.Len(t, query(t, e, `{ ticks(where: {pool: "absent"}) }`)["ticks"], 0)

	// Time series come back newest first.
	days := query(t, e, `{ poolDayDatas(where: {pool: "0xaaa"}) }`)["poolDayDatas"].([]*PoolDayData)
	require.Len(t, days, 3)
	require.Equal(t, []int64{3, 2, 1}, []int64{days[0].Date, days[1].Date, days[2].Date})

	hours := query(t, e, `{ poolHourDatas(where: {pool: "0xaaa"}) }`)["poolHourDatas"].([]*PoolHourData)
	require.Equal(t, int64(3), hours[0].PeriodStartUnix)

	// A `where` that is a bare string — which is what the argument parser makes
	// of nested syntax — narrows nothing rather than narrowing wrongly.
	require.Len(t, query(t, e, `{ ticks(where: "0xaaa") }`)["ticks"], 6)
	require.Len(t, query(t, e, `{ ticks(where: {pool: ""}) }`)["ticks"], 6)
}

func TestSwapsMintsBurnsNewestFirst(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	e := NewQueryExecutor(db, nil)

	// Written in ascending key order with descending timestamps, so an answer
	// in key order is visibly different from an answer in time order.
	for i := 1; i <= 3; i++ {
		ts := int64(10 - i)
		seed(t, db, fmt.Sprintf("%s%d", PrefixSwap, i), &Swap{ID: fmt.Sprint(i), Timestamp: ts})
		seed(t, db, fmt.Sprintf("%s%d", PrefixMint, i), &Mint{ID: fmt.Sprint(i), Timestamp: ts})
		seed(t, db, fmt.Sprintf("%s%d", PrefixBurn, i), &Burn{ID: fmt.Sprint(i), Timestamp: ts})
	}

	swaps := query(t, e, `{ swaps }`)["swaps"].([]*Swap)
	require.Equal(t, []int64{9, 8, 7}, []int64{swaps[0].Timestamp, swaps[1].Timestamp, swaps[2].Timestamp})
	mints := query(t, e, `{ mints }`)["mints"].([]*Mint)
	require.Equal(t, int64(9), mints[0].Timestamp)
	burns := query(t, e, `{ burns }`)["burns"].([]*Burn)
	require.Equal(t, int64(9), burns[0].Timestamp)
}

// The old comparator returned !cmp for ascending order, which reports i<j AND
// j<i for every tie — not an ordering, so sort.Slice was free to permute equal
// rows differently on identical data. Two nodes, one query, two answers.
func TestTokenOrderIsTotalAndStable(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	e := NewQueryExecutor(db, nil)

	seed(t, db, PrefixToken+"a", &Token{ID: "a", VolumeUSD: "10", TotalValueLockedUSD: "1", TxCount: 3})
	seed(t, db, PrefixToken+"b", &Token{ID: "b", VolumeUSD: "10", TotalValueLockedUSD: "2", TxCount: 3})
	seed(t, db, PrefixToken+"c", &Token{ID: "c", VolumeUSD: "10", TotalValueLockedUSD: "3", TxCount: 3})
	seed(t, db, PrefixToken+"d", &Token{ID: "d", VolumeUSD: "", TotalValueLockedUSD: "x", TxCount: 3})

	ids := func(q string) []string {
		out := []string{}
		for _, tok := range query(t, e, q)["tokens"].([]*Token) {
			out = append(out, tok.ID)
		}
		return out
	}

	// Every volume ties except the unparsable one, which sorts as zero. Ties
	// keep key order, so the answer is the same answer every time.
	first := ids(`{ tokens(orderBy: "volumeUSD") }`)
	require.Equal(t, []string{"a", "b", "c", "d"}, first)
	for i := 0; i < 32; i++ {
		require.Equal(t, first, ids(`{ tokens(orderBy: "volumeUSD") }`))
	}

	require.Equal(t, []string{"d", "a", "b", "c"}, ids(`{ tokens(orderBy: "volumeUSD", orderDirection: "asc") }`))
	require.Equal(t, []string{"c", "b", "a", "d"}, ids(`{ tokens(orderBy: "totalValueLockedUSD") }`))
	require.Equal(t, []string{"d", "a", "b", "c"}, ids(`{ tokens(orderBy: "totalValueLockedUSD", orderDirection: "asc") }`))
	require.Equal(t, []string{"a", "b", "c", "d"}, ids(`{ tokens(orderBy: "txCount") }`))
	require.Equal(t, []string{"a", "b", "c", "d"}, ids(`{ tokens }`)) // volumeUSD is the default

	// An orderBy nobody implements is id ascending, not an arbitrary order.
	require.Equal(t, []string{"a", "b", "c", "d"}, ids(`{ tokens(orderBy: "nope") }`))
	require.Equal(t, []string{"d", "c", "b", "a"}, ids(`{ tokens(orderBy: "nope", orderDirection: "asc") }`))
}

func TestPoolsUseTheTokenIndex(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	e := NewQueryExecutor(db, nil)

	for _, id := range []string{"p1", "p2", "p3"} {
		seed(t, db, PrefixPool+id, &Pool{ID: id})
	}
	// The index names two of them, and one address it does not have.
	seed(t, db, PrefixPoolByToken+"0xtok", []string{"p1", "p3", "gone"})

	require.Len(t, query(t, e, `{ pools }`)["pools"], 3)

	byToken := query(t, e, `{ pools(where: {token0: "0xTOK"}) }`)["pools"].([]*Pool)
	require.Equal(t, []string{"p1", "p3"}, []string{byToken[0].ID, byToken[1].ID})

	require.Len(t, query(t, e, `{ pools(where: {token1: "0xtok"}) }`)["pools"], 2)
	require.Len(t, query(t, e, `{ pools(where: {token0: "0xtok"}, first: "1") }`)["pools"], 1)

	// A token with no index entry has no pools — and says so with an empty
	// list, because an absent index is an absent index, not a failure.
	require.Len(t, query(t, e, `{ pools(where: {token0: "absent"}) }`)["pools"], 0)

	// An index that is not a JSON array IS a failure.
	require.NoError(t, db.Put([]byte(PrefixPoolByToken+"0xbad"), []byte(`{}`)))
	require.Contains(t, queryErr(t, e, `{ pools(where: {token0: "0xbad"}) }`), "cannot unmarshal")
}

func TestListsSkipUnreadableRowsAndHonourTheLimit(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	e := NewQueryExecutor(db, nil)

	for i := 0; i < 5; i++ {
		seed(t, db, fmt.Sprintf("%s%d", PrefixPair, i), &Pair{ID: fmt.Sprint(i)})
	}
	require.NoError(t, db.Put([]byte(PrefixPair+"9"), []byte("not json")))

	require.Len(t, query(t, e, `{ pairs }`)["pairs"], 5)
	require.Len(t, query(t, e, `{ pairs(first: "2") }`)["pairs"], 2)
}

func TestDecimalComparison(t *testing.T) {
	require.Equal(t, -1, decimalcmp("1", "2"))
	require.Equal(t, 1, decimalcmp("2", "1"))
	require.Equal(t, 0, decimalcmp("1.5", "1.50"))
	require.Equal(t, 0, decimalcmp("junk", ""))
	require.Equal(t, -1, decimalcmp("junk", "0.1"))
	require.Equal(t, 1, decimalcmp("1e30", "1e29"))
}

func TestIntComparison(t *testing.T) {
	require.Equal(t, -1, int64cmp(1, 2))
	require.Equal(t, 1, int64cmp(2, 1))
	require.Equal(t, 0, int64cmp(2, 2))
}

// Every registered name resolves. A name in the table that no client can reach,
// or a resolver a client can name that is not in the table, is one of the two
// halves of the subgraph contract quietly gone.
func TestEveryRegisteredNameAnswers(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	e := NewQueryExecutor(db, nil)

	needsID := map[string]bool{
		"token": true, "pool": true, "pair": true, "tick": true, "swap": true,
		"mint": true, "burn": true, "tokenDayData": true, "tokenHourData": true,
		"poolDayData": true, "poolHourData": true, "pairDayData": true,
		"uniswapDayData": true, "block": true, "transaction": true,
		"account": true, "balance": true, "get": true, "has": true,
	}
	arg := map[string]string{
		"block": "hash", "transaction": "hash", "account": "address",
		"balance": "address", "get": "key", "has": "key",
	}

	require.Greater(t, len(e.resolvers), 40)
	for name := range e.resolvers {
		q := "{ " + name + " }"
		if needsID[name] {
			key := arg[name]
			if key == "" {
				key = "id"
			}
			q = fmt.Sprintf(`{ %s(%s: "x") }`, name, key)
		}
		resp := e.Execute(context.Background(), &GraphQLRequest{Query: q})
		require.Empty(t, resp.Errors, "registered resolver %q answered %v", name, resp.Errors)
	}
}

func TestScanStopsAtTheLimit(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	for i := 0; i < 10; i++ {
		seed(t, db, fmt.Sprintf("k%d", i), map[string]interface{}{"i": i})
	}
	rows, err := scan[map[string]interface{}](context.Background(), db, "k", 3)
	require.NoError(t, err)
	require.Len(t, rows, 3)
}

func TestNarrowPrefix(t *testing.T) {
	var none *narrow
	require.Equal(t, "base", none.prefix("base", nil))

	n := &narrow{keys: []string{"a", "b"}, sep: "-"}
	require.Equal(t, "base", n.prefix("base", map[string]interface{}{}))
	require.Equal(t, "base", n.prefix("base", map[string]interface{}{"where": "not a map"}))
	require.Equal(t, "base", n.prefix("base", map[string]interface{}{"where": map[string]interface{}{"c": "x"}}))
	require.Equal(t, "baseX", n.prefix("baseX", map[string]interface{}{"where": map[string]interface{}{"a": ""}}))
	require.Equal(t, "base", n.prefix("base", map[string]interface{}{"where": map[string]interface{}{"a": 7}}))
	require.Equal(t, "basev-", n.prefix("base", map[string]interface{}{"where": map[string]interface{}{"a": "V"}}))
	require.Equal(t, "basew-", n.prefix("base", map[string]interface{}{"where": map[string]interface{}{"b": "W"}}))
}

func TestKeyPrefixesAreDistinct(t *testing.T) {
	// A prefix that is a prefix of another makes one entity's scan return the
	// other's rows.
	prefixes := []string{
		PrefixFactory, PrefixBundle, PrefixToken, PrefixPool, PrefixPair,
		PrefixTick, PrefixSwap, PrefixMint, PrefixBurn, PrefixTokenDay,
		PrefixTokenHour, PrefixPoolDay, PrefixPoolHour, PrefixPairDay,
		PrefixDayData, PrefixPoolByToken,
	}
	for i, a := range prefixes {
		for j, b := range prefixes {
			if i != j {
				require.False(t, strings.HasPrefix(a, b), "%q is a prefix of %q", b, a)
			}
		}
	}
}
