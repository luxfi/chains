// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/luxfi/database"
)

// DEX data types matching the Uniswap v2/v3 subgraph schema. The field names are
// the wire contract clients query by, so they are kept verbatim.

// DexFactory represents DEX factory stats (Uniswap-compatible)
type DexFactory struct {
	ID                  string `json:"id"`
	PoolCount           int64  `json:"poolCount"`
	PairCount           int64  `json:"pairCount"` // v2 compat
	TxCount             int64  `json:"txCount"`
	TotalVolumeUSD      string `json:"totalVolumeUSD"`
	TotalVolumeETH      string `json:"totalVolumeETH"`
	TotalFeesUSD        string `json:"totalFeesUSD"`
	TotalValueLockedUSD string `json:"totalValueLockedUSD"`
	TotalLiquidityUSD   string `json:"totalLiquidityUSD"` // v2 compat
	TotalValueLockedETH string `json:"totalValueLockedETH"`
}

// Bundle represents ETH/native price in USD
type Bundle struct {
	ID          string `json:"id"`
	EthPriceUSD string `json:"ethPriceUSD"`
	EthPrice    string `json:"ethPrice"`    // v2 compat (same as ethPriceUSD)
	LuxPriceUSD string `json:"luxPriceUSD"` // native token price
}

// Token represents ERC20 token metadata and stats
type Token struct {
	ID                  string `json:"id"` // address
	Symbol              string `json:"symbol"`
	Name                string `json:"name"`
	Decimals            int64  `json:"decimals"`
	TotalSupply         string `json:"totalSupply"`
	Volume              string `json:"volume"`
	VolumeUSD           string `json:"volumeUSD"`
	UntrackedVolumeUSD  string `json:"untrackedVolumeUSD"`
	FeesUSD             string `json:"feesUSD"`
	TxCount             int64  `json:"txCount"`
	PoolCount           int64  `json:"poolCount"`
	TotalValueLocked    string `json:"totalValueLocked"`
	TotalValueLockedUSD string `json:"totalValueLockedUSD"`
	TotalLiquidity      string `json:"totalLiquidity"` // v2 compat
	DerivedETH          string `json:"derivedETH"`
	DerivedLUX          string `json:"derivedLUX"`     // native token derived price
	TradeVolume         string `json:"tradeVolume"`    // v2 compat
	TradeVolumeUSD      string `json:"tradeVolumeUSD"` // v2 compat
}

// Pool represents a v3-style concentrated liquidity pool
type Pool struct {
	ID                     string `json:"id"` // address
	CreatedAtTimestamp     int64  `json:"createdAtTimestamp"`
	CreatedAtBlockNumber   int64  `json:"createdAtBlockNumber"`
	Token0                 *Token `json:"token0"`
	Token1                 *Token `json:"token1"`
	FeeTier                int64  `json:"feeTier"`
	Liquidity              string `json:"liquidity"`
	SqrtPrice              string `json:"sqrtPrice"`
	Token0Price            string `json:"token0Price"`
	Token1Price            string `json:"token1Price"`
	Tick                   int64  `json:"tick"`
	ObservationIndex       int64  `json:"observationIndex"`
	VolumeToken0           string `json:"volumeToken0"`
	VolumeToken1           string `json:"volumeToken1"`
	VolumeUSD              string `json:"volumeUSD"`
	FeesUSD                string `json:"feesUSD"`
	TxCount                int64  `json:"txCount"`
	TotalValueLockedToken0 string `json:"totalValueLockedToken0"`
	TotalValueLockedToken1 string `json:"totalValueLockedToken1"`
	TotalValueLockedETH    string `json:"totalValueLockedETH"`
	TotalValueLockedUSD    string `json:"totalValueLockedUSD"`
}

// Pair represents a v2-style constant product AMM pair
type Pair struct {
	ID                   string `json:"id"` // address
	Token0               *Token `json:"token0"`
	Token1               *Token `json:"token1"`
	Reserve0             string `json:"reserve0"`
	Reserve1             string `json:"reserve1"`
	TotalSupply          string `json:"totalSupply"`
	ReserveETH           string `json:"reserveETH"`
	ReserveUSD           string `json:"reserveUSD"`
	TrackedReserveETH    string `json:"trackedReserveETH"`
	Token0Price          string `json:"token0Price"`
	Token1Price          string `json:"token1Price"`
	VolumeToken0         string `json:"volumeToken0"`
	VolumeToken1         string `json:"volumeToken1"`
	VolumeUSD            string `json:"volumeUSD"`
	TxCount              int64  `json:"txCount"`
	CreatedAtTimestamp   int64  `json:"createdAtTimestamp"`
	CreatedAtBlockNumber int64  `json:"createdAtBlockNumber"`
}

// Tick represents liquidity at a specific price tick (v3)
type Tick struct {
	ID                   string `json:"id"` // pool#tickIdx
	PoolAddress          string `json:"poolAddress"`
	TickIdx              int64  `json:"tickIdx"`
	LiquidityGross       string `json:"liquidityGross"`
	LiquidityNet         string `json:"liquidityNet"`
	Price0               string `json:"price0"`
	Price1               string `json:"price1"`
	CreatedAtTimestamp   int64  `json:"createdAtTimestamp"`
	CreatedAtBlockNumber int64  `json:"createdAtBlockNumber"`
}

// Swap represents a swap event
type Swap struct {
	ID           string `json:"id"` // txHash#logIndex
	Transaction  string `json:"transaction"`
	Timestamp    int64  `json:"timestamp"`
	Pool         string `json:"pool"`
	Pair         string `json:"pair"` // v2 compat
	Token0       string `json:"token0"`
	Token1       string `json:"token1"`
	Sender       string `json:"sender"`
	Recipient    string `json:"recipient"`
	Origin       string `json:"origin"`
	Amount0      string `json:"amount0"`
	Amount1      string `json:"amount1"`
	Amount0In    string `json:"amount0In"`  // v2
	Amount0Out   string `json:"amount0Out"` // v2
	Amount1In    string `json:"amount1In"`  // v2
	Amount1Out   string `json:"amount1Out"` // v2
	AmountUSD    string `json:"amountUSD"`
	SqrtPriceX96 string `json:"sqrtPriceX96"` // v3
	Tick         int64  `json:"tick"`         // v3
	LogIndex     int64  `json:"logIndex"`
}

// Mint represents a liquidity add event
type Mint struct {
	ID          string `json:"id"`
	Transaction string `json:"transaction"`
	Timestamp   int64  `json:"timestamp"`
	Pool        string `json:"pool"`
	Pair        string `json:"pair"` // v2 compat
	Token0      string `json:"token0"`
	Token1      string `json:"token1"`
	Owner       string `json:"owner"`
	Sender      string `json:"sender"`
	Origin      string `json:"origin"`
	Amount      string `json:"amount"` // liquidity amount
	Amount0     string `json:"amount0"`
	Amount1     string `json:"amount1"`
	AmountUSD   string `json:"amountUSD"`
	TickLower   int64  `json:"tickLower"` // v3
	TickUpper   int64  `json:"tickUpper"` // v3
	Liquidity   string `json:"liquidity"` // v2
	LogIndex    int64  `json:"logIndex"`
}

// Burn represents a liquidity remove event
type Burn struct {
	ID          string `json:"id"`
	Transaction string `json:"transaction"`
	Timestamp   int64  `json:"timestamp"`
	Pool        string `json:"pool"`
	Pair        string `json:"pair"` // v2 compat
	Token0      string `json:"token0"`
	Token1      string `json:"token1"`
	Owner       string `json:"owner"`
	Origin      string `json:"origin"`
	Amount      string `json:"amount"`
	Amount0     string `json:"amount0"`
	Amount1     string `json:"amount1"`
	AmountUSD   string `json:"amountUSD"`
	TickLower   int64  `json:"tickLower"` // v3
	TickUpper   int64  `json:"tickUpper"` // v3
	Liquidity   string `json:"liquidity"` // v2
	LogIndex    int64  `json:"logIndex"`
}

// TokenDayData represents daily token stats
type TokenDayData struct {
	ID                  string `json:"id"` // tokenAddr-timestamp
	Date                int64  `json:"date"`
	Token               string `json:"token"`
	Volume              string `json:"volume"`
	VolumeUSD           string `json:"volumeUSD"`
	TotalValueLocked    string `json:"totalValueLocked"`
	TotalValueLockedUSD string `json:"totalValueLockedUSD"`
	PriceUSD            string `json:"priceUSD"`
	FeesUSD             string `json:"feesUSD"`
	Open                string `json:"open"`
	High                string `json:"high"`
	Low                 string `json:"low"`
	Close               string `json:"close"`
}

// TokenHourData represents hourly token stats
type TokenHourData struct {
	ID                  string `json:"id"`
	PeriodStartUnix     int64  `json:"periodStartUnix"`
	Token               string `json:"token"`
	Volume              string `json:"volume"`
	VolumeUSD           string `json:"volumeUSD"`
	TotalValueLocked    string `json:"totalValueLocked"`
	TotalValueLockedUSD string `json:"totalValueLockedUSD"`
	PriceUSD            string `json:"priceUSD"`
	FeesUSD             string `json:"feesUSD"`
	Open                string `json:"open"`
	High                string `json:"high"`
	Low                 string `json:"low"`
	Close               string `json:"close"`
}

// PoolDayData represents daily pool stats
type PoolDayData struct {
	ID           string `json:"id"`
	Date         int64  `json:"date"`
	Pool         string `json:"pool"`
	Liquidity    string `json:"liquidity"`
	SqrtPrice    string `json:"sqrtPrice"`
	Token0Price  string `json:"token0Price"`
	Token1Price  string `json:"token1Price"`
	Tick         int64  `json:"tick"`
	TvlUSD       string `json:"tvlUSD"`
	VolumeToken0 string `json:"volumeToken0"`
	VolumeToken1 string `json:"volumeToken1"`
	VolumeUSD    string `json:"volumeUSD"`
	FeesUSD      string `json:"feesUSD"`
	TxCount      int64  `json:"txCount"`
	Open         string `json:"open"`
	High         string `json:"high"`
	Low          string `json:"low"`
	Close        string `json:"close"`
}

// PoolHourData represents hourly pool stats
type PoolHourData struct {
	ID              string `json:"id"`
	PeriodStartUnix int64  `json:"periodStartUnix"`
	Pool            string `json:"pool"`
	Liquidity       string `json:"liquidity"`
	SqrtPrice       string `json:"sqrtPrice"`
	Token0Price     string `json:"token0Price"`
	Token1Price     string `json:"token1Price"`
	Tick            int64  `json:"tick"`
	TvlUSD          string `json:"tvlUSD"`
	VolumeToken0    string `json:"volumeToken0"`
	VolumeToken1    string `json:"volumeToken1"`
	VolumeUSD       string `json:"volumeUSD"`
	FeesUSD         string `json:"feesUSD"`
	TxCount         int64  `json:"txCount"`
	Open            string `json:"open"`
	High            string `json:"high"`
	Low             string `json:"low"`
	Close           string `json:"close"`
}

// PairDayData represents daily v2 pair stats
type PairDayData struct {
	ID                string `json:"id"`
	Date              int64  `json:"date"`
	PairAddress       string `json:"pairAddress"`
	Token0            string `json:"token0"`
	Token1            string `json:"token1"`
	Reserve0          string `json:"reserve0"`
	Reserve1          string `json:"reserve1"`
	TotalSupply       string `json:"totalSupply"`
	ReserveUSD        string `json:"reserveUSD"`
	DailyVolumeToken0 string `json:"dailyVolumeToken0"`
	DailyVolumeToken1 string `json:"dailyVolumeToken1"`
	DailyVolumeUSD    string `json:"dailyVolumeUSD"`
	DailyTxns         int64  `json:"dailyTxns"`
}

// Database key prefixes for DEX data. A record lives at "<prefix><id>"; the
// pool->token index lives at PrefixPoolByToken+<token>.
const (
	PrefixFactory     = "dex:factory:"
	PrefixBundle      = "dex:bundle:"
	PrefixToken       = "dex:token:"
	PrefixPool        = "dex:pool:"
	PrefixPair        = "dex:pair:"
	PrefixTick        = "dex:tick:"
	PrefixSwap        = "dex:swap:"
	PrefixMint        = "dex:mint:"
	PrefixBurn        = "dex:burn:"
	PrefixTokenDay    = "dex:tokenday:"
	PrefixTokenHour   = "dex:tokenhour:"
	PrefixPoolDay     = "dex:poolday:"
	PrefixPoolHour    = "dex:poolhour:"
	PrefixPairDay     = "dex:pairday:"
	PrefixDayData     = "dex:daydata:"
	PrefixPoolByToken = "idx:pool:token:"
)

// The subgraph surface has exactly two read shapes — one record by id, and a
// window of records under a prefix — so it is written twice, here, and every
// entity is a line in registerDexResolvers. Bounds, cancellation and ordering
// are therefore properties of the shape rather than of each of forty copies:
// before this, `mints` and `burns` had no upper bound at all, and any of them
// answered `first: "-1"` with `makeslice: cap out of range`, which is a remote
// panic reachable from an unauthenticated query.

// bound reads the caller's paging argument and clamps it into [1, max]. Absent,
// unparsable, negative and oversized all land in range: the caller never picks
// the allocation size.
func bound(args map[string]interface{}, key string, def, max int) int {
	n := def
	switch v := args[key].(type) {
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			n = parsed
		}
	case float64: // JSON variables arrive as float64
		n = int(v)
	}
	if n < 1 {
		return 1
	}
	if n > max {
		return max
	}
	return n
}

// narrow describes how a `where:` argument turns into a key-prefix. The first
// key present wins, and sep is what the indexer wrote between the value and the
// rest of the record id.
type narrow struct {
	keys []string
	sep  string
}

// prefix returns the scan prefix for these args: the base, plus the narrowing
// component when the caller supplied one.
func (n *narrow) prefix(base string, args map[string]interface{}) string {
	if n == nil {
		return base
	}
	where, ok := args["where"].(map[string]interface{})
	if !ok {
		return base
	}
	for _, k := range n.keys {
		if v, ok := where[k].(string); ok && v != "" {
			return base + strings.ToLower(v) + n.sep
		}
	}
	return base
}

// readOne loads one JSON record. A genuine miss is (nil, nil) — GraphQL null.
// A read that FAILED is an error, never an empty answer.
func readOne[T any](db database.Database, key string) (*T, error) {
	raw, err := db.Get([]byte(key))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// object reads one free-form JSON record. A miss is untyped nil, so the
// response carries null rather than a pointer to nothing.
func object(db database.Database, key string) (interface{}, error) {
	v, err := readOne[map[string]interface{}](db, key)
	if v == nil || err != nil {
		return nil, err
	}
	return *v, nil
}

// byID resolves "<entity>(id: ...)". miss supplies the answer for a record that
// is not there; nil means null. The two singletons — factory and bundle — carry
// a default id and answer a zero record instead, because a client reading
// protocol totals wants zeroes, not a null it has to special-case.
func byID[T any](name, prefix, defaultID string, fold bool, miss func(id string) interface{}) ResolverFunc {
	return func(_ context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
		id, ok := args["id"].(string)
		if !ok {
			if defaultID == "" {
				return nil, fmt.Errorf("%s: requires 'id' argument", name)
			}
			id = defaultID
		}
		if fold {
			id = strings.ToLower(id) // addresses are case-folded on write
		}
		v, err := readOne[T](db, prefix+id)
		if err != nil {
			return nil, err
		}
		if v == nil {
			if miss != nil {
				return miss(id), nil
			}
			return nil, nil
		}
		return v, nil
	}
}

// list resolves "<entity>s(first: n, where: {...})". It scans one window under
// the prefix, orders that window, and stops the moment the query's deadline
// passes — which is what makes QueryTimeoutMs mean something.
func list[T any](prefix string, def, max int, n *narrow, order func(args map[string]interface{}, xs []*T)) ResolverFunc {
	return func(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
		limit := bound(args, "first", def, max)

		iter := db.NewIteratorWithPrefix([]byte(n.prefix(prefix, args)))
		defer iter.Release()

		out := make([]*T, 0, limit)
		for iter.Next() && len(out) < limit {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var v T
			if err := json.Unmarshal(iter.Value(), &v); err != nil {
				continue
			}
			out = append(out, &v)
		}
		if err := iter.Error(); err != nil {
			return nil, err
		}
		if order != nil {
			order(args, out)
		}
		return out, nil
	}
}

// desc orders newest-first on an int64 field. SliceStable over a prefix scan is
// total: ties keep key order, so two nodes answer identically.
func desc[T any](get func(*T) int64) func(map[string]interface{}, []*T) {
	return func(_ map[string]interface{}, xs []*T) {
		sort.SliceStable(xs, func(i, j int) bool { return get(xs[i]) > get(xs[j]) })
	}
}

// registerDexResolvers adds the v2/v3 subgraph surface. The names are the wire
// contract — clients query by them — so they stay verbatim.
func (e *QueryExecutor) registerDexResolvers() {
	// Factory/protocol stats and the price bundle answer zeroes when absent.
	factory := byID[DexFactory]("factory", PrefixFactory, "1", false, func(id string) interface{} {
		return &DexFactory{
			ID: id, TotalVolumeUSD: "0", TotalVolumeETH: "0", TotalFeesUSD: "0",
			TotalValueLockedUSD: "0", TotalLiquidityUSD: "0", TotalValueLockedETH: "0",
		}
	})
	e.resolvers["factory"] = factory
	e.resolvers["uniswapFactory"] = factory // v2 compat
	e.resolvers["factories"] = list[DexFactory](PrefixFactory, 100, 1000, nil, nil)

	e.resolvers["bundle"] = byID[Bundle]("bundle", PrefixBundle, "1", false, func(id string) interface{} {
		return &Bundle{ID: id, EthPriceUSD: "0", EthPrice: "0", LuxPriceUSD: "0"}
	})
	e.resolvers["bundles"] = list[Bundle](PrefixBundle, 100, 1000, nil, nil)

	e.resolvers["token"] = byID[Token]("token", PrefixToken, "", true, nil)
	e.resolvers["tokens"] = list[Token](PrefixToken, 100, 1000, nil, orderTokens)

	e.resolvers["pool"] = byID[Pool]("pool", PrefixPool, "", true, nil)
	e.resolvers["pools"] = e.resolvePools

	e.resolvers["pair"] = byID[Pair]("pair", PrefixPair, "", true, nil)
	e.resolvers["pairs"] = list[Pair](PrefixPair, 100, 1000, nil, nil)

	e.resolvers["tick"] = byID[Tick]("tick", PrefixTick, "", false, nil)
	e.resolvers["ticks"] = list[Tick](PrefixTick, 100, 1000,
		&narrow{keys: []string{"pool", "poolAddress"}, sep: "#"}, nil)

	e.resolvers["swap"] = byID[Swap]("swap", PrefixSwap, "", false, nil)
	e.resolvers["swaps"] = list[Swap](PrefixSwap, 100, 1000, nil,
		desc(func(s *Swap) int64 { return s.Timestamp }))

	e.resolvers["mint"] = byID[Mint]("mint", PrefixMint, "", false, nil)
	e.resolvers["mints"] = list[Mint](PrefixMint, 100, 1000, nil,
		desc(func(m *Mint) int64 { return m.Timestamp }))

	e.resolvers["burn"] = byID[Burn]("burn", PrefixBurn, "", false, nil)
	e.resolvers["burns"] = list[Burn](PrefixBurn, 100, 1000, nil,
		desc(func(b *Burn) int64 { return b.Timestamp }))

	byToken := &narrow{keys: []string{"token"}, sep: "-"}
	byPool := &narrow{keys: []string{"pool"}, sep: "-"}

	e.resolvers["tokenDayData"] = byID[TokenDayData]("tokenDayData", PrefixTokenDay, "", false, nil)
	e.resolvers["tokenDayDatas"] = list[TokenDayData](PrefixTokenDay, 30, 365, byToken,
		desc(func(d *TokenDayData) int64 { return d.Date }))

	e.resolvers["tokenHourData"] = byID[TokenHourData]("tokenHourData", PrefixTokenHour, "", false, nil)
	e.resolvers["tokenHourDatas"] = list[TokenHourData](PrefixTokenHour, 24, 168, byToken,
		desc(func(d *TokenHourData) int64 { return d.PeriodStartUnix }))

	e.resolvers["poolDayData"] = byID[PoolDayData]("poolDayData", PrefixPoolDay, "", false, nil)
	e.resolvers["poolDayDatas"] = list[PoolDayData](PrefixPoolDay, 30, 365, byPool,
		desc(func(d *PoolDayData) int64 { return d.Date }))

	e.resolvers["poolHourData"] = byID[PoolHourData]("poolHourData", PrefixPoolHour, "", false, nil)
	e.resolvers["poolHourDatas"] = list[PoolHourData](PrefixPoolHour, 24, 168, byPool,
		desc(func(d *PoolHourData) int64 { return d.PeriodStartUnix }))

	e.resolvers["pairDayData"] = byID[PairDayData]("pairDayData", PrefixPairDay, "", false, nil)
	e.resolvers["pairDayDatas"] = list[PairDayData](PrefixPairDay, 30, 365,
		&narrow{keys: []string{"pairAddress"}, sep: "-"},
		desc(func(d *PairDayData) int64 { return d.Date }))

	// Protocol-level daily totals are free-form: whatever the indexer wrote.
	e.resolvers["uniswapDayData"] = func(_ context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
		id, ok := args["id"].(string)
		if !ok {
			return nil, fmt.Errorf("uniswapDayData: requires 'id' argument")
		}
		return object(db, PrefixDayData+id)
	}
	e.resolvers["uniswapDayDatas"] = func(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
		return scan[map[string]interface{}](ctx, db, PrefixDayData, bound(args, "first", 30, 365))
	}
}

// resolvePools is the one list that is not a prefix scan: a token filter reads
// the pool-by-token index instead, so it stays written out.
func (e *QueryExecutor) resolvePools(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	token := ""
	if where, ok := args["where"].(map[string]interface{}); ok {
		for _, k := range []string{"token0", "token1"} {
			if v, ok := where[k].(string); ok && v != "" {
				token = strings.ToLower(v)
				break
			}
		}
	}
	if token == "" {
		return list[Pool](PrefixPool, 100, 1000, nil, nil)(ctx, db, args)
	}

	limit := bound(args, "first", 100, 1000)
	index, err := readOne[[]string](db, PrefixPoolByToken+token)
	if err != nil || index == nil {
		return []*Pool{}, err
	}

	pools := make([]*Pool, 0, min(limit, len(*index)))
	for _, addr := range *index {
		if len(pools) >= limit {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pool, err := readOne[Pool](db, PrefixPool+addr)
		if err != nil {
			return nil, err
		}
		if pool != nil {
			pools = append(pools, pool)
		}
	}
	return pools, nil
}

// orderTokens applies the caller's orderBy/orderDirection. cmp is three-way so
// that reversing it stays a strict ordering: the old code returned !cmp, which
// reported i<j AND j<i for every tie and left sort.Slice free to permute equal
// rows differently on identical data.
func orderTokens(args map[string]interface{}, xs []*Token) {
	by, _ := args["orderBy"].(string)
	cmp := func(a, b *Token) int {
		switch by {
		case "txCount":
			return int64cmp(a.TxCount, b.TxCount)
		case "totalValueLockedUSD":
			return decimalcmp(a.TotalValueLockedUSD, b.TotalValueLockedUSD)
		case "volumeUSD", "":
			return decimalcmp(a.VolumeUSD, b.VolumeUSD)
		default:
			return strings.Compare(b.ID, a.ID) // unknown key: id ascending
		}
	}
	if dir, _ := args["orderDirection"].(string); dir == "asc" {
		sort.SliceStable(xs, func(i, j int) bool { return cmp(xs[i], xs[j]) < 0 })
		return
	}
	sort.SliceStable(xs, func(i, j int) bool { return cmp(xs[i], xs[j]) > 0 })
}

func int64cmp(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// decimalcmp compares two decimal strings; anything unparsable is zero.
func decimalcmp(a, b string) int {
	return decimal(a).Cmp(decimal(b))
}

func decimal(s string) *big.Float {
	v, ok := new(big.Float).SetString(s)
	if !ok {
		return new(big.Float)
	}
	return v
}
