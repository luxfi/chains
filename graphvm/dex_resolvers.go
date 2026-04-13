// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/luxfi/database"
)

// DEX-specific data types matching Uniswap v2/v3 subgraph schema

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

// Database key prefixes for DEX data
const (
	PrefixFactory   = "dex:factory:"
	PrefixBundle    = "dex:bundle:"
	PrefixToken     = "dex:token:"
	PrefixPool      = "dex:pool:"
	PrefixPair      = "dex:pair:"
	PrefixTick      = "dex:tick:"
	PrefixSwap      = "dex:swap:"
	PrefixMint      = "dex:mint:"
	PrefixBurn      = "dex:burn:"
	PrefixTokenDay  = "dex:tokenday:"
	PrefixTokenHour = "dex:tokenhour:"
	PrefixPoolDay   = "dex:poolday:"
	PrefixPoolHour  = "dex:poolhour:"
	PrefixPairDay   = "dex:pairday:"
	// Index prefixes for efficient queries
	PrefixPoolByToken = "idx:pool:token:"
	PrefixPairByToken = "idx:pair:token:"
	PrefixSwapByPool  = "idx:swap:pool:"
	PrefixSwapByToken = "idx:swap:token:"
)

// registerDexResolvers adds DEX-specific GraphQL resolvers
func (e *QueryExecutor) registerDexResolvers() {
	// Factory/Protocol stats
	e.resolvers["factory"] = e.resolveFactory
	e.resolvers["factories"] = e.resolveFactories
	e.resolvers["uniswapFactory"] = e.resolveFactory // v2 compat

	// Price bundle (critical for quotes)
	e.resolvers["bundle"] = e.resolveBundle
	e.resolvers["bundles"] = e.resolveBundles

	// Token queries
	e.resolvers["token"] = e.resolveToken
	e.resolvers["tokens"] = e.resolveTokens

	// Pool queries (v3)
	e.resolvers["pool"] = e.resolvePool
	e.resolvers["pools"] = e.resolvePools

	// Pair queries (v2)
	e.resolvers["pair"] = e.resolvePair
	e.resolvers["pairs"] = e.resolvePairs

	// Tick queries (v3)
	e.resolvers["tick"] = e.resolveTick
	e.resolvers["ticks"] = e.resolveTicks

	// Swap queries
	e.resolvers["swap"] = e.resolveSwap
	e.resolvers["swaps"] = e.resolveSwaps

	// Mint queries
	e.resolvers["mint"] = e.resolveMint
	e.resolvers["mints"] = e.resolveMints

	// Burn queries
	e.resolvers["burn"] = e.resolveBurn
	e.resolvers["burns"] = e.resolveBurns

	// Time series data
	e.resolvers["tokenDayData"] = e.resolveTokenDayData
	e.resolvers["tokenDayDatas"] = e.resolveTokenDayDatas
	e.resolvers["tokenHourData"] = e.resolveTokenHourData
	e.resolvers["tokenHourDatas"] = e.resolveTokenHourDatas
	e.resolvers["poolDayData"] = e.resolvePoolDayData
	e.resolvers["poolDayDatas"] = e.resolvePoolDayDatas
	e.resolvers["poolHourData"] = e.resolvePoolHourData
	e.resolvers["poolHourDatas"] = e.resolvePoolHourDatas
	e.resolvers["pairDayData"] = e.resolvePairDayData
	e.resolvers["pairDayDatas"] = e.resolvePairDayDatas

	// Aggregation queries for analytics
	e.resolvers["uniswapDayData"] = e.resolveUniswapDayData
	e.resolvers["uniswapDayDatas"] = e.resolveUniswapDayDatas
}

// Factory resolver
func (e *QueryExecutor) resolveFactory(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id := "1" // Default factory ID
	if idArg, ok := args["id"].(string); ok {
		id = idArg
	}

	key := []byte(PrefixFactory + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			// Return empty factory
			return &DexFactory{
				ID:                  id,
				PoolCount:           0,
				PairCount:           0,
				TxCount:             0,
				TotalVolumeUSD:      "0",
				TotalVolumeETH:      "0",
				TotalFeesUSD:        "0",
				TotalValueLockedUSD: "0",
				TotalLiquidityUSD:   "0",
				TotalValueLockedETH: "0",
			}, nil
		}
		return nil, err
	}

	var factory DexFactory
	if err := json.Unmarshal(data, &factory); err != nil {
		return nil, err
	}
	return &factory, nil
}

func (e *QueryExecutor) resolveFactories(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	iter := db.NewIteratorWithPrefix([]byte(PrefixFactory))
	defer iter.Release()

	factories := make([]*DexFactory, 0)
	for iter.Next() {
		var factory DexFactory
		if err := json.Unmarshal(iter.Value(), &factory); err != nil {
			continue
		}
		factories = append(factories, &factory)
	}

	return factories, iter.Error()
}

// Bundle resolver (ETH/LUX price)
func (e *QueryExecutor) resolveBundle(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id := "1"
	if idArg, ok := args["id"].(string); ok {
		id = idArg
	}

	key := []byte(PrefixBundle + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			// Return default bundle with placeholder price
			return &Bundle{
				ID:          id,
				EthPriceUSD: "0",
				EthPrice:    "0",
				LuxPriceUSD: "0",
			}, nil
		}
		return nil, err
	}

	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}
	return &bundle, nil
}

func (e *QueryExecutor) resolveBundles(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	iter := db.NewIteratorWithPrefix([]byte(PrefixBundle))
	defer iter.Release()

	bundles := make([]*Bundle, 0)
	for iter.Next() {
		var bundle Bundle
		if err := json.Unmarshal(iter.Value(), &bundle); err != nil {
			continue
		}
		bundles = append(bundles, &bundle)
	}

	return bundles, iter.Error()
}

// Token resolver
func (e *QueryExecutor) resolveToken(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("token: requires 'id' argument")
	}

	id = strings.ToLower(id) // Normalize address
	key := []byte(PrefixToken + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (e *QueryExecutor) resolveTokens(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 100
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit > 1000 {
		limit = 1000
	}

	orderBy := "volumeUSD"
	if ob, ok := args["orderBy"].(string); ok {
		orderBy = ob
	}

	orderDirection := "desc"
	if od, ok := args["orderDirection"].(string); ok {
		orderDirection = od
	}

	iter := db.NewIteratorWithPrefix([]byte(PrefixToken))
	defer iter.Release()

	tokens := make([]*Token, 0, limit)
	for iter.Next() && len(tokens) < limit*2 { // Over-fetch for sorting
		var token Token
		if err := json.Unmarshal(iter.Value(), &token); err != nil {
			continue
		}
		tokens = append(tokens, &token)
	}

	// Sort by specified field
	sortTokens(tokens, orderBy, orderDirection)

	// Apply limit after sort
	if len(tokens) > limit {
		tokens = tokens[:limit]
	}

	return tokens, iter.Error()
}

// Pool resolver (v3)
func (e *QueryExecutor) resolvePool(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("pool: requires 'id' argument")
	}

	id = strings.ToLower(id)
	key := []byte(PrefixPool + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var pool Pool
	if err := json.Unmarshal(data, &pool); err != nil {
		return nil, err
	}
	return &pool, nil
}

func (e *QueryExecutor) resolvePools(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 100
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit > 1000 {
		limit = 1000
	}

	// Check for token filter
	var tokenFilter string
	if where, ok := args["where"].(map[string]interface{}); ok {
		if t0, ok := where["token0"].(string); ok {
			tokenFilter = strings.ToLower(t0)
		} else if t1, ok := where["token1"].(string); ok {
			tokenFilter = strings.ToLower(t1)
		}
	}

	var pools []*Pool
	var iterErr error

	if tokenFilter != "" {
		// Use index for token filter
		pools, iterErr = e.getPoolsByToken(db, tokenFilter, limit)
	} else {
		iter := db.NewIteratorWithPrefix([]byte(PrefixPool))
		defer iter.Release()

		pools = make([]*Pool, 0, limit)
		for iter.Next() && len(pools) < limit {
			var pool Pool
			if err := json.Unmarshal(iter.Value(), &pool); err != nil {
				continue
			}
			pools = append(pools, &pool)
		}
		iterErr = iter.Error()
	}

	return pools, iterErr
}

// Pair resolver (v2)
func (e *QueryExecutor) resolvePair(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("pair: requires 'id' argument")
	}

	id = strings.ToLower(id)
	key := []byte(PrefixPair + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var pair Pair
	if err := json.Unmarshal(data, &pair); err != nil {
		return nil, err
	}
	return &pair, nil
}

func (e *QueryExecutor) resolvePairs(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 100
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit > 1000 {
		limit = 1000
	}

	iter := db.NewIteratorWithPrefix([]byte(PrefixPair))
	defer iter.Release()

	pairs := make([]*Pair, 0, limit)
	for iter.Next() && len(pairs) < limit {
		var pair Pair
		if err := json.Unmarshal(iter.Value(), &pair); err != nil {
			continue
		}
		pairs = append(pairs, &pair)
	}

	return pairs, iter.Error()
}

// Tick resolver (v3)
func (e *QueryExecutor) resolveTick(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("tick: requires 'id' argument")
	}

	key := []byte(PrefixTick + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var tick Tick
	if err := json.Unmarshal(data, &tick); err != nil {
		return nil, err
	}
	return &tick, nil
}

func (e *QueryExecutor) resolveTicks(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 100
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit > 1000 {
		limit = 1000
	}

	// Filter by pool
	poolFilter := ""
	if where, ok := args["where"].(map[string]interface{}); ok {
		if p, ok := where["pool"].(string); ok {
			poolFilter = strings.ToLower(p)
		} else if p, ok := where["poolAddress"].(string); ok {
			poolFilter = strings.ToLower(p)
		}
	}

	prefix := []byte(PrefixTick)
	if poolFilter != "" {
		prefix = []byte(PrefixTick + poolFilter + "#")
	}

	iter := db.NewIteratorWithPrefix(prefix)
	defer iter.Release()

	ticks := make([]*Tick, 0, limit)
	for iter.Next() && len(ticks) < limit {
		var tick Tick
		if err := json.Unmarshal(iter.Value(), &tick); err != nil {
			continue
		}
		ticks = append(ticks, &tick)
	}

	return ticks, iter.Error()
}

// Swap resolver
func (e *QueryExecutor) resolveSwap(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("swap: requires 'id' argument")
	}

	key := []byte(PrefixSwap + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var swap Swap
	if err := json.Unmarshal(data, &swap); err != nil {
		return nil, err
	}
	return &swap, nil
}

func (e *QueryExecutor) resolveSwaps(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 100
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit > 1000 {
		limit = 1000
	}

	iter := db.NewIteratorWithPrefix([]byte(PrefixSwap))
	defer iter.Release()

	swaps := make([]*Swap, 0, limit)
	for iter.Next() && len(swaps) < limit {
		var swap Swap
		if err := json.Unmarshal(iter.Value(), &swap); err != nil {
			continue
		}
		swaps = append(swaps, &swap)
	}

	// Sort by timestamp descending (newest first)
	sort.Slice(swaps, func(i, j int) bool {
		return swaps[i].Timestamp > swaps[j].Timestamp
	})

	return swaps, iter.Error()
}

// Mint resolver
func (e *QueryExecutor) resolveMint(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("mint: requires 'id' argument")
	}

	key := []byte(PrefixMint + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var mint Mint
	if err := json.Unmarshal(data, &mint); err != nil {
		return nil, err
	}
	return &mint, nil
}

func (e *QueryExecutor) resolveMints(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 100
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}

	iter := db.NewIteratorWithPrefix([]byte(PrefixMint))
	defer iter.Release()

	mints := make([]*Mint, 0, limit)
	for iter.Next() && len(mints) < limit {
		var mint Mint
		if err := json.Unmarshal(iter.Value(), &mint); err != nil {
			continue
		}
		mints = append(mints, &mint)
	}

	return mints, iter.Error()
}

// Burn resolver
func (e *QueryExecutor) resolveBurn(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("burn: requires 'id' argument")
	}

	key := []byte(PrefixBurn + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var burn Burn
	if err := json.Unmarshal(data, &burn); err != nil {
		return nil, err
	}
	return &burn, nil
}

func (e *QueryExecutor) resolveBurns(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 100
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}

	iter := db.NewIteratorWithPrefix([]byte(PrefixBurn))
	defer iter.Release()

	burns := make([]*Burn, 0, limit)
	for iter.Next() && len(burns) < limit {
		var burn Burn
		if err := json.Unmarshal(iter.Value(), &burn); err != nil {
			continue
		}
		burns = append(burns, &burn)
	}

	return burns, iter.Error()
}

// Token time series resolvers
func (e *QueryExecutor) resolveTokenDayData(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("tokenDayData: requires 'id' argument")
	}

	key := []byte(PrefixTokenDay + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var tdd TokenDayData
	if err := json.Unmarshal(data, &tdd); err != nil {
		return nil, err
	}
	return &tdd, nil
}

func (e *QueryExecutor) resolveTokenDayDatas(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 30 // Default to 30 days
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit > 365 {
		limit = 365
	}

	// Filter by token
	tokenFilter := ""
	if where, ok := args["where"].(map[string]interface{}); ok {
		if t, ok := where["token"].(string); ok {
			tokenFilter = strings.ToLower(t)
		}
	}

	prefix := []byte(PrefixTokenDay)
	if tokenFilter != "" {
		prefix = []byte(PrefixTokenDay + tokenFilter + "-")
	}

	iter := db.NewIteratorWithPrefix(prefix)
	defer iter.Release()

	datas := make([]*TokenDayData, 0, limit)
	for iter.Next() && len(datas) < limit {
		var tdd TokenDayData
		if err := json.Unmarshal(iter.Value(), &tdd); err != nil {
			continue
		}
		datas = append(datas, &tdd)
	}

	// Sort by date descending
	sort.Slice(datas, func(i, j int) bool {
		return datas[i].Date > datas[j].Date
	})

	return datas, iter.Error()
}

func (e *QueryExecutor) resolveTokenHourData(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("tokenHourData: requires 'id' argument")
	}

	key := []byte(PrefixTokenHour + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var thd TokenHourData
	if err := json.Unmarshal(data, &thd); err != nil {
		return nil, err
	}
	return &thd, nil
}

func (e *QueryExecutor) resolveTokenHourDatas(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 24 // Default to 24 hours
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit > 168 { // Max 7 days
		limit = 168
	}

	tokenFilter := ""
	if where, ok := args["where"].(map[string]interface{}); ok {
		if t, ok := where["token"].(string); ok {
			tokenFilter = strings.ToLower(t)
		}
	}

	prefix := []byte(PrefixTokenHour)
	if tokenFilter != "" {
		prefix = []byte(PrefixTokenHour + tokenFilter + "-")
	}

	iter := db.NewIteratorWithPrefix(prefix)
	defer iter.Release()

	datas := make([]*TokenHourData, 0, limit)
	for iter.Next() && len(datas) < limit {
		var thd TokenHourData
		if err := json.Unmarshal(iter.Value(), &thd); err != nil {
			continue
		}
		datas = append(datas, &thd)
	}

	sort.Slice(datas, func(i, j int) bool {
		return datas[i].PeriodStartUnix > datas[j].PeriodStartUnix
	})

	return datas, iter.Error()
}

// Pool time series resolvers
func (e *QueryExecutor) resolvePoolDayData(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("poolDayData: requires 'id' argument")
	}

	key := []byte(PrefixPoolDay + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var pdd PoolDayData
	if err := json.Unmarshal(data, &pdd); err != nil {
		return nil, err
	}
	return &pdd, nil
}

func (e *QueryExecutor) resolvePoolDayDatas(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 30
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}

	poolFilter := ""
	if where, ok := args["where"].(map[string]interface{}); ok {
		if p, ok := where["pool"].(string); ok {
			poolFilter = strings.ToLower(p)
		}
	}

	prefix := []byte(PrefixPoolDay)
	if poolFilter != "" {
		prefix = []byte(PrefixPoolDay + poolFilter + "-")
	}

	iter := db.NewIteratorWithPrefix(prefix)
	defer iter.Release()

	datas := make([]*PoolDayData, 0, limit)
	for iter.Next() && len(datas) < limit {
		var pdd PoolDayData
		if err := json.Unmarshal(iter.Value(), &pdd); err != nil {
			continue
		}
		datas = append(datas, &pdd)
	}

	sort.Slice(datas, func(i, j int) bool {
		return datas[i].Date > datas[j].Date
	})

	return datas, iter.Error()
}

func (e *QueryExecutor) resolvePoolHourData(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("poolHourData: requires 'id' argument")
	}

	key := []byte(PrefixPoolHour + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var phd PoolHourData
	if err := json.Unmarshal(data, &phd); err != nil {
		return nil, err
	}
	return &phd, nil
}

func (e *QueryExecutor) resolvePoolHourDatas(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 24
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}

	poolFilter := ""
	if where, ok := args["where"].(map[string]interface{}); ok {
		if p, ok := where["pool"].(string); ok {
			poolFilter = strings.ToLower(p)
		}
	}

	prefix := []byte(PrefixPoolHour)
	if poolFilter != "" {
		prefix = []byte(PrefixPoolHour + poolFilter + "-")
	}

	iter := db.NewIteratorWithPrefix(prefix)
	defer iter.Release()

	datas := make([]*PoolHourData, 0, limit)
	for iter.Next() && len(datas) < limit {
		var phd PoolHourData
		if err := json.Unmarshal(iter.Value(), &phd); err != nil {
			continue
		}
		datas = append(datas, &phd)
	}

	sort.Slice(datas, func(i, j int) bool {
		return datas[i].PeriodStartUnix > datas[j].PeriodStartUnix
	})

	return datas, iter.Error()
}

// Pair time series resolvers (v2)
func (e *QueryExecutor) resolvePairDayData(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("pairDayData: requires 'id' argument")
	}

	key := []byte(PrefixPairDay + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var pdd PairDayData
	if err := json.Unmarshal(data, &pdd); err != nil {
		return nil, err
	}
	return &pdd, nil
}

func (e *QueryExecutor) resolvePairDayDatas(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 30
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}

	pairFilter := ""
	if where, ok := args["where"].(map[string]interface{}); ok {
		if p, ok := where["pairAddress"].(string); ok {
			pairFilter = strings.ToLower(p)
		}
	}

	prefix := []byte(PrefixPairDay)
	if pairFilter != "" {
		prefix = []byte(PrefixPairDay + pairFilter + "-")
	}

	iter := db.NewIteratorWithPrefix(prefix)
	defer iter.Release()

	datas := make([]*PairDayData, 0, limit)
	for iter.Next() && len(datas) < limit {
		var pdd PairDayData
		if err := json.Unmarshal(iter.Value(), &pdd); err != nil {
			continue
		}
		datas = append(datas, &pdd)
	}

	sort.Slice(datas, func(i, j int) bool {
		return datas[i].Date > datas[j].Date
	})

	return datas, iter.Error()
}

// Protocol-level daily data
func (e *QueryExecutor) resolveUniswapDayData(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	id, ok := args["id"].(string)
	if !ok {
		return nil, fmt.Errorf("uniswapDayData: requires 'id' argument")
	}

	key := []byte("dex:daydata:" + id)
	data, err := db.Get(key)
	if err != nil {
		if err == database.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var dayData map[string]interface{}
	if err := json.Unmarshal(data, &dayData); err != nil {
		return nil, err
	}
	return dayData, nil
}

func (e *QueryExecutor) resolveUniswapDayDatas(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error) {
	limit := 30
	if l, ok := args["first"].(string); ok {
		fmt.Sscanf(l, "%d", &limit)
	}

	iter := db.NewIteratorWithPrefix([]byte("dex:daydata:"))
	defer iter.Release()

	datas := make([]map[string]interface{}, 0, limit)
	for iter.Next() && len(datas) < limit {
		var dayData map[string]interface{}
		if err := json.Unmarshal(iter.Value(), &dayData); err != nil {
			continue
		}
		datas = append(datas, dayData)
	}

	return datas, iter.Error()
}

// Helper functions

func (e *QueryExecutor) getPoolsByToken(db database.Database, token string, limit int) ([]*Pool, error) {
	// Use token->pool index
	indexKey := []byte(PrefixPoolByToken + token)
	indexData, err := db.Get(indexKey)
	if err != nil {
		if err == database.ErrNotFound {
			return []*Pool{}, nil
		}
		return nil, err
	}

	var poolAddrs []string
	if err := json.Unmarshal(indexData, &poolAddrs); err != nil {
		return nil, err
	}

	pools := make([]*Pool, 0, len(poolAddrs))
	for _, addr := range poolAddrs {
		if len(pools) >= limit {
			break
		}

		poolKey := []byte(PrefixPool + addr)
		poolData, err := db.Get(poolKey)
		if err != nil {
			continue
		}

		var pool Pool
		if err := json.Unmarshal(poolData, &pool); err != nil {
			continue
		}
		pools = append(pools, &pool)
	}

	return pools, nil
}

func sortTokens(tokens []*Token, orderBy, orderDirection string) {
	sort.Slice(tokens, func(i, j int) bool {
		var cmp bool
		switch orderBy {
		case "volumeUSD":
			vi, _ := new(big.Float).SetString(tokens[i].VolumeUSD)
			vj, _ := new(big.Float).SetString(tokens[j].VolumeUSD)
			if vi == nil {
				vi = big.NewFloat(0)
			}
			if vj == nil {
				vj = big.NewFloat(0)
			}
			cmp = vi.Cmp(vj) > 0
		case "totalValueLockedUSD":
			vi, _ := new(big.Float).SetString(tokens[i].TotalValueLockedUSD)
			vj, _ := new(big.Float).SetString(tokens[j].TotalValueLockedUSD)
			if vi == nil {
				vi = big.NewFloat(0)
			}
			if vj == nil {
				vj = big.NewFloat(0)
			}
			cmp = vi.Cmp(vj) > 0
		case "txCount":
			cmp = tokens[i].TxCount > tokens[j].TxCount
		default:
			cmp = tokens[i].ID < tokens[j].ID
		}

		if orderDirection == "asc" {
			return !cmp
		}
		return cmp
	})
}
