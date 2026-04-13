// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package liquidity implements AMM liquidity pools for the DEX VM.
package liquidity

import (
	"errors"
	"math/big"
	"sync"

	"github.com/luxfi/ids"
)

var (
	ErrInsufficientLiquidity = errors.New("insufficient liquidity")
	ErrPoolNotFound          = errors.New("pool not found")
	ErrInvalidAmount         = errors.New("invalid amount")
	ErrSlippageExceeded      = errors.New("slippage exceeded")
	ErrZeroLiquidity         = errors.New("zero liquidity not allowed")
	ErrPoolExists            = errors.New("pool already exists")
	ErrSameToken             = errors.New("cannot create pool with same token")
)

// PoolType represents the type of AMM pool.
type PoolType uint8

const (
	ConstantProduct PoolType = iota // x * y = k (Uniswap V2 style)
	StableSwap                      // Low slippage for stable pairs
	Concentrated                    // Concentrated liquidity (Uniswap V3 style)
)

func (t PoolType) String() string {
	switch t {
	case ConstantProduct:
		return "constant_product"
	case StableSwap:
		return "stable_swap"
	case Concentrated:
		return "concentrated"
	default:
		return "unknown"
	}
}

// Pool represents an AMM liquidity pool.
type Pool struct {
	ID          ids.ID   `json:"id"`
	Token0      ids.ID   `json:"token0"`   // First token in the pair
	Token1      ids.ID   `json:"token1"`   // Second token in the pair
	Reserve0    *big.Int `json:"reserve0"` // Reserve of token0
	Reserve1    *big.Int `json:"reserve1"` // Reserve of token1
	Type        PoolType `json:"type"`
	FeeBps      uint16   `json:"feeBps"`      // Trading fee in basis points
	TotalSupply *big.Int `json:"totalSupply"` // Total LP tokens

	// Concentrated liquidity parameters (for Concentrated type)
	TickLower    int32    `json:"tickLower,omitempty"`
	TickUpper    int32    `json:"tickUpper,omitempty"`
	SqrtPriceX96 *big.Int `json:"sqrtPriceX96,omitempty"`

	// Statistics
	Volume0 *big.Int `json:"volume0"` // Cumulative volume in token0
	Volume1 *big.Int `json:"volume1"` // Cumulative volume in token1
	Fees0   *big.Int `json:"fees0"`   // Cumulative fees in token0
	Fees1   *big.Int `json:"fees1"`   // Cumulative fees in token1
	TxCount uint64   `json:"txCount"` // Total transaction count

	CreatedAt int64 `json:"createdAt"`
	UpdatedAt int64 `json:"updatedAt"`
}

// LPPosition represents a liquidity provider's position in a pool.
type LPPosition struct {
	Owner      ids.ShortID `json:"owner"`
	PoolID     ids.ID      `json:"poolId"`
	Liquidity  *big.Int    `json:"liquidity"`           // LP tokens held
	Token0Owed *big.Int    `json:"token0Owed"`          // Unclaimed token0 fees
	Token1Owed *big.Int    `json:"token1Owed"`          // Unclaimed token1 fees
	TickLower  int32       `json:"tickLower,omitempty"` // For concentrated
	TickUpper  int32       `json:"tickUpper,omitempty"` // For concentrated
	CreatedAt  int64       `json:"createdAt"`
}

// SwapResult contains the result of a swap operation.
type SwapResult struct {
	AmountIn    *big.Int `json:"amountIn"`
	AmountOut   *big.Int `json:"amountOut"`
	Fee         *big.Int `json:"fee"`
	PriceImpact uint64   `json:"priceImpact"` // In basis points
	NewReserve0 *big.Int `json:"newReserve0"`
	NewReserve1 *big.Int `json:"newReserve1"`
}

// Manager manages all liquidity pools.
type Manager struct {
	mu    sync.RWMutex
	pools map[ids.ID]*Pool
	// Token pair -> Pool ID mapping for fast lookup
	pairToPool map[string]ids.ID
}

// NewManager creates a new liquidity pool manager.
func NewManager() *Manager {
	return &Manager{
		pools:      make(map[ids.ID]*Pool),
		pairToPool: make(map[string]ids.ID),
	}
}

// CreatePool creates a new liquidity pool.
func (m *Manager) CreatePool(
	token0, token1 ids.ID,
	initialAmount0, initialAmount1 *big.Int,
	poolType PoolType,
	feeBps uint16,
) (*Pool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Cannot create a pool with the same token
	if token0 == token1 {
		return nil, ErrSameToken
	}

	// Ensure token0 < token1 (canonical ordering)
	if token0.Compare(token1) > 0 {
		token0, token1 = token1, token0
		initialAmount0, initialAmount1 = initialAmount1, initialAmount0
	}

	pairKey := makePairKey(token0, token1)
	if _, exists := m.pairToPool[pairKey]; exists {
		return nil, ErrPoolExists
	}

	if initialAmount0.Sign() <= 0 || initialAmount1.Sign() <= 0 {
		return nil, ErrInvalidAmount
	}

	// Calculate initial liquidity (geometric mean)
	liquidity := new(big.Int).Sqrt(new(big.Int).Mul(initialAmount0, initialAmount1))
	if liquidity.Sign() <= 0 {
		return nil, ErrZeroLiquidity
	}

	pool := &Pool{
		ID:          ids.GenerateTestID(), // In production, use proper ID generation
		Token0:      token0,
		Token1:      token1,
		Reserve0:    new(big.Int).Set(initialAmount0),
		Reserve1:    new(big.Int).Set(initialAmount1),
		Type:        poolType,
		FeeBps:      feeBps,
		TotalSupply: liquidity,
		Volume0:     big.NewInt(0),
		Volume1:     big.NewInt(0),
		Fees0:       big.NewInt(0),
		Fees1:       big.NewInt(0),
	}

	m.pools[pool.ID] = pool
	m.pairToPool[pairKey] = pool.ID

	return pool, nil
}

// GetPool returns a pool by ID.
func (m *Manager) GetPool(poolID ids.ID) (*Pool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pool, exists := m.pools[poolID]
	if !exists {
		return nil, ErrPoolNotFound
	}
	return pool, nil
}

// GetPoolByPair returns a pool by token pair.
func (m *Manager) GetPoolByPair(token0, token1 ids.ID) (*Pool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Ensure canonical ordering
	if token0.Compare(token1) > 0 {
		token0, token1 = token1, token0
	}

	pairKey := makePairKey(token0, token1)
	poolID, exists := m.pairToPool[pairKey]
	if !exists {
		return nil, ErrPoolNotFound
	}

	return m.pools[poolID], nil
}

// Swap executes a swap on a pool.
func (m *Manager) Swap(
	poolID ids.ID,
	tokenIn ids.ID,
	amountIn *big.Int,
	minAmountOut *big.Int,
) (*SwapResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolID]
	if !exists {
		return nil, ErrPoolNotFound
	}

	if amountIn.Sign() <= 0 {
		return nil, ErrInvalidAmount
	}

	var result *SwapResult
	var err error

	switch pool.Type {
	case ConstantProduct:
		result, err = m.swapConstantProduct(pool, tokenIn, amountIn)
	case StableSwap:
		result, err = m.swapStableSwap(pool, tokenIn, amountIn)
	case Concentrated:
		result, err = m.swapConcentrated(pool, tokenIn, amountIn)
	default:
		return nil, errors.New("unsupported pool type")
	}

	if err != nil {
		return nil, err
	}

	// Check slippage
	if result.AmountOut.Cmp(minAmountOut) < 0 {
		return nil, ErrSlippageExceeded
	}

	// Update pool reserves
	pool.Reserve0.Set(result.NewReserve0)
	pool.Reserve1.Set(result.NewReserve1)

	// Update statistics
	if tokenIn == pool.Token0 {
		pool.Volume0.Add(pool.Volume0, amountIn)
		pool.Fees0.Add(pool.Fees0, result.Fee)
	} else {
		pool.Volume1.Add(pool.Volume1, amountIn)
		pool.Fees1.Add(pool.Fees1, result.Fee)
	}
	pool.TxCount++

	return result, nil
}

// swapConstantProduct implements x * y = k AMM formula.
func (m *Manager) swapConstantProduct(pool *Pool, tokenIn ids.ID, amountIn *big.Int) (*SwapResult, error) {
	var reserveIn, reserveOut *big.Int

	if tokenIn == pool.Token0 {
		reserveIn = pool.Reserve0
		reserveOut = pool.Reserve1
	} else if tokenIn == pool.Token1 {
		reserveIn = pool.Reserve1
		reserveOut = pool.Reserve0
	} else {
		return nil, errors.New("invalid token")
	}

	// Calculate fee
	feeBps := big.NewInt(int64(pool.FeeBps))
	feeMultiplier := new(big.Int).Sub(big.NewInt(10000), feeBps)
	amountInWithFee := new(big.Int).Mul(amountIn, feeMultiplier)

	// amountOut = (reserveOut * amountInWithFee) / (reserveIn * 10000 + amountInWithFee)
	numerator := new(big.Int).Mul(reserveOut, amountInWithFee)
	denominator := new(big.Int).Add(
		new(big.Int).Mul(reserveIn, big.NewInt(10000)),
		amountInWithFee,
	)
	amountOut := new(big.Int).Div(numerator, denominator)

	if amountOut.Sign() <= 0 || amountOut.Cmp(reserveOut) >= 0 {
		return nil, ErrInsufficientLiquidity
	}

	fee := new(big.Int).Div(
		new(big.Int).Mul(amountIn, feeBps),
		big.NewInt(10000),
	)

	// Calculate new reserves
	newReserveIn := new(big.Int).Add(reserveIn, amountIn)
	newReserveOut := new(big.Int).Sub(reserveOut, amountOut)

	var newReserve0, newReserve1 *big.Int
	if tokenIn == pool.Token0 {
		newReserve0, newReserve1 = newReserveIn, newReserveOut
	} else {
		newReserve0, newReserve1 = newReserveOut, newReserveIn
	}

	// Calculate price impact (in basis points)
	oldPrice := new(big.Int).Div(
		new(big.Int).Mul(reserveOut, big.NewInt(10000)),
		reserveIn,
	)
	newPrice := new(big.Int).Div(
		new(big.Int).Mul(newReserveOut, big.NewInt(10000)),
		newReserveIn,
	)
	priceImpact := uint64(new(big.Int).Abs(new(big.Int).Sub(oldPrice, newPrice)).Int64())

	return &SwapResult{
		AmountIn:    amountIn,
		AmountOut:   amountOut,
		Fee:         fee,
		PriceImpact: priceImpact,
		NewReserve0: newReserve0,
		NewReserve1: newReserve1,
	}, nil
}

// swapStableSwap implements a low-slippage curve for stable assets.
func (m *Manager) swapStableSwap(pool *Pool, tokenIn ids.ID, amountIn *big.Int) (*SwapResult, error) {
	// Simplified stable swap - in production use Curve's formula
	// For now, use constant product with lower fee
	return m.swapConstantProduct(pool, tokenIn, amountIn)
}

// swapConcentrated implements concentrated liquidity swap.
func (m *Manager) swapConcentrated(pool *Pool, tokenIn ids.ID, amountIn *big.Int) (*SwapResult, error) {
	// Simplified concentrated liquidity - in production use Uniswap V3's formula
	return m.swapConstantProduct(pool, tokenIn, amountIn)
}

// AddLiquidity adds liquidity to a pool.
func (m *Manager) AddLiquidity(
	poolID ids.ID,
	amount0 *big.Int,
	amount1 *big.Int,
	minLiquidity *big.Int,
) (*big.Int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolID]
	if !exists {
		return nil, ErrPoolNotFound
	}

	if amount0.Sign() <= 0 || amount1.Sign() <= 0 {
		return nil, ErrInvalidAmount
	}

	var liquidity *big.Int
	if pool.TotalSupply.Sign() == 0 {
		// First liquidity provision
		liquidity = new(big.Int).Sqrt(new(big.Int).Mul(amount0, amount1))
	} else {
		// Calculate liquidity from both tokens
		liquidity0 := new(big.Int).Div(
			new(big.Int).Mul(amount0, pool.TotalSupply),
			pool.Reserve0,
		)
		liquidity1 := new(big.Int).Div(
			new(big.Int).Mul(amount1, pool.TotalSupply),
			pool.Reserve1,
		)
		// Take the minimum
		if liquidity0.Cmp(liquidity1) < 0 {
			liquidity = liquidity0
		} else {
			liquidity = liquidity1
		}
	}

	if liquidity.Cmp(minLiquidity) < 0 {
		return nil, ErrSlippageExceeded
	}

	// Update pool
	pool.Reserve0.Add(pool.Reserve0, amount0)
	pool.Reserve1.Add(pool.Reserve1, amount1)
	pool.TotalSupply.Add(pool.TotalSupply, liquidity)

	return liquidity, nil
}

// RemoveLiquidity removes liquidity from a pool.
func (m *Manager) RemoveLiquidity(
	poolID ids.ID,
	liquidity *big.Int,
	minAmount0 *big.Int,
	minAmount1 *big.Int,
) (*big.Int, *big.Int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolID]
	if !exists {
		return nil, nil, ErrPoolNotFound
	}

	if liquidity.Sign() <= 0 {
		return nil, nil, ErrInvalidAmount
	}

	if liquidity.Cmp(pool.TotalSupply) > 0 {
		return nil, nil, ErrInsufficientLiquidity
	}

	// Calculate amounts to return
	amount0 := new(big.Int).Div(
		new(big.Int).Mul(liquidity, pool.Reserve0),
		pool.TotalSupply,
	)
	amount1 := new(big.Int).Div(
		new(big.Int).Mul(liquidity, pool.Reserve1),
		pool.TotalSupply,
	)

	if amount0.Cmp(minAmount0) < 0 || amount1.Cmp(minAmount1) < 0 {
		return nil, nil, ErrSlippageExceeded
	}

	// Update pool
	pool.Reserve0.Sub(pool.Reserve0, amount0)
	pool.Reserve1.Sub(pool.Reserve1, amount1)
	pool.TotalSupply.Sub(pool.TotalSupply, liquidity)

	return amount0, amount1, nil
}

// GetQuote returns the expected output for a swap.
func (m *Manager) GetQuote(poolID ids.ID, tokenIn ids.ID, amountIn *big.Int) (*big.Int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pool, exists := m.pools[poolID]
	if !exists {
		return nil, ErrPoolNotFound
	}

	var reserveIn, reserveOut *big.Int
	if tokenIn == pool.Token0 {
		reserveIn = pool.Reserve0
		reserveOut = pool.Reserve1
	} else if tokenIn == pool.Token1 {
		reserveIn = pool.Reserve1
		reserveOut = pool.Reserve0
	} else {
		return nil, errors.New("invalid token")
	}

	// Calculate output with fee
	feeBps := big.NewInt(int64(pool.FeeBps))
	feeMultiplier := new(big.Int).Sub(big.NewInt(10000), feeBps)
	amountInWithFee := new(big.Int).Mul(amountIn, feeMultiplier)

	numerator := new(big.Int).Mul(reserveOut, amountInWithFee)
	denominator := new(big.Int).Add(
		new(big.Int).Mul(reserveIn, big.NewInt(10000)),
		amountInWithFee,
	)

	return new(big.Int).Div(numerator, denominator), nil
}

// GetAllPools returns all pools.
func (m *Manager) GetAllPools() []*Pool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pools := make([]*Pool, 0, len(m.pools))
	for _, pool := range m.pools {
		pools = append(pools, pool)
	}
	return pools
}

func makePairKey(token0, token1 ids.ID) string {
	return token0.String() + "-" + token1.String()
}
