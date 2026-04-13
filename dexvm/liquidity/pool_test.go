// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package liquidity

import (
	"math/big"
	"testing"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()
	require.NotNil(mgr)

	pools := mgr.GetAllPools()
	require.Empty(pools)
}

func TestCreatePool(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	pool, err := mgr.CreatePool(
		token0,
		token1,
		big.NewInt(1000000000000000000), // 1 token0
		big.NewInt(2000000000000000000), // 2 token1
		ConstantProduct,
		30, // 0.3% fee
	)
	require.NoError(err)
	require.NotNil(pool)
	require.NotEqual(ids.Empty, pool.ID)

	// Verify pool was created
	fetchedPool, err := mgr.GetPool(pool.ID)
	require.NoError(err)
	require.Equal(pool.ID, fetchedPool.ID)
	require.Equal(ConstantProduct, fetchedPool.Type)
	require.Equal(uint16(30), fetchedPool.FeeBps)
}

func TestCreatePoolSameToken(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token := ids.GenerateTestID()

	_, err := mgr.CreatePool(
		token,
		token, // Same token - should fail due to ErrPoolExists after canonical ordering
		big.NewInt(1000000000000000000),
		big.NewInt(2000000000000000000),
		ConstantProduct,
		30,
	)
	require.Error(err)
}

func TestGetQuote(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	// Create pool with 1:2 ratio
	pool, err := mgr.CreatePool(
		token0,
		token1,
		big.NewInt(1000000000000000000), // 1 token0
		big.NewInt(2000000000000000000), // 2 token1
		ConstantProduct,
		30, // 0.3% fee
	)
	require.NoError(err)

	// Get quote for swapping token0 to token1
	// Determine which token is token0 in the pool (canonical ordering)
	var inputToken ids.ID
	if pool.Token0 == token0 {
		inputToken = token0
	} else {
		inputToken = token1
	}

	amountOut, err := mgr.GetQuote(
		pool.ID,
		inputToken,
		big.NewInt(100000000000000000), // 0.1 input token
	)
	require.NoError(err)
	require.NotNil(amountOut)
	require.True(amountOut.Sign() > 0)

	// Output should be reasonable given the reserves
	// For constant product: amountOut = reserveOut * amountIn / (reserveIn + amountIn)
	require.True(amountOut.Cmp(big.NewInt(0)) > 0)
}

func TestSwap(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	// Create pool
	pool, err := mgr.CreatePool(
		token0,
		token1,
		big.NewInt(1000000000000000000),
		big.NewInt(2000000000000000000),
		ConstantProduct,
		30,
	)
	require.NoError(err)

	initialReserve0 := new(big.Int).Set(pool.Reserve0)
	initialReserve1 := new(big.Int).Set(pool.Reserve1)

	// Get quote first
	expectedOut, err := mgr.GetQuote(
		pool.ID,
		pool.Token0,
		big.NewInt(100000000000000000),
	)
	require.NoError(err)

	// Execute swap
	result, err := mgr.Swap(
		pool.ID,
		pool.Token0,
		big.NewInt(100000000000000000),
		big.NewInt(1), // Allow any output
	)
	require.NoError(err)
	require.NotNil(result)
	require.Equal(expectedOut.Int64(), result.AmountOut.Int64())
	require.True(result.Fee.Sign() > 0)

	// Verify reserves changed
	require.True(pool.Reserve0.Cmp(initialReserve0) > 0) // Increased
	require.True(pool.Reserve1.Cmp(initialReserve1) < 0) // Decreased
}

func TestSwapSlippageProtection(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	// Create pool
	pool, err := mgr.CreatePool(
		token0,
		token1,
		big.NewInt(1000000000000000000),
		big.NewInt(2000000000000000000),
		ConstantProduct,
		30,
	)
	require.NoError(err)

	// Try swap with unrealistic minAmountOut
	_, err = mgr.Swap(
		pool.ID,
		pool.Token0,
		big.NewInt(100000000000000000),
		big.NewInt(300000000000000000), // Expect 0.3 token1, but will get less
	)
	require.Error(err)
	require.Equal(ErrSlippageExceeded, err)
}

func TestAddLiquidity(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	// Create pool
	pool, err := mgr.CreatePool(
		token0,
		token1,
		big.NewInt(1000000000000000000),
		big.NewInt(2000000000000000000),
		ConstantProduct,
		30,
	)
	require.NoError(err)

	initialLiquidity := new(big.Int).Set(pool.TotalSupply)
	initialReserve0 := new(big.Int).Set(pool.Reserve0)
	initialReserve1 := new(big.Int).Set(pool.Reserve1)

	// Add liquidity (maintaining ratio)
	lpTokens, err := mgr.AddLiquidity(
		pool.ID,
		big.NewInt(500000000000000000),  // 0.5 token0
		big.NewInt(1000000000000000000), // 1 token1 (maintains 1:2 ratio)
		big.NewInt(1),                   // Min liquidity
	)
	require.NoError(err)
	require.True(lpTokens.Sign() > 0)

	// Verify reserves increased
	require.True(pool.Reserve0.Cmp(initialReserve0) > 0)
	require.True(pool.Reserve1.Cmp(initialReserve1) > 0)
	require.True(pool.TotalSupply.Cmp(initialLiquidity) > 0)
}

func TestRemoveLiquidity(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	// Create pool
	pool, err := mgr.CreatePool(
		token0,
		token1,
		big.NewInt(1000000000000000000),
		big.NewInt(2000000000000000000),
		ConstantProduct,
		30,
	)
	require.NoError(err)

	initialLiquidity := new(big.Int).Set(pool.TotalSupply)

	// Remove half the liquidity
	halfLiquidity := new(big.Int).Div(initialLiquidity, big.NewInt(2))
	amount0, amount1, err := mgr.RemoveLiquidity(
		pool.ID,
		halfLiquidity,
		big.NewInt(1), // Min amount0
		big.NewInt(1), // Min amount1
	)
	require.NoError(err)

	// Should get back roughly half of each token
	require.True(amount0.Sign() > 0)
	require.True(amount1.Sign() > 0)

	// Liquidity should be halved
	expectedLiquidity := new(big.Int).Sub(initialLiquidity, halfLiquidity)
	require.Equal(expectedLiquidity.Int64(), pool.TotalSupply.Int64())
}

func TestGetPoolByPair(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	// Create pool
	pool, err := mgr.CreatePool(
		token0,
		token1,
		big.NewInt(1000000000000000000),
		big.NewInt(2000000000000000000),
		ConstantProduct,
		30,
	)
	require.NoError(err)

	// Find by tokens (both orderings should work)
	foundPool, err := mgr.GetPoolByPair(token0, token1)
	require.NoError(err)
	require.Equal(pool.ID, foundPool.ID)

	foundPool, err = mgr.GetPoolByPair(token1, token0)
	require.NoError(err)
	require.Equal(pool.ID, foundPool.ID)
}

func TestPoolExists(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	// Create first pool
	_, err := mgr.CreatePool(
		token0,
		token1,
		big.NewInt(1000000000000000000),
		big.NewInt(2000000000000000000),
		ConstantProduct,
		30,
	)
	require.NoError(err)

	// Try to create duplicate pool - should fail
	_, err = mgr.CreatePool(
		token0,
		token1,
		big.NewInt(1000000000000000000),
		big.NewInt(2000000000000000000),
		ConstantProduct,
		10,
	)
	require.Error(err)
	require.Equal(ErrPoolExists, err)
}

func TestStableSwapPool(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	// Simulating stablecoins (USDT/USDC)
	usdt := ids.GenerateTestID()
	usdc := ids.GenerateTestID()

	// Create stable swap pool
	pool, err := mgr.CreatePool(
		usdt,
		usdc,
		big.NewInt(1000000000000000000), // 1 USDT
		big.NewInt(1000000000000000000), // 1 USDC
		StableSwap,
		4, // 0.04% fee (lower for stables)
	)
	require.NoError(err)
	require.Equal(StableSwap, pool.Type)

	// Get a swap quote
	amountOut, err := mgr.GetQuote(
		pool.ID,
		pool.Token0,
		big.NewInt(100000000000000000), // 0.1 token
	)
	require.NoError(err)
	require.True(amountOut.Sign() > 0)
}

func TestConcentratedLiquidity(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	// Create concentrated liquidity pool
	pool, err := mgr.CreatePool(
		token0,
		token1,
		big.NewInt(1000000000000000000),
		big.NewInt(2000000000000000000),
		Concentrated,
		30,
	)
	require.NoError(err)
	require.Equal(Concentrated, pool.Type)
}

func TestPoolStats(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	// Create pool
	reserve0, _ := new(big.Int).SetString("10000000000000000000", 10) // 10 tokens
	reserve1, _ := new(big.Int).SetString("20000000000000000000", 10) // 20 tokens
	pool, err := mgr.CreatePool(
		token0,
		token1,
		reserve0,
		reserve1,
		ConstantProduct,
		30,
	)
	require.NoError(err)

	// Execute some swaps
	for i := 0; i < 5; i++ {
		quote, err := mgr.GetQuote(
			pool.ID,
			pool.Token0,
			big.NewInt(10000000000000000), // 0.01 token
		)
		require.NoError(err)

		_, err = mgr.Swap(
			pool.ID,
			pool.Token0,
			big.NewInt(10000000000000000),
			new(big.Int).Sub(quote, big.NewInt(1000000000000)), // Allow small slippage
		)
		require.NoError(err)
	}

	// Check stats
	fetchedPool, err := mgr.GetPool(pool.ID)
	require.NoError(err)
	require.Equal(uint64(5), fetchedPool.TxCount)
	require.True(fetchedPool.Volume0.Sign() > 0)
}

func TestInvalidSwapToken(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()
	invalidToken := ids.GenerateTestID()

	// Create pool
	pool, err := mgr.CreatePool(
		token0,
		token1,
		big.NewInt(1000000000000000000),
		big.NewInt(2000000000000000000),
		ConstantProduct,
		30,
	)
	require.NoError(err)

	// Try to swap with invalid token
	_, err = mgr.Swap(
		pool.ID,
		invalidToken,
		big.NewInt(100000000000000000),
		big.NewInt(1),
	)
	require.Error(err)
}

func TestPoolNotFound(t *testing.T) {
	require := require.New(t)

	mgr := NewManager()

	fakePoolID := ids.GenerateTestID()

	_, err := mgr.GetPool(fakePoolID)
	require.Error(err)
	require.Equal(ErrPoolNotFound, err)

	_, err = mgr.Swap(
		fakePoolID,
		ids.GenerateTestID(),
		big.NewInt(100000000000000000),
		big.NewInt(1),
	)
	require.Error(err)
	require.Equal(ErrPoolNotFound, err)
}

func BenchmarkSwap(b *testing.B) {
	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	reserve0, _ := new(big.Int).SetString("100000000000000000000", 10) // 100 tokens
	reserve1, _ := new(big.Int).SetString("200000000000000000000", 10) // 200 tokens
	pool, _ := mgr.CreatePool(
		token0,
		token1,
		reserve0,
		reserve1,
		ConstantProduct,
		30,
	)

	amountIn := big.NewInt(1000000000000000) // 0.001 token

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		quote, _ := mgr.GetQuote(pool.ID, pool.Token0, amountIn)
		mgr.Swap(pool.ID, pool.Token0, amountIn, new(big.Int).Sub(quote, big.NewInt(10000000000000)))
	}
}

func BenchmarkGetQuote(b *testing.B) {
	mgr := NewManager()

	token0 := ids.GenerateTestID()
	token1 := ids.GenerateTestID()

	reserve0, _ := new(big.Int).SetString("100000000000000000000", 10)
	reserve1, _ := new(big.Int).SetString("200000000000000000000", 10)
	pool, _ := mgr.CreatePool(
		token0,
		token1,
		reserve0,
		reserve1,
		ConstantProduct,
		30,
	)

	amountIn := big.NewInt(1000000000000000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.GetQuote(pool.ID, pool.Token0, amountIn)
	}
}
