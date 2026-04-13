// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package config defines configuration types for the DEX VM.
package config

import (
	"time"

	"github.com/luxfi/ids"
)

// Config contains configuration parameters for the DEX VM.
type Config struct {
	// IndexAllowIncomplete enables indexing of incomplete blocks
	IndexAllowIncomplete bool `json:"indexAllowIncomplete"`
	// IndexTransactions enables transaction indexing
	IndexTransactions bool `json:"indexTransactions"`
	// ChecksumsEnabled enables merkle checksum verification
	ChecksumsEnabled bool `json:"checksumsEnabled"`

	// DEX-specific configuration

	// DefaultSwapFeeBps is the default swap fee in basis points (100 = 1%)
	DefaultSwapFeeBps uint16 `json:"defaultSwapFeeBps"`
	// ProtocolFeeBps is the protocol fee in basis points
	ProtocolFeeBps uint16 `json:"protocolFeeBps"`
	// MaxSlippageBps is the maximum allowed slippage in basis points
	MaxSlippageBps uint16 `json:"maxSlippageBps"`

	// MinLiquidity is the minimum liquidity required for a pool
	MinLiquidity uint64 `json:"minLiquidity"`
	// MaxPoolsPerPair is the maximum number of pools allowed per token pair
	MaxPoolsPerPair uint16 `json:"maxPoolsPerPair"`

	// OrderbookConfig
	MaxOrdersPerAccount uint32        `json:"maxOrdersPerAccount"`
	MaxOrderSize        uint64        `json:"maxOrderSize"`
	MinOrderSize        uint64        `json:"minOrderSize"`
	OrderExpirationTime time.Duration `json:"orderExpirationTime"`

	// Cross-chain configuration
	WarpEnabled     bool     `json:"warpEnabled"`
	TeleportEnabled bool     `json:"teleportEnabled"`
	TrustedChains   []ids.ID `json:"trustedChains"`

	// Block configuration
	BlockInterval  time.Duration `json:"blockInterval"`
	MaxBlockSize   uint64        `json:"maxBlockSize"`
	MaxTxsPerBlock uint32        `json:"maxTxsPerBlock"`
}

// DefaultConfig returns the default configuration for the DEX VM.
func DefaultConfig() Config {
	return Config{
		IndexAllowIncomplete: false,
		IndexTransactions:    true,
		ChecksumsEnabled:     true,

		DefaultSwapFeeBps: 30,  // 0.3%
		ProtocolFeeBps:    5,   // 0.05%
		MaxSlippageBps:    100, // 1%

		MinLiquidity:    1000,
		MaxPoolsPerPair: 10,

		MaxOrdersPerAccount: 1000,
		MaxOrderSize:        1_000_000_000_000_000_000, // 1e18
		MinOrderSize:        1000,
		OrderExpirationTime: 24 * time.Hour,

		WarpEnabled:     true,
		TeleportEnabled: true,
		TrustedChains:   nil,

		BlockInterval:  1 * time.Millisecond, // 1ms blocks for HFT (ultra-low latency)
		MaxBlockSize:   2 * 1024 * 1024,      // 2MB
		MaxTxsPerBlock: 10000,
	}
}
