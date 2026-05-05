// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dexvm implements a high-performance decentralized exchange VM
// for the Lux blockchain network.
//
// The DEX VM provides:
//   - Central Limit Order Book (CLOB) trading with nanosecond price updates
//   - Automated Market Maker (AMM) liquidity pools
//   - Cross-chain atomic swaps via Warp messaging
//   - 200ms block times for high-frequency trading
//   - LX-First arbitrage strategy support
//
// Architecture:
//   - Uses Quasar consensus (BLS + Ringtail + ML-DSA) for finality
//   - Integrates with Warp 1.5 for cross-chain messaging
//   - Supports both spot and perpetual trading
//   - Designed for institutional-grade performance
package dexvm

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/chains/dexvm/config"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var (
	// VMID is the unique identifier for the DEX VM
	VMID = ids.ID{'d', 'e', 'x', 'v', 'm'}

	_ vms.Factory = (*Factory)(nil)
)

// Factory creates new DEX VM instances.
type Factory struct {
	config.Config
}

// New implements vms.Factory interface.
// It creates a new DEX ChainVM instance with the factory's configuration.
// The ChainVM wrapper implements block.ChainVM for integration with the chains manager.
// Allocates a per-VM GPU session at PriorityHigh because the DEX hot path
// is latency-critical (1ms block times).
func (f *Factory) New(logger log.Logger) (interface{}, error) {
	sess, err := accel.NewVMSession("dexvm", accel.WithPriority(accel.PriorityHigh))
	if err != nil {
		return nil, err
	}

	// Create the ChainVM wrapper which implements block.ChainVM
	chainVM := NewChainVM(logger)
	// Apply factory config to inner VM
	chainVM.inner.Config = f.Config
	chainVM.inner.accel = sess
	return chainVM, nil
}
