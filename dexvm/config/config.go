// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package config defines configuration types for the DEX VM — a STATELESS
// ATOMIC ZAP PROXY. The proxy holds NO embedded-AMM configuration (no swap
// fees, pools, or order sizing): matching + DEX state live ONLY on the d-chain,
// reached over ZAP. This config covers transport (the d-chain ZAP endpoint),
// the optional Warp attestation channel, and block cadence.
package config

import (
	"time"

	"github.com/luxfi/ids"
)

// Config contains configuration parameters for the DEX VM proxy.
type Config struct {
	// IndexAllowIncomplete enables indexing of incomplete blocks
	IndexAllowIncomplete bool `json:"indexAllowIncomplete"`
	// IndexTransactions enables transaction indexing
	IndexTransactions bool `json:"indexTransactions"`
	// ChecksumsEnabled enables merkle checksum verification
	ChecksumsEnabled bool `json:"checksumsEnabled"`

	// DexZapEndpoint is the node-local, version-pinned ZAP address of the
	// d-chain's CLOB gateway (e.g. "127.0.0.1:9100"). The proxy forwards
	// byte-identical clob_* frames here. Empty = the relay leg is inert (the
	// proxy still settles via atomic import/export but has no matcher to relay
	// to). MUST be node-local + version-pinned so every validator's proxy and
	// its single-source-of-truth d-chain are byte-identical (consensus-safety).
	DexZapEndpoint string `json:"dexZapEndpoint"`
	// DexZapTimeout bounds a single ZAP relay round-trip.
	DexZapTimeout time.Duration `json:"dexZapTimeout"`

	// Cross-chain configuration. Warp is retained ONLY as the optional
	// fill-attestation / fraud-proof channel — it is NOT the settlement
	// primitive (atomic SharedMemory import/export is). TrustedChains gates
	// which chains may submit attestations.
	WarpEnabled   bool     `json:"warpEnabled"`
	TrustedChains []ids.ID `json:"trustedChains"`

	// Block configuration
	BlockInterval  time.Duration `json:"blockInterval"`
	MaxBlockSize   uint64        `json:"maxBlockSize"`
	MaxTxsPerBlock uint32        `json:"maxTxsPerBlock"`
}

// DefaultConfig returns the default configuration for the DEX VM proxy.
func DefaultConfig() Config {
	return Config{
		IndexAllowIncomplete: false,
		IndexTransactions:    true,
		ChecksumsEnabled:     true,

		// Empty by default: the proxy is inert on the relay leg until the venue
		// operator points it at a d-chain gateway.
		DexZapEndpoint: "",
		DexZapTimeout:  5 * time.Second,

		// Attestation channel off by default; the venue enables it explicitly.
		WarpEnabled:   false,
		TrustedChains: nil,

		BlockInterval:  1 * time.Millisecond, // 1ms blocks for HFT (ultra-low latency)
		MaxBlockSize:   2 * 1024 * 1024,      // 2MB
		MaxTxsPerBlock: 10000,
	}
}
