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

	// FillAttestationPubKey is the venue's (d-chain matcher's) Ed25519 PUBLIC key. When
	// set (non-empty, 32 bytes) it ENABLES fill-attestation enforcement: every validator
	// verifies the carried-fills signature against this key over the canonical
	// (blockHash, entries) message BEFORE settling, so a malicious/MITM proposer cannot
	// settle FABRICATED fills (the single-proposer trust gap). A block whose carried fills
	// lack a valid attestation is settled as a FULL REFUND (fail-secure). Empty = no
	// enforcement (single-trusted-operator / dev) — the documented interim model. This is
	// the canonical setting for an UNTRUSTED validator set (default-on once set).
	//
	// CONSENSUS-SAFETY: this value participates in the deterministic settle decision
	// (whether a block's carried fills are trusted), so it MUST be IDENTICAL on every
	// validator — exactly like DexZapEndpoint must be node-local + version-pinned. If
	// validators disagreed on this key, they would reach different trust decisions for the
	// same block and the network would FORK on the settlement path. Distribute it as a
	// network-upgrade-pinned constant (the same lockstep discipline as the carried-fills
	// wire format), never per-node ad hoc.
	FillAttestationPubKey []byte `json:"fillAttestationPubKey,omitempty"`

	// FillAttestationSeed is the venue's Ed25519 SIGNING seed (32 bytes), set ONLY on a
	// node that is co-located with the venue and therefore authoritative to ATTEST the
	// fills it relayed (the single-operator deployment). When set, the proposer signs the
	// carried fills at build so the block carries a valid attestation. It is a SECRET and
	// MUST come from KMS, never a plaintext manifest. Empty on a pure validator (it only
	// VERIFIES, using FillAttestationPubKey).
	FillAttestationSeed []byte `json:"-"`

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
