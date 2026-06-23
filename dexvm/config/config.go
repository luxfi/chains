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
	// CONSENSUS-SAFETY (STRICTER than DexZapEndpoint): this value participates in the
	// DETERMINISTIC settle decision — verifyFillAttestation gates trustCarried, which
	// decides whether a block's carried fills are consumed into escrow + export legs, which
	// feeds computeStateRoot. So it is recomputed inside the consensus state-transition and
	// MUST be a SINGLE network-pinned constant, IDENTICAL on every validator. This is a
	// STRONGER invariant than DexZapEndpoint's: DexZapEndpoint is a node-local TRANSPORT
	// address used only at the proposer's build (obtainFills) and is NOT recomputed in the
	// deterministic settle path, so two validators may legitimately point at distinct local
	// gateways. FillAttestationPubKey may NOT vary: if validators disagreed on it they would
	// reach different trust decisions for the same block and FORK the StateRoot. It is
	// therefore pinned in GENESIS (vm.go Genesis.FillAttestationPubKey, assigned ONLY in
	// parseGenesis) and is DELIBERATELY absent from parseConfig — runtime per-node config
	// cannot set it. Distribute it as a network-upgrade-pinned constant (the same lockstep
	// discipline as the carried-fills wire format), never per-node ad hoc.
	FillAttestationPubKey []byte `json:"fillAttestationPubKey,omitempty"`

	// FillAttestationSeed is the venue's Ed25519 SIGNING seed (32 bytes), set ONLY on a
	// node that is co-located with the venue and therefore authoritative to ATTEST the
	// fills it relayed (the single-operator deployment). When set, the proposer signs the
	// carried fills at build so the block carries a valid attestation. It is a SECRET and
	// MUST come from KMS, never a plaintext manifest. Empty on a pure validator (it only
	// VERIFIES, using FillAttestationPubKey).
	FillAttestationSeed []byte `json:"-"`

	// --- Real-assets-only enforcement (Gate A, the green-first gate) ----------
	//
	// Every field's SAFE value is its zero value, so a zero-initialised config is the
	// locked-down config. These are BACKEND-enforced at VM Initialize by the registry
	// startup gate (registry.RefuseUnderSyntheticConfig + registry.GuardValueActivation):
	// a front end cannot relax them, and a value-bearing network (mainnet/testnet) hard-
	// fails startup if any synthetic flag is set or value is activated without a legal
	// consensus mode. They are documented here and consumed ONLY in Initialize.

	// DexAllowSyntheticAssets / DexAllowSyntheticMarkets / DexAllowMockLiquidity default
	// false. true is permitted ONLY on a dev/local network (developer opt-in); on
	// mainnet or testnet any true value FAILS startup (ErrSyntheticOnValueNet). The
	// Liquidity / phantom / ASCII-ticker deny-scan runs on EVERY network regardless.
	DexAllowSyntheticAssets  bool `json:"dexAllowSyntheticAssets"`
	DexAllowSyntheticMarkets bool `json:"dexAllowSyntheticMarkets"`
	DexAllowMockLiquidity    bool `json:"dexAllowMockLiquidity"`

	// DexAllowedAssetKinds is the active allowed-kind policy as canonical tokens
	// ("EVM_NATIVE","ERC20","UTXO"). Empty => the canonical default of all three. A
	// configured set may only ever be a SUBSET of those three; any other token (an
	// ASCII ticker, a "D_NATIVE", etc.) FAILS startup (ErrBadAllowedKind).
	DexAllowedAssetKinds []string `json:"dexAllowedAssetKinds"`

	// DexNativeValueEnabled gates real-money (native value) trading. Default false =
	// paper/non-value mode (no value to authorise). When true, the consensus-mode value
	// guard runs and REFUSES startup unless DexConsensusMode is one of exactly two legal
	// value modes (see DexConsensusMode).
	DexNativeValueEnabled bool `json:"dexNativeValueEnabled"`

	// DexConsensusMode is the consensus posture under which native value may activate.
	// Exactly two legal value modes: "QUORUM_FINALITY" (post-quantum BFT) or
	// "HONEST_VALIDATOR_LABELED" (labeled CFT parity). Empty/"UNSET" with value enabled
	// REFUSES startup; any unknown token REFUSES startup. There is never a silent third
	// state.
	DexConsensusMode string `json:"dexConsensusMode"`

	// DexCapsOn / DexHaltReady are the operator-attested compensating controls required
	// to activate value under HONEST_VALIDATOR_LABELED. The third leg of the launch
	// bundle (real-assets-only) is NOT operator-attested — it is MACHINE-DERIVED from the
	// registry being real and no synthetic flag being set, so the operator cannot lie
	// about it. Both default false; under HONEST_VALIDATOR_LABELED either being false
	// REFUSES value activation (ErrLaunchAssertionsUnmet).
	DexCapsOn    bool `json:"dexCapsOn"`
	DexHaltReady bool `json:"dexHaltReady"`

	// DexAssetManifestPath optionally points at the per-network real-assets manifest
	// (assets.{devnet,testnet,mainnet}.json). When set, the manifest is loaded, its
	// declared C-Chain / X-Chain identity is bound to the node's ACTUAL running chain
	// ids (RuntimeVerifier — a real check, not a stub), its assets/markets are admitted
	// into the registry, and the fail-closed startup gate runs over them. Per-token
	// existence on the live net (code>0, decimals(), UTXO assetID) is proven by CI
	// against the target net's RPC BEFORE the artifact ships — the node binds identity +
	// enforces policy; CI proves reality. Empty + DexNativeValueEnabled=true FAILS
	// startup (you cannot activate value with no declared real assets).
	DexAssetManifestPath string `json:"dexAssetManifestPath"`

	// DexAssetManifestSHA256 PINS the manifest to its CI-approved artifact by content hash
	// (M1). When set (a 32-byte SHA-256 in hex, optional "0x"/"sha256:" prefix), the node
	// REFUSES to load a manifest whose bytes do not hash to this value — an edited local
	// manifest (a fabricated token address, an added asset) no longer matches and fails
	// startup. The dexvm proxy holds NO EVM state and cannot eth_getCode the tokens itself,
	// so this content-hash binding is what stops a tampered manifest from loading; pair it
	// with the CI validate-asset-manifests workflow that proves the pinned artifact real and
	// emits this hash. Empty = no pin (shape validation only) — set it in genesis/config for
	// any value-bearing deployment.
	DexAssetManifestSHA256 string `json:"dexAssetManifestSHA256"`

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
