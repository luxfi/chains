// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/luxfi/ids"
)

// Manifest is the on-disk, per-network declaration of the REAL assets and markets
// the DEX admits on that network. There is exactly one manifest per network
// (assets.devnet.json, assets.testnet.json, assets.mainnet.json). Every entry must
// be real on the named network; CI proves this against the network's RPC before
// any deploy, and the node re-proves it (or trusts the CI-validated artifact and
// re-runs the deny-scan) at startup.
//
// The manifest is the SINGLE source of truth for what trades. It does not carry the
// derived AssetIDs/MarketIDs — those are computed from the canonical fields so the
// file cannot disagree with the identity.
type Manifest struct {
	// Network is the canonical network name this manifest applies to. It must match
	// the deploy target; a mismatch is a hard error (you cannot ship the testnet
	// manifest to mainnet).
	Network string `json:"network"`
	// NetworkID is the Lux networkID (1 mainnet, 2 testnet, ...) every asset/market
	// in this manifest must declare. A per-entry networkID that disagrees is rejected.
	NetworkID uint32 `json:"networkID"`
	// EVMChainID is the C-Chain's EVM chainID (eth_chainId): 96369 mainnet, 96368
	// testnet, 96370 devnet, 1337 localnet. It is the AUTHORITATIVE, RPC-checkable
	// identity of the C-Chain — the CI validator confirms the target RPC's
	// eth_chainId equals this before admitting any ERC-20/native entry, so a manifest
	// can never be validated against the wrong chain.
	EVMChainID uint64 `json:"evmChainID"`
	// CChainID is the canonical C-Chain CONSENSUS id (the P-Chain blockchain id, an
	// ids.ID) used in the AssetID preimage so a derived AssetID lives in the same
	// identity space as the on-chain atomic objects. It is network-specific and is
	// confirmed by the CI validator against the live P-Chain (platform.getBlockchains)
	// — the validator REFUSES to proceed if the manifest's CChainID is not the C-Chain
	// the target net actually runs. EVM_NATIVE/ERC20 entries are rooted here; an entry
	// whose chainID disagrees is rejected (so a manifest cannot point an "ERC20" at a
	// non-C chain).
	CChainID ids.ID `json:"cChainID"`
	// ChainLabels maps a source chain id (hex) to its human label, consumed by the
	// forbidden-reference deny-scan (so the off-network-universe check has labels to
	// test). Optional; an unlabeled chain simply has no white-label name to match.
	ChainLabels map[string]string `json:"chainLabels,omitempty"`
	// Assets and Markets are the declared real entries.
	Assets  []Asset  `json:"assets"`
	Markets []Market `json:"markets"`
}

// LoadManifest reads and JSON-decodes a manifest file. It does NOT verify against
// chain state (that is ApplyTo, which needs a verifier) — it only parses and
// structurally validates the shape. A malformed kind/ref/tier fails here.
func LoadManifest(path string) (*Manifest, error) {
	m, _, err := loadManifestBytes(path)
	return m, err
}

// loadManifestBytes reads a manifest file from disk and decodes it via the shared
// decoder. The content-hash is over the EXACT file bytes the node read, so a pinned-hash
// check binds the loaded manifest to the CI-approved artifact byte-for-byte.
func loadManifestBytes(path string) (*Manifest, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("manifest: read %s: %w", path, err)
	}
	return decodeManifestBytes(raw, path)
}

// decodeManifestBytes content-hashes and JSON-decodes raw manifest bytes (from a file or
// from the embedded FS), returning the parsed manifest and the bytes' SHA-256 (lowercase
// hex). It is the SINGLE manifest decoder — disk loads and embedded loads share it so the
// shape-validation, unknown-field rejection, and content-hash discipline are identical for
// both. label is used only for error context (a path or an embed name).
func decodeManifestBytes(raw []byte, label string) (*Manifest, string, error) {
	sum := sha256.Sum256(raw)
	hexSum := hex.EncodeToString(sum[:])
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // a typo'd field (e.g. "asssets") fails closed
	if err := dec.Decode(&m); err != nil {
		return nil, hexSum, fmt.Errorf("manifest: decode %s: %w", label, err)
	}
	if err := m.validateShape(); err != nil {
		return nil, hexSum, fmt.Errorf("manifest %s: %w", label, err)
	}
	return &m, hexSum, nil
}

// ErrManifestHashMismatch is returned when a manifest's actual content SHA-256 does not
// equal the pinned expected hash — the file was edited (a fabricated address, an extra
// asset) away from the CI-approved artifact. Fail-closed: the node refuses to load it.
var ErrManifestHashMismatch = errors.New("registry: manifest content hash does not match the pinned expected hash (the file was modified from the CI-approved artifact)")

// LoadManifestPinned reads a manifest and REFUSES it unless its content SHA-256 equals
// expectedSHA256 (lowercase hex, with or without a "0x"/"sha256:" prefix). This is the M1
// fix: a node verifies the manifest it loads is BYTE-IDENTICAL to the artifact CI approved
// and pinned in genesis/config — the dexvm proxy holds NO EVM state, so it cannot
// eth_getCode the tokens itself; the content-hash binding is what stops a locally edited
// manifest (a fabricated token address) from being loaded.
//
// An empty expectedSHA256 means "no pin configured" and falls back to LoadManifest (shape
// validation only) — pinning is opt-in per deployment, but once a hash is set the file must
// match it exactly. A malformed expected hash is itself an error (fail-closed).
func LoadManifestPinned(path, expectedSHA256 string) (*Manifest, error) {
	if expectedSHA256 == "" {
		return LoadManifest(path)
	}
	want, err := normalizeSHA256(expectedSHA256)
	if err != nil {
		return nil, err
	}
	m, got, err := loadManifestBytes(path)
	if err != nil {
		return nil, err
	}
	if got != want {
		return nil, fmt.Errorf("%w (path=%s want=%s got=%s)", ErrManifestHashMismatch, path, want, got)
	}
	return m, nil
}

// normalizeSHA256 lowercases and strips an optional "0x" or "sha256:" prefix, then checks
// the value is a 64-hex-char (32-byte) digest. A non-conforming value fails closed (you
// cannot pin against a malformed hash).
func normalizeSHA256(h string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(h))
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 64 {
		return "", fmt.Errorf("registry: pinned manifest hash must be a 32-byte SHA-256 (64 hex chars), got %d chars", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("registry: pinned manifest hash is not valid hex: %w", err)
	}
	return s, nil
}

// validateShape checks the manifest is internally consistent before any chain I/O:
// network name present, every asset/market on the manifest's network, every C-Chain
// asset rooted at the manifest's CChainID, and every asset/market structurally valid.
func (m *Manifest) validateShape() error {
	if m.Network == "" {
		return fmt.Errorf("manifest: empty network name")
	}
	if m.NetworkID == 0 {
		return fmt.Errorf("manifest: networkID must be non-zero")
	}
	if m.EVMChainID == 0 {
		return fmt.Errorf("manifest: evmChainID must be non-zero (the RPC-checkable C-Chain identity)")
	}
	if m.CChainID == ids.Empty {
		return fmt.Errorf("manifest: cChainID must be set (the C-Chain consensus id)")
	}
	for i, a := range m.Assets {
		if a.NetworkID != m.NetworkID {
			return fmt.Errorf("manifest: asset[%d] networkID %d != manifest networkID %d", i, a.NetworkID, m.NetworkID)
		}
		switch a.Kind {
		case AssetKindEVMNative, AssetKindERC20:
			if a.ChainID != m.CChainID {
				return fmt.Errorf("manifest: asset[%d] (%s) chainID must be the C-Chain %s, got %s", i, a.Kind, m.CChainID, a.ChainID)
			}
		case AssetKindUTXO:
			// UTXO assets are rooted at a UTXO source chain (X-Chain), not the C-Chain.
		default:
			return fmt.Errorf("manifest: asset[%d] invalid kind", i)
		}
		if err := a.validateShape(); err != nil {
			return fmt.Errorf("manifest: asset[%d]: %w", i, err)
		}
	}
	for i, mk := range m.Markets {
		if mk.NetworkID != m.NetworkID {
			return fmt.Errorf("manifest: market[%d] networkID %d != manifest networkID %d", i, mk.NetworkID, m.NetworkID)
		}
	}
	return nil
}

// chainLabelFor returns the deny-scan label function for this manifest's declared
// chain labels.
func (m *Manifest) chainLabelFor() func(ids.ID) string {
	return func(id ids.ID) string {
		if m.ChainLabels == nil {
			return ""
		}
		return m.ChainLabels[id.Hex()]
	}
}

// ChainLabelFor is the exported deny-scan label function for this manifest, used by the
// node startup gate to run the off-network-universe / forbidden-reference scan with the
// manifest's declared chain labels.
func (m *Manifest) ChainLabelFor() func(ids.ID) string { return m.chainLabelFor() }

// CChainConfirmer is the optional manifest-level check a verifier may implement to
// confirm, before any asset lookup, that the C-Chain it is talking to is the one the
// manifest declares: the live eth_chainId equals EVMChainID and the live C-Chain
// consensus id equals CChainID. The RPC validator implements it (so a manifest is
// never validated against the wrong chain); a local in-process verifier may not need
// to and can omit it. ApplyTo runs it first when present.
type CChainConfirmer interface {
	ConfirmCChain(networkID uint32, evmChainID uint64, cChainID ids.ID) error
}

// ApplyTo registers every manifest asset and creates every manifest market into reg,
// proving each asset real against v, then runs the fail-closed startup gate for the
// manifest's network class and the given policy. It is the ONE routine that turns a
// manifest into a live, gated registry — used identically by CI (with an RPC
// verifier) and by node startup (with the local-chain verifier).
//
// The order is: confirm the C-Chain identity (if v can), register assets (each
// VerifyOnChain), create markets (each pinned to two registered assets), then
// RefuseUnderSyntheticConfig (the residual deny-scan + enabled-market audit). Any
// failure aborts and is returned; reg is left partially populated only on error
// (callers discard it).
func (m *Manifest) ApplyTo(reg *Registry, v ChainVerifier, policy DexAssetPolicy) error {
	if err := m.AdmitInto(reg, v); err != nil {
		return err
	}
	class := NetworkClassFor(m.NetworkID)
	if err := RefuseUnderSyntheticConfig(class, policy, reg, m.chainLabelFor()); err != nil {
		return fmt.Errorf("manifest %s: startup gate: %w", m.Network, err)
	}
	return nil
}

// AdmitInto registers every manifest asset (each proven real against v) and creates
// every manifest market (each pinned to two registered assets) into reg, WITHOUT running
// the fail-closed startup gate. It is the admission half of ApplyTo, separated so a
// caller that owns the gate (the node, which runs the gate once with its own network
// class + policy) does not run it twice. ApplyTo == AdmitInto + RefuseUnderSyntheticConfig.
func (m *Manifest) AdmitInto(reg *Registry, v ChainVerifier) error {
	if err := m.validateShape(); err != nil {
		return err
	}
	if c, ok := v.(CChainConfirmer); ok {
		if err := c.ConfirmCChain(m.NetworkID, m.EVMChainID, m.CChainID); err != nil {
			return fmt.Errorf("manifest %s: C-Chain identity confirm: %w", m.Network, err)
		}
	}
	for i, a := range m.Assets {
		if _, err := reg.Register(a, v); err != nil {
			return fmt.Errorf("manifest %s: asset[%d] (%s): %w", m.Network, i, a.Kind, err)
		}
	}
	for i, mk := range m.Markets {
		if _, err := reg.CreateMarket(mk); err != nil {
			return fmt.Errorf("manifest %s: market[%d]: %w", m.Network, i, err)
		}
	}
	return nil
}

// Validate is the full CI check for one manifest against one verifier: load is done
// by the caller (LoadManifest); this proves every entry real and gate-clean using a
// fresh registry under the canonical locked-down policy. It returns the populated
// registry so a caller can report what was admitted.
func (m *Manifest) Validate(v ChainVerifier) (*Registry, error) {
	reg := New(AssetKindEVMNative, AssetKindERC20, AssetKindUTXO)
	if err := m.ApplyTo(reg, v, DefaultDexAssetPolicy()); err != nil {
		return nil, err
	}
	return reg, nil
}
