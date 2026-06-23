// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luxfi/ids"
)

// manifest_pin_test.go is the M1 proof: a manifest is bound to its CI-approved artifact by a
// pinned content SHA-256. An edited local manifest (a fabricated token address, an added
// asset) no longer hashes to the pin and is REFUSED — the dexvm proxy holds no EVM state, so
// the content-hash is what stops a tampered manifest from loading.

// writePinManifest writes a minimal real manifest and returns (path, sha256-hex).
func writePinManifest(t *testing.T, networkID uint32, cChain ids.ID, erc20 []byte) (string, string) {
	t.Helper()
	m := Manifest{
		Network:    "mainnet",
		NetworkID:  networkID,
		EVMChainID: 96369,
		CChainID:   cChain,
		Assets: []Asset{
			{NetworkID: networkID, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: erc20, Decimals: 18, Symbol: "WLUX", Name: "Wrapped LUX", Enabled: true, RiskTier: RiskTier0},
		},
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "assets.mainnet.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sum := sha256.Sum256(b)
	return path, hex.EncodeToString(sum[:])
}

// TestM1_PinnedManifest_MatchingHashLoads proves the happy path: a manifest whose content
// matches the pinned hash loads.
func TestM1_PinnedManifest_MatchingHashLoads(t *testing.T) {
	cChain := ids.GenerateTestID()
	path, sum := writePinManifest(t, 1, cChain, addr20(0x4a))

	m, err := LoadManifestPinned(path, sum)
	if err != nil {
		t.Fatalf("a manifest matching its pinned hash must load: %v", err)
	}
	if len(m.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(m.Assets))
	}

	// The pin accepts the common "0x" and "sha256:" prefixes too.
	if _, err := LoadManifestPinned(path, "0x"+sum); err != nil {
		t.Fatalf("0x-prefixed pin must load: %v", err)
	}
	if _, err := LoadManifestPinned(path, "sha256:"+strings.ToUpper(sum)); err != nil {
		t.Fatalf("sha256:-prefixed uppercase pin must load: %v", err)
	}
}

// TestM1_EditedManifest_FabricatedAddress_Rejected is the decisive proof: after pinning the
// CI-approved manifest's hash, an attacker EDITS the file to point an asset at a fabricated
// token address. The edited file no longer hashes to the pin, so the node REFUSES it.
func TestM1_EditedManifest_FabricatedAddress_Rejected(t *testing.T) {
	cChain := ids.GenerateTestID()
	path, ciApprovedHash := writePinManifest(t, 1, cChain, addr20(0x4a))

	// Attacker rewrites the manifest in place, swapping the real token for a fabricated
	// address (and it is still structurally valid, so shape validation alone would pass).
	tampered := Manifest{
		Network:    "mainnet",
		NetworkID:  1,
		EVMChainID: 96369,
		CChainID:   cChain,
		Assets: []Asset{
			{NetworkID: 1, ChainID: cChain, Kind: AssetKindERC20, CanonicalRef: addr20(0xEE) /* fabricated */, Decimals: 18, Symbol: "WLUX", Name: "Wrapped LUX", Enabled: true, RiskTier: RiskTier0},
		},
	}
	b, _ := json.MarshalIndent(tampered, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	// Loading WITHOUT a pin would accept the tampered file (shape is valid) — proving the
	// shape check alone is insufficient.
	if _, err := LoadManifest(path); err != nil {
		t.Fatalf("sanity: the tampered file is still structurally valid (shape passes): %v", err)
	}
	// Loading WITH the CI-approved pin REFUSES it (content hash no longer matches).
	if _, err := LoadManifestPinned(path, ciApprovedHash); !errors.Is(err, ErrManifestHashMismatch) {
		t.Fatalf("an edited manifest must be refused against the pinned hash (ErrManifestHashMismatch), got: %v", err)
	}
}

// TestM1_MalformedPin_FailsClosed proves a malformed expected hash is itself refused (you
// cannot pin against garbage).
func TestM1_MalformedPin_FailsClosed(t *testing.T) {
	cChain := ids.GenerateTestID()
	path, _ := writePinManifest(t, 1, cChain, addr20(0x4a))

	for _, bad := range []string{"deadbeef" /* too short */, strings.Repeat("zz", 32) /* non-hex */} {
		if _, err := LoadManifestPinned(path, bad); err == nil {
			t.Fatalf("a malformed pin %q must fail closed", bad)
		}
	}
}

// TestM1_EmptyPin_FallsBackToShapeOnly proves pinning is opt-in: an empty pin loads with
// shape validation only (no hash binding), preserving the unpinned path.
func TestM1_EmptyPin_FallsBackToShapeOnly(t *testing.T) {
	cChain := ids.GenerateTestID()
	path, _ := writePinManifest(t, 1, cChain, addr20(0x4a))
	if _, err := LoadManifestPinned(path, ""); err != nil {
		t.Fatalf("an empty pin must fall back to shape-only load: %v", err)
	}
}
