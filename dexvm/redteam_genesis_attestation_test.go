// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build redteam

// redteam_genesis_attestation_test.go — the HIGH proof that the fill-attestation gate is
// REACHABLE IN PRODUCTION, not merely correct in isolation.
//
// The sibling redteam_fill_attestation_test.go drives enforcement by SETTING
// cvm.inner.Config.FillAttestationPubKey directly. That proves the gate LOGIC but NOT the
// production wiring: a real validator never hand-edits Config — it gets its settings from
// the genesis/config bytes the node hands Initialize(). The HIGH finding was exactly that
// FillAttestationPubKey was NEVER written from genesis (parseConfig copies only enumerated
// fields; parseGenesis carried only DexZapEndpoint+TrustedChains), so in prod the pubkey
// was nil -> verifyFillAttestation returned nil -> trustCarried always true -> the
// fabricated-fills guard could NEVER engage, and a malicious/MITM proposer could settle
// fabricated fills and drain a cross-taker's seam reserve.
//
// These tests drive a REAL genesis blob through Initialize -> parseGenesis (NOT a direct
// Config write) and assert:
//
//	(1) the genesis-pinned pubkey lands in Config (the plumbing exists end-to-end);
//	(2) with it pinned, a FABRICATED (unattested) block becomes a FULL REFUND — enforcement
//	    is on by virtue of GENESIS ALONE, no per-node Config touch;
//	(3) a genesis pubkey of the wrong width is a FATAL Initialize error (fail-closed — a
//	    garbage key must never silently degrade to "no enforcement");
//	(4) the pubkey is DELIBERATELY NOT settable via the runtime config blob (it is
//	    consensus-affecting and must be a single genesis-pinned constant — a per-node config
//	    value would fork the StateRoot).

package dexvm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/luxfi/chains/dexvm/config"
	"github.com/luxfi/crypto/ed25519"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/vm"
	"github.com/luxfi/vm/chains/atomic"
	"github.com/luxfi/warp"
)

// newGenesisHarness is newCountingHarness's production-faithful sibling: it hands the VM a
// real genesis JSON (and optional config JSON) blob through Initialize so the settings flow
// through the SAME parseGenesis/parseConfig path a node uses — never a direct Config write.
// It returns initErr instead of failing so a test can assert a fail-closed Initialize.
func newGenesisHarness(t *testing.T, fills []Fill, genesisJSON, configJSON []byte) (*ChainVM, atomic.SharedMemory, ids.ID, ids.ID, error) {
	t.Helper()
	logger := log.NewNoOpLogger()

	baseDB := memdb.New()
	memoryDB := prefixdb.New([]byte{0}, baseDB)
	m := atomic.NewMemory(memoryDB)

	proxyChain := ids.GenerateTestID()
	cChain := ids.GenerateTestID()
	proxySM := m.NewSharedMemory(proxyChain)
	cChainSM := m.NewSharedMemory(cChain)

	matcher := &countingMatcher{fills: fills}
	prev := zapDialer
	zapDialer = func(_ context.Context, _ string) (zapConn, error) { return matcher, nil }
	t.Cleanup(func() { zapDialer = prev })

	rt := &runtime.Runtime{
		ChainID:      proxyChain,
		CChainID:     cChain,
		NetworkID:    96369,
		Log:          logger,
		SharedMemory: proxySM,
	}

	cvm := NewChainVM(logger)
	// Start from the real default config (NOT a hand-set pubkey) so the ONLY way enforcement
	// turns on is the genesis blob below — the production path under test.
	cvm.inner.Config = config.DefaultConfig()
	cvm.inner.Config.DexZapEndpoint = "127.0.0.1:0"

	initErr := cvm.Initialize(context.Background(), vm.Init{
		Runtime:  rt,
		DB:       prefixdb.New([]byte{1}, baseDB),
		ToEngine: make(chan vm.Message, 8),
		Sender:   warp.FakeSender{},
		Log:      logger,
		Genesis:  genesisJSON,
		Config:   configJSON,
	})
	if initErr == nil {
		cvm.inner.bootstrapped = true
	}
	return cvm, cChainSM, proxyChain, cChain, initErr
}

// genesisWithPubKey builds the network genesis blob a node would ship, pinning the venue's
// Ed25519 attestation pubkey (hex) — the single network-wide constant that turns
// enforcement on for an untrusted validator set.
func genesisWithPubKey(pub ed25519.PublicKey) []byte {
	g := struct {
		FillAttestationPubKey string `json:"fillAttestationPubKey"`
	}{FillAttestationPubKey: hex.EncodeToString(pub)}
	b, _ := json.Marshal(g)
	return b
}

// TestRED_GenesisAttestation_PubKeyReachesConfig proves the plumbing the HIGH finding said
// was missing: a genesis blob carrying fillAttestationPubKey actually lands in Config after
// Initialize, so verifyFillAttestation can see it. Before the fix this asserted-on field
// was always nil because nothing copied it out of genesis.
func TestRED_GenesisAttestation_PubKeyReachesConfig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cvm, _, _, _, initErr := newGenesisHarness(t, nil, genesisWithPubKey(pub), nil)
	if initErr != nil {
		t.Fatalf("Initialize with a valid genesis pubkey must succeed, got: %v", initErr)
	}
	got := cvm.inner.Config.FillAttestationPubKey
	if len(got) != ed25519.PublicKeySize {
		t.Fatalf("genesis-pinned pubkey did not reach Config: got %d bytes, want %d "+
			"(the HIGH inert-gate bug — fillAttestationPubKey never plumbed through genesis)",
			len(got), ed25519.PublicKeySize)
	}
	if string(got) != string(pub) {
		t.Fatalf("genesis-pinned pubkey mismatch: Config holds a different key than the genesis blob")
	}
	// And the gate is now LIVE: verify rejects a missing signature (enforcement on).
	bh := ids.GenerateTestID()
	entries := []carriedFill{{txIndex: 0, fills: []Fill{{Price: 2, Size: 100, Side: 0}}}}
	if verr := verifyFillAttestation(cvm.inner.Config.FillAttestationPubKey, nil, bh, entries); verr != ErrFillAttestationRequired {
		t.Fatalf("with a genesis-pinned pubkey the gate must REQUIRE a signature, got: %v", verr)
	}
	t.Logf("PLUMBING OK: genesis fillAttestationPubKey -> Config -> enforcement live")
}

// TestRED_GenesisAttestation_FabricatedBlockFullRefund is the decisive end-to-end proof:
// enforcement is turned on SOLELY by the genesis blob (no Config touch), and a proposer that
// carries FABRICATED fills it cannot attest (it holds no signing seed) produces a block whose
// every settle is a FULL REFUND — no fabricated proceeds move, so the cross-taker
// seam-reserve drain the HIGH finding describes is impossible.
func TestRED_GenesisAttestation_FabricatedBlockFullRefund(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// A proposer carries a FABRICATED fill (200 base) but cannot attest it (no seed in any
	// config). Enforcement is on ONLY because the genesis blob pinned the pubkey.
	fills := []Fill{{Price: 2, Size: 200, Side: 0}}
	cvm, cChainSM, proxyChain, _, initErr := newGenesisHarness(t, fills, genesisWithPubKey(pub), nil)
	if initErr != nil {
		t.Fatalf("Initialize: %v", initErr)
	}
	// Belt-and-suspenders: prove we did NOT hand-set the pubkey — it came from genesis.
	if len(cvm.inner.Config.FillAttestationPubKey) != ed25519.PublicKeySize {
		t.Fatalf("precondition: enforcement must be on via genesis, but Config pubkey is unset")
	}
	if len(cvm.inner.Config.FillAttestationSeed) != 0 {
		t.Fatalf("precondition: the fabricating proposer must hold NO signing seed")
	}
	ctx := context.Background()

	taker := ids.GenerateTestShortID()
	quoteAsset := ids.GenerateTestID()
	baseAsset := ids.GenerateTestID()
	const lockedQuote uint64 = 1000

	srcUTXOID := seedExportedUTXO(t, cChainSM, proxyChain, taker, quoteAsset, lockedQuote)
	importTx := newImportTxBytes(t, taker, cvm.inner.cChainID(), srcUTXOID, quoteAsset, lockedQuote)
	relayTx := newSettlingRelayTxBytes(t, taker, srcUTXOID, baseAsset, clobSubmitPayload(quoteAsset, lockedQuote), 0, false)

	cvm.inner.clock.Set(time.Unix(1, 0))
	cvm.pendingTxs = [][]byte{importTx, relayTx}
	built, err := cvm.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock: %v", err)
	}
	if err := cvm.SetPreference(ctx, built.ID()); err != nil {
		t.Fatalf("SetPreference: %v", err)
	}
	if err := built.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := built.Accept(ctx); err != nil {
		t.Fatalf("accept: %v", err)
	}

	legs := exportedLegsByAsset(t, cChainSM, proxyChain, taker)
	t.Logf("AFTER GENESIS-GATED UNATTESTED BLOCK: base proceeds=%d quote refund=%d", legs[baseAsset], legs[quoteAsset])
	if legs[baseAsset] != 0 {
		t.Fatalf("FABRICATED FILL SETTLED under a genesis-pinned key: %d base proceeds moved — the gate is "+
			"still inert in the production path.", legs[baseAsset])
	}
	if legs[quoteAsset] != lockedQuote {
		t.Fatalf("fail-secure refund broken: quote refund=%d, want the full locked %d.", legs[quoteAsset], lockedQuote)
	}
}

// TestRED_GenesisAttestation_WrongWidthPubKeyFailsClosed proves a malformed genesis pubkey
// is a FATAL Initialize error, not a silent fallback to "no enforcement". A garbage key that
// parsed to "off" would re-open the fabricated-fills gap on a network that BELIEVED it had
// enforcement on.
func TestRED_GenesisAttestation_WrongWidthPubKeyFailsClosed(t *testing.T) {
	bad := struct {
		FillAttestationPubKey string `json:"fillAttestationPubKey"`
	}{FillAttestationPubKey: hex.EncodeToString([]byte{1, 2, 3, 4})} // 4 bytes, not 32
	blob, _ := json.Marshal(bad)
	_, _, _, _, initErr := newGenesisHarness(t, nil, blob, nil)
	if initErr == nil {
		t.Fatalf("a wrong-width genesis fillAttestationPubKey must FAIL Initialize (fail-closed), but it succeeded")
	}
	t.Logf("FAIL-CLOSED OK: malformed genesis pubkey rejected at Initialize: %v", initErr)
}

// TestRED_GenesisAttestation_NotSettableViaRuntimeConfig proves the consensus-affecting
// invariant: the pubkey is GENESIS-pinned and parseConfig DELIBERATELY does not read it, so a
// per-node runtime config blob cannot set (or vary) it. If it could, two validators with
// different config would reach different trust decisions for the same block and FORK the
// StateRoot.
func TestRED_GenesisAttestation_NotSettableViaRuntimeConfig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// Put the pubkey in the runtime CONFIG blob (not genesis). parseConfig must ignore it.
	cfg := struct {
		FillAttestationPubKey []byte `json:"fillAttestationPubKey"`
	}{FillAttestationPubKey: pub}
	cfgBlob, _ := json.Marshal(cfg)
	cvm, _, _, _, initErr := newGenesisHarness(t, nil, nil, cfgBlob)
	if initErr != nil {
		t.Fatalf("Initialize with a (benign) config blob must succeed, got: %v", initErr)
	}
	if len(cvm.inner.Config.FillAttestationPubKey) != 0 {
		t.Fatalf("runtime config set FillAttestationPubKey (%d bytes) — it is consensus-affecting and MUST be "+
			"genesis-pinned ONLY; a per-node config value forks the StateRoot.",
			len(cvm.inner.Config.FillAttestationPubKey))
	}
	t.Logf("INVARIANT OK: runtime config cannot set the genesis-pinned attestation pubkey")
}
