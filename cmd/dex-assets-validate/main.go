// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command dex-assets-validate is the CI gate for the DEX real-assets-only model. It
// loads a per-network asset manifest and proves EVERY entry real against the TARGET
// network's live RPC before a deploy is allowed to proceed:
//
//   - the C-Chain eth_chainId matches the manifest's evmChainID,
//   - the C-Chain consensus id matches the manifest's cChainID,
//   - every ERC-20 has on-chain code and its declared decimals match decimals(),
//   - every EVM_NATIVE resolves on the C-Chain,
//   - every UTXO assetID exists on the X-Chain,
//   - every market pins to two registered, enabled assets,
//   - the fail-closed startup gate (no synthetic flags on a value net, no
//     Liquidity/mock/ticker reference) passes.
//
// Exit 0 only when the whole manifest is real and gate-clean; any failure exits
// non-zero so the deploy job stops. It NEVER mutates anything — it is read-only
// against the target net.
//
// Usage:
//
//	dex-assets-validate \
//	  -manifest dexvm/registry/manifests/assets.mainnet.json \
//	  -evm-rpc  https://api.lux.network/ext/bc/C/rpc \
//	  -api-base https://api.lux.network \
//	  [-native-decimals 18]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/luxfi/chains/dexvm/registry"
	"github.com/luxfi/chains/dexvm/registry/rpcverify"
	"github.com/luxfi/ids"
)

func main() {
	var (
		manifestPath = flag.String("manifest", "", "path to the per-network asset manifest JSON")
		evmRPC       = flag.String("evm-rpc", "", "C-Chain EVM RPC URL (…/ext/bc/C/rpc)")
		apiBase      = flag.String("api-base", "", "node API base (… root; used for /ext/P and /ext/bc/X)")
		nativeDec    = flag.Uint("native-decimals", 18, "C-Chain native coin decimals")
		timeout      = flag.Duration("timeout", 2*time.Minute, "overall validation timeout")
	)
	flag.Parse()

	if *manifestPath == "" || *evmRPC == "" || *apiBase == "" {
		fmt.Fprintln(os.Stderr, "dex-assets-validate: -manifest, -evm-rpc and -api-base are required")
		flag.Usage()
		os.Exit(2)
	}
	if *nativeDec > 255 {
		fmt.Fprintln(os.Stderr, "dex-assets-validate: -native-decimals out of range")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	m, err := registry.LoadManifest(*manifestPath)
	if err != nil {
		fatal("load manifest", err)
	}
	fmt.Printf("manifest %q: network=%s networkID=%d evmChainID=%d assets=%d markets=%d\n",
		*manifestPath, m.Network, m.NetworkID, m.EVMChainID, len(m.Assets), len(m.Markets))

	v, err := rpcverify.New(ctx, *evmRPC, *apiBase, uint8(*nativeDec))
	if err != nil {
		fatal("dial verifier", err)
	}

	reg, err := m.Validate(v)
	if err != nil {
		fatal("validate manifest against live "+m.Network, err)
	}

	fmt.Printf("OK: %d assets and %d markets verified real on %s; fail-closed gate passed\n",
		reg.Len(), countMarkets(reg), m.Network)
}

func countMarkets(reg *registry.Registry) int {
	n := 0
	reg.EachMarket(func(ids.ID, registry.Market) { n++ })
	return n
}

func fatal(stage string, err error) {
	fmt.Fprintf(os.Stderr, "dex-assets-validate: %s: %v\n", stage, err)
	os.Exit(1)
}
