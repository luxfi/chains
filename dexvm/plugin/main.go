//go:build grpc

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/luxfi/log"
	"github.com/luxfi/node/version"
	"github.com/luxfi/chains/dexvm"
	"github.com/luxfi/node/vms/rpcchainvm"
	"github.com/luxfi/sys/ulimit"
)

func main() {
	versionStr := fmt.Sprintf("DEX-VM/1.0.0 [node=%s, rpcchainvm=%d]", version.Current, version.RPCChainVMProtocol)

	// Set file descriptor limit
	if err := ulimit.Set(ulimit.DefaultFDLimit, log.Root()); err != nil {
		fmt.Printf("failed to set fd limit: %s\n", err)
		os.Exit(1)
	}

	// Create the DEX ChainVM (wrapper around functional VM)
	vm := dexvm.NewChainVM(log.Root())

	fmt.Printf("Starting %s\n", versionStr)
	if err := rpcchainvm.Serve(context.Background(), log.Root(), vm); err != nil {
		fmt.Printf("rpcchainvm.Serve error: %s\n", err)
		os.Exit(1)
	}
}
