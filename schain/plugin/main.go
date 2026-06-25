//go:build grpc

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/luxfi/chains/schain"
	"github.com/luxfi/log"
	"github.com/luxfi/node/version"
	"github.com/luxfi/node/vms/rpcchainvm"
	"github.com/luxfi/sys/ulimit"
)

func main() {
	versionStr := fmt.Sprintf("S-VM/0.1.0 [node=%s, rpcchainvm=%d]", version.Current, version.RPCChainVMProtocol)

	if err := ulimit.Set(ulimit.DefaultFDLimit, log.Root()); err != nil {
		fmt.Printf("failed to set fd limit: %s\n", err)
		os.Exit(1)
	}

	vm := schain.NewChainVM(log.Root())

	fmt.Printf("Starting %s\n", versionStr)
	if err := rpcchainvm.Serve(context.Background(), log.Root(), vm); err != nil {
		fmt.Printf("rpcchainvm.Serve error: %s\n", err)
		os.Exit(1)
	}
}
