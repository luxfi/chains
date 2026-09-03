// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/luxfi/chains/fhevm"
	"github.com/luxfi/log"
	"github.com/luxfi/sys/ulimit"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/vm/rpc"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run is the plugin: answer for the version, or serve the VM.
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("FHE-VM/%s\n", fhevm.Version)
		return nil
	}
	if err := ulimit.Set(ulimit.DefaultFDLimit, log.Root()); err != nil {
		return fmt.Errorf("set fd limit: %w", err)
	}
	raw, err := (&fhevm.Factory{}).New(log.Root())
	if err != nil {
		return fmt.Errorf("build the VM: %w", err)
	}
	return rpc.Serve(context.Background(), log.Root(), raw.(chain.ChainVM))
}
