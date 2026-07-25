// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/luxfi/chains/mpcvm"
	"github.com/luxfi/log"
	"github.com/luxfi/sys/ulimit"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/vm/rpc"
)

// main serves the M-Chain VM as a plugin.
//
// The binary's FILENAME must be the CB58 of mpcvm.VMID
// (qCURact1n41FcoNBch8iMVBwc9AWie48D118ZNJ5tBdWrvryS) — that is how the node's
// plugin registry resolves a vmID from a CreateChainTx to an implementation.
// A binary installed under any other name is invisible and the chain silently
// never starts. See node/Dockerfile and TestVMID_IsCanonicalAndStable.
func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("mpcvm/%s\n", mpcvm.Version)
		os.Exit(0)
	}

	if err := ulimit.Set(ulimit.DefaultFDLimit, log.Root()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set fd limit: %s\n", err)
		os.Exit(1)
	}

	f := &mpcvm.Factory{}
	raw, err := f.New(log.Root())
	if err != nil {
		fmt.Fprintf(os.Stderr, "factory error: %s\n", err)
		os.Exit(1)
	}

	vm := raw.(chain.ChainVM)
	if err := rpc.Serve(context.Background(), log.Root(), vm); err != nil {
		fmt.Fprintf(os.Stderr, "rpc.Serve error: %s\n", err)
		os.Exit(1)
	}
}
