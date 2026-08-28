// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command plugin serves the M-Chain VM to a Lux node.
//
// The binary's FILENAME must be the CB58 of mpcvm.VMID
// (qCURact1n41FcoNBch8iMVBwc9AWie48D118ZNJ5tBdWrvryS) — that is how the node's
// plugin registry resolves a vmID from a CreateChainTx to an implementation.
// A binary installed under any other name is invisible and the chain silently
// never starts, which is why `version` prints the id it must be installed as:
// the fact an operator needs is in the place an operator already looks.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/luxfi/chains/mpcvm"
	"github.com/luxfi/log"
	"github.com/luxfi/sys/ulimit"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/vm/rpc"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// run is main with the exit lifted out, so what the plugin does is reachable
// from a test and only the exit itself is not.
func run(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) > 0 && args[0] == "version" {
		fmt.Fprintf(out, "mpcvm/%s %s\n", mpcvm.Version, mpcvm.VMID)
		return 0
	}
	if err := ulimit.Set(ulimit.DefaultFDLimit, log.Root()); err != nil {
		return fail(errOut, err)
	}
	// Typed at the declaration: "this plugin serves M-Chain's ChainVM" is then
	// a compile error to get wrong, rather than a runtime type assertion on a
	// factory that returns interface{} and an error it never returns.
	var vm chain.ChainVM = &mpcvm.VM{}
	if err := rpc.Serve(ctx, log.Root(), vm); err != nil {
		return fail(errOut, err)
	}
	return 0
}

// fail reports why the plugin is not serving and gives the node a non-zero
// exit. A plugin that dies quietly presents as a chain that never starts.
func fail(w io.Writer, err error) int {
	fmt.Fprintf(w, "mpcvm plugin: %s\n", err)
	return 1
}
