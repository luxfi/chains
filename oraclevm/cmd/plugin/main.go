// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command plugin serves the O-Chain VM to a Lux node.
//
// The binary's FILENAME must be the CB58 of oraclevm.VMID
// (r5m1ujrmXxVcQetG3CQfuDLHp2RHKh6vCDaFgBRQfUcTZh7eS) — that is how the node's
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

	"github.com/luxfi/chains/oraclevm"
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
	// Built through the same vms.Factory the node's registry uses. oraclevm
	// asserts *VM is a chain.ChainVM at compile time and its own test asserts
	// the Factory produces one, so the conversion here cannot be wrong by the
	// time this compiles.
	raw, err := (&oraclevm.Factory{}).New(log.Root())
	if err != nil {
		return fail(errOut, err)
	}
	vm := raw.(chain.ChainVM)

	if len(args) > 0 && args[0] == "version" {
		// The version comes from the VM, not from a second copy of the number
		// here. Two declarations of one version disagree the first time either
		// is bumped, and the one an operator reads is this one.
		v, err := vm.Version(ctx)
		if err != nil {
			return fail(errOut, err)
		}
		fmt.Fprintf(out, "oraclevm/%s %s\n", v, oraclevm.VMID)
		return 0
	}

	if err := ulimit.Set(ulimit.DefaultFDLimit, log.Root()); err != nil {
		return fail(errOut, err)
	}
	if err := rpc.Serve(ctx, log.Root(), vm); err != nil {
		return fail(errOut, err)
	}
	return 0
}

// fail reports why the plugin is not serving and gives the node a non-zero
// exit. A plugin that dies quietly presents as a chain that never starts.
func fail(w io.Writer, err error) int {
	fmt.Fprintf(w, "oraclevm plugin: %s\n", err)
	return 1
}
