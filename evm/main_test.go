// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luxfi/constants"
	"github.com/luxfi/evm/core/parallel"
	"github.com/luxfi/evm/plugin/evm"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/version"
	"github.com/luxfi/vm/rpc/runtime"
)

// canonicalVMIDCB58 is C-Chain's vmID in the encoding the node's plugin
// registry uses. The binary this package builds MUST be installed under
// exactly this filename; the registry resolves a CreateChainTx's vmID to an
// implementation by looking for a file with this name in the plugin directory.
//
// Written out literally rather than computed, so that a change to the vmID —
// for any reason, including an "obviously equivalent" refactor — fails here
// instead of silently producing a chain no node can start.
const canonicalVMIDCB58 = "mgj786NP7uDwBCcq6YwThhaN8FLyybkCa4zBWTQbNgmK6k9A6"

// C-Chain's id is the one in luxfi/constants and nothing else. A vmID is an
// immutable one-way door: baked into the CreateChainTx at genesis, stored by
// the P-Chain forever, and the filename the plugin is installed under.
func TestTheVMIDIsCanonicalAndStable(t *testing.T) {
	if constants.ContractVMID != constants.EVMID {
		t.Fatalf("ContractVMID = %s but EVMID = %s; C-Chain has one id",
			constants.ContractVMID, constants.EVMID)
	}
	if want := (ids.ID{'e', 'v', 'm'}); constants.ContractVMID != want {
		t.Fatalf("ContractVMID bytes = %v, want %v", constants.ContractVMID[:4], want[:4])
	}
	if got := constants.ContractVMID.String(); got != canonicalVMIDCB58 {
		t.Fatalf("ContractVMID CB58 = %q, want %q", got, canonicalVMIDCB58)
	}
}

// The `version` subcommand prints the id the binary must be INSTALLED as, not
// just the software version.
//
// The two facts fail differently and an operator needs both. A wrong software
// version starts a chain that misbehaves; a wrong FILENAME starts nothing at
// all — the node's registry resolves a CreateChainTx's vmID by looking for a
// file with that name, so a correctly built plugin under the wrong name is
// invisible, and the symptom is a chain that never appears with no error
// anywhere.
func TestVersionNamesTheIdTheBinaryMustBeInstalledAs(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, &errOut); code != 0 {
		t.Fatalf("version exited %d, want 0; stderr=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), canonicalVMIDCB58) {
		t.Errorf("version output %q does not name the vmID the plugin must be installed as (%s)",
			out.String(), canonicalVMIDCB58)
	}
	if errOut.Len() != 0 {
		t.Errorf("version wrote to stderr: %q", errOut.String())
	}
}

// The EVM version printed is the VM's own, not a literal beside it. This used
// to print a hardcoded "Lux-EVM/1.0.0" while luxfi/evm carried its own
// plugin/evm.Version; the two agreed only by never being looked at together.
func TestTheVersionIsTheVMsOwn(t *testing.T) {
	want, err := (&evm.VM{}).Version(context.Background())
	if err != nil {
		t.Fatalf("VM.Version: %v", err)
	}

	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, &errOut); code != 0 {
		t.Fatalf("version exited %d, want 0; stderr=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), want) {
		t.Errorf("version output %q does not carry the VM's own version %q", out.String(), want)
	}
}

// The node and rpcchainvm numbers are read from the same package the node
// reads them from. A plugin whose rpcchainvm protocol differs from the node's
// is refused at the handshake with nothing to inspect but this line.
func TestVersionNamesTheProtocolTheNodeMustMatch(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, &errOut); code != 0 {
		t.Fatalf("version exited %d, want 0", code)
	}
	got := out.String()
	if !strings.Contains(got, version.Current.String()) {
		t.Errorf("version output %q does not name the node version %s", got, version.Current)
	}
	if !strings.Contains(got, "rpcchainvm=") {
		t.Errorf("version output %q does not name the rpcchainvm protocol", got)
	}
}

// Anything that is not `version` serves, and serving needs a node. Started by
// hand there is no engine address in the environment, so the plugin says why
// it is not serving and exits non-zero.
//
// The exit code is the load-bearing half. A plugin that fails to serve and
// exits 0 looks to the node's runtime like a plugin that ran and finished, so
// the chain never starts and nothing reports a failure — the same silent
// absence a misnamed binary produces.
func TestAPluginWithNoNodeToServeSaysSoAndFails(t *testing.T) {
	t.Setenv(runtime.EngineAddressKey, "")

	var out, errOut bytes.Buffer
	if code := run(context.Background(), nil, &out, &errOut); code != 1 {
		t.Fatalf("run with no engine address exited %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "evm plugin:") {
		t.Errorf("stderr %q does not name the plugin as the source of the failure", errOut.String())
	}
	if !strings.Contains(errOut.String(), runtime.EngineAddressKey) {
		t.Errorf("stderr %q does not name the missing environment variable %q",
			errOut.String(), runtime.EngineAddressKey)
	}
}

// An empty argument list and an argument that is not `version` take the same
// path: there is one subcommand, and everything else is "serve".
func TestOnlyVersionIsASubcommand(t *testing.T) {
	t.Setenv(runtime.EngineAddressKey, "")

	for _, args := range [][]string{nil, {}, {"serve"}, {"Version"}, {"--version"}} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), args, &out, &errOut); code != 1 {
			t.Errorf("run(%q) exited %d, want 1 (it must have tried to serve)", args, code)
		}
		if out.Len() != 0 {
			t.Errorf("run(%q) wrote %q to stdout; only `version` reports on stdout", args, out.String())
		}
	}
}

// fail is the one place a refusal is reported, so the message names the plugin
// and the code is non-zero whatever went wrong.
func TestEveryRefusalIsAttributedAndNonZero(t *testing.T) {
	var w bytes.Buffer
	if code := fail(&w, errors.New("disk fell off")); code != 1 {
		t.Fatalf("fail() = %d, want 1", code)
	}
	if got := w.String(); got != "evm plugin: disk fell off\n" {
		t.Fatalf("fail() wrote %q", got)
	}
}

// Selecting the backend leaves exactly one lane active, and it is one this
// build actually has. A binary that resolved to a backend it cannot run would
// execute nothing and report a name.
func TestSelectingTheBackendLeavesARunnableLaneActive(t *testing.T) {
	selectExecutionBackend(log.Root())

	active := parallel.ActiveBackend()
	available := parallel.AvailableBackends()
	if len(available) == 0 {
		t.Fatal("no execution backend is available; the EVM cannot run a block")
	}
	for _, b := range available {
		if b == active {
			return
		}
	}
	t.Fatalf("active backend %q is not among the available ones %q", active, available)
}

// Selection is idempotent: the node calls it once at start-up, but a value
// that changed on a second call would mean the answer depends on when it was
// asked.
func TestSelectingTheBackendTwiceGivesTheSameLane(t *testing.T) {
	selectExecutionBackend(log.Root())
	first := parallel.ActiveBackend()
	selectExecutionBackend(log.Root())
	if second := parallel.ActiveBackend(); second != first {
		t.Fatalf("backend moved from %q to %q between two identical calls", first, second)
	}
}
