// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luxfi/chains/relayvm"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/vm/rpc/runtime"
)

// The `version` subcommand prints the id the binary must be INSTALLED as, not
// just the software version.
//
// The two facts fail differently and an operator needs both. A wrong software
// version starts a chain that misbehaves; a wrong FILENAME starts nothing at
// all — the node's registry resolves a CreateChainTx's vmID by looking for a
// file with that name, so a correctly built plugin under the wrong name is
// invisible, and the symptom is a chain that never appears with no error
// anywhere. Printing the id here puts it where an operator already looks.
func TestVersionNamesTheIdTheBinaryMustBeInstalledAs(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, &errOut); code != 0 {
		t.Fatalf("version exited %d, want 0; stderr=%q", code, errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, relayvm.VMID.String()) {
		t.Errorf("version output %q does not name the vmID %s the plugin must be installed as",
			got, relayvm.VMID)
	}
	if errOut.Len() != 0 {
		t.Errorf("version wrote to stderr: %q", errOut.String())
	}
}

// The version printed is the VM's own answer, not a literal beside it. The
// plugin used to print a hardcoded "Relay-VM/1.0.0" while the VM answered with
// its own "1.0.0" from luxfi/relay; the two agreed by coincidence, and the
// first bump of either would have left the one an operator reads — the
// plugin's — wrong.
func TestTheVersionIsTheVMsOwn(t *testing.T) {
	raw, err := (&relayvm.Factory{}).New(log.Root())
	if err != nil {
		t.Fatalf("Factory.New: %v", err)
	}
	want, err := raw.(chain.ChainVM).Version(context.Background())
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

// Anything that is not `version` serves, and serving needs a node. Started by
// hand there is no engine address in the environment, so the plugin says why it
// is not serving and exits non-zero.
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
	if !strings.Contains(errOut.String(), "relayvm plugin:") {
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
	if got := w.String(); got != "relayvm plugin: disk fell off\n" {
		t.Fatalf("fail() wrote %q", got)
	}
}
