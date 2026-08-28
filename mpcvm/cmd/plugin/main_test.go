// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luxfi/chains/mpcvm"
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
	if !strings.Contains(got, mpcvm.Version.String()) {
		t.Errorf("version output %q does not name the software version %s", got, mpcvm.Version)
	}
	if !strings.Contains(got, mpcvm.VMID.String()) {
		t.Errorf("version output %q does not name the vmID %s the plugin must be installed as",
			got, mpcvm.VMID)
	}
	if errOut.Len() != 0 {
		t.Errorf("version wrote to stderr: %q", errOut.String())
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
	if !strings.Contains(errOut.String(), "mpcvm plugin:") {
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
	if got := w.String(); got != "mpcvm plugin: disk fell off\n" {
		t.Fatalf("fail() wrote %q", got)
	}
}
