// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/bridgevm"
)

// TestTheVersionIsTheVMs. An operator asks this binary what it is, and the
// answer used to be a string literal beside the VM's own version: bump either
// one and the plugin reports a version it is not.
func TestTheVersionIsTheVMs(t *testing.T) {
	args := os.Args
	os.Args = []string{args[0], "version"}
	t.Cleanup(func() { os.Args = args })

	require.Equal(t, "Bridge-VM/"+bridgevm.Version.String()+"\n", capture(t, run))
}

// A plugin invoked with anything else serves the VM, which needs the node on
// the other end of the pipe; that path is the process's whole purpose and
// cannot run inside a test.
func TestAnUnknownArgumentIsNotTheVersion(t *testing.T) {
	args := os.Args
	os.Args = []string{args[0], "version", "extra"}
	t.Cleanup(func() { os.Args = args })

	require.Equal(t, "Bridge-VM/"+bridgevm.Version.String()+"\n", capture(t, run))
}

// capture runs f with stdout redirected and returns what it printed.
func capture(t *testing.T, f func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	stdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = stdout }()

	require.NoError(t, f())
	require.NoError(t, w.Close())

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}
