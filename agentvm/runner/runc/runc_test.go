// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package runc

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

// A Runner is a runner.Runner or it is of no use to a set.
var _ runner.Runner = (*Runner)(nil)

func TestUnavailableWithoutBinary(t *testing.T) {
	_, err := New(WithBinary(filepath.Join(t.TempDir(), "runc")))
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
}

func TestUnavailableWithoutPath(t *testing.T) {
	t.Setenv("PATH", "")
	_, err := New()
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
}

func TestUnavailableWhenSilent(t *testing.T) {
	// A file that exists but will not report a version is not a runc. The
	// mechanism's identity is read from the binary, so one that answers nothing
	// cannot be attested and must not be constructed.
	_, err := New(WithBinary(script(t, "#!/bin/sh\nexit 3\n")))
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
}

func TestVersionObserved(t *testing.T) {
	// The witness digest is read from what the binary says it is, so two
	// different binaries are two different witnesses.
	one := script(t, "#!/bin/sh\necho 'runc version 1.2.3'\n")
	two := script(t, "#!/bin/sh\necho 'runc version 9.9.9'\n")
	a, err := New(WithBinary(one))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	b, err := New(WithBinary(two))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if a.Version() != "runc version 1.2.3" {
		t.Fatalf("version %q", a.Version())
	}
	if a.observed == b.observed {
		t.Fatal("two different runc builds produced one witness digest")
	}
}

func TestMechanismGrants(t *testing.T) {
	r := &Runner{}
	if r.Mechanism() != agentvm.MechanismRunc {
		t.Fatalf("mechanism %v", r.Mechanism())
	}
	if r.Placement() != agentvm.PlacementLocal {
		t.Fatalf("placement %v", r.Placement())
	}
	granted := agentvm.Grants(r.Mechanism())
	for _, p := range []agentvm.Property{
		agentvm.KernelShared, agentvm.SyscallFiltered,
		agentvm.MemoryPlain, agentvm.AttestSoftware,
	} {
		if !granted.Has(p) {
			t.Fatalf("runc does not grant %v", p)
		}
	}
	// The filter is the whole of what this mechanism adds. It does not mediate
	// syscalls and it does not give the workload a kernel.
	for _, p := range []agentvm.Property{agentvm.SyscallMediated, agentvm.KernelGuest} {
		if granted.Has(p) {
			t.Fatalf("runc claims %v", p)
		}
	}
}

func TestRunRefusesWorkloadWithoutTimeout(t *testing.T) {
	w := work()
	w.Resource.Timeout = 0
	_, err := (&Runner{}).Run(context.Background(), w, nil)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("error %v, want a refusal naming the timeout", err)
	}
}

func TestRunRefusesWorkloadWithoutCode(t *testing.T) {
	w := work()
	w.Code.Ref = ""
	_, err := (&Runner{}).Run(context.Background(), w, nil)
	if err == nil || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("error %v, want a refusal naming the executable", err)
	}
}

func TestIdentifyUnique(t *testing.T) {
	w := work()
	one, err := identify(w)
	if err != nil {
		t.Fatal(err)
	}
	two, err := identify(w)
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("one workload run twice takes one container name")
	}
	id := w.ID()
	for _, got := range []string{one, two} {
		if !strings.HasPrefix(got, "agentvm-") {
			t.Fatalf("name %q does not say what it is", got)
		}
		if !strings.Contains(got, hex.EncodeToString(id[:8])) {
			t.Fatalf("name %q does not name its workload", got)
		}
	}
}

func TestSpentClamped(t *testing.T) {
	if got := spent(time.Now().Add(-time.Hour), 1000); got != 1000 {
		t.Fatalf("spent %d, want the 1000ms ask", got)
	}
	if got := spent(time.Now(), 1000); got > 1000 {
		t.Fatalf("spent %d, want at most the ask", got)
	}
	if got := spent(time.Now().Add(time.Hour), 1000); got != 0 {
		t.Fatalf("spent %d, want 0", got)
	}
}

// script puts a small executable on disk and returns its path.
func script(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runc")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
