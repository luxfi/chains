// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gvisor

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

// A Runner is a runner.Runner or it is of no use to a set.
var _ runner.Runner = (*Runner)(nil)

// work is a workload with the fields a run is built from.
func work() agentvm.Workload {
	return agentvm.Workload{
		Code: agentvm.Code{
			Kind: agentvm.CodeScript,
			Ref:  "/bin/sum",
			Args: []string{"--base", "16"},
		},
		Resource: agentvm.Resource{CPU: 1000, Memory: 256 << 20, Timeout: 5_000},
	}
}

// runsc puts a stand-in binary on disk and returns its path.
func runsc(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runsc")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// A host kernel and a sentry, as each writes /proc/version.
const (
	host   = "Linux version 6.8.0-45-generic (buildd@lcy02) (x86_64-linux-gnu-gcc 13.2.0) #45-Ubuntu SMP"
	sentry = "Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016 gVisor"
)

func TestMediation(t *testing.T) {
	if err := mediated(sentry); err != nil {
		t.Fatalf("a sentry was refused: %v", err)
	}
	// Case is not part of the fact.
	if err := mediated("linux version 4.4.0 gvisor"); err != nil {
		t.Fatalf("a sentry was refused: %v", err)
	}
	// This is the whole reason the probe exists: a run on the host kernel, which
	// is exactly what a misconfigured sandbox and an ordinary runc container
	// both produce, cannot be attested as mediated.
	if err := mediated(host); !errors.Is(err, ErrNotMediated) {
		t.Fatalf("a host kernel was accepted: %v", err)
	}
	if err := mediated(""); !errors.Is(err, ErrNotMediated) {
		t.Fatalf("silence was accepted: %v", err)
	}
	if err := mediated("Linux version 6.8.0 #45-Ubuntu"); !errors.Is(err, ErrNotMediated) {
		t.Fatalf("a host kernel was accepted: %v", err)
	}
}

func TestUnavailableWithoutBinary(t *testing.T) {
	_, err := New(WithBinary(filepath.Join(t.TempDir(), "runsc")))
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
}

func TestUnavailableWithoutPath(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv(binaryVar, "")
	_, err := New()
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
}

func TestBinaryFromEnv(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "shipped-runsc")
	t.Setenv(binaryVar, missing)
	_, err := New()
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("error %v does not name the binary from %s", err, binaryVar)
	}
}

func TestUnavailableWhenSilent(t *testing.T) {
	_, err := New(WithBinary(runsc(t, "#!/bin/sh\nexit 3\n")))
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
}

func TestBuildPinRefused(t *testing.T) {
	path := runsc(t, "#!/bin/sh\necho 'runsc version release-20260817.0'\n")
	other := common.BytesToHash(crypto.Keccak256([]byte("some other build")))
	_, err := New(WithBinary(path), WithBuild(other))
	if !errors.Is(err, ErrBuild) {
		t.Fatalf("error %v, want ErrBuild", err)
	}
}

func TestBuildPinHeld(t *testing.T) {
	body := "#!/bin/sh\necho 'runsc version release-20260817.0'\n"
	path := runsc(t, body)
	sum := sha256.Sum256([]byte(body))
	pin := common.BytesToHash(crypto.Keccak256(sum[:]))

	r, err := New(WithBinary(path), WithBuild(pin))
	if err != nil {
		t.Fatalf("the pinned build was refused: %v", err)
	}
	if r.Build() != pin {
		t.Fatalf("build %s, want %s", r.Build(), pin)
	}
	if r.Version() != "runsc version release-20260817.0" {
		t.Fatalf("version %q", r.Version())
	}
}

func TestBuildCheckedBeforeExec(t *testing.T) {
	// A binary that would fail to report a version still fails the pin first,
	// which is the only order in which a pin means anything: the check is over
	// bytes on disk, not over what running them produced.
	path := runsc(t, "#!/bin/sh\nexit 3\n")
	_, err := New(WithBinary(path), WithBuild(common.BytesToHash([]byte("elsewhere"))))
	if !errors.Is(err, ErrBuild) {
		t.Fatalf("error %v, want ErrBuild", err)
	}
}

func TestMeasure(t *testing.T) {
	body := "a runsc build"
	path := runsc(t, body)
	got, err := measure(path)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	sum := sha256.Sum256([]byte(body))
	if want := common.BytesToHash(crypto.Keccak256(sum[:])); got != want {
		t.Fatalf("measure = %s, want %s", got, want)
	}
	if _, err := measure(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("measuring a file that is not there succeeded")
	}
}

func TestSandboxArgv(t *testing.T) {
	got := sandbox("/bin/sum", []string{"--base", "16"})
	// Global flags first, then the subcommand: runsc parses them in that order
	// and rejects the argv outright otherwise.
	want := []string{"--network=none", "do", "/bin/sum", "--base", "16"}
	if !slices.Equal(got, want) {
		t.Fatalf("argv %v, want %v", got, want)
	}
	// The probe runs under the same configuration as the workload, or it does
	// not describe the workload's sandbox.
	if !slices.Equal(probe[:2], want[:2]) {
		t.Fatalf("probe argv %v is configured differently from the run", probe)
	}
	if !slices.Contains(probe, "/proc/version") {
		t.Fatalf("probe %v does not ask what kernel answered", probe)
	}
}

func TestArgvDigest(t *testing.T) {
	base := digest(sandbox("/bin/sum", nil))
	if base == (common.Hash{}) {
		t.Fatal("argv digest is zero")
	}
	if base != digest(sandbox("/bin/sum", nil)) {
		t.Fatal("one configuration digests two ways")
	}
	if base == digest(sandbox("/bin/sum", []string{"--base"})) {
		t.Fatal("an argument left the configuration digest unchanged")
	}
	if base == digest([]string{"do", "/bin/sum"}) {
		t.Fatal("dropping the network flag left the configuration digest unchanged")
	}
	// Length prefixes: the same characters cut differently are different argvs.
	if digest([]string{"ab", "c"}) == digest([]string{"a", "bc"}) {
		t.Fatal("two argvs fold to one digest")
	}
}

func TestMechanismGrants(t *testing.T) {
	r := &Runner{}
	if r.Mechanism() != agentvm.MechanismGVisor {
		t.Fatalf("mechanism %v", r.Mechanism())
	}
	if r.Placement() != agentvm.PlacementLocal {
		t.Fatalf("placement %v", r.Placement())
	}
	granted := agentvm.Grants(r.Mechanism())
	for _, p := range []agentvm.Property{
		agentvm.KernelShared, agentvm.SyscallMediated,
		agentvm.MemoryPlain, agentvm.AttestSoftware,
	} {
		if !granted.Has(p) {
			t.Fatalf("gvisor does not grant %v", p)
		}
	}
	// A sentry is not a guest kernel: the host kernel is still underneath it.
	if granted.Has(agentvm.KernelGuest) {
		t.Fatal("gvisor claims a guest kernel")
	}
	if granted.Has(agentvm.SyscallFiltered) {
		t.Fatal("gvisor claims a seccomp filter, which is a different property")
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

func TestRunRefusesUnmediatedSandbox(t *testing.T) {
	// A binary that answers the probe with a host kernel is a configuration
	// that mediated nothing. The run stops at the probe, so the workload never
	// executes under a claim the sandbox cannot support.
	path := runsc(t, "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'runsc version test'; else echo '"+host+"'; fi\n")
	r, err := New(WithBinary(path))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := r.Run(context.Background(), work(), nil); !errors.Is(err, ErrNotMediated) {
		t.Fatalf("error %v, want ErrNotMediated", err)
	}
}

func TestEnv(t *testing.T) {
	got := env([]agentvm.Var{{Name: "LANG", Value: "C"}, {Name: "MODE", Value: "batch"}})
	if want := []string{"LANG=C", "MODE=batch"}; !slices.Equal(got, want) {
		t.Fatalf("env %v, want %v", got, want)
	}
}

func TestSpentClamped(t *testing.T) {
	if got := spent(time.Now().Add(-time.Hour), 1000); got != 1000 {
		t.Fatalf("spent %d, want the 1000ms ask", got)
	}
	if got := spent(time.Now(), 1000); got > 1000 {
		t.Fatalf("spent %d, want at most the ask", got)
	}
}

// TestGlobalFlagsPrecedeSubcommand pins the argv order against the real runsc
// flag parser.
//
// runsc's network flag is global: written after the subcommand it is rejected
// before any sandbox is created, so a runner that builds it that way never
// mediates anything and never finds out. The unit assertion holds everywhere;
// where a runsc is actually installed the same argv is handed to its parser and
// the reply is required not to be a flag error. Nothing is skipped -- on a host
// without runsc the order assertion is the whole test.
func TestGlobalFlagsPrecedeSubcommand(t *testing.T) {
	argv := sandbox("cat", []string{"/proc/version"})
	if argv[0] != "--network=none" {
		t.Fatalf("argv[0] = %q, want the global flag first", argv[0])
	}
	if argv[1] != "do" {
		t.Fatalf("argv[1] = %q, want the subcommand after the global flags", argv[1])
	}

	bin, err := exec.LookPath("runsc")
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, argv...).CombinedOutput()
	if strings.Contains(string(out), "flag provided but not defined") {
		t.Fatalf("runsc rejected the argv this runner builds: %s", out)
	}
}
