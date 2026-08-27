// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
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

// work is a workload with the fields a machine is sized from.
func work() agentvm.Workload {
	return agentvm.Workload{
		Code:     agentvm.Code{Kind: agentvm.CodeImage, Ref: "sum", Args: []string{"--base", "16"}},
		Resource: agentvm.Resource{CPU: 2500, Memory: 512 << 20, Timeout: 30_000},
	}
}

// file writes a named file with the given contents into one directory and
// returns its path.
func file(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// host builds a runner over three stand-in files, which is everything the
// constructor reads.
func host(t *testing.T) *Runner {
	t.Helper()
	dir := t.TempDir()
	r, err := New(Config{
		Binary: file(t, dir, "firecracker", "a vmm"),
		Kernel: file(t, dir, "vmlinux", "a kernel"),
		Rootfs: file(t, dir, "rootfs.ext4", "a root filesystem"),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return r
}

func TestUnavailableWithoutBinary(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Config{
		Binary: filepath.Join(dir, "firecracker"),
		Kernel: file(t, dir, "vmlinux", "a kernel"),
		Rootfs: file(t, dir, "rootfs.ext4", "a root filesystem"),
	})
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
}

func TestUnavailableWithoutPath(t *testing.T) {
	t.Setenv("PATH", "")
	dir := t.TempDir()
	_, err := New(Config{
		Kernel: file(t, dir, "vmlinux", "a kernel"),
		Rootfs: file(t, dir, "rootfs.ext4", "a root filesystem"),
	})
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
}

func TestUnavailableWithoutKernel(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Config{
		Binary: file(t, dir, "firecracker", "a vmm"),
		Kernel: filepath.Join(dir, "vmlinux"),
		Rootfs: file(t, dir, "rootfs.ext4", "a root filesystem"),
	})
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "kernel") {
		t.Fatalf("error %v does not say what is missing", err)
	}
}

func TestUnavailableWithoutRootfs(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Config{
		Binary: file(t, dir, "firecracker", "a vmm"),
		Kernel: file(t, dir, "vmlinux", "a kernel"),
		Rootfs: filepath.Join(dir, "rootfs.ext4"),
	})
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "rootfs") {
		t.Fatalf("error %v does not say what is missing", err)
	}
}

func TestMeasurements(t *testing.T) {
	r := host(t)
	kernel := sha256.Sum256([]byte("a kernel"))
	root := sha256.Sum256([]byte("a root filesystem"))
	if want := common.BytesToHash(crypto.Keccak256(kernel[:])); r.Kernel() != want {
		t.Fatalf("kernel %s, want %s", r.Kernel(), want)
	}
	if want := common.BytesToHash(crypto.Keccak256(root[:])); r.Root() != want {
		t.Fatalf("root %s, want %s", r.Root(), want)
	}
	if r.Kernel() == r.Root() {
		t.Fatal("two different images measured the same")
	}
	if r.filter == (common.Hash{}) {
		t.Fatal("filter digest is zero, which reads as no filter at all")
	}
}

func TestWitnessIsTheKernel(t *testing.T) {
	// Evidence for a guest kernel is checked by comparing what the run observed
	// with what the operator measured. They are one value here, so the check
	// cannot be passed by a runner that measured one kernel and booted another.
	r := host(t)
	seen := r.witness()
	if seen.Serves != agentvm.MechanismFirecracker {
		t.Fatalf("witness serves %v", seen.Serves)
	}
	if seen.Digest != r.Kernel() {
		t.Fatalf("witness %s is not the measured kernel %s", seen.Digest, r.Kernel())
	}
	if seen.Digest == (common.Hash{}) {
		t.Fatal("witness digest is zero")
	}
}

func TestCommandNamesWorkload(t *testing.T) {
	r := host(t)
	w := work()
	got := r.command(w)
	for _, want := range []string{"console=ttyS0", "reboot=k", "panic=1", "pci=off"} {
		if !strings.Contains(got, want) {
			t.Fatalf("command line %q has no %s", got, want)
		}
	}
	id := w.ID()
	if want := "agentvm.workload=" + hex.EncodeToString(id[:]); !strings.Contains(got, want) {
		t.Fatalf("command line %q does not name the workload", got)
	}
	// A different workload boots a different guest.
	other := work()
	other.Resource.CPU = 4000
	if r.command(other) == got {
		t.Fatal("two workloads take one command line")
	}
}

func TestCommandFromOperator(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{
		Binary: file(t, dir, "firecracker", "a vmm"),
		Kernel: file(t, dir, "vmlinux", "a kernel"),
		Rootfs: file(t, dir, "rootfs.ext4", "a root filesystem"),
	}, WithBoot("console=ttyS0 quiet"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	got := r.command(work())
	if !strings.HasPrefix(got, "console=ttyS0 quiet ") {
		t.Fatalf("command line %q does not start from the operator's", got)
	}
	if !strings.Contains(got, "agentvm.workload=") {
		t.Fatalf("command line %q dropped the workload", got)
	}
}

func TestMachineSize(t *testing.T) {
	for _, c := range []struct {
		cpu  uint32
		want int64
	}{
		{1, 1}, {999, 1}, {1000, 1}, {1001, 2}, {2500, 3}, {8000, 8},
	} {
		if got := vcpu(c.cpu); got != c.want {
			t.Fatalf("vcpu(%d) = %d, want %d", c.cpu, got, c.want)
		}
	}
	for _, c := range []struct {
		bytes uint64
		want  int64
	}{
		{1, 1}, {1 << 20, 1}, {(1 << 20) + 1, 2}, {512 << 20, 512}, {(1 << 30) + (1 << 20), 1025},
	} {
		if got := mib(c.bytes); got != c.want {
			t.Fatalf("mib(%d) = %d, want %d", c.bytes, got, c.want)
		}
	}
	// A machine with no processor and no memory does not boot, so an ask that
	// rounds to nothing rounds to one instead.
	if vcpu(0) != 1 || mib(0) != 1 {
		t.Fatalf("empty ask gave %d vcpu and %d MiB", vcpu(0), mib(0))
	}
}

func TestMechanismGrants(t *testing.T) {
	r := &Runner{}
	if r.Mechanism() != agentvm.MechanismFirecracker {
		t.Fatalf("mechanism %v", r.Mechanism())
	}
	if r.Placement() != agentvm.PlacementLocal {
		t.Fatalf("placement %v", r.Placement())
	}
	granted := agentvm.Grants(r.Mechanism())
	for _, p := range []agentvm.Property{
		agentvm.KernelGuest, agentvm.SyscallFiltered,
		agentvm.MemoryPlain, agentvm.AttestSoftware,
	} {
		if !granted.Has(p) {
			t.Fatalf("firecracker does not grant %v", p)
		}
	}
	// Its own kernel is the point. It does not encrypt memory against the host
	// and it does not mediate syscalls in a sentry.
	for _, p := range []agentvm.Property{agentvm.MemoryEncrypted, agentvm.SyscallMediated, agentvm.KernelShared} {
		if granted.Has(p) {
			t.Fatalf("firecracker claims %v", p)
		}
	}
}

func TestRunRefusesWorkloadWithoutTimeout(t *testing.T) {
	w := work()
	w.Resource.Timeout = 0
	_, err := host(t).Run(context.Background(), w, nil)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("error %v, want a refusal naming the timeout", err)
	}
}

func TestRunRefusesWhenVMMWillNotStart(t *testing.T) {
	// The stand-in binary is a file, not a program. Whatever the host does with
	// it, no console frame arrives, and a run without a frame is a failure
	// rather than an empty success.
	w := work()
	w.Resource.Timeout = 200
	res, err := host(t).Run(context.Background(), w, nil)
	if !errors.Is(err, runner.ErrFailed) {
		t.Fatalf("error %v, want ErrFailed", err)
	}
	if len(res.Output) != 0 || res.Exit != 0 {
		t.Fatalf("a failed run reported output %q and exit %d", res.Output, res.Exit)
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
