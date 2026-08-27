// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package firecracker runs workloads in microVMs.
//
// This is the one mechanism below a TEE that gives a workload its own kernel,
// and that is the only reason to pay for a VM boot. The claim is checkable: the
// kernel and the root filesystem are measured as files before anything runs, and
// the run is attested against those measurements, so "the guest booted the
// kernel we shipped" is a statement about bytes rather than about intent.
//
// The guest speaks over its serial console and nothing else. There is no shared
// filesystem, no vsock, no network: the workload's input goes in on the console
// and its answer comes back framed on the same console, which is why the frame
// in console.go is a protocol and not a convenience.
package firecracker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

// name prefixes this package's errors.
const name = "agentvm/runner/firecracker"

// boot is the guest command line every run starts from: one serial console, a
// reboot that halts the VM, a panic that ends it rather than hanging, and no PCI
// probing on a machine that has no PCI.
const boot = "console=ttyS0 reboot=k panic=1 pci=off"

// poll is how often the socket is checked for while the VMM starts.
const poll = 5 * time.Millisecond

// Config is what a microVM boots: the VMM, a kernel image, and a root
// filesystem. All three are paths on the operator's host.
type Config struct {
	Binary string
	Kernel string
	Rootfs string
}

// Option configures a Runner at construction.
type Option func(*Runner)

// WithBoot replaces the guest command line. The workload parameter is appended
// to whatever is set here, so a run always names the workload it booted for.
func WithBoot(args string) Option {
	return func(r *Runner) { r.boot = args }
}

// Runner executes workloads in microVMs.
type Runner struct {
	cfg  Config
	boot string
	// kernel and root are the measurements taken at construction, and filter is
	// the digest of the VMM binary. The VMM's syscall filter is compiled into
	// that binary, so the identity of the filter a run was given is the identity
	// of the build that applied it.
	kernel common.Hash
	root   common.Hash
	filter common.Hash
}

// New builds a runner over one VMM, kernel and root filesystem. It returns an
// error wrapping runner.ErrUnavailable when any of the three is missing or
// unreadable: a microVM runner without a kernel to boot is not a runner that is
// merely degraded, it is one that cannot run anything.
func New(cfg Config, opts ...Option) (*Runner, error) {
	r := &Runner{cfg: cfg, boot: boot}
	for _, o := range opts {
		o(r)
	}
	if r.cfg.Binary == "" {
		r.cfg.Binary = "firecracker"
	}
	if !strings.ContainsRune(r.cfg.Binary, filepath.Separator) {
		path, err := exec.LookPath(r.cfg.Binary)
		if err != nil {
			return nil, fmt.Errorf("%s: %w: %v", name, runner.ErrUnavailable, err)
		}
		r.cfg.Binary = path
	}
	filter, err := measure(r.cfg.Binary)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: vmm: %v", name, runner.ErrUnavailable, err)
	}
	r.filter = filter
	if r.kernel, err = measure(r.cfg.Kernel); err != nil {
		return nil, fmt.Errorf("%s: %w: kernel: %v", name, runner.ErrUnavailable, err)
	}
	if r.root, err = measure(r.cfg.Rootfs); err != nil {
		return nil, fmt.Errorf("%s: %w: rootfs: %v", name, runner.ErrUnavailable, err)
	}
	return r, nil
}

// Mechanism is firecracker.
func (r *Runner) Mechanism() agentvm.Mechanism { return agentvm.MechanismFirecracker }

// Placement is the operator's own host.
func (r *Runner) Placement() agentvm.Placement { return agentvm.PlacementLocal }

// Kernel is the measurement of the guest kernel this runner boots.
func (r *Runner) Kernel() common.Hash { return r.kernel }

// Root is the measurement of the guest root filesystem this runner boots.
func (r *Runner) Root() common.Hash { return r.root }

// command is the guest kernel command line: the operator's line, plus the
// workload the guest is booting for. The guest init reads that parameter to
// know which workload it is serving.
func (r *Runner) command(w agentvm.Workload) string {
	return r.boot + " agentvm.workload=" + hex.EncodeToString(w.ID().Bytes())
}

// witness is what a run of this machine observed of its own isolation. The
// guest booted the kernel measured at construction, so what answered its
// syscalls is that kernel, and the observation is that measurement. Evidence
// for a guest kernel is checked by comparing the two, which holds here by
// construction rather than by agreement.
func (r *Runner) witness() agentvm.Witness {
	return agentvm.Witness{Serves: agentvm.MechanismFirecracker, Digest: r.kernel}
}

// Run boots a microVM for the workload and returns what the guest framed on its
// console. The VM is killed and its socket removed however this returns.
//
// A console that never closed its frame produces no result at all. Truncated
// output and a crashed guest look the same on a serial line, so a run is either
// a complete frame or a failure.
func (r *Runner) Run(ctx context.Context, w agentvm.Workload, input []byte) (runner.Result, error) {
	if w.Resource.Timeout == 0 {
		return runner.Result{}, fmt.Errorf("%s: workload names no timeout", name)
	}

	dir, err := os.MkdirTemp("", "agentvm-vm-")
	if err != nil {
		return runner.Result{}, fmt.Errorf("%s: %w", name, err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "api.sock")

	deadline, stop := context.WithTimeout(ctx, time.Duration(w.Resource.Timeout)*time.Millisecond)
	defer stop()

	out, diag := listen(), &sink{}
	vmm := exec.CommandContext(deadline, r.cfg.Binary, "--api-sock", sock)
	// The guest's console is its only channel in both directions: the input
	// arrives on the serial line and the answer comes back framed on it.
	vmm.Stdin = bytes.NewReader(input)
	vmm.Stdout = out
	vmm.Stderr = diag

	start := time.Now()
	if err := vmm.Start(); err != nil {
		return runner.Result{}, fmt.Errorf("%s: %w: %v", name, runner.ErrFailed, err)
	}
	gone := make(chan error, 1)
	go func() { gone <- vmm.Wait() }()
	reaped := false
	defer func() {
		if reaped {
			return
		}
		_ = vmm.Process.Kill()
		<-gone
	}()

	dead, err := await(deadline, sock, gone)
	reaped = dead
	if err != nil {
		return runner.Result{}, fmt.Errorf("%s: %w: %v: %s", name, runner.ErrFailed, err, trim(diag.bytes()))
	}
	if err := dial(sock).start(deadline, plan{
		Kernel: r.cfg.Kernel,
		Boot:   r.command(w),
		Rootfs: r.cfg.Rootfs,
		VCPU:   vcpu(w.Resource.CPU),
		Memory: mib(w.Resource.Memory),
	}); err != nil {
		return runner.Result{}, err
	}

	// The guest is running. It finishes by closing its frame; anything else that
	// ends the wait ended the run without an answer.
	select {
	case <-out.done():
	case err := <-gone:
		reaped = true
		if !out.finished() {
			return runner.Result{}, fmt.Errorf("%s: %w: vmm exited: %v: %s",
				name, runner.ErrFailed, err, trim(diag.bytes()))
		}
	case <-deadline.Done():
		return runner.Result{}, fmt.Errorf("%s: %w: %v after %dms", name, runner.ErrFailed,
			deadline.Err(), spent(start, w.Resource.Timeout))
	}

	body, exit, err := parse(out.bytes())
	if err != nil {
		return runner.Result{}, err
	}
	res := runner.Result{
		Output: body,
		Exit:   exit,
		Consumed: agentvm.Resource{
			CPU:     w.Resource.CPU,
			Memory:  w.Resource.Memory,
			Timeout: spent(start, w.Resource.Timeout),
		},
		Observed: r.witness(),
		Filter:   r.filter,
		Kernel:   r.kernel,
		Root:     r.root,
	}
	if exit == 0 && len(body) == 0 {
		return res, fmt.Errorf("%s: %w", name, runner.ErrOutput)
	}
	return res, nil
}

// await waits for the VMM to create its socket. It reports whether the VMM has
// already exited, so its caller knows the process has been reaped and does not
// wait for it a second time.
func await(ctx context.Context, sock string, gone <-chan error) (bool, error) {
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		if _, err := os.Stat(sock); err == nil {
			return false, nil
		}
		select {
		case err := <-gone:
			return true, fmt.Errorf("vmm exited before serving its socket: %v", err)
		case <-ctx.Done():
			return false, ctx.Err()
		case <-tick.C:
		}
	}
}

// vcpu is the whole cores a CPU ask in thousandths buys, rounded up, never less
// than one: a machine with no processor does not boot.
func vcpu(cpu uint32) int64 {
	n := (int64(cpu) + 999) / 1000
	if n < 1 {
		return 1
	}
	return n
}

// mib is a memory ask in bytes as whole mebibytes, rounded up, never less than
// one.
func mib(size uint64) int64 {
	n := int64((size + (1 << 20) - 1) >> 20)
	if n < 1 {
		return 1
	}
	return n
}

// measure is the digest of a file on disk: keccak256 over its sha256. Streamed,
// because a root filesystem image is large.
func measure(path string) (common.Hash, error) {
	if path == "" {
		return common.Hash{}, errors.New("no path given")
	}
	f, err := os.Open(path)
	if err != nil {
		return common.Hash{}, err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(crypto.Keccak256(sum.Sum(nil))), nil
}

// spent is the wall time a run took, in milliseconds, never more than it was
// allowed.
func spent(start time.Time, ask uint32) uint32 {
	ms := time.Since(start).Milliseconds()
	if ms < 0 {
		return 0
	}
	if uint64(ms) > uint64(ask) {
		return ask
	}
	return uint32(ms)
}

// trim shortens VMM diagnostics to the part worth carrying in an error.
func trim(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 512 {
		return s[:512]
	}
	return s
}
