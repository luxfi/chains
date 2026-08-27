// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package runc runs workloads in OCI containers on the host kernel.
//
// What this mechanism is worth is written in one place, the agentvm grants
// table: a shared kernel, a seccomp filter, plain memory. This package's job is
// to make that row true. It writes a bundle whose configuration actually carries
// the namespaces, the cgroup limits and the filter, executes it, and reports the
// digest of the filter it wrote. Nothing here decides what the run proves.
//
// Availability is settled when the runner is built. If runc is not on the host
// the constructor fails and the caller has no runc runner to put in a set, so a
// workload demanding a filtered syscall surface finds no runner rather than
// finding this one running without one.
package runc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
const name = "agentvm/runner/runc"

// Option configures a Runner at construction.
type Option func(*Runner)

// WithBinary names the runc binary to drive. Without it the constructor takes
// the first runc on PATH.
func WithBinary(path string) Option {
	return func(r *Runner) { r.binary = path }
}

// WithNetwork leaves the workload on the host's network namespace. Without it
// the container gets a namespace of its own, which has only loopback in it.
func WithNetwork() Option {
	return func(r *Runner) { r.network = true }
}

// Runner executes workloads with runc.
type Runner struct {
	binary  string
	network bool
	// version is what the binary reported at construction, and observed is its
	// digest. The identity of the thing that ran the workload is read once from
	// the binary that will run it, not written down as a constant.
	version  string
	observed common.Hash
}

// New builds a runner over the host's runc. It returns an error wrapping
// runner.ErrUnavailable when runc is absent or will not report its version: a
// mechanism that cannot be interrogated cannot be attested, and a runner that
// cannot be attested has no reason to exist.
func New(opts ...Option) (*Runner, error) {
	r := &Runner{}
	for _, o := range opts {
		o(r)
	}
	if r.binary == "" {
		path, err := exec.LookPath("runc")
		if err != nil {
			return nil, fmt.Errorf("%s: %w: %v", name, runner.ErrUnavailable, err)
		}
		r.binary = path
	}
	out, err := exec.Command(r.binary, "--version").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s --version: %v", name, runner.ErrUnavailable, r.binary, err)
	}
	r.version = strings.TrimSpace(string(out))
	if r.version == "" {
		return nil, fmt.Errorf("%s: %w: %s reported no version", name, runner.ErrUnavailable, r.binary)
	}
	r.observed = common.BytesToHash(crypto.Keccak256([]byte(r.version)))
	return r, nil
}

// Mechanism is runc.
func (r *Runner) Mechanism() agentvm.Mechanism { return agentvm.MechanismRunc }

// Placement is the operator's own host.
func (r *Runner) Placement() agentvm.Placement { return agentvm.PlacementLocal }

// Version is what the runc binary reported at construction.
func (r *Runner) Version() string { return r.version }

// Run executes the workload in a container built for it and torn down after it.
// The code reference is the executable inside the rootfs, its arguments follow,
// the input is the process's standard input, and its standard output is the
// result. A workload that exits non-zero ran: the status is the result. A run
// that never completed is an error, and the result returned with it carries what
// the run did produce and what it cost up to the failure.
func (r *Runner) Run(ctx context.Context, w agentvm.Workload, input []byte) (runner.Result, error) {
	if w.Resource.Timeout == 0 {
		return runner.Result{}, fmt.Errorf("%s: workload names no timeout", name)
	}
	if w.Code.Ref == "" {
		return runner.Result{}, fmt.Errorf("%s: workload names no executable", name)
	}

	bundle, err := os.MkdirTemp("", "agentvm-bundle-")
	if err != nil {
		return runner.Result{}, fmt.Errorf("%s: bundle: %w", name, err)
	}
	defer os.RemoveAll(bundle)
	if err := os.Mkdir(filepath.Join(bundle, "rootfs"), 0o755); err != nil {
		return runner.Result{}, fmt.Errorf("%s: rootfs: %w", name, err)
	}

	s := spec(w, r.network)
	applied, err := filter(s)
	if err != nil {
		return runner.Result{}, fmt.Errorf("%s: filter: %w", name, err)
	}
	doc, err := json.Marshal(s)
	if err != nil {
		return runner.Result{}, fmt.Errorf("%s: config: %w", name, err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), doc, 0o600); err != nil {
		return runner.Result{}, fmt.Errorf("%s: config: %w", name, err)
	}

	id, err := identify(w)
	if err != nil {
		return runner.Result{}, fmt.Errorf("%s: %w", name, err)
	}

	deadline, stop := context.WithTimeout(ctx, time.Duration(w.Resource.Timeout)*time.Millisecond)
	defer stop()

	var out, diag bytes.Buffer
	cmd := exec.CommandContext(deadline, r.binary, "run", "--bundle", bundle, id)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout = &out
	cmd.Stderr = &diag

	start := time.Now()
	err = cmd.Run()
	res := runner.Result{
		Output: out.Bytes(),
		Consumed: agentvm.Resource{
			CPU:     w.Resource.CPU,
			Memory:  w.Resource.Memory,
			Timeout: spent(start, w.Resource.Timeout),
		},
		Observed: agentvm.Witness{Serves: agentvm.MechanismRunc, Digest: r.observed},
		Filter:   applied,
	}

	if err != nil {
		if deadline.Err() != nil {
			return res, fmt.Errorf("%s: %w: %v after %dms", name, runner.ErrFailed,
				deadline.Err(), res.Consumed.Timeout)
		}
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return res, fmt.Errorf("%s: %w: %v: %s", name, runner.ErrFailed, err, trim(diag.Bytes()))
		}
		// A negative code means the process was signalled or never started, so
		// there is no status to report and the run did not complete.
		code := exit.ExitCode()
		if code < 0 {
			return res, fmt.Errorf("%s: %w: %v: %s", name, runner.ErrFailed, err, trim(diag.Bytes()))
		}
		res.Exit = uint32(code)
		return res, nil
	}
	if len(res.Output) == 0 {
		return res, fmt.Errorf("%s: %w", name, runner.ErrOutput)
	}
	return res, nil
}

// identify names the container. The workload id makes the name meaningful and
// the random tail makes it unique, so one workload can be running twice at once
// without the second run colliding with the first.
func identify(w agentvm.Workload) (string, error) {
	var tail [8]byte
	if _, err := rand.Read(tail[:]); err != nil {
		return "", err
	}
	id := w.ID()
	return "agentvm-" + hex.EncodeToString(id[:8]) + "-" + hex.EncodeToString(tail[:]), nil
}

// spent is the wall time a run took, in milliseconds, never more than it was
// allowed. A run cannot report consuming more than its own limit.
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

// trim shortens runtime diagnostics to the part worth carrying in an error.
func trim(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 512 {
		return s[:512]
	}
	return s
}
