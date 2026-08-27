// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gvisor runs workloads under a user-space kernel.
//
// gVisor's sentry answers the workload's syscalls itself and issues a much
// smaller set of its own to the host, which is the single property the agentvm
// grants table gives this mechanism and gives no other. The runsc this package
// drives is the build in hanzo-vm; WithBuild pins it by digest so "our sandbox"
// is a checkable fact rather than the first runsc that happened to be on PATH.
//
// The mediation is measured, not assumed. Before every run the sandbox is asked
// what kernel it is, with the configuration the workload will get, and a reply
// that is not a sentry ends the run. A misconfiguration that quietly produced an
// ordinary host process would otherwise be attested as mediated, which is the
// one lie this mechanism must never be able to tell.
package gvisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

// name prefixes this package's errors.
const name = "agentvm/runner/gvisor"

// binaryVar names the runsc build an operator ships, when the path is not given
// to the constructor directly.
const binaryVar = "AGENTVM_RUNSC"

var (
	// ErrBuild means the runsc binary is not the build the operator pinned. The
	// pin is the digest of the hanzo-vm runsc an operator has decided to run;
	// any other binary, however well it works, is not that one.
	ErrBuild = errors.New(name + ": binary is not the pinned build")
	// ErrNotMediated means the sandbox did not answer as a sentry. Nothing about
	// such a run may be reported as mediated, so the run does not happen.
	ErrNotMediated = errors.New(name + ": sandbox did not mediate syscalls")
)

// Option configures a Runner at construction.
type Option func(*Runner)

// WithBinary names the runsc binary to drive.
func WithBinary(path string) Option {
	return func(r *Runner) { r.binary = path }
}

// WithBuild pins the runsc build. The constructor measures the binary on disk
// and refuses any digest but this one. The value is the operator's own pin of
// the hanzo-vm build it ships: keccak256 over the sha256 of the binary file.
func WithBuild(digest common.Hash) Option {
	return func(r *Runner) { r.expect = digest }
}

// Runner executes workloads under runsc.
type Runner struct {
	binary  string
	version string
	// build is the measured digest of the binary, and expect is the pin it was
	// checked against. A zero pin means the operator did not pin one.
	build  common.Hash
	expect common.Hash
}

// New builds a runner over a runsc binary: the one named by WithBinary, else the
// one named by AGENTVM_RUNSC, else the first on PATH. Whichever it is, it is
// measured, asked for its version, and refused if it will not answer.
func New(opts ...Option) (*Runner, error) {
	r := &Runner{}
	for _, o := range opts {
		o(r)
	}
	if r.binary == "" {
		r.binary = os.Getenv(binaryVar)
	}
	if r.binary == "" {
		path, err := exec.LookPath("runsc")
		if err != nil {
			return nil, fmt.Errorf("%s: %w: %v", name, runner.ErrUnavailable, err)
		}
		r.binary = path
	}
	// Measure before executing: a binary is checked against the pin as bytes on
	// disk, which is the only point at which the check means anything.
	build, err := measure(r.binary)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", name, runner.ErrUnavailable, err)
	}
	r.build = build
	if r.expect != (common.Hash{}) && r.build != r.expect {
		return nil, fmt.Errorf("%w: %s measures %s, pinned %s", ErrBuild, r.binary, r.build, r.expect)
	}
	out, err := exec.Command(r.binary, "--version").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s --version: %v", name, runner.ErrUnavailable, r.binary, err)
	}
	r.version = strings.TrimSpace(string(out))
	if r.version == "" {
		return nil, fmt.Errorf("%s: %w: %s reported no version", name, runner.ErrUnavailable, r.binary)
	}
	return r, nil
}

// Mechanism is gVisor.
func (r *Runner) Mechanism() agentvm.Mechanism { return agentvm.MechanismGVisor }

// Placement is the operator's own host.
func (r *Runner) Placement() agentvm.Placement { return agentvm.PlacementLocal }

// Version is the full version output the binary reported at construction.
func (r *Runner) Version() string { return r.version }

// Build is the measured digest of the binary this runner drives.
func (r *Runner) Build() common.Hash { return r.build }

// sandbox is the argv the sandbox is configured with, after the binary itself.
// Bundle-free single-command mode with no network: the workload gets a sentry
// and nothing to talk to.
//
// The network flag is a runsc GLOBAL flag and has to precede the subcommand.
// Written the other way round runsc's own parser answers "flag provided but not
// defined: -network" and exits before any sandbox exists, so the sandbox that
// would have mediated the syscalls is never created. Measured against runsc
// release-20260817.0.
func sandbox(cmd string, args []string) []string {
	argv := make([]string, 0, 3+len(args))
	argv = append(argv, "--network=none", "do", cmd)
	return append(argv, args...)
}

// probe is the argv that asks the sandbox what kernel it is, under exactly the
// configuration a workload gets. The sentry's procfs answers with its own
// identity, which no host process can produce.
var probe = sandbox("cat", []string{"/proc/version"})

// Run executes the workload under a sentry. The sandbox is asked to identify
// itself first, and a reply that is not a sentry ends the run before the
// workload starts. A workload that exits non-zero ran: the status is the
// result. A run that never completed is an error, and the result returned with
// it carries what the run did produce and what it cost up to the failure.
func (r *Runner) Run(ctx context.Context, w agentvm.Workload, input []byte) (runner.Result, error) {
	if w.Resource.Timeout == 0 {
		return runner.Result{}, fmt.Errorf("%s: workload names no timeout", name)
	}
	if w.Code.Ref == "" {
		return runner.Result{}, fmt.Errorf("%s: workload names no executable", name)
	}
	ask := time.Duration(w.Resource.Timeout) * time.Millisecond

	seen, err := r.observe(ctx, ask)
	if err != nil {
		return runner.Result{}, err
	}

	argv := sandbox(w.Code.Ref, w.Code.Args)
	deadline, stop := context.WithTimeout(ctx, ask)
	defer stop()

	var out, diag bytes.Buffer
	cmd := exec.CommandContext(deadline, r.binary, argv...)
	// Single-command mode hands the sandboxed process the environment runsc was
	// started with, so the workload's declared environment is set here and is
	// the whole of it. The code reference is a path for that reason: there is no
	// PATH to search unless the workload asked for one.
	cmd.Env = env(w.Env)
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
		Observed: agentvm.Witness{
			Serves: agentvm.MechanismGVisor,
			Digest: common.BytesToHash(crypto.Keccak256([]byte(seen), []byte(r.version))),
		},
		Filter: digest(argv),
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

// observe asks the sandbox what kernel it is and returns the reply. The reply is
// classified before the workload runs, so a configuration that produced no
// sentry never executes anything under a claim of mediation.
func (r *Runner) observe(ctx context.Context, ask time.Duration) (string, error) {
	deadline, stop := context.WithTimeout(ctx, ask)
	defer stop()

	var out, diag bytes.Buffer
	cmd := exec.CommandContext(deadline, r.binary, probe...)
	cmd.Stdout = &out
	cmd.Stderr = &diag
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w: probe: %v: %s", name, runner.ErrFailed, err, trim(diag.Bytes()))
	}
	seen := strings.TrimSpace(out.String())
	if err := mediated(seen); err != nil {
		return "", err
	}
	return seen, nil
}

// mediated reads a /proc/version reply and reports whether a sentry wrote it.
// gVisor names itself there; a host kernel names Linux and its build. This is
// the whole classification, and it is why a runc container cannot be attested as
// mediated: runc's /proc/version is the host's.
func mediated(seen string) error {
	if seen == "" {
		return fmt.Errorf("%w: the sandbox reported no kernel", ErrNotMediated)
	}
	if !strings.Contains(strings.ToLower(seen), "gvisor") {
		return fmt.Errorf("%w: the sandbox reported %q", ErrNotMediated, trim([]byte(seen)))
	}
	return nil
}

// digest folds an argv into one hash, each element length-prefixed so two
// different argvs cannot fold to the same bytes.
func digest(argv []string) common.Hash {
	buf := make([]byte, 0, 64)
	for _, a := range argv {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(a)))
		buf = append(buf, n[:]...)
		buf = append(buf, a...)
	}
	return common.BytesToHash(crypto.Keccak256(buf))
}

// measure is the digest of a file on disk: keccak256 over its sha256. Streamed,
// because the thing being measured can be large.
func measure(path string) (common.Hash, error) {
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

// env renders the workload environment in the NAME=VALUE form execve wants, in
// the order the workload holds it.
func env(vars []agentvm.Var) []string {
	out := make([]string, 0, len(vars))
	for _, v := range vars {
		out = append(out, v.Name+"="+v.Value)
	}
	return out
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

// trim shortens sandbox diagnostics to the part worth carrying in an error.
func trim(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 512 {
		return s[:512]
	}
	return s
}
