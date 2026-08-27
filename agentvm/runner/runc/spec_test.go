// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package runc

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
)

// work is a workload with the fields the bundle is built from.
func work() agentvm.Workload {
	return agentvm.Workload{
		Code: agentvm.Code{
			Kind: agentvm.CodeScript,
			Ref:  "/bin/sum",
			Args: []string{"--base", "16"},
		},
		Env: []agentvm.Var{
			{Name: "LANG", Value: "C"},
			{Name: "MODE", Value: "batch"},
		},
		Resource: agentvm.Resource{CPU: 2500, Memory: 512 << 20, Timeout: 30_000},
	}
}

// types returns the namespace types the bundle unshares into.
func types(s Spec) []string {
	out := make([]string, 0, len(s.Linux.Namespaces))
	for _, n := range s.Linux.Namespaces {
		out = append(out, n.Type)
	}
	return out
}

func TestNamespaces(t *testing.T) {
	s := spec(work(), false)
	for _, want := range []string{"pid", "ipc", "uts", "mount", "network"} {
		if !slices.Contains(types(s), want) {
			t.Fatalf("namespace %q missing from %v", want, types(s))
		}
	}
}

func TestNetworkNamespaceDropped(t *testing.T) {
	s := spec(work(), true)
	if slices.Contains(types(s), "network") {
		t.Fatalf("network namespace present with host network: %v", types(s))
	}
	// Everything else stays: asking for the host's network is not asking to
	// share its process table.
	for _, want := range []string{"pid", "ipc", "uts", "mount"} {
		if !slices.Contains(types(s), want) {
			t.Fatalf("namespace %q missing from %v", want, types(s))
		}
	}
}

func TestSeccompRefusesByDefault(t *testing.T) {
	s := spec(work(), false)
	if s.Linux.Seccomp.Default != "SCMP_ACT_ERRNO" {
		t.Fatalf("default action %q, want SCMP_ACT_ERRNO", s.Linux.Seccomp.Default)
	}
	if len(s.Linux.Seccomp.Calls) != 1 {
		t.Fatalf("rules %d, want one allow rule", len(s.Linux.Seccomp.Calls))
	}
	rule := s.Linux.Seccomp.Calls[0]
	if rule.Action != "SCMP_ACT_ALLOW" {
		t.Fatalf("rule action %q, want SCMP_ACT_ALLOW", rule.Action)
	}
	for _, want := range []string{"read", "write", "openat", "mmap", "execve", "exit_group"} {
		if !slices.Contains(rule.Names, want) {
			t.Fatalf("syscall %q not allowed", want)
		}
	}
	// The filter earns its name by what it leaves out.
	for _, deny := range []string{"mount", "pivot_root", "ptrace", "init_module", "bpf", "kexec_load", "setns", "unshare", "reboot"} {
		if slices.Contains(rule.Names, deny) {
			t.Fatalf("syscall %q allowed", deny)
		}
	}
	if !slices.IsSorted(rule.Names) {
		t.Fatal("allow list is not sorted, so the filter has more than one spelling")
	}
}

func TestLimits(t *testing.T) {
	w := work()
	s := spec(w, false)
	// 2500 thousandths is two and a half cores: two and a half periods of
	// runtime per period.
	if want := int64(250_000); s.Linux.Resources.CPU.Quota != want {
		t.Fatalf("quota %d, want %d", s.Linux.Resources.CPU.Quota, want)
	}
	if s.Linux.Resources.CPU.Period != period {
		t.Fatalf("period %d, want %d", s.Linux.Resources.CPU.Period, period)
	}
	if want := int64(w.Resource.Memory); s.Linux.Resources.Memory.Limit != want {
		t.Fatalf("memory limit %d, want %d", s.Linux.Resources.Memory.Limit, want)
	}
	if s.Linux.Resources.Memory.Swap != s.Linux.Resources.Memory.Limit {
		t.Fatal("swap does not match the memory limit, so the run can spill past it")
	}
}

func TestProcess(t *testing.T) {
	w := work()
	s := spec(w, false)
	want := []string{"/bin/sum", "--base", "16"}
	if !slices.Equal(s.Process.Args, want) {
		t.Fatalf("args %v, want %v", s.Process.Args, want)
	}
	wantEnv := []string{"LANG=C", "MODE=batch"}
	if !slices.Equal(s.Process.Env, wantEnv) {
		t.Fatalf("env %v, want %v", s.Process.Env, wantEnv)
	}
	if !s.Process.NoNewPrivileges {
		t.Fatal("new privileges are not refused")
	}
	if s.Process.User.UID == 0 || s.Process.User.GID == 0 {
		t.Fatalf("process runs as uid %d gid %d", s.Process.User.UID, s.Process.User.GID)
	}
	if !s.Root.Readonly {
		t.Fatal("root filesystem is writable")
	}
	if s.Version != "1.0.2" {
		t.Fatalf("spec version %q", s.Version)
	}
	if s.Process.Caps == nil || len(s.Process.Caps.Bounding) != 0 || len(s.Process.Caps.Effective) != 0 {
		t.Fatalf("process holds capabilities: %+v", s.Process.Caps)
	}
}

func TestConfigMarshals(t *testing.T) {
	doc, err := json.Marshal(spec(work(), false))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(doc, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"ociVersion", "process", "root", "mounts", "linux"} {
		if _, ok := back[key]; !ok {
			t.Fatalf("config.json has no %q", key)
		}
	}
}

func TestFilterStable(t *testing.T) {
	one, err := filter(spec(work(), false))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	two, err := filter(spec(work(), false))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if one != two {
		t.Fatalf("two identical bundles digest differently: %s and %s", one, two)
	}
	if one == (common.Hash{}) {
		t.Fatal("filter digest is zero, which reads as no filter at all")
	}
	// The network namespace is not part of the syscall filter, so it does not
	// move the digest.
	host, err := filter(spec(work(), true))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if host != one {
		t.Fatal("the network namespace moved the syscall filter digest")
	}
}

func TestFilterFollowsPolicy(t *testing.T) {
	base, err := filter(spec(work(), false))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}

	wider := spec(work(), false)
	wider.Linux.Seccomp.Calls[0].Names = append(slices.Clone(wider.Linux.Seccomp.Calls[0].Names), "ptrace")
	got, err := filter(wider)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if got == base {
		t.Fatal("allowing another syscall left the filter digest unchanged")
	}

	open := spec(work(), false)
	open.Linux.Seccomp.Default = "SCMP_ACT_ALLOW"
	got, err = filter(open)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if got == base {
		t.Fatal("inverting the default action left the filter digest unchanged")
	}
}

func TestArchNamed(t *testing.T) {
	// Whatever machine this runs on, the filter names the architecture it will
	// be compiled for. A filter with no architecture is a filter the runtime
	// builds from a default, and the digest would then describe less than what
	// was applied.
	if len(arch()) == 0 {
		t.Fatal("no seccomp architecture named for this machine")
	}
}

func TestQuota(t *testing.T) {
	for _, c := range []struct {
		cpu  uint32
		want int64
	}{
		{1, 100}, {500, 50_000}, {1000, 100_000}, {8000, 800_000},
	} {
		if got := quota(c.cpu); got != c.want {
			t.Fatalf("quota(%d) = %d, want %d", c.cpu, got, c.want)
		}
	}
}
