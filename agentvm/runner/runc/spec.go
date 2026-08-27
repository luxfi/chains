// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package runc

// spec.go holds the OCI runtime configuration this runner writes and nothing
// else. It is a pure function of the workload and one flag, so the bundle a run
// gets can be read, diffed and digested without starting anything.
//
// The isolation lives here, not in the runner: the namespaces the process is
// unshared into, the cgroup limits it is held to, and the syscall filter it is
// screened by are all fields of this document. The filter digest is taken over
// the bytes of the seccomp section as marshalled, so it names the policy that was
// actually written into the bundle rather than the policy this file intended.

import (
	"encoding/json"
	"runtime"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
)

// version is the OCI runtime specification this bundle is written against.
const version = "1.0.2"

// period is the cgroup CPU accounting window in microseconds. A quota is a
// fraction of it, so a CPU ask in thousandths of a core is quota = ask * 100.
const period = 100_000

// user is the uid and gid the workload runs as. Nobody, so a mount that escapes
// the read-only root still lands on an account that owns nothing.
const user = 65534

// Spec is the OCI runtime configuration, written to config.json in the bundle.
// Only the fields this runner sets are modelled; a field absent here is a field
// the runtime defaults, and defaulting is a decision, so the set is deliberate.
type Spec struct {
	Version  string  `json:"ociVersion"`
	Process  Process `json:"process"`
	Root     Root    `json:"root"`
	Hostname string  `json:"hostname"`
	Mounts   []Mount `json:"mounts"`
	Linux    Linux   `json:"linux"`
}

// Process is what to execute and under what account.
type Process struct {
	Terminal bool     `json:"terminal"`
	User     User     `json:"user"`
	Args     []string `json:"args"`
	Env      []string `json:"env"`
	Cwd      string   `json:"cwd"`
	Caps     *Caps    `json:"capabilities"`
	// NoNewPrivileges keeps a setuid binary inside the bundle from raising the
	// process past the account it was started as.
	NoNewPrivileges bool `json:"noNewPrivileges"`
}

// User is the account the process runs as.
type User struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

// Caps are the five capability sets. All empty: the workload holds none.
type Caps struct {
	Bounding    []string `json:"bounding"`
	Effective   []string `json:"effective"`
	Inheritable []string `json:"inheritable"`
	Permitted   []string `json:"permitted"`
	Ambient     []string `json:"ambient"`
}

// Root is the container's filesystem root.
type Root struct {
	Path string `json:"path"`
	// Readonly means the workload cannot write to its own image. Writable
	// scratch arrives as a tmpfs mount instead, so what a run can change is
	// enumerated rather than assumed.
	Readonly bool `json:"readonly"`
}

// Mount is one filesystem attached inside the container.
type Mount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options"`
}

// Linux carries the platform isolation: what the process is unshared from, what
// it is limited to, and what syscalls it may issue.
type Linux struct {
	Namespaces []Namespace `json:"namespaces"`
	Resources  Resources   `json:"resources"`
	Seccomp    Seccomp     `json:"seccomp"`
	Masked     []string    `json:"maskedPaths,omitempty"`
	ReadOnly   []string    `json:"readonlyPaths,omitempty"`
}

// Namespace is one namespace the process is unshared into.
type Namespace struct {
	Type string `json:"type"`
}

// Resources are the cgroup limits.
type Resources struct {
	CPU    CPU    `json:"cpu"`
	Memory Memory `json:"memory"`
}

// CPU is the bandwidth limit: Quota microseconds of runtime per Period.
type CPU struct {
	Quota  int64  `json:"quota"`
	Period uint64 `json:"period"`
}

// Memory is the byte limit. Swap equals the limit so the run cannot spill past
// it onto disk.
type Memory struct {
	Limit int64 `json:"limit"`
	Swap  int64 `json:"swap"`
}

// Seccomp is the syscall filter. Everything not named is refused with an errno,
// which fails the calling program rather than killing it, so a workload that
// probes for a blocked call sees a clean refusal.
type Seccomp struct {
	Default string   `json:"defaultAction"`
	Arch    []string `json:"architectures,omitempty"`
	Calls   []Call   `json:"syscalls"`
}

// Call is one rule: these names take this action.
type Call struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// arch names the seccomp architectures for the machine this binary runs on. A
// filter is compiled per architecture, so naming one the host does not have is
// not a stricter filter, it is a filter the runtime may refuse to build.
func arch() []string {
	switch runtime.GOARCH {
	case "amd64":
		return []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"}
	case "arm64":
		return []string{"SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM"}
	case "arm":
		return []string{"SCMP_ARCH_ARM"}
	case "386":
		return []string{"SCMP_ARCH_X86"}
	case "riscv64":
		return []string{"SCMP_ARCH_RISCV64"}
	case "ppc64le":
		return []string{"SCMP_ARCH_PPC64LE"}
	case "s390x":
		return []string{"SCMP_ARCH_S390X"}
	default:
		return nil
	}
}

// allowed is every syscall a normal program needs: memory, files, threads,
// signals, time, and sockets. Sorted, so the filter has one spelling. What is
// missing is the point of the list — mount, pivot_root, ptrace, kexec_load,
// init_module, bpf, keyctl, unshare, setns and the rest of the calls that change
// the machine rather than do work are not here, so the default errno answers
// them.
var allowed = []string{
	"accept", "accept4", "access", "arch_prctl", "bind", "brk",
	"capget", "capset", "chdir", "chmod", "chown", "clock_getres",
	"clock_gettime", "clock_nanosleep", "clone", "clone3", "close",
	"close_range", "connect", "copy_file_range", "dup", "dup2", "dup3",
	"epoll_create", "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_pwait2",
	"epoll_wait", "eventfd", "eventfd2", "execve", "execveat", "exit",
	"exit_group", "faccessat", "faccessat2", "fadvise64", "fallocate",
	"fchdir", "fchmod", "fchmodat", "fchown", "fchownat", "fcntl", "fdatasync",
	"flock", "fork", "fstat", "fstatfs", "fsync", "ftruncate", "futex",
	"futex_waitv", "get_robust_list", "getcpu", "getcwd", "getdents",
	"getdents64", "getegid", "geteuid", "getgid", "getgroups", "getpeername",
	"getpgid", "getpgrp", "getpid", "getppid", "getpriority", "getrandom",
	"getresgid", "getresuid", "getrlimit", "getrusage", "getsid",
	"getsockname", "getsockopt", "gettid", "gettimeofday", "getuid", "ioctl",
	"kill", "lchown", "link", "linkat", "listen", "lseek", "lstat", "madvise",
	"membarrier", "memfd_create", "mkdir", "mkdirat", "mknod", "mknodat",
	"mmap", "mprotect", "mremap", "munmap", "nanosleep", "newfstatat", "open",
	"openat", "openat2", "pause", "pipe", "pipe2", "poll", "ppoll", "prctl",
	"pread64", "preadv", "preadv2", "prlimit64", "pselect6", "pwrite64",
	"pwritev", "pwritev2", "read", "readlink", "readlinkat", "readv",
	"recvfrom", "recvmmsg", "recvmsg", "rename", "renameat", "renameat2",
	"restart_syscall", "rmdir", "rseq", "rt_sigaction", "rt_sigpending",
	"rt_sigprocmask", "rt_sigqueueinfo", "rt_sigreturn", "rt_sigsuspend",
	"rt_sigtimedwait", "sched_get_priority_max", "sched_get_priority_min",
	"sched_getaffinity", "sched_getparam", "sched_getscheduler",
	"sched_setaffinity", "sched_yield", "select", "sendfile", "sendmmsg",
	"sendmsg", "sendto", "set_robust_list", "set_tid_address", "setgid",
	"setgroups", "setitimer", "setpgid", "setresgid", "setresuid", "setsid",
	"setsockopt", "setuid", "shutdown", "sigaltstack", "socket", "socketpair",
	"splice", "stat", "statfs", "statx", "symlink", "symlinkat", "sync",
	"sync_file_range", "syncfs", "sysinfo", "tgkill", "time", "timer_create",
	"timer_delete", "timer_settime", "timerfd_create", "timerfd_settime",
	"times", "tkill", "truncate", "umask", "uname", "unlink", "unlinkat",
	"utimensat", "wait4", "waitid", "write", "writev",
}

// masked are the host interfaces a shared kernel exposes through /proc that a
// workload has no business reading. They are covered rather than removed,
// because a program that opens them gets an empty file instead of a failure.
var masked = []string{
	"/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore",
	"/proc/keys", "/proc/kallsyms", "/proc/latency_stats", "/proc/sched_debug",
	"/proc/scsi", "/proc/timer_list", "/sys/firmware",
}

// guarded are the /proc paths the workload may read but not write.
var guarded = []string{
	"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
}

// mounts are the filesystems every bundle gets: a real proc so the process can
// see itself, and small tmpfs devices. Nothing from the host is bound in, so a
// bundle carries no path the operator did not put in the rootfs.
func mounts() []Mount {
	return []Mount{
		{Destination: "/proc", Type: "proc", Source: "proc",
			Options: []string{"nosuid", "noexec", "nodev"}},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs",
			Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		{Destination: "/dev/pts", Type: "devpts", Source: "devpts",
			Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
		{Destination: "/dev/shm", Type: "tmpfs", Source: "shm",
			Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
		{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs",
			Options: []string{"nosuid", "nodev", "mode=1777", "size=65536k"}},
		{Destination: "/sys", Type: "sysfs", Source: "sysfs",
			Options: []string{"nosuid", "noexec", "nodev", "ro"}},
	}
}

// names are the namespaces the process is unshared into. The network namespace
// is included unless the caller asked for the host's network, and an unshared
// network namespace with nothing configured in it has only loopback, so a
// workload reaches nothing.
func names(network bool) []Namespace {
	ns := []Namespace{
		{Type: "pid"}, {Type: "ipc"}, {Type: "uts"}, {Type: "mount"},
	}
	if !network {
		ns = append(ns, Namespace{Type: "network"})
	}
	return ns
}

// env renders the workload environment in the NAME=VALUE form execve wants,
// in the order the workload holds it. That order is part of the workload's
// identity, so it is not re-sorted here.
func env(vars []agentvm.Var) []string {
	out := make([]string, 0, len(vars))
	for _, v := range vars {
		out = append(out, v.Name+"="+v.Value)
	}
	return out
}

// quota converts a CPU ask in thousandths of a core into microseconds of
// runtime per period. One whole core is one period of runtime per period.
func quota(cpu uint32) int64 { return int64(cpu) * period / 1000 }

// spec builds the bundle configuration for a workload. Pure: the same workload
// and flag give the same document, which is what lets the filter digest be a
// fact about the run rather than a fact about when it happened.
func spec(w agentvm.Workload, network bool) Spec {
	return Spec{
		Version: version,
		Process: Process{
			User: User{UID: user, GID: user},
			Args: append([]string{w.Code.Ref}, w.Code.Args...),
			Env:  env(w.Env),
			Cwd:  "/",
			Caps: &Caps{
				Bounding:    []string{},
				Effective:   []string{},
				Inheritable: []string{},
				Permitted:   []string{},
				Ambient:     []string{},
			},
			NoNewPrivileges: true,
		},
		Root:     Root{Path: "rootfs", Readonly: true},
		Hostname: "agentvm",
		Mounts:   mounts(),
		Linux: Linux{
			Namespaces: names(network),
			Resources: Resources{
				CPU:    CPU{Quota: quota(w.Resource.CPU), Period: period},
				Memory: Memory{Limit: int64(w.Resource.Memory), Swap: int64(w.Resource.Memory)},
			},
			Seccomp: Seccomp{
				Default: "SCMP_ACT_ERRNO",
				Arch:    arch(),
				Calls:   []Call{{Names: allowed, Action: "SCMP_ACT_ALLOW"}},
			},
			Masked:   masked,
			ReadOnly: guarded,
		},
	}
}

// filter is the digest of the syscall filter this bundle carries, taken over the
// marshalled seccomp section itself. Reading it from the bytes rather than from
// a constant means an edit to the policy above moves the digest, and a run
// attests to the filter it was given.
func filter(s Spec) (common.Hash, error) {
	b, err := json.Marshal(s.Linux.Seccomp)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(crypto.Keccak256(b)), nil
}
